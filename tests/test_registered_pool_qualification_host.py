"""Protected qualification host replay with inert Beads and zero model starts."""

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import stat
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch

from cwo_core import beads, native_live_availability as availability, native_pool_qualification_stage as stage
from cwo_core.invocation_ledger import InvocationLedger
from cwo_core.maintenance_authority import sign_controller_directive
from cwo_core.native_pool_admission import FixedCohortAdmissionCapability
from cwo_core.native_pool_qualification_fixtures import fixed_pool_qualification_cohorts
from cwo_core.native_pool_transaction import NativePoolTransactionError
from cwo_core.native_pool_transaction import seal_transaction_plan
from prepare_native_pool_qualification import _materialize_fixtures, _prepare
import registered_pool_qualification as adapter
import registered_pool_qualification_capability as capabilities
import registered_pool_qualification_host as host
import run_native_pool_qualification as controller

from tests.test_native_pool_admission import _candidate_from, _live
from tests.test_native_pool_qualification_budget import record_fixture_starts
from tests.test_native_pool_transaction import bead, transaction_plan
from tests.test_registered_pool_qualification_e2e import _FixtureBeads, _admission_inputs, _seal_run

_KEY = b"inert qualification operator verification key"
_NOW = 1_800_000_000
_EXPIRY = _NOW + 300
_ACTOR = "fixture-operator"
_SOURCE = "fixture-controller"


def _sign(action):
    return sign_controller_directive(verification_key=_KEY, actor_id=_ACTOR, identity_source=_SOURCE,
                                     action_sha256=action, directive_id="inert-host-replay",
                                     issued_at=datetime.fromtimestamp(_NOW - 1, timezone.utc).isoformat())


class RegisteredPoolQualificationHostTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory(prefix="pool-protected-host-")))
        self.request_path = self.root / "qualification.json"
        self.clock = self.enterContext(patch.object(controller, "time", return_value=_NOW))
        self.ledger_root = self.root / "campaign"
        self.enterContext(patch.object(stage, "contained_campaign_ledger_root", return_value=self.ledger_root))
        InvocationLedger(self.ledger_root).open_budget(stage.CAMPAIGN_BUDGET_ID,
            {"starts": stage.CAMPAIGN_START_CAP}, scope_sha256=stage.CAMPAIGN_SCOPE_SHA256)
        self.beads = _FixtureBeads()
        self.enterContext(patch.object(beads, "require_bd"))
        self.enterContext(patch.object(beads.subprocess, "run", side_effect=self.beads.run))
        cohorts = fixed_pool_qualification_cohorts()
        self.admissions = tuple(self._cohort(cohort, "productive") for cohort in cohorts)
        self.calibrations = tuple(self._cohort(cohort, "calibration") for cohort in cohorts)
        self.directive = _sign(host.admission_action_sha256(self.request_path, self.admissions, self.calibrations,
                                                          expires_at=_EXPIRY))

    def _cohort(self, cohort, purpose):
        root = self.root / f"{purpose}-{cohort['size']}"
        root.mkdir(mode=0o700)
        ready, estimates, items, policy = _admission_inputs(cohort)
        candidate = _candidate_from(ready, estimates, policy, requested_workers=cohort["size"])
        claim, _memory = self.beads.register(root, items)
        return host.PoolQualificationAdmission(candidate, claim, root.name, _live)

    def _launch(self, *, directive=None, stage_request=None, campaign_start_limit=20):
        return host.run_registered_pool_qualification(
            self.request_path, verification_key=_KEY, actor_id=_ACTOR, identity_source=_SOURCE,
            admissions=self.admissions, calibration_admissions=self.calibrations,
            admission_directive=self.directive if directive is None else directive, admission_expires_at=_EXPIRY,
            stage_approved_request=self._stage_request if stage_request is None else stage_request,
            campaign_start_limit=campaign_start_limit,
        )

    def _stage_request(self, productive, calibrations):
        self.assertTrue(all(type(row) is dict for row in productive + calibrations))
        prep = _prepare(1, {"sessions": 3, "tool_calls": 60, "runtime_seconds": 60})
        runs = [self._plan_from_receipt(row, cohort) for row, cohort in zip(productive, prep["cohorts"])]
        ledger = InvocationLedger(self.root / "original-ledger")
        accounting = stage.PoolQualificationAccounting(ledger, _EXPIRY)
        binding = stage.contained_pool_qualification_binding(prep, [
            (row["plan"], Path(row["journal_path"]), Path(row["fixture_root"])) for row in runs
        ], accounting=accounting)
        manifest = {"schema": controller.APPROVAL_SCOPE, "preparation": prep, "runs": runs,
                    "expires_at": _EXPIRY, "stage_binding_sha256": binding}
        return {"manifest": manifest, "directive": _sign(controller.qualification_action_sha256(manifest))}

    def _plan_from_receipt(self, receipt, cohort):
        size = cohort["size"]
        fixture = self.root / f"fixture-{size}"
        task_rows = [bead(row["bead_id"], task["write_path"])
                     for row, task in zip(receipt["child_bindings"], cohort["tasks"])]
        plan = transaction_plan(fixture, task_rows, cumulative_before=0)
        for child, original in zip(plan["children"], receipt["child_bindings"]):
            child.update(child_id=original["child_id"], requested_model=stage.QUALIFICATION_MODEL,
                         worktree_identity_sha256=original["worktree_identity_sha256"])
        plan.update(selected_model=stage.QUALIFICATION_MODEL, transaction_id=f"host-n{size}")
        return {"plan": seal_transaction_plan(plan), "authority_path": str(self.root / f"authority-{size}.json"),
                "journal_path": str(self.root / f"run-{size}.jsonl"), "fixture_root": str(fixture),
                "reservation_sha256": receipt["reservation_sha256"], "capability_opportunity_sha256": "e" * 64}

    def _check_original_parent(self, manifest, parent, *, approval, include_pass_record):
        self.assertTrue(include_pass_record)
        self.assertEqual(approval.action_sha256, controller.qualification_action_sha256(manifest))
        self.assertIs(parent.factory, adapter.build_pool_qualification_runtime)
        self.assertEqual(parent.request_path, self.request_path)
        self.assertEqual(stat.S_IMODE(self.request_path.stat().st_mode), 0o600)
        controller._validate_roster(manifest, parent.admissions, stage)
        originals = parent.admissions + parent.calibration_admissions
        for index, admission in enumerate(originals, 1):
            self.assertIs(type(admission.capability), FixedCohortAdmissionCapability)
            self.assertEqual(admission.capability.state, "available")
            self.assertIs(admission.claim_adapter._runner, beads.run_bd_structured)
            ledger = self.root / f"{self.request_path.name}.{index}.reservation.json"
            self.assertEqual(json.loads(ledger.read_text()), admission.receipt)
            self.assertEqual(stat.S_IMODE(ledger.stat().st_mode), 0o600)
        return {"outcome": "inert-boundary"}

    def test_one_host_call_uses_original_guarded_reservations_and_pinned_factory(self):
        self.enterContext(patch.object(availability, "require_pool_qualification"))
        checkpoint = self.enterContext(patch.object(controller, "_run_approved_stage", side_effect=self._check_original_parent))
        self.assertEqual(self._launch(), {"outcome": "inert-boundary"})
        checkpoint.assert_called_once()
        self.assertEqual([len(runner.claim_order) for runner in self.beads.databases.values()], [2, 3, 2, 3])

    def test_default_hold_and_bad_signature_precede_all_beads_io(self):
        stage_request = Mock()
        with (patch.object(availability, "POOL_QUALIFICATION_AVAILABLE", False),
              self.assertRaisesRegex(availability.NativeLiveUnavailable, "native-pool-qualification-unavailable")):
            self._launch(stage_request=stage_request)
        self.enterContext(patch.object(availability, "require_pool_qualification"))
        with self.assertRaisesRegex(controller.QualificationControllerError, "original-operator-directive-required"):
            self._launch(directive={**self.directive, "signature": "0" * 64}, stage_request=stage_request)
        stage_request.assert_not_called()
        self.assertTrue(all(not row.calls for row in self.beads.databases.values()))
        self.assertFalse(tuple(self.root.glob("qualification.json*")))

    def test_signed_increment_enrolls_before_claims_and_binds_the_final_stage(self):
        self.enterContext(patch.object(availability, "require_pool_qualification"))
        ledger = InvocationLedger(self.ledger_root)
        record_fixture_starts(ledger, 17, failed_index=3)
        unstaged = Mock()
        with self.assertRaisesRegex(ValueError, "campaign-start-cap-exhausted"):
            self._launch(stage_request=unstaged)
        with self.assertRaisesRegex(controller.QualificationControllerError, "original-operator-directive-required"):
            self._launch(stage_request=unstaged, campaign_start_limit=30)
        unstaged.assert_not_called()
        self.assertTrue(all(not row.calls for row in self.beads.databases.values()))
        self.assertEqual(stage.campaign_start_status(ledger)["cap"], 20)

        directive = _sign(host.admission_action_sha256(self.request_path, self.admissions, self.calibrations,
                                                     expires_at=_EXPIRY, campaign_start_limit=30))

        def staged(productive, calibrations):
            self.assertEqual(stage.campaign_start_status(ledger)["cap"], 30)
            manifest = self._stage_request(productive, calibrations)["manifest"]
            manifest["campaign_start_limit"] = 30
            return {"manifest": manifest, "directive": _sign(controller.qualification_action_sha256(manifest))}

        def checkpoint_with_competing_enrollment(*args, **kwargs):
            with ThreadPoolExecutor(max_workers=1) as workers:
                competing = workers.submit(stage._require_campaign_enrollment, expires_at=_EXPIRY, run_count=4,
                                           campaign_start_limit=40)
                with self.assertRaisesRegex(NativePoolTransactionError, "pool-qualification-campaign-already-running"):
                    competing.result(timeout=5)
            with self.assertRaisesRegex(NativePoolTransactionError, "pool-qualification-campaign-already-running"):
                with stage._campaign_custody(self.ledger_root, new_owner=True):
                    self.fail("another host obtained the current owner's custody")
            return self._check_original_parent(*args, **kwargs)

        checkpoint = self.enterContext(patch.object(controller, "_run_approved_stage",
                                                   side_effect=checkpoint_with_competing_enrollment))
        self.assertEqual(self._launch(stage_request=staged, directive=directive, campaign_start_limit=30),
                         {"outcome": "inert-boundary"})
        self.assertEqual(checkpoint.call_args.kwargs["approval"].campaign_start_limit, 30)
        self.assertEqual([len(runner.claim_order) for runner in self.beads.databases.values()], [2, 3, 2, 3])
        self.assertEqual(stage.campaign_start_status(ledger)["charged"], 17)
        next_directive = _sign(host.admission_action_sha256(self.request_path, self.admissions, self.calibrations,
                                                          expires_at=_EXPIRY, campaign_start_limit=40))
        with self.assertRaisesRegex(controller.QualificationControllerError, "qualification-request-already-staged"):
            self._launch(stage_request=unstaged, directive=next_directive, campaign_start_limit=40)
        self.assertEqual(stage.campaign_start_status(ledger)["cap"], 30)
        stage._require_campaign_enrollment(expires_at=_EXPIRY, run_count=4, campaign_start_limit=40)
        self.assertEqual(stage.campaign_start_status(ledger)["cap"], 40)

    def test_original_cap_signature_cannot_authorize_the_incremented_final_stage(self):
        self.enterContext(patch.object(availability, "require_pool_qualification"))
        directive = _sign(host.admission_action_sha256(self.request_path, self.admissions, self.calibrations,
                                                     expires_at=_EXPIRY, campaign_start_limit=30))
        checkpoint = self.enterContext(patch.object(controller, "_run_approved_stage"))
        with self.assertRaisesRegex(controller.QualificationControllerError, "approved-campaign-start-limit-invalid"):
            self._launch(directive=directive, campaign_start_limit=30)
        checkpoint.assert_not_called()

    def test_expiry_at_original_pre_show_refuses_before_beads_write(self):
        self.enterContext(patch.object(availability, "require_pool_qualification"))
        first = next(iter(self.beads.databases.values()))

        def advance_on_claim_pre_show(command, *args, **kwargs):
            result = self.beads.run(command, *args, **kwargs)
            if len(first.calls) == 3:
                self.clock.return_value = _EXPIRY
            return result

        self.enterContext(patch.object(beads.subprocess, "run", side_effect=advance_on_claim_pre_show))
        stage_request = Mock()
        with self.assertRaisesRegex(controller.QualificationControllerError, "qualification-directive-expired-or-future"):
            self._launch(stage_request=stage_request)
        self.assertEqual([row[0] for row in first.calls], ["show"] * 3)
        stage_request.assert_not_called()
        self.assertFalse(tuple(self.root.glob("qualification.json*")))

    def test_unenrolled_campaign_refuses_before_disposable_claims(self):
        stage_request = Mock()
        missing = self.root / "not-enrolled"
        with (patch.object(stage, "contained_campaign_ledger_root", return_value=missing),
              self.assertRaisesRegex(ValueError, "campaign-ledger-custody-refused")):
            self._launch(stage_request=stage_request)
        self.assertFalse(missing.exists())
        self.assertTrue(all(not row.calls for row in self.beads.databases.values()))
        stage_request.assert_not_called()

    def test_refused_final_approval_preserves_original_claims_and_refuses_replay(self):
        self.enterContext(patch.object(availability, "require_pool_qualification"))
        stage_request = Mock(side_effect=PermissionError("inert signer refused the final request"))
        with self.assertRaisesRegex(PermissionError, "inert signer refused") as refusal:
            self._launch(stage_request=stage_request)
        self.assertFalse(self.request_path.exists())
        self.assertEqual(len(list(self.root.glob("qualification.json.*.reservation.json"))), 4)
        self.assertEqual(len(list(self.root.glob("qualification.json.*.claim-*.json"))), 10)
        self.assertTrue(refusal.exception.__notes__)
        for runner in self.beads.databases.values():
            self.assertTrue(all(row["status"] == "in_progress" for row in runner.issues.values()))
            self.assertEqual(runner.close_order, [])
        with self.assertRaisesRegex(controller.QualificationControllerError, "qualification-claim-custody-already-present"):
            self._launch(stage_request=stage_request)
        stage_request.assert_called_once()

    def test_partial_cohort_keeps_exact_intent_if_next_claim_expires(self):
        self.enterContext(patch.object(availability, "require_pool_qualification"))
        first = next(iter(self.beads.databases.values()))

        def expire_at_second_pre_show(command, *args, **kwargs):
            result = self.beads.run(command, *args, **kwargs)
            if len(first.calls) == 6:
                self.clock.return_value = _EXPIRY
            return result

        self.enterContext(patch.object(beads.subprocess, "run", side_effect=expire_at_second_pre_show))
        stage_request = Mock()
        with self.assertRaisesRegex(controller.QualificationControllerError, "qualification-directive-expired-or-future"):
            self._launch(stage_request=stage_request)
        self.assertEqual(len(first.claim_order), 1)
        intent = json.loads((self.root / "qualification.json.1.claim-1.json").read_bytes())
        issue = first.issues[first.claim_order[0]]
        self.assertEqual((intent["disposition"], intent["attempt_actor"], intent["bead_id"]),
                         ("claim-intent", issue["assignee"], issue["id"]))
        self.assertFalse(tuple(self.root.glob("qualification.json.*.reservation.json")))
        stage_request.assert_not_called()

    def test_planned_hashes_match_installed_selected_factory_without_launch(self):
        self.enterContext(patch.object(stage, "require_pool_qualification"))
        prep = _prepare(1, {"sessions": 3, "tool_calls": 60, "runtime_seconds": 60})
        _materialize_fixtures(self.root / "fixtures", prep)
        fixture = self.root / "fixtures" / "n2" / "run-1"
        run, _, path = _seal_run(self.root / "original", prep["cohorts"][0], fixture, self.beads,
                                 mode="callback-calibration", with_authority=True)
        original = run.runtime.start_worker_session.__self__
        self.assertIs(type(original), adapter._PoolParent)
        accounting = stage.PoolQualificationAccounting(InvocationLedger(self.root / "ledger"), _EXPIRY)
        actual = stage.pool_qualification_binding(prep, [run], accounting=accounting)
        self.assertEqual(stage.contained_pool_qualification_binding(prep, [(run.plan, run.journal_path, fixture)],
                                                                   accounting=accounting), actual)
        self.assertNotEqual(stage.contained_pool_qualification_binding(prep, [(run.plan, path, fixture)],
                                                                      accounting=accounting), actual)
        approved = capabilities.callback_adapter_scope_sha256(original)
        authority = json.loads(path.read_bytes())
        self.assertEqual(capabilities.calibration_adapter_scope_sha256(run.plan, authority), approved)
        drifted = deepcopy(authority)
        drifted["render_request"]["control_turn_id"] = "different-control-turn"
        self.assertNotEqual(capabilities.calibration_adapter_scope_sha256(run.plan, drifted), approved)
