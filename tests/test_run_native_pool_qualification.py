"""Inert original reservations and operator directives for the pool launcher."""

from contextlib import ExitStack, nullcontext
from copy import copy, deepcopy
from dataclasses import asdict, replace
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import sys
import tempfile
from time import time
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import cwo_core
from cwo_core import native_live_availability as availability
from cwo_core.invocation_ledger import InvocationLedger, request_sha256
from cwo_core.maintenance_authority import sign_controller_directive
from cwo_core.native_pool_admission import reserve_pool_cohort
from cwo_core.native_pool_contracts import canonical_sha256
from cwo_core.native_pool_deferred_context import QUALIFICATION_PROFILE
from cwo_core.native_pool_qualification_fixtures import fixed_pool_qualification_cohorts
from cwo_core.native_pool_qualification_stage import _signed_failure_isolation
from cwo_core.native_pool_transaction import seal_transaction_plan
import run_native_pool_qualification as controller
import registered_pool_qualification_capability as callback_capability
from tests import test_registered_pool_qualification_capability as calibration_tests
from tests.test_native_pool_admission import MemoryBdRunner, _adapter, _fixture_candidate, _live
from tests.test_native_pool_transaction import bead, transaction_plan

_TIME = int(time())
_MODEL = "gpt-6.2-sol"
_BINDING = "a" * 64
_KEY = b"synthetic operator verification key"


class ProtectedPoolControllerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.request_path = self.root / "qualification.json"
        self.enterContext(patch.object(controller, "time", return_value=_TIME))
        self.enterContext(patch.object(controller, "InvocationLedger",
            side_effect=lambda root: InvocationLedger(root, clock=lambda: _TIME)))
        self.pool_hold = self.enterContext(patch.object(availability, "require_pool_qualification", create=True))
        self.n1_hold = self.enterContext(patch.object(controller, "require_registered_n1_live"))
        self.stage = self._stage_boundary()
        self.measurements = {}
        self._capability_boundary()
        cohorts = fixed_pool_qualification_cohorts()
        runs, admissions, calibrations, calibration_admissions, handles = zip(*(self._run_fixture(cohort) for cohort in cohorts))
        self.calibrations, self.calibration_admissions = calibrations, calibration_admissions
        self.manifest = {"schema": controller.APPROVAL_SCOPE, "preparation": {
            "cohorts": cohorts, "runs_per_cohort": 1, "per_run_limits": {"sessions": 3, "tool_calls": 3,
                                                                         "runtime_seconds": 20},
            "qualification_record": {"minimum_codex_version": "0.172.0"}},
            "runs": list(runs), "expires_at": _TIME + 100, "stage_binding_sha256": _BINDING}
        self.parent = controller.ProtectedPoolQualificationParent(
            self.request_path, _KEY, "fixture-operator", "fixture-protected-parent", tuple(admissions), self.builder,
            capabilities=tuple(handles))
        self._authorize(self.manifest)

    def _private_json(self, path, value):
        raw = json.dumps(value, sort_keys=True).encode()
        path.write_bytes(raw)
        path.chmod(0o600)
        return sha256(raw).hexdigest()

    def _authorize(self, manifest, *, key=_KEY):
        directive = self._directive(controller.qualification_action_sha256(manifest), key=key)
        self._private_json(self.request_path, {"manifest": manifest, "directive": directive})

    @staticmethod
    def _directive(action, *, key=_KEY):
        return sign_controller_directive(verification_key=key, actor_id="fixture-operator",
            identity_source="fixture-protected-parent", action_sha256=action, directive_id="test-contained-pool",
            issued_at=datetime.fromtimestamp(_TIME - 1, tz=timezone.utc).isoformat())

    def _stage_boundary(self):
        stage = ModuleType("cwo_core.native_pool_qualification_stage")
        stage.CAMPAIGN_START_CAP = 20
        stage.CAMPAIGN_BUDGET_ID = calibration_tests._CAMPAIGN
        stage.QUALIFICATION_MODEL = _MODEL
        stage._stage_limits = Mock(side_effect=lambda prep, _: (prep["runs_per_cohort"], prep["per_run_limits"]))
        stage._stage_tasks = Mock(side_effect=lambda prep: {row["size"]: row["tasks"] for row in prep["cohorts"]})
        stage._stage_model = Mock()
        stage._signed_failure_isolation = _signed_failure_isolation
        stage.PoolQualificationAccounting = Mock(side_effect=lambda ledger, expires, approval: SimpleNamespace(
            ledger=ledger, expires_at=expires, _approval=approval))
        stage._campaign_custody = Mock(side_effect=lambda _: nullcontext())
        stage._require_campaign_budget = Mock()
        stage.contained_campaign_ledger_root = Mock(return_value=self.root / "fixed-stage-ledger")
        stage.select_contained_pool_runtime = Mock(side_effect=self._select_runtime)
        stage.make_pool_qualification_run = Mock(side_effect=(object(), object()))
        stage.pool_qualification_binding = Mock(return_value=_BINDING)
        stage.contained_pool_qualification_binding = Mock(return_value=_BINDING)
        stage.run_contained_pool_qualification_stage = Mock(return_value={"outcome": "completed", "transactions": [{}, {}]})
        self.builder = Mock()
        self.enterContext(patch.dict(sys.modules, {stage.__name__: stage}))
        self.enterContext(patch.object(cwo_core, "native_pool_qualification_stage", stage, create=True))
        return stage

    def _capability_boundary(self):
        fixture = calibration_tests
        protected_types = (fixture._Parent, fixture._Control, fixture._Host, fixture._Limits,
                           controller.ProtectedPoolQualificationParent)
        self.enterContext(patch.object(callback_capability, "_protected_types", return_value=protected_types))
        self.enterContext(patch.object(callback_capability, "_source_digest", return_value=fixture._digest("installed-sources")))
        context = ModuleType("cwo_core.native_pool_deferred_context")
        context.QUALIFICATION_ADAPTER_VERSION = "pool-contained-v1"
        context.QUALIFICATION_SURFACE = "connected-codex"
        context.QUALIFICATION_MODEL = _MODEL
        context.QUALIFICATION_EFFORT = "xhigh"
        context.QUALIFICATION_TIER = "default"
        context.QUALIFICATION_PROFILE = "cwo-pool-contained"
        context.QUALIFICATION_TOOL = "cwo_finite.finite_command"
        self.enterContext(patch.dict(sys.modules, {context.__name__: context}))

    def _measure_capability(self, size, plan):
        fixture = calibration_tests
        with ExitStack() as stack:
            parent, ledger, reservation, manifest = fixture._fixture(size, self.root / f"measure-{size}", stack)
            parent.plan = deepcopy(plan)
            parent.limits._contained_admission._plan = parent.plan
            manifest.update(calibration_plan_sha256=plan["plan_sha256"],
                            adapter_scope_sha256=callback_capability.callback_adapter_scope_sha256(parent))
            action = callback_capability.calibration_action_sha256(manifest)
            directive = self._directive(action)
            types = (*callback_capability._protected_types()[:-1], controller.ProtectedPoolQualificationParent)
            opener = controller.ProtectedPoolQualificationParent(self.request_path, _KEY, "fixture-operator",
                "fixture-protected-parent", (), self.builder)
            with patch.object(callback_capability, "_protected_types", return_value=types):
                calibration = callback_capability.begin_connected_callback_calibration(parent, opener, manifest=manifest, directive=directive)
                fixture._run_original_controls(calibration, parent)
                handle = calibration.finalize()
            ledger.finish(reservation, "completed", reason="inert original callback measurements settled")
        self.measurements[size] = parent
        return handle, manifest, directive, action

    def _select_runtime(self, plan, builder, *, authority_path, admission, capability):
        self.assertIs(builder, self.builder)
        measured = copy(self.measurements[len(plan["children"])])
        expected = json.loads(authority_path.read_bytes())[controller._OPPORTUNITY]
        measured.plan = plan
        measured.authority = {**measured.authority, "mode": "qualification", controller._OPPORTUNITY: expected}
        callback_capability.require_connected_callback_capability(capability, measured, expected)
        return object()

    def _run_inputs(self, cohort, mode, *, opportunity=None):
        size = cohort["size"]
        candidate, items, policy = _fixture_candidate(size)
        run_name = f"{mode}-{size}"
        admission = reserve_pool_cohort(candidate, claim_adapter=_adapter(MemoryBdRunner(items)),
            admission_nonce=run_name, live_revalidate=_live, policy_document=policy, now="2026-07-21T20:00:02Z")
        self.assertTrue(admission.admitted)
        bindings = admission.receipt["child_bindings"]
        work = self.root / run_name
        task_rows = [bead(binding["bead_id"], task["write_path"])
                     for binding, task in zip(bindings, cohort["tasks"])]
        plan = transaction_plan(work, task_rows, cumulative_before=0)
        for child, binding in zip(plan["children"], bindings):
            child.update(child_id=binding["child_id"], requested_model=_MODEL,
                         worktree_identity_sha256=binding["worktree_identity_sha256"])
        authority_path = self.root / f"authority-{run_name}.json"
        run = {"authority_path": str(authority_path), "journal_path": str(self.root / f"journal-{run_name}.json"),
               "fixture_root": str(work), "reservation_sha256": admission.receipt["reservation_sha256"]}
        authority = {"scope": controller._AUTHORITY_SCOPE, "mode": mode, **{name: run[name]
                     for name in ("fixture_root", "journal_path", "reservation_sha256")}}
        if opportunity is not None:
            run[controller._OPPORTUNITY] = authority[controller._OPPORTUNITY] = opportunity
        plan.update(selected_model=_MODEL, transaction_id=run_name, authority_sha256=self._private_json(authority_path, authority))
        return {**run, "plan": seal_transaction_plan(plan)}, admission

    def _run_fixture(self, cohort):
        setup, setup_admission = self._run_inputs(cohort, "callback-calibration")
        handle, manifest, directive, action = self._measure_capability(cohort["size"], setup["plan"])
        tested, admission = self._run_inputs(cohort, "qualification", opportunity=action)
        return tested, admission, {**setup, "manifest": manifest, "directive": directive}, setup_admission, handle

    def _assert_refused_before_selection(self, reason):
        with self.assertRaisesRegex(controller.QualificationControllerError, reason):
            controller.run_protected_pool_qualification(self.parent)
        self.stage.select_contained_pool_runtime.assert_not_called()
        self.stage.run_contained_pool_qualification_stage.assert_not_called()

    def test_holds_and_missing_parent_precede_any_private_file_read(self):
        with patch.object(controller, "_read_owner_json") as read:
            self.pool_hold.side_effect = availability.NativeLiveUnavailable("native-pool-qualification-unavailable")
            with self.assertRaisesRegex(availability.NativeLiveUnavailable, "native-pool-qualification-unavailable"):
                controller.run_protected_pool_qualification(self.parent)
            self.n1_hold.assert_not_called()
            self.pool_hold.side_effect = None
            self.n1_hold.side_effect = availability.NativeLiveUnavailable("native-registered-n1-live-unavailable")
            with self.assertRaisesRegex(availability.NativeLiveUnavailable, "registered-n1-live-unavailable"):
                controller.run_protected_pool_qualification(self.parent)
            self.n1_hold.side_effect = None
            with self.assertRaisesRegex(controller.QualificationControllerError, "protected-parent-attachment-required"):
                controller.run_protected_pool_qualification(None)
            read.assert_not_called()

    def test_original_signed_cohorts_reach_exact_stage_with_original_reservations(self):
        result = controller.run_protected_pool_qualification(self.parent)
        self.assertEqual(result, self.stage.run_contained_pool_qualification_stage.return_value)
        for call, row, admission, capability in zip(self.stage.select_contained_pool_runtime.call_args_list,
                self.manifest["runs"], self.parent.admissions, self.parent.capabilities):
            self.assertEqual(call.args, (row["plan"], self.builder))
            self.assertEqual(call.kwargs["authority_path"], Path(row["authority_path"]))
            self.assertIs(call.kwargs["admission"], admission)
            self.assertIs(call.kwargs["capability"], capability)
        call = self.stage.run_contained_pool_qualification_stage.call_args
        self.assertEqual(call.args[0], self.manifest["preparation"])
        self.assertEqual(len(call.args[1]), 2)
        self.assertEqual(call.kwargs["approved_binding"], _BINDING)
        accounting = call.kwargs["accounting"]
        self.assertEqual(accounting.ledger.root, self.stage.contained_campaign_ledger_root.return_value)
        self.assertEqual(accounting.expires_at, self.manifest["expires_at"])
        self.assertFalse(self.stage.contained_campaign_ledger_root.return_value.exists())
        self.assertNotIn(_KEY.decode(), repr(self.parent))

    def test_caller_hash_and_unrelated_signed_key_fail_before_authority_reads(self):
        actual_read = controller._read_owner_json
        with patch.object(controller, "_read_owner_json", wraps=actual_read) as read:
            self._private_json(self.request_path, {"manifest": self.manifest, "directive": {"action_sha256":
                               controller.qualification_action_sha256(self.manifest)}})
            self._assert_refused_before_selection("original-operator-directive-required")
            read.assert_called_once_with(self.request_path)
            read.reset_mock()
            self._authorize(self.manifest, key=b"unrelated synthetic key")
            self._assert_refused_before_selection("original-operator-directive-required")
            read.assert_called_once_with(self.request_path)

    def test_expired_and_resealed_wrong_budget_fail_before_stage(self):
        expired = dict(self.manifest, expires_at=_TIME - 1)
        self._authorize(expired)
        self._assert_refused_before_selection("qualification-directive-expired-or-future")
        weak = deepcopy(self.manifest)
        weak["preparation"]["per_run_limits"]["tool_calls"] = 2
        self._authorize(weak)
        self._assert_refused_before_selection("approved-tool-capacity-required")

    def test_signed_request_cannot_exceed_the_stage_start_cap(self):
        excessive = deepcopy(self.manifest)
        excessive["runs"] *= 11
        excessive["preparation"]["runs_per_cohort"] = 11
        self.parent = replace(self.parent, admissions=self.parent.admissions * 11)
        self._authorize(excessive)
        self._assert_refused_before_selection("approved-cohort-set-invalid")
        self.stage._stage_limits.assert_not_called()

    def test_serialized_or_borrowed_reservation_is_refused(self):
        original = self.parent
        first, second = original.admissions
        self.parent = replace(original, admissions=(dict(first.receipt), second))
        self._assert_refused_before_selection("original-pool-reservation-required")
        self.parent = replace(original, admissions=(replace(first, capability=second.capability), second))
        self._assert_refused_before_selection("original-reservation-binding-mismatch")

    def test_private_authority_digest_and_signed_cohort_order_are_checked(self):
        reverse = dict(self.manifest, runs=list(reversed(self.manifest["runs"])))
        self._authorize(reverse)
        self.parent = replace(self.parent, admissions=self.parent.admissions[::-1])
        self._assert_refused_before_selection("approved-run-plan-invalid")
        self.parent = replace(self.parent, admissions=self.parent.admissions[::-1])
        self._authorize(self.manifest)
        authority = Path(self.manifest["runs"][1]["authority_path"])
        authority.write_bytes(authority.read_bytes() + b"\n")
        self._assert_refused_before_selection("approved-run-authority-mismatch")

    def test_signed_stage_binding_must_match_original_runtime_selection(self):
        self.stage.pool_qualification_binding.return_value = "b" * 64
        with self.assertRaisesRegex(controller.QualificationControllerError, "approved-stage-binding-mismatch"):
            controller.run_protected_pool_qualification(self.parent)
        self.assertEqual(self.stage.select_contained_pool_runtime.call_count, 2)
        self.stage.run_contained_pool_qualification_stage.assert_not_called()

    def test_even_a_signed_run_cannot_authorize_a_serialized_connected_receipt(self):
        revised = deepcopy(self.manifest)
        run = revised["runs"][0]
        path = Path(run["authority_path"])
        authority = json.loads(path.read_bytes())
        authority["capability_receipt"] = {"attestation_source": "trusted-control-plane-session-metadata"}
        run["plan"]["authority_sha256"] = self._private_json(path, authority)
        run["plan"] = seal_transaction_plan(run["plan"])
        self._authorize(revised)
        self._assert_refused_before_selection("serialized-connected-capability-refused")

    def test_copied_receipt_forged_handle_and_unmatched_original_refuse(self):
        original = self.parent
        cap2, cap3 = original.capabilities
        self.parent = replace(original, capabilities=({"capability_opportunity_sha256": "f" * 64}, cap3))
        self._assert_refused_before_selection("original-connected-capability-required")
        forged = object.__new__(type(cap2))
        for first, reason in ((forged, "original-connected-capability-required"),
                              (cap3, "connected-capability-scope-or-owner-drift")):
            with self.subTest(reason=reason), self.assertRaisesRegex(callback_capability.CallbackCalibrationError, reason):
                self.parent = replace(original, capabilities=(first, cap3))
                controller.run_protected_pool_qualification(self.parent)
        self.stage.run_contained_pool_qualification_stage.assert_not_called()

    def _combined_request(self):
        module = ModuleType("registered_pool_qualification_calibration")
        module.run_protected_callback_calibration = driver = Mock(side_effect=self.parent.capabilities)
        module.verify_protected_callback_calibration_request = self.verify_calibration = Mock(
            side_effect=lambda _parent, **kwargs: callback_capability.calibration_action_sha256(kwargs["manifest"]))
        self.enterContext(patch.dict(sys.modules, {module.__name__: module}))
        self.parent = replace(self.parent, capabilities=(), calibration_admissions=self.calibration_admissions)
        manifest = deepcopy(dict(self.manifest, calibrations=list(self.calibrations)))
        manifest["expires_at"] = max(manifest["expires_at"], *(row["manifest"]["expires_at"] for row in self.calibrations))
        return manifest, driver

    def test_signed_stage_binding_is_checked_before_any_calibration(self):
        manifest, driver = self._combined_request()
        manifest["stage_binding_sha256"] = "f" * 64
        self._authorize(manifest)
        self._assert_refused_before_selection("approved-stage-binding-mismatch")
        self.verify_calibration.assert_not_called()
        driver.assert_not_called()
        self.stage._require_campaign_budget.assert_not_called()

    def test_directive_over_another_start_cap_refuses_before_selection(self):
        with patch.object(controller, "CAMPAIGN_START_CAP", 21):
            self._authorize(self.manifest)
        self._assert_refused_before_selection("original-operator-directive-required")

    def test_one_protected_invocation_joins_separate_signed_calibrations(self):
        manifest, driver = self._combined_request()
        self._authorize(manifest)
        result = controller.run_protected_pool_qualification(self.parent)
        self.assertEqual(result["outcome"], "completed")
        self.assertEqual(self.stage._require_campaign_budget.call_args.args[1], 4)
        for call, row, admission in zip(driver.call_args_list, manifest["calibrations"], self.calibration_admissions):
            self.assertIs(call.args[0], self.parent)
            self.assertIs(call.kwargs["admission"], admission)
            self.assertEqual(call.kwargs["manifest"], row["manifest"])
            self.assertEqual(call.kwargs["directive"], row["directive"])
        self.assertEqual(driver.call_count, 2)
        for verified, executed in zip(self.verify_calibration.call_args_list, driver.call_args_list, strict=True):
            self.assertEqual(verified.args, executed.args)
            self.assertEqual(verified.kwargs, {key: value for key, value in executed.kwargs.items()
                                               if key != "_campaign_approval"})
            self.assertEqual(executed.kwargs["_campaign_approval"].action_sha256,
                             controller.qualification_action_sha256(manifest))
        self.stage.run_contained_pool_qualification_stage.assert_called_once()

    def test_independent_calibration_signature_and_approved_operation_match_before_starts(self):
        manifest, driver = self._combined_request()
        row = manifest["calibrations"][1]
        row["manifest"]["runtime_seconds"] += 1
        self._authorize(manifest)
        self._assert_refused_before_selection("original-operator-directive-required")
        row["directive"] = self._directive(callback_capability.calibration_action_sha256(row["manifest"]))
        self._authorize(manifest)
        self._assert_refused_before_selection("signed-calibration-opportunity-mismatch")
        self.stage._require_campaign_budget.assert_not_called()
        self.verify_calibration.assert_not_called()
        driver.assert_not_called()

    def test_original_calibration_verification_refusal_precedes_every_charge(self):
        manifest, driver = self._combined_request()
        first, _second = manifest["calibrations"]
        self.verify_calibration.side_effect = (callback_capability.calibration_action_sha256(first["manifest"]), None)
        self._authorize(manifest)
        self._assert_refused_before_selection("signed-calibration-opportunity-mismatch")
        self.stage._require_campaign_budget.assert_not_called()
        driver.assert_not_called()

    @staticmethod
    def _ledger_attempt(ledger, budget, request, *, outcome, amount):
        payload = request.encode()
        digest = request_sha256(payload)
        row = ledger.reserve(budget_id=budget, request_id=request, request_sha256=digest,
                             admission_sha256=digest, amount=amount, expires_at=_TIME + 100)
        reservation = row["reservation_id"]
        if outcome is None:
            return ledger.release(reservation)
        ledger.begin_invocation(reservation, payload)
        return ledger.finish(reservation, outcome, reason="inert observed settlement")

    def _settled_result(self, _preparation, _runs, *, approved_binding, accounting, run_index=0):
        from cwo_core.native_pool_qualification_evidence import WorkerToolObservation

        self.assertEqual(approved_binding, _BINDING)
        ledger = accounting.ledger
        self.assertEqual(ledger.current_time(), _TIME)
        budget = self.stage.CAMPAIGN_BUDGET_ID
        ledger.open_budget(budget, {"starts": 20}, scope_sha256="1" * 64)
        calibrations = [self._ledger_attempt(ledger, budget, name, outcome=outcome, amount={"starts": 1})
                        for name, outcome in (("calibration-earlier", "failed"), ("calibration-current", "completed"))]
        self.calibration_start = calibrations[1]["reservation_id"]
        self._ledger_attempt(ledger, budget, "released-before-start", outcome=None, amount={"starts": 1})
        plan = self.manifest["runs"][run_index]["plan"]
        size = len(plan["children"])
        request = "contained-cohort:" + canonical_sha256({"transaction_id": plan["transaction_id"]})
        started = self._ledger_attempt(ledger, budget, request, outcome="completed", amount={"starts": 1})
        ledger.open_budget("run-bound", {"tool_calls": size}, scope_sha256="2" * 64)
        run_request = "pool-qualification-run:" + canonical_sha256({"transaction_id": plan["transaction_id"]})
        reserved = self._ledger_attempt(ledger, "run-bound", run_request, outcome="completed", amount={"tool_calls": size})
        workers = {}
        tasks = {task["write_path"]: task for task in fixed_pool_qualification_cohorts()[run_index]["tasks"]}
        for index, child in enumerate(plan["children"]):
            child_id = child["child_id"]
            path, = child["write_paths"]
            task = tasks[path]
            slot = int(task["worker_slot"].rsplit("-", 1)[1])
            owner = sha256(child_id.encode()).hexdigest()
            tools = (WorkerToolObservation(additional_tools=("functions.exec",), unexpected=("functions.exec",),
                                           limitations=()) if index == 0 else WorkerToolObservation())
            host = {"worker_id": child_id, "cleanup_confirmed": True, "login_slot": slot,
                    "config_sha256": "c" * 64, "model_catalog_sha256": "d" * 64, "observations": [
                {"stage": "appserver-contained", "observation": {"worktree_readonly": True, "filesystem_ready": True,
                 "network": "registered-provider-tunnel", "managed_login_projection": True,
                 "namespaces": {"mnt": f"mnt:[{index + 1}]", "net": f"net:[{index + 1}]"},
                 "owner_identity_sha256": owner, "peer_worktrees_hidden": size - 1}},
                {"stage": "named-profile-config", "observation": {"id": QUALIFICATION_PROFILE,
                 "managed_login_access": "deny"}},
                {"stage": "tool-contained", "observation": {"worktree_readonly": False, "filesystem_ready": True,
                 "network": "isolated", "managed_login_projection": False,
                 "namespaces": {"mnt": f"mnt:[{index + size + 1}]", "net": f"net:[{index + size + 1}]"},
                 "peer_worktrees_hidden": size - 1}},
                {"stage": "writer-output", "observation": {"call_id": "inert-original", "path": path,
                 "content_sha256": sha256(task["expected_utf8"].encode()).hexdigest()}},
            ]}
            workers[child_id] = {"tools": asdict(tools), "host": host, "task_completed": True, "wire_settled": True,
                                 "thread_profile": {"id": QUALIFICATION_PROFILE, "owner_identity_sha256": owner,
                                                    "widening_refused": True}}
        validation = {"worker_observations": workers, "qualification_active_limits": {"effects_complete": True,
                      "cleanup_confirmed": True}, "qualification_fixture": {"outcome": "verified", "worker_output_count": size},
                      "qualification_settlement": {"outcome": "verified"}}
        transaction = {"transaction_id": plan["transaction_id"], "plan_sha256": plan["plan_sha256"],
            "qualification_campaign": {"reservation_id": started["reservation_id"], "runs_consumed": 20},
            "qualification_accounting": {**reserved, "mode": "active"}, "validation": validation}
        return {"outcome": "stopped", "transactions": [transaction]}

    def test_pass_record_counts_original_intents_and_keeps_unperformed_checks_explicit(self):
        self.stage.run_contained_pool_qualification_stage.side_effect = self._settled_result
        result = controller.run_protected_pool_qualification(self.parent, include_pass_record=True)
        report = result["pass_record"]
        self.assertEqual(report["runs_consumed"], 3)
        self.assertEqual(report["run_cap"], 20)
        self.assertEqual(report["outcome"], "incomplete")
        self.assertEqual(report["minimum_codex_version"], "0.172.0")
        for name in ("n2_concurrency", "readonly_workspace", "registered_writer", "cleanup", "shared_budget",
                     "cross_worker_isolation", "named_profile", "login_path_denied", "profile_cannot_widen",
                     "provider_only_egress", "dedicated_logins"):
            self.assertEqual(report["behaviors"][name], {"outcome": "passed", "runs": [3]})
        for name in ("n3_concurrency", "failure_isolation"):
            self.assertEqual(report["behaviors"][name], {"outcome": "not-run", "runs": []})
        self.assertTrue(any("No login read was attempted" in note for note in report["limitations"]))
        self.assertEqual(report["model_catalog"], [{"run": 3, "mode": "trimmed"}])
        self.assertNotIn("owner_identity_sha256", json.dumps(report))
        observed, = report["tool_lists"]
        self.assertEqual((observed["run"], observed["worker"]), (3, 1))
        self.assertEqual(observed["rollout.additional_tools"], ["functions.exec"])
        self.assertEqual(observed["unexpected"], ["functions.exec"])

    def test_missing_observations_do_not_become_passes_and_observed_failures_are_explicit(self):
        def changed(*args, **kwargs):
            result = self._settled_result(*args, **kwargs)
            validation = result["transactions"][0]["validation"]
            first, second = validation["worker_observations"].values()
            first["host"]["model_catalog_sha256"] = second["host"]["model_catalog_sha256"] = None
            first["thread_profile"]["owner_identity_sha256"] = "e" * 64
            first["host"]["observations"][0]["observation"].pop("network")
            second["host"]["login_slot"] = first["host"]["login_slot"]
            validation["qualification_active_limits"]["cleanup_confirmed"] = False
            return result

        self.stage.run_contained_pool_qualification_stage.side_effect = changed
        report = controller.run_protected_pool_qualification(self.parent, include_pass_record=True)["pass_record"]
        for name in ("cleanup", "dedicated_logins"):
            self.assertEqual(report["behaviors"][name], {"outcome": "failed", "runs": [3]})
        for name in ("named_profile", "profile_cannot_widen", "provider_only_egress", "login_path_denied"):
            self.assertEqual(report["behaviors"][name], {"outcome": "not-run", "runs": []})
        self.assertEqual(report["model_catalog"], [{"run": 3, "mode": "stock-fallback"}])
        self.assertEqual(report["outcome"], "failed")

    def test_failure_isolation_projects_the_original_fixed_negative_case(self):
        def negative_case(*args, **kwargs):
            result = self._settled_result(*args, run_index=1, **kwargs)
            children = self.manifest["runs"][1]["plan"]["children"]
            target, = (child for child in children if child["write_paths"] == ["result-n3-worker-1.txt"])
            transaction, = result["transactions"]
            transaction["qualification_failure_isolation"] = {"target_child_id": target["child_id"], "outcome": "passed"}
            return result

        self.stage.run_contained_pool_qualification_stage.side_effect = negative_case
        report = controller.run_protected_pool_qualification(self.parent, include_pass_record=True)["pass_record"]
        self.assertEqual(report["behaviors"]["failure_isolation"], {"outcome": "passed", "runs": [3]})
        self.assertNotIn("target_child_id", json.dumps(report))

    def test_writer_namespace_ids_can_be_reused_after_independent_cleanup(self):
        def recycled(*args, **kwargs):
            result = self._settled_result(*args, **kwargs)
            workers = result["transactions"][0]["validation"]["worker_observations"]
            first, second = (next(row["observation"] for row in worker["host"]["observations"]
                                  if row["stage"] == "tool-contained") for worker in workers.values())
            second["namespaces"] = first["namespaces"].copy()
            return result

        self.stage.run_contained_pool_qualification_stage.side_effect = recycled
        report = controller.run_protected_pool_qualification(self.parent, include_pass_record=True)["pass_record"]
        for name in ("cross_worker_isolation", "provider_only_egress"):
            self.assertEqual(report["behaviors"][name], {"outcome": "passed", "runs": [3]})

    def test_record_cannot_attach_productive_observation_to_calibration_start(self):
        def unrelated(*args, **kwargs):
            result = self._settled_result(*args, **kwargs)
            result["transactions"][0]["qualification_campaign"]["reservation_id"] = self.calibration_start
            return result

        self.stage.run_contained_pool_qualification_stage.side_effect = unrelated
        with self.assertRaisesRegex(controller.QualificationControllerError, "qualification-record-original-run-required"):
            controller.run_protected_pool_qualification(self.parent, include_pass_record=True)

    def test_owner_only_input_does_not_follow_a_symlink(self):
        original = self.request_path.rename(self.root / "original.json")
        self.request_path.symlink_to(original)
        self._assert_refused_before_selection("protected-file-permissions")
