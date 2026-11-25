from contextlib import ExitStack
from dataclasses import replace
from hashlib import sha256
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from time import monotonic
from types import ModuleType
import unittest
from unittest import mock

from cwo_core import native_live_availability as availability
from cwo_core import native_pool_qualification_stage as stage
from cwo_core.native_pool_deferred_attestation import attest_deferred_turn, verify_deferred_startup
from cwo_core.native_pool_deferred_context import (
    QUALIFICATION_ADAPTER_VERSION,
    QUALIFICATION_EFFORT,
    QUALIFICATION_MODEL,
    QUALIFICATION_PROFILE,
    QUALIFICATION_SURFACE,
    QUALIFICATION_TIER,
    QUALIFICATION_TOOL,
    QUALIFICATION_WRITE_COMMAND,
)
from cwo_core.native_pool_transaction import NativePoolInfrastructureError, NativePoolTransactionError, TransactionJournal

from tests import test_native_pool_admission_contracts as admitted_fixtures
from tests.test_native_pool_qualification_stage import (
    _active_fixture, _preparation_and_runs, _qualification_effect_events, _run_attempt,
)
from tests.test_native_pool_qualification_budget import record_fixture_starts


def _digest(text):
    return sha256(text.encode()).hexdigest()


def _approve_accounting(accounting, binding, *, calibrations=(), campaign_start_limit=20):
    approval = stage._CampaignApproval(binding, _digest("inert signed campaign action"), accounting.expires_at,
                                       calibrations, os.getpid(), None, stage._CAMPAIGN_APPROVAL_TOKEN,
                                       campaign_start_limit=campaign_start_limit)
    return replace(accounting, _approval=approval)


def _exchange(request):
    return {"request_id": request, "request_sha256": _digest(f"request-{request}"),
            "response_sha256": _digest(f"response-{request}")}


class _FixtureObservations:
    def __init__(self, run, harness):
        self.run = run
        self.harness = harness
        self.startups = {}

    def startup(self, limits, child, allocation):
        plan = self.run.plan
        child_id = child["child_id"]
        thread_id = allocation["session_id"]
        original = next(row for row in self.harness.launch.preflight_request["children"] if row["child_id"] == child_id)
        root = Path(original["worktree"])
        path = self.run.journal_path.parent / f"{thread_id}.jsonl"
        existing = child_id == self.run.plan["children"][0]["child_id"]
        readback = {
            "model": QUALIFICATION_MODEL, "effort": QUALIFICATION_EFFORT, "service_tier": QUALIFICATION_TIER,
            "profile": QUALIFICATION_PROFILE, "worktree": str(root), "session_path": str(path),
            "epoch": _digest(thread_id), "owner_identity_sha256": _digest(f"owner-{thread_id}"),
            "worktree_identity_sha256": child["worktree_identity_sha256"], "thread_id": thread_id,
            "session_sha256": _digest(f"startup-prefix-{thread_id}") if existing else None,
            "session_source_identity_sha256": _digest(f"file-{thread_id}") if existing else None,
            "thread_start": _exchange(1),
        }
        startup = verify_deferred_startup(
            plan, journal=TransactionJournal(self.run.journal_path, plan["transaction_id"]), child_id=child_id,
            approved_plan_sha256=plan["plan_sha256"],
            trusted_factories={plan["runtime_adapter_path"]: plan["runtime_adapter_sha256"]}, readback=readback,
            worktree=root, session_path=path, connection_epoch_sha256=readback["epoch"], effort=QUALIFICATION_EFFORT,
            profile=QUALIFICATION_PROFILE, prompt_sha256=_digest(self.harness.launch.task_inputs[child_id]),
            deadline=limits.deadline,
        )
        self.startups[child_id] = startup
        return startup

    def prove(self, limits, child_id, thread_id, turn_id):
        startup = self.startups[child_id]
        turn = {"child_id": child_id, "thread_id": thread_id, "turn_id": turn_id}
        observation = {"thread_id": thread_id, "turn_id": turn_id, "epoch": startup.connection_epoch_sha256,
                       "owner_identity_sha256": startup.owner_identity_sha256}
        pending = {**observation, "request_id": 1, "request_sha256": _digest(f"pending-{turn_id}"),
                   "tool": QUALIFICATION_TOOL, "arguments": {"command": QUALIFICATION_WRITE_COMMAND}}
        evidence = {
            **observation, "session_path": startup.session_path,
            "startup_to_turn": {
                "thread_start": _exchange(1),
                "turn_start": {**_exchange(2), "turn_id": turn_id, "prompt_sha256": startup.prompt_sha256},
                "turn_context": {"turn_id": turn_id, "model": startup.model, "effort": startup.effort},
                "turn_context_index": 1,
                "startup_rollout_prefix_sha256": startup.startup_rollout_sha256,
            },
            "terminal_boundary": {"record_count": 2, "source_identity_sha256": _digest(f"file-{thread_id}"),
                                  "boundary_sha256": _digest(f"prefix-{thread_id}")},
        }
        limits.record_provisional_turn_proof(attest_deferred_turn(startup, turn_ack=turn, evidence=evidence,
                                                                 pending_callback=pending))


def _registered_fixture(root, stack, *, omit_proof=False, original_launches=None):
    path = root / "registered_pool_qualification.py"
    source = 'def build_pool_qualification_runtime(plan, *, assembled):\n    return assembled\n'
    path.write_text(source, encoding="utf-8")
    module = ModuleType("registered_pool_qualification")
    exec(compile(source, str(path), "exec"), module.__dict__)
    stack.enter_context(mock.patch.dict(sys.modules, {module.__name__: module}))
    stack.enter_context(mock.patch.object(stage, "_registered_factory_path", return_value=path))

    original_payload = admitted_fixtures.capability_payload
    with mock.patch.object(admitted_fixtures, "capability_payload", side_effect=lambda **kwargs: {
            **original_payload(**kwargs), "execution_surface": QUALIFICATION_SURFACE,
            "adapter_version": QUALIFICATION_ADAPTER_VERSION}):
        preparation, runs, harnesses, _, accounting = _preparation_and_runs(root, model=QUALIFICATION_MODEL, factory_path=path)
    stack.enter_context(mock.patch.object(stage, "contained_campaign_ledger_root", return_value=accounting.ledger.root))
    accounting.ledger.open_budget(stage.CAMPAIGN_BUDGET_ID, {"starts": 20}, scope_sha256=stage.CAMPAIGN_SCOPE_SHA256)
    active = []
    for run, harness in zip(runs, harnesses):
        if original_launches is not None:
            original_launches.append(harness.launch)
        observations = _FixtureObservations(run, harness)
        bound = _active_fixture(run, harness, startup=observations.startup,
                                observe=None if omit_proof else observations.prove,
                                authorize_writer=_authorize_writer)
        selection = stage.select_contained_pool_runtime(bound.plan, module.build_pool_qualification_runtime,
                                                        assembled=(bound.runtime, bound.bind_limits, bound.cleanup))
        active.append(stage.make_pool_qualification_run(bound.plan, selection, journal_path=bound.journal_path,
                                                        fixture_root=bound.fixture_root))
    binding = stage.pool_qualification_binding(preparation, active, accounting=accounting)
    return preparation, active, _approve_accounting(accounting, binding)


def _authorize_writer(limits, child_id, thread_id, turn_id, write):
    limits.authorize_writer(child_id, thread_id, turn_id, 1, _digest(f"pending-{turn_id}"), write)


class ContainedPoolStageTests(unittest.TestCase):
    @mock.patch.object(availability, "POOL_QUALIFICATION_AVAILABLE", True)
    def test_open_source_still_requires_signed_stage_before_accounting(self):
        forged = stage.PoolQualificationAccounting(None, 1, object.__new__(stage._CampaignApproval))
        with mock.patch.object(stage, "_ledger_root", side_effect=AssertionError("accounting reached")) as ledger:
            for accounting in (None, forged):
                with self.assertRaisesRegex(NativePoolTransactionError, "signed-campaign-approval-required"):
                    stage.run_contained_pool_qualification_stage(None, (), approved_binding="a" * 64,
                                                                 accounting=accounting)
            ledger.assert_not_called()

    def _run_fixture(self, *, omit_proof):
        with TemporaryDirectory() as temporary, ExitStack() as stack:
            preparation, runs, accounting = _registered_fixture(Path(temporary), stack, omit_proof=omit_proof)
            binding = stage.pool_qualification_binding(preparation, runs, accounting=accounting)
            result = stage.run_contained_pool_qualification_stage(preparation, runs, approved_binding=binding,
                                                                  accounting=accounting)
            return result, [_qualification_effect_events(run, accounting) for run in runs if run.journal_path.exists()]

    @mock.patch.object(availability, "POOL_QUALIFICATION_AVAILABLE", False)
    def test_qualification_hold_precedes_access_to_parent_inputs(self):
        preparation, runs, accounting = (mock.MagicMock() for _ in range(3))
        with self.assertRaisesRegex(availability.NativeLiveUnavailable, "native-pool-qualification-unavailable"):
            stage.run_contained_pool_qualification_stage(preparation, runs, approved_binding="untrusted",
                                                         accounting=accounting)
        for value in (preparation, runs, accounting):
            self.assertEqual(value.mock_calls, [])

    @mock.patch.object(availability, "REGISTERED_N1_LIVE_AVAILABLE", True)
    @mock.patch.object(availability, "POOL_QUALIFICATION_AVAILABLE", True)
    def test_good_plan_hash_cannot_select_an_arbitrary_runtime(self):
        with TemporaryDirectory() as temporary:
            _, runs, _, _, _ = _preparation_and_runs(Path(temporary))
            factory = mock.Mock(return_value=runs[0].runtime)
            with self.assertRaisesRegex(NativePoolTransactionError, "registered-factory-required"):
                stage.select_contained_pool_runtime(runs[0].plan, factory)
            factory.assert_not_called()

    @mock.patch.object(availability, "REGISTERED_N1_LIVE_AVAILABLE", True)
    @mock.patch.object(availability, "POOL_QUALIFICATION_AVAILABLE", True)
    def test_regular_approval_does_not_admit_contained_cohorts(self):
        with TemporaryDirectory() as temporary:
            preparation, runs, _, _, accounting = _preparation_and_runs(Path(temporary))
            binding = stage.pool_qualification_binding(preparation, runs, accounting=accounting)
            with (mock.patch.object(stage, "contained_campaign_ledger_root", return_value=accounting.ledger.root),
                  self.assertRaisesRegex(NativePoolTransactionError, "contained-runtime-required")):
                stage.run_contained_pool_qualification_stage(preparation, runs, approved_binding=binding,
                                                             accounting=_approve_accounting(accounting, binding))
            self.assertFalse(any(run.journal_path.exists() for run in runs))

    @mock.patch.object(availability, "REGISTERED_N1_LIVE_AVAILABLE", True)
    @mock.patch.object(availability, "POOL_QUALIFICATION_AVAILABLE", True)
    def test_all_original_pending_proofs_precede_any_debit_for_n2_and_n3(self):
        result, cohorts = self._run_fixture(omit_proof=False)
        self.assertEqual(result["outcome"], "completed", result)
        self.assertEqual([row["qualification_campaign"]["runs_consumed"] for row in result["transactions"]], [1, 2])
        for size, events in zip((2, 3), cohorts, strict=True):
            proofs = [row for row in events if row["event_type"] == "qualification-provisional-turn-proof"]
            debits = [row for row in events if row["event_type"] == "qualification-tool-debit"]
            self.assertEqual((len(proofs), len(debits)), (size, size))
            self.assertLess(max(row["sequence"] for row in proofs), min(row["sequence"] for row in debits))

    @mock.patch.object(availability, "REGISTERED_N1_LIVE_AVAILABLE", True)
    @mock.patch.object(availability, "POOL_QUALIFICATION_AVAILABLE", True)
    def test_missing_original_proof_stops_before_debit_and_next_cohort(self):
        with TemporaryDirectory() as temporary, ExitStack() as stack:
            preparation, (n2, n3), accounting = _registered_fixture(Path(temporary), stack, omit_proof=True)
            binding = stage.pool_qualification_binding(preparation, (n2, n3), accounting=accounting)
            with self.assertRaisesRegex(NativePoolTransactionError, "turn-proof-before-debit-required"):
                stage.run_contained_pool_qualification_stage(preparation, (n2, n3), approved_binding=binding,
                                                             accounting=accounting)
            self.assertEqual(accounting.ledger.summary(stage.CAMPAIGN_BUDGET_ID)["charged"], {"starts": 1})
            self.assertEqual(TransactionJournal(n2.journal_path, n2.plan["transaction_id"]).current_state, "CONTAINED")
            self.assertFalse(n3.journal_path.exists())
            self.assertFalse(tuple(n2.fixture_root.glob("*/result-*.txt")))
            events = _qualification_effect_events(n2, accounting)
            self.assertNotIn("qualification-tool-debit", [row["event_type"] for row in events])

    @mock.patch.object(availability, "REGISTERED_N1_LIVE_AVAILABLE", True)
    @mock.patch.object(availability, "POOL_QUALIFICATION_AVAILABLE", True)
    def test_parent_cannot_substitute_the_registered_runtime_hooks(self):
        with TemporaryDirectory() as temporary, ExitStack() as stack:
            preparation, (n2, n3), accounting = _registered_fixture(Path(temporary), stack)
            modified = replace(n2, cleanup=mock.Mock(return_value=True))
            with self.assertRaisesRegex(NativePoolTransactionError, "contained-runtime-hooks-mismatch"):
                stage.pool_qualification_binding(preparation, (modified, n3), accounting=accounting)

    @mock.patch.object(availability, "REGISTERED_N1_LIVE_AVAILABLE", True)
    @mock.patch.object(availability, "POOL_QUALIFICATION_AVAILABLE", True)
    def test_signed_cutoff_refuses_session_intent_and_preserves_original_cleanup(self):
        with TemporaryDirectory() as temporary, ExitStack() as stack:
            preparation, (n2, n3), accounting = _registered_fixture(Path(temporary), stack)
            clock = [99]
            accounting.ledger.clock = lambda: clock[0]
            original = stage.PoolQualificationRunLimits.before_session
            admitted = []
            tick = monotonic()
            stack.enter_context(mock.patch.object(stage, "monotonic", return_value=tick))
            stack.enter_context(mock.patch("cwo_core.native_pool_deferred_context.monotonic", return_value=tick))

            def cross_signed_cutoff(limits, child_id):
                clock[0] = 101
                original(limits, child_id)
                admitted.append(child_id)

            stack.enter_context(mock.patch.object(stage.PoolQualificationRunLimits, "before_session", cross_signed_cutoff))
            binding = stage.pool_qualification_binding(preparation, (n2, n3), accounting=accounting)
            with self.assertRaises(NativePoolInfrastructureError) as refusal:
                stage.run_contained_pool_qualification_stage(preparation, (n2, n3), approved_binding=binding,
                                                             accounting=accounting)
            self.assertRegex(str(refusal.exception.__cause__), "run-deadline-expired")
            self.assertFalse(admitted)
            self.assertFalse(n3.journal_path.exists())
            self.assertEqual(accounting.ledger.summary(stage.CAMPAIGN_BUDGET_ID)["charged"], {"starts": 1})
            attempt = _run_attempt(n2, accounting)
            self.assertEqual(attempt["charge"], preparation["per_run_limits"])
            self.assertEqual(attempt["state"], "terminal")
            n2.cleanup.assert_called_once()
            events = _qualification_effect_events(n2, accounting)
            self.assertNotIn("qualification-session-intent", [row["event_type"] for row in events])
            self.assertEqual(events[-1]["event_type"], "qualification-effects-settled")
            self.assertTrue(events[-1]["details"]["cleanup_confirmed"])

    @mock.patch.object(availability, "REGISTERED_N1_LIVE_AVAILABLE", True)
    @mock.patch.object(availability, "POOL_QUALIFICATION_AVAILABLE", True)
    def test_signed_cutoff_refuses_writer_after_debit_and_preserves_original_charge(self):
        with TemporaryDirectory() as temporary, ExitStack() as stack:
            preparation, (n2, n3), accounting = _registered_fixture(Path(temporary), stack)
            clock = [90]
            accounting.ledger.clock = lambda: clock[0]
            original = stage.PoolQualificationRunLimits._append
            writer_attempts = []

            def at_signed_cutoff(limits, event, details, **kwargs):
                if event == "writer-release":
                    writer_attempts.append(details["child_id"])
                    clock[0] = accounting.expires_at
                return original(limits, event, details, **kwargs)

            stack.enter_context(mock.patch.object(stage.PoolQualificationRunLimits, "_append", at_signed_cutoff))
            binding = stage.pool_qualification_binding(preparation, (n2, n3), accounting=accounting)
            with self.assertRaisesRegex(NativePoolTransactionError, "run-deadline-expired"):
                stage.run_contained_pool_qualification_stage(preparation, (n2, n3), approved_binding=binding,
                                                             accounting=accounting)
            self.assertTrue(writer_attempts)
            self.assertFalse(tuple(n2.fixture_root.glob("*/result-*.txt")))
            self.assertFalse(n3.journal_path.exists())
            self.assertEqual(accounting.ledger.summary(stage.CAMPAIGN_BUDGET_ID)["charged"], {"starts": 1})
            attempt = _run_attempt(n2, accounting)
            self.assertEqual(attempt["charge"], preparation["per_run_limits"])
            self.assertEqual(attempt["state"], "reconciliation-required")
            n2.cleanup.assert_called_once()
            events = _qualification_effect_events(n2, accounting)
            types = [row["event_type"] for row in events]
            self.assertEqual(types.count("qualification-tool-debit"), 2)
            self.assertNotIn("qualification-writer-release", types)
            self.assertEqual(events[-1]["event_type"], "qualification-effects-settled")
            self.assertTrue(events[-1]["details"]["cleanup_confirmed"])

    @mock.patch.object(availability, "REGISTERED_N1_LIVE_AVAILABLE", True)
    @mock.patch.object(availability, "POOL_QUALIFICATION_AVAILABLE", True)
    def test_campaign_cap_refuses_new_cohorts_after_a_prior_charge(self):
        with TemporaryDirectory() as temporary, ExitStack() as stack:
            preparation, runs, accounting = _registered_fixture(Path(temporary), stack)
            ledger = accounting.ledger
            record_fixture_starts(ledger, 19)
            binding = stage.pool_qualification_binding(preparation, runs, accounting=accounting)
            with self.assertRaisesRegex(NativePoolTransactionError, "campaign-start-cap-exhausted"):
                stage.run_contained_pool_qualification_stage(preparation, runs, approved_binding=binding,
                                                             accounting=accounting)
            self.assertFalse(any(run.journal_path.exists() for run in runs))
            self.assertEqual(ledger.summary(stage.CAMPAIGN_BUDGET_ID)["charged"], {"starts": 19})
