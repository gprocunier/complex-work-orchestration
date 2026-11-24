from __future__ import annotations

from contextlib import ExitStack
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import tempfile
from threading import Barrier, Event, Thread
from time import monotonic
import unittest
from unittest import mock

from tests import test_native_pool_admission_contracts as admitted_fixtures
import prepare_native_pool_qualification as preparation_cli
from tests.test_native_pool_config import RenderFixture
from tests.test_native_pool_transaction import (
    MODEL,
    FakeClock,
    RuntimeHarness,
    _execution_inputs,
    _live,
    bead,
    transaction_plan,
)
from cwo_core import native_live_availability
from cwo_core.invocation_ledger import InvocationLedger, InvocationLedgerError, request_sha256
from cwo_core.native_pool_contracts import canonical_sha256, seal_artifact, write_private_artifact
from cwo_core.native_pool_leases import PoolLeaseRegistry
from cwo_core.native_pool_preflight import run_pool_preflight
from cwo_core.native_pool_qualification_stage import (
    POOL_QUALIFICATION_SEED,
    PoolQualificationAccounting,
    PoolQualificationRun,
    fixed_pool_qualification_cohorts,
    pool_qualification_binding,
    run_pool_qualification_stage as _run_protected_stage,
)
from cwo_core.native_pool_transaction import (
    AdmittedPoolLaunch,
    NativePoolInfrastructureError,
    NativePoolTransactionError,
    TransactionJournal,
    seal_transaction_plan,
)
from cwo_core.native_pool_workspace import capture_workspace_snapshot
from cwo_core.native_tool_isolation import (
    _CONTAINED_POOL_TOKEN,
    _ContainedPoolChild,
    _ContainedPoolToolScope,
    _contained_pool_tool_validation,
    contained_pool_tool_policy,
    contained_pool_tool_surface,
)
from cwo_core.qualification_target import selected_target


def _fixture(root, cohort, fixture_root, *, model=MODEL, factory_path=None):
    root.mkdir()
    tasks = cohort["tasks"]

    def render(path, size):
        fixture = RenderFixture(path, size)
        fixture.integration = fixture_root / "integration"
        fixture.request["integration_root"] = str(fixture.integration)
        fixture.worktrees = [fixture_root / task["worker_slot"] for task in tasks]
        contained_children = {}
        for child, task, worktree in zip(fixture.request["children"], tasks, fixture.worktrees):
            child["worktree"] = str(worktree)
            child["declared_write_paths"] = child["integration_target_paths"] = [task["write_path"]]
            control_path = Path(child["control_contract_file"])
            control = json.loads(control_path.read_text(encoding="utf-8"))
            control["task_sha256"] = hashlib.sha256(task["prompt"].encode()).hexdigest()
            write_private_artifact(control_path, seal_artifact(control, "contract_sha256"))
            if factory_path is not None:
                child["tool_policy"] = contained_pool_tool_policy()
                snapshot = capture_workspace_snapshot(worktree, allowed_paths=[task["write_path"]])
                contained_children[child["child_id"]] = _ContainedPoolChild(str(worktree),
                    canonical_sha256(snapshot["identity"]), task["write_path"], task["prompt"])
        if factory_path is not None:
            scope = _ContainedPoolToolScope(contained_children, model, lambda: None, _CONTAINED_POOL_TOKEN)
            stack.enter_context(_contained_pool_tool_validation(scope))
        return fixture

    prompts = [task["prompt"] for task in tasks]
    with ExitStack() as stack:
        stack.enter_context(mock.patch.object(admitted_fixtures, "RenderFixture", side_effect=render))
        if factory_path is not None:
            stack.enter_context(mock.patch.object(admitted_fixtures, "build_tool_surface_snapshot",
                                                 side_effect=lambda *_args, **_kwargs: contained_pool_tool_surface()))
        fixture, reservation, contract, request = admitted_fixtures._admitted_artifacts(
            root, size=cohort["size"], requested_model=model, prompts=prompts)
        preflight = run_pool_preflight(request, policy_document=fixture.policy_document)
    controls, _, child_callbacks, adapters, pool_callbacks, _ = _execution_inputs(fixture, contract)
    task_inputs = {child["child_id"]: prompt for child, prompt in zip(contract["children"], prompts)}
    for adapter in adapters.values():
        adapter.decisions = ["continue", "complete"]
    qualification_callbacks = {}
    for child, task, worktree in zip(contract["children"], tasks, fixture.worktrees):
        callbacks = child_callbacks[child["child_id"]]
        write = _fixture_writer(task, worktree)
        qualification_callbacks[child["child_id"]] = callbacks["send_input"], write
        callbacks["send_input"] = _write_on_send(callbacks["send_input"], write)
    journal = root / "transaction-journal.jsonl"
    launch = AdmittedPoolLaunch(
        reservation, fixture.admission_capability, contract, request, preflight, controls, task_inputs, child_callbacks,
        {
            "claim_adapter": fixture.claim_adapter,
            "live_revalidate": _live,
            "pool_callbacks": pool_callbacks,
            "lease_registry": PoolLeaseRegistry(root / "leases.json", owner_alive=lambda _owner: True,
                                                now=FakeClock.now_utc),
            "state_file": root / "pool-state.json",
            "capability_receipt": fixture.pool_capability_receipt,
            "policy_document": fixture.policy_document,
        },
    )
    issues = []
    for child in contract["children"]:
        path, = child["declared_write_paths"]
        issue = bead(child["bead_id"], path)
        issue["metadata"]["cwo_ready_set_admission"]["aggregate_hard_budget"] = dict(contract["aggregate_hard_budget"])
        issues.append(issue)
    plan = transaction_plan(root / "transaction", issues)
    plan["selected_model"] = model
    if factory_path is not None:
        plan.update(runtime_adapter_path=str(factory_path), runtime_adapter_sha256=hashlib.sha256(factory_path.read_bytes()).hexdigest())
    for child, admitted in zip(plan["children"], contract["children"]):
        child.update({field: admitted[field] for field in ("child_id", "work_unit_id", "worktree_identity_sha256")})
        child["requested_model"] = model
    plan = seal_transaction_plan(plan)
    harness = RuntimeHarness(plan, issues, clock=lambda: datetime.now(timezone.utc), launch=launch)
    harness.qualification_callbacks = qualification_callbacks
    return PoolQualificationRun(plan, harness.runtime(), journal, fixture_root=fixture_root), harness, adapters


def _fixture_writer(task, worktree):
    def write():
        (worktree / task["write_path"]).write_bytes(task["expected_utf8"].encode("utf-8"))

    return write


def _write_on_send(send_input, write):
    def send(**kwargs):
        write()
        return send_input(**kwargs)

    return send


def _mutate_settlement(kind, options):
    state = options["state_file"]
    if kind == "missing-state":
        state.unlink()
    elif kind == "changed-state":
        value = json.loads(state.read_bytes())
        value["state_sequence"] += 1
        write_private_artifact(state, seal_artifact(value, "state_sha256"))
    else:
        registry = options["lease_registry"].path
        value = json.loads(registry.read_bytes())
        if kind == "missing-lease":
            value["leases"].pop()
        else:
            first = value["leases"][0]
            first["terminal_evidence_sha256"] = "a" * 64
            value["leases"][0] = seal_artifact(first, "lease_sha256")
        write_private_artifact(registry, seal_artifact(value, "registry_sha256"))


def _preparation_and_runs(root, *, model=MODEL, factory_path=None):
    cohorts = fixed_pool_qualification_cohorts()
    fixture_root = root / "fixtures"
    preparation_cli._materialize_fixtures(fixture_root, preparation_cli._prepare(
        1, {"sessions": 3, "tool_calls": 12, "runtime_seconds": 60}))
    n2 = _fixture(root / "n2", cohorts[0], fixture_root / "n2" / "run-1", model=model, factory_path=factory_path)
    n3 = _fixture(root / "n3", cohorts[1], fixture_root / "n3" / "run-1", model=model, factory_path=factory_path)
    caps = {"sessions": 3}
    for field in ("tool_calls", "runtime_seconds"):
        caps[field] = max(group[1].launch.contract["aggregate_hard_budget"][field] for group in (n2, n3))
    preparation = {
        "mode": "prepare-only", "dispatch_authorized": False, "worker_model": MODEL,
        "worker_role": "luna", "target_profile": selected_target()["selection"]["profile"],
        "seed_files": dict(POOL_QUALIFICATION_SEED),
        "cohorts": cohorts, "runs_per_cohort": 1, "per_run_limits": caps,
        "stage_ceiling": {field: value * 2 for field, value in caps.items()},
    }
    ledger_root = root / "qualification-ledger"
    ledger_root.mkdir(mode=0o700)
    accounting = PoolQualificationAccounting(InvocationLedger(ledger_root, clock=lambda: 10), expires_at=100)
    return preparation, (n2[0], n3[0]), (n2[1], n3[1]), (n2[2], n3[2]), accounting


def run_pool_qualification_stage(preparation, runs, **kwargs):
    return _run_protected_stage(preparation, runs, require_active_limits=False, **kwargs)


def _run_stage(preparation, runs, accounting, *, require_active_limits=True):
    return _run_protected_stage(preparation, runs, accounting=accounting, require_active_limits=require_active_limits,
        approved_binding=pool_qualification_binding(preparation, runs, accounting=accounting))


def _active_fixture(run, harness, *, on_debit=None, cleanup=None, serialized=False,
                    startup=None, observe=None, authorize_writer=None):
    current = []
    children = harness.launch.contract["children"]
    receivers, failures = {}, {}

    def start(child, context):
        child_id = child["child_id"]
        current[0].before_session(child_id)
        allocation = run.runtime.start_worker_session(child, context)
        current[0].ack_session(child_id, allocation["session_id"])
        return startup(current[0], child, allocation) if startup is not None else allocation

    def perform_write(write, child_id, thread_id, turn_id):
        limits = current[0]
        if observe is not None:
            observe(limits, child_id, thread_id, turn_id)
        limits.charge_tool(child_id, thread_id, turn_id, 1)
        if on_debit is not None:
            on_debit(limits, child_id, thread_id, turn_id)
        limits.remaining()
        if authorize_writer is None:
            write()
        else:
            authorize_writer(limits, child_id, thread_id, turn_id, write)
        limits.ack_tool(child_id, thread_id, turn_id, 1)

    def receive(write, child_id, thread_id, turn_id):
        try:
            perform_write(write, child_id, thread_id, turn_id)
        except BaseException as failure:
            failures[child_id] = failure

    def wrap_send(send, write, child_id, thread_id):
        def dispatch(**kwargs):
            limits = current[0]
            turn_id = "turn-" + child_id
            limits.before_turn(child_id, thread_id)
            limits.ack_turn(child_id, thread_id, turn_id)
            if serialized:
                perform_write(write, child_id, thread_id, turn_id)
            send(**kwargs)
            if not serialized:
                receiver = Thread(target=receive, args=(write, child_id, thread_id, turn_id), daemon=True)
                receivers[child_id] = receiver
                receiver.start()
            return {"submission_id": turn_id}

        return dispatch

    def wrap_check(check, child_id):
        def observe(**kwargs):
            if len(receivers) < len(children):
                return {"decision": "continue"}
            receiver = receivers[child_id]
            receiver.join(3)
            if receiver.is_alive():
                raise TimeoutError("synthetic fixture receiver did not settle")
            if child_id in failures:
                raise failures[child_id]
            return check(**kwargs)

        return observe

    def settle(cutoff):
        for receiver in receivers.values():
            receiver.join(max(0, cutoff - monotonic()))
        confirmed = cleanup(cutoff) if cleanup is not None else True
        return confirmed and all(not receiver.is_alive() for receiver in receivers.values())

    for child in children:
        child_id = child["child_id"]
        callbacks = harness.launch.child_callbacks[child_id]
        send, write = harness.qualification_callbacks[child_id]
        callbacks["send_input"] = wrap_send(send, write, child_id, child["session_id"])
        if not serialized:
            callbacks["check"] = wrap_check(callbacks["check"], child_id)
    return replace(run, runtime=replace(run.runtime, start_worker_session=start), bind_limits=current.append,
                   cleanup=mock.Mock(side_effect=settle))


def _qualification_effect_events(run, accounting):
    attempt = _run_attempt(run, accounting)
    effect_path = accounting.ledger.root / (attempt["reservation_id"] + ".qualification-effects.jsonl")
    return TransactionJournal(effect_path, run.plan["transaction_id"]).read()


def _run_attempt(run, accounting):
    journal = TransactionJournal(run.journal_path, run.plan["transaction_id"])
    intent, = [event["details"] for event in journal.read() if event["event_type"] == "qualification-accounting-intent"]
    return accounting.ledger.attempt(intent["reservation_id"])


@mock.patch.object(native_live_availability, "POOL_LIVE_AVAILABLE", True)
@mock.patch.object(native_live_availability, "N1_LIVE_AVAILABLE", True)
class PoolQualificationStageTests(unittest.TestCase):
    def test_each_source_hold_precedes_every_callback_and_journal(self):
        for flag, kind in (("POOL_LIVE_AVAILABLE", "pool"), ("N1_LIVE_AVAILABLE", "n1")):
            with self.subTest(flag=flag), mock.patch.object(native_live_availability, flag, False):
                preparation = mock.MagicMock(side_effect=AssertionError("preparation accessed while held"))
                runs = mock.MagicMock(side_effect=AssertionError("runs accessed while held"))
                accounting = mock.MagicMock(side_effect=AssertionError("accounting accessed while held"))
                with self.assertRaisesRegex(native_live_availability.NativeLiveUnavailable, f"native-{kind}-live-unavailable"):
                    run_pool_qualification_stage(preparation, runs, accounting=accounting, approved_binding="untrusted")
                self.assertEqual(preparation.mock_calls, [])
                self.assertEqual(runs.mock_calls, [])
                self.assertEqual(accounting.mock_calls, [])

    def test_ledger_intent_is_durable_before_worker_allocation(self):
        with tempfile.TemporaryDirectory() as temporary:
            preparation, runs, _, _, accounting = _preparation_and_runs(Path(temporary))
            ledger = accounting.ledger
            seen_intents = []

            def observe(run):
                def worker(child, context):
                    events = TransactionJournal(run.journal_path, run.plan["transaction_id"]).read()
                    intent, = [event["details"] for event in events if event["event_type"] == "qualification-accounting-intent"]
                    attempt = ledger.attempt(intent["reservation_id"])
                    self.assertEqual(attempt["request_sha256"], intent["request_sha256"])
                    self.assertEqual(events[-1]["event_type"], "allocation-intent")
                    seen_intents.append(attempt["state"])
                    return run.runtime.start_worker_session(child, context)

                return worker

            runs = tuple(replace(run, runtime=replace(run.runtime,
                        start_worker_session=observe(run))) for run in runs)
            result = run_pool_qualification_stage(preparation, runs,
                accounting=accounting, approved_binding=pool_qualification_binding(preparation, runs, accounting=accounting))
            self.assertEqual(result["outcome"], "completed")
            self.assertEqual(seen_intents, ["invocation-intent"] * 5)
            for run, transaction in zip(runs, result["transactions"]):
                charge = transaction["qualification_accounting"]
                self.assertEqual(charge["charge"], preparation["per_run_limits"])
                self.assertIsNone(charge["observed_usage"])
                events = TransactionJournal(run.journal_path, run.plan["transaction_id"]).read()
                journal_intent, = [event for event in events if event["event_type"] == "qualification-accounting-intent"]
                self.assertEqual(journal_intent["event_sha256"], charge["intent_event_sha256"])
                self.assertEqual(events[-1]["event_sha256"], charge["journal_last_event_sha256"])
            self.assertEqual(ledger.summary(charge["budget_id"])["charged"], preparation["stage_ceiling"])

    def test_active_deadline_covers_preparation_and_cleanup_has_its_own_window(self):
        for limiting_clock in ("runtime", "signed"):
            with self.subTest(limit=limiting_clock), tempfile.TemporaryDirectory() as temporary:
                preparation, runs, harnesses, _, accounting = _preparation_and_runs(Path(temporary))
                runtime_seconds = preparation["per_run_limits"]["runtime_seconds"]
                signed_seconds = 1 if limiting_clock == "signed" else runtime_seconds + 1
                wall_clock = [10]
                accounting.ledger.clock = lambda: wall_clock[0]
                accounting = replace(accounting, expires_at=wall_clock[0] + signed_seconds)
                current = [100.0]
                bound, cleanup_cutoffs = [], []
                run = runs[0]
                expected = min(runtime_seconds, signed_seconds)

                def prepare(plan):
                    limits, = bound
                    self.assertEqual(_run_attempt(run, accounting)["state"], "invocation-intent")
                    self.assertEqual(limits.remaining(), expected)
                    wall_clock[0] -= 1
                    self.assertEqual(limits.remaining(), expected)
                    current[0] = limits.deadline
                    return run.runtime.prepare(plan)

                def cleanup(deadline):
                    cleanup_cutoffs.append(deadline)
                    return True

                first = replace(run, runtime=replace(run.runtime, prepare=prepare), bind_limits=bound.append, cleanup=cleanup)
                with mock.patch("cwo_core.native_pool_qualification_stage.monotonic", side_effect=lambda: current[0]):
                    with self.assertRaisesRegex(NativePoolTransactionError, "run-deadline-expired"):
                        _run_stage(preparation, (first, runs[1]), accounting, require_active_limits=False)
                self.assertEqual(len(cleanup_cutoffs), 1)
                self.assertGreater(cleanup_cutoffs[0], bound[0].deadline)
                self.assertLessEqual(cleanup_cutoffs[0] - bound[0].deadline, 2)
                self.assertEqual([harness.starts for harness in harnesses], [[], []])
                self.assertEqual(_run_attempt(first, accounting)["charge"], preparation["per_run_limits"])
                self.assertFalse(runs[1].journal_path.exists())

    def test_active_unacknowledged_session_intent_holds_original_charge(self):
        with tempfile.TemporaryDirectory() as temporary:
            preparation, runs, harnesses, _, accounting = _preparation_and_runs(Path(temporary))
            bound = []
            cleanup = mock.Mock(return_value=True)
            first = runs[0]

            def lose_session_ack(child, context):
                bound[0].before_session(child["child_id"])
                attempt = _run_attempt(first, accounting)
                effect_path = next(accounting.ledger.root.glob("*.qualification-effects.jsonl"))
                events = TransactionJournal(effect_path, first.plan["transaction_id"]).read()
                self.assertEqual(events[0]["details"]["reservation_id"], attempt["reservation_id"])
                self.assertEqual(events[-1]["event_type"], "qualification-session-intent")
                self.assertEqual(events[-1]["details"]["child_id"], child["child_id"])
                raise ConnectionError("lost synthetic session reply")

            first = replace(first, runtime=replace(first.runtime, start_worker_session=lose_session_ack),
                            bind_limits=bound.append, cleanup=cleanup)
            with self.assertRaisesRegex(NativePoolInfrastructureError, "allocation-acknowledgement-lost") as error:
                _run_stage(preparation, (first, runs[1]), accounting, require_active_limits=False)
            self.assertEqual(str(error.exception.__cause__), "lost synthetic session reply")
            cleanup.assert_called_once()
            attempt = _run_attempt(first, accounting)
            self.assertEqual(attempt["state"], "reconciliation-required")
            self.assertEqual(attempt["charge"], preparation["per_run_limits"])
            self.assertEqual(harnesses[1].starts, [])
            self.assertFalse(runs[1].journal_path.exists())

    def test_active_turn_intent_is_refused_before_original_admitted_send(self):
        for phase in ("last-allocation", "bind"):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as temporary:
                preparation, runs, harnesses, _, accounting = _preparation_and_runs(Path(temporary))
                bound = []
                first, second = tuple(_active_fixture(run, harness) for run, harness in zip(runs, harnesses))
                original_runtime, bind_limits = first.runtime, first.bind_limits
                last_child = first.plan["children"][-1]["child_id"]

                def bind(limits):
                    bound.append(limits)
                    bind_limits(limits)

                def start_worker(child, context):
                    allocation = original_runtime.start_worker_session(child, context)
                    if phase == "last-allocation" and child["child_id"] == last_child:
                        bound[0].before_turn(last_child, allocation["session_id"])
                    return allocation

                def bind_launch(plan, allocations, context):
                    if phase == "bind":
                        last = allocations[-1]
                        bound[0].before_turn(last["child_id"], last["session_id"])
                    return original_runtime.bind_admitted_launch(plan, allocations, context)

                first = replace(first, bind_limits=bind, runtime=replace(original_runtime,
                    start_worker_session=start_worker, bind_admitted_launch=bind_launch))
                with self.assertRaises((NativePoolTransactionError, NativePoolInfrastructureError)) as caught:
                    _run_stage(preparation, (first, second), accounting)
                cause = caught.exception.__cause__ or caught.exception
                self.assertRegex(str(cause), "turn-dispatch-not-active")
                events = _qualification_effect_events(first, accounting)
                self.assertEqual([event["event_type"] for event in events].count("qualification-session-ack"), 2)
                self.assertNotIn("qualification-turn-intent", [event["event_type"] for event in events])
                self.assertEqual(harnesses[1].starts, [])

    def test_active_dispatch_requires_the_original_acknowledged_turn_id(self):
        with tempfile.TemporaryDirectory() as temporary:
            preparation, runs, harnesses, _, accounting = _preparation_and_runs(Path(temporary))
            first, second = tuple(_active_fixture(run, harness) for run, harness in zip(runs, harnesses))
            child_id = first.plan["children"][0]["child_id"]
            callbacks = harnesses[0].launch.child_callbacks[child_id]
            send = callbacks["send_input"]

            def wrong_ack(**kwargs):
                send(**kwargs)
                return {"submission_id": "another-turn"}

            callbacks["send_input"] = wrong_ack
            with self.assertRaisesRegex(NativePoolTransactionError, "turn-dispatch-ack-binding-refused"):
                _run_stage(preparation, (first, second), accounting)
            events = _qualification_effect_events(first, accounting)
            self.assertEqual(events[-1]["details"]["pending"]["turns"], [child_id])
            self.assertNotIn("qualification-tool-overlap-release", [row["event_type"] for row in events])
            self.assertEqual(list(first.fixture_root.glob("*/result-*.txt")), [])
            self.assertEqual(_run_attempt(first, accounting)["state"], "reconciliation-required")
            self.assertEqual(harnesses[1].starts, [])

    def test_active_effect_journal_refuses_a_preexisting_symlink_or_fifo(self):
        for kind in ("symlink", "fifo"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                preparation, runs, harnesses, _, accounting = _preparation_and_runs(root)
                active = tuple(_active_fixture(run, harness) for run, harness in zip(runs, harnesses))
                ledger = accounting.ledger
                original_begin = ledger.begin_invocation
                reservations = []

                def begin(reservation_id, request_bytes):
                    reservations.append(reservation_id)
                    path = ledger.root / (reservation_id + ".qualification-effects.jsonl")
                    if kind == "symlink":
                        path.symlink_to(root / "original-target")
                    else:
                        os.mkfifo(path)
                    return original_begin(reservation_id, request_bytes)

                def refuse_effect_open(path, transaction_id):
                    self.assertFalse(Path(path).name.endswith(".qualification-effects.jsonl"))
                    return TransactionJournal(path, transaction_id)

                with mock.patch.object(ledger, "begin_invocation", side_effect=begin), mock.patch(
                        "cwo_core.native_pool_qualification_stage.TransactionJournal", side_effect=refuse_effect_open):
                    with self.assertRaisesRegex(NativePoolTransactionError, "active-effect-journal-not-fresh"):
                        _run_stage(preparation, active, accounting)
                reservation_id, = reservations
                self.assertEqual(ledger.attempt(reservation_id)["state"], "reconciliation-required")
                self.assertFalse((root / "original-target").exists())
                self.assertEqual([harness.starts for harness in harnesses], [[], []])

    def test_protected_stage_refuses_unbound_run_before_opening_the_budget(self):
        with tempfile.TemporaryDirectory() as temporary:
            preparation, runs, harnesses, _, accounting = _preparation_and_runs(Path(temporary))
            with self.assertRaisesRegex(NativePoolTransactionError, "active-run-hooks-required"):
                _run_protected_stage(preparation, runs, accounting=accounting,
                    approved_binding=pool_qualification_binding(preparation, runs, accounting=accounting))
            self.assertEqual([harness.starts for harness in harnesses], [[], []])
            self.assertEqual(list(accounting.ledger.root.iterdir()), [])

    def test_active_effect_intents_are_durable_before_n2_and_n3_fixture_writes(self):
        with tempfile.TemporaryDirectory() as temporary:
            preparation, runs, harnesses, _, accounting = _preparation_and_runs(Path(temporary))
            charges = []

            def observe(run, harness):
                def before_write(limits, child_id, thread_id, turn_id):
                    child = next(row for row in run.plan["children"] if row["child_id"] == child_id)
                    admitted = next(row for row in harness.launch.preflight_request["children"] if row["child_id"] == child_id)
                    self.assertFalse((Path(admitted["worktree"]) / child["write_paths"][0]).exists())
                    events = _qualification_effect_events(run, accounting)
                    release, = [row for row in events if row["event_type"] == "qualification-tool-overlap-release"]
                    pending = events[:release["sequence"]]
                    self.assertNotIn("qualification-tool-ack", [row["event_type"] for row in pending])
                    debits = {row["details"]["child_id"]: row for row in pending
                              if row["event_type"] == "qualification-tool-debit"}
                    self.assertEqual(debits.keys(), {row["child_id"] for row in run.plan["children"]})
                    self.assertEqual(release["details"]["pending_debits"],
                                     {key: [row["event_sha256"]] for key, row in debits.items()})
                    detail = debits[child_id]["details"]
                    self.assertEqual((detail["thread_id"], detail["turn_id"], detail["request_id"]), (thread_id, turn_id, 1))
                    for key, debit in debits.items():
                        turn, = [row for row in pending if row["event_type"] == "qualification-turn-ack"
                                 and row["details"]["child_id"] == key]
                        self.assertEqual({field: debit["details"][field] for field in turn["details"]}, turn["details"])
                        self.assertLess(turn["sequence"], debit["sequence"])
                    self.assertEqual(_run_attempt(run, accounting)["state"], "invocation-intent")
                    charges.append((len(debits), detail["tool_calls"]))

                return before_write

            active = tuple(_active_fixture(run, harness, on_debit=observe(run, harness))
                           for run, harness in zip(runs, harnesses))
            result = _run_stage(preparation, active, accounting)
            self.assertEqual(result["outcome"], "completed", result)
            self.assertEqual(sorted(charges), [(2, 1), (2, 2), (3, 1), (3, 2), (3, 3)])
            for run, transaction in zip(active, result["transactions"]):
                summary = transaction["qualification_accounting"]
                self.assertEqual((summary["mode"], summary["state"], summary["outcome"]),
                                 ("active", "terminal", "completed"))
                self.assertEqual(summary["charge"], preparation["per_run_limits"])
                self.assertIsNone(summary["observed_usage"])
                events = _qualification_effect_events(run, accounting)
                self.assertEqual(events[0]["details"]["transaction_intent_event_sha256"], summary["intent_event_sha256"])
                self.assertEqual(events[-1]["event_sha256"], summary["effect_journal_last_event_sha256"])
                self.assertEqual(events[-1]["details"]["transaction_last_event_sha256"], summary["journal_last_event_sha256"])
                self.assertEqual(events[-1]["details"]["pending"], {"sessions": [], "turns": [], "tools": []})
                run.cleanup.assert_called_once()

    def test_active_serialized_tool_callbacks_refuse_before_fixture_writes(self):
        with tempfile.TemporaryDirectory() as temporary:
            preparation, runs, harnesses, _, accounting = _preparation_and_runs(Path(temporary))
            first = _active_fixture(runs[0], harnesses[0], serialized=True)
            second = _active_fixture(runs[1], harnesses[1])
            with self.assertRaisesRegex(NativePoolTransactionError, "tool-overlap-required"):
                _run_stage(preparation, (first, second), accounting)

            self.assertEqual(list(first.fixture_root.glob("*/result-*.txt")), [])
            events = _qualification_effect_events(first, accounting)
            self.assertNotIn("qualification-tool-overlap-release", [row["event_type"] for row in events])
            self.assertNotIn("qualification-tool-ack", [row["event_type"] for row in events])
            self.assertEqual(len(events[-1]["details"]["pending"]["tools"]), 1)
            self.assertEqual(events[-1]["details"]["refusal"], "tool-overlap-required")
            attempt = _run_attempt(first, accounting)
            self.assertEqual(attempt["state"], "reconciliation-required")
            self.assertEqual(attempt["charge"], preparation["per_run_limits"])
            first.cleanup.assert_called_once()
            self.assertEqual(harnesses[1].starts, [])

    def test_active_overlap_release_failure_leaves_every_debit_unacknowledged(self):
        for failure in ("journal", "deadline"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                preparation, runs, harnesses, _, accounting = _preparation_and_runs(Path(temporary))
                first, second = tuple(_active_fixture(run, harness) for run, harness in zip(runs, harnesses))
                append = TransactionJournal.append
                expired = Event()
                release_attempts = []

                def interrupt_release(journal, *, event_type, **kwargs):
                    if event_type != "qualification-tool-overlap-release":
                        return append(journal, event_type=event_type, **kwargs)
                    release_attempts.append(event_type)
                    if failure == "journal":
                        raise OSError("synthetic release journal failure")
                    row = append(journal, event_type=event_type, **kwargs)
                    expired.set()
                    return row

                def now():
                    return monotonic() + (preparation["per_run_limits"]["runtime_seconds"] if expired.is_set() else 0)

                reason = "active-effect-journal-refused" if failure == "journal" else "run-deadline-expired"
                with mock.patch.object(TransactionJournal, "append", autospec=True, side_effect=interrupt_release), \
                     mock.patch("cwo_core.native_pool_qualification_stage.monotonic", side_effect=now), \
                     self.assertRaisesRegex(NativePoolTransactionError, reason):
                    _run_stage(preparation, (first, second), accounting)

                self.assertEqual(release_attempts, ["qualification-tool-overlap-release"])
                events = _qualification_effect_events(first, accounting)
                types = [row["event_type"] for row in events]
                self.assertEqual(types.count("qualification-tool-debit"), 2)
                self.assertEqual(types.count("qualification-tool-overlap-release"), int(failure == "deadline"))
                self.assertNotIn("qualification-tool-ack", types)
                self.assertEqual(list(first.fixture_root.glob("*/result-*.txt")), [])
                attempt = _run_attempt(first, accounting)
                self.assertEqual(attempt["state"], "reconciliation-required")
                self.assertEqual(attempt["charge"], preparation["per_run_limits"])
                first.cleanup.assert_called_once()
                self.assertEqual(harnesses[1].starts, [])

    def test_active_unconfirmed_cleanup_or_lease_stops_stage_and_retains_allowance(self):
        for missing in ("cleanup", "lease"):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as temporary:
                preparation, runs, harnesses, _, accounting = _preparation_and_runs(Path(temporary))
                run = runs[0]

                def validate(launched, context):
                    if missing == "lease":
                        _mutate_settlement("missing-lease", harnesses[0].launch.keyword_arguments)
                    return run.runtime.validate(launched, context)

                first = replace(run, runtime=replace(run.runtime, validate=validate))
                first = _active_fixture(first, harnesses[0], cleanup=mock.Mock(return_value=missing != "cleanup"))
                second = _active_fixture(runs[1], harnesses[1])
                result = _run_stage(preparation, (first, second), accounting)
                self.assertEqual(result["outcome"], "stopped")
                transaction, = result["transactions"]
                self.assertFalse(transaction["accepted"])
                self.assertEqual(transaction["qualification_accounting"]["state"], "reconciliation-required")
                self.assertEqual(_run_attempt(first, accounting)["charge"], preparation["per_run_limits"])
                self.assertEqual(harnesses[1].starts, [])
                second.cleanup.assert_not_called()

    def test_active_cleanup_precedes_final_lease_readback(self):
        with tempfile.TemporaryDirectory() as temporary:
            preparation, runs, harnesses, _, accounting = _preparation_and_runs(Path(temporary))

            def drop_lease(_cutoff):
                _mutate_settlement("missing-lease", harnesses[0].launch.keyword_arguments)
                return True

            cleanup = mock.Mock(side_effect=drop_lease)
            first = _active_fixture(runs[0], harnesses[0], cleanup=cleanup)
            second = _active_fixture(runs[1], harnesses[1])
            result = _run_stage(preparation, (first, second), accounting)

            self.assertEqual(result["outcome"], "stopped")
            transaction, = result["transactions"]
            self.assertTrue(transaction["launch_result"]["pool_receipt"]["accepting"])
            self.assertFalse(transaction["accepted"])
            checks = transaction["validation"]["qualification_active_limits"]
            self.assertTrue(checks["cleanup_confirmed"])
            self.assertFalse(checks["leases_confirmed"])
            self.assertIn("settlement-lease-set-mismatch", transaction["validation"]["qualification_settlement"]["reason"])
            attempt = _run_attempt(first, accounting)
            self.assertEqual(attempt["state"], "reconciliation-required")
            self.assertEqual(attempt["charge"], preparation["per_run_limits"])
            cleanup.assert_called_once()
            self.assertEqual(harnesses[1].starts, [])

    def test_active_settlement_rejects_contradictory_duplicate_members(self):
        cases = {
            "state": (b'"state_sequence":', b'"state_sequence": -1, '),
            "registry": (b'"lifecycle_state": "released"', b'"lifecycle_state": "held", '),
        }
        for artifact, (member, contradictory_member) in cases.items():
            with self.subTest(artifact=artifact), tempfile.TemporaryDirectory() as temporary:
                preparation, runs, harnesses, _, accounting = _preparation_and_runs(Path(temporary))
                options = harnesses[0].launch.keyword_arguments
                path = {"state": options["state_file"], "registry": options["lease_registry"].path}[artifact]

                def write_duplicate(_cutoff):
                    original = path.read_bytes()
                    duplicate = original.replace(member, contradictory_member + member, 1)
                    self.assertNotEqual(duplicate, original)
                    self.assertEqual(json.loads(duplicate), json.loads(original))
                    path.write_bytes(duplicate)
                    return True

                cleanup = mock.Mock(side_effect=write_duplicate)
                first = _active_fixture(runs[0], harnesses[0], cleanup=cleanup)
                second = _active_fixture(runs[1], harnesses[1])
                result = _run_stage(preparation, (first, second), accounting)

                self.assertEqual(result["outcome"], "stopped")
                transaction, = result["transactions"]
                self.assertTrue(transaction["launch_result"]["pool_receipt"]["accepting"])
                self.assertFalse(transaction["accepted"])
                self.assertFalse(transaction["validation"]["atomic_promotion_authorized"])
                checks = transaction["validation"]["qualification_active_limits"]
                self.assertTrue(checks["cleanup_confirmed"])
                self.assertFalse(checks["leases_confirmed"])
                self.assertEqual(transaction["validation"]["qualification_settlement"], {
                    "outcome": "refused", "reason": f"pool-qualification-settlement-{artifact}-unreadable",
                })
                attempt = _run_attempt(first, accounting)
                self.assertEqual(attempt["state"], "reconciliation-required")
                self.assertEqual(attempt["charge"], preparation["per_run_limits"])
                cleanup.assert_called_once()
                self.assertEqual(harnesses[1].starts, [])
                second.cleanup.assert_not_called()

    def test_active_last_tool_debit_is_atomic_and_replay_closes_the_gate(self):
        for failure in ("tool-limit-exceeded", "tool-request-replay"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                preparation, runs, harnesses, _, accounting = _preparation_and_runs(Path(temporary))
                admitted = []
                cap = preparation["per_run_limits"]["tool_calls"]
                fault_injected = Event()
                target = runs[0].plan["children"][0]["child_id"]

                def attack(limits, child_id, thread_id, turn_id):
                    if failure == "tool-request-replay":
                        limits.charge_tool(child_id, thread_id, turn_id, 1)
                    for request in range(2, cap - 1):
                        limits.charge_tool(child_id, thread_id, turn_id, request)
                    gate = Barrier(2, timeout=3)
                    faults = []

                    def contend(request):
                        try:
                            gate.wait()
                            limits.charge_tool(child_id, thread_id, turn_id, request)
                            admitted.append(request)
                        except Exception as error:
                            faults.append(error)

                    threads = [Thread(target=contend, args=(request,)) for request in (cap, cap + 1)]
                    for thread in threads:
                        thread.start()
                    for thread in threads:
                        thread.join(3)
                        self.assertFalse(thread.is_alive())
                    self.assertEqual(len(admitted), 1)
                    refused, = faults
                    self.assertIn(failure, str(refused))
                    # A later new request is also refused by the first failure.
                    limits.charge_tool(child_id, thread_id, turn_id, cap + 2)

                def probe(limits, child_id, thread_id, turn_id):
                    if child_id != target:
                        self.assertTrue(fault_injected.wait(3))
                        return
                    try:
                        attack(limits, child_id, thread_id, turn_id)
                    finally:
                        fault_injected.set()

                first = _active_fixture(runs[0], harnesses[0], on_debit=probe)
                second = _active_fixture(runs[1], harnesses[1])
                with self.assertRaisesRegex(NativePoolTransactionError, failure):
                    _run_stage(preparation, (first, second), accounting)
                events = _qualification_effect_events(first, accounting)
                debits = [event for event in events if event["event_type"] == "qualification-tool-debit"]
                self.assertEqual(len(debits), cap if failure == "tool-limit-exceeded" else 2)
                self.assertEqual(events[-1]["details"]["refusal"], failure)
                self.assertEqual(_run_attempt(first, accounting)["state"], "reconciliation-required")
                self.assertEqual(list(first.fixture_root.glob("*/result-*.txt")), [])
                self.assertEqual(harnesses[1].starts, [])

    def test_active_tool_replay_during_validation_refuses_the_completed_effects(self):
        with tempfile.TemporaryDirectory() as temporary:
            preparation, runs, harnesses, _, accounting = _preparation_and_runs(Path(temporary))
            run = runs[0]
            requests = []

            def remember_debit(limits, child_id, thread_id, turn_id):
                requests.append((limits, child_id, thread_id, turn_id))

            def validate(launched, context):
                limits, child_id, thread_id, turn_id = requests[-1]
                with self.assertRaisesRegex(NativePoolTransactionError, "tool-request-replay"):
                    limits.charge_tool(child_id, thread_id, turn_id, 1)
                return run.runtime.validate(launched, context)

            first = replace(run, runtime=replace(run.runtime, validate=validate))
            first = _active_fixture(first, harnesses[0], on_debit=remember_debit)
            second = _active_fixture(runs[1], harnesses[1])
            result = _run_stage(preparation, (first, second), accounting)

            self.assertEqual(result["outcome"], "stopped")
            transaction, = result["transactions"]
            self.assertFalse(transaction["accepted"])
            self.assertTrue(transaction["launch_result"]["pool_receipt"]["accepting"])
            checks = transaction["validation"]["qualification_active_limits"]
            self.assertFalse(checks["effects_complete"])
            self.assertTrue(checks["cleanup_confirmed"])
            self.assertTrue(checks["leases_confirmed"])
            events = _qualification_effect_events(first, accounting)
            self.assertEqual(events[-1]["details"]["refusal"], "tool-request-replay")
            self.assertEqual(events[-1]["details"]["pending"], {"sessions": [], "turns": [], "tools": []})
            self.assertEqual(sum(row["event_type"] == "qualification-tool-debit" for row in events), 2)
            attempt = _run_attempt(first, accounting)
            self.assertEqual((attempt["state"], attempt["outcome"]), ("terminal", "failed"))
            self.assertEqual(attempt["charge"], preparation["per_run_limits"])
            self.assertEqual(harnesses[1].starts, [])

    def test_active_cleanup_error_preserves_preparation_failure_and_charge(self):
        with tempfile.TemporaryDirectory() as temporary:
            preparation, runs, harnesses, _, accounting = _preparation_and_runs(Path(temporary))
            failure = NativePoolTransactionError("original synthetic startup failure")
            run = runs[0]
            first = replace(run, runtime=replace(run.runtime, prepare=mock.Mock(side_effect=failure)),
                            bind_limits=mock.Mock(), cleanup=mock.Mock(side_effect=OSError("synthetic cleanup")))
            second = _active_fixture(runs[1], harnesses[1])
            with self.assertRaisesRegex(NativePoolTransactionError, str(failure)) as raised:
                _run_stage(preparation, (first, second), accounting)
            self.assertIs(raised.exception, failure)
            self.assertIn("qualification cleanup failed (OSError)", failure.__notes__)
            attempt = _run_attempt(first, accounting)
            self.assertEqual(attempt["state"], "reconciliation-required")
            self.assertEqual(attempt["charge"], preparation["per_run_limits"])
            events = _qualification_effect_events(first, accounting)
            self.assertFalse(events[-1]["details"]["cleanup_confirmed"])
            self.assertEqual(harnesses[1].starts, [])

    def test_active_settlement_interruption_preserves_original_charge_and_custody(self):
        for terminal_written in (False, True):
            with self.subTest(terminal_written=terminal_written), tempfile.TemporaryDirectory() as temporary:
                preparation, runs, harnesses, _, accounting = _preparation_and_runs(Path(temporary))
                first, second = tuple(_active_fixture(run, harness) for run, harness in zip(runs, harnesses))
                ledger = accounting.ledger
                original_finish = ledger.finish
                interruption = KeyboardInterrupt("synthetic final settlement interruption")
                terminal_records = []

                def interrupt(reservation_id, outcome, *, reason):
                    if terminal_written:
                        terminal_records.append(original_finish(reservation_id, outcome, reason=reason))
                    raise interruption

                with mock.patch.object(ledger, "finish", side_effect=interrupt) as finish:
                    with self.assertRaises(KeyboardInterrupt) as raised:
                        _run_stage(preparation, (first, second), accounting)
                self.assertIs(raised.exception, interruption)
                finish.assert_called_once()
                first.cleanup.assert_called_once()
                second.cleanup.assert_not_called()
                self.assertEqual(harnesses[1].starts, [])
                self.assertFalse(second.journal_path.exists())
                evidence = _qualification_effect_events(first, accounting)[-1]
                self.assertEqual(evidence["event_type"], "qualification-effects-settled")
                self.assertTrue(evidence["details"]["cleanup_confirmed"])
                self.assertTrue(evidence["details"]["leases_confirmed"])
                attempt = _run_attempt(first, accounting)
                self.assertEqual(attempt["charge"], preparation["per_run_limits"])
                if terminal_written:
                    self.assertEqual((attempt["state"], attempt["outcome"]), ("terminal", "completed"))
                    self.assertEqual([attempt], terminal_records)
                else:
                    self.assertEqual((attempt["state"], attempt["outcome"]), ("reconciliation-required", None))

    def test_active_validation_crossing_deadline_cannot_accept(self):
        with tempfile.TemporaryDirectory() as temporary:
            preparation, runs, harnesses, _, accounting = _preparation_and_runs(Path(temporary))
            now, bound = [100.0], []
            first = _active_fixture(runs[0], harnesses[0])
            original_bind, original_validate = first.bind_limits, first.runtime.validate

            def bind(limits):
                bound.append(limits)
                original_bind(limits)

            def validate(launched, context):
                outcome = original_validate(launched, context)
                now[0] = bound[0].deadline
                return outcome

            first = replace(first, bind_limits=bind, runtime=replace(first.runtime, validate=validate))
            second = _active_fixture(runs[1], harnesses[1])
            with mock.patch("cwo_core.native_pool_qualification_stage.monotonic", side_effect=lambda: now[0]):
                result = _run_stage(preparation, (first, second), accounting)
            self.assertEqual(result["outcome"], "stopped")
            stopped, = result["transactions"]
            self.assertTrue(stopped["launch_result"]["pool_receipt"]["accepting"])
            self.assertFalse(stopped["accepted"])
            self.assertFalse(stopped["validation"]["qualification_active_limits"]["deadline_satisfied"])
            self.assertEqual(stopped["qualification_accounting"]["outcome"], "failed")
            first.cleanup.assert_called_once()
            self.assertEqual(harnesses[1].starts, [])

    def test_ledger_binding_rejects_drift_and_overlap_before_writes(self):
        with tempfile.TemporaryDirectory() as temporary:
            preparation, runs, harnesses, _, accounting = _preparation_and_runs(Path(temporary))
            binding = pool_qualification_binding(preparation, runs, accounting=accounting)
            moved = replace(accounting, ledger=InvocationLedger(Path(temporary) / "other-ledger"))
            for changed in (replace(accounting, expires_at=101), moved):
                with self.assertRaisesRegex(NativePoolTransactionError, "trusted-binding-mismatch"):
                    run_pool_qualification_stage(preparation, runs, accounting=changed, approved_binding=binding)
            inside = replace(accounting, ledger=InvocationLedger(runs[0].fixture_root / "worker-1"))
            with self.assertRaisesRegex(NativePoolTransactionError, "accounting-fixture-overlap"):
                run_pool_qualification_stage(preparation, runs, accounting=inside,
                    approved_binding=pool_qualification_binding(preparation, runs, accounting=inside))
            self.assertEqual([harness.starts for harness in harnesses], [[], []])
            self.assertEqual(list(accounting.ledger.root.iterdir()), [])
            self.assertFalse(moved.ledger.root.exists())
            self.assertFalse((inside.ledger.root / "ledger.json").exists())

    def test_ledger_refuses_unresolved_predecessor_before_any_transaction(self):
        with tempfile.TemporaryDirectory() as temporary:
            preparation, runs, harnesses, _, accounting = _preparation_and_runs(Path(temporary))
            binding = pool_qualification_binding(preparation, runs, accounting=accounting)
            budget_id = "pool-qualification:" + binding
            ledger = accounting.ledger
            ledger.open_budget(budget_id, preparation["stage_ceiling"], scope_sha256=binding)
            predecessor = b"synthetic previous qualification allocation"
            reserved = ledger.reserve(budget_id=budget_id, request_id="synthetic-unresolved-predecessor",
                request_sha256=request_sha256(predecessor), admission_sha256="f" * 64,
                amount=preparation["per_run_limits"], expires_at=accounting.expires_at)
            ledger.begin_invocation(reserved["reservation_id"], predecessor)
            ledger.mark_reconciliation_required(reserved["reservation_id"], reason="synthetic ambiguous attempt")
            with self.assertRaisesRegex(InvocationLedgerError, "requires reconciliation"):
                run_pool_qualification_stage(preparation, runs, accounting=accounting, approved_binding=binding)
            self.assertEqual([harness.starts for harness in harnesses], [[], []])
            self.assertFalse(any(run.journal_path.exists() for run in runs))

    def test_ledger_retains_interrupted_run_for_reconciliation(self):
        with tempfile.TemporaryDirectory() as temporary:
            preparation, runs, harnesses, _, accounting = _preparation_and_runs(Path(temporary))
            stopped = replace(runs[0], runtime=replace(runs[0].runtime, prepare=mock.Mock(side_effect=KeyboardInterrupt)))
            runs = (stopped, runs[1])
            binding = pool_qualification_binding(preparation, runs, accounting=accounting)
            with self.assertRaises(KeyboardInterrupt):
                run_pool_qualification_stage(preparation, runs, accounting=accounting, approved_binding=binding)
            journal = TransactionJournal(stopped.journal_path, stopped.plan["transaction_id"]).read()
            intent, = [event["details"] for event in journal if event["event_type"] == "qualification-accounting-intent"]
            attempt = accounting.ledger.attempt(intent["reservation_id"])
            self.assertEqual(attempt["state"], "reconciliation-required")
            self.assertEqual(attempt["charge"], preparation["per_run_limits"])
            self.assertEqual([harness.starts for harness in harnesses], [[], []])
            self.assertFalse(runs[1].journal_path.exists())

    def test_bound_stage_reaches_original_n2_and_n3_worker_turns(self):
        with tempfile.TemporaryDirectory() as temporary:
            preparation, runs, harnesses, adapters, accounting = _preparation_and_runs(Path(temporary))
            result = run_pool_qualification_stage(preparation, runs,
                                                  accounting=accounting, approved_binding=pool_qualification_binding(preparation, runs, accounting=accounting))
            self.assertEqual(result["outcome"], "completed", result)
            for size, transaction, run, harness, children in zip((2, 3), result["transactions"], runs, harnesses, adapters):
                self.assertEqual(transaction["plan_sha256"], run.plan["plan_sha256"])
                self.assertEqual(len(harness.starts), size)
                for adapter in children.values():
                    self.assertIn("send_input", adapter.calls)
                terminal = TransactionJournal(run.journal_path, run.plan["transaction_id"]).read()[-1]
                self.assertEqual(terminal["event_sha256"], transaction["journal_last_event_sha256"])
                self.assertEqual(transaction["validation"]["qualification_fixture"]["outcome"], "verified")
                evidence = transaction["validation"]["qualification_settlement"]
                self.assertEqual(evidence["outcome"], "verified")
                self.assertEqual(evidence["state_sha256"], transaction["launch_result"]["pool_receipt"]["terminal_state_sha256"])
                self.assertEqual(len(evidence["released_lease_sha256s"]), size)

    def test_settlement_rereads_leases_without_locks_or_path_based_loader(self):
        with tempfile.TemporaryDirectory() as temporary:
            preparation, runs, harnesses, _, accounting = _preparation_and_runs(Path(temporary))
            registry_paths = [harness.launch.keyword_arguments["lease_registry"].path for harness in harnesses]
            post_run = set()
            locked, loaded = set(), set()

            def observe(callback, registry_path):
                def validate(launched, context):
                    post_run.add(registry_path)
                    return callback(launched, context)

                return validate

            def track(callback, calls):
                def check(registry):
                    self.assertNotIn(registry.path, post_run)
                    calls.add(registry.path)
                    return callback(registry)

                return check

            runs = tuple(replace(run, runtime=replace(run.runtime, validate=observe(run.runtime.validate, path)))
                         for run, path in zip(runs, registry_paths))
            with (mock.patch.object(PoolLeaseRegistry, "_locked", track(PoolLeaseRegistry._locked, locked)),
                  mock.patch.object(PoolLeaseRegistry, "_load_unlocked", track(PoolLeaseRegistry._load_unlocked, loaded))):
                result = run_pool_qualification_stage(preparation, runs,
                    accounting=accounting, approved_binding=pool_qualification_binding(preparation, runs, accounting=accounting))
            self.assertEqual(result["outcome"], "completed")
            self.assertEqual(locked, loaded)
            self.assertEqual(locked, set(registry_paths))
            self.assertEqual(post_run, set(registry_paths))

    def test_post_run_settlement_failure_stops_with_original_receipt(self):
        cases = {
            "missing-state": "settlement-state-unreadable",
            "changed-state": "settlement-receipt-mismatch",
            "missing-lease": "settlement-lease-set-mismatch",
            "changed-lease": "settlement-lease-receipt-mismatch",
        }
        for kind, reason in cases.items():
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                preparation, runs, harnesses, _, accounting = _preparation_and_runs(Path(temporary))
                original_validate = runs[0].runtime.validate
                options = harnesses[0].launch.keyword_arguments

                def damage(launched, context):
                    _mutate_settlement(kind, options)
                    return original_validate(launched, context)

                runs = (replace(runs[0], runtime=replace(runs[0].runtime, validate=damage)), runs[1])
                result = run_pool_qualification_stage(preparation, runs,
                    accounting=accounting, approved_binding=pool_qualification_binding(preparation, runs, accounting=accounting))
                self.assertEqual(result["outcome"], "stopped")
                transaction, = result["transactions"]
                self.assertTrue(transaction["launch_result"]["pool_receipt"]["accepting"])
                self.assertFalse(transaction["accepted"])
                self.assertFalse(transaction["validation"]["atomic_promotion_authorized"])
                self.assertEqual(transaction["validation"]["qualification_fixture"]["outcome"], "verified")
                evidence = transaction["validation"]["qualification_settlement"]
                self.assertEqual(evidence["outcome"], "refused")
                self.assertIn(reason, evidence["reason"])
                self.assertEqual(harnesses[1].starts, [])
                self.assertFalse(runs[1].journal_path.exists())

    def test_original_validator_cannot_change_the_journaled_launch_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            preparation, runs, _, _, accounting = _preparation_and_runs(Path(temporary))
            original_validate = runs[0].runtime.validate

            def mutate(launched, context):
                launched["pool_receipt"]["accepting"] = False
                launched["pool_receipt"]["lease_evidence"].clear()
                return original_validate(launched, context)

            runs = (replace(runs[0], runtime=replace(runs[0].runtime, validate=mutate)), runs[1])
            result = run_pool_qualification_stage(preparation, runs,
                accounting=accounting, approved_binding=pool_qualification_binding(preparation, runs, accounting=accounting))
            self.assertEqual(result["outcome"], "completed", result)
            first = result["transactions"][0]
            self.assertTrue(first["launch_result"]["pool_receipt"]["accepting"])
            self.assertEqual(len(first["launch_result"]["pool_receipt"]["lease_evidence"]), 2)
            journal = TransactionJournal(runs[0].journal_path, runs[0].plan["transaction_id"]).read()
            committed, = [entry for entry in journal if entry["event_type"] == "admitted-pool-returned"]
            self.assertEqual(committed["details"]["launch_result_sha256"], canonical_sha256(first["launch_result"]))

    def test_post_run_fixture_failure_stops_with_original_receipt(self):
        cases = {
            "output": ("worker-1/result-n2-worker-1.txt", "Wrong text\n"),
            "wrong-owner": ("worker-1/result-n2-worker-2.txt", "CWO pool qualification for N=2, worker 2\n"),
            "integration": ("integration/extra.txt", "unexpected"),
            "seed": ("worker-2/README.txt", "modified"),
            "git": ("worker-2/.git/logs/HEAD", "modified"),
        }
        for kind, (relative, contents) in cases.items():
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                preparation, runs, harnesses, _, accounting = _preparation_and_runs(Path(temporary))
                original_validate = runs[0].runtime.validate

                def damage(launched, context):
                    (runs[0].fixture_root / relative).write_text(contents, encoding="utf-8")
                    return original_validate(launched, context)

                runs = (replace(runs[0], runtime=replace(runs[0].runtime, validate=damage)), runs[1])
                result = run_pool_qualification_stage(preparation, runs,
                    accounting=accounting, approved_binding=pool_qualification_binding(preparation, runs, accounting=accounting))
                self.assertEqual(result["outcome"], "stopped")
                transaction, = result["transactions"]
                self.assertTrue(transaction["launch_result"]["pool_receipt"]["accepting"])
                self.assertFalse(transaction["accepted"])
                self.assertFalse(transaction["validation"]["atomic_promotion_authorized"])
                self.assertEqual(transaction["validation"]["qualification_fixture"]["outcome"], "refused")
                self.assertEqual(harnesses[1].starts, [])
                self.assertFalse(runs[1].journal_path.exists())

    def test_fixture_link_and_wrong_launch_workspace_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            prep, runs, harnesses, adapters, accounting = _preparation_and_runs(Path(temporary))
            worker = runs[1].fixture_root / "worker-3"
            worker.rename(worker.with_name("moved"))
            worker.symlink_to(worker.with_name("moved"), target_is_directory=True)
            with self.assertRaisesRegex(NativePoolTransactionError, "pool-qualification-fixture-"):
                run_pool_qualification_stage(prep, runs, accounting=accounting, approved_binding=pool_qualification_binding(prep, runs, accounting=accounting))
            self.assertEqual([harness.starts for harness in harnesses], [[], []])
            self.assertFalse(any(run.journal_path.exists() for run in runs))
            worker.unlink()
            worker.with_name("moved").rename(worker)
            harnesses[0].launch.preflight_request["children"][0]["worktree"] = str(worker)
            with self.assertRaisesRegex(NativePoolTransactionError, "pool-qualification-admitted-workspace-drift"):
                run_pool_qualification_stage(prep, runs, accounting=accounting, approved_binding=pool_qualification_binding(prep, runs, accounting=accounting))
            self.assertTrue(harnesses[0].containments[0]["all_contained"])
            self.assertTrue(all("send_input" not in adapter.calls for adapter in adapters[0].values()))
            self.assertFalse(runs[1].journal_path.exists())

    def test_fixture_root_binding_and_preexisting_extra_file_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            prep, runs, harnesses, _, accounting = _preparation_and_runs(Path(temporary))
            approved_binding = pool_qualification_binding(prep, runs, accounting=accounting)
            delegated = replace(runs[0], fixture_root=runs[1].fixture_root)
            with self.assertRaisesRegex(NativePoolTransactionError, "trusted-binding-mismatch"):
                run_pool_qualification_stage(prep, (delegated, runs[1]), accounting=accounting, approved_binding=approved_binding)
            (runs[1].fixture_root / "worker-1" / "extra.txt").write_bytes(b"existing dirt")
            with self.assertRaisesRegex(NativePoolTransactionError, "fixture-clone-not-pristine"):
                run_pool_qualification_stage(prep, runs, accounting=accounting, approved_binding=approved_binding)
            self.assertEqual([harness.starts for harness in harnesses], [[], []])
            self.assertFalse(any(run.journal_path.exists() for run in runs))

    def test_fixture_directories_object_alternates_and_journal_overlap_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            prep, runs, harnesses, _, accounting = _preparation_and_runs(Path(temporary))
            worker = runs[1].fixture_root / "worker-3"
            worker.chmod(0o775)
            with self.assertRaisesRegex(NativePoolTransactionError, "fixture-directory-not-protected"):
                run_pool_qualification_stage(prep, runs, accounting=accounting, approved_binding=pool_qualification_binding(prep, runs, accounting=accounting))
            worker.chmod(0o755)
            alternates = worker / ".git" / "objects" / "info" / "alternates"
            alternates.write_text(str(runs[0].fixture_root / "worker-1" / ".git" / "objects") + "\n")
            with self.assertRaisesRegex(NativePoolTransactionError, "fixture-own-git-directory-required"):
                run_pool_qualification_stage(prep, runs, accounting=accounting, approved_binding=pool_qualification_binding(prep, runs, accounting=accounting))
            alternates.unlink()
            runs = (replace(runs[0], journal_path=worker / "journal.jsonl"), runs[1])
            with self.assertRaisesRegex(NativePoolTransactionError, "fixture-journal-overlap"):
                run_pool_qualification_stage(prep, runs, accounting=accounting, approved_binding=pool_qualification_binding(prep, runs, accounting=accounting))
            self.assertEqual([harness.starts for harness in harnesses], [[], []])
            self.assertFalse(any(run.journal_path.exists() for run in runs))

    def test_admitted_state_file_inside_any_run_is_refused_before_turns(self):
        with tempfile.TemporaryDirectory() as temporary:
            prep, runs, harnesses, adapters, accounting = _preparation_and_runs(Path(temporary))
            harnesses[0].launch.keyword_arguments["state_file"] = runs[1].fixture_root / "pool-state.json"
            with self.assertRaisesRegex(NativePoolTransactionError, "fixture-state-overlap"):
                run_pool_qualification_stage(prep, runs, accounting=accounting, approved_binding=pool_qualification_binding(prep, runs, accounting=accounting))
            self.assertTrue(harnesses[0].containments[0]["all_contained"])
            self.assertTrue(all("send_input" not in adapter.calls for adapter in adapters[0].values()))
            self.assertFalse(runs[1].journal_path.exists())

    def test_missing_or_serialized_lease_registry_is_refused_before_turns(self):
        for serialized in (False, True):
            with self.subTest(serialized=serialized), tempfile.TemporaryDirectory() as temporary:
                prep, runs, harnesses, adapters, accounting = _preparation_and_runs(Path(temporary))
                options = harnesses[0].launch.keyword_arguments
                registry = options.pop("lease_registry")
                if serialized:
                    options["lease_registry"] = {"path": str(registry.path)}
                with self.assertRaisesRegex(NativePoolTransactionError, "fixture-lease-registry-required"):
                    run_pool_qualification_stage(prep, runs, accounting=accounting, approved_binding=pool_qualification_binding(prep, runs, accounting=accounting))
                self.assertTrue(harnesses[0].containments[0]["all_contained"])
                self.assertTrue(all("send_input" not in adapter.calls for adapter in adapters[0].values()))
                self.assertFalse(runs[1].journal_path.exists())

    def test_refused_result_stops_before_second_original_transaction(self):
        with tempfile.TemporaryDirectory() as temporary:
            preparation, runs, harnesses, _, accounting = _preparation_and_runs(Path(temporary))
            harnesses[0].validation["accepted"] = False
            result = run_pool_qualification_stage(preparation, runs,
                                                  accounting=accounting, approved_binding=pool_qualification_binding(preparation, runs, accounting=accounting))
            self.assertEqual(result["outcome"], "stopped")
            self.assertEqual(len(result["transactions"]), 1)
            self.assertFalse(result["transactions"][0]["accepted"])
            self.assertEqual(harnesses[1].starts, [])
            self.assertFalse(runs[1].journal_path.exists())

    def test_original_pool_refusal_is_journaled_without_validator_acceptance(self):
        with tempfile.TemporaryDirectory() as temporary:
            preparation, runs, harnesses, _, accounting = _preparation_and_runs(Path(temporary))
            callbacks = harnesses[0].launch.keyword_arguments["pool_callbacks"]
            original_compare = callbacks["compare_workspaces"]

            def reject_close(*, contract, phase):
                evidence = original_compare(contract=contract, phase=phase)
                if phase == "close":
                    evidence["integration_root_clean"] = False
                    evidence = seal_artifact(evidence, "evidence_sha256")
                return evidence

            callbacks["compare_workspaces"] = reject_close
            self.assertTrue(harnesses[0].validation["accepted"])
            result = run_pool_qualification_stage(preparation, runs,
                accounting=accounting, approved_binding=pool_qualification_binding(preparation, runs, accounting=accounting))
            self.assertEqual(result["outcome"], "stopped")
            transaction, = result["transactions"]
            receipt = transaction["launch_result"]["pool_receipt"]
            self.assertFalse(receipt["accepting"])
            self.assertIn("terminal-workspace-comparison-failed", receipt["reasons"])
            self.assertFalse(transaction["accepted"])
            self.assertFalse(transaction["validation"]["atomic_promotion_authorized"])
            journal = TransactionJournal(runs[0].journal_path, runs[0].plan["transaction_id"]).read()
            self.assertEqual(journal[-1]["state"], "CONTAINED")
            accounting_result = transaction["qualification_accounting"]
            self.assertEqual(accounting_result["outcome"], "failed")
            self.assertEqual(accounting_result["charge"], preparation["per_run_limits"])
            self.assertEqual(accounting_result["journal_last_event_sha256"], journal[-1]["event_sha256"])
            launch_event, = [event for event in journal if event["event_type"] == "admitted-pool-returned"]
            self.assertEqual(launch_event["details"]["launch_result_sha256"], canonical_sha256(transaction["launch_result"]))
            self.assertEqual(harnesses[1].starts, [])
            self.assertFalse(runs[1].journal_path.exists())

    def test_original_execution_exception_is_preserved_and_stops_stage(self):
        with tempfile.TemporaryDirectory() as temporary:
            preparation, runs, harnesses, _, accounting = _preparation_and_runs(Path(temporary))
            error = NativePoolTransactionError("original-adapter-refused")
            first = replace(runs[0], runtime=replace(runs[0].runtime, prepare=mock.Mock(side_effect=error)))
            runs = (first, runs[1])
            binding = pool_qualification_binding(preparation, runs, accounting=accounting)
            with self.assertRaisesRegex(NativePoolTransactionError, "original-adapter-refused") as raised:
                run_pool_qualification_stage(preparation, runs, accounting=accounting, approved_binding=binding)
            self.assertIs(raised.exception, error)
            journal = TransactionJournal(first.journal_path, first.plan["transaction_id"])
            original = journal.read()
            intent, = [event["details"] for event in original if event["event_type"] == "qualification-accounting-intent"]
            attempt = accounting.ledger.attempt(intent["reservation_id"])
            self.assertEqual(attempt["outcome"], "unknown")
            self.assertEqual(attempt["charge"], preparation["per_run_limits"])
            with self.assertRaisesRegex(InvocationLedgerError, "admission replay"):
                run_pool_qualification_stage(preparation, runs, accounting=accounting, approved_binding=binding)
            self.assertEqual(journal.read(), original)
            first.runtime.prepare.assert_called_once()
            self.assertEqual(harnesses[1].starts, [])
            self.assertFalse(runs[1].journal_path.exists())

    def test_changed_or_unenforceable_limits_cannot_start_a_transaction(self):
        with tempfile.TemporaryDirectory() as temporary:
            preparation, runs, harnesses, _, accounting = _preparation_and_runs(Path(temporary))
            original_hash = pool_qualification_binding(preparation, runs, accounting=accounting)
            preparation["per_run_limits"]["tokens"] = 100
            with self.assertRaisesRegex(NativePoolTransactionError, "trusted-binding-mismatch"):
                run_pool_qualification_stage(preparation, runs, accounting=accounting, approved_binding=original_hash)
            with self.assertRaisesRegex(NativePoolTransactionError, "unsupported-limit-requires-protected-host-accounting"):
                run_pool_qualification_stage(preparation, runs, accounting=accounting, approved_binding=pool_qualification_binding(preparation, runs, accounting=accounting))
            del preparation["per_run_limits"]["tokens"]
            preparation["per_run_limits"]["tool_calls"] = 1
            preparation["stage_ceiling"]["tool_calls"] = 2
            with self.assertRaisesRegex(NativePoolTransactionError, "missing-or-excessive-pool-budget"):
                run_pool_qualification_stage(preparation, runs, accounting=accounting, approved_binding=pool_qualification_binding(preparation, runs, accounting=accounting))
            self.assertEqual([harness.starts for harness in harnesses], [[], []])
            self.assertFalse(any(run.journal_path.exists() for run in runs))

    def test_bound_pool_budget_drift_refuses_worker_turns_and_stops(self):
        with tempfile.TemporaryDirectory() as temporary:
            preparation, runs, harnesses, adapters, accounting = _preparation_and_runs(Path(temporary))
            harnesses[0].launch.contract["aggregate_hard_budget"]["tool_calls"] += 1
            with self.assertRaisesRegex(NativePoolTransactionError, "admitted-pool-budget-drift"):
                run_pool_qualification_stage(preparation, runs, accounting=accounting, approved_binding=pool_qualification_binding(preparation, runs, accounting=accounting))
            self.assertTrue(harnesses[0].containments[0]["all_contained"])
            self.assertTrue(all("send_input" not in adapter.calls for adapter in adapters[0].values()))
            self.assertEqual(harnesses[1].starts, [])
            self.assertFalse(runs[1].journal_path.exists())

    def test_even_a_rebound_stage_requires_fixed_fixture_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            preparation, runs, harnesses, _, accounting = _preparation_and_runs(Path(temporary))
            preparation["cohorts"][0]["tasks"][0]["expected_utf8"] = "Different content\n"
            with self.assertRaisesRegex(NativePoolTransactionError, "fixed-fixture-required"):
                run_pool_qualification_stage(preparation, runs, accounting=accounting, approved_binding=pool_qualification_binding(preparation, runs, accounting=accounting))
            self.assertEqual([harness.starts for harness in harnesses], [[], []])
            self.assertFalse(any(run.journal_path.exists() for run in runs))
