"""Replay registered pool qualification through original admission on inert pipes."""

from contextlib import ExitStack
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
from threading import Event
from time import time
import unittest
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import registered_pool_containment as host  # noqa: E402
import registered_pool_qualification as adapter  # noqa: E402
import registered_pool_qualification_capability as capabilities  # noqa: E402
import run_native_pool_qualification as controller  # noqa: E402
from tests.test_native_pool_contained_stage import _approve_accounting
from tests.test_native_pool_qualification_budget import record_fixture_starts
from cwo_core import beads, native_live_availability as availability  # noqa: E402
from cwo_core import native_pool_qualification_stage as stage  # noqa: E402
from cwo_core import native_pool_transaction as transaction  # noqa: E402
from cwo_core.beads_ready_set import build_ready_set_evidence  # noqa: E402
from cwo_core.invocation_ledger import InvocationLedger  # noqa: E402
from cwo_core.native_pool_admission import BeadsClaimAdapter, PoolAdmissionReservation  # noqa: E402
from cwo_core.native_pool_contracts import seal_artifact  # noqa: E402
from cwo_core.native_pool_deferred_context import (  # noqa: E402
    QUALIFICATION_ADAPTER_VERSION,
    QUALIFICATION_MODEL,
    QUALIFICATION_SURFACE,
)
from cwo_core.native_pool_qualification_fixtures import fixed_pool_qualification_cohorts  # noqa: E402
from cwo_core.native_session_boundary import NativeSessionBoundaryError  # noqa: E402
from cwo_core.native_pool_transaction import (  # noqa: E402
    TransactionJournal,
    execution_authoritative_bead_sha256,
    seal_transaction_plan,
)
from prepare_native_pool_qualification import _materialize_fixtures, _prepare  # noqa: E402
from tests import test_native_pool_admission_contracts as admitted_fixtures  # noqa: E402
from tests.test_beads_ready_set import ready_item, released_three_policy  # noqa: E402
from tests.test_native_pool import FakeClock  # noqa: E402
from tests.test_native_pool_admission import MemoryBdRunner  # noqa: E402
from tests.test_native_pool_proportionality import _set_runtime  # noqa: E402
from tests.test_native_pool_qualification_stage import _fixture, _qualification_effect_events, _run_attempt  # noqa: E402
from tests.test_native_pool_transaction import dependencies, packet_bindings  # noqa: E402
from tests.test_registered_pool_qualification import _InertContainment, _pool_test_directory  # noqa: E402


def _private_bytes(path, data):
    path.write_bytes(data)
    path.chmod(0o600)
    return sha256(data).hexdigest()


def _clock():
    return datetime.now(timezone.utc)


def _pace_isolation_polls(stack):
    original_launch_options = adapter._PoolParent._launch_options

    def launch_options(parent, contract, capability):
        options = original_launch_options(parent, contract, capability)
        callbacks = options["pool_callbacks"]
        real_sleep = callbacks["sleep"]
        clock = FakeClock()

        def sleep(*, seconds):
            # Give the inert pipes their real polling interval and advance the scheduler by that interval.
            real_sleep(seconds=seconds)
            clock.sleep(seconds=seconds)

        callbacks.update(monotonic_ns=clock.monotonic_ns, sleep=sleep)
        return options

    stack.enter_context(patch.object(adapter._PoolParent, "_launch_options", launch_options))


class _FixtureBeads:
    """Intercept only the bd subprocess boundary for checked disposable databases."""

    def __init__(self):
        self.databases = {}
        self.original = subprocess.run

    def register(self, directory, items):
        database = str(directory / "test-only.db")
        runner = MemoryBdRunner(items)
        self.databases[database] = runner
        return BeadsClaimAdapter(directory=directory, database=database, actor="inert-pool-test"), runner

    def run(self, command, *args, **kwargs):
        if command[0] != "bd":
            return self.original(command, *args, **kwargs)
        database, actor = command[4], command[6]
        runner = self.databases[database]
        if command[7] not in {"show", "update"}:
            raise AssertionError("unexpected Beads test operation")
        result = runner(tuple(command[7:]), actor=actor)
        return subprocess.CompletedProcess(command, result.returncode, result.stdout, result.stderr)


class _FixtureCapabilities:
    """Substitute only the opaque-capability verifier on original inert runs."""

    def __init__(self):
        self.attachments = {}

    def attach(self, plan, opportunity, receipt):
        attachment = object.__new__(capabilities.ConnectedPoolCallbackCapability)
        self.attachments[attachment] = (plan["plan_sha256"], opportunity, receipt)
        return attachment

    def verify(self, attachment, parent, opportunity):
        plan, expected, receipt = self.attachments[attachment]
        if (type(parent) is not adapter._PoolParent or parent.plan["plan_sha256"] != plan
                or opportunity != expected or parent.authority["capability_opportunity_sha256"] != expected):
            raise AssertionError("unexpected inert capability verification scope")
        parent._verify_artifacts()
        return deepcopy(receipt)


def _admission_inputs(cohort):
    policy = released_three_policy()
    items = [_set_runtime(ready_item(f"bead-{index}", write_paths=[task["write_path"]],
                                     requested_model=QUALIFICATION_MODEL), 600, policy=policy)
             for index, task in enumerate(cohort["tasks"], 1)]
    estimates = {item["id"]: item["raw"]["metadata"]["cwo_ready_set_admission"]["work_plan"] for item in items}
    budget = _aggregate_budget(estimates, cohort["size"])
    for item in items:
        item["raw"]["metadata"]["cwo_ready_set_admission"]["aggregate_hard_budget"] = {
            **budget, "full_suite_runs": cohort["size"], "mutations": 2 * cohort["size"]}
    readiness = build_ready_set_evidence(items, epic_id="epic-proportionality", requested_workers=3,
                                         policy_document=policy)
    return readiness, estimates, items, policy


def _aggregate_budget(estimates, size):
    aggregate = {field: sum(entry["aggregate_allowance"][key] for entry in estimates.values())
                 for field, key in (("tool_calls", "tool_calls_hard"), ("runtime_seconds", "runtime_seconds_hard"),
                                    ("compactions", "max_compactions"))}
    return {**aggregate, "full_suite_runs": 0, "mutations": size}


def _render_fixture(root, cohort, fixture_root, bd):
    admission_inputs = _admission_inputs(cohort)
    issue_root = root / "issuer"
    issue_root.mkdir()
    claim_adapter, memory = bd.register(issue_root, admission_inputs[2])
    source = Path(adapter.__file__).resolve()
    captured = []
    original = admitted_fixtures._admitted_artifacts

    def collect(*args, **kwargs):
        value = original(*args, **kwargs, admission_fixture=admission_inputs, claim_adapter_override=claim_adapter)
        captured.append(value)
        return value

    with patch.object(admitted_fixtures, "_admitted_artifacts", side_effect=collect):
        run, _, _ = _fixture(root / "render", cohort, fixture_root, model=QUALIFICATION_MODEL, factory_path=source)
    render_fixture, reservation, _, preflight = captured[0]
    admitted = PoolAdmissionReservation(reservation, render_fixture.admission_capability, render_fixture.claim_adapter)
    return run.plan, render_fixture, preflight, admitted, admission_inputs[:2], memory


def _fresh_test_capability(capability):
    now = _clock().replace(microsecond=0)
    return seal_artifact({**capability, "execution_surface": QUALIFICATION_SURFACE,
                          "adapter_version": QUALIFICATION_ADAPTER_VERSION,
                          "measured_at": (now - timedelta(seconds=1)).isoformat(),
                          "expires_at": (now + timedelta(minutes=5)).isoformat()}, "receipt_sha256")


def _control_inputs(render_fixture, preflight, root):
    render = deepcopy(render_fixture.request)
    render.update(pool_id=preflight["pool_id"], pool_epoch=preflight["pool_epoch"])
    initial_states, spools = {}, {}
    for index, child in enumerate(render["children"]):
        child_id = child["child_id"]
        initial_states[child_id] = json.loads(Path(child["state_file"]).read_bytes())
        child["state_file"] = str(root / "control" / f"child-state-{index}.json")
        child["control_contract_file"] = str(root / "control" / f"child-control-{index}.json")
        spool = root / f"worker-custody-{index}" / "spool"
        spool.mkdir(parents=True, mode=0o700)
        spools[child_id] = str(spool)
    return render, initial_states, spools


def _approved_artifacts(root, plan):
    artifacts = {}
    for name in ("candidate_manifest", "controller_overlay"):
        path = root / (name + ".json")
        plan[name + "_sha256"] = _private_bytes(path, json.dumps({"inert-test-input": name}).encode())
        artifacts[name] = str(path)
    return artifacts


def _seal_run(root, cohort, fixture_root, bd, fixture_capabilities=None, *, mode="qualification", with_authority=False):
    root.mkdir()
    for name in ("control", "records"):
        (root / name).mkdir(mode=0o700)
    plan, renderer, preflight, admission, readiness_inputs, memory = _render_fixture(root, cohort, fixture_root, bd)
    if fixture_root.name != "run-1":
        plan["transaction_id"] += "-" + fixture_root.name
    plan["budget"]["cumulative_before"] = 0
    plan["budget"]["cumulative_ceiling"] = plan["budget"]["reserved_sessions"]
    for child in plan["children"]:
        child["bead_projection_sha256"] = execution_authoritative_bead_sha256(memory.issues[child["bead_id"]])
    render, initial_states, spools = _control_inputs(renderer, preflight, root)
    preview_pk = {row["child_id"]: row["packet_sha256"] for row in preflight["children"]}
    packets = [{**row, "packet_sha256": preview_pk[row["child_id"]]} for row in packet_bindings(plan)]
    journal = root / "control" / "run.jsonl"
    claim = admission.claim_adapter
    opportunity = sha256(f"inert callback opportunity n={cohort['size']}".encode()).hexdigest()
    authority = {
        "scope": adapter._AUTHORITY_SCOPE, "mode": mode,
        "fixture_root": str(fixture_root), "journal_path": str(journal),
        "control_root": str(root / "control"), "spools": spools, "host": dict.fromkeys(adapter._HOST_FIELDS, "inert-test"),
        "artifacts": _approved_artifacts(root / "records", plan), "reservation_sha256": admission.receipt["reservation_sha256"],
        "render_request": render,
        "preflight_template": preflight, "release_artifacts": {"packet_bindings": packets,
            "release_dependencies": dependencies(plan, issued=_clock().replace(microsecond=0), ttl_ms=120000)},
        "readiness_evidence": readiness_inputs[0], "work_estimates": readiness_inputs[1], "initial_states": initial_states,
        "beads": {"directory": str(claim.directory), "database": claim.database, "actor": claim.actor},
    }
    if mode == "qualification":
        authority["capability_opportunity_sha256"] = opportunity
    authority_path = root / "records" / "authority.json"
    plan["authority_sha256"] = _private_bytes(authority_path, json.dumps(authority, sort_keys=True).encode())
    plan = seal_transaction_plan(plan)
    attachment = None if mode == "callback-calibration" else fixture_capabilities.attach(
        plan, opportunity, _fresh_test_capability(renderer.pool_capability_receipt))
    selection = stage.select_contained_pool_runtime(plan, adapter.build_pool_qualification_runtime,
                                                    authority_path=authority_path, admission=admission, capability=attachment)
    run = stage.make_pool_qualification_run(plan, selection, journal_path=journal, fixture_root=fixture_root)
    return (run, admission, authority_path) if with_authority else run


class AdmittedRegisteredPoolTests(unittest.TestCase):
    def _approved_cohorts(self, root, stack, *, behavior="", signed_isolation=False):
        contained = []
        failed_worker_closed = Event()

        class Peer(_InertContainment):
            def __init__(self, **kwargs):
                super().__init__(**kwargs)
                size = int(self.worktree.parent.parent.name.removeprefix("n"))
                slot = int(self.worktree.name.rsplit("-", 1)[1])
                self.marker = f"CWO_POOL_N{size}_WORKER_{slot}_DONE"
                self.existing = slot == 2
                target_slot = 1 if behavior == "failed-terminal" else 2
                self.behavior = behavior if size == 2 and slot == target_slot and not signed_isolation else ""
                if behavior == "signed-bad-peer" and size == 3 and slot == 2 and self.worktree.parent.name == "run-2":
                    self.behavior = "wrong-marker"
                contained.append(self)

            def run_writer(self, *args, **kwargs):
                output = super().run_writer(*args, **kwargs)
                # Keep the healthy turn open until the coordinator closes the
                # failed one, after both writers have passed the original gate.
                if behavior == "failed-terminal" and not self.behavior:
                    if not failed_worker_closed.wait(5):
                        raise TimeoutError("failed fixture worker did not close before its peer")
                return output

            def close(self):
                result = super().close()
                if self.behavior == "failed-terminal" and result["cleanup_confirmed"]:
                    failed_worker_closed.set()
                return result

        def require_test_boundary():
            self.assertIs(host.PoolWorkerContainment, Peer)
            self.assertIs(availability.POOL_QUALIFICATION_AVAILABLE, False)

        stack.enter_context(patch.object(host, "PoolWorkerContainment", Peer))
        stack.enter_context(patch.object(availability, "POOL_QUALIFICATION_AVAILABLE", False))
        for module in (availability, stage, transaction):
            stack.enter_context(patch.object(module, "require_pool_qualification", require_test_boundary))
        bd = _FixtureBeads()
        stack.enter_context(patch.object(beads, "require_bd", lambda: None))
        stack.enter_context(patch.object(beads.subprocess, "run", bd.run))
        fixture_capabilities = _FixtureCapabilities()
        stack.enter_context(patch.object(capabilities, "require_connected_callback_capability", fixture_capabilities.verify))
        if signed_isolation:
            _pace_isolation_polls(stack)
        if behavior == "wrong-context":
            self._order_mismatch_after_sibling_arrival(stack)
        repeats = 2 if signed_isolation else 1
        prep = _prepare(repeats, {"sessions": 3, "tool_calls": 60, "runtime_seconds": 2700},
                        failure_isolation=signed_isolation)
        _materialize_fixtures(root / "fixtures", prep)
        runs = []
        for cohort in fixed_pool_qualification_cohorts():
            name = f"n{cohort['size']}"
            for number in range(1, repeats + 1):
                slot = f"run-{number}"
                runs.append(_seal_run(root / f"{name}-{slot}", cohort, root / "fixtures" / name / slot, bd,
                                      fixture_capabilities))
        ledger_root = root / "accounting"
        ledger_root.mkdir(mode=0o700)
        accounting = stage.PoolQualificationAccounting(InvocationLedger(ledger_root), expires_at=int(time()) + 900)
        stack.enter_context(patch.object(stage, "contained_campaign_ledger_root", return_value=ledger_root))
        accounting.ledger.open_budget(stage.CAMPAIGN_BUDGET_ID, {"starts": 20}, scope_sha256=stage.CAMPAIGN_SCOPE_SHA256)
        accounting = _approve_accounting(accounting, stage.pool_qualification_binding(prep, runs, accounting=accounting))
        return prep, runs, accounting, contained

    def _order_mismatch_after_sibling_arrival(self, stack):
        original_attest = adapter._PoolWorker._attest_turn

        def attest(worker, pending):
            if worker.containment.behavior == "wrong-context":
                limits = worker.limits
                with limits._condition:
                    self.assertTrue(limits._condition.wait_for(lambda: bool(limits._provisional_arrivals), 3))
            return original_attest(worker, pending)

        stack.enter_context(patch.object(adapter._PoolWorker, "_attest_turn", attest))

    @staticmethod
    def _execute(preparation, runs, accounting):
        binding = stage.pool_qualification_binding(preparation, runs, accounting=accounting)
        return stage.run_contained_pool_qualification_stage(preparation, runs, approved_binding=binding, accounting=accounting)

    def test_inert_n2_n3_use_original_admission_and_release_all_leases(self):
        with _pool_test_directory() as scratch, ExitStack() as stack:
            preparation, runs, accounting, contained = self._approved_cohorts(Path(scratch), stack)
            observed = self._execute(preparation, runs, accounting)
            self.assertEqual(observed["outcome"], "completed", observed)
            self.assertEqual(accounting.ledger.summary(stage.CAMPAIGN_BUDGET_ID)["charged"], {"starts": 2})
            self.assertEqual(len(contained), 5)
            for size, run, result in zip((2, 3), runs, observed["transactions"], strict=True):
                self._assert_settled_run(size, run, result, accounting)
            self.assertTrue(all(worker.process.poll() == 0 for worker in contained))

    def test_inert_stage_finishes_original_allowance_and_reports_linked_start(self):
        with _pool_test_directory() as scratch, ExitStack() as stack:
            preparation, runs, accounting, _ = self._approved_cohorts(Path(scratch), stack)
            ledger = accounting.ledger
            record_fixture_starts(ledger, 19)
            stage._require_campaign_enrollment(expires_at=accounting.expires_at, run_count=2, campaign_start_limit=30)
            binding = stage.pool_qualification_binding(preparation, runs, accounting=accounting)
            accounting = _approve_accounting(accounting, binding, campaign_start_limit=30)
            observed = self._execute(preparation, runs, accounting)
            self.assertEqual(observed["outcome"], "completed", observed)
            starts = [row["qualification_campaign"] for row in observed["transactions"]]
            self.assertEqual([(row["runs_consumed"], row["cap"], row["remaining"]) for row in starts],
                             [(20, 30, 10), (21, 30, 9)])
            self.assertEqual(tuple(ledger.attempt(row["reservation_id"])["budget_id"] for row in starts),
                             stage.campaign_start_status(ledger)["budget_ids"])
            inputs = controller._report_inputs(preparation, 30)
            report = controller._pass_record(stage, observed, [{"plan": run.plan} for run in runs], accounting, inputs)
            self.assertEqual((report["runs_consumed"], report["run_cap"]), (21, 30))
            self.assertEqual(report["behaviors"]["n3_concurrency"]["runs"], [21])

    def _assert_settled_run(self, size, run, result, accounting):
        self.assertEqual(result["state"], "ACCEPTED", result)
        self.assertEqual(result["validation"]["qualification_settlement"]["outcome"], "verified")
        self.assertEqual(len(result["validation"]["qualification_settlement"]["released_lease_sha256s"]), size)
        rows = _qualification_effect_events(run, accounting)
        events = {kind: [row["sequence"] for row in rows if row["event_type"] == "qualification-" + kind]
                  for kind in ("provisional-turn-proof", "tool-debit", "writer-release", "tool-ack")}
        self.assertTrue(all(len(sequence) == size for sequence in events.values()), events)
        self.assertLess(max(events["provisional-turn-proof"]), min(events["tool-debit"]))
        self.assertLess(max(events["tool-debit"]), min(events["writer-release"]))
        outputs = tuple(run.fixture_root.glob("*/result-*.txt"))
        self.assertEqual(len(outputs), size)
        self.assertTrue(all(tuple(row["tools"]["unexpected"]) == ("apply_patch",)
                            for row in result["validation"]["worker_observations"].values()))
        attempt = _run_attempt(run, accounting)
        self.assertEqual((attempt["state"], attempt["outcome"], attempt["charge"]),
                         ("terminal", "completed", attempt["amount"]))

    def test_wrong_original_turn_context_refuses_before_debit_and_stops_cohort(self):
        _, events, worker = self._assert_pre_writer_refusal("wrong-context")
        self.assertEqual(events.count("qualification-provisional-turn-proof"), 1)
        self.assertIsInstance(worker.wire.transport_failure, NativeSessionBoundaryError)

    def test_completed_turn_without_writer_preserves_refusal(self):
        receipt, _, worker = self._assert_pre_writer_refusal("no-writer")
        control, = (row["control_receipt"] for row in receipt["child_terminal_receipts"]
                    if row["child_id"] == worker.child_id)
        self.assertEqual(control["terminal_state"], "control-failed")
        self.assertEqual(control["errors"], [
            "callback-failed:PoolQualificationAdapterError:"
            "pool-qualification-adapter-successful-terminal-requires-original-writer",
        ])
        self.assertEqual(worker.wire.terminal, "completed")
        self.assertEqual(worker.wire.marker, worker.task["completion_marker"])
        self.assertIsNone(worker.wire._pending)

    def _assert_pre_writer_refusal(self, behavior):
        with _pool_test_directory() as scratch, ExitStack() as stack:
            preparation, (n2, n3), accounting, contained = self._approved_cohorts(Path(scratch), stack, behavior=behavior)
            observed = self._execute(preparation, (n2, n3), accounting)
            self.assertEqual(observed["outcome"], "stopped")
            result, = observed["transactions"]
            self.assertEqual((result["state"], result["accepted"]), ("CONTAINED", False))
            receipt = result["launch_result"]["pool_receipt"]
            self.assertFalse(receipt["accepting"])
            self.assertEqual(receipt["first_protected_fault"]["code"], "child-check-failed")
            self.assertEqual([lease["lifecycle_state"] for lease in receipt["lease_evidence"]],
                             ["release-pending", "release-pending"])
            validation = result["validation"]
            self.assertFalse(validation["atomic_promotion_authorized"])
            self.assertEqual(validation["qualification_active_limits"], {
                "effects_complete": False, "cleanup_confirmed": True,
                "leases_confirmed": False, "deadline_satisfied": True,
            })
            settlement = validation["qualification_settlement"]
            self.assertEqual(settlement["outcome"], "refused")
            self.assertTrue(settlement["reason"].startswith("pool-qualification-settlement-state-invalid:"))
            self.assertEqual(len(contained), 2)
            self.assertTrue(all(worker.process.poll() == 0 for worker in contained))
            self.assertFalse(tuple(n2.fixture_root.glob("*/result-*.txt")))
            self.assertFalse(n3.journal_path.exists())
            self.assertEqual(TransactionJournal(n2.journal_path, n2.plan["transaction_id"]).current_state, "CONTAINED")
            effects = _qualification_effect_events(n2, accounting)
            events = [row["event_type"] for row in effects]
            self.assertNotIn("qualification-tool-debit", events)
            self.assertNotIn("qualification-writer-release", events)
            self.assertEqual(effects[-1]["event_type"], "qualification-effects-settled")
            self.assertTrue(effects[-1]["details"]["cleanup_confirmed"])
            self.assertFalse(effects[-1]["details"]["leases_confirmed"])
            self.assertIsNone(effects[-1]["details"]["refusal"])
            self.assertEqual(effects[-1]["details"]["pending"], {"sessions": [], "turns": [], "tools": []})
            attempt = _run_attempt(n2, accounting)
            self.assertEqual((attempt["state"], attempt["outcome"], attempt["charge"]),
                             ("reconciliation-required", None, attempt["amount"]))
            campaign = result["qualification_campaign"]
            settled = accounting.ledger.attempt(campaign["reservation_id"])
            self.assertEqual((campaign["state"], settled["outcome"], settled["charge"]),
                             ("reconciliation-required", None, {"starts": 1}))
            self.assertEqual(accounting.ledger.summary(stage.CAMPAIGN_BUDGET_ID)["charged"], {"starts": 1})
            inputs = controller._report_inputs(preparation, stage.CAMPAIGN_START_CAP)
            report = controller._pass_record(stage, observed, [{"plan": n2.plan}], accounting, inputs)
            self.assertEqual((report["outcome"], report["runs_consumed"]), ("incomplete", 1))
            for behavior in ("n2_concurrency", "n3_concurrency", "shared_budget", "registered_writer", "cleanup"):
                self.assertEqual(report["behaviors"][behavior], {"outcome": "not-run", "runs": []})
            parent = n2.runtime.start_worker_session.__self__
            target = next(worker for worker in parent.workers.values() if worker.task["worker_slot"] == "worker-2")
            return receipt, events, target

    def test_durable_child_failure_after_writer_release_preserves_the_healthy_peer(self):
        with _pool_test_directory() as scratch, ExitStack() as stack:
            preparation, (n2, n3), accounting, contained = self._approved_cohorts(
                Path(scratch), stack, behavior="failed-terminal")
            observed = self._execute(preparation, (n2, n3), accounting)
            self.assertEqual(observed["outcome"], "stopped")
            result, = observed["transactions"]
            self._assert_isolated_failure(n2, result, accounting)
            self.assertFalse(n3.journal_path.exists())
            self.assertEqual(len(contained), 2)
            self.assertTrue(all(worker.process.poll() == 0 for worker in contained))

    def _assert_isolated_failure(self, run, result, accounting):
        self.assertEqual((result["state"], result["accepted"]), ("CONTAINED", False))
        validation = result["validation"]
        self.assertFalse(validation["atomic_promotion_authorized"])
        self.assertTrue(validation["healthy_evidence_retained"])
        self.assertTrue(all(validation["qualification_active_limits"].values()))
        self.assertEqual(len(validation["qualification_settlement"]["released_lease_sha256s"]), 2)
        receipt = result["launch_result"]["pool_receipt"]
        self.assertEqual((receipt["accepting"], receipt["pool_disposition"]), (False, "partial"))
        self.assertIsNone(receipt["first_protected_fault"])
        parent = run.runtime.start_worker_session.__self__
        failed, healthy = sorted(parent.workers.values(), key=lambda worker: worker.task["worker_slot"])
        self.assertEqual(receipt["terminal_order"], [failed.child_id, healthy.child_id])
        self.assertEqual(failed._result["terminal"]["status"], "failed")
        worker_rows = validation["worker_observations"]
        self.assertFalse(worker_rows[failed.child_id]["task_completed"])
        self.assertTrue(worker_rows[healthy.child_id]["task_completed"])
        self.assertTrue(all(row["archive"] and row["wire_settled"] for row in worker_rows.values()))
        dispositions = {row["child_id"]: row for row in receipt["child_dispositions"]}
        self.assertEqual(dispositions[failed.child_id]["runtime_disposition"], "interrupted")
        self.assertEqual(dispositions[healthy.child_id]["artifact_disposition"], "accepted")
        healthy_output = healthy.worktree / healthy.task["write_path"]
        self.assertEqual(healthy_output.read_bytes(), healthy.task["expected_utf8"].encode())
        attempt = _run_attempt(run, accounting)
        self.assertEqual((attempt["state"], attempt["outcome"], attempt["charge"]),
                         ("terminal", "failed", attempt["amount"]))
        self.assertEqual(accounting.ledger.summary(stage.CAMPAIGN_BUDGET_ID)["charged"], {"starts": 1})

    def test_approved_final_case_refuses_only_the_target_before_healthy_writes(self):
        with _pool_test_directory() as scratch, ExitStack() as stack:
            preparation, runs, accounting, contained = self._approved_cohorts(Path(scratch), stack, signed_isolation=True)
            observed = self._execute(preparation, runs, accounting)
            self.assertEqual(observed["outcome"], "completed", observed)
            for transaction_result in observed["transactions"][:-1]:
                self.assertEqual(transaction_result["state"], "ACCEPTED")
                self.assertNotIn("qualification_failure_isolation", transaction_result)
            self._assert_approved_refusal(runs[-1], observed["transactions"][-1], accounting)
            self.assertEqual(accounting.ledger.summary(stage.CAMPAIGN_BUDGET_ID)["charged"], {"starts": 4})
            self.assertTrue(all(worker.process.poll() == 0 for worker in contained))

    def _assert_approved_refusal(self, run, result, accounting):
        self.assertEqual((result["state"], result["accepted"]), ("CONTAINED", False))
        parent = run.runtime.start_worker_session.__self__
        target = next(worker for worker in parent.workers.values() if worker.task["worker_slot"] == "worker-1")
        self.assertEqual(result["qualification_failure_isolation"],
                         {"target_child_id": target.child_id, "outcome": "passed"})
        without_refusal = {**result, "validation": dict(result["validation"])}
        del without_refusal["validation"]["isolation_refusal_observed"]
        self.assertEqual(stage._isolated_run_result(run, without_refusal, target.child_id)["outcome"], "failed")
        self.assertFalse((target.worktree / target.task["write_path"]).exists())
        receipt = result["launch_result"]["pool_receipt"]
        self.assertEqual(receipt["pool_disposition"], "partial")
        self.assertEqual(result["validation"]["qualification_isolation_fixture"],
                         {"outcome": "verified", "worker_output_count": 2})
        self.assertFalse(result["validation"]["atomic_promotion_authorized"])
        rows = _qualification_effect_events(run, accounting)
        events = {kind: [row for row in rows if row["event_type"] == "qualification-" + kind]
                  for kind in ("provisional-turn-proof", "tool-debit", "isolation-refused", "writer-release")}
        self.assertEqual([len(items) for items in events.values()], [3, 3, 1, 2])
        refusal, = events["isolation-refused"]
        self.assertEqual(refusal["details"]["child_id"], target.child_id)
        self.assertLess(max(row["sequence"] for row in events["tool-debit"]), refusal["sequence"])
        self.assertLess(refusal["sequence"], min(row["sequence"] for row in events["writer-release"]))
        self.assertNotIn(target.child_id, {row["details"]["child_id"] for row in events["writer-release"]})
        attempt = _run_attempt(run, accounting)
        self.assertEqual((attempt["state"], attempt["outcome"], attempt["charge"]),
                         ("terminal", "failed", attempt["amount"]))

    def test_approved_refusal_fails_when_a_healthy_peer_cannot_complete(self):
        with _pool_test_directory() as scratch, ExitStack() as stack:
            preparation, runs, accounting, contained = self._approved_cohorts(
                Path(scratch), stack, behavior="signed-bad-peer", signed_isolation=True)
            observed = self._execute(preparation, runs, accounting)
            self.assertEqual(observed["outcome"], "stopped", observed)
            final = observed["transactions"][-1]
            self.assertTrue(final["validation"]["isolation_refusal_observed"])
            self.assertEqual(final["qualification_failure_isolation"]["outcome"], "failed")
            self.assertEqual((final["accepted"], final["validation"]["atomic_promotion_authorized"]), (False, False))
            attempt = _run_attempt(runs[-1], accounting)
            self.assertEqual((attempt["state"], attempt["outcome"], attempt["charge"]),
                             ("terminal", "failed", attempt["amount"]))
            self.assertEqual(accounting.ledger.summary(stage.CAMPAIGN_BUDGET_ID)["charged"], {"starts": 4})
            self.assertTrue(all(worker.process.poll() == 0 for worker in contained))


if __name__ == "__main__":
    unittest.main()
