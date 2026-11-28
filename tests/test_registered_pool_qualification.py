"""Original registered pipes with inert peers and exact disposable outputs."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from threading import Barrier, Event, Lock
from time import monotonic, sleep
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.append(str(SCRIPTS))

import registered_pool_configuration as config  # noqa: E402
import registered_pool_containment as host  # noqa: E402
import registered_pool_qualification as adapter  # noqa: E402
from registered_pool_qualification_capability import (  # noqa: E402
    CallbackCalibrationError,
    ConnectedPoolCallbackCapability,
)
from cwo_core import native_pool_qualification_stage as stage  # noqa: E402
from cwo_core.native_pool_contracts import MAX_CERTIFIED_CHECK_MS, canonical_sha256, zero_token_usage  # noqa: E402
from cwo_core.native_pool_qualification_stage import PoolQualificationRunLimits  # noqa: E402
from cwo_core.native_pool_scheduler import AggregateUsageLedger  # noqa: E402
from cwo_core.native_pool_transaction import NativePoolTransactionError, TransactionJournal, TransactionRuntime, seal_transaction_plan  # noqa: E402
from cwo_core.native_pool_workspace import capture_workspace_snapshot  # noqa: E402
from tests.ordinary_pool_test_helpers import _PEER, _pool_test_directory  # noqa: E402
from tests.test_native_pool_transaction import bead, transaction_plan  # noqa: E402


class _Limits:
    def __init__(self, size):
        self.deadline = monotonic() + 5
        self.barrier = Barrier(size)
        self.lock = Lock()
        self.rows, self.proofs, self.debits = [], {}, set()

    def remaining(self):
        remaining = self.deadline - monotonic()
        if remaining <= 0:
            raise TimeoutError("inert witness exceeded its deadline")
        return remaining

    def before_session(self, child):
        self.rows.append((child, "before-session"))

    def ack_session(self, child, thread):
        self.rows.append((child, "ack-session"))

    def before_turn(self, child, thread):
        self.rows.append((child, "before-turn"))

    def ack_turn(self, child, thread, turn):
        self.rows.append((child, "ack-turn"))

    def record_provisional_turn_proof(self, proof):
        child = proof.startup.child_id
        self.proofs[child] = proof
        self.rows.append((child, "original-proof"))

    def charge_tool(self, child, thread, turn, request):
        proof = self.proofs[child]
        assert (thread, turn, request) == (proof.startup.session_id, proof.turn_id, proof.request_id)
        with self.lock:
            self.debits.add(child)
            self.rows.append((child, "tool-debit"))
        self.barrier.wait(self.remaining())

    def authorize_writer(self, child, thread, turn, request, request_sha256, release):
        with self.lock:
            proof = self.proofs[child]
            assert len(self.debits) == self.barrier.parties and proof.request_sha256 == request_sha256
            self.rows.append((child, "writer-gate"))
            release()

    def ack_tool(self, child, thread, turn, request):
        self.rows.append((child, "tool-ack"))


class _InertContainment:
    def __init__(self, *, worker_id, worktree, spool, write_path, expected_utf8, require_effect, **_settings):
        self.worker_id, self.worktree, self.home = worker_id, worktree, spool
        self.write_path, self.expected_utf8 = write_path, expected_utf8
        self.require_effect = require_effect
        self._appserver = SimpleNamespace(_ending=False, process=None)
        self.spec = {"executable": str(Path(sys.executable).resolve())}
        self.process = None
        self.observations = []

    @property
    def owner_identity_sha256(self):
        return sha256(self.worker_id.encode()).hexdigest()

    def launch_appserver(self):
        self.require_effect()
        inputs = {"home": str(self.home), "login": str(config.LOGIN_MOUNT), "worktree": str(self.worktree),
                  "worker": self.worker_id, "marker": self.marker, "existing": self.existing, "behavior": self.behavior,
                  "namespace": config.FINITE_TOOL_NAMESPACE, "tool": config.WRITER_TOOL,
                  "effort": config.EFFORT}
        self.process = subprocess.Popen([self.spec["executable"], "-I", "-S", "-u", "-c", _PEER, json.dumps(inputs)],
                                        cwd=self.home, env={}, umask=0o077, text=True, encoding="utf-8",
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self._appserver.process = self.process
        self._observe("appserver-contained", readonly=True, network="registered-provider-tunnel", login=True)
        return self.process

    def _observe(self, stage, *, readonly, network, login):
        self.observations.append({"stage": stage, "observation": {"filesystem_ready": True,
            "worktree_readonly": readonly, "network": network, "managed_login_projection": login}})

    def receipt(self):
        return {"observations": self.observations}

    def thread_start_selectors(self):
        return config.thread_start_selectors(self.worktree)

    def require_thread_start(self, params):
        assert params == self.thread_start_selectors()

    def require_thread_readback(self, response):
        config.require_thread_readback(self.worktree, response)

    def require_turn_selectors(self, params, *, thread_id):
        config.require_turn_selectors(params, thread_id=thread_id)

    def rollout_path(self, path, *, thread_id):
        relative = Path(path).relative_to(config.LOGIN_MOUNT)
        assert relative.name.endswith(thread_id + ".jsonl")
        return self.home / relative

    def run_writer(self, call_id, *, authorize, deadline):
        self._observe("tool-contained", readonly=False, network="isolated", login=False)
        if self.behavior == "replace-rollout":
            original, = (self.home / "sessions").glob("*.jsonl")
            alternate = original.with_suffix(".copy")
            alternate.write_bytes(original.read_bytes())
            alternate.replace(original)

        def release():
            assert call_id == self.worker_id + "-call" and monotonic() < deadline
            (self.worktree / self.write_path).write_text(self.expected_utf8, encoding="utf-8")

        authorize(release)
        return b"fixed fixture file written"

    def close(self):
        self._appserver._ending = True
        if self.process is not None:
            self.process.stdin.close()
            self.process.wait(timeout=2)
            self.process.stdout.close()
            self.process.stderr.close()
        return {"cleanup_confirmed": self.process is not None and self.process.poll() == 0}


@contextmanager
def _fixture_root():
    with _pool_test_directory() as temporary:
        root = Path(temporary)
        # Keep Git capture scratch separate from the workunit's temporary files.
        scratch = root / "capture-scratch"
        scratch.mkdir(mode=0o700)
        with patch.object(tempfile, "tempdir", str(scratch)):
            yield root


def _fixture(root, size):
    fixture = root / "workspaces"
    fixture.mkdir()
    tasks = [{"worker_slot": f"worker-{index}", "write_path": f"output-{index}.txt",
              "expected_utf8": f"Inert result for worker {index}.\n", "completion_marker": f"EXAMPLE-DONE-{index}",
              "prompt": f"Write the selected exact output for worker {index}."}
             for index in range(1, size + 1)]
    issues = [bead(f"test-{index}", task["write_path"]) for index, task in enumerate(tasks, 1)]
    plan = transaction_plan(root / "plan", issues, cumulative_before=0)
    plan["selected_model"] = config.MODEL
    source = Path(adapter.__file__).resolve()
    plan["runtime_adapter_path"] = str(source)
    plan["runtime_adapter_sha256"] = sha256(source.read_bytes()).hexdigest()
    for child, task in zip(plan["children"], tasks):
        path = fixture / task["worker_slot"]
        path.mkdir()
        subprocess.run(["git", "init", "--quiet", "--template=", "--initial-branch=main", str(path)],
                       check=True, timeout=5, stdin=subprocess.DEVNULL)
        subprocess.run(["git", "-C", str(path), "-c", "user.name=CWO Tests", "-c", "user.email=cwo@example.invalid",
                        "commit", "--allow-empty", "--quiet", "-m", "Inert workspace"],
                       check=True, timeout=5, stdin=subprocess.DEVNULL)
        child["worktree_identity_sha256"] = canonical_sha256(capture_workspace_snapshot(path, allowed_paths=child["write_paths"])["identity"])
        child["requested_model"] = config.MODEL
    return seal_transaction_plan(plan), tasks, fixture


class RegisteredPoolQualificationTests(unittest.TestCase):
    def test_production_login_is_read_only_and_refuses_replaced_or_unselected_home(self):
        with _pool_test_directory() as scratch:
            home = Path(scratch) / "login"
            home.mkdir(mode=0o700)
            details = home.stat()
            selected = SimpleNamespace(login_home=home, login_identity=(details.st_dev, details.st_ino))
            parent = SimpleNamespace(_ordinary=SimpleNamespace(children={}))
            worker = adapter._PoolWorker(parent, {"child_id": "worker-1"}, {}, None, None, 1)
            with self.assertRaisesRegex(adapter.PoolQualificationAdapterError, "original-production-login-required"):
                _ = worker.production_login_home
            parent._ordinary.children[worker.child_id] = selected
            self.assertEqual(worker.production_login_home, home)
            with self.assertRaises(AttributeError):
                worker.production_login_home = home
            home.rename(home.with_name("previous-login"))
            home.mkdir(mode=0o700)
            with self.assertRaisesRegex(adapter.PoolQualificationAdapterError, "original-production-login-custody-drift"):
                _ = worker.production_login_home

    def _prepare_workers(self, size, behaviors=(), *, calibrating=False):
        root = self.enterContext(_fixture_root())
        plan, tasks, fixture = _fixture(root, size)
        parent = object.__new__(adapter._PoolParent)
        parent.plan, parent.limits, parent.workers, parent._started = plan, _Limits(size), {}, 0
        parent.fixture_root = fixture
        parent._ordinary = SimpleNamespace(children={
            child["child_id"]: SimpleNamespace(worktree=fixture / task["worker_slot"])
            for child, task in zip(plan["children"], tasks)
        })
        parent.tasks = {child["child_id"]: task for child, task in zip(plan["children"], tasks)}
        parent.authority = {"mode": "callback-calibration" if calibrating else adapter._ORDINARY_MODE}
        parent.protected_roots, parent.host_inputs = (), {}
        parent.journal = TransactionJournal(root / "original.jsonl", plan["transaction_id"])
        parent.journal.append(event_type="static-readiness-accepted", state="PREPARED",
                              details={"plan_sha256": plan["plan_sha256"]}, now=datetime.now(timezone.utc))
        for event, state in (("complete-transaction-budget-reserved", "RESERVED"),
                             ("release-dependencies-accepted", "EVIDENCE_READY"), ("allocating-workers", "ALLOCATING")):
            parent.journal.append(event_type=event, state=state, details={}, now=datetime.now(timezone.utc))
        peer_types = {}
        for index, (child, task) in enumerate(zip(plan["children"], tasks)):
            child_id = child["child_id"]
            peer_types[child_id] = (task["completion_marker"], bool(index % 2),
                                    behaviors[index] if index < len(behaviors) else "")
        self.enterContext(patch.object(adapter._PoolParent, "require_effect", lambda selected: selected.limits.remaining()))
        self.enterContext(patch.object(host, "PoolWorkerContainment", _InertContainment))
        original = _InertContainment.__init__

        def initialize(owned, **kwargs):
            original(owned, **kwargs)
            owned.marker, owned.existing, owned.behavior = peer_types[owned.worker_id]

        self.enterContext(patch.object(_InertContainment, "__init__", initialize))
        self.addCleanup(self._cleanup_fixture, parent)
        for index, (child, task) in enumerate(zip(plan["children"], tasks)):
            self._start_worker(parent, fixture, root, child, task, index)
        return parent

    @staticmethod
    def _start_worker(parent, fixture, root, child, task, index):
        child_id = child["child_id"]
        scope = {"allocation_class": "worker", "child_id": child_id, "ordinal": index}
        identity = canonical_sha256({"transaction_id": parent.plan["transaction_id"], **scope})
        parent.journal.append(event_type="allocation-intent", state="ALLOCATING", now=datetime.now(timezone.utc),
                              details=dict(scope, allocation_id=identity, requested_model=config.MODEL))
        spool = root / f"spool-{index}"
        spool.mkdir()
        worker = adapter._PoolWorker(parent, child, task, fixture / task["worker_slot"], spool, index + 1)
        parent.workers[child_id] = worker
        worker.start()

    @staticmethod
    def _cleanup_fixture(parent):
        parent.limits.barrier.abort()
        parent.cleanup(monotonic() + 2)

    @staticmethod
    def _wait(predicate):
        cutoff = monotonic() + 3
        while not predicate():
            if monotonic() >= cutoff:
                raise TimeoutError("inert original pipe produced no expected result")
            sleep(.01)

    def test_two_original_pipes_join_distinct_workers_and_both_startup_shapes(self):
        parent = self._prepare_workers(2)
        first, second = parent.workers.values()
        self.assertIsNone(first._startup.startup_rollout_sha256)
        self.assertEqual(second._startup.startup_rollout_sha256, second._startup_prefix["boundary_sha256"])
        for worker in (first, second):
            self.assertEqual(parent._settlement(worker)["thread_profile"],
                             {"id": config.PROFILE, "owner_identity_sha256": worker.containment.owner_identity_sha256,
                              "widening_refused": True})
        for worker in (first, second):
            worker.start_turn()
        self._wait(lambda: all(worker.poll() for worker in parent.workers.values()))
        self.assertEqual({proof.request_id for proof in parent.limits.proofs.values()}, {71})
        self.assertEqual(len({proof.startup.connection_epoch_sha256 for proof in parent.limits.proofs.values()}), 2)
        for worker in (first, second):
            self.assertEqual((worker.worktree / worker.task["write_path"]).read_text(), worker.task["expected_utf8"])
            self.assertEqual(worker._result["tools"]["unexpected"], ("apply_patch",))
            self.assertEqual(worker._result["tools"]["registered_tools"], ("cwo_finite.write_selected_fixture",))
            call, = worker.wire.qualified_tool_evidence.calls.values()
            self.assertEqual((call.tool, call.arguments), ("write_selected_fixture", b"{}"))
            self.assertEqual(adapter._WorkerControl(worker, {}).check(), {"decision": "complete"})
            worker.archive()
            self.assertIsNotNone(worker._archived)
        self.assertTrue(parent.cleanup(monotonic() + 2))
        status = [kind for _, kind in parent.limits.rows]
        self.assertLess(max(index for index, kind in enumerate(status) if kind == "tool-debit"), status.index("writer-gate"))

    def test_terminal_token_telemetry_remains_in_the_archived_boundary(self):
        parent = self._prepare_workers(2, ("terminal-token-counters", "terminal-token-counters"))
        first, second = parent.workers.values()
        ledger = AggregateUsageLedger(list(parent.workers))

        def observe(control, sequence):
            evidence = control.evidence("inert-state")
            return ledger.observe(child_id=control.worker.child_id, child_state_sha256=evidence["state_sha256"],
                                  decision_sequence=sequence, cumulative_usage=evidence["usage"])

        controls = [adapter._WorkerControl(worker, {"state_file": "inert-state"}) for worker in (first, second)]
        first.start_turn()
        self.assertEqual(controls[0].check(), {"decision": "continue"})
        self.assertEqual(observe(controls[0], 1).aggregate["tokens"], zero_token_usage())
        second.start_turn()
        self._wait(lambda: all(worker.poll() for worker in (first, second)))

        for control, cached, reasoning in zip(controls, (0, 4), (0, 1), strict=True):
            worker = control.worker
            with self.subTest(child=worker.child_id):
                self.assertEqual(control.check(), {"decision": "complete"})
                terminal = worker._result["boundary"]
                expected = {"input": 9, "cached_input": cached, "output": 3, "reasoning": reasoning, "total": 12}
                self.assertEqual(terminal["token_snapshot"], expected)
                self.assertEqual(observe(control, 2).delta["tokens"], zero_token_usage())
                worker.archive()
                original = adapter.locate_unique_session(worker.spool, worker.thread_id)
                self.assertEqual(original.store, "archived_sessions")
                archived, _ = adapter._capture_rollout(original.path, worker.thread_id, baseline=terminal)
                self.assertEqual(archived["token_snapshot"], expected)
        usage = ledger.aggregate
        self.assertEqual((usage["tool_calls"], usage["mutations"]), (2, 2))
        self.assertGreater(usage["runtime_seconds"], 0)
        self.assertEqual(usage["tokens"], zero_token_usage())

    def test_original_writer_reobserves_a_split_rollout_append(self):
        parent = self._prepare_workers(2, ("split-rollout-append", "complete-rollout-append"))
        split, complete = parent.workers.values()
        capture = adapter.capture_boundary
        observed_partial = []
        observed_complete = []
        complete_prefix = []

        def finish_after_partial(path, thread_id, *, baseline=None):
            try:
                boundary, records = capture(path, thread_id, baseline=baseline)
            except adapter.NativeSessionBoundaryError as failure:
                self.assertEqual((path, thread_id), (split._rollout, split.thread_id))
                self.assertEqual(str(failure), "session file has a trailing partial record")
                self.assertNotIn(split.child_id, parent.limits.proofs)
                self.assertNotIn(split.child_id, parent.limits.debits)
                self.assertFalse((split.worktree / split.task["write_path"]).exists())
                self.assertEqual(adapter._WorkerControl(split, {}).check(), {"decision": "continue"})
                observed_partial.append(path)
                self._finish_split_append(split)
                raise
            if path == complete._rollout:
                observed_complete.append(baseline)
                if len(observed_complete) == 1:
                    self.assertNotIn(complete.child_id, parent.limits.proofs)
                    self.assertNotIn(complete.child_id, parent.limits.debits)
                    self.assertFalse((complete.worktree / complete.task["write_path"]).exists())
                    complete_prefix.append({key: boundary[key] for key in ("byte_offset", "boundary_sha256")})
                    self._append_complete_rollout_row(path)
            return boundary, records

        with patch.object(adapter, "capture_boundary", finish_after_partial):
            split.start_turn()
            complete.start_turn()
            self._wait(lambda: any(worker.wire.transport_failure is not None for worker in (split, complete))
                       or all(worker.wire.terminal is not None for worker in (split, complete)))
        self.assertEqual(observed_partial, [split._rollout])
        self.assertIsNone(split.wire.transport_failure)
        self.assertIsNone(complete.wire.transport_failure)
        self.assertEqual(observed_complete, [complete._startup_prefix, *complete_prefix])
        self.assertEqual(parent.limits.proofs.keys(), parent.workers.keys())
        self.assertEqual(parent.limits.debits, parent.workers.keys())
        for worker in (split, complete):
            self.assertIsNotNone(worker.poll())
            self.assertEqual((worker.worktree / worker.task["write_path"]).read_text(), worker.task["expected_utf8"])
            worker.archive()
        self.assertTrue(parent.cleanup(monotonic() + 2))

    def _finish_split_append(self, worker):
        (worker.spool / "finish-append").touch()
        self._wait(lambda: (worker.spool / "append-finished").exists())

    @staticmethod
    def _append_complete_rollout_row(path):
        with path.open("ab") as stream:
            stream.write(b'{"type":"event_msg","payload":{"type":"agent_reasoning"}}\n')

    def _assert_rollout_refusal(self, behavior, reason, captures, *, finish_split=False, edit=None,
                                first_capture=None, after_capture=None):
        parent = self._prepare_workers(2, (behavior,))
        worker = next(iter(parent.workers.values()))
        capture = adapter.capture_boundary
        observed = []

        def observe(path, thread_id, *, baseline=None):
            if not observed and first_capture is not None:
                first_capture(path)
            observed.append(path)
            try:
                result = capture(path, thread_id, baseline=baseline)
            except adapter.NativeSessionBoundaryError:
                if finish_split and len(observed) == 1:
                    self._finish_split_append(worker)
                    if edit is not None:
                        edit(path)
                raise
            if after_capture is not None:
                after_capture(path, worker, len(observed))
            return result

        with patch.object(adapter, "capture_boundary", observe):
            try:
                worker.start_turn()
            except adapter.AppServerError:
                self.assertIsNotNone(worker.wire.transport_failure)
            self._wait(lambda: worker.wire.transport_failure is not None)
        self.assertRegex(str(worker.wire.transport_failure), reason)
        self.assertEqual(observed, [worker._rollout] * captures)
        self.assertFalse(parent.limits.proofs)
        self.assertFalse(parent.limits.debits)
        self.assertFalse((worker.worktree / worker.task["write_path"]).exists())
        self._cleanup_fixture(parent)

    def test_writer_refuses_a_persistent_rollout_tail_after_one_recheck(self):
        self._assert_rollout_refusal("persistent-rollout-tail", "trailing partial record$", 2)

    def test_writer_refuses_a_malformed_complete_record_without_a_recheck(self):
        self._assert_rollout_refusal("malformed-rollout-row", r"session record [0-9]+ is invalid$", 1)

    def _rewrite_rollout_prefix(self, path):
        with path.open("r+b") as stream:
            data = stream.read()
            self.assertIn(b"f" * 40, data)
            stream.seek(data.index(b"f" * 40))
            stream.write(b"e" * 40)

    def test_writer_refuses_a_changed_prefix_during_a_split_append(self):
        self._assert_rollout_refusal("split-rollout-append", "prefix was rewritten", 2,
                                     finish_split=True, edit=self._rewrite_rollout_prefix)

    @staticmethod
    def _replace_rollout_source(path):
        previous = path.rename(path.with_suffix(".previous"))
        path.touch(mode=0o600)
        path.write_bytes(previous.read_bytes())

    def test_writer_refuses_a_replaced_source_during_a_split_append(self):
        self._assert_rollout_refusal("split-rollout-append", "callback-rollout-replaced$", 2,
                                     finish_split=True, edit=self._replace_rollout_source)

    def test_writer_refuses_source_drift_at_the_first_partial_capture(self):
        self._assert_rollout_refusal("split-rollout-append", "active-rollout-source-drift$", 1,
                                     finish_split=True, first_capture=self._replace_rollout_source)

    def test_writer_refuses_a_durable_terminal_completed_by_the_split_append(self):
        self._assert_rollout_refusal("split-rollout-terminal", "callback-after-durable-terminal$", 2,
                                     finish_split=True)

    def test_writer_refuses_unstable_or_untrusted_complete_growth(self):
        def append(path, _worker):
            self._append_complete_rollout_row(path)

        def rewrite(path, _worker):
            stamp = path.stat()
            self._rewrite_rollout_prefix(path)
            os.utime(path, ns=(stamp.st_atime_ns, stamp.st_mtime_ns + 1_000_000_000))

        def rewrite_and_grow(path, worker):
            rewrite(path, worker)
            append(path, worker)

        def replace_and_grow(path, worker):
            self._replace_rollout_source(path)
            append(path, worker)

        def malformed(path, _worker):
            with path.open("ab") as stream:
                stream.write(b'{invalid fixture record}\n')

        def terminal(path, worker):
            row = {"type": "event_msg", "payload": {"type": "task_complete", "turn_id": worker.turn_id}}
            with path.open("ab") as stream:
                stream.write((json.dumps(row) + "\n").encode())

        cases = (
            ("repeated growth", append, "rollout-drift$", 2),
            ("equal-size rewrite", rewrite, "rollout-drift$", 1),
            ("rewrite plus growth", rewrite_and_grow, "prefix was rewritten", 2),
            ("replacement plus growth", replace_and_grow, "rollout-drift$", 1),
            ("malformed suffix", malformed, r"session record [0-9]+ is invalid$", 2),
            ("terminal suffix", terminal, "callback-after-durable-terminal$", 2),
        )
        for name, change, reason, captures in cases:
            with self.subTest(name=name):
                def mutate(path, worker, observation):
                    if observation == 1 or change is append:
                        change(path, worker)

                self._assert_rollout_refusal("complete-rollout-append", reason, captures, after_capture=mutate)

    def test_bad_callback_never_reaches_the_barrier_or_writer(self):
        parent, worker = self._refused_writer("wrong-command")
        self.assertIn("writer-policy", str(worker.wire.transport_failure))
        self.assertEqual(parent.limits.debits, set())
        self.assertFalse((worker.worktree / worker.task["write_path"]).exists())

    def test_check_reports_active_while_original_writer_gate_is_locked(self):
        parent = self._prepare_workers(2)
        first, second = parent.workers.values()
        control = adapter._WorkerControl(first, {})
        gate_entered, allow_release = Event(), Event()
        authorize = parent.limits.authorize_writer

        def hold_gate(child, thread, turn, request, request_sha256, release):
            def held_release():
                if child == first.child_id:
                    gate_entered.set()
                    if not allow_release.wait(parent.limits.remaining()):
                        raise TimeoutError("writer gate did not resume")
                release()

            authorize(child, thread, turn, request, request_sha256, held_release)

        with patch.object(parent.limits, "authorize_writer", hold_gate), ThreadPoolExecutor(1) as pool:
            for worker in (first, second):
                worker.start_turn()
            self.assertTrue(gate_entered.wait(parent.limits.remaining()))
            try:
                self.assertTrue(first.wire.requests.lock.locked())
                check = pool.submit(control.check)
                self.assertEqual(check.result(timeout=MAX_CERTIFIED_CHECK_MS / 1000), {"decision": "continue"})
                self.assertFalse((first.worktree / first.task["write_path"]).exists())
                self.assertIsNone(first._result)
            finally:
                allow_release.set()
            self._wait(lambda: all(worker.poll() for worker in parent.workers.values()))
            self.assertTrue(first._writer_done)
            self.assertEqual(control.check(), {"decision": "complete"})

    def test_legacy_command_refuses_before_pending_or_debit(self):
        parent, worker = self._refused_writer("legacy-command")
        self.assertIn("Dynamic tool identity or fields differ", str(worker.wire.transport_failure))
        self.assertIsNone(worker.wire._pending)
        self.assertFalse(worker.wire.qualified_tool_evidence.calls)
        self.assertFalse(parent.limits.debits)
        self.assertFalse((worker.worktree / worker.task["write_path"]).exists())

    def _refused_writer(self, behavior):
        parent = self._prepare_workers(2, (behavior,))
        worker = next(iter(parent.workers.values()))
        try:
            worker.start_turn()
        except adapter.AppServerError:
            # An original callback refusal can race the waiting start caller.
            self.assertIsNotNone(worker.wire.transport_failure)
        self._wait(lambda: worker.wire.transport_failure is not None)
        return parent, worker

    def test_three_workers_park_original_callbacks_before_any_writes(self):
        parent = self._prepare_workers(3)
        for worker in parent.workers.values():
            worker.start_turn()
        self._wait(lambda: all(worker.poll() for worker in parent.workers.values()))
        rows = parent.limits.rows
        first_gate = next(index for index, (_, kind) in enumerate(rows) if kind == "writer-gate")
        self.assertEqual({child for child, kind in rows[:first_gate] if kind == "tool-debit"}, parent.workers.keys())
        for worker in parent.workers.values():
            worker.archive()
        self.assertTrue(parent.cleanup(monotonic() + 2))

    def test_original_rollout_replacement_refuses_after_charge_before_write(self):
        parent = self._prepare_workers(2, ("replace-rollout",))
        first, second = parent.workers.values()
        first.start_turn()
        second.start_turn()
        self._wait(lambda: first.wire.transport_failure is not None and second.poll() is not None)
        self.assertIn("writer-gate-custody-drift", str(first.wire.transport_failure))
        self.assertFalse((first.worktree / first.task["write_path"]).exists())
        self.assertTrue((second.worktree / second.task["write_path"]).exists())

    def test_archive_acknowledgement_without_archive_effect_refuses(self):
        parent = self._prepare_workers(2, ("no-archive-move",))
        first, second = parent.workers.values()
        first.start_turn()
        second.start_turn()
        self._wait(lambda: first.poll() is not None and second.poll() is not None)
        with self.assertRaisesRegex(adapter.PoolQualificationAdapterError, "archive-did-not-preserve"):
            first.archive()
        self.assertIsNone(first._archived)

    def test_one_wrong_fixture_result_is_a_child_local_control_decision(self):
        parent = self._prepare_workers(2, ("wrong-marker",))
        first, second = parent.workers.values()
        for worker in (first, second):
            worker.start_turn()
        self._wait(lambda: all(worker.poll() for worker in parent.workers.values()))
        self.assertEqual(adapter._WorkerControl(first, {}).check(), {"decision": "interrupt"})
        self.assertEqual(adapter._WorkerControl(second, {}).check(), {"decision": "complete"})
        for worker in (first, second):
            self.assertIsNone(worker.wire.transport_failure)
            worker.archive()
        self.assertTrue(parent.cleanup(monotonic() + 2))

    def test_calibration_refuses_writer_then_interrupts_and_archives_original_turn(self):
        parent = self._prepare_workers(2, ("calibration", "calibration"), calibrating=True)
        workers = tuple(parent.workers.values())
        controls = self._bind_calibration_fixture(parent, workers)
        for key, control in controls.items():
            worker = parent.workers[key]
            control.arm(state_file=control.contract["state_file"], control_turn_id=control.contract["control_turn_id"])
            started = control.send_input(agent_id=worker.thread_id, message=worker.task["prompt"])
            control.mark_dispatched(**started)
        self._wait(lambda: all(worker.calibration_writer_refused() for worker in workers))
        self.assertFalse(parent.limits.proofs)
        self.assertFalse(parent.limits.debits)
        self.assertTrue(all(not (worker.worktree / worker.task["write_path"]).exists() for worker in workers))
        for control in controls.values():
            worker = control.worker
            self.assertEqual(control.check(), {"decision": "continue"})
            control.interrupt()
            self._wait(lambda: worker.wire.terminal == "interrupted")
            self.assertEqual(control.check(), {"decision": "complete"})
            control.finalize(control_action="interrupt-confirmed")
            self.assertEqual(control.close(), {"ack": "closed"})
            self.assertIsNotNone(worker._archived)
            self.assertIsNone(worker.wire.transport_failure)

    def _bind_calibration_fixture(self, parent, workers):
        parent.control_root = workers[0].spool.parent / "control"
        parent.control_root.mkdir()
        parent.children = {worker.child_id: worker.child for worker in workers}
        parent.controls = {}
        render = [{"child_id": worker.child_id, "control_turn_id": f"fixture-turn-{index}",
                   "state_file": str(parent.control_root / f"state-{index}.json"),
                   "control_contract_file": str(parent.control_root / f"contract-{index}.json")}
                  for index, worker in enumerate(workers)]
        parent.authority.update(render_request={"children": render}, initial_states={key: {} for key in parent.children})
        allocations = [{"child_id": worker.child_id, "session_id": worker.thread_id} for worker in workers]
        with patch.object(parent, "_verify_artifacts") as verify:
            controls = parent.bind_calibration_controls(parent.plan, allocations, {})
            verify.assert_called_once_with()
            with self.assertRaisesRegex(adapter.PoolQualificationAdapterError, "admitted-startup-set-drift"):
                parent.bind_calibration_controls(parent.plan, allocations, {})
        with self.assertRaisesRegex(adapter.PoolQualificationAdapterError, "calibration-cannot-bind-productive-launch"):
            parent.bind_admitted_launch(parent.plan, allocations, {})
        return controls

    def test_final_phase_is_required(self):
        parent = self._prepare_workers(2, ("missing-marker-phase", "wrong-marker-phase"))
        for worker in parent.workers.values():
            worker.start_turn()
        self._wait(lambda: all(worker.wire.terminal == "completed" for worker in parent.workers.values()))
        for worker in parent.workers.values():
            self.assertIsNone(worker.wire.transport_failure)
            self.assertIsNone(worker.wire.marker)
            with self.assertRaisesRegex(adapter.PoolQualificationAdapterError, "completion-marker-drift"):
                adapter._WorkerControl(worker, {}).check()

    def test_factory_refuses_unprotected_admission_and_has_no_hook_parameters(self):
        with _fixture_root() as root:
            plan, tasks, fixture = _fixture(root, 2)
            authority = root / "records" / "authority.json"
            authority.parent.mkdir()
            values = dict.fromkeys(adapter._AUTHORITY_FIELDS)
            values.update(scope=adapter._ORDINARY_SCOPE, mode="callback-calibration",
                          fixture_root=str(fixture), control_root=str(root / "control"),
                          journal_path=str(root / "control" / "run.jsonl"), beads={"directory": str(root),
                              "database": str(root / "disposable.db"), "actor": "qualification"},
                          spools={c["child_id"]: str(root / f"custody-{i}" / "spool") for i, c in enumerate(plan["children"])})
            (root / "control").mkdir()
            for spool in values["spools"].values():
                Path(spool).mkdir(parents=True, mode=0o700)
            plan = self._seal_authority(plan, authority, values)
            with self.assertRaisesRegex(NativePoolTransactionError, "original-ordinary-approval-required"):
                adapter.build_pool_qualification_runtime(plan, authority_path=authority, admission={})
            ordinary = SimpleNamespace()
            with patch("registered_pool_ordinary_runtime.require_ordinary_custody"):
                with self.assertRaisesRegex(adapter.PoolQualificationAdapterError, "original-admission-required"):
                    adapter.build_pool_qualification_runtime(plan, authority_path=authority, admission={}, ordinary=ordinary)
            with (patch("registered_pool_ordinary_runtime.require_ordinary_custody"),
                  patch.object(adapter, "_check_admission"), patch.object(host, "PoolWorkerContainment") as spawn):
                ordinary.project = root / "project"
                ordinary.integration_root = fixture
                ordinary.ledger = SimpleNamespace(root=root / "ledger")
                ordinary.lease_registry_path = root / "leases.json"
                ordinary.children = {child["child_id"]: SimpleNamespace(worktree=fixture / task["worker_slot"])
                                     for child, task in zip(plan["children"], tasks)}
                fixture_admission = SimpleNamespace(receipt={})
                with patch("registered_pool_ordinary_runtime.ordinary_pool_tasks", return_value={
                    child["child_id"]: task for child, task in zip(plan["children"], tasks)
                }):
                    self._assert_ordinary_runtime_bindings(plan, authority, values, fixture_admission, ordinary, spawn)

    def _assert_ordinary_runtime_bindings(self, plan, authority, values, fixture_admission, ordinary, spawn):
        factory = adapter.build_pool_qualification_runtime
        substitute = Mock(wraps=factory)
        with self.assertRaisesRegex(NativePoolTransactionError, "registered-factory-required"):
            stage.select_contained_pool_runtime(plan, substitute, ordinary=ordinary)
        substitute.assert_not_called()
        selection = stage.select_contained_pool_runtime(plan, factory, authority_path=authority,
                                                        admission=fixture_admission, ordinary=ordinary)
        runtime, bind, close = selection.runtime, selection.bind_limits, selection.cleanup
        parent = runtime.prepare.__self__
        run = stage.make_pool_qualification_run(plan, selection, journal_path=parent.journal.path,
                                               fixture_root=parent.fixture_root)
        for field in ("bind_limits", "cleanup"):
            with patch.object(stage, "_reserve_run") as reserve:
                with self.assertRaisesRegex(NativePoolTransactionError, "contained-runtime-hooks-mismatch"):
                    stage._accounted_run(replace(run, **{field: Mock()}), runtime, None, {})
                reserve.assert_not_called()
        self.assertIs(type(runtime), TransactionRuntime)
        self.assertIs(runtime.prepare.__self__, bind.__self__)
        self.assertIs(bind.__self__, close.__self__)
        self.assertEqual(runtime.trusted_session_count(), 0)
        self.assertEqual(list(Path(values["control_root"]).iterdir()), [])
        spawn.assert_not_called()
        with self.assertRaisesRegex(adapter.PoolQualificationAdapterError, "original-stage-mode-drift"):
            bind(object.__new__(PoolQualificationRunLimits))
        with self.assertRaisesRegex(adapter.PoolQualificationAdapterError, "calibration-capability-attachment-refused"):
            adapter.build_pool_qualification_runtime(plan, authority_path=authority, admission=fixture_admission, ordinary=ordinary,
                capability=object.__new__(ConnectedPoolCallbackCapability))
        authority.write_text("{}", encoding="utf-8")
        with self.assertRaisesRegex(adapter.PoolQualificationAdapterError, "protected-artifact-drift"):
            adapter.build_pool_qualification_runtime(plan, authority_path=authority, admission=fixture_admission, ordinary=ordinary)
        self._assert_productive_capability_refusals(plan, authority, values, fixture_admission, ordinary)

    @staticmethod
    def _seal_authority(plan, path, values):
        path.write_text(json.dumps(values), encoding="utf-8")
        path.chmod(0o600)
        return seal_transaction_plan({**plan, "authority_sha256": sha256(path.read_bytes()).hexdigest()})

    def _assert_productive_capability_refusals(self, plan, authority, values, admission, ordinary):
        values = {**values, "mode": adapter._ORDINARY_MODE, "capability_opportunity_sha256": "c" * 64}
        productive_plan = self._seal_authority(plan, authority, values)
        with self.assertRaisesRegex(adapter.PoolQualificationAdapterError, "original-connected-capability-required"):
            adapter.build_pool_qualification_runtime(productive_plan, authority_path=authority, admission=admission, ordinary=ordinary,
                capability={"receipt_sha256": "b" * 64})
        with self.assertRaisesRegex(CallbackCalibrationError, "original-connected-capability-required"):
            adapter.build_pool_qualification_runtime(productive_plan, authority_path=authority, admission=admission, ordinary=ordinary,
                capability=object.__new__(ConnectedPoolCallbackCapability))
        raw_plan = self._seal_authority(plan, authority, {**values, "capability_receipt": {}})
        with self.assertRaisesRegex(adapter.PoolQualificationAdapterError, "invalid-qualification-authority"):
            adapter.build_pool_qualification_runtime(raw_plan, authority_path=authority, admission=admission, ordinary=ordinary)

    def test_transport_eof_after_retirement_has_no_observation(self):
        parent = self._prepare_workers(2)
        self.assertTrue(parent.cleanup(monotonic() + 2))
        for worker in parent.workers.values():
            wire = worker.wire
            self.assertIsNone(wire.transport_failure)
            self.assertTrue(wire._retiring.is_set())
            failure = EOFError("fixture retired transport")
            wire._fail_transport(failure, source="protocol-read")
            self.assertIs(wire.transport_failure, failure)
            self.assertIsNone(wire.take_transport_failure_observation())


class PatchCallbackTests(unittest.TestCase):
    def test_only_patch_thread_registers_diff_schema(self):
        def schema(*, patch_mode):
            selectors = config.thread_start_selectors(Path("/checkout"), patch_mode=patch_mode)
            namespace, = selectors["dynamicTools"]
            tool, = namespace["tools"]
            self.assertEqual((namespace["name"], tool["name"]), (config.FINITE_TOOL_NAMESPACE, config.WRITER_TOOL))
            return tool["inputSchema"]

        self.assertEqual(schema(patch_mode=False), {
            "type": "object", "properties": {}, "additionalProperties": False,
        })
        self.assertEqual(schema(patch_mode=True), {
            "type": "object", "properties": {"diff": {"type": "string", "minLength": 1,
                                                      "maxLength": config.MAX_WORKER_DIFF_BYTES}},
            "required": ["diff"], "additionalProperties": False,
        })

    @staticmethod
    def _callback_wire(arguments, *, current, patch_mode):
        wire = object.__new__(adapter._WorkerWire)
        task = {"expected_utf8": None, "patch_preimage_sha256": "a" * 64} if patch_mode else {"expected_utf8": "fixed"}
        wire.factory = adapter._PoolWorker(None, {"child_id": "worker"}, task, None, None, 1)
        wire._items, wire._pending, wire.transport_failure = {}, None, None
        wire._retiring, wire._wire_turn, wire.connection_epoch_sha256 = Event(), ("thread", "turn", 3), "b" * 64
        wire.requests = adapter.RegisteredServerRequests(wire)
        wire.qualified_tool_evidence = adapter.QualifiedToolEvidence(wire)
        scope = {"threadId": "thread", "turnId": "turn"}
        binding = {"namespace": config.FINITE_TOOL_NAMESPACE, "tool": config.WRITER_TOOL}
        item = {"id": "call", "type": "dynamicToolCall", "status": "inProgress", **binding, "arguments": current}
        notice = {"method": "item/started", "params": {**scope, "item": item}}
        request = {"id": 71, "method": "item/tool/call", "params": {
            **scope, **binding, "callId": "call", "arguments": arguments,
        }}
        frames = [(json.dumps(message, ensure_ascii=True) + "\n").encode() for message in (notice, request)]
        wire.process = SimpleNamespace(stdout=frames, poll=lambda: None)
        lines = wire._protocol_lines()
        next(lines)
        wire._observe_notification(notice)
        next(lines)
        return wire, request, frames[1]

    def test_patch_callback_freezes_utf8_limited_diff_and_original_frame_hash(self):
        diff = "é" * (config.MAX_WORKER_DIFF_BYTES // 2)
        arguments = {"diff": diff}
        wire, request, original = self._callback_wire(arguments, current=arguments, patch_mode=True)
        pending = wire._take_writer(request)
        self.assertEqual((pending.request_id, pending.request_sha256), (71, sha256(original).hexdigest()))
        pending.params["arguments"]["diff"] = "alternate"
        self.assertEqual(pending.params["arguments"], {"diff": diff})
        with wire.requests.lock:
            wire._require_pending(pending)

    def test_patch_callback_refuses_wrong_mode_shape_or_current_item(self):
        for arguments, current, patch_mode, reason in (
            ({"diff": "text"}, {"diff": "text"}, False, "writer-policy"),
            ({}, {}, True, "writer-policy"),
            ({"diff": "", "path": "other"}, {"diff": "", "path": "other"}, True, "writer-policy"),
            ({"diff": "é" * (config.MAX_WORKER_DIFF_BYTES // 2 + 1)}, {}, True, "writer-policy"),
            ({"diff": "\ud800"}, {}, True, "writer-policy"),
            ({"diff": "submitted"}, {"diff": "observed"}, True, "callback-without-original-item"),
        ):
            with self.subTest(reason=reason, patch_mode=patch_mode):
                wire, request, _ = self._callback_wire(arguments, current=current, patch_mode=patch_mode)
                with self.assertRaisesRegex(adapter.PoolQualificationAdapterError, reason):
                    wire._take_writer(request)
                self.assertIsNone(wire._pending)
                self.assertEqual(wire.qualified_tool_evidence.calls, {})

    def test_deferred_callback_attestation_uses_the_selected_argument_contract(self):
        from cwo_core import native_pool_deferred_attestation as attestation

        startup = SimpleNamespace(session_id="thread", connection_epoch_sha256="a" * 64, owner_identity_sha256="b" * 64)
        callback = {"thread_id": startup.session_id, "turn_id": "turn", "epoch": startup.connection_epoch_sha256,
                    "owner_identity_sha256": startup.owner_identity_sha256, "tool": attestation.QUALIFICATION_TOOL,
                    "request_id": 71, "request_sha256": "c" * 64}
        for arguments, patch_mode in (({}, False), ({"diff": "approved diff"}, True)):
            with self.subTest(patch_mode=patch_mode):
                observation = {**callback, "arguments": arguments}
                self.assertEqual(attestation._pending_callback(observation, startup, "turn", patch_mode=patch_mode),
                                 (71, "c" * 64))
                with self.assertRaisesRegex(attestation.DeferredAttestationError, "pending-callback-binding-mismatch"):
                    attestation._pending_callback(observation, startup, "turn", patch_mode=not patch_mode)

    def test_patch_calibration_refuses_before_the_writer(self):
        arguments = {"diff": "inert calibration payload"}
        wire, request, _ = self._callback_wire(arguments, current=arguments, patch_mode=True)
        pending = wire._take_writer(request)
        wire.factory.parent = SimpleNamespace(calibration_only=True, limits=SimpleNamespace(remaining=lambda: 1))
        wire.factory._turn_ready.set()
        with patch.object(wire.factory, "write") as write, patch.object(wire, "_commit_callback_reply") as reply:
            wire._run_callback(pending)
        write.assert_not_called()
        reply.assert_called_once_with(pending, adapter._CALIBRATION_REFUSAL, success=False)

    def test_writer_mode_requires_exact_retained_task_selection(self):
        child = {"child_id": "worker"}
        for expected, preimage, reason in ((None, None, "fixed-writer-task-invalid"),
                                           ("fixed", "a" * 64, "patch-writer-task-invalid"),
                                           (None, "not-a-digest", "patch-writer-task-invalid")):
            with self.subTest(reason=reason):
                task = {"expected_utf8": expected, "patch_preimage_sha256": preimage}
                worker = adapter._PoolWorker(None, child, task, None, None, 1)
                with self.assertRaisesRegex(adapter.PoolQualificationAdapterError, reason):
                    worker._writer_selection()
        task = {"expected_utf8": None, "patch_preimage_sha256": "a" * 64}
        worker = adapter._PoolWorker(None, child, task, None, None, 1)
        task["patch_preimage_sha256"] = None
        self.assertEqual(worker._writer_selection(), (None, "a" * 64))


if __name__ == "__main__":
    unittest.main()
