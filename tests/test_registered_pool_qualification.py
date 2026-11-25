"""Original registered pipes with inert peers and fixed disposable outputs."""

from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from threading import Barrier, Lock
from time import monotonic, sleep
from types import SimpleNamespace
import unittest
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.append(str(SCRIPTS))

import registered_pool_configuration as config  # noqa: E402
import registered_pool_containment as host  # noqa: E402
import registered_pool_qualification as adapter  # noqa: E402
from registered_pool_qualification_capability import (  # noqa: E402
    CallbackCalibrationError,
    ConnectedPoolCallbackCapability,
)
from cwo_core.native_pool_contracts import canonical_sha256  # noqa: E402
from cwo_core.native_pool_qualification_fixtures import fixed_pool_qualification_cohorts  # noqa: E402
from cwo_core.native_pool_qualification_stage import PoolQualificationRunLimits  # noqa: E402
from cwo_core.native_pool_transaction import TransactionJournal, TransactionRuntime, seal_transaction_plan  # noqa: E402
from cwo_core.native_pool_workspace import capture_workspace_snapshot  # noqa: E402
from prepare_native_pool_qualification import _materialize_fixtures, _prepare  # noqa: E402
from tests.test_native_pool_transaction import bead, transaction_plan  # noqa: E402


def _pool_test_directory():
    # The actual thread/start frame includes the worktree path twice.
    # Use a short parent and separate the random name from the fixture path.
    return TemporaryDirectory(dir="/tmp", prefix="cwo.pool.", suffix=".test")


_PEER = r"""
import json
from pathlib import Path
import sys
from uuid import uuid4

inputs = json.loads(sys.argv[1])
home, login = Path(inputs['home']), Path(inputs['login'])
marker, behavior = inputs['marker'], inputs['behavior']
if behavior == 'wrong-marker':
    marker = 'wrong fixture marker'
thread, turn = str(uuid4()), str(uuid4())
call, answer = [inputs['worker'] + '-' + suffix for suffix in ('call', 'answer')]
active = home / 'sessions' / ('rollout-' + thread + '.jsonl')
archived = home / 'archived_sessions' / active.name
thread_scope = {'threadId': thread, 'turnId': turn}
tool = {'id': call, 'type': 'dynamicToolCall', 'namespace': inputs['namespace'], 'tool': inputs['tool'],
        'arguments': {'command': inputs['command']}, 'status': 'inProgress', 'contentItems': None, 'success': None}
meta = {'type': 'session_meta', 'payload': {'id': thread, 'cwd': inputs['worktree'], 'history_mode': 'legacy'}}

def emit(value):
    print(json.dumps(value, separators=(',', ':')), flush=True)

def notify(method, params):
    emit({'method': method, 'params': params})

def append(rows):
    active.parent.mkdir(exist_ok=True)
    with active.open('a', encoding='utf-8') as handle:
        for row in rows:
            handle.write(json.dumps(row, separators=(',', ':')) + '\n')

def response(req, result):
    emit({'id': req, 'result': result})

def event(kind, **extra):
    return {'type': 'event_msg', 'payload': {**extra, 'type': kind, 'turn_id': turn}}

for line in sys.stdin:
    frame = json.loads(line)
    req, method = frame.get('id'), frame.get('method')
    params = frame.get('params', {})
    if method == 'initialize':
        response(req, {'codexHome': str(login)})
    elif method == 'initialized':
        continue
    elif method == 'thread/start':
        if inputs['existing']:
            append([meta])
        path = login / 'sessions' / active.name
        profile = {'id': params['permissions'], 'extends': None}
        result = {key: params[key] for key in ('model', 'modelProvider', 'serviceTier', 'cwd', 'runtimeWorkspaceRoots',
                                                'approvalPolicy', 'approvalsReviewer')}
        result.update(reasoningEffort=inputs['effort'], activePermissionProfile=profile,
                      thread={'id': thread, 'path': str(path), 'turns': [], 'ephemeral': False, 'historyMode': 'legacy'})
        response(req, result)
    elif method == 'turn/start':
        assert 'permissions' not in params
        if behavior in ('deferred-context', 'deferred-empty'):
            if behavior == 'deferred-empty' and not inputs['existing']:
                active.parent.mkdir(exist_ok=True)
                active.touch(mode=0o600)
            else:
                append(([] if inputs['existing'] else [meta]) + [event('task_started')])
            response(req, {'turn': {'id': turn, 'items': [], 'status': 'inProgress'}})
            continue
        effort = 'low' if behavior == 'wrong-context' else params['effort']
        append(([] if inputs['existing'] else [meta]) + [event('task_started'),
            {'type': 'world_state', 'payload': {'full': True, 'state': {'top_level_tools': {'apply_patch': 'f' * 40}}}},
            {'type': 'turn_context', 'payload': {'turn_id': turn, 'model': params['model'], 'effort': effort}}])
        response(req, {'turn': {'id': turn, 'items': [], 'status': 'inProgress'}})
        notify('item/started', dict(thread_scope, item=tool))
        command = 'unapproved' if behavior == 'wrong-command' else inputs['command']
        emit({'id': 71, 'method': 'item/tool/call', 'params': dict(thread_scope, callId=call,
              namespace=inputs['namespace'], tool=inputs['tool'], arguments={'command': command})})
    elif method is None and req == 71:
        result = frame['result']
        if behavior == 'calibration':
            assert result == {'success': False, 'contentItems': [{'type': 'inputText', 'text':
                'The registered writer is closed during callback calibration.'}]}
            notify('item/completed', dict(thread_scope, item=dict(tool, status='failed') | result))
            continue
        if result['success'] is False:
            assert result['contentItems'] == [{'type': 'inputText', 'text':
                'The registered writer refused the requested fixture write.'}]
            marker = 'The fixture write was refused.'
        status = 'completed' if result['success'] else 'failed'
        notify('item/completed', dict(thread_scope, item=dict(tool, status=status) | result))
        if behavior == 'failed-terminal':
            error = {'message': 'Synthetic worker failure after the registered write'}
            append([event('task_complete', last_agent_message=None, error=error)])
            notify('turn/completed', {'threadId': thread, 'turn': {'id': turn, 'status': 'failed', 'items': [], 'error': error}})
            continue
        final = {'id': answer, 'type': 'agentMessage', 'text': ''}
        if behavior != 'missing-marker-phase':
            final['phase'] = 'finalAnswer' if behavior == 'wrong-marker-phase' else 'final_answer'
        notify('item/started', dict(thread_scope, item=final))
        append([event('task_complete', last_agent_message=marker, error=None)])
        notify('item/completed', dict(thread_scope, item=dict(final, text=marker)))
        notify('turn/completed', {'threadId': thread, 'turn': {'id': turn, 'status': 'completed', 'items': []}})
    elif method == 'thread/archive':
        if behavior != 'no-archive-move':
            archived.parent.mkdir(exist_ok=True)
            active.rename(archived)
        response(req, {})
    elif method == 'turn/interrupt':
        append([event('turn_aborted')])
        response(req, {})
        notify('turn/completed', {'threadId': thread, 'turn': {'id': turn, 'status': 'interrupted', 'items': []}})
    else:
        raise ValueError('Unexpected inert peer input')
"""


class _Limits:
    isolation_target = None

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
                  "namespace": config.FINITE_TOOL_NAMESPACE, "tool": config.WRITER_TOOL, "command": config.WRITER_COMMAND,
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


def _fixture(root, size):
    plan_data = _prepare(1, {"sessions": 3, "tool_calls": 3, "runtime_seconds": 5})
    _materialize_fixtures(root / "fixture", plan_data)
    fixture = root / "fixture" / f"n{size}" / "run-1"
    tasks = fixed_pool_qualification_cohorts()[size - 2]["tasks"]
    issues = [bead(f"test-{index}", task["write_path"]) for index, task in enumerate(tasks, 1)]
    plan = transaction_plan(root / "plan", issues, cumulative_before=0)
    plan["selected_model"] = config.MODEL
    source = Path(adapter.__file__).resolve()
    plan["runtime_adapter_path"] = str(source)
    plan["runtime_adapter_sha256"] = sha256(source.read_bytes()).hexdigest()
    for child, task in zip(plan["children"], tasks):
        path = fixture / task["worker_slot"]
        child["worktree_identity_sha256"] = canonical_sha256(capture_workspace_snapshot(path, allowed_paths=child["write_paths"])["identity"])
        child["requested_model"] = config.MODEL
    return seal_transaction_plan(plan), tasks, fixture


class RegisteredPoolQualificationTests(unittest.TestCase):
    def _prepare_workers(self, size, behaviors=(), *, calibrating=False):
        root = Path(self.enterContext(_pool_test_directory()))
        plan, tasks, fixture = _fixture(root, size)
        parent = object.__new__(adapter._PoolParent)
        parent.plan, parent.limits, parent.workers, parent._started = plan, _Limits(size), {}, 0
        parent.tasks = {child["child_id"]: task for child, task in zip(plan["children"], tasks)}
        parent.authority = {"mode": "callback-calibration" if calibrating else "qualification"}
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
            self.assertEqual(adapter._WorkerControl(worker, {}).check(), {"decision": "complete"})
            worker.archive()
            self.assertIsNotNone(worker._archived)
        self.assertTrue(parent.cleanup(monotonic() + 2))
        status = [kind for _, kind in parent.limits.rows]
        self.assertLess(max(index for index, kind in enumerate(status) if kind == "tool-debit"), status.index("writer-gate"))

    def test_bad_callback_never_reaches_the_barrier_or_writer(self):
        parent = self._prepare_workers(2, ("wrong-command",))
        worker = next(iter(parent.workers.values()))
        try:
            worker.start_turn()
        except adapter.AppServerError:
            # An original callback refusal can race the waiting start caller.
            self.assertIsNotNone(worker.wire.transport_failure)
        self._wait(lambda: worker.wire.transport_failure is not None)
        self.assertIn("writer-policy", str(worker.wire.transport_failure))
        self.assertEqual(parent.limits.debits, set())
        self.assertFalse((worker.worktree / worker.task["write_path"]).exists())

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
        with _pool_test_directory() as scratch:
            root = Path(scratch)
            plan, tasks, fixture = _fixture(root, 2)
            authority = root / "records" / "authority.json"
            authority.parent.mkdir()
            values = dict.fromkeys(adapter._AUTHORITY_FIELDS)
            values.update(scope=adapter._AUTHORITY_SCOPE, mode="callback-calibration",
                          fixture_root=str(fixture), control_root=str(root / "control"),
                          journal_path=str(root / "control" / "run.jsonl"), beads={"directory": str(root),
                              "database": str(root / "disposable.db"), "actor": "qualification"},
                          spools={c["child_id"]: str(root / f"custody-{i}" / "spool") for i, c in enumerate(plan["children"])})
            (root / "control").mkdir()
            plan = self._seal_authority(plan, authority, values)
            with self.assertRaisesRegex(adapter.PoolQualificationAdapterError, "original-admission-required"):
                adapter.build_pool_qualification_runtime(plan, authority_path=authority, admission={})
            with patch.object(adapter, "_check_admission"), patch.object(host, "PoolWorkerContainment") as spawn:
                fixture_admission = SimpleNamespace(receipt={})
                runtime, bind, close = adapter.build_pool_qualification_runtime(
                    plan, authority_path=authority, admission=fixture_admission)
                self.assertIs(type(runtime), TransactionRuntime)
                self.assertIs(runtime.prepare.__self__, bind.__self__)
                self.assertIs(bind.__self__, close.__self__)
                self.assertEqual(runtime.trusted_session_count(), 0)
                self.assertEqual(list((root / "control").iterdir()), [])
                spawn.assert_not_called()
                with patch.object(adapter.native_live_availability, "require_pool_qualification"):
                    with self.assertRaisesRegex(adapter.PoolQualificationAdapterError, "original-stage-mode-drift"):
                        bind(object.__new__(PoolQualificationRunLimits))
                with self.assertRaisesRegex(adapter.PoolQualificationAdapterError, "calibration-capability-attachment-refused"):
                    adapter.build_pool_qualification_runtime(plan, authority_path=authority, admission=fixture_admission,
                        capability=object.__new__(ConnectedPoolCallbackCapability))
                authority.write_text("{}", encoding="utf-8")
                with self.assertRaisesRegex(adapter.PoolQualificationAdapterError, "protected-artifact-drift"):
                    adapter.build_pool_qualification_runtime(plan, authority_path=authority, admission=fixture_admission)
                self._assert_productive_capability_refusals(plan, authority, values, fixture_admission)

    @staticmethod
    def _seal_authority(plan, path, values):
        path.write_text(json.dumps(values), encoding="utf-8")
        path.chmod(0o600)
        return seal_transaction_plan({**plan, "authority_sha256": sha256(path.read_bytes()).hexdigest()})

    def _assert_productive_capability_refusals(self, plan, authority, values, admission):
        values = {**values, "mode": "qualification", "capability_opportunity_sha256": "c" * 64}
        productive_plan = self._seal_authority(plan, authority, values)
        with self.assertRaisesRegex(adapter.PoolQualificationAdapterError, "original-connected-capability-required"):
            adapter.build_pool_qualification_runtime(productive_plan, authority_path=authority, admission=admission,
                capability={"receipt_sha256": "b" * 64})
        with self.assertRaisesRegex(CallbackCalibrationError, "original-connected-capability-required"):
            adapter.build_pool_qualification_runtime(productive_plan, authority_path=authority, admission=admission,
                capability=object.__new__(ConnectedPoolCallbackCapability))
        raw_plan = self._seal_authority(plan, authority, {**values, "capability_receipt": {}})
        with self.assertRaisesRegex(adapter.PoolQualificationAdapterError, "invalid-qualification-authority"):
            adapter.build_pool_qualification_runtime(raw_plan, authority_path=authority, admission=admission)


if __name__ == "__main__":
    unittest.main()
