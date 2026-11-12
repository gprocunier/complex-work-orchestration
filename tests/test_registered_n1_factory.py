"""Original production RPC and host validators, fake OS/process effects only."""
from __future__ import annotations

import copy
import builtins
import hashlib
import io
import json
import os
from pathlib import Path
import queue
import shutil
import subprocess
import sys
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'tests')]
import registered_n1_factory as runtime  # noqa: E402
import test_linux_owned_children as children  # noqa: E402
import test_offline_admitted_n1 as fixtures  # noqa: E402
import test_maintenance_authority as authorities  # noqa: E402
from cwo_core.host_records import HostRecordStore, using_test_store  # noqa: E402
from test_offline_host_crash_matrix import cleanup_helper  # noqa: E402
from test_local_admission_preparation import example_route  # noqa: E402
from test_route_feasibility_preparation import bind  # noqa: E402

# These are the existing initialize, thread/start and turn/start RPC bounds.
# Observing the first fixture boundary includes their whole startup envelope.
STARTUP_OBSERVATION_SECONDS = 10 + 10 + 30


def wait_for_startup(test, event, worker, outcome):
    deadline = time.monotonic() + STARTUP_OBSERVATION_SECONDS
    while not event.is_set():
        if not worker.is_alive():
            if outcome and isinstance(outcome[0], BaseException):
                raise outcome[0]
            test.fail('EXAMPLE original worker ended before the requested startup boundary')
        remaining = deadline - time.monotonic()
        test.assertGreater(remaining, 0, 'EXAMPLE original startup observation expired')
        event.wait(min(.01, remaining))
    return True


class Lines:
    _EOF = object()

    def __init__(self):
        self.lines = queue.Queue()
        self.closed = False
        self.on_line = None
        self.buffer = self
        self._lock = threading.Lock()
        self._eof = False

    def put(self, value):
        with self._lock:
            if self.closed or self._eof:
                raise ValueError('EXAMPLE stream is closed')
            self.lines.put(json.dumps(value) + '\n')

    def readline(self, size=-1):
        with self._lock:
            if self._eof:
                return ''
        # A quiet pipe blocks until bytes or explicit EOF; idleness is not a
        # transport exception. The owner closes this stream before bounded joins.
        value = self.lines.get()
        if value is self._EOF or value == '':
            with self._lock:
                self._eof = True
                # Wake any reader that was already blocked before EOF latched.
                self.lines.put(self._EOF)
            return ''
        if self.on_line is not None:
            self.on_line(value)
        return value

    def read(self, size):
        return self.readline(size).encode()

    def __iter__(self):
        while True:
            value = self.readline()
            if not value:
                return
            yield value

    def close(self):
        with self._lock:
            if not self.closed:
                self.closed = True
                self.lines.put(self._EOF)


def finish_worker(test, worker, *releases, join_seconds=12):
    """Release held fixture callbacks, then require bounded worker completion."""
    for release in releases:
        release.set()
    worker.join(join_seconds)
    test.assertFalse(worker.is_alive(), 'EXAMPLE fixture worker did not stop before cleanup')


class Input:
    def __init__(self, process):
        self.process = process
        self.closed = False
        self.descriptor = None
        self.reader = None
        self.failure = None
        self.failed_input_frame = None
        self.acknowledged_failure = None

    def fileno(self):
        if self.descriptor is None:
            read_fd, self.descriptor = os.pipe()
            self.reader = threading.Thread(target=self.consume, args=(read_fd,), daemon=True)
            self.reader.start()
        return self.descriptor

    def consume(self, descriptor):
        failed_frame = None
        try:
            with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
                for line in stream:
                    try:
                        message = json.loads(line)
                    except json.JSONDecodeError:
                        failed_frame = line
                        raise
                    self.process.receive(message)
        except BaseException as failure:
            self.failure = failure
            self.failed_input_frame = failed_frame
            raise

    def require_healthy(self):
        self.close()
        if self.reader is not None:
            self.reader.join(1)
            self.process.case.test.assertFalse(self.reader.is_alive(),
                'EXAMPLE fake input producer did not stop before cleanup')
        if self.failure is not None and self.failure is not self.acknowledged_failure:
            raise self.failure

    def acknowledge_failure(self, failure):
        if (self.failure is None or failure is not self.failure
                or type(failure) is not json.JSONDecodeError
                or self.failed_input_frame is None or failure.doc != self.failed_input_frame):
            raise ValueError('EXAMPLE acknowledgement requires the exact recorded input parse failure')
        self.acknowledged_failure = failure

    def write(self, value):
        self.process.receive(json.loads(value))
        return len(value)

    def flush(self):
        pass

    def close(self):
        if not self.closed and self.descriptor is not None:
            os.close(self.descriptor)
            self.reader.join(timeout=1)
        self.closed = True


class RegisteredEffectServer(fixtures.AdmittedFakeServer):
    """EXAMPLE producer: the accepted command creates output before later requests."""

    def __init__(self, root, worker, task):
        super().__init__(root, worker, task)
        self.useful_recorded = False

    def begin_useful(self):
        # Bind the frozen admission while the initial records are private. No
        # observer may see a legacy model/effort that completion later repairs.
        if self.path.exists():
            raise AssertionError('EXAMPLE effect session was already published')
        staged = copy.copy(self)
        staged.path = self.path.with_suffix('.EXAMPLE-staging')
        try:
            staged.set_boundary('valid')
            execution = json.loads(self.admission.execution_bytes)
            records = [json.loads(line) for line in staged.path.read_text().splitlines()]
            for record in records:
                if record['type'] == 'turn_context':
                    record['payload'].update(model=execution['model'], effort=execution['effort'])
            staged.path.write_text(''.join(json.dumps(record) + '\n' for record in records))
            os.replace(staged.path, self.path)
        finally:
            staged.path.unlink(missing_ok=True)
        self.record_completed_write()
        self.useful_recorded = True

    def set_boundary(self, mode):
        if mode == 'valid' and self.useful_recorded:
            return None
        return super().set_boundary(mode)

    def record_completed_write(self):
        if not self.useful_recorded:
            super().record_completed_write()

    def record_refusal(self, label, command, response):
        """Retain the original tool failure in the checked session records."""
        call = 'EXAMPLE-effect-' + label
        output = 'EXAMPLE refused ' + label + ': ' + json.dumps(response, sort_keys=True)
        event = {'turn_id': self.turn_id, 'call_id': call, 'command': [command],
                 'cwd': str(self.root), 'source': 'agent'}
        formatted = ('Chunk ID: EXAMPLE_EFFECT\nWall time: 0.001 seconds\n'
                     'Process exited with code 1\nFinal output:\n' + output)
        self.append_fake_record('response_item', {'type': 'function_call',
            'name': 'exec_command', 'call_id': call,
            'arguments': json.dumps({'cmd': command, 'workdir': str(self.root)})})
        self.append_fake_record('event_msg', {'type': 'exec_command_begin', **event})
        self.append_fake_record('event_msg', {'type': 'exec_command_end', **event,
            'exit_code': 1, 'stdout': '', 'stderr': output,
            'aggregated_output': output, 'formatted_output': formatted,
            'status': 'completed', 'duration': {'secs': 0, 'nanos': 1_000_000}})
        self.append_fake_record('response_item', {'type': 'function_call_output',
            'call_id': call, 'output': formatted})


class RegisteredEffectSpy:
    """Harmless positive controls that would expose any admitted forbidden effect."""

    def __init__(self):
        self.calls = dict.fromkeys(('write', 'network', 'process', 'read'), 0)
        self.memory = {'read': 'EXAMPLE private marker'}
        self.ordinary_failures = 0

    def perform(self, effect):
        self.calls[effect] += 1
        if effect == 'read':
            return self.memory['read']
        self.memory[effect] = 'EXAMPLE effect occurred'
        return self.memory[effect]

    def consume_denial(self, response):
        if response != {'decision': 'decline'}:
            raise AssertionError('EXAMPLE read must be refused before ordinary failure')
        self.ordinary_failures += 1
        raise OSError('EXAMPLE denied read')


class RpcProcess(children.FakeChild):
    """An EXAMPLE process boundary, never installed as a runtime adapter."""

    def __init__(self, process, case, validator=False):
        super().__init__(process)
        self.case, self.validator = case, validator
        self.stdin, self.stdout, self.stderr = Input(self), Lines(), Lines()
        case.test.addCleanup(self.stdin.require_healthy)
        # Even a failed owner cleanup must release fake blocking readers before
        # the composed fixture finishes its bounded cleanup callbacks.
        case.test.addCleanup(self.stdout.close)
        case.test.addCleanup(self.stderr.close)
        self.stdout.on_line = self.read_line
        self.methods, self.replies = [], []
        self.pending = None

    def read_line(self, value):
        if value.startswith('EXAMPLE-oversized-frame'):
            # Fake kernel observation: the original retained child has exited
            # before the original stdout reader's finally block polls it.
            self.process.alive = False
            self.stderr.lines.put('')

    poll = runtime._PipeChild.poll
    wait = runtime._PipeChild.wait

    def stop(self):
        if not self.validator and getattr(self.case, "release_race", False):
            return
        self.stdout.lines.put('')
        if hasattr(self.stderr, 'lines'):
            self.stderr.lines.put('')
        else:
            self.finish_diagnostic()

    def diagnostic_pipe(self):
        read_fd, self.diagnostic_writer = os.pipe()
        self.stderr = os.fdopen(read_fd, 'r', encoding='utf-8')
        self.diagnostic_bytes = 0
        self.diagnostic_written = threading.Event()
        def produce(descriptor):
            data = memoryview(b'EXAMPLE diagnostic ' * 4096)
            try:
                while data:
                    count = os.write(descriptor, data[:4096])
                    self.diagnostic_bytes += count
                    data = data[count:]
            except OSError:
                if self.process.alive:
                    raise
            finally:
                self.diagnostic_written.set()
        self.diagnostic_thread = threading.Thread(target=produce, args=(self.diagnostic_writer,), daemon=True)
        self.diagnostic_thread.start()
        self.case.test.addCleanup(self.finish_diagnostic)

    def finish_diagnostic(self):
        if self.diagnostic_writer is not None:
            os.close(self.diagnostic_writer)
            self.diagnostic_writer = None
        self.diagnostic_thread.join(timeout=1)

    def communicate(self, data, timeout):
        self.case.test.assertEqual(timeout, 10)
        self.stdin.write(data)
        self.stdin.close()
        return self.stdout.readline(), ''

    def receive(self, message):
        case = self.case
        if self.validator:
            if not self.process.alive:
                return
            # Execute the fixed validator with original _compare and real data;
            # only its process/OS boundary is fake. No accepting validator stub.
            output = io.StringIO()
            with patch.object(sys, 'stdin', io.TextIOWrapper(io.BytesIO(json.dumps(message).encode()))), patch.object(sys, 'stdout', output):
                exec(runtime._VALIDATOR.replace("sys.path.insert(0,'/cwo/scripts')", ''), {})
            self.stdout.lines.put(output.getvalue())
            self.process.alive = False
            self.returncode = 0
            return
        if 'method' not in message:
            # Preserve the supplied reply observation when this callback resumes
            # after containment. Each wire witness separately establishes its
            # physical write/parse ordering; this list makes no timing claim.
            self.replies.append(message)
            if not self.process.alive:
                return
            if (self.pending is not None and message.get('result') == {'decision': 'accept'}
                    and not getattr(case, 'effect_schedule', False)
                    and (not getattr(case, 'defer_complete', False) or message['id'] == 'EXAMPLE-request')):
                self.complete()
            return
        if not self.process.alive:
            return
        method, params = message['method'], message['params']
        self.methods.append(method)
        if method == 'initialized':
            return
        if method == 'thread/start' and not getattr(case, 'no_fake_scheduler', False):
            self.before_consumption(self.settled, armed=lambda: self.pending is not None)
        if method == 'turn/start':
            self.pending = 'requested'
        result = self.result(method, params)
        if not self.process.alive:
            return
        self.stdout.put({'id': message['id'], 'result': result})
        if method == 'thread/archive' and case.archive_fault:
            self.before_consumption(lambda: getattr(case.factory.server, 'request_failure', None) is not None)
            self.stdout.put({'id': 'EXAMPLE-late-required-request', 'method': 'item/tool/requestUserInput', 'params': {}})
        if method == 'thread/archive' and case.archive_frame_fault:
            self.before_consumption(lambda: not case.factory.server._reader_threads[0].is_alive())
            self.stdout.lines.put('EXAMPLE-oversized-frame' + 'x' * 65536 + '\n')
        if method == 'turn/start':
            # Approval arrives after the turn response has been installed. Use
            # the next original thread/read RPC as its actual request boundary.
            # Bound the fake child scheduler at the original Condition wait.
            # The original reader and real input pipe keep running; no validator
            # or decision is replaced. Waiting for the real child completion
            # avoids spending the fixture's accelerated host ticks on a callback.
            self.approve()
        if method == 'thread/read' and self.pending is True:
            self.pending = 'requested'
            self.approve()

    def settled(self):
        release = getattr(self.case, 'release_turn_response', False)
        if release:
            return release.is_set() if isinstance(release, threading.Event) else True
        gate = getattr(self.case, 'scheduler_gate', None)
        if gate is not None and not gate.is_set():
            return False
        return (self.pending is None or self.case.factory.server.transport_failure is not None or
                (len(self.replies) == getattr(self, 'expected_replies', None) and
                 self.replies[-1].get('result') != {'decision': 'accept'}))

    def before_consumption(self, observed, *, armed=lambda: True):
        """Control only the real Condition scheduling boundary, never acceptance."""
        condition = self.case.factory.server._condition
        original = condition.wait
        done = False
        def wait(timeout=None):
            nonlocal done
            result = original(timeout)
            if not done and armed():
                done = True
                state = condition._release_save()
                try:
                    deadline = time.monotonic() + 8
                    while not observed():
                        if time.monotonic() >= deadline:
                            raise AssertionError('EXAMPLE wire scheduler did not observe its actual boundary')
                        time.sleep(0.001)
                finally:
                    condition._acquire_restore(state)
            return result
        condition.wait = wait

    def result(self, method, params):
        case, scenario = self.case, self.case.scenario
        if method == 'initialize':
            return {'codexHome': str(case.home)}
        if method == 'thread/start':
            if getattr(case, 'stderr_flood', False):
                case.test.assertTrue(self.diagnostic_written.wait(2))
            response = scenario.thread_response(mutable=True)
            response.update(case.spec['profile_readback'], model=case.spec['model'], modelProvider=case.spec['provider'])
            response.pop('sandbox')
            if case.drift:
                response['activePermissionProfile']['id'] = 'EXAMPLE_FALLBACK'
            return response
        if method == 'turn/start':
            self.case.test.assertEqual(params['input'][0]['text'].encode(), case.receipt.request_bytes)
            scenario.observe_intent(params['input'][0]['text'])
            scenario.started_threads[scenario.thread_id] = scenario.turn_id
            return {'turn': {'id': scenario.turn_id}}
        if method == 'thread/read':
            thread, _latency = scenario.read_thread(scenario.thread_id)
            return {'thread': thread}
        if method == 'thread/archive':
            scenario.archive_thread(scenario.thread_id)
            return {}
        if method == 'turn/interrupt':
            scenario.interrupt_turn(scenario.thread_id, scenario.turn_id)
            return {}
        raise AssertionError('Unexpected EXAMPLE RPC: ' + method)

    def approve(self):
        if not self.process.alive:
            return
        case, scenario = self.case, self.case.scenario
        self.expected_replies = (1 + len(getattr(case, 'request_probes', [])) +
                                 len(case.probe_approvals) + int(case.repeat_approval))
        item = {'id': 'EXAMPLE-item', 'type': 'commandExecution', 'command': case.spec['command'],
                'cwd': str(case.host.worker), 'status': 'inProgress'}
        self.stdout.put({'method': 'item/started', 'params': {'threadId': scenario.thread_id, 'turnId': scenario.turn_id, 'item': item}})
        params = {'itemId': item['id'], 'threadId': scenario.thread_id, 'turnId': scenario.turn_id,
                  'startedAtMs': 1000, 'approvalId': 'EXAMPLE-approval', 'kind': 'command',
                  'command': item['command'], 'cwd': item['cwd'], 'availableDecisions': ['accept', 'decline']}
        params.update(case.approval_change)
        for request_id, method, changes in getattr(case, 'request_probes', []):
            probe = {name: params[name] for name in ('threadId', 'turnId', 'itemId', 'startedAtMs')}
            probe.update(changes)
            self.stdout.put({'id': request_id, 'method': method, 'params': probe})
        if case.probe_approvals:
            for index, change in enumerate(case.probe_approvals):
                denied = dict(params, approvalId='EXAMPLE-denied-' + str(index), **change)
                self.stdout.put({'id': 'EXAMPLE-denied-' + str(index), 'method': runtime.protocol.COMMAND, 'params': denied})
        self.stdout.put({'id': 'EXAMPLE-request', 'method': runtime.protocol.COMMAND, 'params': params})
        if case.repeat_approval:
            self.stdout.put({'id': 'EXAMPLE-repeated-request', 'method': runtime.protocol.COMMAND, 'params': params})

    def complete(self):
        if not self.process.alive:
            return
        case, scenario = self.case, self.case.scenario
        published = scenario.path
        scenario.path = published.with_suffix('.EXAMPLE-staging')
        scenario.complete_turn()
        # Reuse the original session/receipt grammar fixture. These are raw
        # producer records, still checked by every original accepting consumer.
        records = [json.loads(line) for line in scenario.path.read_text().splitlines()]
        for record in records:
            if record['type'] == 'turn_context':
                record['payload'].update(model=case.spec['model'], effort=case.spec['effort'])
        scenario.path.write_text(''.join(json.dumps(record) + '\n' for record in records))
        os.replace(scenario.path, published)
        scenario.path = published
        if case.bad_output:
            (case.host.worker / 'result.txt').write_bytes(b'EXAMPLE wrong output\n')
        self.pending = None


class RegisteredEffectRpcProcess(RpcProcess):
    """One selected original RPC runner with useful work before typed follow-ups."""

    EFFECTS = ('write', 'network', 'process', 'read', 'ordinary-retry', 'escalation')

    def approve(self):
        if not self.process.alive:
            return
        super().approve()
        self.expected_replies = 1 + len(self.EFFECTS)

    def complete(self):
        if not self.process.alive:
            return
        # This session is already public. Its server suppresses a second
        # initial boundary/write and appends the actual terminal on this inode.
        self.case.scenario.complete_turn()
        if self.case.bad_output:
            (self.case.host.worker / 'result.txt').write_bytes(b'EXAMPLE wrong output\n')
        self.pending = None

    def settled(self):
        # Passive capture of the seventh decline precedes its active callback.
        # Keep the original release/gate rules, but also require actual finish.
        return super().settled() and (self.pending is None or
                                     self.case.factory.server.transport_failure is not None)

    def receive(self, message):
        super().receive(message)
        if not self.process.alive:
            return
        if self.validator or 'method' in message or not self.case.effect_schedule:
            return
        if message.get('id') == 'EXAMPLE-request':
            self.case.test.assertEqual(message['result'], {'decision': 'accept'})
            self.case.scenario.begin_useful()
            self.case.useful_output_before_followup = (self.case.host.worker / 'result.txt').read_bytes()
            self._followup(self.EFFECTS[0])
            return
        label = message.get('id', '').removeprefix('EXAMPLE-effect-request-')
        if label not in self.EFFECTS:
            return
        self.case.effect_responses[label] = copy.deepcopy(message)
        if message.get('result') in ({'decision': 'accept'}, {'permissions': {'network': {'enabled': True}}}):
            self.case.effect_spy.perform('read' if label in {'ordinary-retry', 'escalation'} else label)
        self.case.scenario.record_refusal(label, self._effect_command(label), message)
        if label == 'read':
            try:
                self.case.effect_spy.consume_denial(message['result'])
            except OSError as failure:
                self.case.ordinary_error = failure
        next_index = self.EFFECTS.index(label) + 1
        if next_index < len(self.EFFECTS):
            self._followup(self.EFFECTS[next_index])
        else:
            self.complete()

    def _effect_command(self, effect):
        if effect == 'write':
            return 'EXAMPLE_WRITE'
        if effect == 'network':
            return 'EXAMPLE_NETWORK'
        if effect == 'process':
            return 'EXAMPLE_PROCESS'
        if effect == 'escalation':
            return self.case.spec['command']
        return 'EXAMPLE_READ'

    def _followup(self, effect):
        if not self.process.alive:
            return
        case, scenario = self.case, self.case.scenario
        if effect == 'ordinary-retry':
            case.test.assertEqual(case.ordinary_error.args, ('EXAMPLE denied read',))
        item_id = 'EXAMPLE-effect-item-' + effect
        method = runtime.protocol.COMMAND
        item = {'id': item_id, 'type': 'commandExecution', 'status': 'inProgress',
                'command': self._effect_command(effect), 'cwd': str(case.host.worker)}
        params = {'threadId': scenario.thread_id, 'turnId': scenario.turn_id,
                  'itemId': item_id, 'startedAtMs': 1000}
        if effect == 'write':
            method = runtime.protocol.FILE
            item['type'] = 'fileChange'
            params.update(grantRoot=str(case.host.worker), reason='EXAMPLE requested write')
        elif effect == 'network':
            method = runtime.protocol.PERMISSIONS
            params.update(cwd=str(case.host.worker),
                          permissions={'network': {'enabled': True}}, reason='EXAMPLE requested network')
        else:
            params.update(approvalId='EXAMPLE-effect-approval-' + effect,
                          kind='command', command=item['command'], cwd=item['cwd'],
                          availableDecisions=['accept', 'decline'])
            if effect == 'ordinary-retry':
                params['reason'] = 'EXAMPLE ordinary failure retry'
            elif effect == 'escalation':
                params.update(reason='EXAMPLE ordinary failure retry',
                              additionalPermissions={'fileSystem': {'read': ['EXAMPLE-private']}},
                              commandActions=[{'type': 'read', 'command': item['command'],
                                               'name': 'EXAMPLE-private', 'path': 'EXAMPLE-private'}])
        self.stdout.put({'method': 'item/started', 'params': {
            'threadId': scenario.thread_id, 'turnId': scenario.turn_id, 'item': item}})
        self.stdout.put({'id': 'EXAMPLE-effect-request-' + effect,
                         'method': method, 'params': params})


def settle_original_archive(fixture, case):
    """Observe this case's original archive outside accelerated host ticks.

    Positive wire/validation joins opt in explicitly. Other hosts and cases
    keep the original concurrent close schedule, including refusal/race tests.
    """
    if getattr(case, '_original_archive_settlement', False):
        return
    archive_type = sys.modules[runtime.RegisteredAdapter.finalize.__module__].StagedThreadArchive
    original_start = archive_type.start

    def start(archive):
        result = original_start(archive)
        if getattr(getattr(archive.server, 'factory', None), 'host', None) is case.host:
            # Same original eight-second observation used by the wire fixture.
            # require_complete rethrows the actual archive/containment failure.
            archive.require_complete(timeout_seconds=8)
        return result

    fixture.enterContext(patch.object(archive_type, 'start', start))
    case._original_archive_settlement = True


class FactoryTests(unittest.TestCase):
    def setUp(self):
        self.repositories = fixtures.RepositoryFixture(self)
        self.host_records = HostRecordStore.for_tests(self.repositories.root / 'EXAMPLE-PROVENANCE')
        self.enterContext(using_test_store(self.host_records))
        self.original_popen = subprocess.Popen
        self.memfd_create = runtime.owned.ctypes.CDLL(None, use_errno=True).memfd_create
        self.processes = children.ControllerTests(methodName='runTest')
        self.addCleanup(cleanup_helper, self, self.processes)
        self.authority = authorities.MaintenanceAuthorityTests(methodName='runTest')
        self.addCleanup(cleanup_helper, self, self.authority)
        self.authority.setUp()
        self.events = []

    def case(self, *, archive_schedule='concurrent', **changes):
        if archive_schedule not in ('concurrent', 'settled'):
            raise ValueError('Unknown original archive fixture schedule.')
        from types import SimpleNamespace
        repo = self.repositories
        state = repo.root / 'EXAMPLE-host'
        state.mkdir(mode=0o700)
        (state / 'records').mkdir(mode=0o700)
        host = runtime.native.OfflineN1Host(state, repo.target, repo.worker)
        # A record-builder fixture lives behind the fake process/RPC boundary;
        # the *adapter* is the production RegisteredAdapter + registered AppServer.
        effect_schedule = changes.pop('effect_schedule', False)
        server_type = RegisteredEffectServer if effect_schedule else fixtures.AdmittedFakeServer
        scenario = server_type(state / 'fake-server', repo.worker, '')
        home = scenario.codex_home
        home.chmod(0o700)
        # Preserve the original host's legacy reserved child directory name.
        # The requested CODEX_HOME is this exact independently selected home.
        scenario.root = repo.worker
        (state / 'fake-server').chmod(0o700)
        policy = runtime.validation.freeze_policy({'version': 1, 'outputs': [{
            'path': 'result.txt', 'validator': 'bytes', 'size': len(fixtures.host_fixtures.OUTPUT),
            'sha256': hashlib.sha256(fixtures.host_fixtures.OUTPUT).hexdigest()}]})
        spec = {'launcher': '/usr/bin/bwrap', 'executable': str(Path(sys.executable).resolve()),
                'validator': str(Path(sys.executable).resolve()), 'model': 'gpt-6.1-sol',
                'provider': changes.pop('provider', 'EXAMPLE-provider'), 'effort': 'xhigh',
                'thread_start': {'permissions': 'EXAMPLE_ROOT_DENY', 'approvalPolicy': 'untrusted', 'approvalsReviewer': 'user', 'ephemeral': True},
                'profile_readback': {'activePermissionProfile': {'id': 'EXAMPLE_ROOT_DENY', 'extends': None}, 'approvalPolicy': 'untrusted', 'approvalsReviewer': 'user'},
                'pre_effect': {'profile': 'EXAMPLE_ROOT_DENY', 'policy_id': 'EXAMPLE-reported-profile',
                               'rules': [], 'hooks': [], 'grants': [], 'network': False, 'input_capability': 'finite'},
                'command': fixtures.host_fixtures.FAKE_WRITE_COMMAND,
                'expected_token': fixtures.host_fixtures.TOKEN,
                'configuration_pins': {'w14': 'EXAMPLE-reported-config', 'w15': 'EXAMPLE-reported-profile'},
                'validation_policy': policy.report, 'max_steps': changes.pop('max_steps', 64), 'purpose': 'local-engineering',
                'implementation_sha256': runtime.implementation_sha256()}
        finite_tool_mode = changes.pop('finite_tool_mode', None)
        if finite_tool_mode is not None:
            spec['finite_tool_mode'] = finite_tool_mode
        spec['configuration_files'] = {'rules/default.rules': '', 'config.toml':
            'default_permissions = "EXAMPLE_ROOT_DENY"\napproval_policy = "untrusted"\napprovals_reviewer = "user"\n'
            'model = "gpt-6.1-sol"\nmodel_reasoning_effort = "xhigh"\nservice_tier = "default"\n'
            '[permissions.EXAMPLE_ROOT_DENY.filesystem]\n"/" = "deny"\n'
            + json.dumps(str(host.worker)) + ' = "write"\n[permissions.EXAMPLE_ROOT_DENY.network]\nenabled = false\n'}
        for key in ('executable', 'launcher', 'validator'):
            spec[key + '_sha256'] = runtime._file(spec[key])[1]
        spec['custody'] = {'state': str(host.state), 'worker': str(host.worker), 'target': str(host.target),
                           'ledger': str(repo.root / 'EXAMPLE-ledger'), 'initial': copy.deepcopy(host._initial),
                           'state_identity': copy.deepcopy(host._state_identity)}
        if changes.pop('executable_pin_mismatch', False):
            spec['executable_sha256'] = hashlib.sha256(b'EXAMPLE different executable').hexdigest()
        route = example_route()
        node = route['nodes'][0]
        node['execution'].update(model=spec['model'], provider=spec['provider'], effort=spec['effort'], options={'registered_n1': copy.deepcopy(spec)})
        sizing = runtime.admission.planner.work_sizing
        node['estimate_source']['requested_model'] = spec['model']
        node['unit_estimate'] = sizing.evaluate_work_estimate(node['estimate_source'], policy=route['policy'])
        node['source_sha256'] = sizing.canonical_work_estimate_sha256(node['estimate_source'])
        node['unit_sha256'] = sizing.canonical_work_estimate_sha256(node['unit_estimate'])
        node['rendered_request'] = runtime.admission.planner.render_request(node)
        route['limits'] = dict.fromkeys(runtime.admission.planner.RESOURCES, 1_000_000_000)
        bind(route)
        clock, owners = fixtures.ledger_fixtures.FakeClock(), fixtures.ledger_fixtures.FakeOwners()
        receipt = runtime.admission.prepare(route, node['id'], now=clock.now, expires_at=clock.now + 60)
        spec['admission_sha256'] = runtime.admission._receipt_sha256(receipt)
        scenario.expected_task = receipt.request_bytes.decode()
        ledger = runtime.admission.ledger_api.InvocationLedger(repo.root / 'EXAMPLE-ledger', clock=clock, owner_probe=owners)
        scenario.ledger, scenario.admission = ledger, receipt
        scenario.expected_observers = ['RegisteredN1Factory._observer']
        case = SimpleNamespace(test=self, host=host, scenario=scenario, home=home, spec=spec, route=route,
                               receipt=receipt, node_id=node['id'], ledger=ledger, policy=policy,
                               drift=False, bad_output=False, approval_change={}, probe_approvals=[], repeat_approval=False,
                               archive_fault=False, raced_approval=False, archive_frame_fault=False, on_startup=None,
                               effect_schedule=effect_schedule, effect_spy=RegisteredEffectSpy(),
                               effect_responses={}, ordinary_error=None, useful_output_before_followup=None)
        for key, value in changes.items():
            setattr(case, key, value)
        self._boundaries(case)
        self._authority(case)
        if archive_schedule == 'settled':
            settle_original_archive(self, case)
        return case

    def _authority(self, case):
        a = self.authority
        a.workspace = case.host.worker
        a.mission['scope']['workspace_roots'] = [str(a.workspace)]
        a.mission['scope']['models'] = [case.spec['model']]
        a.mission_hash = authorities.mission_sha256(a.mission)
        a.directive = a.sign(a.mission_hash, 'EXAMPLE-mission')
        a.adapter = Path(runtime.__file__).resolve()
        a.registry['installed-native-v1'] = {'adapter_path': str(a.adapter), 'adapter_sha256': hashlib.sha256(a.adapter.read_bytes()).hexdigest()}
        controller = case.host.state.parent / 'EXAMPLE-authority'
        controller.mkdir(mode=0o700)
        a.store = authorities.MaintenanceStateStore(controller, mission_id=a.mission['mission_id'], mission_sha256=a.mission_hash)
        a.store.initialize()
        a.verifier = a.make_verifier()
        plan, operation, _directive = a.operation(operation_id='EXAMPLE-operation')
        plan['registered_n1'] = copy.deepcopy(case.spec)
        plan['selected_model'] = case.spec['model']
        plan['children'][0]['requested_model'] = case.spec['model']
        operation['model'] = case.spec['model']
        directive = a.reseal(plan, operation)
        case.capability = a.verifier.verify_operation(plan, operation, directive)
        case.capability.claim()
        case.verifier = a.verifier

    def _boundaries(self, case):
        # Held-route fixtures replace OS/process effects, then explicitly
        # patch the installed hold for this test's lifetime only.
        self.enterContext(patch.object(runtime.live_availability, 'N1_LIVE_AVAILABLE', True))
        self.processes.setUp()
        runtime.owned.ctypes.CDLL.return_value.memfd_create = self.memfd_create
        # Keep actual bounded git capture subprocesses; deny other Popen calls.
        subprocess.Popen.side_effect = self.original_popen
        self.tables, self.spawned = [], []
        test = self
        class FakeBackend(children.FakeLinux, runtime._PipeBackend):
            spawn = runtime._PipeBackend.spawn
            def __init__(self, pass_fds):
                children.FakeLinux.__init__(self)
                self.pass_fds = pass_fds
                test.tables.append(self)
                test.processes.tables.append(self)
            def _popen(self, argv, executable, workspace):
                test.assertEqual(test.attempt(case)['state'], 'invocation-intent')
                test.assertEqual(argv[1], '--args')
                args_fd = int(argv[2])
                raw = os.pread(args_fd, 32768, 0)
                argv = [argv[0], *raw.decode().rstrip('\0').split('\0')]
                test.assertIn('--block-fd', argv)
                test.held.add(int(argv[argv.index('--block-fd') + 1]))
                test.assertIn('--unshare-all', argv)
                validator = runtime._VALIDATOR in argv
                if not validator and test.spawned and hasattr(case, 'tool_spawn_entered'):
                    case.tool_spawn_entered.set()
                    case.tool_spawn_release.wait(12)
                result = children.FakeLinux._popen(self, argv, executable, workspace)
                result.process.executable, result.process.cwd = executable, workspace
                process_type = RegisteredEffectRpcProcess if case.effect_schedule else RpcProcess
                process = process_type(result.process, case, validator=validator)
                if not validator and getattr(case, 'blocked_stdin', False):
                    read_fd, write_fd = os.pipe()
                    os.set_blocking(write_fd, False)
                    try:
                        while True:
                            os.write(write_fd, b'EXAMPLE pipe backpressure\n' * 256)
                    except BlockingIOError:
                        pass
                    os.set_blocking(write_fd, True)
                    case.blocked_read = read_fd
                    process.stdin = os.fdopen(write_fd, 'w', buffering=1, encoding='utf-8')
                if not validator and getattr(case, 'stderr_flood', False):
                    process.diagnostic_pipe()
                self.children[-1] = process
                self.events.append(('spawn', validator))
                self.spawn_calls[-1] = (argv, executable, workspace)
                test.spawned.append(process)
                test.events.append(('spawn', validator))
                if not validator and case.on_startup is not None:
                    case.on_startup()
                test.assertEqual(test.attempt(case)['observers'], ['RegisteredN1Factory._observer'])
                info_fd = int(argv[argv.index('--info-fd') + 1])
                pid = 2147000000 + len(test.spawned)
                test.namespace_children[pid] = validator
                os.write(info_fd, json.dumps({'child-pid': pid}).encode())
                return process
        self.enterContext(patch.object(runtime, '_PipeBackend', FakeBackend))
        # Run the *actual* namespace observer. Fake only its kernel readlinks;
        # info-fd bytes traverse real pipes and every accepting check stays real.
        self.namespace_children = {}
        self.namespace_handles = {}
        def namespace_pidfd(pid, flags):
            self.assertIn(pid, self.namespace_children)
            self.assertEqual(flags, 0)
            read_fd, write_fd = os.pipe()
            self.namespace_handles[read_fd] = pid
            self.addCleanup(os.close, write_fd)
            return read_fd
        self.enterContext(patch.object(os, 'pidfd_open', namespace_pidfd))
        original_text = Path.read_text
        def proc_text(path, *args, **kwargs):
            if path.parent == Path('/proc/self/fdinfo') and int(path.name) in self.namespace_handles:
                return 'Pid:\t' + str(self.namespace_handles[int(path.name)]) + '\n'
            if path.name == 'status' and path.parent.name.isdigit() and int(path.parent.name) in self.namespace_children:
                return 'NSpid:\t' + path.parent.name + '\t1\n'
            return original_text(path, *args, **kwargs)
        self.enterContext(patch.object(Path, 'read_text', proc_text))
        original_readlink = os.readlink
        def readlink(path, *args, **kwargs):
            parts = Path(path).parts
            if len(parts) == 5 and parts[1] == 'proc' and parts[2].isdigit() and int(parts[2]) in self.namespace_children:
                if parts[4] == 'mnt':
                    test.events.append(('observe', self.namespace_children[int(parts[2])]))
                return 'EXAMPLE-isolated-' + parts[4]
            return original_readlink(path, *args, **kwargs)
        self.enterContext(patch.object(os, 'readlink', readlink))
        # Fake children do not inherit actual pipe descriptors. Keep the peer
        # ends until the gate write to model the kernel operation without EPIPE.
        real_close = os.close
        self.held = set()
        def close(fd):
            if fd not in self.held:
                real_close(fd)
                self.namespace_handles.pop(fd, None)
        self.enterContext(patch.object(runtime.os, 'close', close))
        self.addCleanup(lambda: [real_close(fd) for fd in self.held])
        original_signal = self.processes.signal_api.side_effect
        def signal_child(descriptor, signum):
            value = original_signal(descriptor, signum)
            for table in test.tables:
                for child in table.children:
                    if not child.process.alive:
                        child.stop()
            return value
        self.processes.signal_api.side_effect = signal_child
        # Our fixed validator runs as a fake process; its output pipe still
        # exposes the standard select boundary.
        select_original = runtime.select.select
        def select(reads, writes, errors, timeout=None):
            if reads and reads[0] in self.namespace_handles:
                return (reads, [], []) if not self.spawned[-1].process.alive else ([], [], [])
            if reads and isinstance(reads[0], Lines):
                return reads, [], []
            return select_original(reads, writes, errors, timeout)
        self.enterContext(patch.object(runtime.select, 'select', select))

    def factory(self, case, **options):
        factory = runtime.RegisteredN1Factory(case.capability, case.verifier, receipt=case.receipt,
            route=case.route, node_id=case.node_id, ledger=case.ledger, host=case.host, policy=case.policy,
            **options)
        case.factory = factory
        return factory

    def attempt(self, case):
        path = case.ledger.root / runtime.admission.ledger_api.LEDGER_FILE
        return next(iter(json.loads(path.read_bytes())['attempts'].values()))

    def test_original_rpc_useful_capture_validation_and_no_redispatch(self):
        case = self.case(archive_schedule='settled')
        factory = self.factory(case)
        result = factory.run()
        self.assertEqual(result['attempt']['outcome'], 'completed')
        self.assertIsInstance(factory.adapter, runtime.native.LiveThreadAdapter)
        self.assertIs(type(factory.server), runtime._RegisteredServer)
        self.assertIn('turn/start', self.spawned[0].methods)
        self.assertIn('thread/archive', self.spawned[0].methods)
        self.assertEqual(self.spawned[0].replies[0]['result'], {'decision': 'accept'})
        self.assertEqual(len(self.spawned), 2)
        host, token, report, target, policy = factory.issued_artifact()
        self.assertEqual(runtime.validation.consume_validated(host, token, report, target, policy),
                         (('result.txt', fixtures.host_fixtures.OUTPUT),))
        self.assertIs(factory.run(), result)
        self.assertEqual(len(self.spawned), 2)
        self.assertEqual([event[0] for event in self.events], ['spawn', 'observe', 'spawn', 'observe'])
        self.assertTrue(factory.server.lifetime.termination['child_reaped'])

    def test_same_rpc_denies_grants_stdin_and_unknown_context_before_useful_command(self):
        case = self.case(archive_schedule='settled', probe_approvals=[
            {'additionalPermissions': {'network': {'enabled': True}}, 'reason': 'EXAMPLE ordinary retry'},
            {'kind': 'writeStdin', 'reason': 'EXAMPLE empty or nonempty input is unknown'},
            {'itemId': 'EXAMPLE-unknown-item', 'reason': 'EXAMPLE reassuring text'},
            {'availableDecisions': ['acceptForSession']},
            {'proposedExecpolicyAmendment': ['EXAMPLE widening']},
        ])
        factory = self.factory(case)
        factory.run()
        replies = self.spawned[0].replies
        self.assertEqual([reply['result']['decision'] for reply in replies], ['decline'] * 5 + ['accept'])
        self.assertEqual(len(self.spawned), 2)

    def test_original_registered_useful_then_forbidden_effect_matrix(self):
        case = self.case(archive_schedule='settled', effect_schedule=True)
        factory = self.factory(case)
        boundary_api = sys.modules[runtime.RegisteredAdapter.finalize.__module__]
        initial, passive = {}, []
        original_begin, original_receive = RegisteredEffectServer.begin_useful, RpcProcess.receive

        def begin(server):
            original_begin(server)
            initial['raw'] = server.path.read_bytes()
            initial['stat'] = server.path.stat()
            initial['summary'] = boundary_api.session_boundary_summary(
                server.codex_home, server.thread_id, None, turn_id=server.turn_id,
                expected_workdir=server.root)

        def receive(process, message):
            original_receive(process, message)
            if message.get('id') == 'EXAMPLE-effect-request-escalation':
                # Controlled observation after passive capture, before the
                # final active refusal and terminal append can run.
                passive.append((RpcProcess.settled(process), process.settled(), process.pending))

        with patch.object(RegisteredEffectServer, 'begin_useful', begin), patch.object(RpcProcess, 'receive', receive):
            result = factory.run()
        runner = self.spawned[0]
        self.assertEqual(passive, [(True, False, 'requested')])
        final_raw, final_stat = case.scenario.path.read_bytes(), case.scenario.path.stat()
        self.assertTrue(final_raw.startswith(initial['raw']))
        self.assertGreater(len(final_raw), len(initial['raw']))
        self.assertEqual((initial['stat'].st_dev, initial['stat'].st_ino),
                         (final_stat.st_dev, final_stat.st_ino))
        context = [json.loads(line)['payload'] for line in initial['raw'].splitlines()
                   if json.loads(line)['type'] == 'turn_context']
        self.assertEqual([(item['model'], item['effort']) for item in context],
                         [(case.spec['model'], case.spec['effort'])])
        summary = boundary_api.session_boundary_summary(case.home, case.scenario.thread_id, None,
            turn_id=case.scenario.turn_id, baseline=initial['summary'],
            expected_source_identity_sha256=initial['summary']['source_identity_sha256'],
            expected_workdir=case.host.worker)
        self.assertGreater(summary['record_count'], initial['summary']['record_count'])
        self.assertIs(type(runner), RegisteredEffectRpcProcess)
        self.assertIs(runner, factory.server.process)
        self.assertEqual(case.useful_output_before_followup, fixtures.host_fixtures.OUTPUT)
        self.assertEqual((case.host.worker / 'result.txt').read_bytes(), fixtures.host_fixtures.OUTPUT)
        self.assertEqual(result['attempt']['outcome'], 'completed')
        self.assertEqual(result['attempt']['charge'], result['attempt']['amount'])
        self.assertIsNone(result['attempt']['observed_usage'])
        self.assertEqual(case.ordinary_error.args, ('EXAMPLE denied read',))
        self.assertEqual(case.effect_spy.ordinary_failures, 1)
        self.assertEqual(list(case.effect_responses), list(RegisteredEffectRpcProcess.EFFECTS))
        self.assertEqual(set(case.effect_responses), set(RegisteredEffectRpcProcess.EFFECTS))
        for effect, response in case.effect_responses.items():
            expected = {'permissions': {}} if effect == 'network' else {'decision': 'decline'}
            with self.subTest(effect=effect):
                self.assertEqual(response['result'], expected)
        self.assertEqual(case.effect_spy.calls, dict.fromkeys(case.effect_spy.calls, 0))
        self.assertEqual(len(runner.replies), 7)
        self.assertEqual([event[0] for event in self.events], ['spawn', 'observe', 'spawn', 'observe'])
        self.assertEqual(runner.methods.count('turn/start'), 1)
        self.assertEqual(runner.methods.count('thread/start'), 1)
        self.assertIsNone(factory.server.transport_failure)
        evidence = factory.server._effective_thread_start_evidence[factory.adapter.thread_id]
        self.assertEqual(evidence['request']['permissions'], case.spec['thread_start']['permissions'])
        self.assertEqual(evidence['response']['activePermissionProfile'],
                         case.spec['profile_readback']['activePermissionProfile'])
        self.assertEqual(evidence['response']['approvalPolicy'], 'untrusted')
        self.assertEqual(evidence['response']['approvalsReviewer'], 'user')
        self.assertFalse(evidence['request']['allowProviderModelFallback'])
        self.assertNotIn('sandbox', evidence['request'])
        self.assertNotIn('sandbox', evidence['response'])
        raw = case.scenario.path.read_text()
        for effect in RegisteredEffectRpcProcess.EFFECTS:
            self.assertIn('EXAMPLE refused ' + effect, raw)
        approvals = [json.loads(path.read_text())['observation'] for path in
                     sorted((factory.records / 'transport-observations').iterdir())
                     if json.loads(path.read_text())['stage'] == 'approval']
        self.assertEqual(len(approvals), 7)
        self.assertEqual([entry['decision'] for entry in approvals].count('accept'), 1)
        self.assertEqual([entry['decision'] for entry in approvals].count('decline'), 6)
        by_id = {entry['id']: entry for entry in approvals}
        self.assertEqual(by_id['EXAMPLE-effect-request-write']['method'], runtime.protocol.FILE)
        self.assertEqual(by_id['EXAMPLE-effect-request-network']['method'], runtime.protocol.PERMISSIONS)
        self.assertEqual(by_id['EXAMPLE-effect-request-network']['params']['permissions'],
                         {'network': {'enabled': True}})
        retry = by_id['EXAMPLE-effect-request-ordinary-retry']['params']
        escalation = by_id['EXAMPLE-effect-request-escalation']['params']
        self.assertEqual(retry['reason'], escalation['reason'])
        self.assertNotIn('additionalPermissions', retry)
        self.assertEqual(escalation['command'], case.spec['command'])
        self.assertEqual(escalation['additionalPermissions']['fileSystem']['read'], ['EXAMPLE-private'])
        self.assertEqual(self.attempt(case)['state'], 'terminal')
        host, token, report, target, policy = factory.issued_artifact()
        self.assertEqual(token, factory.token)
        self.assertEqual(runtime.validation.consume_validated(host, token, report, target, policy),
                         (('result.txt', fixtures.host_fixtures.OUTPUT),))
        self.assertIs(factory.run(), result)
        self.assertEqual(len(self.spawned), 2)
        control = RegisteredEffectSpy()
        self.assertEqual([control.perform(effect) for effect in control.calls],
                         ['EXAMPLE effect occurred'] * 3 + ['EXAMPLE private marker'])
        self.assertEqual(list(control.calls.values()), [1] * 4)

    def test_registration_refuses_mixed_unknown_or_widened_reported_facts(self):
        case = self.case()
        for field, change in (
            ('thread_start', {'sandbox': 'workspace-write'}),
            ('pre_effect', {'input_capability': 'unknown'}),
            ('pre_effect', {'grants': ['EXAMPLE grant']}),
            ('pre_effect', {'rules': ['EXAMPLE allow']}),
            ('pre_effect', {'network': True}),
        ):
            spec = copy.deepcopy(case.spec)
            spec[field].update(change)
            with self.subTest(field=field, change=list(change)), self.assertRaises(ValueError):
                runtime._profile(spec)
        self.assertEqual(self.spawned, [])

    def test_mutated_original_route_refuses_before_any_startup_effect(self):
        case = self.case()
        factory = self.factory(case)
        factory.route['purpose'] = 'EXAMPLE mutated task'
        with self.assertRaises(ValueError):
            factory.run()
        self.assertEqual(self.spawned, [])

    def test_registered_path_cannot_replace_independently_pinned_executable_bytes(self):
        case = self.case(executable_pin_mismatch=True)
        with self.assertRaisesRegex(ValueError, 'registered bytes'):
            self.factory(case)
        self.assertEqual(self.spawned, [])

    def test_repeated_wire_approval_identity_loses_control_without_capture_or_retry(self):
        case = self.case(repeat_approval=True)
        factory = self.factory(case)
        with self.assertRaises(ValueError):
            factory.run()
        self.assertIsNotNone(factory.server.request_failure)
        self.assertIn('Repeated approval', str(factory.server.request_failure))
        self.assertIsNone(factory.token)
        self.assertFalse((case.host.state / 'artifact').exists())
        with self.assertRaises(ValueError):
            factory.run()
        self.assertEqual(len(self.spawned), 1)
        self.assertEqual(self.attempt(case)['charge'], self.attempt(case)['amount'])

    def test_lost_namespace_observation_keeps_gate_closed_and_charge_retained(self):
        case = self.case()
        factory = self.factory(case)
        original = os.readlink
        def same_namespace(path, *args, **kwargs):
            parts = Path(path).parts
            if len(parts) == 5 and parts[1] == 'proc' and parts[2].isdigit() and int(parts[2]) in self.namespace_children:
                return original('/proc/self/ns/' + parts[4])
            return original(path, *args, **kwargs)
        with patch.object(os, 'readlink', same_namespace), patch.object(os, 'write', wraps=os.write) as writes:
            with self.assertRaisesRegex(ValueError, 'namespace'):
                factory.run()
        self.assertNotIn(b'1', [call.args[1] for call in writes.call_args_list])
        self.assertEqual(self.spawned[0].methods, [])
        self.assertEqual(self.attempt(case)['charge'], self.attempt(case)['amount'])

    def test_projected_import_and_productive_path_do_not_import_test_modules(self):
        case = self.case(archive_schedule='settled')
        factory = self.factory(case)
        projection = self.repositories.root / 'EXAMPLE-projection'
        shutil.copytree(ROOT / 'scripts', projection / 'scripts')
        shutil.copytree(ROOT / 'policy', projection / 'policy')
        shutil.copytree(ROOT / 'schemas', projection / 'schemas')
        code = "import sys;sys.path.insert(0,sys.argv[1]);import registered_n1_factory;assert not any(n.startswith('test_') for n in sys.modules)"
        process = self.original_popen([sys.executable, '-I', '-S', '-c', code, str(projection / 'scripts')],
                            env={}, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        _out, error = process.communicate(timeout=10)
        self.assertEqual(process.returncode, 0, error.decode()[:500])
        # Also exercise the productive production path with test imports denied.
        original = builtins.__import__
        def importing(name, *args, **kwargs):
            if name == 'tests' or name.startswith('test_'):
                raise AssertionError('EXAMPLE forbidden runtime fixture import')
            return original(name, *args, **kwargs)
        with patch.object(builtins, '__import__', importing):
            factory.run()
            factory.issued_artifact()
        self.assertFalse((projection / 'tests').exists())

    def test_actual_profile_fallback_retains_charge_and_never_turns(self):
        case = self.case(drift=True)
        factory = self.factory(case)
        with self.assertRaisesRegex(ValueError, 'readback'):
            factory.run()
        self.assertNotIn('turn/start', self.spawned[0].methods)
        attempt = self.attempt(case)
        self.assertEqual(attempt['charge'], attempt['amount'])
        with self.assertRaisesRegex(ValueError, 'reconciliation'):
            factory.run()
        self.assertEqual(len(self.spawned), 1)

    def test_completed_execution_with_wrong_bytes_has_no_issued_output(self):
        case = self.case(archive_schedule='settled', bad_output=True)
        factory = self.factory(case)
        with self.assertRaises(ValueError):
            factory.run()
        self.assertEqual(factory.execution['status'], 'artifact-ready')
        self.assertIsNone(factory.token)
        with self.assertRaises(ValueError):
            factory.issued_artifact()
        self.assertEqual(len(self.spawned), 1)

    def test_serialized_authority_cannot_create_a_factory(self):
        case = self.case()
        for capability in (None, True, case.capability.evidence()):
            with self.subTest(kind=type(capability).__name__), self.assertRaises(ValueError):
                runtime.RegisteredN1Factory(capability, case.verifier, receipt=case.receipt,
                    route=case.route, node_id=case.node_id, ledger=case.ledger, host=case.host, policy=case.policy)
        self.assertEqual(self.spawned, [])

    def test_registered_capability_refuses_other_host_and_ledger_locations(self):
        case = self.case()
        self.factory(case)
        state = self.repositories.root / 'EXAMPLE-other-state'
        (state / 'records').mkdir(parents=True, mode=0o700)
        state.chmod(0o700)
        (state / 'fake-server' / 'codex-home').mkdir(parents=True, mode=0o700)
        host = runtime.native.OfflineN1Host(state, case.host.target, case.host.worker)
        ledger = runtime.admission.ledger_api.InvocationLedger(self.repositories.root / 'EXAMPLE-other-ledger',
            clock=case.ledger.clock, owner_probe=case.ledger.owner_probe)
        with self.assertRaises(ValueError):
            runtime.RegisteredN1Factory(case.capability, case.verifier, receipt=case.receipt,
                route=case.route, node_id=case.node_id, ledger=ledger, host=host, policy=case.policy)
        self.assertEqual(self.spawned, [])

    def test_preexisting_unregistered_spool_file_refuses_before_startup(self):
        case = self.case()
        (case.home / 'EXAMPLE-unregistered.txt').write_text('EXAMPLE existing parent data\n')
        with self.assertRaisesRegex(ValueError, 'unregistered initial spool'):
            self.factory(case)
        self.assertEqual(self.spawned, [])

    def test_unregistered_spool_data_added_after_factory_refuses_before_effects(self):
        case = self.case()
        factory = self.factory(case)
        (case.home / 'EXAMPLE-unregistered.txt').write_text('EXAMPLE existing parent data\n')
        with self.assertRaisesRegex(ValueError, 'unregistered initial spool'):
            factory.run()
        self.assertEqual(self.spawned, [])

    def test_namespace_synthetic_parent_is_not_the_host_controller_store(self):
        from types import SimpleNamespace
        case = self.case(archive_schedule='settled')
        factory = self.factory(case)
        original = os.stat
        identity = case.host.state.stat()
        def projected_stat(path, *args, **kwargs):
            if str(path).startswith('/proc/') and str(path).endswith('/root' + str(case.host.state)):
                return SimpleNamespace(st_dev=identity.st_dev, st_ino=identity.st_ino + 1, st_mode=identity.st_mode)
            return original(path, *args, **kwargs)
        failure = None
        with patch.object(os, 'stat', projected_stat):
            try:
                factory.run()
            except ValueError as error:
                failure = error
        self.assertIsNone(failure, 'EXAMPLE synthetic namespace ancestors must not be confused with the real controller store')

    def test_namespace_actual_controller_store_inode_refuses_before_release(self):
        case = self.case()
        factory = self.factory(case)
        original = os.stat
        def exposed_stat(path, *args, **kwargs):
            if str(path).startswith('/proc/') and str(path).endswith('/root' + str(case.host.state)):
                return original(case.host.state)
            return original(path, *args, **kwargs)
        with patch.object(os, 'stat', exposed_stat):
            with self.assertRaisesRegex(ValueError, 'controller store'):
                factory.run()
        self.assertEqual(len(self.spawned), 1)
        self.assertEqual(self.spawned[0].methods, [])
        self.assertIsNone(factory.token)

    def test_late_required_request_after_archive_response_cannot_reach_capture(self):
        case = self.case(archive_schedule='concurrent', archive_fault=True)
        factory = self.factory(case)
        with self.assertRaises(ValueError):
            factory.run()
        self.assertIsNone(factory.token)
        self.assertFalse((case.host.state / 'artifact').exists())

    def test_frame_fault_after_archive_response_and_child_exit_cannot_reach_capture(self):
        case = self.case(archive_schedule='concurrent', archive_frame_fault=True)
        factory = self.factory(case)
        with self.assertRaises(ValueError):
            factory.run()
        self.assertIsNone(factory.token)
        self.assertFalse((case.host.state / 'artifact').exists())

    def test_original_registered_stdout_queue_flood_refuses_before_capture(self):
        """Queue saturation refuses through the registered process and RPC reader."""
        case = self.case()
        factory = self.factory(case)
        original_init = runtime._RegisteredServer.__init__
        original_put = Lines.put
        servers = []
        flooded = False

        def retain_server(server, *args, **kwargs):
            # Initialization can refuse before the factory assigns its server.
            # Retain the actual instance without changing construction or IO.
            servers.append(server)
            original_init(server, *args, **kwargs)

        def flood(lines, value):
            nonlocal flooded
            original_put(lines, value)
            if (not flooded and isinstance(value, dict)
                    and isinstance(value.get('result'), dict)
                    and value['result'].get('codexHome') == str(case.home)):
                flooded = True
                for _ in range(512):
                    lines.lines.put(json.dumps({'method': 'EXAMPLE/notification', 'params': {}}) + '\n')

        with (patch.object(runtime._RegisteredServer, '__init__', retain_server),
              patch.object(Lines, 'put', flood)):
            with self.assertRaises((ValueError, runtime.AppServerError)):
                factory.run()
        self.assertTrue(flooded)
        self.assertEqual(len(servers), 1)
        server = servers[0]
        self.assertIs(server.factory, factory)
        self.assertIs(server.process, self.spawned[0])
        self.assertIsNotNone(server.transport_failure)
        self.assertIn('frame/queue bound', str(server.transport_failure))
        self.assertTrue(server.requests.closed)
        self.assertTrue(server.lifetime.contained)
        self.assertTrue(server.lifetime.termination_recorded)
        self.assertTrue(server.lifetime.termination['child_exit_confirmed'])
        self.assertTrue(server.lifetime.termination['child_reaped'])
        self.assertIsNone(server.lifetime.namespace_handle)
        self.assertFalse(any(reader.is_alive() for reader in server._reader_threads))
        self.assertIsNone(factory.token)
        self.assertFalse((case.host.state / 'artifact').exists())
        self.assertEqual(self.attempt(case)['charge'], self.attempt(case)['amount'])
        self.assertEqual(len(self.spawned), 1)
        with self.assertRaises(ValueError):
            factory.run()
        self.assertEqual(len(self.spawned), 1)

    def test_original_registered_request_flood_retains_charge_without_capture(self):
        """Pending/history flood through the same registered RPC process."""
        command = fixtures.host_fixtures.FAKE_WRITE_COMMAND
        probes = [(f'EXAMPLE-flood-{index}', runtime.protocol.COMMAND, {
            'approvalId': f'EXAMPLE-flood-approval-{index}', 'kind': 'command',
            'command': command, 'cwd': str(self.repositories.worker),
            'availableDecisions': ['accept', 'decline'],
        }) for index in range(65)]
        case = self.case(request_probes=probes, defer_complete=True, max_steps=256)
        factory = self.factory(case)
        with self.assertRaises((ValueError, runtime.AppServerError)):
            factory.run()
        self.assertIsNotNone(factory.server.transport_failure)
        self.assertRegex(str(factory.server.transport_failure),
                         'registered-(pending-bound|request-reused-or-bound)')
        self.assertIsNone(factory.token)
        self.assertFalse((case.host.state / 'artifact').exists())
        self.assertEqual(self.attempt(case)['charge'], self.attempt(case)['amount'])
        self.assertEqual(len(self.spawned), 1)
        with self.assertRaises(ValueError):
            factory.run()
        self.assertEqual(len(self.spawned), 1)

    def test_duplicate_wire_keys_refuse_before_output(self):
        case = self.case()
        original_put = Lines.put

        def ambiguous(lines, value):
            if isinstance(value, dict) and value.get('method') == runtime.protocol.COMMAND:
                raw = json.dumps(value).replace(
                    '"params": {',
                    '"params": {"command": "EXAMPLE contradictory command",', 1)
                lines.lines.put(raw + '\n')
            else:
                original_put(lines, value)

        factory = self.factory(case)
        with patch.object(Lines, 'put', ambiguous):
            with self.assertRaises(ValueError):
                factory.run()
        self.assertIsNone(factory.token)
        self.assertFalse((case.host.state / 'artifact').exists())
        self.assertFalse(any(reply.get('result') == {'decision': 'accept'}
                             for process in self.spawned for reply in process.replies))

    def test_unknown_wire_method_returns_protocol_error_before_refusal(self):
        case = self.case()
        original_put = Lines.put

        def unsupported(lines, value):
            if isinstance(value, dict) and value.get('method') == runtime.protocol.COMMAND:
                value = dict(value, method='EXAMPLE/unsupported')
            original_put(lines, value)

        factory = self.factory(case)
        with patch.object(Lines, 'put', unsupported):
            with self.assertRaises(ValueError):
                factory.run()
        replies = [reply for process in self.spawned for reply in process.replies]
        self.assertIn({'id': 'EXAMPLE-request', 'error': {
            'code': -32601, 'message': 'Unsupported server request'}}, replies)
        self.assertFalse(any(reply.get('result') == {'decision': 'accept'} for reply in replies))
        self.assertIsNone(factory.token)
        self.assertFalse((case.host.state / 'artifact').exists())
        with self.assertRaises(ValueError):
            factory.run()
        self.assertEqual(len(self.spawned), 1)
        self.assertEqual(self.attempt(case)['charge'], self.attempt(case)['amount'])

    def test_registered_startup_holds_original_host_claim_and_persists_intent(self):
        case = self.case(archive_schedule='settled')
        factory = self.factory(case)
        observations = []
        def observe():
            with self.assertRaisesRegex(ValueError, 'claim is busy'):
                with case.host._locked(create=True):
                    self.fail('EXAMPLE concurrent host claim was admitted')
            intent = json.loads((case.host.state / 'registered-startup.json').read_bytes())
            self.assertEqual(intent['operation_id'], factory.operation_id)
            self.assertEqual(intent['admission_sha256'], case.spec['admission_sha256'])
            observations.append(intent['registered_specification'] == case.spec)
        case.on_startup = observe
        factory.run()
        self.assertEqual(observations, [True])

    def test_consecutive_turn_response_item_and_approval_frames_are_accepted(self):
        """Consecutive frames remain valid with serialized approval/archive completion.

        The two eight-second barriers are outside max_steps=8. This checks wire
        ordering and acceptance, not approval/host-tick scheduling within eight steps.
        """
        case = self.case(archive_schedule='settled', raced_approval=True, max_steps=8)
        factory = self.factory(case)
        completed = threading.Event()
        original_complete = RpcProcess.complete
        original_start = runtime._RegisteredServer.start_turn

        def complete(process):
            original_complete(process)
            completed.set()

        def start(server, *args, **kwargs):
            result = original_start(server, *args, **kwargs)
            self.assertTrue(completed.wait(8), 'EXAMPLE actual approval completion was not observed')
            return result

        failure = None
        with (patch.object(RpcProcess, 'complete', complete),
              patch.object(runtime._RegisteredServer, 'start_turn', start)):
            try:
                factory.run()
            except ValueError as error:
                failure = error
        self.assertIsNone(failure, 'Serialized consecutive wire approvals must remain valid')
        self.assertTrue(completed.is_set())
        self.assertEqual(self.spawned[0].replies[0]['result'], {'decision': 'accept'})

    def test_target_drift_after_construction_refuses_before_process_and_rpc(self):
        case = self.case()
        factory = self.factory(case)
        (case.host.target / 'seed.txt').write_text('EXAMPLE target drift\n')
        with self.assertRaises(ValueError):
            factory.run()
        self.assertEqual(self.spawned, [])

    def test_failed_observation_and_identity_refusal_do_not_report_containment(self):
        case = self.case()
        factory = self.factory(case)
        original = os.readlink
        def changed_identity(path, *args, **kwargs):
            parts = Path(path).parts
            if len(parts) == 5 and parts[1] == 'proc' and parts[2].isdigit() and int(parts[2]) in self.namespace_children:
                self.spawned[0].process.executable = '/EXAMPLE/different-executable'
                return original('/proc/self/ns/' + parts[4])
            return original(path, *args, **kwargs)
        with patch.object(os, 'readlink', changed_identity):
            with self.assertRaises(ValueError) as caught:
                factory.run()
        self.assertIs(caught.exception.app_server_cleanup['all_contained'], False)
        self.assertEqual(self.spawned[0].methods, [])


    def test_full_registered_pipe_times_out_and_uses_owned_cleanup_without_retry(self):
        case = self.case(blocked_stdin=True)
        factory = self.factory(case)
        finished, errors = threading.Event(), []
        def run():
            try:
                factory.run()
            except BaseException as failure:
                errors.append(failure)
            finally:
                finished.set()
        worker = threading.Thread(target=run, daemon=True)
        worker.start()
        try:
            self.assertTrue(finished.wait(12), 'EXAMPLE bounded RPC write must not block on a full real pipe')
        finally:
            if hasattr(case, 'blocked_read'):
                os.close(case.blocked_read)
            worker.join(timeout=3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], TimeoutError)
        self.assertIsNone(factory.token)
        self.assertEqual(len(self.spawned), 1)
        self.assertTrue(factory.server is None or factory.server.lifetime.contained)
        self.assertTrue(self.tables[0].births[0].reaped)
        with self.assertRaises(ValueError):
            factory.run()
        self.assertEqual(len(self.spawned), 1)

    def test_reader_eof_during_retained_release_preserves_success_without_second_reap(self):
        case = self.case(archive_schedule='concurrent', release_race=True, raced_approval=True, max_steps=256)
        factory = self.factory(case)
        original = runtime.owned._LinuxBackend._reap
        forced, polls = [], []
        original_poll = RpcProcess.poll
        def poll(child):
            if child._handle_birth.releasing:
                polls.append(child.returncode)
            return original_poll(child)
        def reap(backend, birth, *, releasing=False):
            if releasing and not forced and not birth.child.validator:
                self.assertTrue(birth.releasing)
                self.assertIsNone(birth.active_operation)
                forced.append(True)
                birth.child.stdout.lines.put('')
                birth.child.stderr.lines.put('')
                factory.server._reader_threads[0].join(timeout=1)
                self.assertFalse(factory.server._reader_threads[0].is_alive())
            return original(backend, birth, releasing=releasing)
        failure = None
        with patch.object(RpcProcess, 'poll', poll), patch.object(runtime.owned._LinuxBackend, '_reap', reap):
            try:
                factory.run()
            except ValueError as error:
                failure = error
        self.assertEqual(forced, [True])
        self.assertEqual(polls, [None], 'EXAMPLE original poll must enter the actual unreaped release window')
        self.assertIsNone(failure, 'EXAMPLE release interleaving fault type: ' + type(factory.server.transport_failure).__name__)
        self.assertIsNotNone(factory.token)
        for table in self.tables:
            reaps = [e for e in table.events if e[0] == 'waitid' and not e[2] & os.WNOWAIT]
            self.assertEqual(len(reaps), 1)


    def test_reserved_status_poll_serializes_with_termination_before_release(self):
        case = self.case(archive_schedule='concurrent', raced_approval=True, max_steps=256)
        factory = self.factory(case)
        paused, attempted, resume = threading.Event(), threading.Event(), threading.Event()
        original_wait = self.processes.waitid_api.side_effect
        original_enter = runtime.owned._LinuxEngine._enter
        original_terminate = runtime.owned.LinuxOwnedChildController.terminate
        releases = []
        def waitid(kind, descriptor, options):
            server = factory.server
            if (server is not None and threading.current_thread() is server._reader_threads[0]
                    and not server.process.process.alive and not paused.is_set()):
                paused.set()
                if not resume.wait(2):
                    raise AssertionError('EXAMPLE paused status did not resume')
            return original_wait(kind, descriptor, options)
        def enter(engine, state):
            if state == 'terminating' and engine is factory.server.lifetime.controller._engine:
                attempted.set()
            return original_enter(engine, state)
        def release():
            attempted.wait(2)
            # Keep the actual status reservation active while the original retained-child owner
            # termination attempts its lifecycle lock/operation.
            time.sleep(0.05)
            resume.set()
        def terminate(controller, *args, **kwargs):
            if controller is factory.server.lifetime.controller and not paused.is_set():
                self.assertTrue(factory.server.lifetime._ending)
                factory.server.process.process.alive = False
                factory.server.process.stop()
                self.assertTrue(paused.wait(2), 'EXAMPLE actual EOF poll did not reserve its operation')
                thread = threading.Thread(target=release, daemon=True)
                releases.append(thread)
                thread.start()
            return original_terminate(controller, *args, **kwargs)
        failure = None
        try:
            with patch.object(os, 'waitid', waitid), patch.object(runtime.owned._LinuxEngine, '_enter', enter), patch.object(runtime.owned.LinuxOwnedChildController, 'terminate', terminate):
                try:
                    factory.run()
                except ValueError as error:
                    failure = error
        finally:
            resume.set()
            for thread in releases:
                thread.join(timeout=2)
        self.assertTrue(paused.is_set() and attempted.is_set())
        self.assertIsNone(failure, 'EXAMPLE reserved status poll must finish before original termination takes authority')
        self.assertIsNotNone(factory.token)
        for table in self.tables:
            reaps = [e for e in table.events if e[0] == 'waitid' and not e[2] & os.WNOWAIT]
            self.assertEqual(len(reaps), 1)


    def test_unterminated_stderr_budget_refuses_without_capture_and_retains_charge(self):
        case = self.case(stderr_flood=True, raced_approval=True, max_steps=256)
        factory = self.factory(case)
        with self.assertRaises((ValueError, runtime.AppServerError)):
            factory.run()
        self.assertGreater(self.spawned[0].diagnostic_bytes, 65536)
        self.assertIsNone(factory.token)
        self.assertFalse((case.host.state / 'artifact').exists())
        self.assertEqual(self.attempt(case)['charge'], self.attempt(case)['amount'])
        self.assertEqual(len(self.spawned), 1)
        self.assertTrue(self.tables[0].births[0].reaped)
        with self.assertRaises(ValueError):
            factory.run()
        self.assertEqual(len(self.spawned), 1)


if __name__ == '__main__':
    unittest.main()
