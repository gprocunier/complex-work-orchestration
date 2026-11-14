"""Original registered caller through the selected finite fake-server tool route."""
from __future__ import annotations

import json
import os
import threading
import time
from typing import Callable, NamedTuple
import unittest
from unittest.mock import patch

from tests import test_registered_n1_factory as family
from tests.test_registered_finite_input import ToolLines
import registered_finite_input as gate_module
import registered_finite_tool_calls as finite_tools


class ReplyPublicationRow(NamedTuple):
    original_id: str
    exceptional: bool


class SelectedFlowRow(NamedTuple):
    original_id: str
    oracle: Callable[[], None]


class DynamicRpcProcess(family.RpcProcess):
    def __init__(self, process, case, validator=False):
        super().__init__(process, case, validator=validator)
        self.is_tool = not validator and bool(case.test.spawned)
        if self.is_tool:
            self.stdout = ToolLines()
            self.stdout.put('' if getattr(case, 'command_eof', False)
                            or getattr(case, 'command_no_output', False)
                            else getattr(case, 'command_output', 'EXAMPLE finite command output\n'))
            read, write = os.pipe()
            os.set_blocking(read, False)
            self.stdin = os.fdopen(write, 'wb', buffering=0)
            case.tool_stream, case.tool_read = self.stdout, read
            case.test.addCleanup(self.stdout.close)
            case.test.addCleanup(os.close, read)
            case.test.addCleanup(self.stdin.close)

    def result(self, method, params):
        response = super().result(method, params)
        if not self.process.alive:
            return response
        if method == 'turn/start' and getattr(self.case, 'materialize_on_turn_start', False):
            scenario = self.case.scenario
            scenario.set_boundary('valid')
            records = [json.loads(line) for line in scenario.path.read_text().splitlines()]
            for record in records:
                if record['type'] == 'turn_context':
                    record['payload'].update(model=self.case.spec['model'],
                                             effort=self.case.spec['effort'])
            scenario.path.write_text(''.join(json.dumps(record) + '\n' for record in records))
        if method == 'thread/start':
            tools = []
            for item in params['dynamicTools']:
                tools.append({'type': item['type'], 'name': item['name'],
                              'description': item['description'], 'parameters': item['inputSchema']})
            self.case.test.assertEqual(tools, finite_tools._response_tools())
            capture = {'start': params, 'response': response,
                       'request': {'model': params['model'], 'tools': tools}}
            if getattr(self.case, 'catalog_drift', False):
                capture['request']['tools'].append({'name': 'write_stdin'})
            path = self.case.home / 'finite-tool-capture.json'
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
                json.dump(capture, stream)
                stream.flush()
                os.fsync(stream.fileno())
        return response

    def complete(self):
        if not self.process.alive:
            return
        if not getattr(self.case, 'materialize_on_turn_start', False):
            return super().complete()
        scenario = self.case.scenario
        with patch.object(scenario, 'set_boundary', lambda _kind: None):
            scenario.complete_turn()
        self.pending = None

    def approve(self):
        if not self.process.alive:
            return
        scenario = self.case.scenario
        if hasattr(self.case, 'command_prepared'):
            self.case.command_prepared.set()
            self.case.command_release.wait(5)
        if getattr(self.case, 'short_command_deadline', False):
            pending = self.case.factory.server._tool_queue
            original_put = pending.put_nowait
            pending.put_nowait = lambda entry: original_put((entry[0], time.monotonic() + .05))
            self.case.test.addCleanup(setattr, pending, 'put_nowait', original_put)
        self._send_tool('EXAMPLE-command-call', getattr(self.case, 'command_tool', 'finite_command'),
                        {'command': self.case.spec['command']}, scenario)
        if getattr(self.case, 'flood_tool_queue', False):
            self.case.flood_ready.wait(5)
            for index in range(9):
                self._send_tool('EXAMPLE-extra-' + str(index), 'finite_poll',
                                {'commandCallId': 'EXAMPLE-command-call', 'chars': ''}, scenario)

    def _send_tool(self, call, tool, arguments, scenario):
        # A held synthetic callback can outlive the original host's child
        # containment. It must not emit a new request after that actual exit.
        # Live-child stream errors still propagate from the unchanged put.
        if not self.process.alive:
            return
        item = {'id': call, 'type': 'dynamicToolCall', 'status': 'inProgress',
                'tool': tool, 'namespace': None, 'arguments': arguments}
        self.stdout.put({'method': 'item/started', 'params': {
            'threadId': scenario.thread_id, 'turnId': scenario.turn_id, 'item': item}})
        request_id = (getattr(self.case, 'command_request_id', 'EXAMPLE-request-' + call)
                      if call == 'EXAMPLE-command-call' else 'EXAMPLE-request-' + call)
        if call == 'EXAMPLE-command-call' and (getattr(self.case, 'colliding_permission_before_command', False)
                                               or getattr(self.case, 'typed_distinct_request_ids', False)):
            permission_id = 7 if getattr(self.case, 'typed_distinct_request_ids', False) else request_id
            self.stdout.put({'id': permission_id,
                             'method': family.runtime.protocol.PERMISSIONS, 'params': {
                'threadId': scenario.thread_id, 'turnId': scenario.turn_id, 'itemId': call,
                'startedAtMs': 1000, 'cwd': 'EXAMPLE-cwd',
                'permissions': {'network': {'enabled': True}}}})
        self.stdout.put({'id': request_id, 'method': 'item/tool/call', 'params': {
            'threadId': scenario.thread_id,
            'turnId': ('EXAMPLE-wrong-turn' if call == 'EXAMPLE-poll-call'
                       and getattr(self.case, 'poll_wrong_turn', False) else scenario.turn_id),
            'callId': call, 'tool': tool, 'arguments': arguments}})
        if call == 'EXAMPLE-command-call' and getattr(self.case, 'colliding_permission_after_command', False):
            self.stdout.put({'id': request_id,
                             'method': family.runtime.protocol.PERMISSIONS, 'params': {
                'threadId': scenario.thread_id, 'turnId': scenario.turn_id, 'itemId': call,
                'startedAtMs': 1000, 'cwd': 'EXAMPLE-cwd',
                'permissions': {'network': {'enabled': True}}}})

    def receive(self, message):
        if self.is_tool or 'method' in message:
            return super().receive(message)
        super().receive(message)
        if not self.process.alive:
            return
        if message.get('id') == getattr(self.case, 'command_request_id',
                                       'EXAMPLE-request-EXAMPLE-command-call'):
            if message.get('result', {}).get('success') is not True:
                return
            scenario = self.case.scenario
            if getattr(self.case, 'reused_id_after_command_answer', False):
                self.stdout.put({'id': message['id'], 'method': family.runtime.protocol.PERMISSIONS,
                                 'params': {'threadId': scenario.thread_id, 'turnId': scenario.turn_id,
                                            'itemId': 'EXAMPLE-command-call', 'startedAtMs': 1000,
                                            'cwd': 'EXAMPLE-cwd',
                                            'permissions': {'network': {'enabled': True}}}})
                return
            if getattr(self.case, 'tool_exit_before_completion', None) is not None:
                tool = self.case.test.spawned[1]
                tool.returncode = self.case.tool_exit_before_completion
                tool.process.alive = False
                self.case.tool_stream.put('')
            if not getattr(self.case, 'poll_before_command_completed', False):
                self.stdout.put({'method': 'item/completed', 'params': {
                    'threadId': scenario.thread_id, 'turnId': scenario.turn_id,
                    'item': {'id': 'EXAMPLE-command-call', 'status': 'completed'}}})
                if hasattr(self.case, 'completion_emitted'):
                    self.case.completion_emitted.set()
            if getattr(self.case, 'tool_eof_after_command', False):
                self.case.tool_stream.put('')
            elif getattr(self.case, 'tool_swap_after_command', False):
                substitute = ToolLines()
                self.case.test.addCleanup(substitute.close)
                self.case.test.spawned[1].stdout = substitute
            elif getattr(self.case, 'tool_exit_before_poll', None) is not None:
                tool = self.case.test.spawned[1]
                if hasattr(self.case, 'tool_tail_before_poll'):
                    self.case.tool_stream.put(self.case.tool_tail_before_poll)
                tool.returncode = self.case.tool_exit_before_poll
                tool.process.alive = False
                self.case.tool_stream.put('')
            elif not (getattr(self.case, 'natural_tool_exit', False)
                      or getattr(self.case, 'poll_empty_running', False)
                      or getattr(self.case, 'tool_exit_before_completion', None) is not None):
                self.case.tool_stream.put(getattr(self.case, 'poll_output',
                                                  'EXAMPLE finite poll output\n'))
            if hasattr(self.case, 'poll_prepared'):
                self.case.poll_prepared.set()
                self.case.poll_release.wait(15)
            if getattr(self.case, 'poll_epoch_drift', False):
                self.case.factory.server.connection_epoch_sha256 = 'EXAMPLE-foreign-epoch'
            self._send_tool('EXAMPLE-poll-call', 'finite_poll',
                            {'commandCallId': 'EXAMPLE-command-call',
                             'chars': getattr(self.case, 'poll_chars', '')}, scenario)
        elif message.get('id') == 'EXAMPLE-request-EXAMPLE-poll-call':
            if getattr(self.case, 'replay_poll', False):
                self.stdout.put({'id': 'EXAMPLE-replayed-poll-request', 'method': 'item/tool/call',
                                 'params': {'threadId': self.case.scenario.thread_id,
                                            'turnId': self.case.scenario.turn_id,
                                            'callId': 'EXAMPLE-poll-call', 'tool': 'finite_poll',
                                            'arguments': {'commandCallId': 'EXAMPLE-command-call', 'chars': ''}}})
                return
            if message.get('result', {}).get('success') is True:
                observed = json.loads(message['result']['contentItems'][0]['text'])
                self.case.test.assertEqual(set(observed), {'running', 'stdout'})
                self.case.test.assertIs(type(observed['running']), bool)
                self.case.test.assertIs(type(observed['stdout']), str)
                self.case.poll_observation = observed
                self.case.poll_state = 'running' if observed['running'] else 'clean-exited'
                self.complete()
            elif getattr(self.case, 'complete_after_refusal', False):
                self.complete()


class RegisteredFiniteToolWiringTests(unittest.TestCase):
    def setUp(self):
        self.fixture = family.FactoryTests(methodName='runTest')
        self.fixture.setUp()
        self.addCleanup(family.cleanup_helper, self, self.fixture)

    def wait_for_startup(self, event, worker, outcome):
        return family.wait_for_startup(self, event, worker, outcome)

    def _run_tool_exit(self, *, output=True, status=0, pid_exited=True,
                       trailing='', close_output=True):
        case = self.fixture.case(archive_schedule='settled', finite_tool_mode='captured-host-tools',
                                 command_no_output=not output, natural_tool_exit=True)
        factory = self.fixture.factory(case)
        original_read = os.read
        observed = []

        def read(descriptor, count):
            data = original_read(descriptor, count)
            if (len(self.fixture.spawned) >= 2 and not observed
                    and descriptor == case.tool_stream.fileno()):
                tool = self.fixture.spawned[1]
                tool.returncode = status
                tool.process.alive = not pid_exited
                if trailing:
                    case.tool_stream.put(trailing)
                if close_output and not case.tool_stream.writer.closed:
                    case.tool_stream.put('')
                observed.append(data)
            return data

        with patch.object(family, 'RpcProcess', DynamicRpcProcess), patch.object(os, 'read', side_effect=read):
            try:
                result = factory.run()
            except BaseException as failure:
                result = failure
        self.assertEqual(len(observed), 1, 'the original tool pipe must be observed')
        self.assertEqual(observed[0], b'EXAMPLE finite command output\n' if output else b'')
        return case, factory, result

    def _exit_between_command_read_and_reply(self, *, trailing, close_output=True,
                                             command_output=None):
        case = self.fixture.case(archive_schedule='settled', finite_tool_mode='captured-host-tools', natural_tool_exit=True,
                                 **({} if command_output is None else {'command_output': command_output}))
        factory = self.fixture.factory(case)
        original = family.runtime._RegisteredServer._commit_tool_reply
        observed = []

        def commit(server, message, response, deadline, *, refusal=False):
            if (not observed and message.get('params', {}).get('tool') == 'finite_command'
                    and response.get('result', {}).get('success') is True):
                tool = self.fixture.spawned[1]
                case.tool_stream.put(trailing)
                tool.returncode = 0
                tool.process.alive = False
                if close_output:
                    case.tool_stream.put('')
                observed.append(True)
            return original(server, message, response, deadline, refusal=refusal)

        with patch.object(family, 'RpcProcess', DynamicRpcProcess), \
                patch.object(family.runtime._RegisteredServer, '_commit_tool_reply', commit):
            try:
                result = factory.run()
            except BaseException as failure:
                result = failure
        self.assertEqual(observed, [True])
        return case, factory, result

    def test_naturally_completed_tool_with_output_replies_and_polls_empty(self):
        case, factory, result = self._run_tool_exit()
        self.assertEqual(result['attempt']['outcome'], 'completed')
        self.assertEqual(factory.server.finite_input.terminal_code, 0)
        self.assertEqual(self.fixture.spawned[0].replies[0]['result']['contentItems'][0]['text'],
                         'EXAMPLE finite command output\n')
        self.assertEqual(case.poll_observation, {'stdout': '', 'running': False})
        self.assertEqual(case.poll_state, 'clean-exited')
        self.assertIsNotNone(factory.issued_artifact())
        with self.assertRaises(BlockingIOError):
            os.read(case.tool_read, 1)

    def test_naturally_completed_tool_without_output_replies_and_polls_empty(self):
        case, factory, result = self._run_tool_exit(output=False)
        self.assertEqual(result['attempt']['outcome'], 'completed')
        self.assertEqual(factory.server.finite_input.terminal_code, 0)
        self.assertEqual(self.fixture.spawned[0].replies[0]['result']['contentItems'][0]['text'], '')
        self.assertEqual(case.poll_observation, {'stdout': '', 'running': False})
        self.assertIsNotNone(factory.issued_artifact())

    def test_natural_exit_drains_buffered_tail_before_command_reply(self):
        _case, factory, result = self._run_tool_exit(trailing='EXAMPLE buffered tail\n')
        self.assertEqual(result['attempt']['outcome'], 'completed')
        self.assertEqual(factory.server.finite_input.terminal_code, 0)
        self.assertEqual(self.fixture.spawned[0].replies[0]['result']['contentItems'][0]['text'],
                         'EXAMPLE finite command output\nEXAMPLE buffered tail\n')

    def test_exit_between_initial_read_and_reply_drains_tail_atomically(self):
        case, factory, result = self._exit_between_command_read_and_reply(
            trailing='EXAMPLE late tail\n')
        self.assertIsInstance(result, dict,
            (str(result), repr(factory.server.transport_failure),
             factory.server.finite_input.lifecycle.phase,
             factory.server.finite_input.output_bytes_seen,
             len(self.fixture.spawned[0].replies)))
        self.assertEqual(result['attempt']['outcome'], 'completed')
        self.assertEqual(self.fixture.spawned[0].replies[0]['result']['contentItems'][0]['text'],
                         'EXAMPLE finite command output\nEXAMPLE late tail\n')
        self.assertEqual(case.poll_observation, {'stdout': '', 'running': False})
        self.assertIsNotNone(factory.issued_artifact())

    def test_cumulative_stdout_bound_accepts_exact_limit_with_clean_eof(self):
        case = self.fixture.case(archive_schedule='settled', finite_tool_mode='captured-host-tools',
                                 command_output='A' * 2500, tool_exit_before_poll=0,
                                 tool_tail_before_poll='B' * 1596)
        factory = self.fixture.factory(case)
        with patch.object(family, 'RpcProcess', DynamicRpcProcess):
            result = factory.run()
        self.assertEqual(result['attempt']['outcome'], 'completed')
        self.assertEqual(case.poll_observation, {'stdout': 'B' * 1596, 'running': False})
        self.assertEqual(factory.server.finite_input.output_bytes_seen, 4096)
        self.assertIsNotNone(factory.issued_artifact())

    def test_cumulative_stdout_bound_refuses_one_byte_over_on_poll(self):
        case = self.fixture.case(finite_tool_mode='captured-host-tools',
                                 command_output='A' * 2500, poll_output='B' * 1597)
        factory = self.fixture.factory(case)
        with patch.object(family, 'RpcProcess', DynamicRpcProcess), self.assertRaises(ValueError):
            factory.run()
        self.assertEqual(self.fixture.spawned[0].replies[0]['result']['contentItems'][0]['text'],
                         'A' * 2500)
        self.assertFalse(any(reply.get('result', {}).get('success') is True
                             for reply in self.fixture.spawned[0].replies[1:]))
        self.assertEqual(factory.server.finite_input.output_bytes_seen, 4097)
        attempt = self.fixture.attempt(case)
        self.assertEqual(attempt['outcome'], 'unknown')
        self.assertEqual(attempt['charge'], attempt['amount'])

    def test_cumulative_stdout_bound_refuses_command_then_terminal_tail(self):
        case, factory, result = self._exit_between_command_read_and_reply(
            command_output='A' * 2500, trailing='B' * 2500)
        self.assertIsInstance(result, BaseException)
        self.assertFalse(any(reply.get('result', {}).get('success') is True
                             for reply in self.fixture.spawned[0].replies))
        self.assertEqual(factory.server.finite_input.output_bytes_seen, 5000)
        attempt = self.fixture.attempt(case)
        self.assertEqual(attempt['outcome'], 'unknown')
        self.assertEqual(attempt['charge'], attempt['amount'])

    def test_exit_between_read_and_reply_without_eof_refuses(self):
        case, _factory, result = self._exit_between_command_read_and_reply(
            trailing='EXAMPLE late tail\n', close_output=False)
        self.assertIsInstance(result, BaseException)
        self.assertFalse(any(reply.get('result', {}).get('success') is True
                             for reply in self.fixture.spawned[0].replies))
        attempt = self.fixture.attempt(case)
        self.assertEqual(attempt['outcome'], 'unknown')
        self.assertEqual(attempt['charge'], attempt['amount'])

    def test_exit_between_poll_read_and_reply_carries_final_status_and_tail(self):
        case = self.fixture.case(archive_schedule='settled', finite_tool_mode='captured-host-tools')
        factory = self.fixture.factory(case)
        original = family.runtime._RegisteredServer._commit_tool_reply
        observed = []

        def commit(server, message, response, deadline, *, refusal=False):
            if (not observed and message.get('params', {}).get('tool') == 'finite_poll'
                    and response.get('result', {}).get('success') is True):
                tool = self.fixture.spawned[1]
                case.tool_stream.put('EXAMPLE late poll tail\n')
                tool.returncode = 0
                tool.process.alive = False
                case.tool_stream.put('')
                observed.append(True)
            return original(server, message, response, deadline, refusal=refusal)

        with patch.object(family, 'RpcProcess', DynamicRpcProcess), \
                patch.object(family.runtime._RegisteredServer, '_commit_tool_reply', commit):
            result = factory.run()
        self.assertEqual(observed, [True])
        self.assertEqual(result['attempt']['outcome'], 'completed')
        self.assertEqual(case.poll_observation,
                         {'stdout': 'EXAMPLE finite poll output\nEXAMPLE late poll tail\n',
                          'running': False})
        self.assertEqual(case.poll_state, 'clean-exited')

    def test_running_reply_observation_retries_clean_exit_while_writer_waits(self):
        case = self.fixture.case(archive_schedule='settled', finite_tool_mode='captured-host-tools', natural_tool_exit=True)
        case.command_prepared, case.command_release = threading.Event(), threading.Event()
        factory = self.fixture.factory(case)
        prepared = threading.Event()
        retries, result = [], []

        def run():
            try:
                result.append(factory.run())
            except BaseException as failure:
                result.append(failure)

        with patch.object(family, 'RpcProcess', DynamicRpcProcess):
            worker = threading.Thread(target=run, daemon=True)
            worker.start()
            self.addCleanup(family.finish_worker, self, worker, case.command_release)
            self.addCleanup(case.command_release.set)
            self.assertTrue(self.wait_for_startup(case.command_prepared, worker, result))
            gate = factory.server.finite_input
            issue = gate.issue_reply_observation
            commit = gate.commit_reply_observation

            def observed_issue(producer, message, response, deadline, frame, refusal):
                ticket = issue(producer, message, response, deadline, frame, refusal)
                if (ticket is not None and message.get('params', {}).get('tool') == 'finite_command'
                        and gate.reply_tickets[ticket].phase == 'running'):
                    prepared.set()
                return ticket

            def observed_commit(*args):
                value = commit(*args)
                if value is False:
                    retries.append(True)
                return value

            writer = factory.server.process.stdin._lock
            self.assertTrue(writer.acquire(timeout=2))
            held = True
            try:
                with patch.object(gate, 'issue_reply_observation', observed_issue), \
                        patch.object(gate, 'commit_reply_observation', observed_commit):
                    case.command_release.set()
                    self.assertTrue(prepared.wait(10))
                    tool = self.fixture.spawned[1]
                    case.tool_stream.put('EXAMPLE writer-wait tail\n')
                    tool.returncode = 0
                    tool.process.alive = False
                    case.tool_stream.put('')
                    writer.release()
                    held = False
                    worker.join(12)
            finally:
                if held:
                    writer.release()
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['attempt']['outcome'], 'completed')
        self.assertTrue(retries, 'the old running ticket must lose its final fence')
        self.assertEqual(self.fixture.spawned[0].replies[0]['result']['contentItems'][0]['text'],
                         'EXAMPLE finite command output\nEXAMPLE writer-wait tail\n')
        self.assertEqual(case.poll_observation, {'stdout': '', 'running': False})

    def test_original_selected_flow_and_reply_ticket_oracles(self):
        """One actual selected command/poll serves both read-only oracle rows.

        The original ticket-reuse probe still runs at the real command commit;
        it is an additional refused observer call in the common positive flow.
        """
        case = self.fixture.case(archive_schedule='settled', finite_tool_mode='captured-host-tools')
        factory = self.fixture.factory(case)
        original = gate_module.RegisteredFiniteInput.commit_reply_observation
        replayed = []
        with self.assertRaises(gate_module.FiniteInputError):
            gate_module.ReplyTicket()

        def commit(gate, *args):
            value = original(gate, *args)
            if (value is True and args[2].get('params', {}).get('tool') == 'finite_command'):
                with self.assertRaises(gate_module.FiniteInputError):
                    original(gate, *args)
                replayed.append(True)
            return value

        with patch.object(family, 'RpcProcess', DynamicRpcProcess), \
                patch.object(gate_module.RegisteredFiniteInput, 'commit_reply_observation', commit):
            result = factory.run()

        def ticket_oracle():
            self.assertEqual(result['attempt']['outcome'], 'completed')
            self.assertEqual(replayed, [True])
            self.assertEqual(len(self.fixture.spawned[0].replies), 2)

        def pipe_oracle():
            self.assert_selected_pipe_observations(case, factory, result)

        rows = (
            SelectedFlowRow('test_original_reply_observation_is_opaque_and_one_use', ticket_oracle),
            SelectedFlowRow('test_original_selected_command_and_fresh_empty_poll_use_real_pipes',
                            pipe_oracle),
        )
        for row in rows:
            with self.subTest(original_id=row.original_id):
                row.oracle()

    def _eagain_tool_reply_terminal_order(self, negative_first):
        """The registered command reply keeps each real pipe attempt ordered."""
        case = self.fixture.case(finite_tool_mode='captured-host-tools')
        case.command_prepared, case.command_release = threading.Event(), threading.Event()
        factory = self.fixture.factory(case)
        first_result, release_first = threading.Event(), threading.Event()
        second_written, release_second = threading.Event(), threading.Event()
        target, writes, outcomes, deadlines = {}, [], [], []
        original_write = os.write
        original_commit = gate_module.RegisteredFiniteInput.commit_reply_observation

        def atomic(descriptor, data):
            frame = bytes(data)
            if (descriptor == target.get('fd') and b'"success":true' in frame
                    and b'EXAMPLE-request-EXAMPLE-command-call' in frame):
                writes.append(frame)
                if len(writes) == 1:
                    raise BlockingIOError('EXAMPLE confirmed no-byte tool reply EAGAIN')
                count = original_write(descriptor, data)
                if len(writes) == 2:
                    second_written.set()
                    release_second.wait(3)
                return count
            return original_write(descriptor, data)

        def commit(gate, ticket, producer, message, response, deadline,
                   frame, writer, refusal):
            if (message.get('params', {}).get('tool') == 'finite_command'
                    and response.get('result', {}).get('success') is True):
                deadlines.append(deadline)
            value = original_commit(gate, ticket, producer, message, response,
                                    deadline, frame, writer, refusal)
            if (value is False and not first_result.is_set()
                    and message.get('params', {}).get('tool') == 'finite_command'
                    and response.get('result', {}).get('success') is True):
                first_result.set()
                if negative_first:
                    release_first.wait(3)
            return value

        def run():
            try:
                outcomes.append(factory.run())
            except BaseException as failure:
                outcomes.append(failure)

        with patch.object(family, 'RpcProcess', DynamicRpcProcess), patch.object(
                gate_module.RegisteredFiniteInput, 'commit_reply_observation', commit), patch.object(
                os, 'write', atomic):
            worker = threading.Thread(target=run, daemon=True)
            worker.start()
            self.addCleanup(family.finish_worker, self, worker, case.command_release, release_first, release_second)
            self.addCleanup(case.command_release.set)
            self.addCleanup(release_first.set)
            self.addCleanup(release_second.set)
            try:
                self.assertTrue(self.wait_for_startup(case.command_prepared, worker, outcomes))
                server = factory.server
                target['fd'] = server.process.stdin.descriptor
                case.command_release.set()
                self.assertTrue(first_result.wait(8))
                lifecycle = server.finite_input.lifecycle
                key, first = next((key, ticket) for key, ticket in
                                  lifecycle.authority_commits.items()
                                  if key[0] == 'tool-reply')
                self.assertEqual(lifecycle.authority_attempt_results[first], 'not-sent')
                self.assertEqual(lifecycle.authority_outcomes[key], 'precommit-retry')
                identity = (case.scenario.thread_id, case.scenario.turn_id,
                            'EXAMPLE-command-call')
                self.assertFalse(lifecycle.command_reply_dispatched(identity))
                self.assertEqual(first[2][0], server.connection_epoch_sha256)
                self.assertEqual(first[2][1], 'EXAMPLE-request-EXAMPLE-command-call')
                if not negative_first:
                    self.assertTrue(second_written.wait(3))
                    self.assertTrue(lifecycle.command_reply_dispatched(identity))
                process = self.fixture.spawned[0]
                process.stdout.put({'method': 'turn/completed', 'params': {
                    'threadId': case.scenario.thread_id,
                    'turn': {'id': case.scenario.turn_id, 'status': 'interrupted'}}})
                end = time.monotonic() + 3
                while not lifecycle.authority_revoked_turns and time.monotonic() < end:
                    time.sleep(.002)
                self.assertTrue(lifecycle.authority_revoked_turns)
                revocation = next(order for order, kind, _target, _value in
                                  lifecycle.authority_revocations if kind == 'turn')
                if negative_first:
                    self.assertEqual(lifecycle.authority_commits[key], first)
                    self.assertEqual(lifecycle.authority_outcomes[key],
                                     'revoked-before-physical-send')
                else:
                    retry = lifecycle.authority_commits[key]
                    self.assertNotEqual(retry, first)
                    self.assertEqual(retry[2], first[2])
                    self.assertLess(first[0], retry[0])
                    self.assertLess(retry[0], revocation)
                    self.assertIsNone(lifecycle.authority_attempt_results[retry])
                    self.assertEqual(lifecycle.authority_outcomes[key],
                                     'ambiguous-after-revocation')
                release_first.set()
                release_second.set()
                worker.join(12)
            finally:
                case.command_release.set()
                release_first.set()
                release_second.set()
                worker.join(12)
            self.assertFalse(worker.is_alive())
            self.assertEqual(len(outcomes), 1)
            self.assertIsInstance(outcomes[0], BaseException)
            self.assertIsNone(factory.token)
            self.assertEqual(len(writes), 1 if negative_first else 2)
            successes = [reply for reply in process.replies
                         if reply.get('id') == 'EXAMPLE-request-EXAMPLE-command-call'
                         and reply.get('result', {}).get('success') is True]
            self.assertEqual(len(successes), 0 if negative_first else 1)
            self.assertEqual(lifecycle.authority_attempt_results[first], 'not-sent')
            self.assertEqual(len(deadlines), 1 if negative_first else 2)
            self.assertEqual(len(set(deadlines)), 1)
            if not negative_first:
                self.assertEqual(lifecycle.authority_attempt_results[retry], 'wire-sent')
                self.assertEqual(lifecycle.authority_outcomes[key],
                                 'wire-sent-after-revocation')
            attempt = self.fixture.attempt(case)
            self.assertEqual(attempt['outcome'], 'unknown')
            self.assertEqual(attempt['charge'], attempt['amount'])

    def test_eagain_retry_terminal_orders_on_registered_tool_reply_pipe(self):
        for negative_first in (True, False):
            with self.subTest(negative_first=negative_first):
                fixture = RegisteredFiniteToolWiringTests(methodName='runTest')
                fixture.setUp()
                try:
                    fixture._eagain_tool_reply_terminal_order(negative_first)
                finally:
                    family.cleanup_helper(self, fixture)

    def test_terminal_after_reply_observation_revokes_before_writer_commit(self):
        case = self.fixture.case(finite_tool_mode='captured-host-tools')
        case.command_prepared, case.command_release = threading.Event(), threading.Event()
        factory = self.fixture.factory(case)
        prepared, result = threading.Event(), []

        def run():
            try:
                result.append(factory.run())
            except BaseException as failure:
                result.append(failure)

        with patch.object(family, 'RpcProcess', DynamicRpcProcess):
            worker = threading.Thread(target=run, daemon=True)
            worker.start()
            self.addCleanup(family.finish_worker, self, worker, case.command_release)
            self.addCleanup(case.command_release.set)
            self.assertTrue(self.wait_for_startup(case.command_prepared, worker, result))
            gate = factory.server.finite_input
            issue = gate.issue_reply_observation

            def observed_issue(producer, message, response, deadline, frame, refusal):
                ticket = issue(producer, message, response, deadline, frame, refusal)
                if ticket is not None and message.get('params', {}).get('tool') == 'finite_command':
                    prepared.set()
                return ticket

            writer = factory.server.process.stdin._lock
            self.assertTrue(writer.acquire(timeout=2))
            held = True
            try:
                with patch.object(gate, 'issue_reply_observation', observed_issue):
                    case.command_release.set()
                    self.assertTrue(prepared.wait(10))
                    self.fixture.spawned[0].stdout.put({'method': 'turn/completed', 'params': {
                        'threadId': case.scenario.thread_id,
                        'turn': {'id': case.scenario.turn_id, 'status': 'completed'}}})
                    until = time.monotonic() + 2
                    while ((case.scenario.thread_id, case.scenario.turn_id)
                           not in factory.server.requests.terminals and time.monotonic() < until):
                        time.sleep(.005)
                    self.assertIn((case.scenario.thread_id, case.scenario.turn_id),
                                  factory.server.requests.terminals)
                    writer.release()
                    held = False
                    worker.join(12)
            finally:
                if held:
                    writer.release()
        self.assertEqual(len(result), 1)
        self.assertIsInstance(result[0], BaseException)
        self.assertFalse(any(reply.get('result', {}).get('success') is True
                             for reply in self.fixture.spawned[0].replies))
        attempt = self.fixture.attempt(case)
        self.assertEqual(attempt['outcome'], 'unknown')
        self.assertEqual(attempt['charge'], attempt['amount'])

    def test_reader_fault_and_owned_cleanup_progress_during_registration_capture_read(self):
        # Protocol reader liveness and startup revocation: the second capture
        # read is registration's corroborating read, after original issuance.
        case = self.fixture.case(archive_schedule='concurrent', finite_tool_mode='captured-host-tools')
        factory = self.fixture.factory(case)
        entered, release, result = threading.Event(), threading.Event(), []
        original_read = finite_tools._read_capture_file
        calls = []

        def blocked_read(path):
            calls.append(path)
            if len(calls) == 2:
                entered.set()
                release.wait(10)
            return original_read(path)

        def run():
            try:
                result.append(factory.run())
            except BaseException as failure:
                result.append(failure)

        self.addCleanup(release.set)
        with patch.object(family, 'RpcProcess', DynamicRpcProcess), patch.object(
                finite_tools, '_read_capture_file', blocked_read):
            worker = threading.Thread(target=run, daemon=True)
            worker.start()
            self.addCleanup(family.finish_worker, self, worker, release)
            self.assertTrue(self.wait_for_startup(entered, worker, result), 'registration must reach the bounded capture read')
            server = factory.server
            self.fixture.spawned[0].stdout.put({'method': 'item/started', 'params': {
                'item': {'type': 'commandExecution', 'id': 'EXAMPLE-uncontrolled'}}})
            until = time.monotonic() + 3
            while server.transport_failure is None and time.monotonic() < until:
                time.sleep(.005)
            self.assertIsNotNone(server.transport_failure, 'original reader fault must publish')
            self.assertTrue(server.requests.closed)
            self.assertEqual(server.finite_input.state, 'revoked')
            self.assertTrue(server._tool_cleanup_scheduled)
            self.assertFalse(release.is_set())
            # Invoke the original retained-child owner through the registered server.
            # cleanup path while the registration observation remains blocked.
            closed = threading.Event()
            def cleanup():
                try:
                    server.close()
                except BaseException:
                    pass
                finally:
                    closed.set()
            closer = threading.Thread(target=cleanup, daemon=True)
            closer.start()
            self.addCleanup(closer.join, 12)
            self.assertTrue(closed.wait(5), 'original owned cleanup must not wait for capture')
            self.assertTrue(server.lifetime.contained)
            self.assertFalse(release.is_set())
            release.set()
            worker.join(12)
        self.assertEqual(len(result), 1)
        self.assertIsInstance(result[0], BaseException)
        self.assertNotEqual(factory.server.finite_tools.state, 'registered')
        self.assertEqual(len(self.fixture.spawned), 1, 'no tool gate may open')
        self.assertFalse(any(reply.get('result', {}).get('success') is True
                             for reply in self.fixture.spawned[0].replies))
        self.assertIsNone(factory.token, 'no qualified artifact follows startup fault')
        attempt = self.fixture.attempt(case)
        self.assertEqual(attempt['outcome'], 'unknown')
        self.assertEqual(attempt['charge'], attempt['amount'])

    def test_reader_fault_during_catalog_record_prevents_registration(self):
        # The protocol post-callout fence: even a persisted catalog observation
        # cannot revive a transport fault before final registration.
        case = self.fixture.case(archive_schedule='concurrent', finite_tool_mode='captured-host-tools')
        factory = self.fixture.factory(case)
        entered, release, result = threading.Event(), threading.Event(), []
        original_record = factory.record
        original_read = finite_tools._read_capture_file
        installed = []

        def blocked_record(stage, observation):
            value = original_record(stage, observation)
            if stage == 'finite-tool-catalog':
                entered.set()
                release.wait(10)
            return value

        def install_record(path):
            if not installed:
                factory.record = blocked_record
                self.addCleanup(setattr, factory, 'record', original_record)
                installed.append(True)
            return original_read(path)

        def run():
            try:
                result.append(factory.run())
            except BaseException as failure:
                result.append(failure)

        self.addCleanup(release.set)
        with patch.object(family, 'RpcProcess', DynamicRpcProcess), patch.object(
                finite_tools, '_read_capture_file', install_record):
            worker = threading.Thread(target=run, daemon=True)
            worker.start()
            self.addCleanup(family.finish_worker, self, worker, release)
            self.assertTrue(self.wait_for_startup(entered, worker, result), 'startup=' + repr(result))
            server = factory.server
            self.assertEqual(server.finite_tools.state, 'registering')
            self.fixture.spawned[0].stdout.put({'method': 'item/started', 'params': {
                'item': {'type': 'commandExecution', 'id': 'EXAMPLE-uncontrolled'}}})
            until = time.monotonic() + 3
            while server.transport_failure is None and time.monotonic() < until:
                time.sleep(.005)
            self.assertIsNotNone(server.transport_failure)
            self.assertTrue(server.requests.closed)
            closed = threading.Event()
            def cleanup():
                try:
                    server.close()
                except BaseException:
                    pass
                finally:
                    closed.set()
            closer = threading.Thread(target=cleanup, daemon=True)
            closer.start()
            self.addCleanup(closer.join, 12)
            self.assertTrue(closed.wait(5))
            self.assertTrue(server.lifetime.contained)
            self.assertFalse(release.is_set())
            release.set()
            worker.join(12)
        self.assertEqual(len(result), 1)
        self.assertIsInstance(result[0], BaseException)
        self.assertNotEqual(factory.server.finite_tools.state, 'registered')
        self.assertEqual(len(self.fixture.spawned), 1)
        self.assertIsNone(factory.token)
        attempt = self.fixture.attempt(case)
        self.assertEqual(attempt['outcome'], 'unknown')
        self.assertEqual(attempt['charge'], attempt['amount'])

    def test_terminal_reader_stays_live_during_bounded_capture_recheck(self):
        case = self.fixture.case(finite_tool_mode='captured-host-tools')
        case.command_prepared, case.command_release = threading.Event(), threading.Event()
        factory = self.fixture.factory(case)
        entered, release, result = threading.Event(), threading.Event(), []
        original = family.runtime._RegisteredServer._capture_before_reply

        def blocked_capture(server, refusal):
            if not refusal:
                entered.set()
                release.wait(10)
            return original(server, refusal)

        def run():
            try:
                result.append(factory.run())
            except BaseException as failure:
                result.append(failure)

        self.addCleanup(release.set)
        self.addCleanup(case.command_release.set)
        with patch.object(family, 'RpcProcess', DynamicRpcProcess), patch.object(
                family.runtime._RegisteredServer, '_capture_before_reply', blocked_capture):
            worker = threading.Thread(target=run, daemon=True)
            worker.start()
            self.addCleanup(family.finish_worker, self, worker, case.command_release, release)
            self.assertTrue(self.wait_for_startup(case.command_prepared, worker, result))
            case.command_release.set()
            self.assertTrue(entered.wait(10))
            self.fixture.spawned[0].stdout.put({'method': 'turn/completed', 'params': {
                'threadId': case.scenario.thread_id,
                'turn': {'id': case.scenario.turn_id, 'status': 'completed'}}})
            until = time.monotonic() + 2
            while ((case.scenario.thread_id, case.scenario.turn_id)
                   not in factory.server.requests.terminals and time.monotonic() < until):
                time.sleep(.005)
            self.assertIn((case.scenario.thread_id, case.scenario.turn_id),
                          factory.server.requests.terminals)
            release.set()
            worker.join(12)
        self.assertEqual(len(result), 1)
        self.assertIsInstance(result[0], BaseException)
        self.assertFalse(any(reply.get('result', {}).get('success') is True
                             for reply in self.fixture.spawned[0].replies))
        attempt = self.fixture.attempt(case)
        self.assertEqual(attempt['outcome'], 'unknown')
        self.assertEqual(attempt['charge'], attempt['amount'])

    def test_clean_exit_after_command_reply_preserves_fresh_empty_poll(self):
        case = self.fixture.case(archive_schedule='settled', finite_tool_mode='captured-host-tools', tool_exit_before_poll=0)
        factory = self.fixture.factory(case)
        with patch.object(family, 'RpcProcess', DynamicRpcProcess):
            result = factory.run()
        self.assertEqual(result['attempt']['outcome'], 'completed')
        self.assertEqual(factory.server.finite_input.terminal_code, 0)
        self.assertEqual(self.fixture.spawned[0].replies[0]['result']['contentItems'][0]['text'],
                         'EXAMPLE finite command output\n')
        self.assertEqual(case.poll_observation, {'stdout': '', 'running': False})

    def test_clean_exit_before_completed_item_still_allows_fresh_poll(self):
        case = self.fixture.case(archive_schedule='settled', finite_tool_mode='captured-host-tools',
                                 tool_exit_before_completion=0)
        factory = self.fixture.factory(case)
        with patch.object(family, 'RpcProcess', DynamicRpcProcess):
            result = factory.run()
        self.assertEqual(result['attempt']['outcome'], 'completed')
        self.assertEqual(factory.server.finite_input.terminal_code, 0)
        self.assertEqual(case.poll_observation, {'stdout': '', 'running': False})

    def test_running_empty_poll_is_distinct_from_clean_empty_poll(self):
        case = self.fixture.case(archive_schedule='settled', finite_tool_mode='captured-host-tools', poll_empty_running=True)
        factory = self.fixture.factory(case)
        with patch.object(family, 'RpcProcess', DynamicRpcProcess):
            result = factory.run()
        self.assertEqual(result['attempt']['outcome'], 'completed')
        self.assertEqual(case.poll_observation, {'stdout': '', 'running': True})
        self.assertEqual(case.poll_state, 'running')

    def test_nonzero_exit_after_command_reply_refuses_poll_and_full_charge(self):
        case = self.fixture.case(finite_tool_mode='captured-host-tools', tool_exit_before_poll=7)
        factory = self.fixture.factory(case)
        with patch.object(family, 'RpcProcess', DynamicRpcProcess), self.assertRaises(BaseException):
            factory.run()
        self.assertTrue(self.fixture.spawned[0].replies[0]['result']['success'])
        self.assertFalse(any(reply.get('result', {}).get('success') is True
                             for reply in self.fixture.spawned[0].replies[1:]))
        attempt = self.fixture.attempt(case)
        self.assertEqual(attempt['outcome'], 'unknown')
        self.assertEqual(attempt['charge'], attempt['amount'])

    def test_nonzero_owned_tool_exit_refuses_success_and_retains_full_charge(self):
        case, factory, result = self._run_tool_exit(status=7)
        self.assertIsInstance(result, BaseException)
        self.assertEqual(factory.server.finite_input.terminal_code, 7)
        self.assertFalse(any(reply.get('result', {}).get('success') is True
                             for reply in self.fixture.spawned[0].replies))
        attempt = self.fixture.attempt(case)
        self.assertEqual(attempt['outcome'], 'unknown')
        self.assertEqual(attempt['charge'], attempt['amount'])

    def test_exit_status_without_same_handle_death_refuses_success(self):
        case, factory, result = self._run_tool_exit(pid_exited=False)
        self.assertIsInstance(result, BaseException)
        self.assertFalse(any(reply.get('result', {}).get('success') is True
                             for reply in self.fixture.spawned[0].replies))
        attempt = self.fixture.attempt(case)
        self.assertEqual(attempt['outcome'], 'unknown')
        self.assertEqual(attempt['charge'], attempt['amount'])

    def test_live_process_stdout_eof_refuses_success(self):
        case, factory, result = self._run_tool_exit(output=False, status=None, pid_exited=False)
        self.assertIsInstance(result, BaseException)
        self.assertFalse(any(reply.get('result', {}).get('success') is True
                             for reply in self.fixture.spawned[0].replies))
        attempt = self.fixture.attempt(case)
        self.assertEqual(attempt['outcome'], 'unknown')
        self.assertEqual(attempt['charge'], attempt['amount'])

    def test_clean_status_without_stdout_eof_refuses_success(self):
        case, _factory, result = self._run_tool_exit(close_output=False)
        self.assertIsInstance(result, BaseException)
        self.assertFalse(any(reply.get('result', {}).get('success') is True
                             for reply in self.fixture.spawned[0].replies))
        attempt = self.fixture.attempt(case)
        self.assertEqual(attempt['outcome'], 'unknown')
        self.assertEqual(attempt['charge'], attempt['amount'])

    def test_clean_exit_output_over_bound_refuses_success(self):
        case, _factory, result = self._run_tool_exit(trailing='X' * 4096)
        self.assertIsInstance(result, BaseException)
        self.assertFalse(any(reply.get('result', {}).get('success') is True
                             for reply in self.fixture.spawned[0].replies))
        attempt = self.fixture.attempt(case)
        self.assertEqual(attempt['outcome'], 'unknown')
        self.assertEqual(attempt['charge'], attempt['amount'])

    def test_default_original_route_cannot_spawn_unselected_tool(self):
        case = self.fixture.case(archive_schedule='settled')
        factory = self.fixture.factory(case)
        entered, resume = threading.Event(), threading.Event()
        result = []
        original = family.RpcProcess.approve

        def paused(process):
            entered.set()
            resume.wait(3)
            return original(process)

        def run():
            try:
                result.append(factory.run())
            except BaseException as failure:
                result.append(failure)

        with patch.object(family.RpcProcess, 'approve', paused):
            worker = threading.Thread(target=run, daemon=True)
            worker.start()
            try:
                self.assertTrue(self.wait_for_startup(entered, worker, result))
                self.assertIsNone(factory.server.finite_tools)
                with self.assertRaisesRegex(family.runtime.native.OfflineHostError,
                                            'selected finite producer'):
                    family.runtime._Containment(factory, role='tool').launch(
                        ['/usr/bin/sh', '-c', case.spec['command']], case.home,
                        tool_call={'callId': 'EXAMPLE-forged-command'},
                        deadline=time.monotonic() + 2, tool_decision=object())
                self.assertEqual(len(self.fixture.spawned), 1)
            finally:
                resume.set()
                worker.join(8)
        self.assertEqual(result[0]['attempt']['outcome'], 'completed')

    def assert_selected_pipe_observations(self, case, factory, result):
        self.assertEqual(result['attempt']['outcome'], 'completed')
        self.assertEqual(factory.server.finite_input.dynamic_command[:3],
                         (case.scenario.thread_id, case.scenario.turn_id, 'EXAMPLE-command-call'))
        self.assertEqual(self.fixture.spawned[0].replies[0]['result']['contentItems'][0]['text'],
                         'EXAMPLE finite command output\n')
        self.assertEqual(case.poll_observation,
                         {'stdout': 'EXAMPLE finite poll output\n', 'running': True})
        with self.assertRaises(BlockingIOError):
            os.read(case.tool_read, 1)
        self.assertTrue(self.fixture.spawned[1].process.alive is False)
        sessions = [birth.receipt.registration.session_id for table in self.fixture.tables
                    for birth in table.births]
        self.assertEqual(set(sessions), {factory.operation_id + suffix for suffix in
            ('-transport', '-tool', '-validation')})
        self.assertIsNotNone(factory.issued_artifact())

    def _special_capture_refusal(self, read_index):
        case = self.fixture.case(finite_tool_mode='captured-host-tools')
        factory = self.fixture.factory(case)
        original = finite_tools._read_capture_file
        observed, results = [], []
        fifo_installed = threading.Event()
        path = case.home / 'finite-tool-capture.json'
        def read_capture(name):
            observed.append(name)
            if len(observed) == read_index:
                name.unlink()
                os.mkfifo(name, 0o600)
                fifo_installed.set()
            return original(name)
        def run():
            try:
                results.append(factory.run())
            except BaseException as failure:
                results.append(failure)
        with patch.object(family, 'RpcProcess', DynamicRpcProcess), patch.object(
                finite_tools, '_read_capture_file', read_capture):
            worker = threading.Thread(target=run, daemon=True)
            worker.start()
            try:
                self.assertTrue(self.wait_for_startup(fifo_installed, worker, results))
                worker.join(5)
                self.assertFalse(worker.is_alive(), 'Catalog open waited for a FIFO writer.')
            finally:
                # Unblock only a failing old implementation, so its retained
                # regression leaves neither a daemon nor an owned fixture alive.
                if worker.is_alive() and len(observed) == read_index:
                    descriptor = os.open(path, os.O_WRONLY | os.O_NONBLOCK | os.O_CLOEXEC)
                    os.close(descriptor)
                worker.join(8)
        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], ValueError)
        self.assertEqual(len(self.fixture.spawned), 1)
        self.assertIsNone(factory.token)
        attempt = self.fixture.attempt(case)
        self.assertEqual(attempt['outcome'], 'unknown')
        self.assertEqual(attempt['charge'], attempt['amount'])

    def test_catalog_drift_refuses_before_command_or_tool_process(self):
        case = self.fixture.case(finite_tool_mode='captured-host-tools', catalog_drift=True)
        factory = self.fixture.factory(case)
        with patch.object(family, 'RpcProcess', DynamicRpcProcess), self.assertRaises(ValueError):
            factory.run()
        self.assertEqual(len(self.fixture.spawned), 1)
        self.assertIsNone(factory.token)
        family.cleanup_helper(self, self.fixture)
        for read_index in (1, 2):
            with self.subTest(capture_phase=('startup' if read_index == 1 else 'registration')):
                # Each original route owns independent IDs/process fixtures.
                fixture = RegisteredFiniteToolWiringTests(methodName='runTest')
                fixture.setUp()
                try:
                    fixture._special_capture_refusal(read_index)
                finally:
                    family.cleanup_helper(self, fixture)

    def test_nonempty_poll_refuses_without_any_tool_stdin_delivery(self):
        case = self.fixture.case(archive_schedule='settled', finite_tool_mode='captured-host-tools',
                                 poll_chars='EXAMPLE nonempty', complete_after_refusal=True)
        factory = self.fixture.factory(case)
        with patch.object(family, 'RpcProcess', DynamicRpcProcess):
            result = factory.run()
        self.assertEqual(result['attempt']['outcome'], 'completed')
        self.assertEqual([reply['result']['success'] for reply in self.fixture.spawned[0].replies],
                         [True, False])
        with self.assertRaises(BlockingIOError):
            os.read(case.tool_read, 1)
        self.assertIn('EXAMPLE-poll-call', factory.server.finite_input.used_approvals)
        self.assertNotIn('finite-poll-intent', [json.loads(path.read_bytes())['stage'] for path in
            (factory.records / 'transport-observations').iterdir()])

    def test_poll_before_original_command_completion_refuses_without_input(self):
        case = self.fixture.case(archive_schedule='settled', finite_tool_mode='captured-host-tools',
                                 poll_before_command_completed=True, complete_after_refusal=True)
        factory = self.fixture.factory(case)
        with patch.object(family, 'RpcProcess', DynamicRpcProcess):
            result = factory.run()
        self.assertEqual(result['attempt']['outcome'], 'completed')
        self.assertEqual([reply['result']['success'] for reply in self.fixture.spawned[0].replies],
                         [True, False])
        self.assertEqual(factory.server._command_reply_committed,
                         (case.scenario.thread_id, case.scenario.turn_id, 'EXAMPLE-command-call'))
        self.assertNotIn((case.scenario.thread_id, case.scenario.turn_id, 'EXAMPLE-command-call'),
                         factory.server.requests.completed_items)
        with self.assertRaises(BlockingIOError):
            os.read(case.tool_read, 1)

    def test_fast_completion_waits_for_atomic_command_reply_marker(self):
        case = self.fixture.case(archive_schedule='settled', finite_tool_mode='captured-host-tools')
        case.completion_emitted = threading.Event()
        factory = self.fixture.factory(case)
        entered, release = threading.Event(), threading.Event()
        result = []
        original = family.runtime._RegisteredServer._mark_command_reply
        def held_marker(server, message, response, item):
            if message.get('params', {}).get('tool') == 'finite_command':
                entered.set()
                release.wait(5)
            return original(server, message, response, item)
        def run():
            try:
                result.append(factory.run())
            except BaseException as failure:
                result.append(failure)
        with patch.object(family, 'RpcProcess', DynamicRpcProcess), patch.object(
                family.runtime._RegisteredServer, '_mark_command_reply', held_marker):
            thread = threading.Thread(target=run, daemon=True)
            thread.start()
            self.addCleanup(family.finish_worker, self, thread, release)
            self.addCleanup(release.set)
            self.assertTrue(self.wait_for_startup(entered, thread, result))
            self.assertTrue(case.completion_emitted.wait(5))
            release.set()
            thread.join(12)
        self.assertEqual(len(result), 1)
        self.assertIsInstance(result[0], dict)
        self.assertEqual(result[0]['attempt']['outcome'], 'completed')
        self.assertEqual([reply['result']['success'] for reply in self.fixture.spawned[0].replies],
                         [True, True])

    def test_fast_item_completion_during_prior_reply_dispatch_waits_for_full_send(self):
        case = self.fixture.case(archive_schedule='settled', finite_tool_mode='captured-host-tools')
        case.completion_emitted = threading.Event()
        factory = self.fixture.factory(case)
        entered, release = threading.Event(), threading.Event()
        outcome = []
        physical = gate_module.RegisteredFiniteInput._write_reply_frame

        def held_after_real_write(writer, frame):
            sent = physical(writer, frame)
            if b'"success":true' in frame and not entered.is_set():
                entered.set()
                release.wait(5)
            return sent

        def run():
            try:
                outcome.append(factory.run())
            except BaseException as failure:
                outcome.append(failure)

        with patch.object(family, 'RpcProcess', DynamicRpcProcess), patch.object(
                gate_module.RegisteredFiniteInput, '_write_reply_frame',
                staticmethod(held_after_real_write)):
            worker = threading.Thread(target=run, daemon=True)
            worker.start()
            self.addCleanup(release.set)
            self.addCleanup(family.finish_worker, self, worker, release)
            self.assertTrue(self.wait_for_startup(entered, worker, outcome), 'physical reply write was not reached')
            self.assertTrue(case.completion_emitted.wait(5), 'fake server did not observe the reply')
            identity = (case.scenario.thread_id, case.scenario.turn_id, 'EXAMPLE-command-call')
            end = time.monotonic() + 3
            while identity not in factory.server.requests.completed_items:
                self.assertLess(time.monotonic(), end, 'item intake waited for writer return')
                time.sleep(.002)
            lifecycle = factory.server.finite_input.lifecycle
            self.assertTrue(lifecycle.command_reply_dispatched(identity))
            self.assertEqual(lifecycle.phase, 'command-effect')
            self.assertIsNone(factory.server._command_reply_committed)
            release.set()
            worker.join(12)
        self.assertFalse(worker.is_alive(), 'the registered action thread did not finish')
        self.assertEqual(len(outcome), 1)
        self.assertIsInstance(outcome[0], dict)
        self.assertEqual(outcome[0]['attempt']['outcome'], 'completed')
        self.assertEqual([reply['result']['success'] for reply in self.fixture.spawned[0].replies],
                         [True, True])
        self.assertIn(identity, factory.server.requests.completed_items)
        self.assertEqual(factory.server._command_reply_committed, identity)

    def test_unknown_dynamic_tool_refuses_before_owned_command_launch(self):
        case = self.fixture.case(finite_tool_mode='captured-host-tools', command_tool='write_stdin')
        factory = self.fixture.factory(case)
        with patch.object(family, 'RpcProcess', DynamicRpcProcess), self.assertRaises(ValueError):
            factory.run()
        self.assertEqual(len(self.fixture.spawned), 1)
        attempt = self.fixture.attempt(case)
        self.assertEqual(attempt['outcome'], 'unknown')
        self.assertEqual(attempt['charge'], attempt['amount'])

    def test_raw_request_id_collision_across_permissions_and_tool_refuses(self):
        case = self.fixture.case(finite_tool_mode='captured-host-tools',
                                 colliding_permission_before_command=True)
        factory = self.fixture.factory(case)
        with patch.object(family, 'RpcProcess', DynamicRpcProcess), self.assertRaises(ValueError):
            factory.run()
        self.assertEqual(len(self.fixture.spawned), 1)
        attempt = self.fixture.attempt(case)
        self.assertEqual(attempt['outcome'], 'unknown')
        self.assertEqual(attempt['charge'], attempt['amount'])

    def test_typed_integer_and_string_request_ids_remain_distinct(self):
        case = self.fixture.case(archive_schedule='settled', finite_tool_mode='captured-host-tools',
                                 typed_distinct_request_ids=True, command_request_id='7',
                                 no_fake_scheduler=True, materialize_on_turn_start=True)
        case.tool_spawn_entered, case.tool_spawn_release = threading.Event(), threading.Event()
        factory = self.fixture.factory(case)
        outcome = []
        def run():
            try:
                outcome.append(factory.run())
            except BaseException as failure:
                outcome.append(failure)
        with patch.object(family, 'RpcProcess', DynamicRpcProcess):
            worker = threading.Thread(target=run, daemon=True)
            worker.start()
            self.addCleanup(family.finish_worker, self, worker, case.tool_spawn_release, join_seconds=20)
            self.addCleanup(case.tool_spawn_release.set)
            self.assertTrue(self.wait_for_startup(case.tool_spawn_entered, worker, outcome),
                            f'host checks: {factory.adapter.check_count}; '
                            f'outcome: {type(outcome[0]).__name__ if outcome else "running"}; '
                            f'queued: {factory.server._tool_queue.qsize()}; '
                            f'inflight: {factory.server.finite_tools.inflight is not None}; '
                            f'producer: {factory.server.finite_tools.state}; '
                            f'transport: {type(factory.server.transport_failure).__name__}: '
                            f'{factory.server.transport_failure}')
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline and factory.adapter.check_count < 64:
                time.sleep(.01)
            case.tool_spawn_release.set()
            worker.join(20)
        self.assertEqual(len(outcome), 1)
        result = outcome[0]
        self.assertIsInstance(result, dict, f'host checks: {factory.adapter.check_count}')
        self.assertEqual(result['attempt']['outcome'], 'completed')
        self.assertIn((int, 7), factory.server.requests.entries)
        self.assertEqual({(type(reply['id']), reply['id']) for reply in self.fixture.spawned[0].replies},
                         {(int, 7), (str, '7'), (str, 'EXAMPLE-request-EXAMPLE-poll-call')})

    def test_answered_dynamic_id_cannot_reappear_as_permission_request(self):
        case = self.fixture.case(finite_tool_mode='captured-host-tools',
                                 reused_id_after_command_answer=True)
        factory = self.fixture.factory(case)
        with patch.object(family, 'RpcProcess', DynamicRpcProcess), self.assertRaises(ValueError):
            factory.run()
        attempt = self.fixture.attempt(case)
        self.assertEqual(attempt['outcome'], 'unknown')
        self.assertEqual(attempt['charge'], attempt['amount'])
        self.assertEqual(len(self.fixture.spawned), 2)
        self.assertTrue(self.fixture.spawned[1].process.alive is False)

    def test_blocked_poll_decision_does_not_block_terminal_reader(self):
        case = self.fixture.case(finite_tool_mode='captured-host-tools')
        case.poll_prepared, case.poll_release = threading.Event(), threading.Event()
        factory = self.fixture.factory(case)
        result = []
        def run():
            try:
                result.append(factory.run())
            except BaseException as failure:
                result.append(failure)
        with patch.object(family, 'RpcProcess', DynamicRpcProcess):
            thread = threading.Thread(target=run, daemon=True)
            thread.start()
            self.addCleanup(family.finish_worker, self, thread, case.poll_release)
            self.addCleanup(case.poll_release.set)
            self.assertTrue(self.wait_for_startup(case.poll_prepared, thread, result))
            entered, release = threading.Event(), threading.Event()
            self.addCleanup(release.set)
            original = factory.record
            def blocked(stage, observation):
                if stage == 'finite-tool-decision' and observation.get('tool') == 'finite_poll':
                    entered.set()
                    release.wait(5)
                return original(stage, observation)
            with patch.object(factory, 'record', blocked):
                case.poll_release.set()
                self.assertTrue(entered.wait(5))
                self.fixture.spawned[0].stdout.put({'method': 'turn/completed', 'params': {
                    'threadId': case.scenario.thread_id,
                    'turn': {'id': case.scenario.turn_id, 'status': 'completed'}}})
                deadline = time.monotonic() + 3
                while (case.scenario.thread_id, case.scenario.turn_id) not in factory.server.requests.terminals:
                    self.assertLess(time.monotonic(), deadline, 'reader blocked behind tool decision')
                    time.sleep(.01)
                release.set()
                thread.join(10)
        self.assertEqual(len(result), 1)
        self.assertIsInstance(result[0], BaseException)
        attempt = self.fixture.attempt(case)
        self.assertEqual(attempt['outcome'], 'unknown')
        self.assertEqual(attempt['charge'], attempt['amount'])
        stages = [json.loads(path.read_bytes())['stage'] for path in
                  (factory.records / 'transport-observations').iterdir()]
        self.assertNotIn('finite-poll-intent', stages)
        self.assertNotIn('finite-poll-intent-aborted', stages)
        self.assertFalse(any(reply.get('result', {}).get('success') is True
                             for reply in self.fixture.spawned[0].replies[1:]))
        self.assertEqual(factory.server.finite_input.output_bytes_seen,
                         len(b'EXAMPLE finite command output\n'))
        with self.assertRaises(BlockingIOError):
            os.read(case.tool_read, 1)

    def _bad_tool_pipe(self, option):
        case = self.fixture.case(finite_tool_mode='captured-host-tools', **{option: True})
        factory = self.fixture.factory(case)
        with patch.object(family, 'RpcProcess', DynamicRpcProcess), self.assertRaises(ValueError):
            factory.run()
        attempt = self.fixture.attempt(case)
        self.assertEqual(attempt['outcome'], 'unknown')
        self.assertEqual(attempt['charge'], attempt['amount'])
        self.assertIsNotNone(factory.server.transport_failure)
        self.assertTrue(self.fixture.spawned[1].process.alive is False)
        with self.assertRaises(BlockingIOError):
            os.read(case.tool_read, 1)

    def test_poll_eof_revokes_and_contains_original_tool(self):
        self._bad_tool_pipe('tool_eof_after_command')

    def test_poll_pipe_swap_revokes_and_contains_original_tool(self):
        self._bad_tool_pipe('tool_swap_after_command')

    def _poll_wait_schedule(self, action):
        case = self.fixture.case(archive_schedule='concurrent', finite_tool_mode='captured-host-tools')
        case.poll_prepared, case.poll_release = threading.Event(), threading.Event()
        factory = self.fixture.factory(case)
        result = []
        def run():
            try:
                result.append(factory.run())
            except BaseException as failure:
                result.append(failure)
        with patch.object(family, 'RpcProcess', DynamicRpcProcess):
            thread = threading.Thread(target=run, daemon=True)
            thread.start()
            self.addCleanup(family.finish_worker, self, thread, case.poll_release)
            self.addCleanup(case.poll_release.set)
            self.assertTrue(self.wait_for_startup(case.poll_prepared, thread, result))
            entered, release = threading.Event(), threading.Event()
            self.addCleanup(release.set)
            original = gate_module.select.select
            gate = factory.server.finite_input
            charged_before = gate.output_bytes_seen
            def paused(reads, writes, errors, timeout=None):
                if (len(reads) == 1 and type(reads[0]) is int
                        and reads[0] != gate.output_fd
                        and os.fstat(reads[0]).st_ino == gate.output_stat[1]):
                    entered.set()
                    release.wait(3)
                    return [], [], []
                return original(reads, writes, errors, timeout)
            with patch.object(gate_module.select, 'select', paused):
                case.poll_release.set()
                self.assertTrue(entered.wait(5))
                if action in {'terminal', 'exceptional'}:
                    if action == 'exceptional':
                        with self.assertRaisesRegex(family.runtime.protocol.PreparationError,
                                                    'registered-terminal-before-bound-turn'):
                            factory.server.requests.observe_response({'result': {'thread': {
                                'id': case.scenario.thread_id, 'turns': [
                                    {'id': case.scenario.turn_id, 'status': 'completed', 'items': []},
                                    {'id': 'EXAMPLE-unrelated-turn', 'status': 'completed', 'items': []}]}}})
                        self.assertEqual(gate.lifecycle.phase, 'fault')
                    else:
                        self.fixture.spawned[0].stdout.put({'method': 'turn/completed', 'params': {
                            'threadId': case.scenario.thread_id,
                            'turn': {'id': case.scenario.turn_id, 'status': 'completed'}}})
                    deadline = time.monotonic() + 3
                    while (case.scenario.thread_id, case.scenario.turn_id) not in factory.server.requests.terminals:
                        self.assertLess(time.monotonic(), deadline, 'reader blocked on pipe wait')
                        time.sleep(.01)
                else:
                    closed = threading.Event()
                    closer = threading.Thread(target=lambda: (gate.close(), closed.set()), daemon=True)
                    closer.start()
                    self.assertTrue(closed.wait(3), 'close blocked on pipe wait')
                    closer.join(3)
                time.sleep(1.1)
                release.set()
                thread.join(10)
        self.assertEqual(len(result), 1)
        self.assertIsInstance(result[0], BaseException)
        attempt = self.fixture.attempt(case)
        self.assertEqual(attempt['outcome'], 'unknown')
        self.assertEqual(attempt['charge'], attempt['amount'])
        if action == 'exceptional':
            self.assertEqual(gate.output_bytes_seen, charged_before)
            self.assertFalse(any(reply.get('id') == 'EXAMPLE-request-EXAMPLE-poll-call'
                                 and reply.get('result', {}).get('success') is True
                                 for reply in self.fixture.spawned[0].replies))
            self.assertTrue(gate.cleanup_attempted)
            self.assertTrue(gate.closed_lifetime.contained)
            with self.assertRaises(BlockingIOError):
                os.read(case.tool_read, 1)

    def test_exceptional_projection_during_poll_pipe_wait(self):
        self._poll_wait_schedule('exceptional')

    def test_terminal_during_poll_wait_revokes_before_reply(self):
        self._poll_wait_schedule('terminal')

    def test_close_during_poll_wait_is_responsive_and_deadline_refuses(self):
        self._poll_wait_schedule('close')

    def _bad_poll_identity(self, option):
        case = self.fixture.case(finite_tool_mode='captured-host-tools', **{option: True})
        factory = self.fixture.factory(case)
        with patch.object(family, 'RpcProcess', DynamicRpcProcess), self.assertRaises(ValueError):
            factory.run()
        attempt = self.fixture.attempt(case)
        self.assertEqual(attempt['outcome'], 'unknown')
        self.assertEqual(attempt['charge'], attempt['amount'])
        self.assertEqual(len(self.fixture.spawned), 2)
        with self.assertRaises(BlockingIOError):
            os.read(case.tool_read, 1)

    def test_wrong_turn_poll_refuses_before_process_input(self):
        self._bad_poll_identity('poll_wrong_turn')

    def test_epoch_drift_poll_refuses_before_process_input(self):
        self._bad_poll_identity('poll_epoch_drift')

    def test_replayed_poll_call_refuses_without_second_delivery(self):
        self._bad_poll_identity('replay_poll')

    def _terminal_during_command(self, stage, *, exceptional=False):
        case = self.fixture.case(finite_tool_mode='captured-host-tools')
        case.command_prepared, case.command_release = threading.Event(), threading.Event()
        factory = self.fixture.factory(case)
        result = []
        def run():
            try:
                result.append(factory.run())
            except BaseException as failure:
                result.append(failure)
        with patch.object(family, 'RpcProcess', DynamicRpcProcess):
            thread = threading.Thread(target=run, daemon=True)
            thread.start()
            self.addCleanup(family.finish_worker, self, thread, case.command_release)
            self.addCleanup(case.command_release.set)
            self.assertTrue(self.wait_for_startup(case.command_prepared, thread, result))
            entered, release = threading.Event(), threading.Event()
            self.addCleanup(release.set)
            original_record = factory.record
            original_launch = family.runtime._Containment.launch
            def blocked_record(name, observation):
                if ((stage == 'before-intent' and name == 'finite-tool-decision'
                     and observation.get('tool') == 'finite_command')
                        or (stage == 'during-intent' and name == 'finite-tool-command-intent')):
                    entered.set()
                    release.wait(5)
                value = original_record(name, observation)
                if ((stage == 'intent' and name == 'finite-tool-command-intent')
                        or (stage == 'gate' and name == 'tool-contained')):
                    entered.set()
                    release.wait(5)
                return value
            def blocked_launch(lifetime, command, home, **kwargs):
                process = original_launch(lifetime, command, home, **kwargs)
                if lifetime.role == 'tool':
                    entered.set()
                    release.wait(5)
                return process
            patcher = (patch.object(factory, 'record', blocked_record) if stage in {'before-intent', 'during-intent', 'intent', 'gate'}
                       else patch.object(family.runtime._Containment, 'launch', blocked_launch))
            with patcher:
                case.command_release.set()
                self.assertTrue(entered.wait(5))
                if exceptional:
                    with self.assertRaisesRegex(family.runtime.protocol.PreparationError,
                                                'registered-terminal-before-bound-turn'):
                        factory.server.requests.observe_response({'result': {'thread': {
                            'id': case.scenario.thread_id, 'turns': [
                                {'id': case.scenario.turn_id, 'status': 'completed', 'items': []},
                                {'id': 'EXAMPLE-unrelated-turn', 'status': 'completed', 'items': []}]}}})
                    self.assertEqual(factory.server.finite_input.lifecycle.phase, 'fault')
                else:
                    self.fixture.spawned[0].stdout.put({'method': 'turn/completed', 'params': {
                        'threadId': case.scenario.thread_id,
                        'turn': {'id': case.scenario.turn_id, 'status': 'completed'}}})
                deadline = time.monotonic() + 3
                while (case.scenario.thread_id, case.scenario.turn_id) not in factory.server.requests.terminals:
                    self.assertLess(time.monotonic(), deadline, 'reader blocked during command callout')
                    time.sleep(.01)
                release.set()
                thread.join(10)
        self.assertEqual(len(result), 1)
        self.assertIsInstance(result[0], BaseException)
        attempt = self.fixture.attempt(case)
        self.assertEqual(attempt['outcome'], 'unknown')
        self.assertEqual(attempt['charge'], attempt['amount'])
        self.assertEqual(len(self.fixture.spawned), 1 if stage in {'before-intent', 'during-intent', 'intent'} else 2)
        if stage in {'launch', 'gate'}:
            self.assertTrue(self.fixture.spawned[1].process.alive is False)
        return factory

    def test_exceptional_projection_during_command_decision_and_intent(self):
        for stage in ('before-intent', 'during-intent'):
            with self.subTest(stage=stage):
                fixture = RegisteredFiniteToolWiringTests(methodName='runTest')
                fixture.setUp()
                try:
                    factory = fixture._terminal_during_command(stage, exceptional=True)
                    end = time.monotonic() + 3
                    while True:
                        records = [json.loads(path.read_text()) for path in
                                   (factory.records / 'transport-observations').iterdir()]
                        stages = [row['stage'] for row in records]
                        if stage != 'during-intent' or 'finite-command-intent-aborted' in stages:
                            break
                        self.assertLess(time.monotonic(), end, stages)
                        time.sleep(.001)
                    self.assertEqual(stages.count('finite-tool-command-intent'),
                                     int(stage == 'during-intent'))
                    self.assertEqual(stages.count('finite-command-intent-aborted'),
                                     int(stage == 'during-intent'))
                finally:
                    family.cleanup_helper(self, fixture)

    def test_terminal_during_decision_callout_admits_no_command_intent(self):
        """Callback terminal precedes intent admission."""
        factory = self._terminal_during_command('before-intent')
        stages = [json.loads(path.read_bytes())['stage'] for path in
                  (factory.records / 'transport-observations').iterdir()]
        self.assertNotIn('finite-tool-command-intent', stages)
        self.assertNotIn('finite-command-intent-aborted', stages)

    def test_terminal_during_command_intent_persistence_aborts_reservation(self):
        """Preterminal reservation has no late grant."""
        factory = self._terminal_during_command('during-intent')
        stages = [json.loads(path.read_bytes())['stage'] for path in
                  (factory.records / 'transport-observations').iterdir()]
        self.assertEqual(stages.count('finite-tool-command-intent'), 1)
        self.assertEqual(stages.count('finite-command-intent-aborted'), 1)
        records = [json.loads(path.read_bytes()) for path in
                   (factory.records / 'transport-observations').iterdir()]
        reserved = next(row['observation'] for row in records
                        if row['stage'] == 'finite-tool-command-intent')
        aborted = next(row['observation'] for row in records
                       if row['stage'] == 'finite-command-intent-aborted')
        self.assertEqual(reserved['intent_state'], 'reserved')
        self.assertEqual(reserved['reservation_generation'],
                         aborted['reservation_generation'])
        self.assertLess(reserved['reservation_lifecycle_generation'],
                        aborted['abort_lifecycle_generation'])

    def _command_read_projection_schedule(self, *, exceptional=False):
        """Terminal projection and revocation fence the captured command output path."""
        case = self.fixture.case(finite_tool_mode='captured-host-tools',
                                 materialize_on_turn_start=True)
        factory = self.fixture.factory(case)
        entered, release, outcome = threading.Event(), threading.Event(), []
        original_read = gate_module.RegisteredFiniteInput.read_stdout

        def paused(gate, descriptor, deadline, **kwargs):
            params = kwargs.get('params')
            if (not entered.is_set() and type(params) is dict
                    and params.get('tool') == 'finite_command'):
                entered.set()
                release.wait(5)
            return original_read(gate, descriptor, deadline, **kwargs)

        def run():
            try:
                outcome.append(factory.run())
            except BaseException as failure:
                outcome.append(failure)

        with patch.object(family, 'RpcProcess', DynamicRpcProcess), patch.object(
                gate_module.RegisteredFiniteInput, 'read_stdout', paused):
            worker = threading.Thread(target=run, daemon=True)
            worker.start()
            self.addCleanup(family.finish_worker, self, worker, release)
            self.addCleanup(release.set)
            try:
                self.assertTrue(self.wait_for_startup(entered, worker, outcome))
                gate = factory.server.finite_input
                self.assertEqual(gate.output_bytes_seen, 0)
                if exceptional:
                    with self.assertRaisesRegex(family.runtime.protocol.PreparationError,
                                                'registered-terminal-before-bound-turn'):
                        factory.server.requests.observe_response({'result': {'thread': {
                            'id': case.scenario.thread_id, 'turns': [
                                {'id': case.scenario.turn_id, 'status': 'completed', 'items': []},
                                {'id': 'EXAMPLE-unrelated-turn', 'status': 'completed', 'items': []}]}}})
                    self.assertEqual(gate.lifecycle.phase, 'fault')
                else:
                    self.fixture.spawned[0].stdout.put({'method': 'turn/completed', 'params': {
                        'threadId': case.scenario.thread_id,
                        'turn': {'id': case.scenario.turn_id, 'status': 'completed'}}})
                end = time.monotonic() + 3
                while gate.lifecycle.phase != ('fault' if exceptional else 'terminal'):
                    self.assertLess(time.monotonic(), end)
                    time.sleep(.001)
            finally:
                release.set()
                worker.join(12)
        self.assertEqual(gate.output_bytes_seen, 0)
        self.assertFalse(any(reply.get('result', {}).get('success') is True
                             for reply in self.fixture.spawned[0].replies))
        self.assertEqual(os.read(gate.output_fd, 4096),
                         b'EXAMPLE finite command output\n')
        with self.assertRaises(BlockingIOError):
            os.read(case.tool_read, 1)
        self.assertTrue(self.fixture.spawned[1].process.alive is False)
        self.assertIsInstance(outcome[0], BaseException)
        self.assertEqual(self.fixture.attempt(case)['outcome'], 'unknown')
        self.assertEqual(self.fixture.attempt(case)['charge'],
                         self.fixture.attempt(case)['amount'])

    def test_terminal_before_original_command_stdout_effect_consumes_no_bytes(self):
        self._command_read_projection_schedule()

    def test_exceptional_projection_before_original_command_stdout_effect(self):
        self._command_read_projection_schedule(exceptional=True)

    def test_terminal_during_clean_exit_tail_refresh_preserves_unread_tail(self):
        """Clean-exit and reply reobservation preserve unread output after refusal."""
        case = self.fixture.case(finite_tool_mode='captured-host-tools',
                                 natural_tool_exit=True, materialize_on_turn_start=True)
        factory = self.fixture.factory(case)
        entered, release, outcome = threading.Event(), threading.Event(), []
        exited = []
        original_commit = family.runtime._RegisteredServer._commit_tool_reply
        original_read = gate_module.RegisteredFiniteInput.read_stdout
        tail = b'EXAMPLE late clean tail\n'

        def exit_before_reply(server, message, response, deadline, *, refusal=False):
            if (not exited and not refusal
                    and message.get('params', {}).get('tool') == 'finite_command'
                    and response.get('result', {}).get('success') is True):
                tool = self.fixture.spawned[1]
                case.tool_stream.put(tail.decode())
                tool.returncode = 0
                tool.process.alive = False
                case.tool_stream.put('')
                exited.append(True)
            return original_commit(server, message, response, deadline, refusal=refusal)

        def paused(gate, descriptor, deadline, **kwargs):
            if (gate.terminal_code == 0 and not entered.is_set()
                    and kwargs.get('params', {}).get('tool') == 'finite_command'):
                entered.set()
                release.wait(5)
            return original_read(gate, descriptor, deadline, **kwargs)

        def run():
            try:
                outcome.append(factory.run())
            except BaseException as failure:
                outcome.append(failure)

        with patch.object(family, 'RpcProcess', DynamicRpcProcess), patch.object(
                family.runtime._RegisteredServer, '_commit_tool_reply', exit_before_reply), patch.object(
                gate_module.RegisteredFiniteInput, 'read_stdout', paused):
            worker = threading.Thread(target=run, daemon=True)
            worker.start()
            self.addCleanup(family.finish_worker, self, worker, release)
            self.addCleanup(release.set)
            try:
                self.assertTrue(self.wait_for_startup(entered, worker, outcome))
                gate = factory.server.finite_input
                self.assertEqual(gate.output_bytes_seen,
                                 len(b'EXAMPLE finite command output\n'))
                self.fixture.spawned[0].stdout.put({'method': 'turn/completed', 'params': {
                    'threadId': case.scenario.thread_id,
                    'turn': {'id': case.scenario.turn_id, 'status': 'completed'}}})
                end = time.monotonic() + 3
                while gate.lifecycle.phase != 'terminal':
                    self.assertLess(time.monotonic(), end)
                    time.sleep(.001)
            finally:
                release.set()
                worker.join(12)
        self.assertEqual(exited, [True])
        self.assertEqual(gate.output_bytes_seen,
                         len(b'EXAMPLE finite command output\n'))
        self.assertEqual(os.read(gate.output_fd, 4096), tail)
        self.assertFalse(any(reply.get('result', {}).get('success') is True
                             for reply in self.fixture.spawned[0].replies))
        with self.assertRaises(BlockingIOError):
            os.read(case.tool_read, 1)
        self.assertIsInstance(outcome[0], BaseException)
        self.assertEqual(self.fixture.attempt(case)['outcome'], 'unknown')
        self.assertEqual(self.fixture.attempt(case)['charge'],
                         self.fixture.attempt(case)['amount'])

    def test_terminal_after_reply_ticket_before_atomic_commit_refuses_success(self):
        """An integration ticket cannot outrun terminal request evidence."""
        case = self.fixture.case(finite_tool_mode='captured-host-tools',
                                 materialize_on_turn_start=True)
        factory = self.fixture.factory(case)
        entered, release, outcome = threading.Event(), threading.Event(), []
        original_commit = gate_module.RegisteredFiniteInput.commit_reply_observation

        def paused(gate, ticket, producer, message, response, deadline,
                   frame, writer, refusal):
            if (not entered.is_set() and not refusal
                    and message.get('params', {}).get('tool') == 'finite_command'):
                entered.set()
                release.wait(5)
            return original_commit(gate, ticket, producer, message, response,
                                   deadline, frame, writer, refusal)

        def run():
            try:
                outcome.append(factory.run())
            except BaseException as failure:
                outcome.append(failure)

        with patch.object(family, 'RpcProcess', DynamicRpcProcess), patch.object(
                gate_module.RegisteredFiniteInput, 'commit_reply_observation', paused):
            worker = threading.Thread(target=run, daemon=True)
            worker.start()
            self.addCleanup(family.finish_worker, self, worker, release)
            self.addCleanup(release.set)
            try:
                self.assertTrue(self.wait_for_startup(entered, worker, outcome))
                gate = factory.server.finite_input
                self.assertEqual(gate.output_bytes_seen,
                                 len(b'EXAMPLE finite command output\n'))
                self.fixture.spawned[0].stdout.put({'method': 'turn/completed', 'params': {
                    'threadId': case.scenario.thread_id,
                    'turn': {'id': case.scenario.turn_id, 'status': 'completed'}}})
                end = time.monotonic() + 3
                while gate.lifecycle.phase != 'terminal':
                    self.assertLess(time.monotonic(), end)
                    time.sleep(.001)
            finally:
                release.set()
                worker.join(12)
        self.assertFalse(any(reply.get('result', {}).get('success') is True
                             for reply in self.fixture.spawned[0].replies))
        self.assertEqual(gate.output_bytes_seen,
                         len(b'EXAMPLE finite command output\n'))
        with self.assertRaises(BlockingIOError):
            os.read(case.tool_read, 1)
        self.assertTrue(self.fixture.spawned[1].process.alive is False)
        self.assertIsInstance(outcome[0], BaseException)
        self.assertEqual(self.fixture.attempt(case)['outcome'], 'unknown')
        self.assertEqual(self.fixture.attempt(case)['charge'],
                         self.fixture.attempt(case)['amount'])

    def test_terminal_after_command_intent_prevents_tool_launch(self):
        self._terminal_during_command('intent')

    def test_terminal_during_owned_tool_launch_contains_child(self):
        self._terminal_during_command('launch')

    def test_nonblocking_gate_write_failure_faults_before_command_read(self):
        """T07 failed effect cannot leave an accepting command-effect phase."""
        case = self.fixture.case(finite_tool_mode='captured-host-tools')
        case.command_prepared, case.command_release = threading.Event(), threading.Event()
        factory = self.fixture.factory(case)
        outcome = []
        original_write = os.write

        def denied(fd, data):
            if data == b'1':
                raise BlockingIOError('EXAMPLE gate backpressure')
            return original_write(fd, data)

        def run():
            try:
                outcome.append(factory.run())
            except BaseException as failure:
                outcome.append(failure)

        with patch.object(family, 'RpcProcess', DynamicRpcProcess):
            worker = threading.Thread(target=run, daemon=True)
            worker.start()
            self.addCleanup(family.finish_worker, self, worker, case.command_release)
            self.addCleanup(case.command_release.set)
            self.assertTrue(self.wait_for_startup(case.command_prepared, worker, outcome))
            with patch.object(os, 'write', denied):
                case.command_release.set()
                worker.join(12)
        self.assertEqual(len(outcome), 1)
        gate = factory.server.finite_input
        self.assertEqual(gate.lifecycle.phase, 'fault')
        self.assertEqual(gate.output_bytes_seen, 0)
        self.assertFalse(any(reply.get('result', {}).get('success') is True
                             for reply in self.fixture.spawned[0].replies))
        self.assertTrue(self.fixture.spawned[1].process.alive is False)
        with self.assertRaises(BlockingIOError):
            os.read(case.tool_read, 1)
        self.assertEqual(self.fixture.attempt(case)['outcome'], 'unknown')
        self.assertEqual(self.fixture.attempt(case)['charge'],
                         self.fixture.attempt(case)['amount'])

    def test_terminal_before_tool_gate_release_contains_unrun_child(self):
        writes = []
        original_write = os.write

        def counted(fd, data):
            if data == b'1' and len(self.fixture.spawned) > 1:
                writes.append(fd)
            return original_write(fd, data)

        with patch.object(os, 'write', counted):
            factory = self._terminal_during_command('gate')
        self.assertEqual(writes, [], 'revocation-first issued a real child gate byte')
        lifecycle = factory.server.finite_input.lifecycle
        self.assertFalse(any(kind == 'registered-gate'
                             for kind, _binding in lifecycle.authority_commits))
        self.assertFalse(any(reply.get('result', {}).get('success') is True
                             for reply in self.fixture.spawned[0].replies))

    def test_transport_fault_contains_pending_birth_while_tool_record_blocks(self):
        case = self.fixture.case(archive_schedule='concurrent', finite_tool_mode='captured-host-tools')
        case.command_prepared, case.command_release = threading.Event(), threading.Event()
        factory = self.fixture.factory(case)
        entered, release, result = threading.Event(), threading.Event(), []
        original_record = factory.record

        def blocked_record(name, observation):
            if name == 'tool-contained':
                entered.set()
                release.wait(10)
            return original_record(name, observation)

        def run():
            try:
                result.append(factory.run())
            except BaseException as failure:
                result.append(failure)

        self.addCleanup(release.set)
        self.addCleanup(case.command_release.set)
        with patch.object(family, 'RpcProcess', DynamicRpcProcess):
            worker = threading.Thread(target=run, daemon=True)
            worker.start()
            self.addCleanup(family.finish_worker, self, worker, case.command_release, release)
            self.assertTrue(self.wait_for_startup(case.command_prepared, worker, result))
            with patch.object(factory, 'record', blocked_record):
                case.command_release.set()
                self.assertTrue(entered.wait(10))
                gate = factory.server.finite_input
                pending = gate.pending_lifetime
                self.assertIsNotNone(pending)
                self.assertIsNone(factory.server.finite_tools.lifetime)
                self.assertEqual(gate.cleanup_phase(), 'owned-active')
                factory.server._fail_transport(RuntimeError('EXAMPLE fault during tool record'))
                until = time.monotonic() + 8
                while gate.cleanup_phase() != 'contained' and time.monotonic() < until:
                    time.sleep(.005)
                self.assertEqual(gate.cleanup_phase(), 'contained')
                self.assertFalse(pending.process.process.alive)
                self.assertFalse(release.is_set(), 'cleanup must finish while record remains blocked')
                release.set()
                worker.join(12)
        self.assertEqual(len(result), 1)
        self.assertIsInstance(result[0], BaseException)
        self.assertFalse(any(reply.get('result', {}).get('success') is True
                             for reply in self.fixture.spawned[0].replies))
        attempt = self.fixture.attempt(case)
        self.assertEqual(attempt['outcome'], 'unknown')
        self.assertEqual(attempt['charge'], attempt['amount'])

    def test_pending_birth_launch_observer_timeout_survives_owner_completion(self):
        case = self.fixture.case(archive_schedule='concurrent', finite_tool_mode='captured-host-tools')
        case.command_prepared, case.command_release = threading.Event(), threading.Event()
        factory = self.fixture.factory(case)
        record_entered, release_record = threading.Event(), threading.Event()
        owner_entered, release_owner = threading.Event(), threading.Event()
        observer_entered = threading.Event()
        result, calls = [], []
        primary = RuntimeError('EXAMPLE pending-birth transport fault')
        original_record = factory.record

        def blocked_record(name, observation):
            if name == 'tool-contained':
                record_entered.set()
                if not release_record.wait(12):
                    raise AssertionError('EXAMPLE pending record release missing')
            return original_record(name, observation)

        def run():
            try:
                result.append(factory.run())
            except BaseException as failure:
                result.append(failure)

        self.addCleanup(release_record.set)
        self.addCleanup(release_owner.set)
        self.addCleanup(case.command_release.set)
        with patch.object(family, 'RpcProcess', DynamicRpcProcess):
            worker = threading.Thread(target=run, daemon=True)
            worker.start()
            self.addCleanup(family.finish_worker, self, worker, case.command_release, release_record, release_owner)
            self.assertTrue(self.wait_for_startup(case.command_prepared, worker, result))
            with patch.object(factory, 'record', blocked_record):
                case.command_release.set()
                self.assertTrue(record_entered.wait(10))
                gate = factory.server.finite_input
                pending = gate.pending_lifetime
                self.assertIsNotNone(pending)
                original_effect = pending.controller.terminate
                original_wait = pending._termination_finished.wait

                def paused_effect(*args, **kwargs):
                    calls.append(1)
                    owner_entered.set()
                    if not release_owner.wait(12):
                        raise AssertionError('EXAMPLE pending owner release missing')
                    return original_effect(*args, **kwargs)

                def failed_observation(timeout=None):
                    if timeout == 10 and not observer_entered.is_set():
                        observer_entered.set()
                        release_owner.set()
                        self.assertTrue(original_wait(8))
                        return False
                    return original_wait(timeout)

                with patch.object(pending.controller, 'terminate', paused_effect), patch.object(
                        pending._termination_finished, 'wait', failed_observation):
                    factory.server._fail_transport(primary)
                    self.assertTrue(owner_entered.wait(5))
                    self.assertEqual(gate.cleanup_phase(), 'cleanup-pending')
                    release_record.set()
                    self.assertTrue(observer_entered.wait(8))
                    worker.join(12)
        self.assertFalse(worker.is_alive())
        self.assertEqual(len(result), 1)
        self.assertIsInstance(result[0], BaseException)
        self.assertEqual(calls, [1])
        self.assertTrue(pending.contained)
        self.assertTrue(pending.termination_recorded)
        self.assertEqual(gate.cleanup_phase(), 'unknown')
        self.assertTrue(gate.cleanup_unresolved)
        self.assertIn('timeout', [item.kind for item in gate.cleanup_observations])
        self.assertIs(factory.server.transport_failure, primary)
        self.assertFalse(any(reply.get('result', {}).get('success') is True
                             for reply in self.fixture.spawned[0].replies))
        self.assertEqual(gate.output_bytes_seen, 0)
        with self.assertRaises(BlockingIOError):
            os.read(case.tool_read, 1)
        attempt = self.fixture.attempt(case)
        self.assertEqual(attempt['outcome'], 'unknown')
        self.assertEqual(attempt['charge'], attempt['amount'])

    def test_expired_queued_command_refuses_before_owned_tool_effect(self):
        case = self.fixture.case(finite_tool_mode='captured-host-tools', short_command_deadline=True)
        case.command_prepared, case.command_release = threading.Event(), threading.Event()
        factory = self.fixture.factory(case)
        result = []
        def run():
            try:
                result.append(factory.run())
            except BaseException as failure:
                result.append(failure)
        original = factory.record
        def delayed(stage, observation):
            value = original(stage, observation)
            if stage == 'finite-tool-command-intent':
                time.sleep(.1)
            return value
        with patch.object(family, 'RpcProcess', DynamicRpcProcess):
            thread = threading.Thread(target=run, daemon=True)
            thread.start()
            self.addCleanup(family.finish_worker, self, thread, case.command_release)
            self.addCleanup(case.command_release.set)
            self.assertTrue(self.wait_for_startup(case.command_prepared, thread, result))
            with patch.object(factory, 'record', delayed):
                case.command_release.set()
                thread.join(15)
        self.assertEqual(len(result), 1)
        self.assertIsInstance(result[0], BaseException)
        self.assertEqual(len(self.fixture.spawned), 1)
        attempt = self.fixture.attempt(case)
        self.assertEqual(attempt['outcome'], 'unknown')
        self.assertEqual(attempt['charge'], attempt['amount'])

    def test_bounded_dynamic_queue_faults_while_decision_blocks_reader_free(self):
        case = self.fixture.case(finite_tool_mode='captured-host-tools', flood_tool_queue=True)
        case.command_prepared, case.command_release = threading.Event(), threading.Event()
        factory = self.fixture.factory(case)
        entered, release = threading.Event(), threading.Event()
        case.flood_ready = entered
        result = []
        original = factory.record
        def blocked(stage, observation):
            if stage == 'finite-tool-decision' and observation.get('tool') == 'finite_command':
                entered.set()
                release.wait(5)
            return original(stage, observation)
        def run():
            try:
                result.append(factory.run())
            except BaseException as failure:
                result.append(failure)
        with patch.object(family, 'RpcProcess', DynamicRpcProcess):
            thread = threading.Thread(target=run, daemon=True)
            thread.start()
            self.addCleanup(family.finish_worker, self, thread, case.command_release, release)
            self.addCleanup(case.command_release.set)
            self.addCleanup(release.set)
            self.assertTrue(self.wait_for_startup(case.command_prepared, thread, result))
            with patch.object(factory, 'record', blocked):
                case.command_release.set()
                self.assertTrue(entered.wait(5))
                deadline = time.monotonic() + 3
                while factory.server.transport_failure is None:
                    self.assertLess(time.monotonic(), deadline, 'reader blocked behind tool decision')
                    time.sleep(.01)
                release.set()
                thread.join(12)
        self.assertEqual(len(result), 1)
        self.assertIsInstance(result[0], BaseException)
        self.assertEqual(len(self.fixture.spawned), 1)
        attempt = self.fixture.attempt(case)
        self.assertEqual(attempt['outcome'], 'unknown')
        self.assertEqual(attempt['charge'], attempt['amount'])

    def test_capture_changed_after_registration_refuses_before_command(self):
        case = self.fixture.case(finite_tool_mode='captured-host-tools')
        case.command_prepared, case.command_release = threading.Event(), threading.Event()
        factory = self.fixture.factory(case)
        result = []
        def run():
            try:
                result.append(factory.run())
            except BaseException as failure:
                result.append(failure)
        with patch.object(family, 'RpcProcess', DynamicRpcProcess):
            thread = threading.Thread(target=run, daemon=True)
            thread.start()
            self.addCleanup(family.finish_worker, self, thread, case.command_release)
            self.addCleanup(case.command_release.set)
            self.assertTrue(self.wait_for_startup(case.command_prepared, thread, result))
            path = case.home / 'finite-tool-capture.json'
            capture = json.loads(path.read_text())
            capture['request']['tools'].append({'name': 'write_stdin'})
            path.write_text(json.dumps(capture))
            case.command_release.set()
            thread.join(10)
        self.assertEqual(len(result), 1)
        self.assertIsInstance(result[0], BaseException)
        self.assertEqual(len(self.fixture.spawned), 1)
        attempt = self.fixture.attempt(case)
        self.assertEqual(attempt['outcome'], 'unknown')
        self.assertEqual(attempt['charge'], attempt['amount'])

    def test_capture_changed_during_decision_refuses_before_tool_launch(self):
        case = self.fixture.case(finite_tool_mode='captured-host-tools')
        case.command_prepared, case.command_release = threading.Event(), threading.Event()
        factory = self.fixture.factory(case)
        result = []
        def run():
            try:
                result.append(factory.run())
            except BaseException as failure:
                result.append(failure)
        with patch.object(family, 'RpcProcess', DynamicRpcProcess):
            thread = threading.Thread(target=run, daemon=True)
            thread.start()
            self.addCleanup(family.finish_worker, self, thread, case.command_release)
            self.addCleanup(case.command_release.set)
            self.assertTrue(self.wait_for_startup(case.command_prepared, thread, result))
            entered, release = threading.Event(), threading.Event()
            self.addCleanup(release.set)
            original = factory.record
            def blocked(stage, observation):
                value = original(stage, observation)
                if stage == 'finite-tool-decision' and observation.get('tool') == 'finite_command':
                    entered.set()
                    release.wait(5)
                return value
            with patch.object(factory, 'record', blocked):
                case.command_release.set()
                self.assertTrue(entered.wait(5))
                path = case.home / 'finite-tool-capture.json'
                capture = json.loads(path.read_text())
                capture['request']['tools'].append({'name': 'write_stdin'})
                path.write_text(json.dumps(capture))
                release.set()
                thread.join(10)
        self.assertEqual(len(result), 1)
        self.assertIsInstance(result[0], BaseException)
        self.assertEqual(len(self.fixture.spawned), 1)
        attempt = self.fixture.attempt(case)
        self.assertEqual(attempt['outcome'], 'unknown')
        self.assertEqual(attempt['charge'], attempt['amount'])

    def test_capture_changed_after_command_output_refuses_before_reply(self):
        case = self.fixture.case(finite_tool_mode='captured-host-tools')
        factory = self.fixture.factory(case)
        original = family.runtime._RegisteredServer._commit_tool_reply
        def change_before_reply(server, message, response, deadline, *, refusal=False):
            if message['id'] == 'EXAMPLE-request-EXAMPLE-command-call' and not refusal:
                path = case.home / 'finite-tool-capture.json'
                capture = json.loads(path.read_text())
                capture['request']['tools'].append({'name': 'write_stdin'})
                path.write_text(json.dumps(capture))
            return original(server, message, response, deadline, refusal=refusal)
        with patch.object(family, 'RpcProcess', DynamicRpcProcess), patch.object(
                family.runtime._RegisteredServer, '_commit_tool_reply', change_before_reply), \
                self.assertRaises(ValueError):
            factory.run()
        self.assertEqual(len(self.fixture.spawned), 2)
        self.assertEqual(len(self.fixture.spawned[0].replies), 1)
        self.assertIn('error', self.fixture.spawned[0].replies[0])
        self.assertTrue(self.fixture.spawned[1].process.alive is False)
        attempt = self.fixture.attempt(case)
        self.assertEqual(attempt['outcome'], 'unknown')
        self.assertEqual(attempt['charge'], attempt['amount'])

    def test_factory_authority_drift_before_reply_observation_refuses(self):
        case = self.fixture.case(finite_tool_mode='captured-host-tools')
        factory = self.fixture.factory(case)
        original = gate_module.RegisteredFiniteInput.issue_reply_observation
        changed = []

        def issue(gate, producer, message, response, deadline, frame, refusal):
            if (not changed and not refusal
                    and message.get('params', {}).get('tool') == 'finite_command'):
                factory.policy_bytes = b'EXAMPLE changed policy bytes'
                changed.append(True)
            return original(gate, producer, message, response, deadline, frame, refusal)

        with patch.object(family, 'RpcProcess', DynamicRpcProcess), patch.object(
                gate_module.RegisteredFiniteInput, 'issue_reply_observation', issue), \
                self.assertRaises(ValueError):
            factory.run()
        self.assertEqual(changed, [True])
        self.assertFalse(any(reply.get('result', {}).get('success') is True
                             for reply in self.fixture.spawned[0].replies))
        attempt = self.fixture.attempt(case)
        self.assertEqual(attempt['outcome'], 'unknown')
        self.assertEqual(attempt['charge'], attempt['amount'])

    def test_capture_drift_while_writer_waits_refuses_final_reply(self):
        case = self.fixture.case(finite_tool_mode='captured-host-tools')
        case.command_prepared, case.command_release = threading.Event(), threading.Event()
        factory = self.fixture.factory(case)
        ticket_issued = threading.Event()
        result = []
        original = gate_module.RegisteredFiniteInput.issue_reply_observation
        def observed(gate, producer, message, response, deadline, frame, refusal):
            ticket = original(gate, producer, message, response, deadline, frame, refusal)
            if (ticket is not None and not refusal
                    and message['id'] == 'EXAMPLE-request-EXAMPLE-command-call'):
                ticket_issued.set()
            return ticket
        def run():
            try:
                result.append(factory.run())
            except BaseException as failure:
                result.append(failure)
        with patch.object(family, 'RpcProcess', DynamicRpcProcess), patch.object(
                gate_module.RegisteredFiniteInput, 'issue_reply_observation', observed):
            thread = threading.Thread(target=run, daemon=True)
            thread.start()
            self.addCleanup(family.finish_worker, self, thread, case.command_release)
            self.addCleanup(case.command_release.set)
            self.assertTrue(self.wait_for_startup(case.command_prepared, thread, result))
            writer = factory.server.process.stdin._lock
            self.assertTrue(writer.acquire(timeout=2))
            try:
                case.command_release.set()
                self.assertTrue(ticket_issued.wait(10))
                path = case.home / 'finite-tool-capture.json'
                capture = json.loads(path.read_text())
                capture['request']['tools'].append({'name': 'write_stdin'})
                path.write_text(json.dumps(capture))
            finally:
                writer.release()
            thread.join(12)
        self.assertEqual(len(result), 1)
        self.assertIsInstance(result[0], BaseException)
        self.assertEqual(len(self.fixture.spawned[0].replies), 1)
        self.assertIn('error', self.fixture.spawned[0].replies[0])
        attempt = self.fixture.attempt(case)
        self.assertEqual(attempt['outcome'], 'unknown')
        self.assertEqual(attempt['charge'], attempt['amount'])


    def _terminal_wait_schedule(self, method, *, before_wait):
        case = self.fixture.case(finite_tool_mode='captured-host-tools',
                                 materialize_on_turn_start=True)
        case.command_prepared, case.command_release = threading.Event(), threading.Event()
        factory = self.fixture.factory(case)
        outcome = []
        def run():
            try:
                outcome.append(factory.run())
            except BaseException as failure:
                outcome.append(failure)
        with patch.object(family, 'RpcProcess', DynamicRpcProcess):
            worker = threading.Thread(target=run, daemon=True)
            worker.start()
            self.addCleanup(family.finish_worker, self, worker, case.command_release)
            self.addCleanup(case.command_release.set)
            self.assertTrue(self.wait_for_startup(case.command_prepared, worker, outcome))
            server = factory.server
            lifecycle = server.finite_input.lifecycle
            end = time.monotonic() + 3
            while lifecycle.phase != 'await-command':
                self.assertLess(time.monotonic(), end)
                time.sleep(.001)
            observed = threading.Event()
            result = []
            original_wait = lifecycle.condition.wait
            def wait(timeout=None):
                observed.set()
                return original_wait(timeout)
            def host_wait():
                try:
                    result.append(server.await_finite_progress(
                        host_deadline=time.monotonic() + 3))
                except BaseException as failure:
                    result.append(failure)
            with patch.object(lifecycle.condition, 'wait', wait):
                waiter = None
                if not before_wait:
                    waiter = threading.Thread(target=host_wait, daemon=True)
                    waiter.start()
                    self.assertTrue(observed.wait(2))
                params = {'threadId': case.scenario.thread_id}
                if method.startswith('turn/'):
                    params['turn'] = {'id': case.scenario.turn_id,
                                      'status': method.split('/')[1]}
                self.fixture.spawned[0].stdout.put({'method': method, 'params': params})
                end = time.monotonic() + 2
                while lifecycle.phase != 'terminal':
                    self.assertLess(time.monotonic(), end, method)
                    time.sleep(.001)
                if before_wait:
                    host_wait()
                else:
                    waiter.join(2)
                    self.assertFalse(waiter.is_alive(), method)
            self.assertEqual(result, [None], method)
            self.assertEqual(lifecycle.phase, 'terminal')
            case.command_release.set()
            worker.join(12)
        self.assertEqual(len(outcome), 1)
        self.assertNotIn(lifecycle.phase, lifecycle.WAITING)
        self.assertFalse(any(reply.get('result', {}).get('success') is True
                             for reply in self.fixture.spawned[0].replies))
        self.assertEqual(self.fixture.attempt(case)['outcome'], 'unknown')
        self.assertEqual(self.fixture.attempt(case)['charge'],
                         self.fixture.attempt(case)['amount'])

    def test_all_original_terminal_notifications_wake_before_and_during_wait(self):
        for method in ('turn/completed', 'turn/failed', 'turn/interrupted',
                       'thread/closed', 'thread/archived'):
            for before_wait in (True, False):
                with self.subTest(method=method, before_wait=before_wait):
                    fixture = RegisteredFiniteToolWiringTests(methodName='runTest')
                    fixture.setUp()
                    try:
                        fixture._terminal_wait_schedule(method, before_wait=before_wait)
                    finally:
                        family.cleanup_helper(self, fixture)


    def _terminal_projection_schedule(self, *, before_wait):
        # This test owns the driver/read ordering; the generic fake scheduler
        # waits for a command completion that this no-command case never emits.
        case = self.fixture.case(archive_schedule='concurrent', finite_tool_mode='captured-host-tools',
                                 materialize_on_turn_start=True, no_fake_scheduler=True)
        case.command_prepared, case.command_release = threading.Event(), threading.Event()
        factory = self.fixture.factory(case)
        outcome, observed, result = [], threading.Event(), []
        driver_parked, driver_release = threading.Event(), threading.Event()
        self.addCleanup(driver_release.set)
        original_result = DynamicRpcProcess.result
        def projection(process, method, params):
            response = original_result(process, method, params)
            if method == 'thread/read' and getattr(case, 'terminal_projection', False):
                response['thread']['turns'] = [{
                    'id': case.scenario.turn_id, 'status': 'completed', 'items': []}]
            return response
        def no_command_until_projection(process):
            case.command_prepared.set()
            self.assertTrue(case.command_release.wait(5),
                            'EXAMPLE projection producer release missing')
        def run():
            try:
                outcome.append(factory.run())
            except BaseException as failure:
                outcome.append(failure)
        original_progress = family.runtime._RegisteredServer.await_finite_progress
        def held_progress(server, *args, **kwargs):
            if server is factory.server and threading.current_thread() is worker:
                driver_parked.set()
                self.assertTrue(driver_release.wait(5),
                                'EXAMPLE projection driver release missing')
            return original_progress(server, *args, **kwargs)
        with patch.object(family, 'RpcProcess', DynamicRpcProcess), patch.object(
                DynamicRpcProcess, 'result', projection), patch.object(
                DynamicRpcProcess, 'approve', no_command_until_projection), patch.object(
                family.runtime._RegisteredServer, 'await_finite_progress', held_progress):
            worker = threading.Thread(target=run, daemon=True)
            worker.start()
            self.addCleanup(family.finish_worker, self, worker, case.command_release, driver_release)
            self.addCleanup(case.command_release.set)
            self.assertTrue(self.wait_for_startup(case.command_prepared, worker, outcome))
            case.command_release.set()
            server = factory.server
            lifecycle = server.finite_input.lifecycle
            self.assertTrue(driver_parked.wait(3),
                            'EXAMPLE projection driver must park before the terminal read')
            self.assertEqual(lifecycle.phase, 'await-command')
            self.assertIsNone(server.transport_failure)
            self.assertEqual(outcome, [])
            original_wait = lifecycle.condition.wait
            def wait(timeout=None):
                observed.set()
                return original_wait(timeout)
            def host_wait():
                try:
                    result.append(server.await_finite_progress(
                        host_deadline=time.monotonic() + 3))
                except BaseException as failure:
                    result.append(failure)
            with patch.object(lifecycle.condition, 'wait', wait):
                waiter = None
                if not before_wait:
                    waiter = threading.Thread(target=host_wait, daemon=True)
                    waiter.start()
                    self.assertTrue(observed.wait(2))
                case.terminal_projection = True
                case.command_release.set()
                server.request('thread/read', {'threadId': case.scenario.thread_id}, timeout=3)
                end = time.monotonic() + 2
                while lifecycle.phase != 'terminal':
                    self.assertLess(time.monotonic(), end)
                    time.sleep(.001)
                if before_wait:
                    host_wait()
                else:
                    waiter.join(2)
                    self.assertFalse(waiter.is_alive())
            self.assertEqual(result, [None])
            case.command_release.set()
            driver_release.set()
            worker.join(12)
        self.assertEqual(len(outcome), 1)
        attempt = self.fixture.attempt(case)
        self.assertEqual(attempt['outcome'], 'unknown')
        self.assertEqual(attempt['charge'], attempt['amount'])

    def test_original_read_projection_wakes_before_and_during_wait(self):
        for before_wait in (True, False):
            with self.subTest(before_wait=before_wait):
                fixture = RegisteredFiniteToolWiringTests(methodName='runTest')
                fixture.setUp()
                try:
                    fixture._terminal_projection_schedule(before_wait=before_wait)
                finally:
                    family.cleanup_helper(self, fixture)


    def _split_original_publication_schedule(self, route, before_wait):
        """Pause the real protocol write while its reducer publication is pending."""
        case = self.fixture.case(archive_schedule='concurrent', finite_tool_mode='captured-host-tools',
                                 materialize_on_turn_start=True)
        case.command_prepared, case.command_release = threading.Event(), threading.Event()
        factory = self.fixture.factory(case)
        outcome, waiting, entered, release = [], [], threading.Event(), threading.Event()
        driver_release = threading.Event()
        self.addCleanup(driver_release.set)
        self.addCleanup(release.set)
        self.addCleanup(case.command_release.set)

        def run():
            try:
                outcome.append(factory.run())
            except BaseException as failure:
                outcome.append(failure)

        original_result = DynamicRpcProcess.result
        def projected(process, method, params):
            response = original_result(process, method, params)
            if method == 'thread/read' and getattr(case, 'terminal_projection', False):
                response['thread']['turns'] = [{
                    'id': case.scenario.turn_id, 'status': 'completed', 'items': []}]
            elif method == 'thread/read' and route == 'trusted':
                response['thread']['turns'] = [{
                    'id': case.scenario.turn_id, 'status': 'inProgress', 'items': []}]
            return response

        def no_command(process):
            case.command_prepared.set()

        original_progress = family.runtime._RegisteredServer.await_finite_progress
        def held_progress(server, *args, **kwargs):
            if server is factory.server and threading.current_thread() is worker:
                driver_release.wait(5)
            return original_progress(server, *args, **kwargs)

        with patch.object(family, 'RpcProcess', DynamicRpcProcess), patch.object(
                DynamicRpcProcess, 'result', projected), patch.object(
                DynamicRpcProcess, 'approve', no_command), patch.object(
                family.runtime._RegisteredServer, 'await_finite_progress', held_progress):
            worker = threading.Thread(target=run, daemon=True)
            worker.start()
            self.addCleanup(family.finish_worker, self, worker, case.command_release, release, driver_release)
            self.assertTrue(self.wait_for_startup(case.command_prepared, worker, outcome))
            server = factory.server
            lifecycle = server.finite_input.lifecycle
            end = time.monotonic() + 3
            while lifecycle.phase != 'await-command':
                self.assertLess(time.monotonic(), end)
                time.sleep(.001)
            original_publish = server.requests._publish_progress
            turn = case.scenario.thread_id, case.scenario.turn_id

            def split():
                negative = (turn in server.requests.terminals
                            or turn in server.requests.trusted_terminals
                            or turn == server.requests.cancelled_turn
                            or server.requests.closed)
                if negative and not entered.is_set():
                    entered.set()
                    release.wait(3)
                return original_publish()

            def host_wait():
                try:
                    waiting.append(server.await_finite_progress())
                except BaseException as failure:
                    waiting.append(failure)

            with patch.object(server.requests, '_publish_progress', split):
                waiter = None
                if not before_wait:
                    waiter = threading.Thread(target=host_wait, daemon=True)
                    waiter.start()
                    self.addCleanup(waiter.join, 3)
                    time.sleep(.02)
                action = None
                if route.startswith('turn/') or route.startswith('thread/'):
                    params = {'threadId': turn[0]}
                    if route.startswith('turn/'):
                        params['turn'] = {'id': turn[1], 'status': route.split('/')[1]}
                    self.fixture.spawned[0].stdout.put({'method': route, 'params': params})
                elif route == 'projection':
                    case.terminal_projection = True
                    action = threading.Thread(target=lambda: server.request(
                        'thread/read', {'threadId': turn[0]}, timeout=3), daemon=True)
                    action.start()
                elif route == 'trusted':
                    self.fixture.spawned[0].complete()
                elif route == 'cancel':
                    action = threading.Thread(target=lambda: server.interrupt_turn(
                        *turn, timeout=3), daemon=True)
                    action.start()
                elif route == 'fault':
                    action = threading.Thread(target=lambda: server._fail_transport(
                        ValueError('EXAMPLE split original fault')), daemon=True)
                    action.start()
                elif route == 'close':
                    action = threading.Thread(target=server.close, daemon=True)
                    action.start()
                else:
                    self.fail('Unlisted original publication route')
                self.assertTrue(entered.wait(3), route)
                if route == 'fault':
                    self.assertEqual(lifecycle.phase, 'fault')
                else:
                    self.assertNotIn(lifecycle.phase, lifecycle.TERMINAL)
                with lifecycle.condition:
                    lifecycle.edge_deadline = time.monotonic() + .05
                    lifecycle.condition.notify_all()
                if before_wait:
                    waiter = threading.Thread(target=host_wait, daemon=True)
                    waiter.start()
                    self.addCleanup(waiter.join, 3)
                time.sleep(.12)
                if route == 'fault':
                    self.assertEqual(len(waiting), 1, route)
                    self.assertIsInstance(waiting[0], family.runtime.AppServerError)
                else:
                    self.assertEqual(waiting, [], route)
                release.set()
                driver_release.set()
                waiter.join(3)
                self.assertFalse(waiter.is_alive(), route)
                if action is not None:
                    action.join(3)
            case.command_release.set()
            driver_release.set()
            worker.join(12)
        self.assertEqual(len(outcome), 1, route)
        self.assertNotEqual(str(waiting[0]), 'registered-finite-progress-deadline')
        self.assertNotIn(lifecycle.phase, lifecycle.WAITING)
        self.assertEqual(sum(bool(getattr(child, 'is_tool', False)) for child in self.fixture.spawned), 0)
        self.assertEqual(server.finite_input.cleanup_phase(), 'unselected')
        self.assertFalse(any(reply.get('result', {}).get('success') is True
                             for reply in self.fixture.spawned[0].replies))
        records = [json.loads(path.read_text()) for path in
                   (factory.records / 'transport-observations').iterdir()]
        self.assertFalse(any(row['stage'] in {
            'finite-tool-command-intent', 'finite-poll-intent'}
            for row in records))
        attempt = self.fixture.attempt(case)
        self.assertEqual(attempt['outcome'], 'unknown')
        self.assertEqual(attempt['charge'], attempt['amount'])
        self.assertIsInstance(outcome[0], BaseException)

    def test_original_split_terminal_publication_before_and_during_wait(self):
        routes = ('turn/completed', 'turn/failed', 'turn/interrupted',
                  'thread/closed', 'thread/archived', 'projection',
                  'cancel', 'fault', 'close')
        for route in routes:
            for before_wait in (True, False):
                with self.subTest(route=route, before_wait=before_wait):
                    fixture = RegisteredFiniteToolWiringTests(methodName='runTest')
                    fixture.setUp()
                    try:
                        fixture._split_original_publication_schedule(route, before_wait)
                    finally:
                        family.cleanup_helper(self, fixture)

    def test_original_trusted_terminal_split_publication(self):
        for before_wait in (True, False):
            with self.subTest(before_wait=before_wait):
                fixture = RegisteredFiniteToolWiringTests(methodName='runTest')
                fixture.setUp()
                try:
                    fixture._split_original_publication_schedule('trusted', before_wait)
                finally:
                    family.cleanup_helper(self, fixture)

    def _split_reply_publication_schedule(self, tool, stage, *, exceptional=False):
        case = self.fixture.case(archive_schedule='concurrent', finite_tool_mode='captured-host-tools',
                                 materialize_on_turn_start=True)
        factory = self.fixture.factory(case)
        entered, stage_release = threading.Event(), threading.Event()
        fact, fact_release = threading.Event(), threading.Event()
        self.addCleanup(stage_release.set)
        self.addCleanup(fact_release.set)
        outcome, reads, issued, committed, phases, errors = [], [], [], [], [], []
        request_id = ('EXAMPLE-request-EXAMPLE-command-call' if tool == 'finite_command'
                      else 'EXAMPLE-request-EXAMPLE-poll-call')
        original_publish = family.runtime._CoherentServerRequests._publish_progress
        original_issue = gate_module.RegisteredFiniteInput.issue_reply_observation
        original_commit = gate_module.RegisteredFiniteInput.commit_reply_observation
        original_read = os.read

        def publish(requests):
            turn = case.scenario.thread_id, case.scenario.turn_id
            if requests.server is factory.server and turn in requests.terminals and not fact.is_set():
                fact.set()
                fact_release.wait(3)
            result = original_publish(requests)
            if fact.is_set() and not phases:
                phases.append(requests.server.finite_input.lifecycle.phase)
            return result

        def issue(gate, producer, message, response, deadline, frame, refusal):
            if (stage == 'issue' and not entered.is_set() and not refusal
                    and message.get('params', {}).get('tool') == tool
                    and response.get('result', {}).get('success') is True):
                entered.set()
                stage_release.wait(3)
            ticket = original_issue(gate, producer, message, response, deadline, frame, refusal)
            if (stage == 'issue' and entered.is_set()
                    and message.get('params', {}).get('tool') == tool
                    and response.get('result', {}).get('success') is True):
                issued.append(ticket)
            return ticket

        def commit(gate, ticket, producer, message, response, deadline,
                   frame, writer, refusal):
            if (stage == 'commit' and not entered.is_set() and not refusal
                    and message.get('params', {}).get('tool') == tool
                    and response.get('result', {}).get('success') is True):
                committed.append(ticket)
                entered.set()
                stage_release.wait(3)
            return original_commit(gate, ticket, producer, message, response,
                                   deadline, frame, writer, refusal)

        def read(descriptor, count):
            data = original_read(descriptor, count)
            if hasattr(case, 'tool_stream'):
                source = os.fstat(case.tool_stream.fileno())
                actual = os.fstat(descriptor)
                if (actual.st_dev, actual.st_ino) == (source.st_dev, source.st_ino):
                    reads.append(data)
            return data

        def run():
            try:
                outcome.append(factory.run())
            except BaseException as failure:
                outcome.append(failure)

        with patch.object(family, 'RpcProcess', DynamicRpcProcess), patch.object(
                family.runtime._CoherentServerRequests, '_publish_progress', publish), patch.object(
                gate_module.RegisteredFiniteInput, 'issue_reply_observation', issue), patch.object(
                gate_module.RegisteredFiniteInput, 'commit_reply_observation', commit), patch.object(
                os, 'read', side_effect=read):
            worker = threading.Thread(target=run, daemon=True)
            worker.start()
            self.addCleanup(family.finish_worker, self, worker, stage_release, fact_release)
            self.assertTrue(self.wait_for_startup(entered, worker, outcome), (tool, stage))
            gate = factory.server.finite_input
            charged_before = gate.output_bytes_seen
            reads_before = list(reads)
            action = None
            if exceptional:
                def project():
                    try:
                        factory.server.requests.observe_response({'result': {'thread': {
                            'id': case.scenario.thread_id, 'turns': [
                                {'id': case.scenario.turn_id, 'status': 'completed', 'items': []},
                                {'id': 'EXAMPLE-unrelated-turn', 'status': 'completed', 'items': []}]}}})
                    except BaseException as failure:
                        errors.append(failure)
                action = threading.Thread(target=project, daemon=True)
                action.start()
                self.addCleanup(action.join, 3)
            else:
                self.fixture.spawned[0].stdout.put({'method': 'turn/completed', 'params': {
                    'threadId': case.scenario.thread_id,
                    'turn': {'id': case.scenario.turn_id, 'status': 'completed'}}})
            self.assertTrue(fact.wait(3), (tool, stage))
            self.assertIn((case.scenario.thread_id, case.scenario.turn_id),
                          factory.server.requests.terminals)
            self.assertNotIn(gate.lifecycle.phase, gate.lifecycle.TERMINAL)
            stage_release.set()
            time.sleep(.05)
            self.assertFalse(any(reply.get('id') == request_id
                                 and reply.get('result', {}).get('success') is True
                                 for reply in self.fixture.spawned[0].replies))
            fact_release.set()
            if action is not None:
                action.join(3)
                self.assertFalse(action.is_alive())
            worker.join(12)
        if exceptional:
            self.assertEqual(len(errors), 1)
            self.assertEqual(str(errors[0]), 'registered-terminal-before-bound-turn')
        self.assertEqual(len(outcome), 1)
        self.assertIsInstance(outcome[0], BaseException)
        self.assertEqual(phases, ['fault' if exceptional else 'terminal'])
        self.assertEqual(reads, reads_before)
        self.assertEqual(gate.output_bytes_seen, charged_before)
        self.assertEqual(charged_before, sum(len(data) for data in reads))
        self.assertTrue(reads)
        self.assertEqual(issued, [])
        if committed:
            self.assertTrue(gate.reply_tickets[committed[0]].used)
        self.assertFalse(any(reply.get('id') == request_id
                             and reply.get('result', {}).get('success') is True
                             for reply in self.fixture.spawned[0].replies))
        with self.assertRaises(BlockingIOError):
            os.read(case.tool_read, 1)
        self.assertTrue(gate.cleanup_attempted)
        self.assertTrue(gate.closed_lifetime.contained)
        records = [json.loads(path.read_text()) for path in
                   (factory.records / 'transport-observations').iterdir()]
        stages = [row['stage'] for row in records]
        self.assertEqual(stages.count('finite-tool-command-intent'), 1)
        self.assertEqual(stages.count('finite-poll-intent'),
                         int(tool == 'finite_poll'))
        attempt = self.fixture.attempt(case)
        self.assertEqual(attempt['outcome'], 'unknown')
        self.assertEqual(attempt['charge'], attempt['amount'])

    def test_original_split_reply_publication_family(self):
        rows = (
            ReplyPublicationRow('test_original_split_reply_issue_and_commit_command_and_poll', False),
            ReplyPublicationRow('test_exceptional_original_projection_fences_command_and_poll_reply', True),
        )
        for row in rows:
            for tool in ('finite_command', 'finite_poll'):
                for stage in ('issue', 'commit'):
                    with self.subTest(original_id=row.original_id, tool=tool, stage=stage):
                        fixture = RegisteredFiniteToolWiringTests(methodName='runTest')
                        fixture.setUp()
                        try:
                            fixture._split_reply_publication_schedule(
                                tool, stage, exceptional=row.exceptional)
                        finally:
                            family.cleanup_helper(self, fixture)

    def test_original_pending_command_deadline_survives_later_poll(self):
        case = self.fixture.case(finite_tool_mode='captured-host-tools',
                                 materialize_on_turn_start=True)
        case.command_prepared, case.command_release = threading.Event(), threading.Event()
        factory = self.fixture.factory(case)
        entered, release, outcome = threading.Event(), threading.Event(), []
        original_record = factory.record
        def blocked_record(stage, observation):
            if stage == 'tool-contained':
                entered.set()
                release.wait(8)
            return original_record(stage, observation)
        def run():
            try:
                outcome.append(factory.run())
            except BaseException as failure:
                outcome.append(failure)
        with patch.object(family, 'RpcProcess', DynamicRpcProcess):
            worker = threading.Thread(target=run, daemon=True)
            worker.start()
            self.addCleanup(family.finish_worker, self, worker, case.command_release, release)
            self.addCleanup(case.command_release.set)
            self.addCleanup(release.set)
            self.assertTrue(self.wait_for_startup(case.command_prepared, worker, outcome))
            with patch.object(factory, 'record', blocked_record):
                case.command_release.set()
                self.assertTrue(entered.wait(8))
                server = factory.server
                lifecycle = server.finite_input.lifecycle
                self.assertEqual(lifecycle.phase, 'pending-birth')
                command_key = family.runtime.protocol._id_key(
                    'EXAMPLE-request-EXAMPLE-command-call')
                command_deadline = lifecycle.pending[command_key][2]
                process = self.fixture.spawned[0]
                process._send_tool('EXAMPLE-late-poll', 'finite_poll',
                                   {'commandCallId': 'EXAMPLE-command-call', 'chars': ''},
                                   case.scenario)
                end = time.monotonic() + 2
                while len(lifecycle.pending) != 2:
                    self.assertLess(time.monotonic(), end)
                    time.sleep(.001)
                poll_key = family.runtime.protocol._id_key(
                    'EXAMPLE-request-EXAMPLE-late-poll')
                self.assertGreater(lifecycle.pending[poll_key][2], command_deadline)
                self.assertEqual(lifecycle.pending[command_key][2], command_deadline)
                lifecycle.clock = lambda: command_deadline + .001
                with self.assertRaises(family.runtime.AppServerError) as caught:
                    server.await_finite_progress()
                self.assertIn('registered-finite-progress-deadline',
                              str(caught.exception))
                server._fail_transport(caught.exception)
                release.set()
                worker.join(12)
        self.assertEqual(len(outcome), 1)
        self.assertIsInstance(outcome[0], BaseException)
        attempt = self.fixture.attempt(case)
        self.assertEqual(attempt['outcome'], 'unknown')
        self.assertEqual(attempt['charge'], attempt['amount'])


    def test_original_reply_near_request_bound_allows_later_completion(self):
        """An injected clock and committed reply fix the bound; release is finite."""
        case = self.fixture.case(archive_schedule='settled', finite_tool_mode='captured-host-tools',
                                 materialize_on_turn_start=True)
        factory = self.fixture.factory(case)
        received, release, outcome = threading.Event(), threading.Event(), []
        committed = threading.Event()
        clock, request_bounds = [time.monotonic()], []
        original_lifecycle_init = gate_module._FiniteLifecycle.__init__
        original_mark = family.runtime._RegisteredServer._mark_command_reply
        original_receive = DynamicRpcProcess.receive
        def lifecycle_init(lifecycle):
            original_lifecycle_init(lifecycle, clock=lambda: clock[0])
        def mark(server, message, response, item):
            command = (message.get('params', {}).get('tool') == 'finite_command'
                       and response.get('result', {}).get('success') is True)
            if command:
                key = family.runtime.protocol._id_key(message['id'])
                deadline = server.finite_input.lifecycle.pending[key][2]
                request_bounds.append(deadline)
                clock[0] = deadline - .001
            result = original_mark(server, message, response, item)
            if command:
                committed.set()
            return result
        def receive(process, message):
            if (not process.is_tool and message.get('id') ==
                    'EXAMPLE-request-EXAMPLE-command-call'
                    and message.get('result', {}).get('success') is True):
                received.set()
                self.assertTrue(release.wait(30), 'Finite reply fixture release timed out')
            return original_receive(process, message)
        def run():
            try:
                outcome.append(factory.run())
            except BaseException as failure:
                outcome.append(failure)
        with patch.object(family, 'RpcProcess', DynamicRpcProcess), patch.object(
                gate_module._FiniteLifecycle, '__init__', lifecycle_init), patch.object(
                family.runtime._RegisteredServer, '_mark_command_reply', mark), patch.object(
                DynamicRpcProcess, 'receive', receive):
            worker = threading.Thread(target=run, daemon=True)
            worker.start()
            self.addCleanup(family.finish_worker, self, worker, release)
            self.addCleanup(release.set)
            self.assertTrue(self.wait_for_startup(received, worker, outcome))
            self.assertTrue(committed.wait(10))
            server = factory.server
            lifecycle = server.finite_input.lifecycle
            self.assertEqual(lifecycle.phase, 'command-replied')
            key = family.runtime.protocol._id_key(
                'EXAMPLE-request-EXAMPLE-command-call')
            # The committed wire reply has retired its intake deadline.
            self.assertNotIn(key, lifecycle.pending)
            self.assertEqual(len(request_bounds), 1)
            old_bound = request_bounds[0]
            self.assertLess(clock[0], old_bound)
            clock[0] = old_bound + .001
            self.assertGreater(clock[0], old_bound)
            server.await_finite_progress(host_deadline=clock[0])
            self.assertEqual(lifecycle.phase, 'command-replied')
            release.set()
            worker.join(12)
        self.assertEqual(len(outcome), 1)
        self.assertIsInstance(outcome[0], dict)
        self.assertEqual(outcome[0]['attempt']['outcome'], 'completed')


    def test_two_prequeued_polls_and_later_poll_have_no_postrefusal_effect(self):
        """Prior 7e2 finding: count intents, physical reads and replies, not only stdin."""
        case = self.fixture.case(finite_tool_mode='captured-host-tools',
                                 poll_chars='EXAMPLE nonempty', complete_after_refusal=False,
                                 materialize_on_turn_start=True)
        case.poll_prepared, case.poll_release = threading.Event(), threading.Event()
        factory = self.fixture.factory(case)
        decision_entered, release_decision = threading.Event(), threading.Event()
        refusal_seen, release_refusal = threading.Event(), threading.Event()
        result, physical_reads = [], []
        original_record = factory.record
        original_receive = DynamicRpcProcess.receive
        original_read = os.read

        def record(stage, observation):
            if (stage == 'finite-tool-decision' and observation.get('tool') == 'finite_poll'
                    and observation.get('call') == 'EXAMPLE-poll-call'):
                decision_entered.set()
                release_decision.wait(5)
            return original_record(stage, observation)

        def receive(process, message):
            if (not process.is_tool and message.get('id') ==
                    'EXAMPLE-request-EXAMPLE-poll-call'
                    and message.get('result', {}).get('success') is False):
                refusal_seen.set()
                release_refusal.wait(5)
            return original_receive(process, message)

        def read(fd, count):
            server = factory.server
            gate = None if server is None else server.finite_input
            if gate is not None and gate.output_stat is not None:
                try:
                    if gate._pipe_stat(fd) == gate.output_stat:
                        physical_reads.append(count)
                except (OSError, ValueError, gate_module.FiniteInputError):
                    pass
            return original_read(fd, count)

        def run():
            try:
                result.append(factory.run())
            except BaseException as failure:
                result.append(failure)

        def received(call):
            key = family.runtime.protocol._id_key('EXAMPLE-request-' + call)
            return key in factory.server._request_ids

        with patch.object(family, 'RpcProcess', DynamicRpcProcess), patch.object(
                DynamicRpcProcess, 'receive', receive):
            worker = threading.Thread(target=run, daemon=True)
            worker.start()
            self.addCleanup(family.finish_worker, self, worker, case.poll_release, release_decision, release_refusal)
            self.addCleanup(release_refusal.set)
            self.addCleanup(release_decision.set)
            try:
                self.assertTrue(self.wait_for_startup(case.poll_prepared, worker, result))
                with patch.object(factory, 'record', record):
                    case.poll_release.set()
                    self.assertTrue(decision_entered.wait(5))
                    gate = factory.server.finite_input
                    read_patcher = patch.object(os, 'read', read)
                    read_patcher.start()
                    before_bytes, before_reads = gate.output_bytes_seen, len(physical_reads)
                    self.fixture.spawned[0]._send_tool('EXAMPLE-second-poll', 'finite_poll',
                        {'commandCallId': 'EXAMPLE-command-call', 'chars': ''}, case.scenario)
                    end = time.monotonic() + 3
                    while not received('EXAMPLE-second-poll'):
                        self.assertLess(time.monotonic(), end)
                        time.sleep(.001)
                    self.assertEqual(len(gate.lifecycle.pending), 2)
                    release_decision.set()
                    self.assertTrue(refusal_seen.wait(5))
                    self.assertEqual(gate.lifecycle.phase, 'refused')
                    self.fixture.spawned[0]._send_tool('EXAMPLE-third-poll', 'finite_poll',
                        {'commandCallId': 'EXAMPLE-command-call', 'chars': ''}, case.scenario)
                    end = time.monotonic() + 3
                    while not received('EXAMPLE-third-poll'):
                        self.assertLess(time.monotonic(), end)
                        time.sleep(.001)
            finally:
                case.poll_release.set()
                release_decision.set()
                release_refusal.set()
                worker.join(12)
                if 'read_patcher' in locals():
                    read_patcher.stop()
        self.assertEqual(len(result), 1)
        stages = [json.loads(path.read_bytes())['stage'] for path in
                  (factory.records / 'transport-observations').iterdir()]
        self.assertEqual(stages.count('finite-poll-intent'), 0)
        self.assertEqual(stages.count('finite-poll-intent-aborted'), 0)
        self.assertEqual(len(physical_reads), before_reads)
        self.assertEqual(gate.output_bytes_seen, before_bytes)
        successes = {reply['id']: reply['result']['success'] for reply in
                     self.fixture.spawned[0].replies if 'result' in reply
                     and 'success' in reply['result']}
        self.assertEqual(successes, {
            'EXAMPLE-request-EXAMPLE-command-call': True,
            'EXAMPLE-request-EXAMPLE-poll-call': False,
            'EXAMPLE-request-EXAMPLE-second-poll': False,
            'EXAMPLE-request-EXAMPLE-third-poll': False})
        with self.assertRaises(BlockingIOError):
            os.read(case.tool_read, 1)
        self.assertIsInstance(result[0], BaseException)
        self.assertEqual(self.fixture.attempt(case)['outcome'], 'unknown')
        self.assertEqual(self.fixture.attempt(case)['charge'],
                         self.fixture.attempt(case)['amount'])

    def test_original_late_request_cannot_revive_poll_refusal(self):
        case = self.fixture.case(finite_tool_mode='captured-host-tools',
                                 poll_chars='EXAMPLE nonempty',
                                 complete_after_refusal=True,
                                 materialize_on_turn_start=True)
        factory = self.fixture.factory(case)
        entered, release, outcome = threading.Event(), threading.Event(), []
        original_receive = DynamicRpcProcess.receive
        def receive(process, message):
            if (not process.is_tool and message.get('id') ==
                    'EXAMPLE-request-EXAMPLE-poll-call'
                    and message.get('result', {}).get('success') is False):
                entered.set()
                release.wait(5)
            return original_receive(process, message)
        def run():
            try:
                outcome.append(factory.run())
            except BaseException as failure:
                outcome.append(failure)
        with patch.object(family, 'RpcProcess', DynamicRpcProcess), patch.object(
                DynamicRpcProcess, 'receive', receive):
            worker = threading.Thread(target=run, daemon=True)
            worker.start()
            self.addCleanup(family.finish_worker, self, worker, release)
            self.addCleanup(release.set)
            self.assertTrue(self.wait_for_startup(entered, worker, outcome))
            server = factory.server
            lifecycle = server.finite_input.lifecycle
            # The receiver sees the written frame before the sender publishes
            # its lifecycle transition. Wait for that actual commit boundary.
            with lifecycle.condition:
                self.assertTrue(lifecycle.condition.wait_for(
                    lambda: lifecycle.phase in lifecycle.TERMINAL, timeout=10))
            self.assertEqual(lifecycle.phase, 'refused')
            self.fixture.spawned[0]._send_tool(
                'EXAMPLE-late-after-refusal', 'finite_poll',
                {'commandCallId': 'EXAMPLE-command-call', 'chars': ''},
                case.scenario)
            end = time.monotonic() + 2
            while family.runtime.protocol._id_key(
                    'EXAMPLE-request-EXAMPLE-late-after-refusal') not in server._request_ids:
                self.assertLess(time.monotonic(), end)
                time.sleep(.001)
            self.assertEqual(lifecycle.phase, 'refused')
            self.assertFalse(lifecycle.pending)
            release.set()
            worker.join(12)
        self.assertEqual(len(outcome), 1)
        self.assertNotIn(lifecycle.phase, lifecycle.WAITING)
        late = [reply for reply in self.fixture.spawned[0].replies
                if reply.get('id') == 'EXAMPLE-request-EXAMPLE-late-after-refusal']
        self.assertFalse(any(reply.get('result', {}).get('success') is True
                             for reply in late))
        with self.assertRaises(BlockingIOError):
            os.read(case.tool_read, 1)


    def _partial_original_projection_schedule(self, kind, pause_after, before_wait):
        """The real fake server supplies the selected request epoch and item."""
        case = self.fixture.case(finite_tool_mode='captured-host-tools',
                                 materialize_on_turn_start=True)
        case.command_prepared, case.command_release = threading.Event(), threading.Event()
        factory = self.fixture.factory(case)
        outcome, observed, entered, release, phases = [], [], threading.Event(), threading.Event(), []
        self.addCleanup(case.command_release.set)
        self.addCleanup(release.set)
        decision_entered, decision_release = threading.Event(), threading.Event()
        self.addCleanup(decision_release.set)
        original_record = factory.record

        def hold_decision(name, observation):
            if kind == 'item' and name == 'finite-tool-decision':
                decision_entered.set()
                decision_release.wait(5)
            return original_record(name, observation)

        def no_command(process):
            case.command_prepared.set()
            case.command_release.wait(5)
            if kind == 'item':
                process._send_tool('EXAMPLE-command-call', 'finite_command',
                                   {'command': case.spec['command']}, case.scenario)

        def run():
            try:
                outcome.append(factory.run())
            except BaseException as failure:
                outcome.append(failure)

        with patch.object(family, 'RpcProcess', DynamicRpcProcess), patch.object(
                DynamicRpcProcess, 'approve', no_command):
            worker = threading.Thread(target=run, daemon=True)
            worker.start()
            self.addCleanup(family.finish_worker, self, worker, case.command_release, release, decision_release)
            self.assertTrue(self.wait_for_startup(case.command_prepared, worker, outcome), outcome)
            if kind == 'item':
                record_patch = patch.object(factory, 'record', hold_decision)
                record_patch.start()
                self.addCleanup(record_patch.stop)
                case.command_release.set()
            server = factory.server
            lifecycle = server.finite_input.lifecycle
            end = time.monotonic() + 3
            if kind == 'item':
                self.assertTrue(decision_entered.wait(3))
            else:
                while lifecycle.phase != 'await-command':
                    self.assertLess(time.monotonic(), end)
                    time.sleep(.001)
            turn = case.scenario.thread_id, case.scenario.turn_id
            item = 'EXAMPLE-command-call'
            initial_phase = lifecycle.phase
            if kind == 'item':
                self.assertIn((*turn, item), server._items)
                self.assertTrue(lifecycle.pending)
                projection = {'id': turn[0], 'turns': [{'id': turn[1],
                    'status': 'inProgress', 'items': [
                        {'id': item, 'status': 'completed'},
                        {'id': 'EXAMPLE-unstarted-item', 'status': 'completed'}]}]}
                method, selected = '_terminal_item', (*turn, item)
                expected = 'registered-item-terminal-before-start'
                fact = lambda: (*turn, item) in server.requests.completed_items
            else:
                projection = {'id': turn[0], 'turns': [
                    {'id': turn[1], 'status': 'completed', 'items': []},
                    {'id': 'EXAMPLE-unrelated-turn', 'status': 'completed', 'items': []}]}
                method, selected = '_terminal', turn
                expected = 'registered-terminal-before-bound-turn'
                fact = lambda: turn in server.requests.terminals
            before_generation = lifecycle.generation
            original = getattr(server.requests, method)
            publish = server.requests._publish_progress
            original_wait = lifecycle.condition.wait
            waiting = threading.Event()

            def pause(*args):
                if args == selected:
                    if not pause_after:
                        entered.set()
                        release.wait(3)
                    result = original(*args)
                    if pause_after:
                        entered.set()
                        release.wait(3)
                    return result
                return original(*args)

            def record_publish():
                publish()
                phases.append((lifecycle.phase, lifecycle.generation))

            def wait(timeout=None):
                waiting.set()
                return original_wait(timeout)

            def host_wait():
                try:
                    observed.append(server.await_finite_progress(
                        host_deadline=time.monotonic() + 3))
                except BaseException as failure:
                    observed.append(failure)

            errors = []
            def project():
                try:
                    server.requests.observe_response({'result': {'thread': projection}})
                except BaseException as failure:
                    errors.append(failure)

            with patch.object(server.requests, method, pause), patch.object(
                    server.requests, '_publish_progress', record_publish), patch.object(
                    lifecycle.condition, 'wait', wait):
                waiter = None
                if not before_wait:
                    waiter = threading.Thread(target=host_wait, daemon=True)
                    waiter.start()
                    self.assertTrue(waiting.wait(2))
                action = threading.Thread(target=project, daemon=True)
                action.start()
                self.assertTrue(entered.wait(2))
                self.assertEqual(fact(), pause_after)
                self.assertEqual(lifecycle.phase, initial_phase)
                if before_wait:
                    waiter = threading.Thread(target=host_wait, daemon=True)
                    waiter.start()
                    self.assertTrue(waiting.wait(2))
                self.assertEqual(observed, [])
                release.set()
                action.join(3)
                waiter.join(3)
                self.assertFalse(action.is_alive())
                self.assertFalse(waiter.is_alive())
            self.assertEqual(len(errors), 1)
            self.assertEqual(str(errors[0]), expected)
            self.assertTrue(fact())
            self.assertTrue(any(phase == 'fault' for phase, _generation in phases))
            self.assertEqual(lifecycle.phase, 'fault')
            self.assertIs(server.transport_failure, errors[0])
            self.assertGreater(lifecycle.generation, before_generation)
            self.assertEqual(len(observed), 1)
            self.assertIsInstance(observed[0], BaseException)
            self.assertIs(observed[0].__cause__, errors[0])
            self.assertFalse(lifecycle.pending)
            self.assertEqual(server.finite_input.output_bytes_seen, 0)
            self.assertFalse(server.finite_input.reply_tickets)
            self.assertFalse(any(reply.get('result', {}).get('success') is True
                                 for reply in self.fixture.spawned[0].replies))
            self.assertEqual(sum(bool(getattr(child, 'is_tool', False))
                                 for child in self.fixture.spawned), 0)
            self.assertEqual(server.finite_input.cleanup_phase(), 'unselected')
            records = [json.loads(path.read_text()) for path in
                       (factory.records / 'transport-observations').iterdir()]
            self.assertFalse(any(row['stage'] in {
                'finite-tool-command-intent', 'finite-poll-intent'}
                for row in records))
            server._fail_transport(errors[0])
            decision_release.set()
            case.command_release.set()
            worker.join(12)
        self.assertEqual(len(outcome), 1)
        attempt = self.fixture.attempt(case)
        self.assertEqual(attempt['outcome'], 'unknown')
        self.assertEqual(attempt['charge'], attempt['amount'])
        self.assertTrue(factory.server.lifetime.contained)
        records = [json.loads(path.read_text()) for path in
                   (factory.records / 'transport-observations').iterdir()]
        self.assertEqual(sum(row['stage'] == 'appserver-terminated'
                             for row in records), 1)

    def test_partial_original_multiturn_and_multiitem_projection_wakes(self):
        for kind in ('turn', 'item'):
            for pause_after in (False, True):
                for before_wait in (False, True):
                    with self.subTest(kind=kind, pause_after=pause_after,
                                      before_wait=before_wait):
                        fixture = RegisteredFiniteToolWiringTests(methodName='runTest')
                        fixture.setUp()
                        try:
                            fixture._partial_original_projection_schedule(
                                kind, pause_after, before_wait)
                        finally:
                            family.cleanup_helper(self, fixture)

    def test_original_publication_failure_faults_without_masking_rejection(self):
        class Selected:
            pass

        server = Selected()
        server._wire_turn = ('EXAMPLE-thread', 'EXAMPLE-selected', 1)
        server._items = {}
        server.transport_failure = None
        server.finite_tools = Selected()
        server.finite_tools.command_call_id = None
        server.finite_input = Selected()
        server.finite_input.lifecycle = gate_module._FiniteLifecycle()
        lifecycle = server.finite_input.lifecycle
        lifecycle.select('EXAMPLE-epoch', server._wire_turn[:2],
                         time.monotonic() + 5)
        server.requests = family.runtime._CoherentServerRequests(server)

        def latch(failure):
            if server.transport_failure is None:
                server.transport_failure = failure

        server._publish_transport_failure = latch
        projection = {'result': {'thread': {'id': 'EXAMPLE-thread', 'turns': [
            {'id': 'EXAMPLE-selected', 'status': 'completed', 'items': []},
            {'id': 'EXAMPLE-unrelated', 'status': 'completed', 'items': []}]}}}
        with patch.object(server.requests, '_publish_progress',
                          side_effect=RuntimeError('EXAMPLE publication failure')):
            with self.assertRaisesRegex(family.runtime.protocol.PreparationError,
                                        'registered-terminal-before-bound-turn') as caught:
                server.requests.observe_response(projection)
        self.assertIn(server._wire_turn[:2], server.requests.terminals)
        self.assertEqual(lifecycle.phase, 'fault')
        self.assertIs(server.transport_failure, caught.exception)
        self.assertTrue(server.requests.wake.is_set())
        self.assertIn('Reducer publication also failed',
                      '\n'.join(caught.exception.__notes__))

    def test_gate_dispatch_before_terminal_keeps_prior_effect_and_full_charge(self):
        case = self.fixture.case(finite_tool_mode='captured-host-tools')
        case.command_prepared, case.command_release = threading.Event(), threading.Event()
        factory = self.fixture.factory(case)
        entered, release = threading.Event(), threading.Event()
        outcome, gate_writes = [], []
        original_write = os.write

        def written_then_held(fd, data):
            if data == b'1' and len(self.fixture.spawned) > 1:
                count = original_write(fd, data)
                gate_writes.append(count)
                entered.set()
                release.wait(10)
                return count
            return original_write(fd, data)

        def run():
            try:
                outcome.append(factory.run())
            except BaseException as failure:
                outcome.append(failure)

        with patch.object(family, 'RpcProcess', DynamicRpcProcess), patch.object(
                os, 'write', written_then_held):
            worker = threading.Thread(target=run, daemon=True)
            worker.start()
            self.addCleanup(release.set)
            self.addCleanup(case.command_release.set)
            self.addCleanup(family.finish_worker, self, worker, case.command_release, release)
            self.assertTrue(self.wait_for_startup(case.command_prepared, worker, outcome))
            case.command_release.set()
            self.assertTrue(entered.wait(8), 'the registered gate was not physically written')
            lifecycle = factory.server.finite_input.lifecycle
            ticket = next(ticket for (kind, _binding), ticket in lifecycle.authority_commits.items()
                          if kind == 'registered-gate')
            self.fixture.spawned[0].stdout.put({'method': 'turn/completed', 'params': {
                'threadId': case.scenario.thread_id,
                'turn': {'id': case.scenario.turn_id, 'status': 'interrupted'}}})
            end = time.monotonic() + 3
            while not lifecycle.authority_revoked_turns:
                self.assertLess(time.monotonic(), end, 'terminal did not reach the shared owner')
                time.sleep(.002)
            self.assertLess(ticket[0], lifecycle.authority_revocations[-1][0])
            release.set()
            worker.join(12)
        self.assertFalse(worker.is_alive(), 'registered runner did not terminate')
        self.assertEqual(gate_writes, [1])
        self.assertEqual(len(self.fixture.spawned), 2)
        self.assertFalse(self.fixture.spawned[1].process.alive)
        self.assertEqual(lifecycle.authority_outcomes[ticket[1:]],
                         'effect-applied-before-containment')
        self.assertFalse(any(reply.get('result', {}).get('success') is True
                             for reply in self.fixture.spawned[0].replies))
        self.assertEqual(len(outcome), 1)
        self.assertIsInstance(outcome[0], BaseException)
        self.assertIsNone(factory.token)
        attempt = self.fixture.attempt(case)
        self.assertEqual(attempt['outcome'], 'unknown')
        self.assertEqual(attempt['charge'], attempt['amount'])


    def test_raw_request_id_collision_after_tool_request_refuses(self):
        case = self.fixture.case(finite_tool_mode='captured-host-tools',
                                 colliding_permission_after_command=True)
        factory = self.fixture.factory(case)
        with patch.object(family, 'RpcProcess', DynamicRpcProcess), self.assertRaises(ValueError):
            factory.run()
        attempt = self.fixture.attempt(case)
        self.assertEqual(attempt['outcome'], 'unknown')
        self.assertEqual(attempt['charge'], attempt['amount'])
        self.assertIsNotNone(factory.server.transport_failure)

    def test_command_eof_refuses_and_contains_original_tool(self):
        case = self.fixture.case(finite_tool_mode='captured-host-tools', command_eof=True)
        factory = self.fixture.factory(case)
        with patch.object(family, 'RpcProcess', DynamicRpcProcess), self.assertRaises(ValueError):
            factory.run()
        attempt = self.fixture.attempt(case)
        self.assertEqual(attempt['outcome'], 'unknown')
        self.assertEqual(attempt['charge'], attempt['amount'])
        self.assertEqual(len(self.fixture.spawned), 2)
        self.assertTrue(self.fixture.spawned[1].process.alive is False)
        with self.assertRaises(BlockingIOError):
            os.read(case.tool_read, 1)


if __name__ == '__main__':
    unittest.main()
