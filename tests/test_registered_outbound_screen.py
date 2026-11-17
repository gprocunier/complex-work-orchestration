"""Physical finite reply fencing, without claiming host or child qualification."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))

import registered_finite_input as finite
import registered_n1_factory as registered
from cwo_core import outbound_screen
from cwo_core.prepared_outbound import PreparedSource


class FiniteReplyWireTests(unittest.TestCase):
    def reply(self, text='EXAMPLE useful output\n'):
        """Use original frame/ticket/reducer/write code; simulate retained liveness only."""
        read, write = os.pipe()
        for descriptor in (read, write):
            self.addCleanup(os.close, descriptor)
        os.set_blocking(read, False)
        writer = SimpleNamespace(descriptor=write, flush=Mock())
        factory = SimpleNamespace(capability=object(), receipt=object(), ledger=object(),
                                  host=object(), _ledger_handles=object(), _host_bytes=b'host',
                                  policy_bytes=b'policy', _source='EXAMPLE source',
                                  spec={'command': 'printf EXAMPLE'})
        server = object.__new__(registered._RegisteredServer)
        server.connection_epoch_sha256 = 'e' * 64
        server.transport_failure = None
        server.requests = SimpleNamespace(lock=threading.RLock(), closed=False,
            terminals=set(), trusted_terminals=set(), cancelled_turn=None, completed_items=set())
        lifetime = SimpleNamespace(birth=object(), receipt=object())
        producer = SimpleNamespace(factory=factory, lock=threading.RLock(), lifetime=lifetime,
            epoch=server.connection_epoch_sha256, _current=lambda params: True,
            refresh_terminal_reply=lambda *args: None)
        server.finite_tools = producer
        gate = finite.RegisteredFiniteInput(factory, server)
        server.finite_input = gate
        server._sync_finite_progress_locked = Mock()
        gate.state, gate.lifetime, gate.process = 'active', lifetime, object()
        gate.authority = gate._authority_snapshot()
        gate._current_process = Mock(return_value=True)
        deadline = time.monotonic() + 5
        message = {'id': 'EXAMPLE-reply', 'params': {'threadId': 'EXAMPLE-thread',
            'turnId': 'EXAMPLE-turn', 'callId': 'EXAMPLE-call', 'tool': 'finite_command'}}
        response = {'id': message['id'], 'result': {'success': True,
            'contentItems': [{'type': 'inputText', 'text': text}]}}
        gate.lifecycle.select(producer.epoch, ('EXAMPLE-thread', 'EXAMPLE-turn'), deadline)
        gate.lifecycle.queue(finite.protocol._id_key(message['id']), 'finite_command',
                             ('EXAMPLE-thread', 'EXAMPLE-turn'), 'EXAMPLE-call', deadline)
        for event in ('decide-command', 'command-intent', 'pending-birth', 'gate-closed', 'gate-release'):
            gate.lifecycle.move(event, call='EXAMPLE-call')
        frame = server._tool_reply_frame(message, response, deadline)
        return SimpleNamespace(read=read, writer=writer, gate=gate, producer=producer,
            server=server, message=message, response=response, deadline=deadline, frame=frame)

    def commit(self, case, frame=None):
        frame = case.frame if frame is None else frame
        ticket = case.gate.issue_reply_observation(case.producer, case.message,
            case.response, case.deadline, frame, False)
        error, result = None, None
        try:
            result = case.gate.commit_reply_observation(ticket, case.producer, case.message,
                case.response, case.deadline, frame, case.writer, False)
        except BaseException as failure:
            error = failure
        try:
            wire = os.read(case.read, 4096)
        except BlockingIOError:
            wire = b''
        return error, result, wire, ticket

    def assert_refused_without_wire(self, case, frame=None):
        error, _result, wire, ticket = self.commit(case, frame)
        self.assertFalse(bool(wire), 'Unscreened finite reply reached the physical wire')
        self.assertTrue(isinstance(error, outbound_screen.OutboundRefused),
                        'Finite reply did not preserve its controlled outbound refusal')
        self.assertTrue(case.gate.reply_tickets[ticket].used)
        self.assertEqual(list(case.gate.lifecycle.authority_attempt_results.values()), ['unknown-send'])
        self.assertEqual(case.gate.lifecycle.phase, 'command-effect')
        return error

    def test_original_clean_useful_reply_writes_identical_bytes_once(self):
        case = self.reply()
        error, result, wire, ticket = self.commit(case)
        self.assertIsNone(error)
        self.assertIs(result, True)
        self.assertTrue(wire == case.frame, 'Useful finite reply bytes changed')
        self.assertEqual(list(case.gate.lifecycle.authority_attempt_results.values()), ['wire-sent'])
        self.assertEqual(case.gate.lifecycle.phase, 'command-replied')
        with self.assertRaises(finite.FiniteInputError):
            case.gate.commit_reply_observation(ticket, case.producer, case.message,
                case.response, case.deadline, case.frame, case.writer, False)
        with self.assertRaises(BlockingIOError):
            os.read(case.read, 4096)

    def test_sensitive_corpus_replies_refuse_before_any_physical_write(self):
        corpus = json.loads((ROOT / 'tests/fixtures/outbound_screening/seed-corpus.json').read_text())
        cases = [case for case in corpus['cases'] if case.get('sensitive')]
        self.assertEqual(len(cases), 52)
        for item in cases:
            with self.subTest(case=item['id']):
                error = self.assert_refused_without_wire(self.reply(item['text']))
                self.assertFalse(any(span in str(error) for span in item['sensitive']),
                                 'Outbound refusal exposed original sensitive content')

    def test_final_injected_frame_cannot_borrow_an_earlier_clean_source_scan(self):
        item = json.loads((ROOT / 'tests/fixtures/outbound_screening/seed-corpus.json').read_text())['cases'][0]
        for duplicate in (False, True):
            with self.subTest(duplicate=duplicate):
                case = self.reply()
                earlier = PreparedSource.capture(case.response).bind(case.response,
                    outbound_screen.require_clean(case.frame, surface='native finite tool reply',
                                                  content_type='application/json'))
                self.assertTrue(earlier.require_unchanged(case.response, case.frame) == case.frame)
                injected = case.frame[:-2] + b',"wireOnly":' + json.dumps(item['text']).encode()
                if duplicate:
                    injected += b',"wireOnly":"EXAMPLE clean last value"'
                injected += b'}\n'
                self.assert_refused_without_wire(case, injected)

    def test_flush_source_mutation_refuses_instead_of_sending_an_unbound_frame(self):
        case = self.reply()
        def mutate():
            case.response['result']['contentItems'][0]['text'] = 'EXAMPLE changed after ticket'
        case.writer.flush.side_effect = mutate
        self.assert_refused_without_wire(case)

    def test_flush_or_scan_crossing_original_deadline_cannot_write(self):
        for stage in ('flush', 'scan'):
            with self.subTest(stage=stage):
                case = self.reply()
                now = [case.deadline - .1]
                original = finite.prepared_outbound.prepare_json_frame

                def expire():
                    now[0] = case.deadline

                def scan(*args, **kwargs):
                    prepared = original(*args, **kwargs)
                    if stage == 'scan':
                        expire()
                    return prepared

                if stage == 'flush':
                    case.writer.flush.side_effect = expire
                with patch.object(time, 'monotonic', side_effect=lambda: now[0]), \
                        patch.object(finite.prepared_outbound, 'prepare_json_frame', side_effect=scan):
                    error, _result, wire, ticket = self.commit(case)
                self.assertFalse(bool(wire), 'Expired finite reply reached the physical wire')
                self.assertTrue(isinstance(error, finite.FiniteInputError),
                                'Original finite deadline did not produce a controlled refusal')
                self.assertTrue(case.gate.reply_tickets[ticket].used)
                self.assertEqual(list(case.gate.lifecycle.authority_attempt_results.values()), ['unknown-send'])
                self.assertEqual(case.gate.lifecycle.phase, 'command-effect')

    def test_flush_refusal_keeps_its_primary_and_unknown_send(self):
        case = self.reply()
        primary = outbound_screen.OutboundRefused('EXAMPLE controlled flush refusal')
        case.writer.flush.side_effect = primary
        error = self.assert_refused_without_wire(case)
        self.assertIs(error, primary)

    def test_accounting_failure_cannot_replace_the_outbound_refusal(self):
        case = self.reply()
        primary = outbound_screen.OutboundRefused('EXAMPLE controlled flush refusal')
        case.writer.flush.side_effect = primary
        secondary = RuntimeError('EXAMPLE secondary details must stay private')
        with patch.object(case.gate.lifecycle, 'authority_result', side_effect=secondary):
            error, _result, wire, ticket = self.commit(case)
        self.assertFalse(bool(wire), 'Refused finite reply reached the physical wire')
        self.assertTrue(error is primary, 'Accounting failure replaced the original outbound refusal')
        self.assertTrue(case.gate.reply_tickets[ticket].used)
        self.assertEqual(list(case.gate.lifecycle.authority_attempt_results.values()), [None])
        notes = str(getattr(error, '__notes__', ()))
        self.assertIn('RuntimeError', notes)
        self.assertNotIn(str(secondary), notes)


if __name__ == '__main__':
    unittest.main()
