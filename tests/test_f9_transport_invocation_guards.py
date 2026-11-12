"""Transport/intent checks: exact raw-response bindings and one-use opener."""
from __future__ import annotations

from dataclasses import replace
import json
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import urllib.request

from tests import test_registered_app_server_transport_f2 as transport_fixtures
from tests import test_local_gate_boundaries as local_fixtures
from cwo_core import local_invocation as local
import registered_app_server_transport as transport


class F9TransportInvocationGuards(unittest.TestCase):
    def parser_fixture(self, with_ledger):
        fixture = transport_fixtures.RegisteredTransportF2Tests('runTest')
        self.addCleanup(fixture.doCleanups)
        return fixture, fixture.pending_response(with_ledger=with_ledger)

    def test_F9_02ec145407a12aba_9af6fa1a4982ef58_012d59aaa547737e_pending_fields(self):
        for field, bad in (('request_id', 42), ('wire_request_sha256', None), ('dispatch_record_sha256', 7)):
            for changed in (False, True):
                with self.subTest(field=field, changed=changed):
                    fixture, (server, pending, ledger, _, message) = self.parser_fixture(False)
                    if changed:
                        pending[field] = bad
                    server._consume_raw_stdout_line(json.dumps(message))
                    if changed:
                        fixture.assert_no_observed_witness(server, ledger)
                    else:
                        self.assertIn(41, server._observed_negative_turn_response_capabilities_by_request)
                    self.assertEqual(server._responses, {41: message})

    def test_F9_dbddb99a332e893a_2e368ca110168878_e58aa1546dcb5b98_ledger_binding(self):
        fields = ('turn_intent_id', 'wire_request_sha256', 'dispatch_record_sha256')
        for field in fields:
            for changed in (False, True):
                with self.subTest(field=field, changed=changed):
                    fixture, (server, _, ledger, original, message) = self.parser_fixture(True)
                    if changed:
                        binding = ledger._pending_turn_negative_response_observer_capabilities.pop(original)
                        ledger._pending_turn_negative_response_observer_capabilities.register(original,
                            replace(binding, **{field: 'EXAMPLE-other' if field == 'turn_intent_id' else '0' * 64}))
                    server._consume_raw_stdout_line(json.dumps(message))
                    if changed:
                        fixture.assert_no_observed_witness(server, ledger)
                    else:
                        self.assertIn(41, server._observed_negative_turn_response_capabilities_by_request)
                    self.assertNotIn(original, ledger._pending_turn_negative_response_observer_capabilities)

    def test_F9_bea6d0bf4107cbeb_reader_close_stops_startup_immediately(self):
        for close in (False, True):
            server = object.__new__(transport.RegisteredAppServer)
            server._reader_threads, server._closing, server._cleanup_result = [], False, None
            started = []
            def thread(**options):
                def start():
                    started.append(options['target'])
                    if close:
                        server._closing = True
                return SimpleNamespace(start=start)
            with self.subTest(close=close), patch.object(transport.threading, 'Thread', side_effect=thread):
                if close:
                    with self.assertRaisesRegex(transport.AppServerError, 'closed-during-startup'):
                        server._start_readers()
                    self.assertEqual(len(started), 1)
                else:
                    server._start_readers()
                    self.assertEqual(len(started), 2)

    def test_F9_25bc3909d39343c1_opener_binding_cannot_be_replaced_or_reused(self):
        request = urllib.request.Request('http://127.0.0.1:8000/post', data=b'exact', method='POST')
        for state in ('fresh', 'completed', 'failed'):
            first = SimpleNamespace(open=Mock(return_value=object()))
            second = SimpleNamespace(open=Mock(return_value=object()))
            handle = local_fixtures.Handle()
            gate = local.LocalHttpGate(handle, local.reserved_requests(request, None))
            self.assertIs(gate.bind(first), gate)
            if state == 'failed':
                first.open.side_effect = OSError('EXAMPLE failure')
                with self.assertRaises(OSError):
                    gate.open(request, timeout=1)
            elif state == 'completed':
                gate.open(request, timeout=1)
            before = (dict(gate._states), list(gate.sent), gate.usage())
            with self.subTest(state=state), self.assertRaises(SystemExit):
                gate.bind(second)
            self.assertIs(gate._opener, first)
            self.assertEqual((gate._states, gate.sent, gate.usage()), before)
            second.open.assert_not_called()
            if state == 'fresh':
                gate.open(request, timeout=1)
                first.open.assert_called_once()
