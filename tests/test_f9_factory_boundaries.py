"""Original factory and containment checks; all process boundaries stay fake."""
from __future__ import annotations

import copy
from dataclasses import replace
import json
import os
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from tests import test_f4_factory_pool_guards as fixtures
import registered_n1_factory as factory_api
import registered_finite_input as finite_input


class F9FactoryBoundaries(unittest.TestCase):
    def factory(self, **options):
        helper = fixtures.F4FactoryPoolGuardTests('runTest')
        helper._outcome = self._outcome
        self.addCleanup(helper.doCleanups)
        return helper.factory_fixture(**options)

    def test_F9_30ec01a931a57410_import_image_refuses_symlink_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            scripts = Path(temporary)
            (scripts / 'ordinary.py').write_text('EXAMPLE ordinary source')
            with patch.object(factory_api, '__file__', str(scripts / 'factory-entry.py')):
                self.assertEqual(len(factory_api.implementation_sha256()), 64)
                (scripts / 'alias.py').symlink_to(scripts / 'ordinary.py')
                with self.assertRaisesRegex(ValueError, 'Unsupported installed source entry'):
                    factory_api.implementation_sha256()

    def test_F9_5d937fa98b3dcf1e_closed_writer_abort_never_reuses_descriptor(self):
        for closed in (False, True):
            read, write = os.pipe()
            self.addCleanup(os.close, read)
            stream = os.fdopen(write, 'w')
            writer = factory_api._DeadlineInput(stream, lambda _: None)
            if closed:
                stream.close()
            with patch.object(factory_api.os, 'dup2', wraps=os.dup2) as poison:
                writer.abort()
                self.assertEqual(poison.call_count, 0 if closed else 1)
            self.assertIsNone(writer._poison)
            stream.close()

    @staticmethod
    def lifetime():
        factory = SimpleNamespace(server=None, record=Mock())
        lifetime = factory_api._Containment(factory, role='appserver')
        lifetime.receipt = object()
        return factory, lifetime

    def test_F9_eeb22ef8270c4ca9_a9a2b049d5b04f6f_termination_outcome_and_namespace(self):
        for scenario in ('completed', 'unknown-outcome', 'namespace-live'):
            factory, lifetime = self.lifetime()
            report = dict(outcome='unknown' if scenario == 'unknown-outcome' else 'terminated',
                child_exit_confirmed=True, child_reaped=True)
            lifetime.controller = SimpleNamespace(terminate=Mock(return_value=report))
            read, write = os.pipe()
            os.close(write)
            lifetime.namespace_handle = read
            try:
                with patch.object(factory_api.select, 'select', return_value=([] if scenario == 'namespace-live' else [read], [], [])):
                    if scenario == 'completed':
                        self.assertEqual(lifetime._terminate_claimed(), report)
                        self.assertTrue(lifetime.contained and lifetime.termination_recorded)
                        factory.record.assert_called_once()
                    else:
                        with self.assertRaises(factory_api.native.OfflineHostError):
                            lifetime._terminate_claimed()
                        self.assertFalse(lifetime.contained or lifetime.termination_recorded)
                        factory.record.assert_not_called()
            finally:
                if lifetime.namespace_handle is not None:
                    os.close(lifetime.namespace_handle)

    def test_F9_b75ef30d3d7142b1_failed_observer_cannot_publish_contained(self):
        event = Mock()
        factory, lifetime = self.lifetime()
        factory.server = SimpleNamespace(finite_input=SimpleNamespace(lifecycle=SimpleNamespace(original_cleanup_event=event)))
        lifetime.contained = lifetime.termination_recorded = True
        lifetime._record_observation()
        event.assert_called_with('contained')
        lifetime._record_observation(RuntimeError('EXAMPLE observer failed after physical containment'))
        event.assert_called_with('unknown')
        self.assertTrue(lifetime.observation_snapshot()[2])

    def test_F9_9f3348b28423bd09_pending_completion_does_not_mask_refusal(self):
        server = object.__new__(factory_api._RegisteredServer)
        turn, command = ('EXAMPLE-thread', 'EXAMPLE-turn'), 'EXAMPLE-command'
        lifecycle = finite_input._FiniteLifecycle(clock=lambda: 0)
        lifecycle.turn, lifecycle.command, lifecycle.phase = turn, command, 'command-effect'
        server.finite_tools = SimpleNamespace(command_call_id=command)
        server.finite_input = SimpleNamespace(lifecycle=lifecycle)
        server.transport_failure, server._wire_turn = None, (*turn, 1)
        server.requests = SimpleNamespace(closed=False, terminals=set(), trusted_terminals=set(), cancelled_turn=None,
            completed_items=set(), refusal_only=False)
        self.assertFalse(server._sync_command_completion_locked(lifecycle, turn))
        server.requests.refusal_only = True
        server._sync_finite_progress_locked()
        self.assertEqual(lifecycle.phase, 'refused')

    def test_F9_fcafe5e528cc9ef6_actual_turn_response_is_pending_and_bound(self):
        def server():
            value = object.__new__(factory_api._RegisteredServer)
            value.thread_id, value._request_id, value._response_ids = 'EXAMPLE-thread', 1, set()
            value.connection_epoch_sha256 = 'a' * 64
            value.requests = SimpleNamespace(observe_response=Mock(), observe_turn_response=Mock(), lock=threading.RLock())
            value._turn_dispatch_records = {value.thread_id: dict(request_id=1, status='dispatching',
                connection_epoch_sha256=value.connection_epoch_sha256, thread_id=value.thread_id)}
            value._wire_turn, value.finite_tools = None, None
            return value
        message = dict(id=1, result={'turn': {'id': 'EXAMPLE-turn', 'status': 'inProgress'}})
        good = server()
        good._observe_response(copy.deepcopy(message))
        self.assertEqual(good._wire_turn, ('EXAMPLE-thread', 'EXAMPLE-turn', 1))
        for bad in ('status', 'epoch', 'empty', 'large', 'nonstring', 'existing'):
            current, changed = server(), copy.deepcopy(message)
            record = current._turn_dispatch_records[current.thread_id]
            if bad == 'status':
                record['status'] = 'prepared'
            elif bad == 'epoch':
                record['connection_epoch_sha256'] = 'b' * 64
            elif bad == 'existing':
                current._wire_turn = ('EXAMPLE-other', 'EXAMPLE-existing', 0)
            else:
                changed['result']['turn']['id'] = {'empty': '', 'large': 'x' * 257, 'nonstring': 7}[bad]
            with self.subTest(bad=bad), self.assertRaisesRegex(ValueError, 'pending dispatch'):
                current._observe_response(changed)
            current.requests.observe_turn_response.assert_not_called()

    def test_F9_5074816c554bdd87_24dc42872da06adc_registered_adapter_methods_and_failure(self):
        adapter = object.__new__(factory_api.RegisteredAdapter)
        adapter.server = SimpleNamespace(_fail_transport=Mock())
        owner = SimpleNamespace(server=adapter.server)
        factory_api._ADAPTERS[adapter] = owner
        self.addCleanup(factory_api._ADAPTERS.pop, adapter, None)
        factory_api.require_adapter(adapter)
        with patch.object(adapter, '_timed', lambda *_: None), self.assertRaisesRegex(ValueError, 'adapter methods changed'):
            factory_api.require_adapter(adapter)
        failure = RuntimeError('EXAMPLE execution failed')
        factory_api.observe_execution_failure(adapter, failure)
        adapter.server._fail_transport.assert_called_once_with(failure)
        factory_api.observe_execution_failure(object(), failure)
        self.assertEqual(adapter.server._fail_transport.call_count, 1)

    def test_F9_89f4562bae0f48b2_constructor_claim_reader_share_store(self):
        fixture, case, factory = self.factory()
        settings = dict(receipt=case.receipt, route=case.route, node_id=case.node_id,
            ledger=case.ledger, host=case.host, policy=case.policy)
        with patch.object(factory.verifier, '_claim', lambda *_: None), \
                patch.object(factory_api, '_private', side_effect=AssertionError('EXAMPLE constructor reached write')) as private:
            with self.assertRaisesRegex(ValueError, 'one maintenance store'):
                factory_api.RegisteredN1Factory(factory.capability, factory.verifier, **settings)
            private.assert_not_called()
        self.assertFalse(getattr(fixture, 'spawned', []))

    def test_F9_60ca77c239e94c6e_a0c7de011dd39941_purpose_and_whole_options(self):
        fixture, _, factory = self.factory()
        factory._validate()
        original_spec, original_receipt = factory.spec, factory.receipt
        spec = copy.deepcopy(original_spec)
        spec['purpose'] = 'external-contract'
        execution = json.loads(original_receipt.execution_bytes)
        execution['options'] = {'registered_n1': {key: value for key, value in spec.items() if key != 'admission_sha256'}}
        changed = replace(original_receipt, execution_bytes=factory_api._snapshot(execution))
        spec['admission_sha256'] = factory_api.admission._receipt_sha256(changed)
        with patch.object(factory, 'spec', spec), patch.object(factory, 'receipt', changed), \
                self.assertRaisesRegex(ValueError, 'External execution-purpose'):
            factory._validate()
        execution = json.loads(original_receipt.execution_bytes)
        execution['options']['registered_n1']['command'] += ' EXAMPLE-drift'
        changed = replace(original_receipt, execution_bytes=factory_api._snapshot(execution))
        spec = {**original_spec, 'admission_sha256': factory_api.admission._receipt_sha256(changed)}
        with patch.object(factory, 'spec', spec), patch.object(factory, 'receipt', changed), \
                self.assertRaisesRegex(ValueError, 'Whole-workflow options'):
            factory._validate()
        self.assertFalse(getattr(fixture, 'spawned', []))

    def test_F9_8fd64fd0e02b940b_0f230512e50d25a1_c433fc4bcdb342bf_late_guards(self):
        fixture, _, factory = self.factory()
        factory.guard()
        for change in ('ledger', 'image', 'node'):
            if change == 'ledger':
                context = patch.object(factory.ledger, 'clock', lambda: 0)
                message = 'ledger path, clock, owner probe'
            elif change == 'image':
                context = patch.object(factory_api, 'implementation_sha256', return_value='0' * 64)
                message = 'import image drift'
            else:
                context = patch.object(factory, 'node_id', 'EXAMPLE-other-node')
                message = 'custody or route replay'
            with self.subTest(change=change), context, self.assertRaisesRegex(ValueError, message):
                factory.guard()
        self.assertFalse(getattr(fixture, 'spawned', []))

    def test_F9_9138cbde02a44213_finite_capture_has_connection_epoch(self):
        _, _, factory = self.factory(finite_tool_mode='captured-host-tools')
        process = object()
        server = SimpleNamespace(finite_tools=object(), transport_failure=None, connection_epoch_sha256='a' * 64,
            process=process, lifetime=SimpleNamespace(receipt=object(), birth=object(), process=process))
        factory.server = server
        factory.require_finite_fake_capture()
        server.connection_epoch_sha256 = None
        with self.assertRaisesRegex(ValueError, 'finite capture selection'):
            factory.require_finite_fake_capture()

    def test_F9_6e758fafa771f001_503aca40c1c941ec_issued_failed_admission_and_report(self):
        fixture, case, factory = self.factory(bad_output=True)
        factory.select_controlled_failure()
        with self.assertRaises(factory_api.validation.ValidationError) as raised:
            factory.run()
        primary = raised.exception
        self.assertEqual(factory.controlled_failure(primary)['outcome'], 'failed')
        path = factory.ledger.root / factory_api.admission.ledger_api.LEDGER_FILE
        before = path.read_bytes()
        document = json.loads(before)
        document['attempts'][factory._controlled_issued[1]]['admission_sha256'] = '0' * 64
        path.write_text(json.dumps(document))
        try:
            with self.assertRaisesRegex(ValueError, 'Original failed attempt'):
                factory.controlled_failure(primary)
        finally:
            path.write_bytes(before)
        changed_report = {**primary.report, 'offline_validation_complete': True}
        primary._report = factory_api.validation._encode(changed_report)
        self.assertFalse(factory._issued_failure_current(factory._controlled_issued, primary))
        with self.assertRaisesRegex(ValueError, 'No issued original controlled'):
            factory.controlled_failure(primary)
        self.assertEqual(fixture.attempt(case)['outcome'], 'failed')
