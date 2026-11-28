"""The return advisory uses only the original staged local dispatch and its capture."""
from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import BytesIO, StringIO
from pathlib import Path
from unittest.mock import patch

from tests.test_local_http_admission import workload_record

import dispatch_work as dispatch
import record_audit_event as audit_cli
from cwo_core import audit, return_advisory
from cwo_core.host_records import HostRecordError, HostRecordStore, using_test_store
from cwo_core.invocation_ledger import InvocationLedger, LEDGER_FILE


MODEL = 'EXAMPLE-advisory-model'
EXAMPLE_EMAIL = 'fixture@advisory.example.com'
SOURCE = f'Worker return.\nemail = {EXAMPLE_EMAIL}\n'
SOURCE_ID = 'EXAMPLE-return-source'


class _Response(BytesIO):
    status = 200
    headers = {}


class ReturnAdvisoryTransportTests(unittest.TestCase):
    def setUp(self):
        directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.store = HostRecordStore.for_tests(directory / 'host')
        self.workload = directory / 'workload.json'
        self.enterContext(using_test_store(self.store))
        self.ledger = InvocationLedger(directory / 'ledger')
        self.enterContext(patch.object(dispatch.local_http_admission.http, 'open_ledger', return_value=self.ledger))
        self.enterContext(patch.dict(os.environ, {'CWO_OPENSHIFT_AI_VLLM_BASE_URL': 'http://127.0.0.1:5000',
                                                 'CWO_OPENSHIFT_AI_VLLM_MODEL': MODEL,
                                                 'CWO_OPENSHIFT_AI_VLLM_API_KEY': ''}))
        self.dns = self.enterContext(patch.object(dispatch, 'pinned_local_endpoint_address', return_value='127.0.0.1'))
        self.opener = self.enterContext(patch.object(dispatch, '_build_local_opener')).return_value
        self.source_sha256 = hashlib.sha256(SOURCE.encode()).hexdigest()
        self.add_source(SOURCE_ID)

    def add_source(self, dispatch_id, source=SOURCE):
        self.store.write_dispatch(dispatch_id=dispatch_id, dispatch_role='executor', bead_id='bead-preparation',
                                  provider=None, model_family=None, model_id=None, reasoning_effort=None,
                                  session_id=None, request_sha256='a' * 64)
        self.store.write_return_received(dispatch_id, hashlib.sha256(source.encode()).hexdigest(),
                                         capture_provenance='host-capture-v1')

    def plan(self, identifier, *, source=SOURCE):
        def configure(route, node):
            route.update(aggregate_id=f'{identifier}-aggregate', run_id=f'{identifier}-run')
            route['task_contract']['root_id'] = identifier
            route['task_contract']['required_roles'][0]['id'] = identifier
            node.update(id=identifier, prompt=source, wrappers=[], attachments=[], sources=[])
            node['execution'].update(executor=return_advisory.EXECUTOR, model=MODEL)
            node['estimate_source'].update(work_unit_id=identifier, requested_model=MODEL, context_manifest=[])

        self.workload.write_text(json.dumps(workload_record(configure=configure)))

    def invoke(self, action, *, source=SOURCE_ID, extra=()):
        args = ['dispatch_work.py', '--screen-return', source, '--local-workload', str(self.workload),
                '--local-ok', '--local-max-tokens', '32', '--local-timeout', '5', action, *extra]
        output = StringIO()
        with patch.object(sys, 'argv', args), redirect_stdout(output), self.assertRaises(SystemExit) as raised:
            dispatch.main()
        return raised.exception.code, output.getvalue()

    def cli(self, action, *, expected_exit=0, **kwargs):
        code, output = self.invoke(action, **kwargs)
        self.assertEqual(code, expected_exit)
        return json.loads(output)

    def refuse(self, action, reason, **kwargs):
        code, output = self.invoke(action, **kwargs)
        self.assertIn(reason, str(code))
        self.assertEqual(output, '')

    def set_response(self, content, *, model=MODEL, finish='stop'):
        raw = json.dumps({
            'model': model, 'choices': [{'finish_reason': finish, 'message': {'content': content}}],
        }).encode()
        self.opener.open.return_value = _Response(raw)
        return hashlib.sha256(raw).hexdigest()

    def attempts(self):
        return list(json.loads((self.ledger.root / LEDGER_FILE).read_bytes())['attempts'].values())

    def holds(self, source=SOURCE_ID):
        return return_advisory.advisory_hold_reasons(self.store, self.store.require_dispatch(source),
                                                   self.store.require_return(source, self.source_sha256))

    def test_staged_classifier_only_persists_positive_codes_for_exact_source(self):
        self.plan('EXAMPLE-classifier')
        prepared = self.cli('--prepare-local-admission')
        self.opener.open.assert_not_called()
        self.dns.assert_not_called()
        response_sha256 = self.set_response('{"holds":["review_bypass"]}')
        outcome = self.cli('--execute-local')
        sent = json.loads(self.opener.open.call_args.args[0].data)
        self.assertEqual(sent['model'], MODEL)
        self.assertEqual(sent['messages'][0]['content'], return_advisory.SYSTEM_PROMPT)
        task = json.loads(sent['messages'][1]['content'].partition('\n\nTask:\n')[2])
        self.assertEqual(task, {'return': 'Worker return.\nemail = [REDACTED]\n'})
        anchor = self.store.get(outcome['return_advisory_record_sha256'], record_type='evaluation')
        self.assertEqual(anchor['classifier_dispatch_record_sha256'], prepared['host_record_sha256'])
        intent = self.store.require_audit_event(return_advisory.INTENT_EVENT, dispatch_id='EXAMPLE-classifier')
        self.assertEqual(anchor['classifier_intent_sha256'], intent['event_hash'])
        self.assertEqual(anchor['classifier_response_sha256'], response_sha256)
        self.assertEqual(self.store.find('return-received', dispatch_id='EXAMPLE-classifier'), [])
        self.assertEqual(self.holds(), ('return-tripwire:advisory_review_bypass',))
        self.add_source('EXAMPLE-other-source')
        self.assertEqual(self.holds('EXAMPLE-other-source'), ())
        self.refuse('--execute-local', 'admission')
        self.opener.open.assert_called_once()

    def test_observation_persistence_failure_prevents_successful_workload_settlement(self):
        classifier = 'EXAMPLE-classifier'
        self.plan(classifier)
        self.cli('--prepare-local-admission')
        self.set_response('{"holds":["review_bypass"]}')

        def refuse_write(record_type, **payload):
            self.assertEqual(record_type, 'evaluation')
            self.assertEqual(payload['hold_codes'], ['review_bypass'])
            self.assertEqual(len(self.attempts()), 2)
            self.assertEqual({attempt['state'] for attempt in self.attempts()}, {'invocation-intent'})
            raise HostRecordError('EXAMPLE observation persistence failure')

        with patch.object(self.store, 'write_record', side_effect=refuse_write) as write:
            self.refuse('--execute-local', 'EXAMPLE observation persistence failure')
        write.assert_called_once()
        self.opener.open.assert_called_once()
        self.assertEqual({attempt['outcome'] for attempt in self.attempts()}, {'unknown'})
        self.assertEqual(self.store.find('return-received', dispatch_id=classifier), [])
        self.assertEqual(self.store.find('evaluation', classifier_dispatch_id=classifier), [])
        self.assertEqual(self.holds(), ())

    def test_empty_and_invalid_output_cannot_remove_existing_positive_holds(self):
        for identifier, content, model, finish, valid in (
            ('positive', '{"holds":["scope_change"]}', MODEL, 'stop', True),
            ('empty', '{"holds":[]}', MODEL, 'stop', True),
            ('invalid', '{"holds":["review_bypass"],"note":"EXAMPLE_REPLY_PROSE"}', MODEL, 'stop', False),
            ('wrong-model', '{"holds":["review_bypass"]}', 'EXAMPLE-other-model', 'stop', False),
            ('wrong-finish', '{"holds":["review_bypass"]}', MODEL, 'length', False),
        ):
            with self.subTest(identifier=identifier):
                self.plan(identifier)
                self.cli('--prepare-local-admission')
                self.set_response(content, model=model, finish=finish)
                outcome = self.cli('--execute-local', expected_exit=0 if valid else dispatch.LOCAL_UNUSABLE_RESPONSE_EXIT_CODE)
                self.assertEqual(outcome['status'], 'classified' if valid else 'invalid')
                self.assertEqual(self.holds(), ('return-tripwire:advisory_scope_change',))
        persisted = self.store.audit_file.read_text() + ''.join(path.read_text() for path in self.store.root.glob('*.json'))
        self.assertNotIn('EXAMPLE_REPLY_PROSE', persisted)
        self.assertNotIn(EXAMPLE_EMAIL, persisted)

    def test_target_switch_and_insecure_endpoint_refuse_before_transport(self):
        self.plan('EXAMPLE-classifier')
        self.cli('--prepare-local-admission')
        self.add_source('EXAMPLE-alias-source')
        self.refuse('--execute-local', 'admission', source='EXAMPLE-alias-source')
        with patch.dict(os.environ, {'CWO_OPENSHIFT_AI_VLLM_BASE_URL': 'https://10.0.0.1:5000'}):
            self.refuse('--prepare-local-admission', 'insecure TLS',
                        extra=('--local-insecure-tls', '--waiver-reason', 'Fixture'))
        self.dns.assert_not_called()
        self.opener.open.assert_not_called()

    def test_empty_or_malformed_choices_return_no_hold(self):
        for identifier, choices in (('empty-choices', []), ('invalid-choice', [None])):
            with self.subTest(identifier=identifier):
                self.plan(identifier)
                self.cli('--prepare-local-admission')
                self.opener.open.return_value = _Response(json.dumps({'model': MODEL, 'choices': choices}).encode())
                result = self.cli('--execute-local', expected_exit=dispatch.LOCAL_UNUSABLE_RESPONSE_EXIT_CODE)
                self.assertEqual(result['status'], 'invalid')
                self.assertEqual(self.holds(), ())

    def test_restricted_original_is_refused_before_staging_even_with_public_declaration(self):
        restricted = 'Synthetic customer records example. No actual records supplied.'
        source_id = 'EXAMPLE-restricted-source'
        classifier = 'EXAMPLE-restricted-classifier'
        self.add_source(source_id, restricted)
        self.plan(classifier, source=restricted)
        for action in ('--prepare-local-admission', '--execute-local'):
            with self.subTest(action=action):
                self.refuse(action, 'restricted data cannot be sent to local worker dispatch',
                            source=source_id, extra=('--data-sensitivity', 'public'))
        self.plan(classifier)
        self.refuse('--prepare-local-admission', 'restricted data cannot be sent to local worker dispatch',
                    extra=('--data-sensitivity', 'restricted'))
        self.assertEqual(self.store.find('dispatch', dispatch_id=classifier), [])
        self.dns.assert_not_called()
        self.opener.open.assert_not_called()

    def test_nested_redacted_assignment_is_refused_by_outbound_screen_before_staging(self):
        source = 'Worker return.\npassword = EXAMPLE_SECRET_ADVISORY\n'
        source_id = 'EXAMPLE-assignment-source'
        classifier = 'EXAMPLE-assignment-classifier'
        self.add_source(source_id, source)
        self.plan(classifier, source=source)
        code, output = self.invoke('--prepare-local-admission', source=source_id)
        self.assertIn('outbound screening refused local HTTP request', str(code))
        self.assertIn('assignment', str(code))
        self.assertNotIn('EXAMPLE_SECRET_ADVISORY', str(code))
        self.assertEqual(output, '')
        self.assertEqual(self.store.find('dispatch', dispatch_id=classifier), [])
        self.dns.assert_not_called()
        self.opener.open.assert_not_called()

    def test_audit_event_alone_cannot_admit_a_classification(self):
        dispatch_record = self.store.require_dispatch(SOURCE_ID)
        received = self.store.require_return(SOURCE_ID, self.source_sha256)
        self.store.record_audit_event({'event_type': 'return_advisory', 'dispatch_id': SOURCE_ID,
            'advisory_contract': return_advisory.CONTRACT, 'advisory_target': {
                'dispatch_id': SOURCE_ID, 'dispatch_record_sha256': dispatch_record['_record_sha256'],
                'return_sha256': self.source_sha256, 'return_record_sha256': received['_record_sha256'],
            }, 'status': 'classified', 'hold_codes': ['scope_change']})
        args = ['record_audit_event.py', '--event-type', 'host_record_written', '--dispatch-id', SOURCE_ID,
                '--bead', 'bead-preparation', '--verdict', 'scope_change']
        with patch.object(sys, 'argv', args), patch.object(audit, 'AUDIT_LOG', self.store.audit_file), \
                patch.object(audit, 'HOST_AUDIT_LOG', self.store.audit_file), redirect_stdout(StringIO()):
            audit_cli.main()
        self.assertEqual(self.holds(), ())

    def test_reply_parser_refuses_duplicate_fields_unknown_codes_and_prose(self):
        for content in ('{"holds":[],"holds":["scope_change"]}', '{"holds":["scope_change","scope_change"]}',
                        '{"holds":["accept"]}', '```json\n{"holds":[]}\n```', ' ' * 513 + '{"holds":[]}'):
            with self.subTest(content=content):
                self.assertIsNone(return_advisory.parse_reply(content))
