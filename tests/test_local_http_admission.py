"""The ordinary local HTTP effect requires a whole-workload admission."""
from __future__ import annotations

import argparse
import json
import os
import tempfile
import time
import sys
import unittest
from pathlib import Path
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import StringIO
from threading import Thread
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))

import dispatch_work as dispatch  # noqa: E402
from cwo_core import audit as cwo_audit  # noqa: E402
from cwo_core.host_records import HostRecordStore, using_test_store  # noqa: E402
from cwo_core.invocation_ledger import InvocationLedger, LEDGER_FILE  # noqa: E402
from cwo_core.routing import classify_work  # noqa: E402


class LocalHttpAdmissionTests(unittest.TestCase):
    def test_direct_dispatch_without_workload_admission_refuses_before_effects(self):
        task = 'Review the documentation examples.'
        args = argparse.Namespace(local_base_url='http://127.0.0.1:8080', local_model='offline-model',
                                  execute_local=True, local_max_tokens=32)
        route = classify_work(task, local_ok=True, prefer_local=True, requested_roles=['documentation'])
        envelope = dispatch.build_local_envelope(
            task=task, route=route, dispatch_id='local-http-admission-missing',
            bead_id='bead-local-http-missing', epic_id='epic-local-http-missing', args=args)
        with patch.object(dispatch.local_http_admission.http, 'reserved_local_invocation') as reservation, \
                patch.object(dispatch, 'record_local_execution') as provenance, \
                patch.object(dispatch, 'pinned_local_endpoint_address', side_effect=AssertionError('DNS effect')) as dns, \
                patch.object(dispatch, '_build_local_opener') as open_transport:
            with self.assertRaisesRegex(SystemExit, 'workload admission'):
                dispatch.execute_local_envelope(envelope, route['selected_executor'], args)
        for effect in (reservation, provenance, dns, open_transport):
            effect.assert_not_called()


def workload_record(*, configure=None):
    from tests.test_route_feasibility_preparation import bind, planner, record

    route = record(tiny=True)
    route['aggregate_id'] = 's57-workload-aggregate'
    node = route['nodes'][0]
    node['prompt'] = 'Review the documentation examples for clarity.\npassword = EXAMPLE_LOCAL_SECRET'
    node['execution'].update(executor='openshift_ai_vllm_secure_reviewer', provider='openshift_ai_vllm',
                             model='EXAMPLE-vllm', effort='default', options={'max_tokens': 32})
    node['estimate_source']['requested_model'] = 'EXAMPLE-vllm'
    if configure is not None:
        configure(route, node)
    node['unit_estimate'] = planner.work_sizing.evaluate_work_estimate(node['estimate_source'], policy=route['policy'])
    for name in ('source', 'unit'):
        key = 'estimate_source' if name == 'source' else 'unit_estimate'
        node[f'{name}_sha256'] = planner.work_sizing.canonical_work_estimate_sha256(node[key])
    node['rendered_request'] = planner.render_request(node)
    planned = planner.prepare(bind(route))
    if planned['status'] != 'within-declared-limits':
        raise AssertionError(f'fixture must pass the real workload planner: {planned["reasons"]}')
    route['limits'] = planned['totals'].copy()
    return {'route_input': bind(route), 'node_id': node['id'], 'node_attempts': {}}


class LocalHttpCliTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.host = HostRecordStore.for_tests(self.directory / 'host')
        self.ledger = InvocationLedger(self.directory / 'ledger')
        self.enterContext(using_test_store(self.host))
        self.enterContext(patch.object(dispatch.local_http_admission.http, 'open_ledger', return_value=self.ledger))
        self.enterContext(patch.dict(os.environ, {'CWO_OPENSHIFT_AI_VLLM_API_KEY': ''}))
        self.enterContext(patch.object(cwo_audit, 'AUDIT_LOG', self.host.audit_file))
        self.enterContext(patch.object(cwo_audit, 'HOST_AUDIT_LOG', self.host.audit_file))
        self.calls = []
        self.authorization = []
        self.drip_response = False
        self.server = self.start_server()
        self.url = f'http://127.0.0.1:{self.server.server_port}'
        self.workload_path = self.directory / 'workload.json'
        self.store_workload(workload_record())

    def start_server(self):
        class FakeOpenAIHandler(BaseHTTPRequestHandler):
            def do_POST(handler):
                payload = json.loads(handler.rfile.read(int(handler.headers['Content-Length'])))
                self.calls.append((handler.path, payload, self.attempts()))
                self.authorization.append(handler.headers.get('Authorization'))
                body = json.dumps({'model': 'EXAMPLE-vllm', 'choices': [
                    {'finish_reason': 'stop', 'message': {'content': '## Status\ncompleted\n\n'
                        '## Summary\nThe example documents its bounded input.'}}]}).encode()
                handler.send_response(200)
                handler.send_header('Content-Type', 'application/json')
                handler.send_header('Content-Length', str(len(body)))
                handler.end_headers()
                if self.drip_response:
                    try:
                        for position in range(0, len(body), 4):
                            handler.wfile.write(body[position:position + 4])
                            time.sleep(0.075)
                    except OSError:
                        pass
                else:
                    handler.wfile.write(body)

            def log_message(self, *_args):
                return

        server = ThreadingHTTPServer(('127.0.0.1', 0), FakeOpenAIHandler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.shutdown)
        return server

    def attempts(self):
        path = self.ledger.root / LEDGER_FILE
        return list(json.loads(path.read_bytes())['attempts'].values()) if path.exists() else []

    def store_workload(self, workload):
        self.workload_path.write_text(json.dumps(workload), encoding='utf-8')

    def cli(self, action, *, url=None, model='EXAMPLE-vllm', timeout='5', key_file=None):
        args = ['dispatch_work.py', '--local-workload', str(self.workload_path), '--local-ok', '--prefer-local',
                '--local-profile', 'openshift-ai-vllm', '--requested-role', 'documentation',
                '--local-model', model, '--local-max-tokens', '32',
                '--local-timeout', timeout, '--local-result-view', 'compact', '--json', action]
        endpoint = self.url if url is None else url
        if endpoint:
            args.extend(['--local-base-url', endpoint])
        if key_file is not None:
            args.extend(['--local-api-key-file', str(key_file)])
        output = StringIO()
        with patch.object(sys, 'argv', args), redirect_stdout(output):
            try:
                dispatch.main()
            except SystemExit as exc:
                if exc.code != 0:
                    raise
        return json.loads(output.getvalue())

    def test_original_admission_reaches_fake_vllm_once_and_evaluates_exact_capture(self):
        directory = self.directory / 'endpoint'
        directory.mkdir()
        directory.chmod(0o755)
        key_file = directory / 'local-api-key'
        key_file.write_text('EXAMPLE-BEARER-TOKEN\n', encoding='ascii')
        key_file.chmod(0o600)
        with patch.object(dispatch, 'pinned_local_endpoint_address', wraps=dispatch.pinned_local_endpoint_address) as dns:
            staged = self.cli('--prepare-local-admission', key_file=key_file)
            self.assertFalse(self.attempts())
            self.assertFalse(self.calls)
            dns.assert_not_called()
            result = self.cli('--execute-local', key_file=key_file)['local_response']
            with self.assertRaisesRegex(SystemExit, 'workload admission refused'):
                self.cli('--execute-local', key_file=key_file)
            dns.assert_called_once()
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.authorization, ['Bearer EXAMPLE-BEARER-TOKEN'])
        self.assertNotIn('EXAMPLE-BEARER-TOKEN', self.host.audit_file.read_text())
        self.assertNotIn('EXAMPLE-BEARER-TOKEN', (self.ledger.root / LEDGER_FILE).read_text())
        endpoint, payload, at_effect = self.calls[0]
        self.assertEqual(endpoint, '/v1/chat/completions')
        self.assertEqual(payload['model'], 'EXAMPLE-vllm')
        self.assertEqual(payload['max_tokens'], 32)
        text = payload['messages'][-1]['content']
        self.assertNotIn('EXAMPLE_LOCAL_SECRET', text)
        self.assertIn('[REDACTED]', text)
        self.assertEqual({attempt['state'] for attempt in at_effect}, {'invocation-intent'})
        self.assertEqual(len(at_effect), 2)
        admitted = next(attempt for attempt in self.attempts() if attempt['budget_id'] == 's57-workload-aggregate')
        self.assertEqual(admitted['admission_sha256'], staged['admission_sha256'])
        intent_event = self.host.require_audit_event('local_http_workload_invocation_intent', dispatch_id='plan')
        self.assertEqual(intent_event['local_http_admission_sha256'], staged['admission_sha256'])
        self.assertEqual(intent_event['local_http_attempt_id'], admitted['attempt_id'])
        self.assertEqual(set(admitted['charge']), {'tokens', 'tool_calls', 'runtime_seconds', 'cost_microunits'})
        self.assertEqual(admitted['outcome'], 'completed')
        self.assertEqual(result['completion_status'], 'completed')
        captured = self.host.require_return('plan', result['normalized_return_sha256'])
        evaluation = self.host.get(result['evaluation']['record_sha256'])
        self.assertEqual(evaluation['return_record_sha256'], captured['_record_sha256'])
        self.assertEqual(evaluation['dispatch_record_sha256'], staged['host_record_sha256'])
        self.assertEqual(evaluation['evaluation']['result_class'], 'advisory-nonproduction')
        self.assertIs(evaluation['evaluation']['implementation_blocked'], True)
        self.assertIs(evaluation['evaluation']['peer_review_required'], True)

    def test_unconfigured_endpoint_refuses_without_reservation_or_socket(self):
        with patch.dict(os.environ, {'CWO_OPENSHIFT_AI_VLLM_BASE_URL': ''}), \
                patch.object(dispatch, 'pinned_local_endpoint_address') as dns, \
                patch.object(dispatch, '_build_local_opener') as transport:
            for action in ('--prepare-local-admission', '--execute-local'):
                with self.subTest(action=action), self.assertRaisesRegex(SystemExit, '--local-base-url'):
                    self.cli(action, url='')
            dns.assert_not_called()
            transport.assert_not_called()
        self.assertEqual(self.host.find('dispatch'), [])
        self.assertEqual(self.attempts(), [])
        self.assertEqual(self.calls, [])

    def test_invalid_or_changed_key_refuses_without_reservation_or_socket(self):
        directory = self.directory / 'endpoint'
        directory.mkdir()
        directory.chmod(0o755)
        key_file = directory / 'local-api-key'
        key_file.write_bytes(b'EXAMPLE-KEY\n')
        key_file.chmod(0o644)
        with patch.object(dispatch, 'pinned_local_endpoint_address') as dns, \
                patch.object(dispatch, '_build_local_opener') as transport:
            with self.assertRaisesRegex(SystemExit, 'private regular file'):
                self.cli('--prepare-local-admission', key_file=key_file)
            key_file.chmod(0o600)
            directory.chmod(0o775)
            with self.assertRaisesRegex(SystemExit, 'directory writable only by its owner'):
                self.cli('--prepare-local-admission', key_file=key_file)
            directory.chmod(0o755)
            self.cli('--prepare-local-admission', key_file=key_file)
            self.assert_key_drift_refused(key_file)
            dns.assert_not_called()
            transport.assert_not_called()
        self.assertEqual(self.attempts(), [])
        self.assertEqual(self.calls, [])

    def assert_key_drift_refused(self, key_file):
        key_file.write_bytes(b'EXAMPLE-CHANGED-KEY\n')
        with self.assertRaisesRegex(SystemExit, 'differs from the original host admission'):
            self.cli('--execute-local', key_file=key_file)
        key_file.write_bytes(b'EXAMPLE-KEY\nEXAMPLE-ANOTHER\n')
        with self.assertRaisesRegex(SystemExit, 'one nonempty ASCII token'):
            self.cli('--execute-local', key_file=key_file)

    def test_cli_refuses_missing_original_record_and_endpoint_or_model_drift_before_effects(self):
        with patch.object(dispatch, 'pinned_local_endpoint_address') as dns, \
                patch.object(dispatch, '_build_local_opener') as transport:
            with self.assertRaisesRegex(SystemExit, 'original staged host record'):
                self.cli('--execute-local')
            self.cli('--prepare-local-admission')
            with self.assertRaisesRegex(SystemExit, 'differs from the original host admission'):
                self.cli('--execute-local', url='http://127.0.0.1:1')
            with self.assertRaisesRegex(SystemExit, 'original executor, provider, model or request options differ'):
                self.cli('--execute-local', model='EXAMPLE-different-model')
            dns.assert_not_called()
            transport.assert_not_called()
        self.assertEqual(self.attempts(), [])
        self.assertEqual(self.calls, [])

    def test_changed_whole_workload_or_reservation_ledger_refuses_before_socket(self):
        from tests.test_route_feasibility_preparation import bind

        self.cli('--prepare-local-admission')
        with patch.object(dispatch, 'pinned_local_endpoint_address') as dns, \
                patch.object(dispatch, '_build_local_opener') as transport:
            changed = workload_record()
            changed['route_input']['purpose'] += ' Separate unstaged planning context.'
            bind(changed['route_input'])
            self.store_workload(changed)
            with self.assertRaisesRegex(SystemExit, 'differs from the original host admission'):
                self.cli('--execute-local')
            self.store_workload(workload_record())
            replacement = InvocationLedger(self.directory / 'another-ledger')
            replacement.open_budget('another-budget', {'requests': 1}, scope_sha256='a' * 64)
            with patch.object(dispatch.local_http_admission.http, 'open_ledger', return_value=replacement):
                with self.assertRaisesRegex(SystemExit, 'original reservation ledger changed'):
                    self.cli('--execute-local')
            dns.assert_not_called()
            transport.assert_not_called()
        self.assertEqual(self.attempts(), [])
        self.assertEqual(self.calls, [])

    def test_dripping_response_expires_and_keeps_full_workload_charge(self):
        self.drip_response = True
        self.cli('--prepare-local-admission', timeout='1')
        started = time.monotonic()
        with self.assertRaisesRegex(SystemExit, 'deadline expired'):
            self.cli('--execute-local', timeout='1')
        self.assertLess(time.monotonic() - started, 2.6)
        self.assertEqual(len(self.calls), 1)
        admitted = next(attempt for attempt in self.attempts() if attempt['budget_id'] == 's57-workload-aggregate')
        self.assertEqual(admitted['outcome'], 'timeout')
        self.assertEqual(admitted['charge'], admitted['amount'])
        self.assertEqual(self.host.find('return-received'), [])
