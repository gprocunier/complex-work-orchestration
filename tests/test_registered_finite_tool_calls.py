"""Pinned dynamic-tool wire and exact captured-catalog negatives.

The positive original caller/process schedule belongs to the registered N1 factory
integration; these cases do not replace that end-to-end evidence.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import registered_finite_tool_calls as tools  # noqa: E402


class RegisteredFiniteToolWireTests(unittest.TestCase):
    def setUp(self):
        self.model = 'EXAMPLE-model'
        self.capture = {'model': self.model, 'tools': tools._response_tools()}

    def test_exact_captured_catalog_refuses_builtin_and_mixed_surfaces(self):
        expected = tools._digest(self.capture)
        self.assertEqual(tools.require_exact_capture(self.model, self.capture), expected)
        for changed in (
            {'model': 'EXAMPLE-fallback', 'tools': self.capture['tools']},
            {'model': self.model, 'tools': self.capture['tools'] + [{'name': 'write_stdin'}]},
            {'model': self.model, 'tools': self.capture['tools'] + [{'name': 'exec_command'}]},
            {'model': self.model, 'tools': [self.capture['tools'][0]]},
            {'model': self.model, 'tools': list(reversed(self.capture['tools']))},
            {**self.capture, 'input': [{'type': 'additional_tools', 'tools': []}]},
        ):
            with self.subTest(changed=changed):
                with self.assertRaises(tools.FiniteToolError):
                    tools.require_exact_capture(self.model, changed)
        changed = copy.deepcopy(self.capture)
        changed['tools'][1]['parameters']['properties']['chars']['type'] = 'object'
        with self.assertRaises(tools.FiniteToolError):
            tools.require_exact_capture(self.model, changed)

    def test_pinned_dynamic_tool_request_and_response_shapes(self):
        pinned = ROOT / 'tests/fixtures/codex-protocol-provisional/0.164.0/stable/codex_app_server_protocol.schemas.json'
        schemas = json.loads(pinned.read_text())['definitions']
        params = schemas['DynamicToolCallParams']['properties']
        response = schemas['DynamicToolCallResponse']['properties']
        self.assertEqual(set(schemas['DynamicToolCallParams']['required']),
                         {'arguments', 'callId', 'threadId', 'tool', 'turnId'})
        self.assertEqual(set(params), {'arguments', 'callId', 'namespace', 'threadId', 'tool', 'turnId'})
        self.assertEqual(set(schemas['DynamicToolCallResponse']['required']), {'contentItems', 'success'})
        self.assertEqual(set(response), {'contentItems', 'success'})
        self.assertEqual([tool['name'] for tool in tools.RegisteredFiniteToolCalls.thread_parameters()['dynamicTools']],
                         ['finite_command', 'finite_poll'])

    def test_unknown_and_malformed_dynamic_requests_refuse_before_process(self):
        base = {'id': 'EXAMPLE-request', 'method': 'item/tool/call', 'params': {
            'arguments': {'command': 'EXAMPLE-command'}, 'callId': 'EXAMPLE-call',
            'threadId': 'EXAMPLE-thread', 'turnId': 'EXAMPLE-turn',
            'tool': 'finite_command'}}
        request, params = tools.RegisteredFiniteToolCalls._params(base)
        self.assertEqual(request.method, 'item/tool/call')
        self.assertEqual(params['callId'], 'EXAMPLE-call')
        for change in ({'tool': 'write_stdin'}, {'namespace': 'functions'},
                       {'callId': ''}, {'extra': True}):
            message = copy.deepcopy(base)
            message['params'].update(change)
            with self.subTest(change=change):
                with self.assertRaises(tools.FiniteToolError):
                    tools.RegisteredFiniteToolCalls._params(message)
        message = copy.deepcopy(base)
        message['method'] = 'item/tool/requestUserInput'
        with self.assertRaises(tools.FiniteToolError):
            tools.RegisteredFiniteToolCalls._params(message)

    def test_offline_capture_file_refuses_public_mode_symlink_and_duplicate_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'finite-tool-capture.json'
            path.write_text('{"start":{},"response":{},"request":{}}', encoding='utf-8')
            path.chmod(0o600)
            raw, identity = tools._read_capture_file(path)
            self.assertEqual(json.loads(raw), {'start': {}, 'response': {}, 'request': {}})
            self.assertEqual(identity[1], path.stat().st_ino)
            captured = tools.CapturedToolSurface(tools._CAPTURE_TOKEN, None, None,
                                                 'EXAMPLE-epoch', raw, identity)
            changed = captured.payload
            changed['request']['tools'] = [{'name': 'write_stdin'}]
            self.assertEqual(captured.payload['request'], {})
            path.chmod(0o644)
            with self.assertRaises(tools.FiniteToolError):
                tools._read_capture_file(path)
            path.chmod(0o600)
            alias = Path(directory) / 'alias.json'
            alias.symlink_to(path)
            with self.assertRaises(OSError):
                tools._read_capture_file(alias)
            with self.assertRaises(tools.FiniteToolError):
                json.loads('{"model":"EXAMPLE","model":"OTHER"}',
                           object_pairs_hook=tools._unique_object)


if __name__ == '__main__':
    unittest.main()
