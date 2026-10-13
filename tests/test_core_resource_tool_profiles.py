"""Prospective profiles and actual RPC mechanics, using providerless fixtures only."""
from copy import deepcopy
import io
import json
from pathlib import Path
import sys
import threading
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import codex_tool_surface as surface
from cwo_core import native_tool_isolation as isolation
import run_native_pool_live_canaries as live
from tests.test_codex_tool_surface import ToolProfileProofTests, synthetic_empty_endpoint_inventory


class CoreProfileTests(unittest.TestCase):
    setUp = ToolProfileProofTests.setUp
    tearDown = ToolProfileProofTests.tearDown
    proof = ToolProfileProofTests.proof
    validate = ToolProfileProofTests.validate

    def test_exact_core_profiles_both_transports_no_legacy_expansion(self):
        for name, tools in isolation.CORE_RESOURCE_TOOL_PROFILES.items():
            mutable = name == 'mutating-core-resources-v2'
            policy = isolation.default_tool_policy(mutable=mutable, tool_profile=name)
            self.assertEqual(policy['version'], 2)
            self.assertEqual(policy['permitted_tools'], list(tools))
            self.assertEqual(isolation.normalize_tool_policy(policy), policy)
            for namespaced in (False, True):
                with self.subTest(profile=name, transport=namespaced):
                    proof = self.proof(list(tools), namespaced)
                    self.assertEqual(self.validate(proof, list(tools)), [])
                    self.assertEqual(proof['effect_policy']['sandbox'], 'workspaceWrite' if mutable else 'readOnly')
                    self.assertEqual(proof['process_binding']['endpoint_inventory']['before']['pages'][0]['response']['data'], [])
            with self.assertRaises(isolation.NativeToolIsolationError):
                isolation.default_tool_policy(mutable=not mutable, tool_profile=name)
            legacy = isolation.default_tool_policy(mutable=mutable)
            self.assertEqual(legacy['version'], 1)
            legacy['permitted_tools'] = list(tools)
            self.assertTrue(isolation.validate_tool_policy(legacy))

    def test_strict_profile_shapes_types_and_exact_sets(self):
        profile = 'read-only-core-resources-v2'
        policy = isolation.default_tool_policy(mutable=False, tool_profile=profile)
        for patch in ({'version': True}, {'version': 1}, {'version': 2.0}, {'tool_profile': 'mutating-core-resources-v2'},
                      {'permitted_tools': policy['permitted_tools'] + ['web_search']},
                      {'permitted_tools': policy['permitted_tools'][:-1]},
                      {'permitted_tools': sorted(policy['permitted_tools'] + ['write_stdin'])},
                      {'workload_class': 'safety-canary'}, {'enforcement_mode': 'trusted-detect-and-contain'}):
            with self.subTest(patch=patch):
                value = {**deepcopy(policy), **patch}
                self.assertTrue(isolation.validate_tool_policy(value))
        tools = list(isolation.CORE_RESOURCE_TOOL_PROFILES[profile])
        for bad in (tools + ['web_search'], tools[:-1], tools + ['write_stdin']):
            with self.assertRaises(surface.CodexToolSurfaceError): surface.normalized_tools(bad)

    def test_v4_parses_historically_but_never_dispatches(self):
        proof = self.proof()
        proof['version'] = 4
        proof.pop('effect_policy')
        binding = proof['capture_binding']
        binding.pop('effect_policy'); binding.pop('tool_profile')
        binding['binding_sha256'] = surface.canonical_sha256({k:v for k,v in binding.items() if k!='binding_sha256'})
        proof['process_binding']['capture_binding_sha256'] = binding['binding_sha256']
        proof['process_binding'].pop('endpoint_inventory')
        proof['proof_sha256'] = surface.canonical_sha256({k:v for k,v in proof.items() if k!='proof_sha256'})
        self.assertEqual(self.validate(proof), [])
        with mock.patch.object(surface,'_codex_binary',return_value=self.binary), mock.patch.object(surface,'_codex_version',return_value='test-version'), self.assertRaisesRegex(surface.CodexToolSurfaceError, 'historical-proof-not-dispatch-authority'):
            surface.require_surface_proof(proof, requested_model=self.captured['model'], permitted_tools=surface.EXACT_OPERATIVE_TOOLS)

    def test_proof_inventory_and_effect_tampering_cannot_reseal_to_success(self):
        tools = list(surface.EXACT_CORE_RESOURCE_READ_ONLY_TOOLS)
        original = self.proof(tools)
        edits = [lambda p:p['effect_policy'].update(network_access=0),
            lambda p:p['process_binding']['endpoint_inventory']['after'].update(thread_id='other'),
            lambda p:p['process_binding']['endpoint_inventory']['before']['pages'][0]['response'].update(data=[{'name':'disabled','status':'failed'}]),
            lambda p:p['capture_binding'].update(tool_profile='read-only-v1')]
        for edit in edits:
            with self.subTest(edit=edit):
                proof = deepcopy(original); edit(proof)
                proof['proof_sha256'] = surface.canonical_sha256({k:v for k,v in proof.items() if k!='proof_sha256'})
                self.assertTrue(self.validate(proof, tools))

    def test_three_packet_schema_sites_preserve_closed_v1_and_v2(self):
        import jsonschema
        def policies(node):
            if type(node) is dict:
                if 'tool_policy' in node.get('properties', {}): yield node['properties']['tool_policy']
                for value in node.values(): yield from policies(value)
            elif type(node) is list:
                for value in node: yield from policies(value)
        for filename in ('native-worker-packet.schema.json', 'native-supervision-pool-contract.schema.json', 'native-supervision-pool-render-request.schema.json'):
            document=json.loads((ROOT/'schemas'/filename).read_text())
            nodes=list(policies(document))
            self.assertEqual(len(nodes),1)
            nodes[0]=deepcopy(nodes[0])
            nodes[0]['$defs']=deepcopy(document.get('$defs', {}))
            for profile in isolation.CORE_RESOURCE_TOOL_PROFILES:
                policy=isolation.default_tool_policy(mutable=surface.tool_profile_is_mutable(profile), tool_profile=profile)
                jsonschema.validate(policy,nodes[0])
                for edit in ({'extra': True}, {'tool_profile':'read-only-v1'}, {'permitted_tools':policy['permitted_tools']+['view_image']}):
                    with self.assertRaises(jsonschema.ValidationError): jsonschema.validate({**policy,**edit},nodes[0])
            jsonschema.validate(isolation.default_tool_policy(mutable=True),nodes[0])


class EndpointInventoryTests(unittest.TestCase):
    def server(self):
        server = object.__new__(live.AppServer)
        server._condition = threading.Condition()
        server._mcp_guard_required = True
        server._mcp_endpoint_fault = None
        server._mcp_notification_generation = 0
        server._zero_mcp_observations = {}
        server._mcp_finalized_threads = set()
        server.started_threads = {'synthetic-thread': None}
        server.process = mock.Mock(pid=123)
        server.process.poll.return_value = None
        server.process.stdin = io.StringIO()
        server.connection_epoch_sha256 = 'e' * 64
        server._reader_error = None
        server._request_id = 0
        server._responses = {}
        server.rpc_latencies = {}
        server.request = mock.Mock(return_value=({'data': [], 'nextCursor': None}, 0))
        return server

    def test_actual_full_pagination_own_thread_request_shape_and_closed_result(self):
        server = self.server()
        server.request.side_effect = [({'data':[], 'nextCursor':'page2'},0), ({'data':[], 'nextCursor':None},0)]
        result = server.require_zero_mcp_endpoints('synthetic-thread')
        self.assertEqual(len(result['pages']),2)
        self.assertEqual([c.args for c in server.request.call_args_list], [
            ('mcpServerStatus/list',{'threadId':'synthetic-thread','detail':'full','limit':100,'cursor':None}),
            ('mcpServerStatus/list',{'threadId':'synthetic-thread','detail':'full','limit':100,'cursor':'page2'})])
        with self.assertRaises(live.AppServerError): server.require_zero_mcp_endpoints('foreign-thread')
        result['pages'][0]['response']['data'].append({'name':'fabricated'})
        self.assertEqual(server._zero_mcp_observations['synthetic-thread'][0]['pages'][0]['response']['data'],[])

    def test_any_endpoint_even_disabled_failed_or_toolless_latches_failure(self):
        for record in ({'name':'disabled','enabled':False}, {'name':'failed','status':'failed'}, {'name':'resource-only','tools':{}}):
            server=self.server();server.request.return_value=({'data':[record]},0)
            with self.assertRaisesRegex(live.AppServerError,'endpoints-not-empty'): server.require_zero_mcp_endpoints('synthetic-thread')
            server.request.return_value=({'data':[]},0)
            with self.assertRaises(live.AppServerError): server.require_zero_mcp_endpoints('synthetic-thread')

    def test_reentrant_notification_during_inventory_or_before_wire_denies(self):
        server=self.server()
        def reentrant(*args,**kwargs):
            server._observe_mcp_notification({'method':'mcpServer/startupStatus/updated','params':{'threadId':'synthetic-thread','name':'new'}})
            return {'data':[]},0
        server.request.side_effect=reentrant
        with self.assertRaises(live.AppServerError):server.require_zero_mcp_endpoints('synthetic-thread')
        self.assertEqual(server._zero_mcp_observations,{})
        server=self.server();server.require_zero_mcp_endpoints('synthetic-thread')
        def guard():
            server._observe_mcp_notification({'method':'mcpServer/startupStatus/updated','params':{}})
            return {'synthetic':True}
        with self.assertRaises(live.AppServerError):
            server.request_once_with_guard('turn/start', {'threadId':'synthetic-thread'},timeout=1,pre_dispatch_guard=guard)
        self.assertEqual(server.process.stdin.getvalue(),'')

    def test_final_inventory_is_actual_once_and_notification_latch_remains(self):
        server=self.server();server.require_zero_mcp_endpoints('synthetic-thread')
        thread={'id':'synthetic-thread','turns':[{'id':'turn','status':'completed'}]}
        server._guard_thread_observation('synthetic-thread',thread)
        server._guard_thread_observation('synthetic-thread',thread)
        self.assertEqual(server.request.call_count,2)
        server._observe_mcp_notification({'method':'mcpServer/startupStatus/updated','params':{}})
        with self.assertRaises(live.AppServerError):server._guard_thread_observation('synthetic-thread',thread)
        server=self.server();server.require_zero_mcp_endpoints('synthetic-thread')
        server.request.return_value=({'data':[{'name':'late'}]},0)
        with self.assertRaises(live.AppServerError):server._guard_thread_observation('synthetic-thread',thread)

    def test_inventory_raw_reader_strict_malformed_pagination_epoch_types(self):
        original=synthetic_empty_endpoint_inventory('synthetic-thread',123)
        changes=[lambda x:x.update(version=True), lambda x:x.update(pid=True), lambda x:x.update(notification_generation=False),
            lambda x:x.update(connection_epoch_sha256='f'*64), lambda x:x.update(pages=[]),
            lambda x:x['pages'][0]['request'].update(detail='toolsAndAuthOnly'),
            lambda x:x['pages'][0]['request'].pop('threadId'),
            lambda x:x['pages'][0]['response'].update(nextCursor='unread'),
            lambda x:x['pages'].append(deepcopy(x['pages'][0]))]
        for change in changes:
            value=deepcopy(original);change(value)
            with self.subTest(change=change), self.assertRaises(surface.CodexToolSurfaceError):
                surface.require_zero_endpoint_inventory(value,thread_id='synthetic-thread',pid=123,connection_epoch_sha256='e'*64)
        server=self.server();server.request.return_value=({'data':[],'nextCursor':'repeat'},0)
        with self.assertRaisesRegex(live.AppServerError,'cursor-invalid'):server.require_zero_mcp_endpoints('synthetic-thread')

    def test_unobserved_turn_and_reload_block_before_any_write(self):
        server=self.server()
        del server.request
        for method, params in [('turn/start',{'threadId':'synthetic-thread'}),('config/mcpServer/reload',{})]:
            with self.assertRaises(live.AppServerError):server.request(method,params,timeout=.01)
        self.assertEqual(server.process.stdin.getvalue(),'')

    def test_single_wire_turn_rechecks_after_reentrant_persistence(self):
        server=self.server()
        server._notifications=[]
        server.allocation_ledger=None
        server._known_thread_turn_ids={}
        records=[]
        def persist(record):
            records.append(record)
            if len(records)==2:
                server._observe_mcp_notification({'method':'mcpServer/startupStatus/updated','params':{}})
            return deepcopy(record)
        server._persist_turn_dispatch_record=persist
        with self.assertRaisesRegex(live.AppServerError,'endpoint-appearance'):
            server.start_turn('synthetic-thread','No provider request must occur.')
        self.assertEqual(server.process.stdin.getvalue(),'')
        self.assertEqual(len(records),2)

    def test_guarded_request_cannot_bypass_endpoint_reload_block(self):
        server=self.server()
        with self.assertRaisesRegex(live.AppServerError,'reload-forbidden'):
            server.request_once_with_guard('config/mcpServer/reload',{},timeout=.01,pre_dispatch_guard=lambda:{})
        self.assertEqual(server.process.stdin.getvalue(),'')
