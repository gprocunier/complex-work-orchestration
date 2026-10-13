"""Synthetic local-probe lifecycle tests; no provider or model qualification."""
import json
import contextlib
import io
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import check_codex_worker_surface as probe
from tests.test_codex_tool_surface import synthetic_empty_endpoint_inventory

class ProbeLifecycleTests(unittest.TestCase):
    def run_probe(self, *, wrong=None, close_failure=False, startup_failure=False, drift=False, turn_failure=False, workspace_cleanup_failure=False):
        listener=mock.Mock();listener.server_address=('127.0.0.1',12345)
        listener.socket.fileno.return_value=-1
        thread=mock.Mock();thread.ident=123;thread.is_alive.return_value=False
        event=mock.Mock();event.wait.return_value=True
        workspace=tempfile.TemporaryDirectory()
        remove_workspace=workspace.cleanup
        if workspace_cleanup_failure:workspace.cleanup=mock.Mock(side_effect=OSError('workspace-remove-failed'))
        captured={'model':'gpt-5.6-luna','tools':[{'name':'exec_command'},{'name':'write_stdin'}]}
        server=mock.Mock();server.codex_home=ROOT if wrong!='home' else ROOT/'wrong';server.launched_executable='/fixture/codex';server.process.pid=123;server.close.return_value={'all_contained':True,'resources_closed':True,'errors':[]};calls=[]
        server.started_threads = {}
        server.require_zero_mcp_endpoints.side_effect = lambda tid: synthetic_empty_endpoint_inventory(tid, 123)
        def request(method,params,**kw):
            calls.append((method,params))
            if method=='thread/start':
                self.assertFalse(params['allowProviderModelFallback'])
                response={'model':'gpt-5.6-luna','modelProvider':'cwo-loopback-probe','approvalPolicy':'never','sandbox':{'type':'readOnly','networkAccess':False},'thread':{'id':'fixture-thread'}}
                if wrong=='model':response['model']='wrong'
                if wrong=='provider':response['modelProvider']='real-provider'
                if wrong=='sandbox':response['sandbox']['type']='workspaceWrite'
                return response,0
            # Real synchronous callback inside turn/start, not two sequential observations.
            handler=handler_class[0].__new__(handler_class[0])
            import io
            payload=json.dumps(captured).encode();handler.headers={'content-length':str(len(payload))}
            handler.rfile=io.BytesIO(payload);handler.wfile=io.BytesIO()
            handler.send_response=mock.Mock();handler.send_header=mock.Mock();handler.end_headers=mock.Mock()
            handler.do_POST()
            self.assertTrue(event.set.called)
            if turn_failure:raise probe.AppServerError('synchronous-turn-failure')
            return {},0
        server.request.side_effect=request
        if close_failure:server.close.side_effect=OSError('synthetic-close-failure')
        binding={'codex_home':str(ROOT),'codex_binary':'/fixture/codex','binding_sha256':'a'*64,'lockdown_config':{'fixture':True},'lockdown_config_sha256':probe.canonical_sha256({'fixture':True}),'requested_model':'gpt-5.6-luna','requested_tools':['exec_command','write_stdin']}
        handler_class=[]
        def factory(address,klass):handler_class.append(klass);return listener
        try:
            with mock.patch.object(probe,'prepare_capture_binding',return_value=binding),mock.patch.object(probe,'require_capture_binding',side_effect=probe.CodexToolSurfaceError('codex-capture-binding-drift:codex_binary') if drift else None,return_value=binding),mock.patch.object(probe,'ThreadingHTTPServer',side_effect=factory),mock.patch.object(probe.threading,'Thread',return_value=thread),mock.patch.object(probe.threading,'Event',return_value=event),mock.patch.object(probe,'probe_thread_config',return_value={'fixture':True}),mock.patch.object(probe,'AppServer',side_effect=OSError('synthetic-start-failure') if startup_failure else None,return_value=server),mock.patch.object(probe.tempfile,'TemporaryDirectory',return_value=workspace):
                result=probe.capture_tool_request(codex_home=ROOT,requested_model='gpt-5.6-luna',timeout_seconds=1,permitted_tools=['exec_command','write_stdin'],catalog_projection=Path('/fixture/unused'))
                self.assertEqual(result,captured)
        finally:
            remove_workspace()  # Disposable mock process only; no live owner can remain.
            listener.shutdown.assert_not_called();listener.server_close.assert_called_once();thread.join.assert_called_once()
            if wrong or startup_failure or drift:self.assertFalse(any(c[0]=='turn/start' for c in calls))
        return calls

    def test_supported_readonly_and_synchronous_capture(self):self.run_probe()
    def test_wrong_model_provider_sandbox_stops_before_turn(self):
        for wrong in ['model','provider','sandbox']:
            with self.subTest(wrong=wrong),self.assertRaisesRegex(ValueError,'probe-thread-start-invalid'):self.run_probe(wrong=wrong)
    def test_cleanup_even_when_server_close_fails(self):
        with self.assertRaisesRegex(ValueError,'synthetic-close-failure'):self.run_probe(close_failure=True)
    def test_cleanup_on_startup_failure(self):
        with self.assertRaisesRegex(OSError,'synthetic-start-failure'):self.run_probe(startup_failure=True)
    def test_malformed_profile_fails_before_listener_or_server(self):
        for value in [None,{},[{}],['exec_command',{}]]:
            with mock.patch.object(probe,'ThreadingHTTPServer') as listener,mock.patch.object(probe,'AppServer') as server,self.assertRaises(ValueError):
                probe.capture_tool_request(codex_home=ROOT,requested_model='gpt-5.6-luna',timeout_seconds=1,permitted_tools=value)
            listener.assert_not_called();server.assert_not_called()

    def test_wrong_initialized_home_is_rejected_before_turn(self):
        with self.assertRaisesRegex(ValueError,'home-or-binary-mismatch'):self.run_probe(wrong='home')

    def test_primary_error_not_masked_by_cleanup(self):
        with self.assertRaisesRegex(ValueError,'probe-thread-start-invalid') as caught:self.run_probe(wrong='model',close_failure=True)
        self.assertIn('synthetic-close-failure',str(caught.exception.probe_cleanup_errors))

    def test_drift_before_turn_prevents_dispatch(self):
        with self.assertRaisesRegex(ValueError,'capture-binding-drift'):self.run_probe(drift=True)

    def test_actual_synchronous_callback_then_failure_is_contained(self):
        with self.assertRaisesRegex(probe.AppServerError,'synchronous-turn-failure') as caught:
            self.run_probe(turn_failure=True)
        self.assertIs(caught.exception.app_server_cleanup['all_contained'],True)
        self.assertIs(caught.exception.probe_cleanup['listener_closed'],True)

    def test_workspace_cleanup_failure_is_not_success_or_primary_error_masking(self):
        for turn_failure in (False,True):
            expected='synchronous-turn-failure' if turn_failure else 'probe-cleanup-failed'
            with self.subTest(turn_failure=turn_failure),self.assertRaisesRegex(Exception,expected) as caught:
                self.run_probe(turn_failure=turn_failure,workspace_cleanup_failure=True)
            self.assertIn('workspace-remove-failed',str(caught.exception.probe_cleanup_errors))


class ListenerOwnershipTests(unittest.TestCase):
    """Real local sockets/threads; no Codex process or provider request."""

    def check_startup_failure(self, mode):
        servers=[];threads=[];real_server=probe.ThreadingHTTPServer;real_thread=threading.Thread
        def server_factory(*args):
            server=real_server(*args);servers.append(server);return server
        def thread_factory(*args, **kwargs):
            if mode=='constructor':raise RuntimeError('thread-constructor-failed')
            thread=real_thread(*args,**kwargs);threads.append(thread);start=thread.start
            def fail_start():
                if mode=='partial-start':start()
                raise RuntimeError('thread-start-failed')
            thread.start=fail_start;return thread
        evidence={};started=time.monotonic()
        try:
            with mock.patch.object(probe,'prepare_capture_binding',return_value={}), \
                    mock.patch.object(probe,'ThreadingHTTPServer',side_effect=server_factory), \
                    mock.patch.object(probe.threading,'Thread',side_effect=thread_factory), \
                    mock.patch.object(probe,'AppServer') as app:
                with self.assertRaisesRegex(RuntimeError,'thread-.*-failed'):
                    probe.capture_tool_request(codex_home=ROOT,requested_model='gpt-5.6-luna',
                                               timeout_seconds=1,evidence=evidence)
                app.assert_not_called()
            self.assertLess(time.monotonic()-started,3)
            self.assertEqual(servers[0].socket.fileno(),-1)
            self.assertTrue(all(not t.is_alive() for t in threads))
            with socket.socket() as check:check.bind(servers[0].server_address)
            self.assertIs(evidence['probe_cleanup']['all_contained'],True)
        finally:
            for server in servers:server.server_close()

    def test_real_listener_closed_when_thread_constructor_fails(self):self.check_startup_failure('constructor')
    def test_real_listener_closed_when_thread_start_fails(self):self.check_startup_failure('start')
    def test_real_started_thread_is_joined_when_start_raises_after_starting(self):self.check_startup_failure('partial-start')

    def test_primary_and_listener_cleanup_failures_both_preserved(self):
        listener=mock.Mock();listener.server_address=('127.0.0.1',12345)
        listener.server_close.side_effect=OSError('socket-close-failed');listener.socket.fileno.return_value=5
        evidence={}
        with mock.patch.object(probe,'prepare_capture_binding',return_value={}), \
                mock.patch.object(probe,'ThreadingHTTPServer',return_value=listener), \
                mock.patch.object(probe.threading,'Thread',side_effect=RuntimeError('original-start')):
            with self.assertRaisesRegex(RuntimeError,'original-start') as caught:
                probe.capture_tool_request(codex_home=ROOT,requested_model='gpt-5.6-luna',timeout_seconds=1,evidence=evidence)
        self.assertIn('socket-close-failed',str(caught.exception.probe_cleanup_errors))
        self.assertIs(evidence['probe_cleanup']['all_contained'],False)
        self.assertIs(evidence['probe_cleanup']['listener_closed'],False)

    def test_constructor_cleanup_report_survives_capture(self):
        error=probe.AppServerError('initialize-original')
        error.app_server_cleanup={'all_contained':False,'resources_closed':False,'pid':123,'errors':['kill-failed']}
        binding={'lockdown_config_sha256':probe.canonical_sha256({})}
        evidence={}
        with mock.patch.object(probe,'prepare_capture_binding',return_value=binding), \
                mock.patch.object(probe,'probe_thread_config',return_value={}), \
                mock.patch.object(probe,'AppServer',side_effect=error):
            with self.assertRaisesRegex(probe.AppServerError,'initialize-original'):
                probe.capture_tool_request(codex_home=ROOT,requested_model='gpt-5.6-luna',timeout_seconds=1,evidence=evidence)
        self.assertEqual(evidence['process_cleanup']['pid'],123)
        self.assertIs(evidence['process_cleanup']['all_contained'],False)
        self.assertIs(evidence['probe_cleanup']['listener_closed'],True)


class ProbeFailureCliTests(unittest.TestCase):
    def test_proof_and_failure_evidence_write_failure_never_persists_acceptance(self):
        writes=[];stdout=io.StringIO()
        def write(path,value):
            writes.append((path,dict(value)))
            if len(writes)==2:raise OSError('proof-write-failed')
            if len(writes)==3:raise OSError('failure-evidence-write-failed')
        def capture(**kw):
            kw['evidence'].update(capture_binding={},process_binding={});return {}
        with mock.patch.object(probe,'capture_tool_request',side_effect=capture), \
                mock.patch.object(probe,'build_surface_proof',return_value={}), \
                mock.patch.object(probe,'validate_surface_proof',return_value=[]), \
                mock.patch.object(probe,'_write_private_json',side_effect=write), \
                mock.patch.object(sys,'argv',['probe','--model','gpt-5.6-luna','--output','/not-written/proof','--host-evidence','/not-written/host']), \
                contextlib.redirect_stdout(stdout):
            self.assertEqual(probe.main(),1)
        result=json.loads(stdout.getvalue())
        self.assertEqual(result['error'],'proof-write-failed')
        self.assertIn('failure-evidence-write-failed',result['evidence_write_error'])
        self.assertIsNot(writes[0][1].get('accepted'),True)
        self.assertFalse(writes[2][1]['accepted'])

    def invoke(self, error, *, write_failure=False):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);output=root/'proof.json';host=root/'host.json';stdout=io.StringIO()
            writer=mock.patch.object(probe,'_write_private_json',side_effect=OSError('evidence-disk-full')) if write_failure else contextlib.nullcontext()
            with mock.patch.object(probe,'capture_tool_request',side_effect=error),writer, \
                    mock.patch.object(sys,'argv',['probe','--model','gpt-5.6-luna','--output',str(output),'--host-evidence',str(host)]), \
                    contextlib.redirect_stdout(stdout):
                status=probe.main()
            self.assertFalse(output.exists())
            durable=json.loads(host.read_text()) if host.exists() else None
            if host.exists():self.assertEqual(host.stat().st_mode & 0o777,0o600)
            return status,json.loads(stdout.getvalue()),durable

    def test_original_and_cleanup_failure_are_persisted_privately(self):
        error=probe.AppServerError('initialize-original')
        error.app_server_cleanup={'all_contained':False,'resources_closed':False,'pid':123,'errors':['kill-failed']}
        error.probe_cleanup_errors=['listener-close-failed'];error.add_note('separate cleanup note')
        status,printed,durable=self.invoke(error)
        self.assertEqual(status,1);self.assertEqual(printed['error'],'initialize-original')
        self.assertEqual(printed['app_server_cleanup'],error.app_server_cleanup)
        for key,value in printed.items():self.assertEqual(durable[key],value)
        self.assertEqual(durable['provider_model_calls'],0);self.assertFalse(durable['qualification'])

    def test_evidence_failure_does_not_mask_original_or_cleanup(self):
        error=probe.AppServerError('primary')
        error.app_server_cleanup={'all_contained':False,'resources_closed':False,'pid':123,'errors':['kill-failed']}
        status,printed,durable=self.invoke(error,write_failure=True)
        self.assertEqual(status,1);self.assertEqual(printed['error'],'primary')
        self.assertIn('evidence-disk-full',printed['evidence_write_error'])
        self.assertEqual(printed['app_server_cleanup']['errors'],['kill-failed']);self.assertIsNone(durable)

    def test_unknown_or_malformed_cleanup_never_becomes_contained(self):
        for report in (None,{},[],{'all_contained':0,'resources_closed':1,'errors':[]}):
            error=RuntimeError('startup');error.app_server_cleanup=report
            with self.subTest(report=report):
                status,printed,durable=self.invoke(error)
                self.assertEqual(status,1)
                self.assertIsNone(printed['app_server_cleanup']['all_contained'])
                self.assertIsNone(durable['app_server_cleanup']['resources_closed'])

    def test_interrupt_stays_failure_with_cleanup_evidence(self):
        error=KeyboardInterrupt();error.app_server_cleanup={'all_contained':True,'resources_closed':True,'errors':[]}
        status,printed,durable=self.invoke(error)
        self.assertEqual(status,130);self.assertFalse(printed['accepted'])
        self.assertEqual(durable['error_type'],'KeyboardInterrupt')
