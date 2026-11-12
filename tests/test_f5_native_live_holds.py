"""Held native routes: zero live launches and explicit fake positive controls."""
from __future__ import annotations

from contextlib import redirect_stderr
import io
import json
from pathlib import Path
from types import SimpleNamespace
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'scripts'), str(ROOT / 'tests')]

from cwo_core import native_live_availability as A  # noqa: E402
from cwo_core import maintenance_native_runtime as M  # noqa: E402
from cwo_core import maintenance_qualification as Q  # noqa: E402
from cwo_core.supervision.transport import app_server as T  # noqa: E402
import registered_n1_factory as N  # noqa: E402
import registered_n1_workflow as W  # noqa: E402
import registered_native_pool_retry as R  # noqa: E402
import run_native_pool_activation_preview as V  # noqa: E402
import run_native_pool_live_canaries as C  # noqa: E402
import run_admitted_native_pool_transaction as L  # noqa: E402
import check_codex_worker_surface as S  # noqa: E402
from tests import test_registered_n1_factory as NF  # noqa: E402
from tests import test_registered_native_pool_host as PF  # noqa: E402


class FakeLaunchReached(RuntimeError):
    """An intercepted test launch; no executable is started."""


class F5NativeLiveHoldTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(mock.patch.multiple(A, N1_LIVE_AVAILABLE=False,
            POOL_LIVE_AVAILABLE=False, CAMPAIGN_LIVE_AVAILABLE=False))

    def test_f5_held_route_constants_ship_off_in_a_fresh_interpreter(self):
        code = ("import sys; sys.path.insert(0, " + repr(str(ROOT / 'scripts')) + "); "
                "from cwo_core import native_live_availability as a; "
                "print(a.N1_LIVE_AVAILABLE, a.POOL_LIVE_AVAILABLE, a.CAMPAIGN_LIVE_AVAILABLE)")
        result = subprocess.run([sys.executable, '-I', '-c', code], capture_output=True, text=True, check=True)
        self.assertEqual(result.stdout, 'False False False\n')

    def test_r5_f5_held_n1_raw_library_zero_launch_and_patched_fake_launch(self):
        with mock.patch.object(T, '_codex_binary', return_value=Path('/EXAMPLE/fake-codex')) as binary, \
             mock.patch.object(T.subprocess, 'Popen', side_effect=FakeLaunchReached) as launch:
            with self.assertRaisesRegex(A.NativeLiveUnavailable, 'native-n1-live-unavailable'):
                T.AppServer()
            self.assertEqual((binary.call_count, launch.call_count), (0, 0))
            with mock.patch.object(A, 'N1_LIVE_AVAILABLE', True), self.assertRaises(FakeLaunchReached):
                T.AppServer(executable='/EXAMPLE/fake-codex', codex_home='/EXAMPLE/home')
            self.assertEqual(launch.call_count, 1)
            def hold_after_lookup(*args):
                A.N1_LIVE_AVAILABLE = False
                return Path('/EXAMPLE/home')
            with mock.patch.object(A, 'N1_LIVE_AVAILABLE', True), \
                 mock.patch.object(T, '_explicit_launch_home', side_effect=hold_after_lookup), \
                 self.assertRaises(A.NativeLiveUnavailable):
                T.AppServer(executable='/EXAMPLE/fake-codex', codex_home='/EXAMPLE/home')
            self.assertEqual(launch.call_count, 1)

    def test_f5_held_n1_registered_run_zero_effect_and_original_fake_launch_control(self):
        fixture = NF.FactoryTests('runTest')
        fixture._outcome = self._outcome
        fixture.setUp()
        self.addCleanup(NF.cleanup_helper, self, fixture)
        case = fixture.case()
        factory = fixture.factory(case)
        with mock.patch.object(A, 'N1_LIVE_AVAILABLE', False):
            with self.assertRaisesRegex(A.NativeLiveUnavailable, 'native-n1-live-unavailable'):
                factory.run()
        self.assertEqual(fixture.spawned, [])
        self.assertIs(factory._started, False)
        self.assertFalse((case.ledger.root / N.admission.ledger_api.LEDGER_FILE).exists())
        with mock.patch.object(A, 'N1_LIVE_AVAILABLE', True):
            factory.run()
        self.assertEqual(len(fixture.spawned), 2)
        self.assertIsNotNone(factory.issued_artifact())

    def test_f5_held_n1_direct_containment_zero_launch_and_fake_boundary_control(self):
        factory = SimpleNamespace(spec={'executable': '/EXAMPLE/fake-codex'}, require_effect=mock.Mock())
        lifetime = N._Containment(factory)
        with mock.patch.object(N.os, 'pipe', side_effect=FakeLaunchReached) as pipe:
            with self.assertRaises(A.NativeLiveUnavailable):
                lifetime.launch(['/EXAMPLE/fake-codex', 'app-server', '--stdio'], None)
            self.assertEqual((factory.require_effect.call_count, pipe.call_count), (0, 0))
            with mock.patch.object(A, 'N1_LIVE_AVAILABLE', True), self.assertRaises(FakeLaunchReached):
                lifetime.launch(['/EXAMPLE/fake-codex', 'app-server', '--stdio'], None)
            self.assertEqual((factory.require_effect.call_count, pipe.call_count), (1, 1))

    def test_f5_held_n1_workflow_maintenance_and_probes_before_claim_or_write(self):
        workflow = W.RegisteredN1Workflow.__new__(W.RegisteredN1Workflow)
        workflow._locked = mock.Mock(side_effect=FakeLaunchReached)
        runtime = M._Runtime.__new__(M._Runtime)
        runtime.prepared, runtime.plan = False, {}
        runtime._guard = mock.Mock(side_effect=FakeLaunchReached)
        capability = SimpleNamespace(evidence=mock.Mock(side_effect=FakeLaunchReached))
        with mock.patch.object(S, 'prepare_capture_binding', side_effect=FakeLaunchReached) as capture, \
             mock.patch.object(Q, 'require_maintenance_operation', return_value=capability), \
             mock.patch.object(S, 'ThreadingHTTPServer', side_effect=AssertionError) as listener, \
             mock.patch.object(Q, 'private_write', side_effect=AssertionError) as write:
            entries = ((workflow.run, workflow._locked), (lambda: runtime.prepare({}), runtime._guard),
                (lambda: S.capture_tool_request(codex_home=Path('/EXAMPLE'), requested_model='EXAMPLE', timeout_seconds=1), capture),
                (lambda: Q.observe_qualification(operation=None, verifier=None, plan=None, workspace=Path('/EXAMPLE'),
                    output=Path('/EXAMPLE/output'), session_ledger=None, tool_surface_proof={},
                    control_image_sha256='', fit_prompt=''), capability.evidence))
            for entry, guard in entries:
                with self.subTest(entry=entry), self.assertRaises(A.NativeLiveUnavailable):
                    entry()
                self.assertEqual(guard.call_count, 0)
                with mock.patch.object(A, 'N1_LIVE_AVAILABLE', True), self.assertRaises(FakeLaunchReached):
                    entry()
                self.assertEqual(guard.call_count, 1)
            self.assertEqual((listener.call_count, write.call_count), (0, 0))
        args = SimpleNamespace(timeout_seconds=1, profile='mutating', catalog_projection=None)
        with mock.patch.object(S.argparse.ArgumentParser, 'parse_args', return_value=args), \
             mock.patch.object(S, '_write_private_json', side_effect=AssertionError) as write, \
             self.assertRaises(A.NativeLiveUnavailable):
            S.main()
        self.assertEqual(write.call_count, 0)

    def test_f5_held_pool_zero_launch_despite_enabled_and_original_fake_launch_control(self):
        fixture = PF.PoolTests('runTest')
        fixture._outcome = self._outcome
        self.addCleanup(NF.cleanup_helper, self, fixture)
        fixture.cohort(1, enabled=True)
        fixture.adopt()
        request = fixture.config.request('execute')
        with mock.patch.multiple(A, N1_LIVE_AVAILABLE=False, POOL_LIVE_AVAILABLE=False):
            self.assertIs(fixture.host.run(fixture.config.request('validate-only'))['authority_validated'], True)
        with mock.patch.object(A, 'POOL_LIVE_AVAILABLE', False):
            with self.assertRaisesRegex(A.NativeLiveUnavailable, 'native-pool-live-unavailable'):
                fixture.host.run(request)
        self.assertEqual(list(fixture.state.iterdir()), [])
        self.assertIsNone(fixture.config.workflows[0].factory)
        self.assertFalse((fixture.ledger.root / N.admission.ledger_api.LEDGER_FILE).exists())
        with mock.patch.object(A, 'POOL_LIVE_AVAILABLE', True):
            report = fixture.host.run(request)
        self.assertEqual(report['states'], ['validated'])
        self.assertEqual(len(fixture.fixtures[0].fixture.spawned), 2)

    def test_f5_held_pool_retry_refuses_before_intent_and_patched_boundary_control(self):
        retry = R.ApprovedPoolRetry.__new__(R.ApprovedPoolRetry)
        retry.host = SimpleNamespace(_locked=mock.Mock(side_effect=FakeLaunchReached))
        for n1, pool in ((True, False), (False, True)):
            with self.subTest(n1=n1, pool=pool), mock.patch.multiple(A, N1_LIVE_AVAILABLE=n1, POOL_LIVE_AVAILABLE=pool):
                with self.assertRaises(A.NativeLiveUnavailable):
                    retry.run()
        self.assertEqual(retry.host._locked.call_count, 0)
        with mock.patch.multiple(A, N1_LIVE_AVAILABLE=True, POOL_LIVE_AVAILABLE=True), \
             self.assertRaises(FakeLaunchReached):
            retry.run()
        self.assertEqual(retry.host._locked.call_count, 1)

    def test_f5_held_pool_v8_multiworker_loader_refuses_before_operation_claim(self):
        capability = SimpleNamespace(claim=mock.Mock(side_effect=FakeLaunchReached))
        plan = {'version': 8, 'children': [{}, {}]}
        with mock.patch('cwo_core.maintenance_authority.require_maintenance_operation', return_value=capability), \
             mock.patch.object(A, 'N1_LIVE_AVAILABLE', True):
            with self.assertRaises(RuntimeError) as denied:
                L._load_runtime(plan)
            self.assertIsInstance(denied.exception, A.NativeLiveUnavailable)
            self.assertRegex(str(denied.exception), 'native-pool-live-unavailable')
            self.assertEqual(capability.claim.call_count, 0)
            with mock.patch.object(A, 'POOL_LIVE_AVAILABLE', True), self.assertRaises(FakeLaunchReached):
                L._load_runtime(plan)
            self.assertEqual(capability.claim.call_count, 1)

        # Execute the actual compile/exec seam with a top-level marker. A
        # post-import runtime type check cannot substitute for this ordering.
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / 'EXAMPLE-module-executed'
            source = (f"from pathlib import Path\nPath({str(marker)!r}).touch()\n"
                      "raise RuntimeError('EXAMPLE adapter top level')\n").encode()
            capability = SimpleNamespace(claim=mock.Mock(), adapter_path=Path('/EXAMPLE/adapter.py'),
                                         read_adapter_source=mock.Mock(return_value=source))
            with mock.patch('cwo_core.maintenance_authority.require_maintenance_operation', return_value=capability):
                for n1, pool in ((False, True), (True, False)):
                    with self.subTest(n1=n1, pool=pool), \
                         mock.patch.multiple(A, N1_LIVE_AVAILABLE=n1, POOL_LIVE_AVAILABLE=pool), \
                         self.assertRaises(A.NativeLiveUnavailable):
                        L._load_runtime(plan)
                    capability.claim.assert_not_called()
                    capability.read_adapter_source.assert_not_called()
                    self.assertFalse(marker.exists())
                with mock.patch.multiple(A, N1_LIVE_AVAILABLE=True, POOL_LIVE_AVAILABLE=True), \
                     self.assertRaisesRegex(RuntimeError, 'EXAMPLE adapter top level'):
                    L._load_runtime(plan)
                capability.claim.assert_called_once_with()
                capability.read_adapter_source.assert_called_once_with()
                self.assertTrue(marker.exists())

    def test_r1_f5_held_preview_routes_zero_launch_and_independent_fake_controls(self):
        with mock.patch.object(V, 'LIVE_ACTIVATION_AVAILABLE', True), \
             mock.patch.object(V, 'AppServer', return_value=object()) as launch:
            for profile in ('n1-read-only', 'n1-mutable', 'n2-read-only'):
                with self.subTest(profile=profile), self.assertRaises(V.LiveActivationUnavailable):
                    V._start_activation_server(profile)
            self.assertEqual(launch.call_count, 0)
            with mock.patch.object(A, 'N1_LIVE_AVAILABLE', True):
                for profile in ('n1-read-only', 'n1-mutable'):
                    self.assertIs(V._start_activation_server(profile), launch.return_value)
                with self.assertRaises(V.LiveActivationUnavailable):
                    V._start_activation_server('n2-read-only')
            self.assertEqual(launch.call_count, 2)
            with mock.patch.object(A, 'POOL_LIVE_AVAILABLE', True), self.assertRaises(V.LiveActivationUnavailable):
                V._start_activation_server('n2-read-only')
            with mock.patch.multiple(A, N1_LIVE_AVAILABLE=True, POOL_LIVE_AVAILABLE=True):
                self.assertIs(V._start_activation_server('n2-read-only'), launch.return_value)
            self.assertEqual(launch.call_count, 3)

    def test_f5_held_campaign_zero_launch_and_independent_patched_fake_control(self):
        with mock.patch.object(C, 'AppServer', return_value=object()) as launch:
            for n1, pool, campaign in ((False, True, True), (True, False, True), (True, True, False)):
                with self.subTest(n1=n1, pool=pool, campaign=campaign), \
                     mock.patch.multiple(A, N1_LIVE_AVAILABLE=n1, POOL_LIVE_AVAILABLE=pool, CAMPAIGN_LIVE_AVAILABLE=campaign), \
                     self.assertRaises(A.NativeLiveUnavailable):
                    C._start_campaign_server()
            self.assertEqual(launch.call_count, 0)
            with mock.patch.multiple(A, N1_LIVE_AVAILABLE=True, POOL_LIVE_AVAILABLE=True, CAMPAIGN_LIVE_AVAILABLE=True):
                self.assertIs(C._start_campaign_server(), launch.return_value)
            self.assertEqual(launch.call_count, 1)

    def test_f5_held_campaign_supplied_server_pool_entries_cannot_bypass_route_holds(self):
        server = mock.Mock()
        options = dict(root=Path('/EXAMPLE'), integration=Path('/EXAMPLE'), pool_name='EXAMPLE',
            worktrees=[], mutable=False, prompts=[], expected_tokens=[], pre_thread_start_check=mock.Mock())
        for n1, pool, campaign in ((False, True, True), (True, False, True), (True, True, False)):
            with self.subTest(n1=n1, pool=pool, campaign=campaign), \
                 mock.patch.multiple(A, N1_LIVE_AVAILABLE=n1, POOL_LIVE_AVAILABLE=pool, CAMPAIGN_LIVE_AVAILABLE=campaign):
                for entry in (C.run_pool_canary, C.build_pool_inputs):
                    with self.subTest(entry=entry.__name__), self.assertRaises(A.NativeLiveUnavailable):
                        entry(server, {}, {}, **options)
        self.assertEqual(server.mock_calls, [])
        with mock.patch.multiple(A, N1_LIVE_AVAILABLE=True, POOL_LIVE_AVAILABLE=True, CAMPAIGN_LIVE_AVAILABLE=True), \
             mock.patch.object(C.uuid, 'uuid4', side_effect=FakeLaunchReached) as boundary:
            for entry in (C.run_pool_canary, C.build_pool_inputs):
                with self.subTest(entry=entry.__name__), self.assertRaises(FakeLaunchReached):
                    entry(server, {}, {}, **options)
            self.assertEqual(boundary.call_count, 2)

    def test_f5_held_campaign_main_and_preclaim_zero_input_claim_write_or_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'EXAMPLE-output.json'
            args = SimpleNamespace(output=str(output))
            stderr = io.StringIO()
            with mock.patch.object(C.argparse.ArgumentParser, 'parse_args', return_value=args), \
                 mock.patch.object(C, 'load_private_json_snapshot', side_effect=AssertionError) as read, \
                 mock.patch.object(C, 'acquire_global_campaign_claim', side_effect=AssertionError) as claim, \
                 mock.patch.object(C, 'write_private_artifact', side_effect=AssertionError) as write, \
                 mock.patch.object(C, 'AppServer', side_effect=AssertionError) as launch, redirect_stderr(stderr):
                self.assertEqual(C.main(), 1)
                with self.assertRaises(A.NativeLiveUnavailable):
                    C.validate_and_acquire_global_campaign_claim(None, campaign_nonce='', authorization_id='',
                        authorization_sha256='', repo_head='', guarded_primary=output, output=output,
                        authorization_state=output, steering_registry=output, allocation_ledger=output)
                self.assertEqual((read.call_count, claim.call_count, write.call_count, launch.call_count), (0, 0, 0, 0))
            self.assertEqual(json.loads(stderr.getvalue())['failure_code'], 'native-campaign-live-unavailable')
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_n10_raw_rpc_rechecks_native_methods_after_construction_and_keeps_cleanup(self):
        """Already-created transports still refuse new native work at the wire."""
        def server():
            value = T.AppServer.__new__(T.AppServer)
            value.process = SimpleNamespace(stdin=io.StringIO(), poll=lambda: None)
            value._condition = threading.Condition()
            value._request_id, value._reader_error = 0, None
            value._responses = {1: {'id': 1, 'result': {}}}
            value.rpc_latencies = {}
            value._require_mcp_guard = mock.Mock()
            return value

        methods = ('thread/start', 'thread/resume', 'thread/fork', 'turn/start', 'config/mcpServer/reload',
                   'future/launch', 'thread/compact/start', 'command/exec', 'fs/writeFile', 'process/start', 'plugin/install',
                   'thread/read/extra', 'turn/interrupt ', 'Thread/archive', '')
        for method in methods:
            for api in ('notify', 'request', 'request_once_with_guard'):
                with self.subTest(method=method, api=api):
                    value, guard = server(), mock.Mock(return_value={})
                    options = {'timeout': .1, 'pre_dispatch_guard': guard} if api == 'request_once_with_guard' else {}
                    with self.assertRaisesRegex(A.NativeLiveUnavailable, 'native-n1-live-unavailable'):
                        getattr(value, api)(method, {}, **options)
                    self.assertEqual(value.process.stdin.getvalue(), '')
                    guard.assert_not_called()
                    with mock.patch.object(A, 'N1_LIVE_AVAILABLE', True):
                        getattr(value, api)(method, {}, **options)
                    payload = json.loads(value.process.stdin.getvalue())
                    self.assertEqual((payload['method'], payload['params']), (method, {}))
                    self.assertEqual(value.process.stdin.getvalue().count('\n'), 1)
        # A caller guard is a callout; lowering the hold there must deny the write.
        def revoke():
            A.N1_LIVE_AVAILABLE = False
            return {}
        for method in ('turn/start', 'future/launch'):
            value = server()
            with mock.patch.object(A, 'N1_LIVE_AVAILABLE', True), self.assertRaises(A.NativeLiveUnavailable):
                value.request_once_with_guard(method, {}, timeout=.1, pre_dispatch_guard=revoke)
            self.assertEqual(value.process.stdin.getvalue(), '')
        value = server()
        value._require_mcp_guard.side_effect = lambda *args: revoke()
        with mock.patch.object(A, 'N1_LIVE_AVAILABLE', True), self.assertRaises(A.NativeLiveUnavailable):
            value.request('turn/start', {}, timeout=.1)
        self.assertEqual(value.process.stdin.getvalue(), '')
        # Read, interruption and archive RPC remain usable for containment.
        for method in ('initialize', 'initialized', 'thread/read', 'turn/interrupt', 'thread/archive',
                       'thread/delete', 'model/list', 'mcpServerStatus/list'):
            for api in ('notify', 'request', 'request_once_with_guard'):
                with self.subTest(cleanup=method, api=api):
                    value, guard = server(), mock.Mock(return_value={})
                    options = {'timeout': .1, 'pre_dispatch_guard': guard} if api == 'request_once_with_guard' else {}
                    if api == 'request':
                        self.assertEqual(value.request(method, {}, timeout=.1)[0], {})
                    else:
                        result = getattr(value, api)(method, {}, **options)
                        if api == 'request_once_with_guard':
                            self.assertEqual(result[0], {})
                    self.assertEqual(json.loads(value.process.stdin.getvalue())['method'], method)
                    self.assertEqual(value.process.stdin.getvalue().count('\n'), 1)
        # Reuse the real dispatch/ledger fixture for the separate direct writer.
        from tests.test_run_native_pool_live_canaries import AmbiguousTurnDispatchTests
        fixture = AmbiguousTurnDispatchTests('runTest')
        fixture._outcome = self._outcome
        self.addCleanup(fixture.doCleanups)
        with tempfile.TemporaryDirectory() as directory:
            value, ledger, _state, writer, thread, _turns = fixture.server(Path(directory), 'normal')
            with mock.patch.object(ledger, 'turn_intent', wraps=ledger.turn_intent) as intent:
                with self.assertRaises(A.NativeLiveUnavailable):
                    value.start_turn(thread, 'EXAMPLE prompt')
                intent.assert_not_called()
            self.assertEqual(writer.payloads, [])
        for revoked in (True, False):
            with self.subTest(direct_turn_revoked=revoked), tempfile.TemporaryDirectory() as directory:
                value, _ledger, _state, writer, thread, _turns = fixture.server(Path(directory), 'normal')
                with mock.patch.object(A, 'N1_LIVE_AVAILABLE', True):
                    if revoked:
                        value._require_mcp_guard = lambda *args: revoke()
                        with self.assertRaises(A.NativeLiveUnavailable):
                            value.start_turn(thread, 'EXAMPLE prompt')
                    else:
                        value.start_turn(thread, 'EXAMPLE prompt')
                self.assertEqual(len(writer.payloads), 0 if revoked else 1)

    def test_n8_campaign_adapter_late_turn_rechecks_each_hold_and_keeps_generic_adapter(self):
        from tests import test_run_native_pool_live_canaries as fixtures
        fixture = fixtures.LiveThreadBoundaryPhaseTests('runTest')
        # Observe the selector from actual build_pool_inputs, then exercise that
        # selected contract on the functioning admitted fake-turn fixture.
        selected = []
        original_adapter = fixtures.LIVE.LiveThreadAdapter
        def capture_adapter(*args, **kwargs):
            value = original_adapter(*args, **kwargs)
            selected.append(value.campaign_live_route)
            return value
        with mock.patch.multiple(A, N1_LIVE_AVAILABLE=True, POOL_LIVE_AVAILABLE=True, CAMPAIGN_LIVE_AVAILABLE=True), \
             mock.patch.object(fixtures.LIVE, 'LiveThreadAdapter', side_effect=capture_adapter):
            fixtures.FullAutoAuthorizationLauncherTests(
                'test_pool_setup_forwards_bound_receipt_without_context_free_validation'
            ).test_pool_setup_forwards_bound_receipt_without_context_free_validation()
        self.assertEqual(len(selected), 2)
        # Omission must select the same campaign hold as the explicit pool route.
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(A, 'N1_LIVE_AVAILABLE', True):
            root = Path(directory)
            server = fixtures.FakeLiveThreadServer(root)
            adapter = C.LiveThreadAdapter(server, server.thread_response(), prompt='bounded prompt',
                expected_token='DONE', worktree=root, mutable=False, expected_mutation=None, record_dir=root)
            fixture.controller_bind_and_arm(adapter)
            with mock.patch.object(server, 'start_turn', wraps=server.start_turn) as wire:
                with self.assertRaisesRegex(A.NativeLiveUnavailable, 'native-campaign-live-unavailable'):
                    adapter.send_input(message='bounded prompt')
                wire.assert_not_called()
            with mock.patch.multiple(A, POOL_LIVE_AVAILABLE=True, CAMPAIGN_LIVE_AVAILABLE=True), \
                 mock.patch.object(server, 'start_turn', wraps=server.start_turn) as wire:
                adapter.send_input(message='bounded prompt')
                wire.assert_called_once_with(adapter.thread_id, 'bounded prompt')
        for stage in ('entry', 'late'):
            for held in ('N1_LIVE_AVAILABLE', 'POOL_LIVE_AVAILABLE', 'CAMPAIGN_LIVE_AVAILABLE', None):
                with self.subTest(stage=stage, held=held), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    server = fixtures.FakeLiveThreadServer(root)
                    with mock.patch.multiple(A, N1_LIVE_AVAILABLE=True, POOL_LIVE_AVAILABLE=True, CAMPAIGN_LIVE_AVAILABLE=True):
                        adapter = C.LiveThreadAdapter(server, server.thread_response(), prompt='bounded prompt',
                            expected_token='DONE', worktree=root, mutable=False, expected_mutation=None,
                            record_dir=root, campaign_live_route=selected[0])
                        fixture.controller_bind_and_arm(adapter)
                        original = adapter._require_effective_boundary
                        if stage == 'late':
                            def boundary(*args, **kwargs):
                                result = original(*args, **kwargs)
                                if held is not None and kwargs:
                                    setattr(A, held, False)
                                return result
                            adapter._require_effective_boundary = boundary
                        elif held is not None:
                            setattr(A, held, False)
                        with mock.patch.object(server, 'start_turn', wraps=server.start_turn) as wire:
                            if held is None:
                                adapter.send_input(message='bounded prompt')
                                wire.assert_called_once_with(adapter.thread_id, 'bounded prompt')
                            else:
                                with self.assertRaises(A.NativeLiveUnavailable):
                                    adapter.send_input(message='bounded prompt')
                                wire.assert_not_called()
        # A normal N1 adapter does not inherit an unrelated campaign/pool hold.
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(A, 'N1_LIVE_AVAILABLE', True):
            root = Path(directory)
            server = fixtures.FakeLiveThreadServer(root)
            adapter = fixture.adapter(Path(directory), server, fixtures.FakeMonotonicClock())
            with mock.patch.object(server, 'start_turn', wraps=server.start_turn) as wire:
                adapter.send_input(message='bounded prompt')
                wire.assert_called_once()
