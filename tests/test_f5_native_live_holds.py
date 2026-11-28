"""Held native routes: zero live launches and explicit fake positive controls."""
from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
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
from cwo_core.native_pool import LegacyNativePoolExecutionRetired  # noqa: E402
from cwo_core import maintenance_native_runtime as M  # noqa: E402
from cwo_core import maintenance_qualification as Q  # noqa: E402
from cwo_core.supervision.transport import app_server as T  # noqa: E402
import registered_n1_factory as N  # noqa: E402
import registered_n1_workflow as W  # noqa: E402
import registered_native_pool_host as P  # noqa: E402
import registered_native_pool_retry as R  # noqa: E402
import run_native_pool_activation_preview as V  # noqa: E402
import run_native_pool_live_canaries as C  # noqa: E402
import run_admitted_native_pool_transaction as L  # noqa: E402
import check_codex_worker_surface as S  # noqa: E402
from tests import test_registered_n1_factory as NF  # noqa: E402


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
             mock.patch.object(T, 'check_codex_capabilities') as capabilities, \
             mock.patch.object(T.subprocess, 'Popen', side_effect=FakeLaunchReached) as launch:
            with self.assertRaisesRegex(A.NativeLiveUnavailable, 'native-n1-live-unavailable'):
                T.AppServer()
            self.assertEqual((binary.call_count, launch.call_count), (0, 0))
            capabilities.assert_not_called()
            with mock.patch.object(A, 'N1_LIVE_AVAILABLE', True), self.assertRaises(FakeLaunchReached):
                T.AppServer(executable='/EXAMPLE/fake-codex', codex_home='/EXAMPLE/home')
            self.assertEqual(launch.call_count, 1)
            capabilities.assert_called_once_with('/EXAMPLE/fake-codex')
            def hold_after_lookup(*args):
                A.N1_LIVE_AVAILABLE = False
                return Path('/EXAMPLE/home')
            with mock.patch.object(A, 'N1_LIVE_AVAILABLE', True), \
                 mock.patch.object(T, '_explicit_launch_home', side_effect=hold_after_lookup), \
                 self.assertRaises(A.NativeLiveUnavailable):
                T.AppServer(executable='/EXAMPLE/fake-codex', codex_home='/EXAMPLE/home')
            self.assertEqual(launch.call_count, 1)
            capabilities.assert_called_once()

    def test_registered_production_source_decision_leaves_raw_launch_and_rpc_held(self):
        self.assertIs(A.REGISTERED_N1_LIVE_AVAILABLE, True)
        raw = T.AppServer.__new__(T.AppServer)
        with mock.patch.object(T.subprocess, 'Popen', side_effect=FakeLaunchReached) as spawn:
            A.require_registered_n1_live()
            with self.assertRaisesRegex(A.NativeLiveUnavailable, 'native-n1-live-unavailable'):
                T.AppServer(executable='/EXAMPLE/fake-codex', codex_home='/EXAMPLE/home')
            for method in ('thread/start', 'turn/start', 'thread/resume', 'command/exec'):
                with self.subTest(method=method), self.assertRaises(A.NativeLiveUnavailable):
                    T._require_native_rpc(method, raw)
            T._require_native_rpc('thread/archive', raw)
        spawn.assert_not_called()

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

    def test_partial_launch_pipe_allocation_closes_both_descriptors_and_keeps_primary(self):
        factory = SimpleNamespace(spec={'executable': '/EXAMPLE/fake-codex'}, require_effect=mock.Mock())
        lifetime = N._Containment(factory)
        failure = OSError('EXAMPLE namespace info pipe allocation failed')
        with mock.patch.object(A, 'N1_LIVE_AVAILABLE', True), \
             mock.patch.object(N.os, 'pipe', side_effect=[(51, 52), failure]) as pipe, \
             mock.patch.object(N.os, 'close') as close, \
             mock.patch.object(lifetime, '_provider_network_fds') as provider:
            with self.assertRaises(OSError) as raised:
                lifetime.launch(['/EXAMPLE/fake-codex', 'app-server', '--stdio'], None)
        self.assertIs(raised.exception, failure)
        self.assertEqual(pipe.call_count, 2)
        self.assertCountEqual(close.call_args_list, [mock.call(51), mock.call(52)])
        self.assertEqual(lifetime._fds, [])
        provider.assert_not_called()

    def test_f5_held_n1_workflow_maintenance_and_probes_before_claim_or_write(self):
        workflow = W.RegisteredN1Workflow.__new__(W.RegisteredN1Workflow)
        workflow._locked = mock.Mock(side_effect=FakeLaunchReached)
        runtime = M._Runtime.__new__(M._Runtime)
        runtime.prepared, runtime.plan = False, {}
        runtime._guard = mock.Mock(side_effect=FakeLaunchReached)
        for entry, guard in ((workflow.run, workflow._locked), (lambda: runtime.prepare({}), runtime._guard)):
            with self.subTest(entry=entry), self.assertRaises(A.NativeLiveUnavailable):
                entry()
            self.assertEqual(guard.call_count, 0)
            with mock.patch.object(A, 'N1_LIVE_AVAILABLE', True), self.assertRaises(FakeLaunchReached):
                entry()
            guard.assert_called_once()

    def test_retired_surface_probe_refuses_even_when_generic_n1_is_enabled(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            argv = ["probe", "--codex-home", str(root / "missing-home"),
                    "--output", str(root / "proof.json"), "--capture", str(root / "capture.json"),
                    "--host-evidence", str(root / "host.json")]
            for available in (False, True):
                with self.subTest(available=available), mock.patch.object(A, "N1_LIVE_AVAILABLE", available), \
                     mock.patch("cwo_core.codex_tool_surface.prepare_capture_binding",
                                side_effect=FakeLaunchReached) as bind, \
                     mock.patch("model_catalog_startup.configure_cli_model_catalog",
                                side_effect=FakeLaunchReached) as catalog, \
                     mock.patch("http.server.ThreadingHTTPServer", side_effect=FakeLaunchReached) as listener, \
                     mock.patch.object(T.subprocess, "Popen", side_effect=FakeLaunchReached) as launch, \
                     mock.patch.object(sys, "argv", argv):
                    with self.assertRaisesRegex(A.NativeLiveUnavailable, "^native-n1-live-unavailable$"):
                        S.capture_tool_request(codex_home=root / "missing-home", requested_model="EXAMPLE",
                                               timeout_seconds=1)
                    with self.assertRaisesRegex(A.NativeLiveUnavailable, "^native-n1-live-unavailable$"):
                        S.main()
                for effect in (bind, catalog, listener, launch):
                    effect.assert_not_called()
            self.assertEqual(list(root.iterdir()), [])

    def test_retired_maintenance_observer_validates_operation_before_unconditional_refusal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs = {"operation": None, "verifier": None, "plan": None, "workspace": root / "missing",
                      "output": root / "observation", "session_ledger": None, "tool_surface_proof": {},
                      "control_image_sha256": "", "fit_prompt": ""}
            operation = SimpleNamespace(evidence=mock.Mock(side_effect=FakeLaunchReached))
            for available in (False, True):
                with self.subTest(available=available), mock.patch.object(A, "N1_LIVE_AVAILABLE", available):
                    with self.assertRaisesRegex(ValueError, "opaque-operation-required"):
                        Q.observe_qualification(**inputs)
                    with mock.patch.object(Q, "require_maintenance_operation", return_value=operation) as verify, \
                         mock.patch.object(Q, "private_write", side_effect=FakeLaunchReached) as write, \
                         mock.patch.object(T, "AppServer", side_effect=FakeLaunchReached) as launch, \
                         self.assertRaisesRegex(A.NativeLiveUnavailable, "^native-n1-live-unavailable$"):
                        Q.observe_qualification(**inputs)
                    verify.assert_called_once_with(None, verifier=None, plan=None)
                    write.assert_not_called()
                    launch.assert_not_called()
            operation.evidence.assert_not_called()
            self.assertEqual(list(root.iterdir()), [])

    def test_f5_legacy_pool_holds_and_retirement_precede_effects(self):
        legacy = object.__new__(P.RegisteredNativePoolHost)
        request = {'version': 1, 'mode': 'execute', 'pool_id': 'EXAMPLE-pool', 'workers': ['EXAMPLE-worker']}
        with self.assertRaisesRegex(A.NativeLiveUnavailable, 'native-pool-live-unavailable'):
            legacy.run(request)
        with mock.patch.object(A, 'POOL_LIVE_AVAILABLE', True):
            with self.assertRaisesRegex(A.NativeLiveUnavailable, 'native-n1-live-unavailable'):
                legacy.run(request)
            with (mock.patch.object(A, 'N1_LIVE_AVAILABLE', True),
                  self.assertRaisesRegex(ValueError, 'registered-serial-pool-execution-retired')):
                legacy.run(request)

    def test_f5_legacy_retry_holds_and_retirement_precede_effects(self):
        retry = object.__new__(R.ApprovedPoolRetry)
        with self.assertRaisesRegex(A.NativeLiveUnavailable, 'native-pool-live-unavailable'):
            retry.run()
        with mock.patch.object(A, 'POOL_LIVE_AVAILABLE', True):
            with self.assertRaisesRegex(A.NativeLiveUnavailable, 'native-n1-live-unavailable'):
                retry.run()
            with (mock.patch.object(A, 'N1_LIVE_AVAILABLE', True),
                  self.assertRaisesRegex(ValueError, 'registered-serial-pool-retry-retired')):
                retry.run()

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

    def test_r1_f5_retired_preview_refuses_all_profiles_even_with_flags_on(self):
        with mock.patch.object(V, "LIVE_ACTIVATION_AVAILABLE", True), \
             mock.patch.multiple(A, N1_LIVE_AVAILABLE=True, POOL_LIVE_AVAILABLE=True), \
             mock.patch.object(V, "AppServer") as launch:
            for profile in ("n1-read-only", "n1-mutable", "n2-read-only"):
                with self.subTest(profile=profile), self.assertRaises(V.LiveActivationUnavailable):
                    V._start_activation_server(profile)
            launch.assert_not_called()

    def test_f5_campaign_server_refuses_without_a_launch(self):
        with mock.patch.object(C, 'AppServer') as launch:
            for n1, pool, campaign, code in (
                (False, True, True, 'native-n1-live-unavailable'),
                (False, False, True, 'native-pool-live-unavailable'),
                (False, False, False, 'native-campaign-live-unavailable'),
            ):
                with self.subTest(n1=n1, pool=pool, campaign=campaign), \
                     mock.patch.multiple(A, N1_LIVE_AVAILABLE=n1, POOL_LIVE_AVAILABLE=pool,
                                         CAMPAIGN_LIVE_AVAILABLE=campaign), \
                     self.assertRaisesRegex(A.NativeLiveUnavailable, '^' + code + '$'):
                    C._start_campaign_server()
            with mock.patch.multiple(A, N1_LIVE_AVAILABLE=True, POOL_LIVE_AVAILABLE=True,
                                     CAMPAIGN_LIVE_AVAILABLE=True), \
                 self.assertRaisesRegex(LegacyNativePoolExecutionRetired, '^legacy-pool-execution-retired$'):
                C._start_campaign_server()
        launch.assert_not_called()

    def test_f5_held_campaign_supplied_server_pool_entries_cannot_bypass_route_holds(self):
        server = mock.Mock()
        options = dict(root=Path('/EXAMPLE'), integration=Path('/EXAMPLE'), pool_name='EXAMPLE',
            worktrees=[], mutable=False, prompts=[], expected_tokens=[], pre_thread_start_check=mock.Mock())
        for n1, pool, campaign, exception, code in (
            (False, False, False, A.NativeLiveUnavailable, 'native-campaign-live-unavailable'),
            (False, False, True, A.NativeLiveUnavailable, 'native-pool-live-unavailable'),
            (False, True, True, A.NativeLiveUnavailable, 'native-n1-live-unavailable'),
            (True, True, True, LegacyNativePoolExecutionRetired, 'legacy-pool-execution-retired'),
        ):
            with mock.patch.multiple(A, N1_LIVE_AVAILABLE=n1, POOL_LIVE_AVAILABLE=pool,
                                     CAMPAIGN_LIVE_AVAILABLE=campaign):
                for entry in (C.run_pool_canary, C.build_pool_inputs):
                    with self.subTest(entry=entry.__name__, code=code), self.assertRaisesRegex(exception, '^' + code + '$'):
                        entry(server, {}, {}, **options)
        self.assertEqual(server.mock_calls, [])
        options["pre_thread_start_check"].assert_not_called()

    def test_retired_campaign_wrappers_refuse_with_all_holds_patched(self):
        inputs = mock.Mock()
        path = Path('/EXAMPLE/never-created')
        options = dict(output=path, authorization_state=path, steering_registry=path, allocation_ledger=path)
        with mock.patch.multiple(A, N1_LIVE_AVAILABLE=True, POOL_LIVE_AVAILABLE=True, CAMPAIGN_LIVE_AVAILABLE=True):
            with self.assertRaisesRegex(LegacyNativePoolExecutionRetired, '^legacy-pool-execution-retired$'):
                C.validate_and_acquire_global_campaign_claim(inputs, campaign_nonce='', authorization_id='',
                    authorization_sha256='', repo_head='', guarded_primary=path, **options)
        self.assertEqual(inputs.mock_calls, [])

    def test_f5_held_campaign_main_and_preclaim_zero_input_claim_write_or_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'EXAMPLE-output.json'
            argv = [C.__file__, '--output', str(output), '--authorization', str(output)]
            for n1, pool, campaign, exception, code in (
                (False, False, False, A.NativeLiveUnavailable, 'native-campaign-live-unavailable'),
                (False, False, True, A.NativeLiveUnavailable, 'native-pool-live-unavailable'),
                (False, True, True, A.NativeLiveUnavailable, 'native-n1-live-unavailable'),
                (True, True, True, LegacyNativePoolExecutionRetired, 'legacy-pool-execution-retired'),
            ):
                stderr = io.StringIO()
                stdout = io.StringIO()
                with self.subTest(code=code), \
                     mock.patch.multiple(A, N1_LIVE_AVAILABLE=n1, POOL_LIVE_AVAILABLE=pool,
                                         CAMPAIGN_LIVE_AVAILABLE=campaign), \
                     mock.patch.object(sys, 'argv', argv), \
                     mock.patch.object(C, 'seal_artifact', wraps=C.seal_artifact) as seal, \
                     mock.patch.object(C, 'load_private_json_snapshot') as read, \
                     mock.patch.object(C, 'acquire_global_campaign_claim') as claim, \
                     mock.patch.object(C, 'write_private_artifact') as write, \
                     mock.patch.object(C, 'AppServer') as launch, \
                     redirect_stderr(stderr), redirect_stdout(stdout):
                    self.assertEqual(C.main(), 1)
                    with self.assertRaisesRegex(exception, '^' + code + '$'):
                        C.validate_and_acquire_global_campaign_claim(None, campaign_nonce='', authorization_id='',
                            authorization_sha256='', repo_head='', guarded_primary=output, output=output,
                            authorization_state=output, steering_registry=output, allocation_ledger=output)
                    for effect in (read, claim, write, launch):
                        effect.assert_not_called()
                report = json.loads(stderr.getvalue())
                self.assertEqual(report, {
                    'release_gate_passed': False,
                    'failure_class': exception.__name__,
                    'failure_code': code,
                    'failure_message_sha256': C.sha256_text(code),
                    'evidence_sha256': report['evidence_sha256'],
                    'failure_evidence_persisted': False,
                })
                self._assert_zero_campaign_allocation(seal, report)
                self.assertEqual(stdout.getvalue(), '')
                self.assertEqual(list(Path(directory).iterdir()), [])

    def _assert_zero_campaign_allocation(self, seal, report):
        seal.assert_called_once()
        body, field = seal.call_args.args
        self.assertEqual(field, 'evidence_sha256')
        self.assertEqual(body['validation_outcome'], 'rejected')
        self.assertEqual(body['containment'], {
            'allocated_count': 0, 'identified_thread_count': 0, 'interrupted_count': 0,
            'archived_count': 0, 'already_contained_count': 0, 'unresolved_allocation_intent_count': 0,
            'unresolved_turn_intent_count': 0, 'ambiguous_count': 0, 'all_contained': True,
            'ledger_consistent': True, 'ledger_error_sha256': [],
        })
        self.assertIsNone(body['authorization_state_sha256'])
        self.assertIsNone(body['allocation_ledger'])
        self.assertEqual(body['steering_consumptions'], {})
        self.assertEqual(body['campaign_bindings'], {})
        self.assertEqual(report['evidence_sha256'], C.seal_artifact(body, field)[field])
        self.assertRegex(report['evidence_sha256'], '^[0-9a-f]{64}$')

    def test_retired_campaign_cli_ignores_missing_and_unknown_arguments(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / 'EXAMPLE-output.json'
            for arguments in ([], ['--authorization'], ['--unknown-option'], ['--help'],
                              ['--output', str(output), '--campaign-manifest', str(output)]):
                with self.subTest(arguments=arguments):
                    completed = subprocess.run([sys.executable, '-I', '-B', C.__file__, *arguments],
                                               cwd=root, capture_output=True, text=True, timeout=10)
                    self.assertEqual((completed.returncode, completed.stdout), (1, ''))
                    report = json.loads(completed.stderr)
                    self.assertEqual(report, {
                        'release_gate_passed': False,
                        'failure_class': 'NativeLiveUnavailable',
                        'failure_code': 'native-campaign-live-unavailable',
                        'failure_message_sha256': C.sha256_text('native-campaign-live-unavailable'),
                        'evidence_sha256': report['evidence_sha256'],
                        'failure_evidence_persisted': False,
                    })
                    self.assertRegex(report['evidence_sha256'], '^[0-9a-f]{64}$')
                    self.assertEqual(list(root.iterdir()), [])

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
                            record_dir=root, campaign_live_route=True)
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
