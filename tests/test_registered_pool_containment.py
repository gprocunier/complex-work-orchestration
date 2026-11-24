"""Check the contained pool host with synthetic files and inert stdio peers."""

from hashlib import sha256
from pathlib import Path
import select
import sys
import tempfile
from threading import RLock
import time
import tomllib
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))

import registered_pool_configuration as config
import registered_pool_containment as containment
import registered_n1_qualification as qualification
from cwo_core import native_live_availability as availability


class PoolConfigurationTests(unittest.TestCase):
    @patch.object(availability, 'POOL_QUALIFICATION_AVAILABLE', True)
    def test_open_source_still_refuses_a_raw_worker_before_private_paths(self):
        with patch.object(containment.native, '_path', side_effect=AssertionError('private path reached')) as path:
            with self.assertRaisesRegex(config.PoolContainmentError, 'Original retained pool worker required'):
                containment.PoolWorkerContainment(
                    worker_id='fixture', worktree=None, spool=None, login_slot=1, executable=None, launcher=None,
                    validator=None, executable_sha256=None, launcher_sha256=None, validator_sha256=None,
                    protected_roots=(), write_path='marker.txt', expected_utf8='fixture', require_effect=lambda: None,
                )
            path.assert_not_called()

    def test_raw_writer_cannot_replace_original_retained_authorization(self):
        worker = object.__new__(containment.PoolWorkerContainment)
        worker._lock = RLock()
        worker._authorize_effect = self.test_raw_writer_cannot_replace_original_retained_authorization
        with (patch.object(worker, 'require_effect'), patch.object(worker, '_run_writer') as launch,
              self.assertRaisesRegex(config.PoolContainmentError, 'Original retained pool writer required')):
            worker.run_writer('fixture', authorize=lambda release: release(), deadline=time.monotonic() + 1)
        launch.assert_not_called()

    def test_immutable_configuration_and_writer_registration(self):
        worker, spool = Path('/fixture/worker'), Path('/fixture/private-spool')
        raw = (b'{"models":[{"slug":"gpt-6.2-sol","tool_mode":"code_mode_only","multi_agent_version":"v2",'
               b'"experimental_supported_tools":["clock","test_sync_tool","send_message_to_user_async"],'
               b'"apply_patch_tool_type":"freeform"}]}')
        catalog = config.trim_model_catalog(raw, source_sha256=sha256(raw).hexdigest())
        config.require_trimmed_model_catalog(catalog, sha256(catalog).hexdigest())
        with self.assertRaises(config.PoolContainmentError):
            config.require_trimmed_model_catalog(raw, sha256(raw).hexdigest())
        self.assertNotIn(b'apply_patch_tool_type', catalog)
        self.assertNotIn(b'multi_agent_version', catalog)
        self.assertIn(b'"experimental_supported_tools":[]', catalog)
        self.assertIn(b'"tool_mode":"direct"', catalog)
        files = config.configuration_files(worker, spool, catalog=catalog)
        settings = tomllib.loads(files['config.toml'].decode())
        self.assertEqual(settings['model_catalog_json'], str(spool / config.CATALOG_NAME))
        self.assertFalse(settings['features']['code_mode']['enabled'])
        self.assertFalse(settings['features']['shell_tool'])
        self.assertFalse(settings['agents']['enabled'])
        permission = settings['permissions'][config.PROFILE]
        self.assertEqual(permission, {'filesystem': {'/': 'deny', str(worker): 'read',
                                                       str(qualification.LOGIN_MOUNT): 'deny'},
                                      'network': {'enabled': False}})
        fallback = tomllib.loads(config.configuration_files(worker, spool)['config.toml'].decode())
        self.assertNotIn('model_catalog_json', fallback)
        self.assertEqual(fallback['features']['code_mode']['direct_only_tool_namespaces'], ['cwo_finite'])
        registered, = config.thread_start_selectors(worker)['dynamicTools']
        self.assertEqual(registered['name'], 'cwo_finite')
        tool, = registered['tools']
        self.assertEqual(tool['name'], 'finite_command')
        self.assertEqual(tool['inputSchema']['properties']['command']['enum'], [config.WRITER_COMMAND])

    def test_later_turn_cannot_widen_its_selectors(self):
        turn = {'threadId': 'thread-one', 'model': qualification.MODEL, 'effort': qualification.EFFORT,
                'serviceTier': qualification.TIER, 'input': []}
        config.require_turn_selectors(turn, thread_id='thread-one')
        for drift in ({'model': 'default'}, {'serviceTier': 'fast'}, {'effort': 'max'},
                      {'threadId': 'thread-two'}, {'cwd': '/outside'}, {'permissions': ':workspace'},
                      {'sandboxPolicy': {'type': 'dangerFullAccess'}}, {'approvalPolicy': 'on-request'}):
            with self.subTest(drift=drift), self.assertRaises(config.PoolContainmentError):
                config.require_turn_selectors({**turn, **drift}, thread_id='thread-one')

    def test_named_profile_refuses_a_missing_or_widened_login_deny_rule(self):
        worktree = Path('/fixture/worker')
        raw = config.configuration_files(worktree, Path('/fixture/spool'))['config.toml']
        rule = f'"{qualification.LOGIN_MOUNT}" = "deny"\n'.encode()
        config.require_named_deny_policy(worktree, raw)
        for changed in (raw.replace(rule, b''), raw.replace(rule, rule.replace(b'"deny"', b'"read"'))):
            with self.assertRaisesRegex(config.PoolContainmentError, 'named login deny policy'):
                config.require_named_deny_policy(worktree, changed)


class _InertBroker:
    def __init__(self):
        self.closed = False
        self.revoked = False

    def revoke(self):
        self.revoked = True

    def close(self):
        self.closed = True


class PoolWorkerContainmentTests(unittest.TestCase):
    def setUp(self):
        workspace = tempfile.TemporaryDirectory(prefix='cwo-pool-containment-', dir='/tmp')
        self.addCleanup(workspace.cleanup)
        self.root = Path(workspace.name)
        self.slots = {slot: self.root / f'login-{slot}' for slot in (1, 2, 3)}
        for slot, directory in self.slots.items():
            directory.mkdir(mode=0o700)
            auth = directory / 'auth.json'
            auth.write_text(f'synthetic marker {slot}\n')
            auth.chmod(0o600)
        self.state = self.root / 'campaign'
        self.launcher = Path('/usr/bin/bwrap').resolve()
        self.validator = Path('/usr/bin/python3').resolve()
        self.peer = self.root / 'inert-appserver'
        self.peer.write_text(f"""#!{self.validator}
import errno, pathlib, sys
assert sys.argv[1:] == ['app-server', '--stdio']
try:
    pathlib.Path('appserver-side-effect.txt').write_text('unexpected write')
except OSError as error:
    assert error.errno == errno.EROFS
else:
    raise AssertionError('App-server worktree was writable')
print('read-only inert app server', flush=True)
assert sys.stdin.read() == ''
""")
        self.peer.chmod(0o700)
        self.enterContext(patch.object(qualification, 'managed_login_home', side_effect=lambda slot=1: self.slots[slot]))
        self.enterContext(patch.object(qualification, '_campaign_directory', return_value=self.state))
        self.enterContext(patch.object(availability, 'require_registered_n1_live'))
        self.enterContext(patch.object(availability, 'require_pool_qualification', create=True))
        self.enterContext(patch.object(qualification, 'require_executable_schema'))
        self.enterContext(patch.object(containment, '_require_original_worker', side_effect=lambda effect, *_: effect()))
        self.enterContext(patch.object(containment, '_require_original_writer'))
        qualification.initialize_campaign()

    def _paths(self, slot):
        worktree, custody = self.root / f'worker-{slot}', self.root / f'custody-{slot}'
        for path in (worktree, worktree / '.git', custody, custody / 'codex-home'):
            path.mkdir(mode=0o700)
        return worktree, custody / 'codex-home'

    def _worker(self, slot, paths, protected=()):
        worker, spool = paths
        worker = containment.PoolWorkerContainment(
            worker_id=f'worker-{slot}', worktree=worker, spool=spool, login_slot=slot,
            executable=self.peer, executable_sha256=sha256(self.peer.read_bytes()).hexdigest(),
            launcher=self.launcher, launcher_sha256=sha256(self.launcher.read_bytes()).hexdigest(),
            validator=self.validator, validator_sha256=sha256(self.validator.read_bytes()).hexdigest(),
            protected_roots=protected, write_path='marker.txt', expected_utf8=f'marker {slot}\n',
            require_effect=lambda: None,
        )
        self.addCleanup(worker.close)
        return worker

    @staticmethod
    def _inert_network(lifetime):
        if lifetime.role == 'appserver':
            lifetime.provider_network = _InertBroker()
        return ()

    @staticmethod
    def _inert_bootstrap(lifetime, command):
        return [lifetime.factory.spec['validator'], '-I', '-S', '-c', containment.n1._BOOTSTRAP, *command]

    def _replace_provider(self):
        lifetime = containment._PoolLifetime
        self.enterContext(patch.object(lifetime, '_provider_network_fds', self._inert_network))
        self.enterContext(patch.object(lifetime, '_bootstrap_command', self._inert_bootstrap))
        self.enterContext(patch.object(lifetime, '_provider_network_mounts', return_value=[]))
        self.enterContext(patch.object(lifetime, '_release_provider_descriptor'))

    def _start_inert_apps(self, workers):
        for worker in workers:
            child = worker.launch_appserver()
            self.assertTrue(select.select([child.stdout], [], [], 5)[0])
            self.assertEqual(child.stdout.readline(), 'read-only inert app server\n')

    def test_n1_and_pool_slots_share_durable_exclusion(self):
        original = qualification.claim_managed_login()
        with self.assertRaisesRegex(qualification.QualificationError, 'remains unresolved'):
            qualification.claim_managed_login(1)
        second, third = qualification.claim_managed_login(2), qualification.claim_managed_login(3)
        with self.assertRaisesRegex(qualification.QualificationError, 'lease changed'):
            qualification.release_managed_login(second, 3)
        with self.assertRaisesRegex(qualification.QualificationError, 'remains unresolved'):
            qualification.claim_managed_login(3)
        for slot, nonce in enumerate((original, second, third), 1):
            qualification.release_managed_login(nonce, slot)
        self.assertEqual(sorted(path.name for path in self.state.iterdir()), ['starts.jsonl'])

    def test_source_holds_apply_before_private_worker_reads(self):
        with patch.object(availability, 'require_pool_qualification', side_effect=availability.NativeLiveUnavailable,
                          create=True):
            with self.assertRaises(availability.NativeLiveUnavailable):
                containment.PoolWorkerContainment(
                    worker_id='fixture', worktree=None, spool=None, login_slot=1, executable=None, launcher=None,
                    validator=None, executable_sha256=None, launcher_sha256=None, validator_sha256=None,
                    protected_roots=(), write_path='marker.txt', expected_utf8='fixture', require_effect=lambda: None,
                )

    def test_same_thread_gate_seals_unreleased_callback(self):
        paths = self._paths(1)
        worker = self._worker(1, paths)
        call = containment._WriterCall('request-1', lambda release: captures.append(release))
        lifetime = containment._PoolLifetime(worker, 'tool', [])
        captures = []
        with self.assertRaisesRegex(config.PoolContainmentError, 'did not release'):
            lifetime._release_writer_gate(call, time.monotonic() + 1)
        with self.assertRaisesRegex(config.PoolContainmentError, 'no longer owns'):
            captures[0]()

    @unittest.skipUnless(Path('/usr/bin/bwrap').is_file(), 'Bubblewrap is required for physical containment')
    def test_physical_pool_worker_boundaries_and_exact_writes(self):
        self._replace_provider()
        # Distinct app servers are all running before the first fixed writer.
        paths = [self._paths(slot) for slot in (1, 2, 3)]
        workers = [self._worker(slot, pair, protected=tuple(peer[0] for peer in paths if peer != pair))
                   for slot, pair in enumerate(paths, 1)]
        self._start_inert_apps(workers)
        self.assertEqual(len({worker.owner_identity_sha256 for worker in workers}), 3)
        for slot, worker in enumerate(workers, 1):
            self.assertFalse((paths[slot - 1][0] / 'marker.txt').exists())
            result = worker.run_writer(f'call-{slot}', authorize=lambda release: release(),
                                       deadline=time.monotonic() + 10)
            self.assertEqual(result, containment._WRITTEN.encode())
        for slot, (worker, (worktree, _)) in enumerate(zip(workers, paths), 1):
            self.assertEqual(set(path.name for path in worktree.iterdir()), {'.git', 'marker.txt'})
            self.assertEqual((worktree / 'marker.txt').read_text(), f'marker {slot}\n')
            self.assertEqual((self.slots[slot] / 'auth.json').read_text(), f'synthetic marker {slot}\n')
            receipt = worker.close()
            self.assertTrue(receipt['cleanup_confirmed'])
            self.assertFalse(receipt['failed'])
            rows = {row['stage']: row['observation'] for row in receipt['observations']}
            self.assertTrue(rows['appserver-contained']['worktree_readonly'])
            self.assertFalse(rows['tool-contained']['managed_login_projection'])
            self.assertEqual(rows['writer-output']['call_id'], f'call-{slot}')
            self.assertTrue(worker._appserver.provider_network.revoked)
            self.assertTrue(worker._appserver.provider_network.closed)
            self.assertEqual(worker.close(), receipt)
        self.assertEqual(sorted(path.name for path in self.state.iterdir()), ['starts.jsonl'])

    @unittest.skipUnless(Path('/usr/bin/bwrap').is_file(), 'Bubblewrap is required for physical containment')
    def test_refused_callback_never_writes_and_original_worker_is_cleaned(self):
        self._replace_provider()
        paths = self._paths(1)
        worker = self._worker(1, paths)
        self._start_inert_apps((worker,))
        with self.assertRaisesRegex(config.PoolContainmentError, 'did not release'):
            worker.run_writer('call-1', authorize=lambda release: None, deadline=time.monotonic() + 10)
        self.assertFalse((paths[0] / 'marker.txt').exists())
        self.assertTrue(worker.receipt()['cleanup_confirmed'])
        self.assertTrue(worker.receipt()['failed'])

    def test_unknown_cleanup_keeps_original_login_lease(self):
        paths = self._paths(1)
        worker = self._worker(1, paths)
        worker._prepare_home()
        worker._managed_lifetime = containment._PoolLifetime(worker, 'appserver', [])
        worker._managed_lifetime._managed_mount_started = True
        with self.assertRaisesRegex(config.PoolContainmentError, 'cleanup is unresolved'):
            worker.close()
        self.assertFalse(worker.receipt()['cleanup_confirmed'])
        with self.assertRaisesRegex(qualification.QualificationError, 'remains unresolved'):
            qualification.claim_managed_login(1)
        self.assertEqual((self.slots[1] / 'auth.json').read_text(), 'synthetic marker 1\n')
