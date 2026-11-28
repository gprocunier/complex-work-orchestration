"""Check the contained pool host with synthetic files and inert stdio peers."""

from base64 import b64encode
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
import json
import os
from pathlib import Path
import select
import socket
import stat
import subprocess
import sys
import tempfile
from threading import Barrier, RLock
import time
import tomllib
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, PropertyMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))

import registered_pool_configuration as config
import registered_pool_containment as containment
import registered_n1_qualification as qualification
import registered_pool_qualification as pool
from cwo_core import native_live_availability as availability


class PoolConfigurationTests(unittest.TestCase):
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

    def test_production_login_selection_requires_the_original_effect_check(self):
        parent = object.__new__(pool._PoolParent)
        worker = pool._PoolWorker(parent, {'child_id': 'fixture'}, {}, None, None, 1)
        parent.workers = {worker.child_id: worker}
        with (patch.object(pool._PoolParent, 'require_effect', side_effect=ValueError('effect refused')),
              patch.object(pool._PoolWorker, 'production_login_home', new_callable=PropertyMock) as select_login,
              self.assertRaisesRegex(ValueError, 'effect refused')):
            containment._require_original_worker(worker.require_effect, worker.child_id, None, None, 1)
        select_login.assert_not_called()

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
        self.assertEqual(tool['name'], 'write_selected_fixture')
        self.assertEqual(tool['inputSchema'], {'type': 'object', 'properties': {}, 'additionalProperties': False})
        self.assertIn('The controller writes the signed fixture already selected for this worker.', tool['description'])
        self.assertIn('The worker shell and checkout stay read-only.', tool['description'])

    def test_default_tier_contract(self):
        worker, spool = Path('/fixture/worker'), Path('/fixture/private-spool')
        catalog = b'{"models":[{"slug":"gpt-6.2-sol"}]}'
        for model_catalog in (None, catalog):
            with self.subTest(trimmed=model_catalog is not None):
                raw = config.configuration_files(worker, spool, catalog=model_catalog)['config.toml']
                settings = tomllib.loads(raw.decode())
                self.assertEqual(settings['service_tier'], 'default')
                self.assertNotIn('fast_mode', settings['features'])
        self.assertEqual(config.thread_start_selectors(worker)['serviceTier'], 'default')

        response = {'cwd': str(worker), 'runtimeWorkspaceRoots': [str(worker)],
                    'activePermissionProfile': {'id': config.PROFILE, 'extends': None},
                    'model': qualification.MODEL, 'modelProvider': qualification.PROVIDER,
                    'approvalPolicy': qualification.APPROVAL_POLICY, 'approvalsReviewer': 'user',
                    'reasoningEffort': qualification.EFFORT,
                    'thread': {'id': 'thread-one', 'turns': [], 'ephemeral': False,
                               'historyMode': qualification.HISTORY_MODE}}
        config.require_thread_readback(worker, {**response, 'serviceTier': 'default'})
        rejected = [response, *({**response, 'serviceTier': value} for value in (None, 'fast', 'priority', 'flex'))]
        for drift in rejected:
            with self.subTest(tier=drift.get('serviceTier', 'missing')), self.assertRaises(config.PoolContainmentError):
                config.require_thread_readback(worker, drift)

    def test_later_turn_cannot_widen_its_selectors(self):
        turn = {'threadId': 'thread-one', 'model': qualification.MODEL, 'effort': qualification.EFFORT,
                'serviceTier': qualification.TIER, 'input': []}
        config.require_turn_selectors(turn, thread_id='thread-one')
        for drift in ({'model': 'default'}, {'serviceTier': None}, {'serviceTier': 'fast'},
                      {'serviceTier': 'priority'}, {'serviceTier': 'flex'}, {'effort': 'max'},
                      {'threadId': 'thread-two'}, {'cwd': '/outside'}, {'permissions': ':workspace'},
                      {'sandboxPolicy': {'type': 'dangerFullAccess'}}, {'approvalPolicy': 'on-request'}):
            with self.subTest(drift=drift), self.assertRaises(config.PoolContainmentError):
                config.require_turn_selectors({**turn, **drift}, thread_id='thread-one')
        del turn['serviceTier']
        with self.assertRaises(config.PoolContainmentError):
            config.require_turn_selectors(turn, thread_id='thread-one')

    def test_named_profile_refuses_a_missing_or_widened_login_deny_rule(self):
        worktree = Path('/fixture/worker')
        raw = config.configuration_files(worktree, Path('/fixture/spool'))['config.toml']
        rule = f'"{qualification.LOGIN_MOUNT}" = "deny"\n'.encode()
        config.require_named_deny_policy(worktree, raw)
        for changed in (raw.replace(rule, b''), raw.replace(rule, rule.replace(b'"deny"', b'"read"'))):
            with self.assertRaisesRegex(config.PoolContainmentError, 'named login deny policy'):
                config.require_named_deny_policy(worktree, changed)


class CheckedPatchWriterTests(unittest.TestCase):
    stage_name = '.cwo-patch-' + 'a' * 32

    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.target = self.root / 'source.py'
        self.before = b'value = 1\n'
        self.target.write_bytes(self.before)
        self.target.chmod(0o751)

    def _command(self, after, program=None, *, path=None):
        if path is None:
            path = self.target.relative_to(self.root).as_posix()
        return [sys.executable, '-I', '-S', '-c', program or containment._PATCH_WRITER, path,
                sha256(self.before).hexdigest(), sha256(after).hexdigest(),
                json.dumps(containment._patch_mark(self.target.stat())), self.stage_name]

    def _run(self, command, data):
        with containment._patch_parent(self.root, self.target.relative_to(self.root).as_posix()) as (directory, _):
            flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
            with os.fdopen(os.open(self.stage_name, flags, 0o600, dir_fd=directory), 'r+b') as staging:
                try:
                    info = os.fstat(staging.fileno())
                    stdin = f'{info.st_dev} {info.st_ino}\n'.encode() + b64encode(data)
                    return subprocess.run(command, cwd=self.root, input=stdin, capture_output=True, timeout=5)
                finally:
                    containment._remove_patch_staging(directory, self.stage_name, staging.fileno())

    def test_patch_writer_fits_retained_launcher_argument_bounds(self):
        worker = SimpleNamespace(spec={'validator': sys.executable}, _output_path=self.target.name)
        prepared = SimpleNamespace(content=b'updated\n', preimage_sha256=sha256(self.before).hexdigest(),
                                   target_mark=containment._patch_mark(self.target.stat()))
        command, _ = containment.PoolWorkerContainment._writer_command(worker, prepared, self.stage_name)
        lifetime = containment._PoolLifetime(worker, 'tool', command)
        launcher = '/usr/bin/bwrap'
        argv = containment.n1._launcher_argv(launcher, 3, lifetime._bootstrap_command(command))
        workspace = str(self.root)
        self.assertEqual(containment.n1.owned._freeze('worker-1-tool', argv, workspace, launcher),
                         ('worker-1-tool', tuple(argv), workspace))

    def test_empty_checked_postimage_replaces_the_file_and_preserves_permissions(self):
        nested = self.root / 'src' / 'package'
        nested.mkdir(parents=True)
        self.target = self.target.rename(nested / self.target.name)
        self.assertEqual(containment.read_pool_patch_file(self.root, 'src/package/source.py'), self.before)
        completed = self._run(self._command(b''), b'')
        self.assertEqual((completed.returncode, completed.stdout, completed.stderr),
                         (0, containment._WRITTEN.encode(), b''))
        self.assertEqual(self.target.read_bytes(), b'')
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), 0o751)
        self.assertEqual(list(nested.iterdir()), [self.target])

    def test_short_and_surplus_input_leave_the_original_file(self):
        after = b'value = 2\n'
        command = self._command(after)
        surplus = b'x' * (containment.MAX_WORKER_PATCH_BYTES + 16)
        for data in (after[:-1], after + b'x', surplus):
            with self.subTest(length=len(data)):
                completed = self._run(command, data)
                self.assertEqual((completed.returncode, completed.stdout), (1, b''))
                self.assertEqual(self.target.read_bytes(), self.before)
                self.assertEqual(list(self.root.iterdir()), [self.target])

    def test_changed_preimage_and_failed_replacement_leave_no_staging_file(self):
        after = b'value = 2\n'
        program = ('import os\n'
                   'def refused(*args, **kwargs):\n    raise OSError("synthetic replacement failure")\n'
                   'os.replace = refused\n' + containment._PATCH_WRITER)
        self.assertEqual(self._run(self._command(after, program), after).returncode, 1)
        self.assertEqual(self.target.read_bytes(), self.before)
        self.assertEqual(list(self.root.iterdir()), [self.target])
        command = self._command(after)
        changed = b'value = 3\n'
        self.target.write_bytes(changed)
        self.assertEqual(self._run(command, after).returncode, 1)
        self.assertEqual(self.target.read_bytes(), changed)
        self.assertEqual(list(self.root.iterdir()), [self.target])

    def test_staging_cleanup_preserves_an_entry_with_different_custody(self):
        stage = self.root / self.stage_name
        other = self.root / 'other.txt'
        other.write_bytes(b'unrelated')
        with containment._patch_parent(self.root, self.target.name) as (directory, _), stage.open('xb') as original:
            other.replace(stage)
            with self.assertRaisesRegex(config.PoolContainmentError, 'staging entry changed'):
                containment._remove_patch_staging(directory, self.stage_name, original.fileno())
        self.assertEqual(stage.read_bytes(), b'unrelated')
        self.assertEqual(self.target.read_bytes(), self.before)

    def test_host_reader_rejects_aliases_nonregular_and_nontext_files(self):
        alias = self.root / 'alias.py'
        alias.symlink_to(self.target)
        with self.assertRaisesRegex(config.PoolContainmentError, 'regular file'):
            containment.read_pool_patch_file(self.root, alias.name)
        alias.unlink()
        os.link(self.target, alias)
        with self.assertRaisesRegex(config.PoolContainmentError, 'one link'):
            containment.read_pool_patch_file(self.root, self.target.name)
        alias.unlink()
        alias.mkdir()
        with self.assertRaisesRegex(config.PoolContainmentError, 'regular file'):
            containment.read_pool_patch_file(self.root, alias.name)
        self.target.write_bytes(b'\xff')
        with self.assertRaisesRegex(config.PoolContainmentError, 'UTF-8'):
            containment.read_pool_patch_file(self.root, self.target.name)

    def test_patch_path_requires_ordinary_components_and_rejects_symlinked_ancestors(self):
        for path in ('/source.py', './source.py', 'a/../source.py', 'a//source.py', 'source.py/',
                     '.git/config', 'src/.hidden/file.py', 'src/space name.py', 'src\\source.py'):
            with self.subTest(path=path):
                self.assertFalse(containment.pool_patch_path(path))
        self.assertTrue(containment.pool_patch_path('src/module-1/source.py'))
        with self.assertRaisesRegex(config.PoolContainmentError, 'ordinary worktree file'):
            containment._writer_bytes('src/source.py', 'legacy fixed write')
        nested = self.root / 'src'
        nested.mkdir()
        self.target = self.target.rename(nested / self.target.name)
        (self.root / 'alias').symlink_to(nested, target_is_directory=True)
        alias = 'alias/source.py'
        with self.assertRaises(config.PoolContainmentError):
            containment.read_pool_patch_file(self.root, alias)
        after = b'value = 2\n'
        self.assertEqual(self._run(self._command(after, path=alias), after).returncode, 1)
        self.assertEqual(self.target.read_bytes(), self.before)
        self.assertEqual(list(nested.iterdir()), [self.target])


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
        self.configured = {slot: self.root / f'account-{slot}' for slot in self.slots}
        for slot, directory in self.configured.items():
            directory.mkdir(mode=0o700)
            auth = directory / 'auth.json'
            auth.write_text(f'synthetic marker {slot}\n')
            auth.chmod(0o600)
        self.production_home = None
        self.login_homes = ()
        self.login_state = self.root / 'worker-login-state'
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
        self.enterContext(patch.object(qualification, 'worker_login_state', return_value=self.login_state))
        self.enterContext(patch.object(availability, 'require_registered_n1_live'))
        self.enterContext(patch.object(availability, 'require_registered_contained_pool_live', create=True))
        self.enterContext(patch.object(qualification, 'require_executable_schema'))
        self.enterContext(patch.object(containment, '_require_original_worker', side_effect=self._original_effect))
        self.enterContext(patch.object(containment, '_require_original_writer'))

    def _original_effect(self, effect, worker_id, worktree, spool, slot, containment=None):
        effect()
        home = self.configured[slot] if self.production_home is None else self.production_home
        return home, self.login_homes

    def _select_production_login(self, name='configured-login'):
        self.production_home = self.root / name
        self.production_home.mkdir(mode=0o700)
        auth = self.production_home / 'auth.json'
        auth.write_text('synthetic configured account\n')
        auth.chmod(0o600)
        return self.production_home

    def _paths(self, slot):
        worktree, custody = self.root / f'worker-{slot}', self.root / f'custody-{slot}'
        for path in (worktree, worktree / '.git', custody, custody / 'codex-home'):
            path.mkdir(mode=0o700)
        return worktree, custody / 'codex-home'

    def _worker(self, slot, paths, protected=(), *, patch_preimage_sha256=None, write_path='marker.txt'):
        worker, spool = paths
        worker = containment.PoolWorkerContainment(
            worker_id=f'worker-{slot}', worktree=worker, spool=spool, login_slot=slot,
            executable=self.peer, executable_sha256=sha256(self.peer.read_bytes()).hexdigest(),
            launcher=self.launcher, launcher_sha256=sha256(self.launcher.read_bytes()).hexdigest(),
            validator=self.validator, validator_sha256=sha256(self.validator.read_bytes()).hexdigest(),
            protected_roots=protected, write_path=write_path,
            expected_utf8=f'marker {slot}\n' if patch_preimage_sha256 is None else None,
            require_effect=lambda: None, patch_preimage_sha256=patch_preimage_sha256,
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

    def test_provider_registration_uses_only_managed_login_and_cleans_up_before_spawn(self):
        worker = self._worker(1, self._paths(1))
        broker = _InertBroker()
        child_socket, peer_socket = socket.socketpair()
        with child_socket, peer_socket:
            broker.child_socket = child_socket
            with (patch.object(containment.n1.provider_network, 'ProviderBroker', return_value=broker) as create_broker,
                  patch.object(containment._PoolLifetime, '_command', side_effect=RuntimeError('offline launch stop')),
                  self.assertRaisesRegex(RuntimeError, '^offline launch stop$')):
                worker.launch_appserver()

        create_broker.assert_called_once_with(worker._appserver._record_provider_denial,
                                              allow_personal_access_token=False, allow_managed_login=True)
        self.assertTrue(broker.closed)
        self.assertIsNone(worker._appserver.receipt)
        self.assertIsNone(worker._appserver.process)
        prepared, retired, released = worker.receipt()['observations']
        self.assertEqual(prepared['stage'], 'login-projections-prepared')
        self.assertEqual(retired, {**prepared, 'stage': 'login-projections-retired'})
        self.assertEqual(released, {'stage': 'login-released', 'observation': {'slot': 1}})
        self.assertEqual(list(self.login_state.iterdir()), [])

    def test_production_projection_uses_the_same_login_interlock_as_n1(self):
        login = self._select_production_login()
        with patch.object(qualification, 'campaign_directory', side_effect=AssertionError('campaign state touched')):
            worker = self._worker(1, self._paths(1))
            self.assertTrue(worker.production_live)
            worker._prepare_home()
            self.assertIs(type(worker._managed_login), containment._PoolLoginMount)
            self.assertEqual(worker._managed_login.home, login)
            n1_mount = qualification.WorkerLoginMount(login, self.login_state)
            with self.assertRaisesRegex(qualification.QualificationError, 'remains unresolved'):
                n1_mount.claim()
            worker.close()
            self.assertEqual(set(path.name for path in login.iterdir()), {'auth.json'})
            n1_mount.release(n1_mount.claim())
            self.assertEqual(list(self.login_state.iterdir()), [])
        self.assertEqual(list(self.login_state.iterdir()), [])

    def test_qualification_pool_interlocks_follow_containment_cleanup(self):
        self.slots = self.configured
        self.login_homes = tuple(self.slots.values())
        self.enterContext(patch.object(qualification, '_controller_home', return_value=self.root))
        qualification.initialize_campaign()
        first, second = (self._worker(slot, self._paths(slot)) for slot in (1, 2))
        self.assertIn(qualification.campaign_directory(), first._protected_roots())

        historical = qualification.claim_managed_login(1)
        with self.assertRaisesRegex(qualification.QualificationError, 'remains unresolved'):
            first._worker_login.claim()
        self.assertEqual(list(self.login_state.iterdir()), [])
        qualification.release_managed_login(historical, 1)
        first._prepare_home()
        second._prepare_home()
        for slot in (1, 2):
            with self.assertRaisesRegex(qualification.QualificationError, 'remains unresolved'):
                qualification.claim_managed_login(slot)
        self.assertEqual(len(list(self.login_state.iterdir())), 2)

        first.close()
        historical = qualification.claim_managed_login(1)
        qualification.release_managed_login(historical, 1)
        second._managed_lifetime = containment._PoolLifetime(second, 'appserver', [])
        second._managed_lifetime._managed_mount_started = True
        with self.assertRaisesRegex(config.PoolContainmentError, 'cleanup is unresolved'):
            second.close()
        self.assertEqual(len(list(self.login_state.iterdir())), 1)
        with self.assertRaisesRegex(qualification.QualificationError, 'remains unresolved'):
            qualification.claim_managed_login(2)
        self.assertEqual(qualification.campaign_usage()['total'], 0)

    def test_production_provider_requires_managed_login(self):
        self._select_production_login()
        worker = self._worker(1, self._paths(1))
        lifetime = containment._PoolLifetime(worker, 'appserver', [])
        with patch.object(containment.n1.provider_network, 'ProviderBroker') as create_broker:
            with self.assertRaisesRegex(ValueError, 'production worker login is unavailable'):
                lifetime._provider_network_fds()
            create_broker.assert_not_called()

    def test_production_projection_conflict_keeps_original_worker_overlay(self):
        login = self._select_production_login()
        conflict = login / 'installation_id'
        conflict.write_text('synthetic existing installation')
        worker = self._worker(1, self._paths(1))
        worker._prepare_home()
        mount = worker._managed_login
        self.assertIs(type(mount), qualification.WorkerLoginMount)
        self.assertEqual(mount.home, login)
        self.assertEqual(mount.work.parent, self.login_state)
        self.assertTrue(mount.work.is_dir())
        worker.close()
        self.assertFalse(mount.work.exists())
        self.assertEqual(conflict.read_text(), 'synthetic existing installation')
        self.assertEqual(list(self.login_state.iterdir()), [])

    def test_concurrent_production_workers_can_create_shared_interlock_state(self):
        self._select_production_login()
        first = self._worker(1, self._paths(1))
        self._select_production_login('another-configured-login')
        second = self._worker(2, self._paths(2))
        contenders = Barrier(2)
        mkdir = os.mkdir

        def create(path, mode, *, dir_fd=None):
            if path == self.login_state.name and dir_fd is not None:
                contenders.wait(timeout=5)
            mkdir(path, mode, dir_fd=dir_fd)

        with patch.object(os, 'mkdir', side_effect=create), ThreadPoolExecutor(max_workers=2) as executor:
            preparing = [executor.submit(worker._prepare_home) for worker in (first, second)]
            for completed in preparing:
                completed.result(timeout=10)
        self.assertEqual(len(list(self.login_state.glob('login-*.lock'))), 2)
        for worker in (first, second):
            worker.close()
        self.assertEqual(list(self.login_state.iterdir()), [])

    def test_production_gate_applies_before_private_worker_reads(self):
        self._select_production_login()
        with (patch.object(availability, 'require_registered_contained_pool_live',
                           side_effect=availability.NativeLiveUnavailable, create=True),
              patch.object(containment.native, '_path', side_effect=AssertionError('private path reached'))):
            with self.assertRaises(availability.NativeLiveUnavailable):
                self._worker(1, self._paths(1))

    def test_production_refuses_untrusted_login_location_and_non_path(self):
        login = self._select_production_login()
        paths = self._paths(1)
        self.production_home = str(login)
        with self.assertRaisesRegex(config.PoolContainmentError, 'configured worker login'):
            self._worker(1, paths)
        self.production_home = self.slots[1]
        with self.assertRaisesRegex(qualification.QualificationError, 'qualification homes'):
            self._worker(1, paths)
        self.assertEqual(list(paths[1].iterdir()), [])
        self.assertFalse(self.login_state.exists())

    def test_production_login_and_interlock_cannot_overlap_protected_roots(self):
        login = self._select_production_login()
        paths = self._paths(1)
        for root in (login, self.login_state):
            with (self.subTest(root=root),
                  self.assertRaisesRegex(config.PoolContainmentError, 'separate from other protected roots')):
                self._worker(1, paths, protected=(root,))
        self.assertEqual(list(paths[1].iterdir()), [])
        self.assertFalse(self.login_state.exists())

    def test_production_fences_refuse_selected_path_or_inode_drift(self):
        login = self._select_production_login()
        worker = self._worker(1, self._paths(1))
        with (patch.object(worker, '_prepare_home') as prepare,
              patch.object(containment._PoolLifetime, 'launch', side_effect=AssertionError('unexpected launch'))):
            self.production_home = self.root / 'foreign-login'
            with self.assertRaisesRegex(config.PoolContainmentError, 'configured worker login changed'):
                worker.launch_appserver()
            self.production_home = login
            original = login.rename(self.root / 'retained-login')
            try:
                login.mkdir(mode=0o700)
                auth = login / 'auth.json'
                auth.write_text('synthetic foreign account\n')
                auth.chmod(0o600)
                with self.assertRaisesRegex(qualification.QualificationError, 'login directory changed'):
                    worker.launch_appserver()
                auth.unlink()
                login.rmdir()
            finally:
                original.rename(login)
            prepare.assert_not_called()

    def test_production_uncertain_cleanup_keeps_the_original_n1_lease(self):
        login = self._select_production_login()
        worker = self._worker(1, self._paths(1))
        worker._prepare_home()
        worker._managed_lifetime = containment._PoolLifetime(worker, 'appserver', [])
        worker._managed_lifetime._managed_mount_started = True
        with self.assertRaisesRegex(config.PoolContainmentError, 'cleanup is unresolved'):
            worker.close()
        self.assertFalse(worker.receipt()['cleanup_confirmed'])
        with self.assertRaisesRegex(qualification.QualificationError, 'remains unresolved'):
            qualification.WorkerLoginMount(login, self.login_state).claim()

    @unittest.skipUnless(Path('/usr/bin/bwrap').is_file(), 'Bubblewrap is required for physical containment')
    def test_production_login_round_trip(self):
        self._assert_login_round_trip(self._select_production_login())

    def _assert_login_round_trip(self, login):
        self._replace_provider()
        original = {}
        for name in ('tmp', 'log'):
            directory = login / name
            directory.mkdir(mode=0o700)
            marker = directory / 'original'
            marker.write_text('retained directory marker')
            original[name] = directory.stat().st_ino, marker.stat().st_ino
        auth = login / 'auth.json'
        auth_inode = auth.stat().st_ino
        fixture = self.peer.read_text()
        at = fixture.index("print('read-only inert app server'")
        self.peer.write_text(fixture[:at] + '''import os
home = pathlib.Path(os.environ['CODEX_HOME'])
assert not (home / 'tmp' / 'original').exists()
assert not (home / 'log' / 'original').exists()
assert os.statvfs(home / 'config.toml').f_flag & os.ST_RDONLY
assert os.statvfs(home / 'rules' / 'default.rules').f_flag & os.ST_RDONLY
auth = home / 'auth.json'
refresh = home / 'EXAMPLE-refresh'
with refresh.open('x') as stream:
    os.fchmod(stream.fileno(), 0o600)
    stream.write('renewed synthetic marker')
    stream.flush()
    os.fsync(stream.fileno())
refresh.replace(auth)
directory = os.open(home, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(directory)
finally:
    os.close(directory)
active = home / 'sessions' / 'EXAMPLE-rollout'
active.write_text('synthetic session marker')
active.rename(home / 'archived_sessions' / active.name)
''' + fixture[at:])
        _, spool = paths = self._paths(1)
        worker = self._worker(1, paths, protected=(self.configured[2], self.configured[3]))
        self._start_inert_apps((worker,))
        self.assertEqual(worker.run_writer('call-1', authorize=lambda release: release(),
                                           deadline=time.monotonic() + 10), containment._WRITTEN.encode())
        receipt = worker.close()
        self.assertTrue(receipt['cleanup_confirmed'])
        self.assertEqual((spool / 'archived_sessions' / 'EXAMPLE-rollout').read_text(), 'synthetic session marker')
        self.assertFalse((spool / 'sessions' / 'EXAMPLE-rollout').exists())
        self.assertEqual(set(path.name for path in login.iterdir()), {'auth.json', 'tmp', 'log'})
        self.assertNotEqual(auth.stat().st_ino, auth_inode)
        self.assertEqual(auth.read_text(), 'renewed synthetic marker')
        for name, (directory_inode, marker_inode) in original.items():
            directory = login / name
            self.assertEqual(directory.stat().st_ino, directory_inode)
            self.assertEqual((directory / 'original').stat().st_ino, marker_inode)
            self.assertEqual((directory / 'original').read_text(), 'retained directory marker')
        rows = {row['stage']: row['observation'] for row in receipt['observations']}
        self.assertEqual(set(rows['login-projections-prepared']['preserved']), {'tmp', 'log'})
        self.assertEqual(rows['login-projections-prepared'], rows['login-projections-retired'])
        self.assertFalse(rows['tool-contained']['managed_login_projection'])
        on_disk = [json.loads(path.read_text()) for path in sorted(worker._receipt_root.glob('*.json'))]
        self.assertEqual(on_disk, receipt['observations'])
        self.assertEqual([row['stage'] for row in on_disk[-3:]],
                         ['appserver-terminated', 'login-projections-retired', 'login-released'])

    def test_login_projection_failure(self):
        first = self._worker(1, self._paths(1))
        create = containment._PoolLoginMount._create_link

        def create_then_refuse(mount, name, target):
            if mount._owned:
                raise OSError('synthetic setup failure')
            create(mount, name, target)

        with (patch.object(containment._PoolLoginMount, '_create_link', create_then_refuse),
              self.assertRaisesRegex(OSError, 'synthetic setup failure')):
            first.launch_appserver()
        self.assertIsNone(first._appserver)
        self.assertEqual(set(path.name for path in self.configured[1].iterdir()), {'auth.json'})
        self.assertEqual(first.receipt()['observations'][-1]['stage'], 'login-released')

        second = self._worker(2, self._paths(2))
        second._prepare_home()
        displaced = self.configured[2] / 'sessions'
        displaced.unlink()
        displaced.write_text('foreign entry')
        with self.assertRaisesRegex(config.PoolContainmentError, 'projection entry changed'):
            second.close()
        self.assertEqual(displaced.read_text(), 'foreign entry')
        self.assertTrue((self.configured[2] / 'config.toml').is_symlink())
        self.assertFalse(second.receipt()['cleanup_confirmed'])
        with self.assertRaisesRegex(qualification.QualificationError, 'remains unresolved'):
            qualification.WorkerLoginMount(self.configured[2], self.login_state).claim()

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
            self.assertEqual((self.configured[slot] / 'auth.json').read_text(), f'synthetic marker {slot}\n')
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
        self.assertEqual(list(self.login_state.iterdir()), [])

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

    def test_interrupted_patch_waits_for_original_writer_retirement_before_staging_cleanup(self):
        for slot, confirmed in enumerate((True, False), 1):
            with self.subTest(confirmed=confirmed):
                self._assert_interrupted_patch_staging(slot, confirmed)

    def _assert_interrupted_patch_staging(self, slot, confirmed):
        paths = self._paths(slot)
        target = paths[0] / 'src' / 'marker.txt'
        target.parent.mkdir()
        target.write_bytes(b'old\n')
        neighbor = target.parent / 'neighbor.txt'
        neighbor.write_bytes(b'unrelated\n')
        path = target.relative_to(paths[0]).as_posix()
        worker = self._worker(slot, paths, patch_preimage_sha256=sha256(b'old\n').hexdigest(), write_path=path)
        worker._prepare_home()
        worker._appserver = SimpleNamespace(receipt=None, process=None)
        worker.record('appserver-terminated', {})
        authorize = Mock()
        diff = f'--- a/{path}\n+++ b/{path}\n@@ -1 +1 @@\n-old\n+new\n'
        authorize.pending = SimpleNamespace(params={'arguments': {'diff': diff}}, request_sha256='a' * 64)
        child = Mock()
        stage = None

        def launch(lifetime, command, _home, **_binding):
            nonlocal stage
            stage = target.parent / command[-1]
            self.assertFalse(stage.exists())
            self.assertFalse(worker._workspace_capture_guard.locked())
            lifetime.process = child
            lifetime.receipt = object()
            return child

        def interrupted(stdin, _timeout):
            self.assertTrue(worker._workspace_capture_guard.locked())
            info = stage.stat()
            self.assertEqual(stdin, f'{info.st_dev} {info.st_ino}\n' + b64encode(b'new\n').decode())
            stage.write_bytes(b'partial\n')
            raise TimeoutError('synthetic writer deadline')

        def settle(lifetime):
            self.assertEqual(stage.read_bytes(), b'partial\n')
            if confirmed:
                self.assertTrue(worker._workspace_capture_guard.locked())
                worker.record('tool-terminated', {})
                lifetime.termination_recorded = True
            else:
                raise RuntimeError('synthetic unconfirmed retirement')

        child.communicate.side_effect = interrupted
        with (patch.object(containment._PoolLifetime, 'launch', launch),
              patch.object(containment._PoolLifetime, 'settle_termination', settle),
              self.assertRaisesRegex(TimeoutError, 'synthetic writer deadline')):
            worker.run_writer('call-1', authorize=authorize, deadline=time.monotonic() + 5)
        self.assertEqual(worker.receipt()['cleanup_confirmed'], confirmed)
        self.assertFalse(worker._workspace_capture_guard.locked())
        self.assertEqual(stage.exists(), not confirmed)
        self.assertEqual(target.read_bytes(), b'old\n')
        self.assertEqual(neighbor.read_bytes(), b'unrelated\n')

    @unittest.skipUnless(Path('/usr/bin/bwrap').is_file(), 'Bubblewrap is required for physical containment')
    def test_checked_patch_uses_the_same_gate_and_bounded_postimage_pipe(self):
        self._replace_provider()
        paths = self._paths(1)
        path = 'src/marker.txt'
        target = paths[0] / path
        target.parent.mkdir()
        unchanged = b'x' * 40_000 + b'\n'
        before, after = unchanged + b'old\n', unchanged + b'new\n'
        target.write_bytes(before)
        target.chmod(0o751)
        preimage_sha256 = sha256(before).hexdigest()
        worker = self._worker(1, paths, patch_preimage_sha256=preimage_sha256, write_path=path)
        self._start_inert_apps((worker,))
        diff = f'--- a/{path}\n+++ b/{path}\n@@ -2 +2 @@\n-old\n+new\n'

        def release_with_original_preimage(release):
            self.assertEqual(target.read_bytes(), before)
            release()

        authorize = Mock(side_effect=release_with_original_preimage)
        authorize.pending = SimpleNamespace(params={'arguments': {'diff': diff}}, request_sha256='a' * 64)
        self.assertEqual(worker.run_writer('call-1', authorize=authorize, deadline=time.monotonic() + 10),
                         containment._WRITTEN.encode())
        authorize.assert_called_once()
        self.assertEqual(target.read_bytes(), after)
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o751)
        self.assertEqual(set(paths[0].iterdir()), {target.parent, paths[0] / '.git'})
        self.assertEqual(list(target.parent.iterdir()), [target])
        rows = {row['stage']: row['observation'] for row in worker.close()['observations']}
        self.assertTrue(rows['appserver-contained']['worktree_readonly'])
        self.assertEqual(rows['tool-contained']['network'], 'isolated')
        self.assertFalse(rows['tool-contained']['managed_login_projection'])
        self.assertEqual(rows['writer-output'], {
            'call_id': 'call-1', 'path': path, 'content_sha256': sha256(after).hexdigest(),
            'patch_preimage_sha256': preimage_sha256, 'request_sha256': 'a' * 64,
            'diff_sha256': sha256(diff.encode()).hexdigest(),
        })
