"""Offline qualification authority and campaign accounting fixtures."""

from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import select
import subprocess
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tests import test_registered_n1_factory as family

import registered_n1_qualification as qualification
import selected_native_containment as selected
from cwo_core.codex_protocol_capabilities import CapabilityError
from cwo_core import model_identities
from cwo_core.maintenance_authority import MaintenanceAuthorityError, canonical_authority_sha256
from cwo_core.outbound_screen import OutboundRefused
from cwo_core.supervision.transport.app_server import AppServer

runtime = family.runtime
_EXAMPLE_ACCESS_TOKEN = 'at-EXAMPLE-offline-qualification'


def _fd_identity(descriptor):
    try:
        info = os.fstat(descriptor)
    except OSError:
        return None
    return info.st_dev, info.st_ino


class CampaignTests(unittest.TestCase):
    def setUp(self):
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.directory = root / qualification.CAMPAIGN
        self.enterContext(patch.object(qualification, '_campaign_directory', return_value=self.directory))
        qualification.initialize_campaign()

    def record(self, index, *, repair=None, expires_at=None):
        return qualification._StartRequest(
            operation_sha256=f'{index:064x}',
            expires_at=int(time.time()) + 60 if expires_at is None else expires_at,
            repair_sha256=repair,
        )

    def test_one_budget_preserves_version_one_history_and_refuses_start_twenty_one(self):
        journal = self.directory / 'starts.jsonl'
        header = b'{"campaign":"native-single-worker-host-qualification","version":1}\n'
        self.assertEqual(journal.read_bytes(), header)
        history = bytearray(header)
        for index in range(10):
            row = {'sequence': index + 1, 'operation_sha256': f'{index:064x}',
                   'repair_sha256': None if index < 5 else 'a' * 64, 'started_at': 1700000000 + index}
            history.extend((json.dumps(row, sort_keys=True, separators=(',', ':')) + '\n').encode())
        journal.write_bytes(history)
        self.assertEqual(qualification.campaign_usage(), {'initial': 5, 'rechecks': 5, 'total': 10})
        sixth_recheck = qualification._campaign_start(self.record(10, repair='b' * 64))
        self.assertEqual((sixth_recheck['sequence'], sixth_recheck['repair_sha256']), (11, 'b' * 64))
        requests = [self.record(index, repair=None if index < 17 else 'b' * 64) for index in range(11, 20)]
        with ThreadPoolExecutor(max_workers=4) as workers:
            rows = list(workers.map(qualification._campaign_start, requests))
        self.assertEqual(sorted(row['sequence'] for row in rows), list(range(12, 21)))
        self.assertEqual(qualification.campaign_usage(), {'initial': 11, 'rechecks': 9, 'total': 20})
        full_journal = journal.read_bytes()
        self.assertTrue(full_journal.startswith(history))
        for repair in (None, 'b' * 64):
            with self.assertRaisesRegex(qualification.QualificationError, 'campaign.*limit'):
                qualification._campaign_start(self.record(20, repair=repair))
        with self.assertRaises(FileExistsError):
            qualification.initialize_campaign()
        self.assertEqual(journal.read_bytes(), full_journal)

    def test_repair_digest_does_not_require_an_initial_start(self):
        start = qualification._campaign_start(self.record(0, repair='a' * 64))
        self.assertEqual(start['repair_sha256'], 'a' * 64)
        self.assertEqual(qualification.campaign_usage(), {'initial': 0, 'rechecks': 1, 'total': 1})

    def test_expiry_replay_missing_or_corrupt_accounting_fail_closed(self):
        with self.assertRaisesRegex(qualification.QualificationError, 'expired'):
            qualification._campaign_start(self.record(0, expires_at=int(time.time())))
        self.assertEqual(qualification.campaign_usage()['total'], 0)
        qualification._campaign_start(self.record(1))
        with self.assertRaisesRegex(qualification.QualificationError, 'already started'):
            qualification._campaign_start(self.record(1, repair='a' * 64))
        journal = self.directory / qualification._JOURNAL
        journal.unlink()
        with self.assertRaises(qualification.QualificationError):
            qualification._campaign_start(self.record(2))
        journal.write_bytes(b'incomplete')
        journal.chmod(0o600)
        with self.assertRaises(qualification.QualificationError):
            qualification._campaign_start(self.record(2))

    def test_run_local_model_mapping_keeps_normal_roles_and_rejects_unknown_roles(self):
        original = {role: model_identities.resolve_model(role) for role in model_identities.MODEL_ROLES}
        for role in original:
            self.assertEqual(qualification.select_run_model(role),
                {'model': 'gpt-6.2-sol', 'effort': 'xhigh', 'service_tier': 'default', 'provider': 'openai'})
        self.assertEqual({role: model_identities.resolve_model(role) for role in original}, original)
        with self.assertRaisesRegex(qualification.QualificationError, 'role'):
            qualification.select_run_model('EXAMPLE-unknown')
        with self.assertRaises(ValueError):
            model_identities.resolve_model('astra', config={'version': 1, 'roles': {
                role: {'current': 'gpt-6.2-sol', 'selection': 'explicit'} for role in original}})


    def test_managed_login_lease_is_exclusive_and_requires_original_release(self):
        first = qualification.claim_managed_login()
        with self.assertRaisesRegex(qualification.QualificationError, 'unresolved'):
            qualification.claim_managed_login()
        qualification.release_managed_login(first)
        second = qualification.claim_managed_login()
        with self.assertRaisesRegex(qualification.QualificationError, 'changed'):
            qualification.release_managed_login(first)
        qualification.release_managed_login(second)

    def test_managed_login_interlock_has_one_owner_across_contending_launches(self):
        def claim(_):
            try:
                return qualification.claim_managed_login()
            except qualification.QualificationError as exc:
                self.assertIn('unresolved', str(exc))
                return None

        with ThreadPoolExecutor(max_workers=4) as workers:
            leases = list(filter(None, workers.map(claim, range(4))))
        self.assertEqual(len(leases), 1)
        qualification.release_managed_login(leases[0])


class ManagedLoginNamespaceTests(unittest.TestCase):
    def setUp(self):
        self.launcher = '/usr/bin/bwrap'
        if not Path(self.launcher).is_file():
            self.skipTest('The actual bubblewrap executable is unavailable.')
        supported, reason = runtime.owned.atomic_spawn.supported()
        if not supported:
            self.skipTest(reason)
        help_text = subprocess.run([self.launcher, '--help'], check=True, capture_output=True, timeout=5).stdout
        if b'--overlay-src' not in help_text:
            self.skipTest('Bubblewrap does not support operation-local overlay projections.')
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory(dir='/tmp')))
        self.login = self.root / 'EXAMPLE-dedicated-login'
        self.login.mkdir(mode=0o700)
        self.auth = self.login / 'auth.json'
        self.auth.write_bytes(b'EXAMPLE original login\n')
        self.auth.chmod(0o600)
        for name in ('auth.json.lock', 'auth.lock'):
            (self.login / name).touch(mode=0o600)
        for name in ('log', 'tmp'):
            (self.login / name).mkdir(mode=0o700)
            (self.login / name / 'EXAMPLE previous').touch(mode=0o600)
        self.spool = self.root / 'operation' / 'spool'
        (self.spool / 'rules').mkdir(parents=True, mode=0o700)
        (self.spool / 'config.toml').write_bytes(b'# EXAMPLE signed configuration\n')
        (self.spool / 'rules' / 'default.rules').touch()
        worker = self.root / 'worker'
        (worker / '.git').mkdir(parents=True)
        self.validator = family.runtime_validator()
        self.factory = SimpleNamespace(spec={'launcher': self.launcher,
            'configuration_files': {'config.toml': '', 'rules/default.rules': ''}, 'validator': self.validator},
            host=SimpleNamespace(worker=worker), _managed_lease='EXAMPLE-lease',
            host_records=SimpleNamespace(assert_worker_roots_excluded=lambda roots: None))
        self.enterContext(patch.object(qualification, '_campaign_directory', return_value=self.root))
        self.mount = qualification.ManagedLoginMount(self.login)
        self.mount.prepare(self.spool)
        self.addCleanup(self.mount.retire)

    def witness(self, role, program):
        lifetime = runtime._Containment(self.factory, role=role)
        if role == 'appserver':
            self.enterContext(patch.object(lifetime, '_managed_mount', return_value=self.mount))
        command = [self.validator, '-I', '-S', '-c', program]
        read_gate, write_gate = os.pipe()
        read_info, write_info = os.pipe()
        for fd in (read_gate, write_gate, read_info, write_info):
            self.addCleanup(os.close, fd)
        argv = lifetime._command(command, self.spool, read_gate, write_info)
        with subprocess.Popen([*argv, '--', *command], pass_fds=(read_gate, write_info),
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
            try:
                os.write(write_gate, b'1')
                if not select.select([process.stdout], [], [], 5)[0]:
                    self.fail('The synthetic namespace did not reach its startup witness.')
                ready = process.stdout.readline()
                if ready != b'EXAMPLE ready\n':
                    self.fail(process.stderr.read().decode(errors='replace'))
                pid = json.loads(os.read(read_info, 4096))['child-pid']
                root = Path('/proc') / str(pid) / 'root'
                if role == 'appserver':
                    self.mount.confirm(root, self.spool)
                else:
                    self.assertFalse((root / qualification.LOGIN_MOUNT.relative_to('/')).exists())
                stdout, stderr = process.communicate(b'1', timeout=5)
                self.assertEqual((process.returncode, stdout), (0, b'EXAMPLE done\n'), stderr.decode(errors='replace'))
            finally:
                if process.poll() is None:
                    process.kill()

    def test_real_mount_is_appserver_only_and_preserves_atomic_file_and_archive_writes(self):
        ready = "import os, sys\nfrom pathlib import Path\nprint('EXAMPLE ready', flush=True)\nassert sys.stdin.read(1) == '1'\n"
        self.witness('appserver', ready + r'''
home = Path(os.environ['CODEX_HOME'])
assert 'CODEX_ACCESS_TOKEN' not in os.environ
assert (home / 'config.toml').read_bytes() == b'# EXAMPLE signed configuration\n'
try:
    (home / 'config.toml').write_text('EXAMPLE tamper')
except OSError:
    pass
else:
    raise AssertionError('The signed config is writable')
auth = home / 'auth.json'
assert auth.read_bytes() == b'EXAMPLE original login\n'
update = home / 'EXAMPLE-auth-refresh'
update.write_bytes(b'EXAMPLE refreshed login\n')
update.chmod(0o600)
os.replace(update, auth)
for name in ('log', 'tmp', 'shell_snapshots'):
    runtime = home / name
    assert not (runtime / 'EXAMPLE previous').exists()
    (runtime / 'EXAMPLE current').touch()
rollout = home / 'sessions' / 'EXAMPLE-rollout'
rollout.write_bytes(b'EXAMPLE turn')
os.replace(rollout, home / 'archived_sessions' / rollout.name)
print('EXAMPLE done')
''')
        self.assertEqual(self.auth.read_bytes(), b'EXAMPLE refreshed login\n')
        self.assertEqual({path.name for path in self.login.iterdir()},
                         {'auth.json', 'auth.json.lock', 'auth.lock', 'log', 'tmp'})
        for name in ('log', 'tmp'):
            self.assertEqual({path.name for path in (self.login / name).iterdir()}, {'EXAMPLE previous'})
        for name in ('log', 'tmp', 'shell_snapshots'):
            self.assertTrue((self.spool.parent / 'managed-runtime' / name / 'EXAMPLE current').is_file())
        self.assertEqual((self.spool / 'archived_sessions' / 'EXAMPLE-rollout').read_bytes(), b'EXAMPLE turn')
        for role in ('tool', 'validator'):
            with self.subTest(role=role):
                self.witness(role, ready + f'''
assert 'CODEX_HOME' not in os.environ
assert not Path({str(self.auth)!r}).exists()
assert not Path({str(qualification.LOGIN_MOUNT / 'auth.json')!r}).exists()
print('EXAMPLE done')
''')


class FactoryQualificationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = family.FactoryTests(methodName='runTest')
        self.addCleanup(family.cleanup_helper, self, self.fixture)
        self.fixture.setUp()

    def test_qualification_requires_permit_and_does_not_open_production(self):
        case = self.fixture.case(qualification=True)
        with self.assertRaises(runtime.live_availability.NativeLiveUnavailable):
            self.fixture.factory(case, qualification_permit=None).run()
        factory = self.fixture.factory(case)
        factory.require_launch_selection()
        for guard in (runtime.live_availability.require_n1_live,
                      runtime.live_availability.require_pool_live,
                      runtime.live_availability.require_campaign_live):
            with self.assertRaises(runtime.live_availability.NativeLiveUnavailable):
                guard()
        self.assertEqual(qualification.campaign_usage()['total'], 0)
        self.assertEqual(self.fixture.spawned, [])

    def test_qualification_refuses_history_readback_drift_before_turn(self):
        case = self.fixture.case(qualification=True, no_fake_scheduler=True)
        factory = self.fixture.factory(case)
        result = family.RpcProcess.result

        def drift(process, method, params):
            response = result(process, method, params)
            if method == 'thread/start':
                response['thread']['historyMode'] = 'paginated'
            return response

        with (patch.object(family.RpcProcess, 'result', drift),
              self.assertRaisesRegex(qualification.QualificationError, 'history mode readback')):
            factory.run()

        self.assertNotIn('turn/start', self.fixture.spawned[0].methods)
        self.assertTrue(factory.server.lifetime.contained)

    def managed_case(self, **changes):
        case = self.fixture.case(qualification=True, managed_login=True, **changes)
        login_home = case.host.state.parent / 'EXAMPLE-dedicated-login'
        login_home.mkdir(mode=0o700)
        dummy = login_home / 'auth.json'
        dummy.write_text('EXAMPLE managed login file\n')
        dummy.chmod(0o600)
        self.enterContext(patch.object(qualification, 'managed_login_home', return_value=login_home))
        # This fixture replaces kernel births. The actual projection is checked
        # by the separate real namespace witness.
        self.enterContext(patch.object(qualification.ManagedLoginMount, 'confirm'))
        case.scenario.initialize_home = qualification.LOGIN_MOUNT
        return case, login_home

    def test_sensitive_qualification_workspace_refuses_before_login_ledger_and_birth(self):
        repositories = self.fixture.repositories
        parent = repositories.root / 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
        parent.mkdir(mode=0o700)
        repositories.worker = repositories.worker.rename(parent / 'worker')
        case, _login = self.managed_case()
        factory = self.fixture.factory(case)

        with (patch.object(qualification, 'claim_managed_login',
                           wraps=qualification.claim_managed_login) as claim,
              patch.object(runtime.admission, 'invoke_offline',
                           wraps=runtime.admission.invoke_offline) as invoke,
              self.assertRaisesRegex(OutboundRefused, 'outbound screening refused native model request')):
            factory.run()

        self.assertEqual((claim.call_count, invoke.call_count, len(self.fixture.spawned),
                          qualification.campaign_usage()['total']), (0, 0, 0, 0))
        family.assert_no_native_births(self, self.fixture)
        self.assertFalse(case.ledger.root.exists())
        self.assertFalse((case.host.state / 'registered-startup.json').exists())
        self.assertIsNone(factory._qualification_start)
        self.assertFalse(factory._started)

    def test_managed_login_preserves_original_spool_and_excludes_other_roles(self):
        case, login_home = self.managed_case(drift=True)
        factory = self.fixture.factory(case)
        self.assertEqual(factory.home, case.home)
        with self.assertRaisesRegex(ValueError, 'profile readback'):
            factory.run()
        self.assertEqual(factory.server.codex_home, case.home)
        self.assertEqual(factory.server.lifetime.provider_network._providers,
                         runtime.provider_network.PROVIDERS | {'auth.openai.com'})
        for role in ('tool', 'validator'):
            lifetime = runtime._Containment(factory, role=role)
            self.assertNotIn(str(login_home), lifetime._command([case.spec['validator']], None, 1, 2))
            self.assertEqual(lifetime._provider_network_fds(), ())
        self.assertEqual(qualification.campaign_usage()['total'], 1)
        lease = qualification.claim_managed_login()
        qualification.release_managed_login(lease)

    def test_managed_login_rejects_unsafe_auth_metadata_and_interlock(self):
        case, login_home = self.managed_case()
        auth = login_home / 'auth.json'
        alternate = login_home / 'EXAMPLE-other'
        auth.rename(alternate)
        auth.symlink_to(alternate)
        with self.assertRaisesRegex(ValueError, 'private authentication file'):
            self.fixture.factory(case)
        auth.unlink()
        alternate.rename(auth)
        factory = self.fixture.factory(case)
        with self.assertRaisesRegex(ValueError, 'one authentication mode'):
            factory.run(provider_access_token=_EXAMPLE_ACCESS_TOKEN)
        lease = qualification.claim_managed_login()
        try:
            with self.assertRaisesRegex(ValueError, 'unresolved'):
                factory.run()
        finally:
            qualification.release_managed_login(lease)
        self.assertEqual(qualification.campaign_usage()['total'], 0)
        self.assertEqual(self.fixture.spawned, [])

    def test_unsupported_login_mount_refuses_before_charge_and_releases_confirmed_namespace(self):
        case, _login = self.managed_case()
        factory = self.fixture.factory(case)
        with patch.object(runtime._Containment, '_confirm_mounts', side_effect=ValueError('EXAMPLE unsupported mount')):
            with self.assertRaisesRegex(ValueError, 'unsupported mount'):
                factory.run()
        self.assertEqual(qualification.campaign_usage()['total'], 0)
        self.assertTrue(factory._managed_lifetime.contained)
        qualification.release_managed_login(qualification.claim_managed_login())

    def test_unknown_login_mount_teardown_preserves_the_interlock(self):
        case, _login = self.managed_case(drift=True)
        factory = self.fixture.factory(case)
        with patch.object(runtime._Containment, '_stop_namespace', side_effect=ValueError('EXAMPLE unknown teardown')):
            with self.assertRaisesRegex(ValueError, 'profile readback'):
                factory.run()
        self.assertFalse(factory._managed_lifetime.contained)
        with self.assertRaisesRegex(qualification.QualificationError, 'unresolved'):
            qualification.claim_managed_login()

    def test_managed_login_requires_permit_before_looking_up_the_login(self):
        case, _login = self.managed_case()
        with patch.object(qualification, 'managed_login_home') as lookup:
            with self.assertRaises(runtime.live_availability.NativeLiveUnavailable):
                self.fixture.factory(case, qualification_permit=None)
        lookup.assert_not_called()
        self.assertEqual(self.fixture.spawned, [])

    def test_reported_rollout_cannot_point_into_the_login_home(self):
        case, _login = self.managed_case()
        factory = self.fixture.factory(case)
        original = case.scenario.thread_response

        def report_auth_path(*args, **kwargs):
            response = original(*args, **kwargs)
            response['thread']['path'] = str(qualification.LOGIN_MOUNT / 'auth.json')
            return response

        with patch.object(case.scenario, 'thread_response', side_effect=report_auth_path):
            with self.assertRaisesRegex(ValueError, 'reported qualification rollout path differs'):
                factory.run()
        self.assertEqual(qualification.campaign_usage()['total'], 1)
        self.assertNotIn('turn/start', self.fixture.spawned[0].methods)

    def test_managed_login_captures_and_archives_the_original_reported_rollout(self):
        from tests import test_registered_finite_tool_wiring as wiring

        case, _login = self.managed_case(archive_schedule='settled')
        factory = self.fixture.factory(case)
        checkout = wiring.RegisteredFiniteToolWiringTests(methodName='runTest')
        checkout.fixture = self.fixture
        self.addCleanup(family.cleanup_helper, self, checkout)
        request_start, request_read = case.scenario.thread_response, case.scenario.read_thread

        def project(thread):
            relative = Path(thread['path']).relative_to(case.home)
            thread['path'] = str(qualification.LOGIN_MOUNT / relative)

        def start(*args, **kwargs):
            response = request_start(*args, **kwargs)
            project(response['thread'])
            return response

        def read(*args, **kwargs):
            thread, latency = request_read(*args, **kwargs)
            project(thread)
            return thread, latency

        with (patch.object(case.scenario, 'thread_response', side_effect=start),
              patch.object(case.scenario, 'read_thread', side_effect=read),
              patch.object(family, 'RpcProcess', wiring.NamespacedFiniteRpcProcess),
              checkout._positive_finite_completion(case)):
            result = factory.run()

        self.assertEqual(result['attempt']['outcome'], 'completed')
        self.assertEqual(case.scenario.path.parent, case.home / 'archived_sessions')
        identity = qualification.native_session_boundary.session_source_identity(
            case.scenario.path, case.scenario.thread_id)
        self.assertEqual(factory._managed_login.rollout, identity)

    def test_access_token_requires_signed_qualification_before_effect(self):
        case = self.fixture.case()
        factory = self.fixture.factory(case)
        with patch.object(runtime.live_availability, 'N1_LIVE_AVAILABLE', True):
            with self.assertRaisesRegex(ValueError, 'signed qualification'):
                factory.run(provider_access_token=_EXAMPLE_ACCESS_TOKEN)
        self.assertFalse((case.home / 'config.toml').exists())
        self.assertEqual(self.fixture.spawned, [])

    def test_malformed_access_tokens_refuse_before_effect(self):
        case = self.fixture.case(qualification=True)
        factory = self.fixture.factory(case)
        for token in ('', 'EXAMPLE-jwt', 'at-', 'at-EXAMPLE\nvalue', 'at-EXAMPLE\0value',
                      'at-EXAMPLEé', 'at-' + 'x' * 4096, _EXAMPLE_ACCESS_TOKEN.encode()):
            with self.subTest(token_type=type(token).__name__):
                with self.assertRaisesRegex(ValueError, 'personal access token'):
                    factory.run(provider_access_token=token)
        self.assertEqual(qualification.campaign_usage()['total'], 0)
        self.assertFalse((case.home / 'config.toml').exists())
        self.assertEqual(self.fixture.spawned, [])

    def test_access_token_handoff_is_bounded_to_the_original_appserver_birth(self):
        case = self.fixture.case(qualification=True, drift=True)
        factory = self.fixture.factory(case)
        lifetimes = []
        launch = runtime._Containment._provider_network_fds

        def capture(lifetime):
            descriptors = launch(lifetime)
            lifetimes.append((lifetime, {fd: _fd_identity(fd) for fd in descriptors}))
            return descriptors

        with patch.object(runtime._Containment, '_provider_network_fds', capture):
            with self.assertRaisesRegex(ValueError, 'profile readback'):
                factory.run(provider_access_token=_EXAMPLE_ACCESS_TOKEN)
            with self.assertRaisesRegex(ValueError, 'one original launch'):
                factory.run(provider_access_token=_EXAMPLE_ACCESS_TOKEN)
        [(lifetime, descriptors)] = lifetimes
        self.assertEqual(lifetime.role, 'appserver')
        control, attachment = descriptors
        self.assertNotEqual(control, attachment)
        self.assertNotIn(_EXAMPLE_ACCESS_TOKEN, repr(self.fixture.tables[0].spawn_calls))
        self.assertNotIn(_EXAMPLE_ACCESS_TOKEN.encode(), (case.home / 'config.toml').read_bytes())
        for descriptor, identity in descriptors.items():
            self.assertIsNotNone(identity)
            self.assertNotEqual(_fd_identity(descriptor), identity)
        self.assertEqual(qualification.campaign_usage()['total'], 1)
        self.assertEqual(len(self.fixture.spawned), 1)

    def test_early_launch_refusal_releases_the_staged_attachment(self):
        case = self.fixture.case(qualification=True)
        factory = self.fixture.factory(case)
        lifetimes = []

        def refuse(lifetime, *_args):
            descriptor = lifetime._access_token_fd
            lifetimes.append((lifetime, descriptor, _fd_identity(descriptor)))
            raise runtime.native.OfflineHostError('EXAMPLE launcher refusal')

        with patch.object(runtime._Containment, '_command', refuse):
            with self.assertRaisesRegex(ValueError, 'EXAMPLE launcher refusal'):
                factory.run(provider_access_token=_EXAMPLE_ACCESS_TOKEN)
        [(lifetime, descriptor, identity)] = lifetimes
        self.assertIsNotNone(identity)
        self.assertNotEqual(_fd_identity(descriptor), identity)
        self.assertEqual(lifetime.provider_network.child_socket.fileno(), -1)
        self.assertIsNone(factory._provider_access_token)
        self.assertEqual(qualification.campaign_usage()['total'], 0)
        self.assertEqual(self.fixture.spawned, [])

    def test_tampered_permit_and_expiry_refused_before_worker(self):
        case = self.fixture.case(qualification=True)
        permit = case.qualification_permit
        permit['authorization']['expires_at'] += 1
        with self.assertRaises(MaintenanceAuthorityError):
            self.fixture.factory(case, qualification_permit=permit)
        valid = self.fixture.qualification_permit(case)
        with patch.object(qualification.time, 'time', return_value=valid['authorization']['expires_at']):
            with self.assertRaisesRegex(qualification.QualificationError, 'expired'):
                self.fixture.factory(case, qualification_permit=valid)
        self.assertEqual(qualification.campaign_usage()['total'], 0)
        self.assertEqual(self.fixture.spawned, [])

    def test_permit_requires_signed_version_two_and_exact_integer_start_limit(self):
        case = self.fixture.case(qualification=True)
        permit = case.qualification_permit
        body = permit['authorization']
        legacy = {**body, 'version': 1}
        legacy.pop('start_limit', None)
        signer = self.fixture.authority
        for invalid in (legacy, {**body, 'version': 1}, {**body, 'version': 2.0},
                        {**body, 'start_limit': 21}, {**body, 'start_limit': 15}, {**body, 'start_limit': 20.0}):
            directive = signer.sign(canonical_authority_sha256(invalid), qualification.CAMPAIGN,
                                    parent=canonical_authority_sha256(signer.directive))
            with self.subTest(authorization=invalid):
                with self.assertRaisesRegex(qualification.QualificationError, 'permit does not bind'):
                    self.fixture.factory(case, qualification_permit={'authorization': invalid, 'directive': directive})
        wrong_signature = {'authorization': body, 'directive': signer.sign(
            canonical_authority_sha256({**body, 'start_limit': 21}), qualification.CAMPAIGN,
            parent=canonical_authority_sha256(signer.directive))}
        with self.assertRaises(MaintenanceAuthorityError):
            self.fixture.factory(case, qualification_permit=wrong_signature)
        self.assertEqual((body['version'], body['start_limit']), (2, 20))
        self.fixture.factory(case).require_launch_selection()
        self.assertEqual(qualification.campaign_usage()['total'], 0)
        self.assertEqual(self.fixture.spawned, [])

    def test_total_limit_refuses_before_any_worker_or_configuration(self):
        case = self.fixture.case(qualification=True)
        expires_at = case.qualification_permit['authorization']['expires_at']
        for index in range(20):
            qualification._campaign_start(
                qualification._StartRequest(f'{index:064x}', expires_at, None))
        with self.assertRaisesRegex(qualification.QualificationError, 'campaign.*limit'):
            self.fixture.factory(case).run()
        self.assertEqual(qualification.campaign_usage()['total'], 20)
        self.assertFalse((case.home / 'config.toml').exists())
        self.assertEqual(self.fixture.spawned, [])

    def test_alternate_signed_model_plan_and_nondefault_config_are_refused(self):
        case = self.fixture.case(qualification=True)
        plan = case.capability.bound_plan()
        operation = case.capability.evidence()['operation']
        for key, value in (('model', 'gpt-6.2-astra'), ('effort', 'ultra'), ('provider', 'alternate')):
            with self.subTest(field=key), self.assertRaisesRegex(qualification.QualificationError, 'Exact qualification'):
                qualification.require_model_selection(dict(case.spec, **{key: value}), plan, operation)
        files = dict(case.spec['configuration_files'])
        files['config.toml'] = files['config.toml'].replace('service_tier = "default"', 'service_tier = "priority"')
        with self.assertRaisesRegex(ValueError, 'Registered configuration'):
            runtime._configuration(dict(case.spec, configuration_files=files), case.host.worker)

    def test_raw_transport_cannot_adopt_another_factory_permit(self):
        case = self.fixture.case(qualification=True)
        self.fixture.factory(case).require_launch_selection()

        class OtherTransport(AppServer):
            def _require_rpc(self, _method):
                return None

        server = object.__new__(OtherTransport)
        server.qualification_permit = case.qualification_permit
        with self.assertRaises(runtime.live_availability.NativeLiveUnavailable):
            server.request('thread/start', {})
        with self.assertRaises(runtime.live_availability.NativeLiveUnavailable):
            server.start_turn('thread', 'benign fixture')

    def test_started_worker_failure_is_charged_at_release(self):
        case = self.fixture.case(qualification=True, drift=True)
        factory = self.fixture.factory(case)
        with self.assertRaisesRegex(ValueError, 'profile readback'):
            factory.run()
        case.schema_check.assert_called_once()
        self.assertIs(case.schema_check.call_args.kwargs['n1_qualification'], True)
        self.assertEqual(qualification.campaign_usage()['total'], 1)
        self.assertEqual(len(self.fixture.spawned), 1)
        self.assertNotIn('turn/start', self.fixture.spawned[0].methods)
        self.assertTrue(factory.server.lifetime.contained)

    def test_schema_refusal_precedes_appserver_birth_and_campaign_start(self):
        case = self.fixture.case(qualification=True, drift=True)
        factory = self.fixture.factory(case)
        scratch = Path(self.enterContext(tempfile.TemporaryDirectory()))
        checked_binary = Path(case.spec['executable'])

        def refuse(binary, *, launcher, n1_qualification):
            self.assertEqual(binary, checked_binary)
            self.assertIs(n1_qualification, True)
            self.assertEqual(qualification.campaign_usage()['total'], 0)
            self.assertEqual(self.fixture.spawned, [])
            argv = launcher(scratch)
            self.assertIn('--unshare-all', argv)
            self.assertEqual(argv[argv.index('--chdir') + 1], str(scratch))
            self.assertNotIn(str(case.home), argv)
            raise CapabilityError('EXAMPLE missing qualification namespace')

        with patch.object(selected, 'check_codex_capabilities', side_effect=refuse) as check:
            with self.assertRaisesRegex(ValueError, 'missing qualification namespace'):
                factory.run()
        check.assert_called_once()
        self.assertEqual(self.fixture.spawned, [])
        self.assertEqual(qualification.campaign_usage()['total'], 0)

    def test_ordinary_registered_launch_does_not_require_qualification_schema(self):
        case = self.fixture.case(drift=True)
        factory = self.fixture.factory(case)
        with patch.object(selected, 'check_codex_capabilities') as check:
            with self.assertRaisesRegex(ValueError, 'profile readback'):
                factory.run()
        check.assert_not_called()
        self.assertEqual(len(self.fixture.spawned), 1)

    def test_schema_executable_must_match_the_signed_digest(self):
        directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        binary = directory / 'codex'
        binary.write_bytes(b'EXAMPLE different executable')
        binary.chmod(0o700)
        with patch.object(selected, 'check_codex_capabilities') as check:
            with self.assertRaisesRegex(qualification.QualificationError, 'differs from the signed binary'):
                qualification.require_executable_schema(str(binary), '0' * 64)
        check.assert_not_called()

    def test_composed_fixture_restores_process_denial(self):
        original_kill = os.kill
        try:
            self.fixture.case(qualification=True)
            self.assertIsNot(os.kill, original_kill)
        finally:
            self.doCleanups()
            restored_kill = os.kill
            # Keep a failing cleanup witness from leaking its own fixture.
            family.cleanup_helper(self, self.fixture.processes)
            family.cleanup_helper(self, self.fixture.authority)
        self.assertIs(restored_kill, original_kill)

    def test_registered_startup_retains_timestamped_notifications_and_stops_before_turn(self):
        from cwo_core.supervision.transport import app_server

        case, _login = self.managed_case(no_fake_scheduler=True)
        factory = self.fixture.factory(case)
        timestamp = 1795442406000
        remote_control = {'method': 'remoteControl/status/changed', 'params': {'status': 'disabled'},
                          'emittedAtMs': timestamp}
        original_gate = app_server._require_native_rpc

        class TimestampedStartup(family.RpcProcess):
            def result(self, method, params):
                result = super().result(method, params)
                if method == 'thread/start':
                    self.stdout.put(remote_control)
                    self.stdout.put({'method': 'thread/started', 'params': {'thread': result['thread']},
                                     'emittedAtMs': timestamp + 1})
                return result

        def stop_before_turn(method, transport=None):
            if method == 'turn/start':
                with self.assertRaises(runtime.live_availability.NativeLiveUnavailable):
                    original_gate('remoteControl/enable', transport)
                raise ValueError('EXAMPLE stopped before model turn')
            return original_gate(method, transport)

        with (patch.object(family, 'RpcProcess', TimestampedStartup),
              patch.object(app_server, '_require_native_rpc', side_effect=stop_before_turn),
              self.assertRaisesRegex(ValueError, 'EXAMPLE stopped before model turn')):
            factory.run()

        self.assertEqual(factory.server.thread_id, case.scenario.thread_id)
        events = [notification for _, notification in factory.server._notifications]
        self.assertIn(remote_control, events)
        started, = [notification for notification in events if notification['method'] == 'thread/started']
        self.assertEqual(started['emittedAtMs'], timestamp + 1)
        stages = [json.loads(path.read_bytes())['stage'] for path in
                  (factory.records / 'transport-observations').glob('observation-*.json')]
        self.assertIn('qualification-dispatch', stages)
        self.assertIn('finite-tool-catalog', stages)
        self.assertNotIn('turn/start', self.fixture.spawned[0].methods)
        self.assertTrue(factory.server.lifetime.contained)
