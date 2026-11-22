"""Offline qualification authority and campaign accounting fixtures."""

from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from tests import test_registered_n1_factory as family

import registered_n1_qualification as qualification
from cwo_core import model_identities
from cwo_core.maintenance_authority import MaintenanceAuthorityError
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

    def test_one_budget_survives_new_controllers_and_signed_rechecks(self):
        for index in range(10):
            qualification._campaign_start(self.record(index))
        with self.assertRaisesRegex(qualification.QualificationError, 'initial.*limit'):
            qualification._campaign_start(self.record(10))
        with ThreadPoolExecutor(max_workers=4) as workers:
            rows = list(workers.map(qualification._campaign_start,
                [self.record(index, repair='a' * 64) for index in range(10, 15)]))
        self.assertEqual(sorted(row['sequence'] for row in rows), list(range(11, 16)))
        self.assertEqual(qualification.campaign_usage(), {'initial': 10, 'rechecks': 5, 'total': 15})
        with self.assertRaisesRegex(qualification.QualificationError, 'campaign.*limit'):
            qualification._campaign_start(self.record(15, repair='b' * 64))
        with self.assertRaises(FileExistsError):
            qualification.initialize_campaign()

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

    def test_initial_limit_refuses_before_any_worker_or_configuration(self):
        case = self.fixture.case(qualification=True)
        expires_at = case.qualification_permit['authorization']['expires_at']
        for index in range(qualification.INITIAL_LIMIT):
            qualification._campaign_start(
                qualification._StartRequest(f'{index:064x}', expires_at, None))
        with self.assertRaisesRegex(qualification.QualificationError, 'initial.*limit'):
            self.fixture.factory(case).run()
        self.assertEqual(qualification.campaign_usage()['total'], qualification.INITIAL_LIMIT)
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
        self.assertEqual(qualification.campaign_usage()['total'], 1)
        self.assertEqual(len(self.fixture.spawned), 1)
        self.assertNotIn('turn/start', self.fixture.spawned[0].methods)
        self.assertTrue(factory.server.lifetime.contained)

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
