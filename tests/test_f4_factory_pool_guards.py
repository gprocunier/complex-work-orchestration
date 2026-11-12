"""Fault-specific factory/pool refusals with otherwise current bindings.

Reuse existing EXAMPLE builders without collecting their test classes. All
process effects remain behind their fake OS/RPC fixtures and test-only holds.
"""
from __future__ import annotations

import copy
import json
import os
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'tests')]
import registered_host_root_boundary as roots
import registered_n1_factory as R
import registered_native_pool_host as P
import test_registered_n1_factory as N
import test_registered_native_pool_host as pools


class NextBoundary(Exception):
    """Stop a positive control at the next effect boundary, before any launch."""


class F4FactoryPoolGuardTests(unittest.TestCase):
    def factory_fixture(self, **changes):
        fixture = N.FactoryTests('runTest')
        fixture._outcome = self._outcome
        fixture.setUp()
        self.addCleanup(N.cleanup_helper, self, fixture)
        case = fixture.case(**changes)
        return fixture, case, fixture.factory(case)

    def pool_fixture(self):
        fixture = pools.PoolTests('runTest')
        fixture._outcome = self._outcome
        self.addCleanup(N.cleanup_helper, self, fixture)
        fixture.cohort(1)
        return fixture

    @staticmethod
    def invoke(factory, effect):
        return R.admission.invoke_offline(factory.receipt, factory.route, factory.node_id,
            ledger=factory.ledger, effect=effect, observer=factory._observer)

    @staticmethod
    def decision_state(factory):
        # The decision has no process dependency: supply its original observed
        # item/turn fields, while require_effect still verifies real custody.
        server = object.__new__(R._RegisteredServer)
        server.factory, server.finite_tools = factory, None
        server._approval_ids = set()
        correlation = ('EXAMPLE-thread', 'EXAMPLE-turn', 'EXAMPLE-item')
        server._wire_turn = correlation[:2]
        server._items = {correlation: {'type': 'commandExecution', 'status': 'inProgress',
            'command': factory.spec['command'], 'cwd': str(factory.host.worker)}}
        params = dict(zip(('threadId', 'turnId', 'itemId'), correlation))
        params.update(approvalId='EXAMPLE-approval', startedAtMs=1000, kind='command',
            command=factory.spec['command'], cwd=str(factory.host.worker),
            availableDecisions=['accept', 'decline'])
        return server, params

    def test_F4_M131_M132_initial_spool_entry_bound_and_configured_file_clause(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            config = home / 'config.toml'
            config.write_text('EXAMPLE staged configuration')
            R._cold_spool(home, True)
            with self.assertRaisesRegex(ValueError, 'unregistered initial spool file'):
                R._cold_spool(home, False)
            config.unlink()
            sessions = home / 'sessions'
            sessions.mkdir()
            for index in range(63):
                (sessions / str(index)).mkdir()
            R._cold_spool(home, False)  # Exactly 64 entries is still allowed.
            (sessions / 'EXAMPLE-65th').mkdir()
            with self.assertRaisesRegex(ValueError, 'entry bound'):
                R._cold_spool(home, False)

    def test_F4_M133_each_containment_role_requires_its_exact_launch_command(self):
        fixture, _case, factory = self.factory_fixture()
        commands = {
            'appserver': [factory.spec['executable'], 'app-server', '--stdio'],
            'tool': ['/usr/bin/sh', '-c', factory.spec['command']],
            'validator': [factory.spec['validator'], '-I', '-S', '-c', R._VALIDATOR],
        }

        def effect(*_args):
            for role, allowed in commands.items():
                lifetime = R._Containment(factory, role=role)
                with self.subTest(role=role), patch.object(lifetime, '_preflight_tool_launch',
                        side_effect=NextBoundary) as following:
                    with self.assertRaises(NextBoundary):
                        lifetime.launch(allowed, factory.home)
                    following.reset_mock()
                    for command in ([*allowed, 'EXAMPLE-extra'], ['EXAMPLE-other-executable', *allowed[1:]]):
                        with self.subTest(command=command), self.assertRaisesRegex(ValueError, 'no other executable allowance'):
                            lifetime.launch(command, factory.home)
                    following.assert_not_called()
            return R.admission.ledger_api.EffectResult('completed')

        self.invoke(factory, effect)
        self.assertEqual(fixture.spawned, [])

    def test_F4_M134_approval_decision_requires_current_invocation_intent(self):
        fixture, _case, factory = self.factory_fixture()
        server, params = self.decision_state(factory)

        def effect(*_args):
            self.assertEqual(server._decision(R.protocol.COMMAND, params), 'accept')
            return R.admission.ledger_api.EffectResult('completed')

        self.invoke(factory, effect)
        fresh = dict(params, approvalId='EXAMPLE-after-settlement')
        before = set(server._approval_ids)
        with self.assertRaisesRegex(ValueError, 'persisted invocation intent differs'):
            server._decision(R.protocol.COMMAND, fresh)
        self.assertEqual(server._approval_ids, before)
        self.assertEqual(fixture.spawned, [])


    def test_F4_M138_M139_guard_rechecks_private_roots_and_original_host_snapshot(self):
        fixture, case, factory = self.factory_fixture()
        factory.guard()
        # An added child-visible mount makes just the previously private target
        # exposed; every directory, signed plan and host observation stays intact.
        with patch.object(roots, '_RUNTIME', (*roots._RUNTIME, case.host.target)), \
                self.assertRaisesRegex(ValueError, 'Protected roots intersect'):
            factory.guard()
        factory.guard()
        with patch.object(factory, '_host_bytes', b'EXAMPLE different original host binding'), \
                self.assertRaisesRegex(ValueError, 'Original host binding changed'):
            factory.guard()
        factory.guard()
        self.assertEqual(fixture.spawned, [])

    def test_F4_M141_each_invocation_argument_must_match_original_admission(self):
        fixture, _case, factory = self.factory_fixture()
        request = factory.receipt.request_bytes
        execution = json.loads(factory.receipt.execution_bytes)
        allowance = json.loads(factory.receipt.amounts_bytes)
        changed_execution, changed_allowance = copy.deepcopy(execution), dict(allowance)
        changed_execution['effort'] = 'EXAMPLE-other-effort'
        resource = next(iter(changed_allowance))
        changed_allowance[resource] += 1
        cases = ((request + b'EXAMPLE different request', execution, allowance),
                 (request, changed_execution, allowance),
                 (request, execution, changed_allowance))

        def effect(*_args):
            for index, arguments in enumerate(cases):
                with self.subTest(argument=index), self.assertRaisesRegex(ValueError, 'Original admission invocation binding differs'):
                    factory._effect(*arguments, {})
            return R.admission.ledger_api.EffectResult('completed')

        self.invoke(factory, effect)
        self.assertEqual(fixture.spawned, [])

    def test_F4_M142_unavailable_artifact_refuses_before_validation_boundary(self):
        fixture, _case, factory = self.factory_fixture()
        # Probe the producer/validator boundary with the original guard and real
        # persisted intent. A producer fault must not invoke the validator.
        report = {'status': 'artifact-ready', 'error': None}
        probe = SimpleNamespace(receipt=factory.receipt, ledger=factory.ledger,
            guard=factory.guard, host=SimpleNamespace(run_registered=lambda _factory: dict(report)),
            execution=None, token=None)
        probe.host._initial = factory.host._initial
        probe.policy = factory.policy
        probe.record_native_return = lambda _report: None  # This status probe fakes the producer/custody surface.

        def effect(request, execution, allowance, observation):
            with patch.object(R.validation, 'validate_artifact', side_effect=NextBoundary) as validator:
                with self.assertRaises(NextBoundary):
                    R.RegisteredN1Factory._effect(probe, request, execution, allowance, observation)
                validator.reset_mock()
                for status in ('reconciliation-required', 'EXAMPLE-unavailable'):
                    report.update(status=status, error='EXAMPLE native artifact unavailable')
                    with self.subTest(status=status), self.assertRaisesRegex(R.native.OfflineHostError, 'EXAMPLE native artifact unavailable'):
                        R.RegisteredN1Factory._effect(probe, request, execution, allowance, observation)
                    validator.assert_not_called()
            return R.admission.ledger_api.EffectResult('completed')

        self.invoke(factory, effect)
        self.assertEqual(fixture.spawned, [])


    def test_F4_M114_git_metadata_read_rechecks_identity_and_bounded_length(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'EXAMPLE-metadata'
            path.write_bytes(b'EXAMPLE metadata')
            self.assertEqual(P._read_metadata(path, 1024), path.read_bytes())
            original = P.H.workspace_capture.read_at
            for fault in ('metadata-drift', 'short-read'):
                def read(*args, fault=fault, **kwargs):
                    kind, data, before = original(*args, **kwargs)
                    if fault == 'metadata-drift':
                        path.write_bytes(b'EXAMPLE changed!')
                        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns + 1))
                    else:
                        data = data[:-1]
                    return kind, data, before
                with self.subTest(fault=fault), patch.object(P.H.workspace_capture, 'read_at', read), \
                        self.assertRaisesRegex(ValueError, 'metadata changed during its bounded read'):
                    P._read_metadata(path, 1024)


    @staticmethod
    def configuration_inputs(pool):
        return {'pool_id': pool.config.pool_id,
            'controllers': dict(zip(pool.workers, pool.config.controllers)), 'state_directory': pool.state,
            'ledger': pool.ledger, 'limits': pool.config.limits, 'enabled': True}

    def test_F4_M119_M120_configuration_requires_exact_dict_and_boolean_types(self):
        pool = self.pool_fixture()
        settings = self.configuration_inputs(pool)
        P.PoolConfiguration(**settings)

        class NamedControllers(dict):
            pass

        cases = [('controllers', NamedControllers(settings['controllers']), 'Protected named controllers')]
        cases.extend(('enabled', value, 'enable switch must be Boolean') for value in (0, 1, 'EXAMPLE-enabled'))
        for field, value, message in cases:
            with self.subTest(field=field, value_type=type(value).__name__), self.assertRaisesRegex(ValueError, message):
                P.PoolConfiguration(**dict(settings, **{field: value}))

    def test_F4_M121_host_requires_exact_protected_configuration_type(self):
        pool = self.pool_fixture()
        self.assertIs(P.RegisteredNativePoolHost(pool.config).config, pool.config)

        class ConfigurationSubclass(P.PoolConfiguration):
            pass

        subclass = object.__new__(ConfigurationSubclass)
        subclass.__dict__.update(pool.config.__dict__)
        for configuration in (subclass, SimpleNamespace(**pool.config.__dict__)):
            with self.subTest(configuration_type=type(configuration).__name__), self.assertRaisesRegex(ValueError, 'Protected pool configuration is required'):
                P.RegisteredNativePoolHost(configuration)

    def test_F4_M123_adoption_rechecks_current_configuration_before_member_writes(self):
        pool = self.pool_fixture()
        pool.host._current()
        before = [fixture.settings['state_store'].read_state() for fixture in pool.fixtures]
        pool.config.enabled = False
        with self.assertRaisesRegex(ValueError, 'Protected pool source or configuration changed'):
            pool.adopt()
        self.assertEqual(before, [fixture.settings['state_store'].read_state() for fixture in pool.fixtures])
        self.assertTrue(all(workflow._adoption is None for workflow in pool.config.workflows))
        self.assertFalse(list(pool.state.iterdir()))

    def test_F4_M127_controlled_failure_requires_same_receipt_as_original_member(self):
        pool = self.pool_fixture()
        pool.config.controlled_failure_workers = tuple(pool.workers)
        pool.config.binding = pool.config.describe()
        pool.fixtures[0].case.bad_output = True
        with self.assertRaises(R.validation.ValidationError) as caught:
            pool.execute()
        workflow = pool.config.workflows[0]
        self.assertIs(getattr(workflow, '_pool_failure', None), caught.exception,
            'The pool must retain the exact issued original member failure.')
        primary = caught.exception
        evidence = P.RegisteredNativePoolHost._controlled_failure(workflow, primary)
        self.assertEqual(evidence, workflow.factory.controlled_failure(primary))
        self.assertEqual(evidence['outcome'], 'failed')
        self.assertEqual(next(iter(pool.attempts().values()))['outcome'], 'failed')
        original = workflow.config.receipt
        workflow.config.receipt = replace(original, budget_id='EXAMPLE-other-budget')
        try:
            with self.assertRaisesRegex(ValueError, 'Original member factory, operation and admission binding changed'):
                P.RegisteredNativePoolHost._controlled_failure(workflow, primary)
        finally:
            workflow.config.receipt = original

    def test_F4_M117_worktree_ownership_requires_both_time_and_entry_budgets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'EXAMPLE-file').touch()
            with patch.object(P.time, 'monotonic', return_value=0):
                self.assertEqual(len(P._worktree_ownership(root)), 2)
            with patch.object(P.time, 'monotonic', side_effect=(0, 11)), \
                    self.assertRaisesRegex(ValueError, 'inspection bound'):
                P._worktree_ownership(root)
            for index in range(19_999):
                (root / str(index)).touch()
            with patch.object(P.time, 'monotonic', return_value=0):
                self.assertEqual(len(P._worktree_ownership(root)), 20_001)
                (root / 'EXAMPLE-over-bound').touch()
                with self.assertRaisesRegex(ValueError, 'inspection bound'):
                    P._worktree_ownership(root)

    def test_F4_M135_repeated_approval_refuses_with_fresh_wire_request_context(self):
        fixture, _case, factory = self.factory_fixture()
        server, params = self.decision_state(factory)

        def effect(*_args):
            self.assertEqual(server._decision(R.protocol.COMMAND, params), 'accept')
            with self.assertRaisesRegex(ValueError, 'Repeated approval identity'):
                server._decision(R.protocol.COMMAND, dict(params))
            self.assertEqual(server._decision(R.protocol.COMMAND,
                dict(params, approvalId='EXAMPLE-distinct-approval')), 'accept')
            return R.admission.ledger_api.EffectResult('completed')

        self.invoke(factory, effect)
        self.assertEqual(fixture.spawned, [])


    def test_F4_M143_M144_known_output_rejection_requires_failed_file_and_complete_failure_shape(self):
        fixture, _case, factory = self.factory_fixture(bad_output=True)
        factory.select_controlled_failure()
        with self.assertRaises(R.validation.ValidationError) as caught:
            factory.run()
        primary, report = caught.exception, factory.execution
        self.assertTrue(factory._known_output_rejection(report, primary))
        cases = (
            ('validation-complete', {'offline_validation_complete': True}),
            ('host-checks-missing', {'host_checks': []}),
            ('errors-missing', {'errors': []}),
        )
        for name, changes in cases:
            observed = primary.report
            observed.update(changes)
            malformed = R.validation.ValidationError('EXAMPLE malformed failure report', observed)
            with self.subTest(shape=name):
                self.assertFalse(factory._known_output_rejection(report, malformed))
        self.assertEqual(fixture.attempt(_case)['outcome'], 'failed')


if __name__ == '__main__':
    unittest.main()
