"""Registered pool profile joins through the actual pool and N1 factories.

Only original non-test helper functions are bound below. No concrete upstream
TestCase becomes a module global or contributes tests to this family.
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'tests')]
import test_registered_native_pool_host as F  # noqa: E402
import test_registered_finite_tool_wiring as tools  # noqa: E402


class PoolProfileTests(unittest.TestCase):
    cohort = F.PoolTests.cohort
    adopt = F.PoolTests.adopt
    execute = F.PoolTests.execute
    attempts = F.PoolTests.attempts
    assert_accounting = F.PoolTests.assert_accounting
    assert_source_retained = F.PoolTests.assert_source_retained

    def assert_admitted_accounting(self, invoked):
        self.assert_accounting(invoked)
        rows = list(self.attempts().values())
        expected = {worker: json.loads(f.case.receipt.amounts_bytes)
                    for worker, f in zip(self.workers, self.fixtures)}
        self.assertEqual(len(rows), len(expected))
        self.assertEqual({r['request_id']: r['amount'] for r in rows}, expected)
        self.assertEqual({r['request_id']: r['charge'] for r in rows}, expected)
        summary = self.ledger.summary(self.config.pool_id)
        self.assertEqual(summary['charged'], {key: sum(a[key] for a in expected.values())
                                             for key in next(iter(expected.values()))})
        for worker, fixture in zip(self.workers[:invoked], self.fixtures[:invoked]):
            path = fixture.case.ledger.root / F.P.R.admission.ledger_api.LEDGER_FILE
            member_rows = list(json.loads(path.read_bytes())['attempts'].values())
            self.assertEqual(len(member_rows), 1)
            self.assertEqual(member_rows[0]['admission_sha256'],
                             F.P.R.admission._receipt_sha256(fixture.case.receipt))
            self.assertEqual(member_rows[0]['amount'], expected[worker])
            self.assertEqual(member_rows[0]['charge'], expected[worker])
        return {row['request_id']: row for row in rows}

    def assert_foreign_profile_refusal(self, size):
        # Current strict correlation closes the connection; it cannot be followed
        # by a useful command on that same connection as the old fixture assumed.
        try:
            self.cohort(size, archive_schedule='settled', shared_source=True)
            failed = self.fixtures[-1]
            foreign = self.fixtures[0].case.scenario.thread_id if size > 1 else 'EXAMPLE-other-thread'
            failed.case.probe_approvals = [{'threadId': foreign}]
            self.adopt()
            with self.assertRaises(ValueError):
                self.host.run(self.config.request('execute'))
            self.assertEqual(self.host.status()['states'], ['validated'] * (size - 1) + ['failed'])
            self.assert_admitted_accounting(size)
            factory = failed.workflow.factory
            self.assertIn('Stale, reordered', str(factory.server.transport_failure))
            self.assertIsNone(factory.token)
        finally:
            self.doCleanups()

    def test_r2_pool_members_use_selected_finite_empty_poll_and_deny_nonempty(self):
        """Full-load acceptance: materialized member startup, signed tools and real byte gate."""
        original_case = F.N.FactoryTests.case
        def selected_case(fixture, **changes):
            return original_case(fixture, finite_tool_mode='captured-host-tools',
                                 materialize_on_turn_start=True, no_fake_scheduler=True, **changes)
        with F.F.WorkflowTests.read_only_source_family(self) as source:
            for chars in ('', 'EXAMPLE_TOKEN_0001'):
                with self.subTest(chars=chars), patch.object(F.N.FactoryTests, 'case', selected_case):
                    try:
                        self.cohort(2, archive_schedule='settled', shared_source=True,
                                    source_evidence=source())
                        for fixture in self.fixtures:
                            fixture.case.poll_chars = chars
                            fixture.case.complete_after_refusal = True
                        with patch.object(F.N, 'RpcProcess', tools.DynamicRpcProcess):
                            self.assertEqual(self.execute()['states'], ['validated', 'validated'])
                        self.assert_admitted_accounting(2)
                        for fixture in self.fixtures:
                            case, factory = fixture.case, fixture.workflow.factory
                            self.assertEqual(factory.spec['implementation_sha256'], F.P.R.implementation_sha256())
                            self.assertEqual(factory.spec['finite_tool_mode'], 'captured-host-tools')
                            self.assertEqual(factory.spec['pre_effect'], case.spec['pre_effect'])
                            self.assertEqual(factory.spec['configuration_pins'], case.spec['configuration_pins'])
                            boundary = factory.adapter._effective_boundary
                            self.assertEqual(boundary['thread_start']['request']['permissions'],
                                             case.spec['thread_start']['permissions'])
                            self.assertEqual(boundary['thread_response']['activePermissionProfile'],
                                             case.spec['profile_readback']['activePermissionProfile'])
                            self.assertIs(factory.server.finite_input.factory, factory)
                            self.assertIn('EXAMPLE-poll-call', factory.server.finite_input.used_approvals)
                            observations = [json.loads(path.read_bytes()) for path in
                                            (factory.records / 'transport-observations').iterdir()]
                            self.assertEqual(any(row['stage'] == 'finite-poll-intent' for row in observations), not chars)
                            self.assertEqual(factory.server.finite_input.dynamic_command[:3],
                                             (case.scenario.thread_id, case.scenario.turn_id, 'EXAMPLE-command-call'))
                            replies = fixture.fixture.spawned[0].replies
                            self.assertEqual([r['result']['success'] for r in replies], [True, chars == ''])
                            self.assertEqual(replies[0]['result']['contentItems'][0]['text'],
                                             'EXAMPLE finite command output\n')
                            if chars:
                                self.assertEqual(replies[1]['result']['contentItems'][0]['text'],
                                                 'finite-tool-request-refused')
                            else:
                                observed = json.loads(replies[1]['result']['contentItems'][0]['text'])
                                self.assertIs(type(observed), dict)
                                self.assertEqual(set(observed), {'running', 'stdout'})
                                self.assertIs(observed['running'], True)
                                self.assertEqual(observed['stdout'], 'EXAMPLE finite poll output\n')
                            with self.assertRaises(BlockingIOError):
                                os.read(case.tool_read, 1)
                            self.assertEqual(len(fixture.fixture.spawned), 3)
                            self.assertFalse(fixture.fixture.spawned[1].process.alive)
                            self.assertEqual(F.P.W.V.consume_validated(*factory.issued_artifact()),
                                             (('result.txt', F.N.fixtures.host_fixtures.OUTPUT),))
                            self.assertFalse(case.host.target.joinpath('result.txt').exists())
                    finally:
                        self.doCleanups()

    def test_r2_unsupported_input_capability_refuses_at_actual_host_before_startup(self):
        """An authentic parent signature cannot invent registered input support."""
        self.cohort(2)
        member = self.fixtures[1]
        plan, operation, _ = copy.deepcopy(member.workflow.config.native_bundle)
        plan['registered_n1']['pre_effect']['input_capability'] = 'EXAMPLE_UNSUPPORTED_INPUT'
        directive = member.fixture.authority.reseal(plan, operation)
        member.workflow.config.native_bundle = [plan, operation, directive]
        with self.assertRaisesRegex(ValueError, 'unsupported input'):
            self.host.run(self.config.request('validate-only'))
        self.assertFalse(list(self.state.iterdir()))
        self.assertFalse(self.ledger.root.exists())
        for fixture in self.fixtures:
            self.assertFalse(fixture.case.ledger.root.exists())
            self.assertFalse(fixture.case.host.worker.joinpath('result.txt').exists())
            self.assertFalse(hasattr(fixture.fixture, 'spawned'))


    def test_r2_each_finite_profile_refuses_unproved_retry_and_stdin(self):
        """New per-member profile/correlation join, not the producer matrix."""
        for size in (1, 2, 3):
            with self.subTest(size=size):
                try:
                    self.cohort(size, archive_schedule='settled')
                    for fixture in self.fixtures:
                        case = fixture.case
                        case.probe_approvals = [
                            {'additionalPermissions': {}, 'reason': 'EXAMPLE approved retry'},
                            {'kind': 'writeStdin', 'reason': 'EXAMPLE approved retry'},
                        ]
                        # Reason text cannot distinguish a safe command from widening.
                        case.approval_change = {'reason': 'EXAMPLE approved retry'}
                    report = self.execute()
                    self.assertEqual(report['states'], ['validated'] * size)
                    self.assert_admitted_accounting(size)
                    threads = []
                    for fixture in self.fixtures:
                        case, factory = fixture.case, fixture.workflow.factory
                        threads.append(factory.adapter.thread_id)
                        self.assertIs(type(factory), F.P.R.RegisteredN1Factory)
                        self.assertIs(type(factory.server), F.P.R._RegisteredServer)
                        self.assertEqual(factory.spec['pre_effect'], case.spec['pre_effect'])
                        self.assertEqual(factory.spec['configuration_pins'], case.spec['configuration_pins'])
                        start = factory.adapter._effective_boundary['thread_start']
                        self.assertEqual(start['request']['permissions'], case.spec['thread_start']['permissions'])
                        self.assertEqual(start['response']['activePermissionProfile'],
                                         case.spec['profile_readback']['activePermissionProfile'])
                        observations = [json.loads(path.read_bytes())
                                        for path in sorted((factory.records / 'transport-observations').iterdir())]
                        approvals = [row['observation'] for row in observations if row['stage'] == 'approval']
                        self.assertEqual([a['decision'] for a in approvals], ['decline'] * 2 + ['accept'])
                        self.assertEqual(approvals[-1]['params']['threadId'], case.scenario.thread_id)
                        self.assertEqual(approvals[-1]['params']['turnId'], case.scenario.turn_id)
                        self.assertEqual(approvals[-1]['params']['cwd'], str(case.host.worker))
                        self.assertEqual(F.P.W.V.consume_validated(*factory.issued_artifact()),
                                         (('result.txt', F.N.fixtures.host_fixtures.OUTPUT),))
                        self.assertFalse(case.host.target.joinpath('result.txt').exists())
                    self.assertEqual(len(set(threads)), size)
                    before = copy.deepcopy(self.attempts())
                    with self.assertRaisesRegex(ValueError, 'never redispatch'):
                        self.host.run(self.config.request('execute'))
                    self.assertEqual(self.attempts(), before)
                finally:
                    self.doCleanups()
                self.assert_foreign_profile_refusal(size)


    def test_r3_member_profile_drift_retains_sibling_evidence_and_spend(self):
        """Exact readback failure after a useful sibling, with no profile fallback."""
        self.cohort(3, archive_schedule='settled')
        self.fixtures[1].case.drift = True
        self.adopt()
        with self.assertRaisesRegex(ValueError, 'profile|fallback|drift'):
            self.host.run(self.config.request('execute'))
        self.assertEqual(self.host.status()['states'], ['validated', 'failed', 'held'])
        rows = self.assert_admitted_accounting(2)
        self.assertEqual([(rows[w]['state'], rows[w]['outcome']) for w in self.workers],
                         [('terminal', 'completed'), ('terminal', 'unknown'), ('reserved', None)])
        first, failed, held = self.fixtures
        self.assertEqual(F.P.W.V.consume_validated(*first.workflow.factory.issued_artifact()),
                         (('result.txt', F.N.fixtures.host_fixtures.OUTPUT),))
        self.assertFalse(failed.case.host.worker.joinpath('result.txt').exists())
        self.assertFalse(hasattr(held.fixture, 'spawned'))
        before = copy.deepcopy(self.attempts())
        with self.assertRaisesRegex(ValueError, 'never redispatch'):
            self.host.run(self.config.request('execute'))
        self.assertEqual(self.attempts(), before)
