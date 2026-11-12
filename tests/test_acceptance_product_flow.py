"""Real original HTTP adjudication writes closure authority; fake bd only."""
from __future__ import annotations

from contextlib import contextmanager, redirect_stdout
from io import StringIO
import json
import shutil
import subprocess
import sys
import unittest
from unittest.mock import patch

from tests import test_workflow_adjudication as W
from tests import test_production_closure as P
from cwo_core import host_records, policy
import setup_workspace_database as setup

workflow, binding = W.workflow, W.binding


class AcceptanceProductFlowTests(unittest.TestCase):
    make_host = W.WorkflowAdjudicationTests.make_host
    resolve = W.WorkflowAdjudicationTests.resolve
    opener = W.WorkflowAdjudicationTests.opener
    ticket = W.WorkflowAdjudicationTests.ticket
    document = W.WorkflowAdjudicationTests.document
    run_ticket = W.WorkflowAdjudicationTests.run_ticket
    setUp = W.WorkflowAdjudicationTests.setUp
    exact_http = W.WorkflowAdjudicationTests.exact_http
    source = W.WorkflowAdjudicationTests.source
    support = W.WorkflowAdjudicationTests.support
    designated = W.WorkflowAdjudicationTests.designated

    def provision(self, *, clean=True, initialize=True):
        path = policy.POLICY_DIR / 'provider-registry.yaml'
        document = json.loads(path.read_text())
        document['review_models']['local-openai-compatible'] = {
            'EXAMPLE-review-model': {'model_family': 'EXAMPLE-local', 'stronger_than': []}}
        path.write_text(json.dumps(document))
        policy.clear_policy_cache()
        producer, _, _ = self.source(clean=clean)
        control, _, _, _ = self.designated(producer, support_override=())
        storage = self.home / 'EXAMPLE-database-storage'
        storage.mkdir(mode=0o700)
        database = storage / 'EXAMPLE-workspace.db'
        database.touch(mode=0o600)
        if initialize:
            with patch.object(sys, 'argv', ['setup_workspace_database.py', '--database', str(database)]), \
                    redirect_stdout(StringIO()), patch.object(subprocess, 'run') as bd:
                setup.main()
            bd.assert_not_called()
        return producer, control, database, host_records.configured_store()

    @contextmanager
    def closure(self, producer, database, authority):
        builders = P.fixtures.QualifiedClosureTests('runTest')
        self.addCleanup(builders.doCleanups)
        case = builders.compact(bead_id=producer.expected.task)
        custody = self.home / 'EXAMPLE-closure-custody'
        custody.mkdir(mode=0o700)
        builders.provision(case, custody)
        contract = json.loads((custody / 'contract.json').read_bytes())
        contract['record_type'] = 'cwo-production-closure-custody'
        del contract['scope']
        contract['bead'].update(updated_at='EXAMPLE-before',
            comment_count=len(contract['bead']['comments']), revision='EXAMPLE-before-revision')
        builders.write(custody, 'contract.json', P.original._freeze(contract))
        process = P.ExampleProcess(contract['bead'], database)
        with patch.object(subprocess, 'run', side_effect=process), \
                patch.object(shutil, 'which', side_effect=process.lookup):
            yield case, custody, process

    def test_completed_adjudication_persists_once_then_real_closure_requires_every_phase(self):
        """Checks: setup, original capture/evaluation/decision, exact receipt, gate and every reference."""
        producer, control, database, store = self.provision()
        self.assertFalse(P.qualified.PRODUCTION_CLOSURE_AVAILABLE)
        self.assertIsNone(control.acceptance_record)
        self.assertFalse(store.find('acceptance-decision'))
        receipt = control.current()  # Existing completed-adjudication flow, never pipeline.accept.
        self.assertEqual(binding._parse(receipt.record_bytes)['decision'], 'accepted')
        acceptance_id = control.acceptance_record
        self.assertIsInstance(acceptance_id, str)
        accepted = store.get(acceptance_id)
        authority = dict(acceptance_record=acceptance_id, return_sha256=binding._sha(producer.raw),
                         evaluation_sha256=accepted['evaluation_sha256'])
        before = len(store.find('acceptance-decision'))
        try:
            repeated = control.current()
        except Exception as failure:
            self.fail('Repeated completed observation must reuse one acceptance: ' + str(failure))
        self.assertEqual(repeated, receipt)
        self.assertEqual(control.acceptance_record, acceptance_id)
        self.assertEqual(len(store.find('acceptance-decision')), before)
        with self.closure(producer, database, authority) as (case, custody, process):
            options = dict(database=str(database), actor='EXAMPLE-supervisor', **authority)
            # Gate is checked first even with fully genuine original host evidence.
            with self.assertRaisesRegex(P.original.ClosureError, 'unavailable'):
                with P.qualified.production_custody(str(custody), **options):
                    self.fail('default gate opened')
            self.assertEqual(process.calls, [])
            evaluation = store.get(accepted['evaluation_record'])
            referenced = {'dispatch': evaluation['dispatch_record_sha256'],
                'capture': evaluation['return_record_sha256'], 'evaluation': accepted['evaluation_record'],
                'adjudication': accepted['adjudication_record'], 'acceptance': acceptance_id,
                'database-setup': store.find('workspace-database-identity')[0]['_record_sha256']}
            for phase, record_id in referenced.items():
                path = store.root / (record_id + '.json')
                raw = path.read_bytes()
                path.unlink()
                snapshot = {p.relative_to(self.home): p.read_bytes() for p in self.home.rglob('*') if p.is_file()}
                try:
                    with self.subTest(missing_phase=phase), \
                            patch.object(P.qualified, 'PRODUCTION_CLOSURE_AVAILABLE', True):
                        with self.assertRaises(P.original.ClosureError):
                            with P.qualified.production_custody(str(custody), **options):
                                self.fail('missing phase registered')
                    self.assertEqual(process.calls, [])
                    self.assertEqual(process.effects, [])
                    self.assertEqual(snapshot, {p.relative_to(self.home): p.read_bytes()
                                               for p in self.home.rglob('*') if p.is_file()})
                finally:
                    path.write_bytes(raw)
                    path.chmod(0o600)
            with patch.object(P.qualified, 'PRODUCTION_CLOSURE_AVAILABLE', True), \
                    P.qualified.production_custody(str(custody), **options) as host:
                P.qualified.observe(host)
                P.qualified.bind(host)
                result = P.closure.execute_qualified_completed(host)
            self.assertTrue(result['completed'])
            self.assertEqual([effect[0] for effect in process.effects], ['comment', 'close'])

    def test_missing_setup_or_original_designation_never_manufactures_acceptance(self):
        """Checks: setup is physical and original designated completion remains the decision authority."""
        producer, control, database, store = self.provision()
        identity_record = store.find('workspace-database-identity')[0]
        path = store.root / (identity_record['_record_sha256'] + '.json')
        raw = path.read_bytes()
        path.unlink()
        try:
            with self.assertRaises(ValueError):
                control.current()
            self.assertIsNone(control.acceptance_record)
        finally:
            path.write_bytes(raw)
            path.chmod(0o600)
        self.assertIsNone(control.acceptance_record)
        # A fresh original control is still required after the failed original was revoked.
        other, _, _, _ = self.designated(producer, identity='second-review', support_override=())
        other.host.require_active_completion = lambda _ticket: (_ for _ in ()).throw(ValueError('completion revoked'))
        with self.assertRaisesRegex(ValueError, 'revoked'):
            other.current()
        self.assertFalse(store.find('acceptance-decision'))

    def test_workspace_setup_is_idempotent_but_ambiguous_database_selection_refuses(self):
        """Setup changes no Beads state and cannot choose between two identities at acceptance."""
        producer, control, database, store = self.provision()
        before = {p.relative_to(store.state_root): p.read_bytes()
                  for p in store.state_root.rglob('*') if p.is_file()}
        with patch.object(sys, 'argv', ['setup_workspace_database.py', '--database', str(database)]), \
                redirect_stdout(StringIO()), patch.object(subprocess, 'run') as bd:
            setup.main()
        bd.assert_not_called()
        self.assertEqual(before, {p.relative_to(store.state_root): p.read_bytes()
                                  for p in store.state_root.rglob('*') if p.is_file()})
        another = database.with_name('EXAMPLE-other.db')
        another.touch(mode=0o600)
        with patch.object(sys, 'argv', ['setup_workspace_database.py', '--database', str(another)]), \
                redirect_stdout(StringIO()), patch.object(subprocess, 'run') as bd:
            setup.main()
        bd.assert_not_called()
        before = {p.relative_to(self.home): p.read_bytes() for p in self.home.rglob('*') if p.is_file()}
        with self.assertRaisesRegex(ValueError, 'selection is missing or ambiguous'):
            control.current()
        self.assertIsNone(control.acceptance_record)
        self.assertFalse(store.find('acceptance-decision'))
        self.assertEqual(before, {p.relative_to(self.home): p.read_bytes()
                                  for p in self.home.rglob('*') if p.is_file()})

    def test_cached_acceptance_rechecks_the_exact_current_task_context(self):
        """A same-bead/same-return acceptance from another dispatch is not this evaluation."""
        from cwo_core.host_acceptance import HostAcceptancePipeline, HostAdjudicationDecision
        from cwo_core.host_return_intake import record_received_return
        producer, control, database, store = self.provision()
        control.current()
        accepted = store.get(control.acceptance_record)
        own = store.require_dispatch(accepted['dispatch_id'])
        fields = {name: own.get(name) for name in ('dispatch_id', 'dispatch_role', 'provider',
            'model_family', 'model_id', 'reasoning_effort', 'session_id', 'packet_sha256',
            'request_sha256', 'review_target', 'evaluation_metadata', 'bead_id', 'executor', 'provider_key')}
        fields.update(dispatch_id='EXAMPLE-another-dispatch', session_id='EXAMPLE-another-session')
        store.write_dispatch(**fields)
        record_received_return(store, fields['dispatch_id'], producer.raw)
        # A coherent second host-pipeline acceptance isolates the cached reader:
        # same task and actual bytes, independently valid graph, different evaluation.
        pipeline = HostAcceptancePipeline(lambda _evaluation: HostAdjudicationDecision(
            'accepted', 'EXAMPLE another completed host acceptance', 'EXAMPLE-other-control'), store=store)
        other = pipeline.accept(producer.raw.decode(), bead_id=producer.expected.task,
            dispatch_id=fields['dispatch_id'], database_identity=store.require_database_identity(database))
        alternate = store.get(other)
        self.assertEqual(alternate['bead_id'], accepted['bead_id'])
        self.assertEqual(alternate['return_sha256'], accepted['return_sha256'])
        self.assertNotEqual(alternate['evaluation_sha256'], accepted['evaluation_sha256'])
        control.acceptance_record = other
        before = {p.relative_to(self.home): p.read_bytes() for p in self.home.rglob('*') if p.is_file()}
        from cwo_core.errors import CWOPolicyError
        with self.assertRaisesRegex(CWOPolicyError, 'context does not match'):
            control.current()
        self.assertEqual(before, {p.relative_to(self.home): p.read_bytes()
                                  for p in self.home.rglob('*') if p.is_file()})

    def test_other_completed_decisions_remain_observations_without_acceptance(self):
        """A designated rejection/change request is observable and writes no acceptance."""
        producer, _, database, store = self.provision()
        for decision in ('rejected', 'accepted-with-changes', 'quarantined'):
            other, _, _, _ = self.designated(producer, identity=decision, decision=decision,
                                             support_override=())
            try:
                observed = other.current()
            except Exception as failure:
                self.fail('A genuine completed non-acceptance stopped being observable: ' + str(failure))
            self.assertEqual(binding._parse(observed.record_bytes)['decision'], decision)
            self.assertIsNone(other.acceptance_record)
        self.assertFalse(store.find('acceptance-decision'))

    def test_completed_decision_rechecks_physical_database_before_returning_authority(self):
        """Drift after persistence refuses the observation; no Beads effect is attempted."""
        from cwo_core.host_acceptance import HostAcceptancePipeline
        producer, control, database, store = self.provision()
        original = HostAcceptancePipeline.accept
        def change_database(pipeline, *args, **kwargs):
            result = original(pipeline, *args, **kwargs)
            database.chmod(0o400)
            return result
        with patch.object(HostAcceptancePipeline, 'accept', change_database), \
                patch.object(subprocess, 'run') as bd:
            with self.assertRaisesRegex(ValueError, 'physical identity mismatch'):
                control.current()
        bd.assert_not_called()
        database.chmod(0o600)
        with self.assertRaisesRegex(ValueError, 'terminal'):
            control.current()

    def test_cached_acceptance_rechecks_live_database_after_its_original_observation(self):
        """Actual database drift after cached selection cannot return current authority."""
        producer, control, database, store = self.provision()
        control.current()
        selected = False
        original_select, original_observe = store.workspace_database, control._current
        def select():
            nonlocal selected
            result = original_select()
            selected = True
            return result
        def observe():
            result = original_observe()
            if selected:
                database.chmod(0o400)
            return result
        with patch.object(store, 'workspace_database', select), patch.object(control, '_current', observe):
            with self.assertRaisesRegex(ValueError, 'physical identity mismatch'):
                control.current()
        database.chmod(0o600)
        with self.assertRaisesRegex(ValueError, 'terminal'):
            control.current()

    def test_held_evaluation_remains_observable_without_acceptance(self):
        """Genuine incomplete acceptance prerequisites yield no authority or persistence."""
        producer, control, database, store = self.provision(clean=False)
        before = {p.relative_to(self.home): p.read_bytes() for p in self.home.rglob('*') if p.is_file()}
        try:
            observed = control.current()
        except Exception as failure:
            self.fail('A genuinely held completed observation stopped being observable: ' + str(failure))
        self.assertFalse(binding._parse(observed.evaluation_bytes)['accepted_for_use'])
        self.assertIsNone(control.acceptance_record)
        self.assertFalse(store.find('acceptance-decision'))
        self.assertEqual(before, {p.relative_to(self.home): p.read_bytes()
                                  for p in self.home.rglob('*') if p.is_file()})

    def test_missing_database_setup_produces_no_acceptance_or_writes(self):
        """A genuine completed decision without workspace setup grants no authority."""
        producer, control, database, store = self.provision(initialize=False)
        before = {p.relative_to(self.home): p.read_bytes() for p in self.home.rglob('*') if p.is_file()}
        self.assertIsNone(control.record_acceptance())
        control.current()
        self.assertIsNone(control.acceptance_record)
        self.assertFalse(store.find('acceptance-decision'))
        self.assertEqual(before, {p.relative_to(self.home): p.read_bytes()
                                  for p in self.home.rglob('*') if p.is_file()})
