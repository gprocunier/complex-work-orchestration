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
from tests import test_registered_n1_workflow as N
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

    def test_final_review_basis_requires_original_complete_observations_in_the_request(self):
        producer, control, database, store = self.provision()
        request = binding._parse(producer.observed.ticket.prepared.request_bytes)
        before = {path: path.read_bytes() for path in store.state_root.rglob('*') if path.is_file()}
        self.assertEqual(W.workflow._delivery_basis(producer.delivery_observation, producer.expected, request),
                         producer.delivery_basis)
        selected = next(row for row in request['sources'] if row['id'] == 'cwo-delivery-observations')
        for change in ('missing', 'changed', 'duplicate'):
            document = binding._parse(binding._json(request))
            if change == 'missing':
                document['sources'].remove(selected)
            elif change == 'changed':
                next(row for row in document['sources'] if row['id'] == selected['id'])['text'] += ' '
            else:
                document['sources'].append(dict(selected))
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'exact complete delivery observations'):
                W.workflow._delivery_basis(producer.delivery_observation, producer.expected, document)
        with self.assertRaisesRegex(P.original.ClosureError, 'issued immutable observation'):
            W.workflow._delivery_basis(producer.delivery_observation.report, producer.expected, request)
        self.assertIsNone(control.acceptance_record)
        self.assertEqual(before, {path: path.read_bytes() for path in store.state_root.rglob('*') if path.is_file()})

    def test_relevant_edit_invalidates_the_original_final_review_before_acceptance(self):
        producer, control, database, store = self.provision()
        (self.delivery_case.repo / 'src/item.txt').write_text('EXAMPLE after-final-review edit\n')
        before = {path: path.read_bytes() for path in store.state_root.rglob('*') if path.is_file()}
        with self.assertRaises(P.original.ClosureError):
            control.current()
        self.assertIsNone(control.acceptance_record)
        self.assertEqual(before, {path: path.read_bytes() for path in store.state_root.rglob('*') if path.is_file()})

    def native_delivery(self):
        builders = P.fixtures.QualifiedClosureTests('runTest')
        self.addCleanup(builders.doCleanups)
        self.delivery_case = builders.compact(bead_id=self.route['parent_id'])
        producer, _, _ = self.source(closure_case=self.delivery_case)
        excerpt = 'Observed baseline ' + producer.expected.scope + ' and candidate ' + producer.expected.candidate + '.'
        control, _, support, _ = self.designated(producer, all_findings=True, extra={'accepted_excerpt': excerpt})
        path = self.home / 'EXAMPLE-native-adjudication.json'
        path.write_bytes(control.current().record_bytes)
        evidence = N.W.EvidenceInputs(self.home, producer.current(), producer.expected, path.name,
                                     adjudication=control, observed_support=support)
        native = N.WorkflowTests('runTest')
        self.addCleanup(N.F.cleanup_helper, self, native)
        native.setUp(source_evidence=(producer, evidence))
        return native

    def test_native_consumer_refuses_changed_original_delivery_review_before_effects(self):
        native = self.native_delivery()
        native.adopt()
        (self.delivery_case.repo / 'src/item.txt').write_text('EXAMPLE delivery drift before native effect\n')
        with self.assertRaisesRegex(P.original.ClosureError, 'current candidate'):
            native.workflow.run()
        self.assertEqual(native.fixture.spawned, [])
        self.assertEqual(native.settings['state_store'].read_state()['operations'], {})
        self.assertFalse((native.case.host.target / 'result.txt').exists())

    def test_native_consumer_refuses_delivery_edit_during_original_evidence_consumption(self):
        native = self.native_delivery()
        native.adopt()
        consume = N.W.S.consume_source
        def change(*args, **options):
            result = consume(*args, **options)
            (self.delivery_case.repo / 'src/item.txt').write_text('EXAMPLE delivery drift during evidence use\n')
            return result
        with patch.object(N.W.S, 'consume_source', side_effect=change), \
                self.assertRaisesRegex(P.original.ClosureError, 'current candidate'):
            native.workflow.run()
        self.assertEqual(native.fixture.spawned, [])
        self.assertEqual(native.settings['state_store'].read_state()['operations'], {})
        self.assertFalse((native.case.host.target / 'result.txt').exists())
        (self.delivery_case.repo / 'src/item.txt').write_bytes(P.fixtures.fixtures.AFTER)
        with self.assertRaisesRegex(ValueError, 'terminal'):
            native.settings['evidence'].current()

    def test_native_consumer_preserves_the_exact_original_delivery_review_positive(self):
        native = self.native_delivery()
        result = native.run_native(archive_schedule='settled')
        self.assertTrue(result['execution_complete'])
        self.assertTrue(result['validation_complete'])

    def test_native_consumer_cannot_drop_the_delivery_handle_and_basis_to_downgrade(self):
        native = self.native_delivery()
        native.adopt()
        producer = native.source_fixture
        producer.delivery_observation = producer.delivery_basis = None
        with self.assertRaisesRegex(ValueError, 'issued.*delivery observation'):
            native.workflow.run()
        self.assertEqual(native.fixture.spawned, [])
        self.assertEqual(native.settings['state_store'].read_state()['operations'], {})
        self.assertFalse((native.case.host.target / 'result.txt').exists())

    def provision(self, *, clean=True, initialize=True):
        path = policy.POLICY_DIR / 'provider-registry.yaml'
        document = json.loads(path.read_text())
        document['review_models']['local-openai-compatible'] = {
            'EXAMPLE-review-model': {'model_family': 'EXAMPLE-local', 'stronger_than': []},
            'EXAMPLE-adjudicator-model': {'model_family': 'EXAMPLE-review', 'stronger_than': []}}
        path.write_text(json.dumps(document))
        policy.clear_policy_cache()
        builders = P.fixtures.QualifiedClosureTests('runTest')
        self.addCleanup(builders.doCleanups)
        self.delivery_case = builders.compact(bead_id=self.route['parent_id'])
        self.delivery_case.bead.update(updated_at='EXAMPLE-before',
            comment_count=len(self.delivery_case.bead['comments']), revision='EXAMPLE-before-revision')
        producer, _, _ = self.source(clean=clean, closure_case=self.delivery_case)
        control, _, _, _ = self.designated(producer, support_override=(), model='EXAMPLE-adjudicator-model')
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
    def closure(self, producer, database, authority, *, case=None):
        builders = P.fixtures.QualifiedClosureTests('runTest')
        self.addCleanup(builders.doCleanups)
        case = self.delivery_case if case is None else case
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

    def test_unrelated_valid_candidate_cannot_consume_same_task_acceptance(self):
        """The accepted return must concern this baseline and delivered candidate."""
        producer, control, database, store = self.provision()
        control.current()
        accepted = store.get(control.acceptance_record)
        authority = dict(acceptance_record=control.acceptance_record,
                         return_sha256=binding._sha(producer.raw),
                         evaluation_sha256=accepted['evaluation_sha256'])
        builders = P.fixtures.QualifiedClosureTests('runTest')
        self.addCleanup(builders.doCleanups)
        other = builders.compact(bead_id=producer.expected.task, additive=True)
        with self.closure(producer, database, authority, case=other) as (_, custody, process), \
                patch.object(P.qualified, 'PRODUCTION_CLOSURE_AVAILABLE', True):
            before = {p.relative_to(self.home): p.read_bytes() for p in self.home.rglob('*') if p.is_file()}
            with self.assertRaisesRegex(P.original.ClosureError, 'accepted source.*candidate|delivery context'):
                with P.qualified.production_custody(str(custody), database=str(database),
                        actor='EXAMPLE-supervisor', **authority) as host:
                    P.qualified.observe(host)
                    P.qualified.bind(host)
                    P.closure.execute_qualified_completed(host)
            self.assertEqual(process.calls, [])
            self.assertEqual(process.effects, [])
            self.assertEqual(before, {p.relative_to(self.home): p.read_bytes()
                                     for p in self.home.rglob('*') if p.is_file()})

    def test_same_baseline_different_delivered_candidate_refuses_before_beads(self):
        """A passing candidate under the same obligations is still a different delivery."""
        producer, control, database, store = self.provision()
        control.current()
        accepted = store.get(control.acceptance_record)
        authority = dict(acceptance_record=control.acceptance_record,
                         return_sha256=binding._sha(producer.raw),
                         evaluation_sha256=accepted['evaluation_sha256'])
        case = self.delivery_case
        (case.repo / 'src/extra.txt').write_text('EXAMPLE additional delivered content\n')
        case.candidate = P.original.ci.capture_candidate(case.repo, chain=case.chain,
            base_commit=case.workspace.base, scope_paths=['src'])
        case.bead['comments'].append({'text': P.original.ci.candidate_reference_line(
            case.bead['id'], P.original.ci.candidate_digest(case.candidate))})
        self.assertEqual(producer.expected.scope, case.chain['digest'])
        self.assertNotEqual(producer.expected.candidate, P.original.ci.candidate_digest(case.candidate))
        with self.closure(producer, database, authority) as (_, custody, process), \
                patch.object(P.qualified, 'PRODUCTION_CLOSURE_AVAILABLE', True):
            before = {p.relative_to(self.home): p.read_bytes() for p in self.home.rglob('*') if p.is_file()}
            with self.assertRaisesRegex(P.original.ClosureError, 'accepted source.*candidate'):
                with P.qualified.production_custody(str(custody), database=str(database),
                        actor='EXAMPLE-supervisor', **authority):
                    self.fail('different delivered candidate registered')
            self.assertEqual(process.calls, [])
            self.assertEqual(process.effects, [])
            self.assertEqual(before, {p.relative_to(self.home): p.read_bytes()
                                     for p in self.home.rglob('*') if p.is_file()})

    def test_completed_adjudication_persists_once_then_real_closure_requires_every_phase(self):
        """Checks: setup, original capture/evaluation/decision, exact receipt, gate and every reference."""
        producer, control, database, store = self.provision()
        self.assertTrue(P.qualified.PRODUCTION_CLOSURE_AVAILABLE)
        request = binding._parse(producer.observed.ticket.prepared.request_bytes)
        evidence = [binding._parse(item['text'].encode()) for item in request['sources']
                    if item['id'] == 'cwo-delivery-observations']
        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0]['resolved_baseline'], self.delivery_case.chain)
        self.assertEqual(evidence[0]['candidate'], self.delivery_case.candidate)
        self.assertEqual(evidence[0]['observation_sha256'],
                         P.original.observation_digest(self.delivery_case.review_observation))
        self.assertIn(producer.expected.candidate, producer.raw.decode())
        self.assertIsNone(control.acceptance_record)
        self.assertFalse(store.find('acceptance-decision'))
        receipt = control.current()  # Existing completed-adjudication flow, never pipeline.accept.
        self.assertEqual(binding._parse(receipt.record_bytes)['decision'], 'accepted')
        acceptance_id = control.acceptance_record
        self.assertIsInstance(acceptance_id, str)
        accepted = store.get(acceptance_id)
        self.assertEqual(accepted['source_context']['scope'], self.delivery_case.chain['digest'])
        self.assertEqual(accepted['source_context']['candidate'],
                         P.original.ci.candidate_digest(self.delivery_case.candidate))
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
            with patch.object(P.qualified, 'PRODUCTION_CLOSURE_AVAILABLE', False), \
                    self.assertRaisesRegex(P.original.ClosureError, 'unavailable'):
                with P.qualified.production_custody(str(custody), **options):
                    self.fail('patched-off kill switch opened')
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
                P.qualified.observe(host, observation=case.review_observation)
                P.qualified.bind(host)
                result = P.closure.execute_qualified_completed(host)
            self.assertTrue(result['completed'])
            self.assertEqual([effect[0] for effect in process.effects], ['comment', 'close'])
            self.assertEqual(process.effects[0][1:3], ('--', producer.expected.task))
            self.assertEqual(process.effects[0][3], result['summary'])
            self.assertIn('Baseline ' + producer.expected.scope, result['summary'])
            self.assertIn('Candidate ' + producer.expected.candidate, result['summary'])
            self.assertEqual(process.bead['comments'][-1]['text'], result['summary'])
            self.assertEqual(process.bead['status'], 'closed')
            before_effects = list(process.effects)
            with self.assertRaises(P.original.ClosureError):
                P.closure.execute_qualified_completed(host)
            self.assertEqual(process.effects, before_effects)

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
        fields['evaluation_metadata']['source_context']['dispatch_id'] = fields['dispatch_id']
        store.write_dispatch(**fields)
        record_received_return(store, fields['dispatch_id'], producer.raw)
        # A coherent second host-pipeline acceptance isolates the cached reader:
        # same task and actual bytes, independently valid graph, different evaluation.
        pipeline = HostAcceptancePipeline(lambda _evaluation: HostAdjudicationDecision(
            'accepted', 'EXAMPLE another completed host acceptance', 'EXAMPLE-other-control'), store=store,
            adjudication_identity=workflow._completed_adjudicator(control.host, control.ticket))
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
