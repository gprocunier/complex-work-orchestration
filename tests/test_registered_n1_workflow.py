"""Registered workflow joins; EXAMPLE process/RPC/OS effects, real target effects.

Original producer matrices are reused through their builders, never collected
here. The checkpoint/consent/drift overlap deliberately proves this new consumer.
"""
from __future__ import annotations

import copy
from contextlib import contextmanager
import hashlib
import importlib
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'tests')]
import registered_n1_workflow as W  # noqa: E402
import test_registered_n1_factory as F  # noqa: E402
import tests.test_workflow_adjudication as E  # noqa: E402
import tests.test_registered_finite_tool_wiring as tools  # noqa: E402


def read_only_evidence(method):
    """Share original reviews only when this case never refuses their controller."""
    method.read_only_evidence = True
    return method


def evidence_snapshot(evidence):
    """Observe retained review files without replacing any product recheck."""
    roots = {evidence.root, *(host._ledger.root.parent for host, *_ in evidence._completed)}
    return tuple((str(path), path.lstat().st_mode, path.lstat().st_ino,
                  path.read_bytes() if path.is_file() else None)
                 for root in sorted(roots) for path in (root, *sorted(root.rglob('*'))))


def c1_failure_note(workflow):
    """Bounded observation after original factory cleanup, never effect authority."""
    factory = workflow.factory
    receipt = ((factory.execution or {}).get('receipt') or {}) if factory is not None else {}
    adapter = None if factory is None else factory.adapter
    server = None if factory is None else factory.server
    snapshot = {'capture_phase': 'post-original-factory-cleanup-before-test-fixture-cleanup',
                'capture_consistency': 'best-effort-nonblocking',
                'native_receipt': {}, 'adapter': None, 'lifecycle': None, 'staged_archive': None}
    for name in ('actions', 'decisions', 'errors'):
        values = receipt.get(name, [])
        snapshot['native_receipt'][name] = [str(value)[:160] for value in values[:80]]
        snapshot['native_receipt'][name + '_count'] = len(values)
    snapshot['native_receipt'].update(poll_count=receipt.get('poll_count'),
        terminal_state=str(receipt.get('terminal_state'))[:80])
    if adapter is not None:
        snapshot['adapter'] = {'check_count': adapter.check_count,
                              'boundary_phase': str(adapter._boundary_phase)[:80]}
        archive = adapter._staged_archive
        if archive is not None:
            snapshot['staged_archive'] = {'started': archive._started, 'done': archive._done.is_set(),
                'error_type': None if archive._error is None else type(archive._error).__name__[:80]}
    if server is not None:
        life = server.finite_input.lifecycle
        snapshot['lifecycle'] = {'phase': str(life.phase)[:80], 'generation': life.generation,
            'edge_deadline': life.edge_deadline, 'pending_count': len(life.pending),
            'pending': [[str(key)[:160], str(value)[:512]]
                        for key, value in list(life.pending.items())[:16]],
            'original_terminal': life.original_terminal, 'original_fault': life.original_fault,
            'original_closed': life.original_closed}
    encoded = json.dumps(snapshot, sort_keys=True)
    suffix = ' [diagnostic JSON truncated]' if len(encoded) > 32768 else ''
    return 'EXAMPLE C1 failure observation: ' + encoded[:32768] + suffix


class WorkflowTests(unittest.TestCase):
    @staticmethod
    @contextmanager
    def read_only_source_family(test):
        """Own one actual producer across compatible rows, never native state."""
        owner = WorkflowTests('runTest')
        try:
            source = owner.evidence()
            evidence = source[1]
            snapshot = evidence_snapshot(evidence)

            def current():
                # A faulted row keeps its refused evidence for diagnosis. The
                # next cohort must construct its own source, not borrow it.
                if evidence.adjudication._refusal is not None:
                    return None
                test.assertEqual(evidence_snapshot(evidence), snapshot)
                return source

            def retained():
                test.assertIsNone(evidence.adjudication._refusal)
                test.assertEqual(evidence_snapshot(evidence), snapshot)

            owner.addCleanup(retained)
            yield current
        finally:
            F.cleanup_helper(test, owner)

    @classmethod
    def read_only_source(cls):
        if '_read_only_source' not in cls.__dict__:
            helper = E.WorkflowAdjudicationTests('runTest')
            cls.addClassCleanup(cls.cleanup_source, helper)
            helper.setUp()
            cls._read_only_source = cls.produce_evidence(helper)
            cls._source_snapshot = evidence_snapshot(cls._read_only_source[1])
            cls.addClassCleanup(delattr, cls, '_read_only_source')
            cls.addClassCleanup(delattr, cls, '_source_snapshot')
        return cls._read_only_source

    @staticmethod
    def cleanup_source(helper):
        if not helper.doCleanups():
            raise AssertionError('EXAMPLE shared source fixture cleanup failed')

    def assert_read_only_evidence(self):
        self.assertIsNone(self.settings['evidence'].adjudication._refusal)
        self.assertEqual(evidence_snapshot(self.settings['evidence']), self._source_snapshot)

    def setUp(self, *, source_evidence=None):
        self._process_kill_before_fixture = os.kill
        method = getattr(type(self), self._testMethodName, None)
        shared = getattr(method, 'read_only_evidence', False)
        if source_evidence is not None:
            self.source_fixture, evidence = source_evidence
        elif shared:
            self.source_fixture, evidence = self.read_only_source()
            # A faulted row must never lend its terminal controller to another
            # row. Keep the old evidence for diagnosis and build privately.
            if evidence.adjudication._refusal is not None:
                shared = False
                self.source_fixture, evidence = self.evidence()
        else:
            self.source_fixture, evidence = self.evidence()
        self.fixture = F.FactoryTests('runTest')
        self.fixture.setUp()
        self.addCleanup(F.cleanup_helper, self, self.fixture)
        selected = (dict(finite_tool_mode='captured-host-tools', natural_tool_exit=True,
                         materialize_on_turn_start=True, no_fake_scheduler=True)
                    if self._testMethodName == 'test_c1_real_registered_native_validation_separate_consent_and_real_publication'
                    else {})
        self.case = self.fixture.case(**selected)
        c, a = self.case, self.fixture.authority
        a.mission['scope']['workspace_roots'].append(str(c.host.target))
        a.mission['scope']['factory_ids'].append('EXAMPLE-publication')
        a.registry['EXAMPLE-publication'] = {'adapter_path': str(Path(W.G.__file__).resolve()),
            'adapter_sha256': hashlib.sha256(Path(W.G.__file__).read_bytes()).hexdigest()}
        a.mission_hash = F.authorities.mission_sha256(a.mission)
        a.directive = a.sign(a.mission_hash, 'EXAMPLE_WORKFLOW_MISSION')
        plan = c.capability.bound_plan()
        operation = c.capability.evidence()['operation']
        plan['authority_sha256'] = operation['mission_sha256'] = a.mission_hash
        native = (plan, operation, a.reseal(plan, operation))
        pubplan, pubop = copy.deepcopy(plan), copy.deepcopy(operation)
        pubplan.pop('registered_n1')
        pubplan.update(transaction_id='EXAMPLE-publication', **{
            'runtime_adapter_path': a.registry['EXAMPLE-publication']['adapter_path'],
            'runtime_adapter_sha256': a.registry['EXAMPLE-publication']['adapter_sha256']})
        pubop.update(operation_id='EXAMPLE-publication', factory_id='EXAMPLE-publication', workspace=str(c.host.target))
        publication = (pubplan, pubop, a.reseal(pubplan, pubop))
        authority_state = c.host.state.parent / 'EXAMPLE_WORKFLOW_AUTHORITY'
        authority_state.mkdir(mode=0o700)
        store = F.authorities.MaintenanceStateStore(authority_state, mission_id=a.mission['mission_id'],
                                                    mission_sha256=a.mission_hash)
        store.initialize()
        state, pubstate = c.host.state.parent / 'EXAMPLE_CONTROLLER', c.host.state.parent / 'EXAMPLE_PUBLICATION'
        state.mkdir(mode=0o700)
        pubstate.mkdir(mode=0o700)
        self.settings = dict(mission=a.mission, mission_directive=a.directive, verification_key=a.key,
            actor_id=a.actor, identity_source=a.identity, factory_registry=a.registry, state_store=store,
            native_bundle=native, publication_bundle=publication, policy_specification=c.policy.report,
            receipt=c.receipt, route=c.route, node_id=c.node_id, ledger=c.ledger, host=c.host,
            controller_state=state, publication_state=pubstate, evidence=evidence)
        self.workflow = self.make_workflow()
        test = self
        class FactoryReference:
            @property
            def server(self):
                return test.workflow.factory.server
        c.factory = FactoryReference()
        if shared:
            self.assert_read_only_evidence()
            self.addCleanup(self.assert_read_only_evidence)

    def make_workflow(self, module=W):
        return module.RegisteredN1Workflow(module.ControllerConfiguration(**self.settings))

    def adopt(self, workflow=None):
        workflow = workflow or self.workflow
        return workflow.adopt_execution(adoption_id='EXAMPLE_CURRENT_EXECUTION', disclosure_consent={
            'boundary': 'local-only', 'allowed_effects': ['native-worker', 'target-publication'],
            'request_sha256': hashlib.sha256(self.case.receipt.request_bytes).hexdigest()})

    def run_native(self, *, expected_children=2, archive_schedule='concurrent'):
        if archive_schedule == 'settled':
            F.settle_original_archive(self.fixture, self.case)
        elif archive_schedule != 'concurrent':
            raise ValueError('Unknown original archive fixture schedule.')
        self.adopt()
        result = self.workflow.run()
        self.assertTrue(result['execution_complete'])
        self.assertTrue(result['validation_complete'])
        self.assertFalse((self.case.host.target / 'result.txt').exists())
        self.assertEqual(len(self.fixture.spawned), expected_children)
        self.assertEqual(self.fixture.attempt(self.case)['outcome'], 'completed')
        return result

    def allow_publication(self):
        self.workflow.adopt_publication(adoption_id='EXAMPLE_CURRENT_PUBLICATION')

    def fresh_controller(self):
        # Fake process replacement: real fresh module registries, host, policy,
        # verifier and ledger objects. No old host/token/capability is retained.
        self.enterContext(patch.dict(sys.modules))
        for name in ('offline_artifact_validation', 'guarded_artifact_target',
                     'registered_n1_factory', 'registered_n1_workflow'):
            sys.modules.pop(name, None)
        module = importlib.import_module('registered_n1_workflow')
        evidence = self.settings['evidence']
        self.settings['evidence'] = module.EvidenceInputs(evidence.root, evidence.source,
            evidence.context, evidence.path, adjudication=evidence.adjudication,
            observed_support=evidence.support)
        c = self.case
        self.settings['host'] = module.H.OfflineN1Host(c.host.state, c.host.target, c.host.worker)
        old = c.ledger
        self.settings['ledger'] = module.R.admission.ledger_api.InvocationLedger(old.root,
            clock=old.clock, owner_probe=old.owner_probe)
        store = self.settings['state_store']
        self.settings['state_store'] = module.A.MaintenanceStateStore(store.directory,
            mission_id=store.mission_id, mission_sha256=store.mission_sha256)
        fresh = self.make_workflow(module)
        self.assertIsNone(fresh.factory)
        self.assertIsNot(fresh.config.host, c.host)
        self.assertIsNot(module.V._TOKENS, W.V._TOKENS)
        self.assertFalse(module.V._TOKENS)
        self.assertFalse(fresh.verifier._capabilities)
        if self.workflow._artifact is not None:
            with self.assertRaises(ValueError):
                module.V._issued(module.V._TOKENS, module.V.ValidatedObservation,
                                 self.workflow._artifact[1])
        self.adopt(fresh)
        return fresh

    @read_only_evidence
    def test_c1_real_registered_native_validation_separate_consent_and_real_publication(self):
        """Full-load acceptance: materialized startup, finite natural completion and publication."""
        original_read, observed = os.read, []
        def natural_exit(descriptor, count):
            # Original wiring._run_tool_exit schedule: retain the actual handle,
            # namespace death, bounded pipe bytes and real EOF, not a status label.
            data = original_read(descriptor, count)
            if (len(self.fixture.spawned) >= 2 and not observed
                    and descriptor == self.case.tool_stream.fileno()):
                tool = self.fixture.spawned[1]
                tool.returncode, tool.process.alive = 0, False
                self.case.tool_stream.put('')
                observed.append(data)
            return data
        with patch.object(F, 'RpcProcess', tools.DynamicRpcProcess), patch.object(os, 'read', side_effect=natural_exit):
            try:
                result = self.run_native(archive_schedule='settled', expected_children=3)
            except BaseException as failure:
                try:
                    failure.add_note(c1_failure_note(self.workflow))
                except BaseException as diagnostic_failure:
                    try:
                        failure.add_note('EXAMPLE C1 diagnostic capture failed: '
                                         + type(diagnostic_failure).__name__)
                    except BaseException:
                        pass
                raise
        self.assertEqual(observed, [b'EXAMPLE finite command output\n'])
        factory = self.workflow.factory
        self.assertEqual(factory.spec['finite_tool_mode'], 'captured-host-tools')
        self.assertEqual(factory.server.finite_input.terminal_code, 0)
        replies = self.fixture.spawned[0].replies
        self.assertEqual(replies[0]['result']['contentItems'][0]['text'], 'EXAMPLE finite command output\n')
        self.assertEqual(json.loads(replies[1]['result']['contentItems'][0]['text']),
                         {'stdout': '', 'running': False})
        with self.assertRaises(BlockingIOError):
            os.read(self.case.tool_read, 1)
        evidence = json.loads(self.workflow._selected_action)['evidence']
        self.assertEqual(evidence['projection']['decision'], 'accepted')
        self.assertFalse(evidence['projection']['remaining_holds'])
        self.assertFalse(evidence['projection']['trusted_host_authority'])
        with self.assertRaisesRegex(ValueError, 'Separate publication'):
            self.workflow.publish()
        self.allow_publication()
        result = self.workflow.publish()
        self.assertTrue(result['publication']['publication_complete'])
        self.assertEqual((self.case.host.target / 'result.txt').read_bytes(), F.fixtures.host_fixtures.OUTPUT)
        self.assertEqual(self.workflow.publish()['publication']['new_invocation']['replacements'], 0)
        with self.assertRaisesRegex(ValueError, 'never redispatch'):
            self.workflow.run()
        self.assertEqual(len(self.fixture.spawned), 3)
        for flag in W.G._FALSE:
            self.assertIs(result[flag], False)

    @read_only_evidence
    def test_r1_evidence_and_task_risk_are_not_execution_or_disclosure_consent(self):
        """Separate adoption refusal overlaps original authority negatives."""
        with self.assertRaisesRegex(ValueError, 'current execution adoption'):
            self.workflow.run()
        with self.assertRaisesRegex(ValueError, 'disclosure consent'):
            self.workflow.adopt_execution(adoption_id='EXAMPLE_BAD', disclosure_consent={'task_risk': 'accepted'})
        self.assertEqual(self.fixture.spawned, [])
        self.assertEqual(list(self.workflow.config.state.iterdir()), [])
        plan, operation, _directive = copy.deepcopy(self.settings['native_bundle'])
        plan['registered_n1']['purpose'] = 'EXAMPLE-external-work'
        directive = self.fixture.authority.reseal(plan, operation)
        self.settings['native_bundle'] = (plan, operation, directive)
        with self.assertRaisesRegex(ValueError, 'External execution purpose'):
            self.make_workflow()

    def evidence(self):
        helper = E.WorkflowAdjudicationTests('runTest')
        self.addCleanup(F.cleanup_helper, self, helper)
        helper.setUp()
        return self.produce_evidence(helper)

    @staticmethod
    def produce_evidence(helper):
        producer, _, _ = helper.source()
        control, _broker, support, _ = helper.designated(producer, all_findings=True)
        root = producer.root
        path = 'EXAMPLE_COMPLETED_ADJUDICATION.json'
        (root / path).write_bytes(control.current().record_bytes)
        evidence = W.EvidenceInputs(root, producer.current(), producer.expected, path,
                                   adjudication=control, observed_support=support)
        return producer, evidence

    def test_r1_missing_original_evidence_refuses_bootstrap_and_adopted_effects(self):
        """I7/C1: reproduce the source-free positive; arbitrary evidence grants nothing."""
        settings = dict(self.settings)
        settings.pop('evidence')
        with self.assertRaises(TypeError):
            W.ControllerConfiguration(**settings)
        for invalid in (None, {}, object()):
            with self.subTest(evidence=type(invalid).__name__):
                with self.assertRaisesRegex(ValueError, 'Original source and designated adjudication'):
                    W.ControllerConfiguration(**dict(settings, evidence=invalid))
        evidence = self.settings['evidence']
        with self.assertRaisesRegex(ValueError, 'Original designated completed adjudication'):
            W.EvidenceInputs(evidence.root, evidence.source, evidence.context, evidence.path,
                             adjudication={'decision': 'accepted'}, observed_support=evidence.support)
        self.adopt()
        self.workflow.config.evidence = None
        with self.assertRaisesRegex(ValueError, 'Original source and designated adjudication'):
            self.workflow.run()
        self.workflow.config.evidence = evidence
        with self.assertRaisesRegex(ValueError, 'terminal'):
            self.workflow.run()
        with self.assertRaisesRegex(ValueError, 'terminal'):
            evidence.adjudication.current()
        self.assertEqual(self.fixture.spawned, [])
        self.assertEqual(list(self.workflow.config.state.iterdir()), [])
        self.assertEqual(self.settings['state_store'].read_state()['operations'], {})

    def test_r1_original_source_and_designated_adjudication_drift_before_native_and_target(self):
        """The same original enrollment remains refused after exact byte restoration."""
        kinds = ('adjudication', 'adjudicator', 'peer-review-policy', 'share-boundaries',
                 'source-ledger', 'review-ledger')
        for index, kind in enumerate(kinds):
            if index:
                self.doCleanups()
                self.setUp()
            with self.subTest(kind=kind):
                self._refused_enrollment(kind)
        self.doCleanups()
        self.setUp()
        self.run_native(archive_schedule='settled')
        self.allow_publication()
        fixture, evidence = self.source_fixture, self.settings['evidence']
        original = (fixture.root / fixture.dispatch_path).read_bytes()
        (fixture.root / fixture.dispatch_path).chmod(0o600)
        (fixture.root / fixture.dispatch_path).write_text('{}')
        with self.assertRaises(ValueError):
            self.workflow.publish()
        (fixture.root / fixture.dispatch_path).write_bytes(original)
        with self.assertRaisesRegex(ValueError, 'terminal'):
            self.workflow.publish()
        with self.assertRaisesRegex(ValueError, 'terminal'):
            self.fresh_controller()
        self.assertIsNotNone(evidence.adjudication._refusal)
        self.assertFalse((self.case.host.target / 'result.txt').exists())

    def _refused_enrollment(self, kind):
        fixture, evidence = self.source_fixture, self.settings['evidence']
        self.adopt()
        if kind in ('adjudication', 'adjudicator'):
            path = fixture.root / evidence.path
            changed = W.B._parse(path.read_bytes())
            changed['adjudicator'] = 'architect'
            raw = b'{}' if kind == 'adjudication' else W.B._json(changed)
        elif kind in ('peer-review-policy', 'share-boundaries'):
            path = W.B.policy.POLICY_DIR / (kind + '.yaml')
            raw = path.read_bytes() + b'\n'
        else:
            host, _token, observed, *_ = evidence._completed[kind == 'review-ledger']
            path = host._ledger.root / W.R.admission.ledger_api.LEDGER_FILE
            changed = W.B._parse(path.read_bytes())
            reservation = W.B._parse(observed.attempt_bytes)['reservation_id']
            row = next(row for row in changed['attempts'].values() if row['reservation_id'] == reservation)
            row['outcome'] = 'unknown'
            raw = W.B._json(changed)
        original = path.read_bytes()
        try:
            path.write_bytes(raw)
            with self.assertRaises(ValueError) as caught:
                self.workflow.run()
        finally:
            path.write_bytes(original)
        self.assertIs(evidence.adjudication._refusal, caught.exception)
        for action in (evidence.current, evidence.adjudication.current, self.workflow.run):
            with self.assertRaisesRegex(ValueError, 'terminal'):
                action()
        with self.assertRaisesRegex(ValueError, 'terminal'):
            W.EvidenceInputs(evidence.root, evidence.source, evidence.context, evidence.path,
                adjudication=evidence.adjudication, observed_support=evidence.support)
        self.assertEqual(self.fixture.spawned, [])
        self.assertEqual(self.settings['state_store'].read_state()['operations'], {})

    @read_only_evidence
    def test_r6_target_drift_at_original_publisher_effect_boundary(self):
        """Target replacement races are checked again at the workflow join."""
        self.run_native(archive_schedule='settled')
        self.allow_publication()
        original = self.workflow.target._apply_one
        def drift(*args):
            (self.case.host.target / 'EXAMPLE_OTHER.txt').write_text('EXAMPLE drift')
            return original(*args)
        with patch.object(self.workflow.target, '_apply_one', side_effect=drift):
            with self.assertRaises(W.G.PublicationError):
                self.workflow.publish()
        self.assertFalse((self.case.host.target / 'result.txt').exists())
        self.assertEqual(len(self.fixture.spawned), 2)

    def test_r6_known_completed_restart_uses_new_registries_no_dispatch_or_charge_release(self):
        """Controller objects recover an authenticated completed target."""
        self.run_native(archive_schedule='settled')
        self.allow_publication()
        self.workflow.publish()
        accounting = self.fixture.attempt(self.case)
        fresh = self.fresh_controller()
        result = fresh.recover()
        self.assertTrue(result['publication']['publication_complete'])
        self.assertEqual(result['publication']['new_invocation']['replacements'], 0)
        evidence = fresh.config.evidence
        path = evidence.root / evidence.path
        original = path.read_bytes()
        path.write_text('{}')
        with self.assertRaises(ValueError):
            fresh.recover()
        self.assertEqual(self.fixture.attempt(self.case), accounting)
        self.assertEqual(len(self.fixture.spawned), 2)
        path.write_bytes(original)
        with self.assertRaisesRegex(ValueError, 'terminal'):
            fresh.recover()
        with self.assertRaisesRegex(ValueError, 'terminal'):
            fresh.publish()
        self.assertEqual(self.fixture.attempt(self.case), accounting)
        self.assertEqual(len(self.fixture.spawned), 2)

    @read_only_evidence
    def test_r6_validated_checkpoint_restart_requires_distinct_current_publication_adoption(self):
        """Known native/validation checkpoint is recoverable before publication consent."""
        self.run_native(archive_schedule='settled')
        fresh = self.fresh_controller()
        self.assertTrue(fresh.recover()['validation_complete'])
        with self.assertRaisesRegex(ValueError, 'Separate publication'):
            fresh.publish()
        fresh.adopt_publication(adoption_id='EXAMPLE_FRESH_PUBLICATION')
        self.assertTrue(fresh.publish()['publication']['publication_complete'])
        self.assertEqual(len(self.fixture.spawned), 2)

    @read_only_evidence
    def test_r6_zero_applied_checkpoint_restart_and_retained_custody_tamper(self):
        """Genuine known checkpoint-zero recovery, then custody forgery refusal."""
        self.run_native(archive_schedule='settled')
        self.allow_publication()
        stop = KeyboardInterrupt('EXAMPLE checkpoint zero')
        with patch.object(self.workflow.target, '_apply_one', side_effect=stop):
            with self.assertRaises(KeyboardInterrupt):
                self.workflow.publish()
        fresh = self.fresh_controller()
        self.assertTrue(fresh.recover()['publication']['publication_complete'])
        custody = fresh.config.state / 'custody.json'
        value = json.loads(custody.read_bytes())
        value['body']['custody']['observation']['files'] = []
        custody.chmod(0o600)
        custody.write_text(json.dumps(value))
        custody.chmod(0o400)
        again = self.fresh_controller()
        with self.assertRaises(ValueError):
            again.recover()
        self.assertEqual(len(self.fixture.spawned), 2)

    @read_only_evidence
    def test_r1_revocation_at_startup_is_rechecked_before_gate_release(self):
        """Current controller state is checked inside the original factory startup."""
        self.adopt()
        self.case.on_startup = self.workflow.config.store.revoke
        with self.assertRaises(ValueError):
            self.workflow.run()
        self.assertIsNone(self.workflow.factory.token)
        self.assertFalse((self.case.host.state / 'artifact').exists())
        self.assertFalse((self.case.host.target / 'result.txt').exists())

    def test_r1_source_evidence_drift_during_original_startup_refuses_before_native_turn(self):
        """Original source drift after process creation cannot reach the native turn."""
        fixture = self.source_fixture
        self.adopt()
        def drift():
            path = fixture.root / fixture.dispatch_path
            path.chmod(0o600)
            path.write_text('{}')
        self.case.on_startup = drift
        with self.assertRaises(ValueError):
            self.workflow.run()
        self.assertNotIn('turn/start', self.fixture.spawned[0].methods)
        self.assertIsNone(self.workflow.factory.token)
        self.assertFalse((self.case.host.state / 'artifact').exists())
        self.assertFalse((self.case.host.target / 'result.txt').exists())

    @read_only_evidence
    def test_r6_known_checkpoint_interruption_recovery_and_unknown_restart(self):
        """Checkpoint replay after interruption never resumes unknown bytes."""
        self.run_native(archive_schedule='settled')
        self.allow_publication()
        original = self.workflow.target._record
        stop = KeyboardInterrupt('EXAMPLE known completed checkpoint')
        def interrupt(name, value):
            if name == 'receipt.json':
                raise stop
            return original(name, value)
        with patch.object(self.workflow.target, '_record', side_effect=interrupt):
            with self.assertRaises(KeyboardInterrupt) as caught:
                self.workflow.publish()
        self.assertIs(caught.exception, stop)
        fresh = self.fresh_controller()
        self.assertTrue(fresh.recover()['publication']['publication_complete'])
        self.assertEqual(len(self.fixture.spawned), 2)
        # Original checkpoint no longer matches: matching useful bytes cannot
        # authenticate a different target or unknown journal observation.
        (self.case.host.target / 'EXAMPLE_UNKNOWN.txt').write_text('EXAMPLE unknown effect')
        again = self.fresh_controller()
        with self.assertRaisesRegex(ValueError, 'Guarded target publication refused'):
            again.recover()
        self.assertEqual(len(self.fixture.spawned), 2)

    @read_only_evidence
    def test_r1_unknown_native_interruption_restart_never_redispatches(self):
        """No custody on unknown native work; original charge remains."""
        self.adopt()
        stop = KeyboardInterrupt('EXAMPLE startup observation interrupted')
        self.case.on_startup = lambda: (_ for _ in ()).throw(stop)
        with self.assertRaises(KeyboardInterrupt):
            self.workflow.run()
        accounting = self.fixture.attempt(self.case)
        count = len(self.fixture.spawned)
        fresh = self.fresh_controller()
        with self.assertRaisesRegex(ValueError, 'requires reconciliation'):
            fresh.recover()
        with self.assertRaisesRegex(ValueError, 'never redispatch'):
            fresh.run()
        self.assertEqual(len(self.fixture.spawned), count)
        self.assertEqual(self.fixture.attempt(self.case), accounting)

    def _failed_custody(self, *, sync):
        F.settle_original_archive(self.fixture, self.case)
        self.adopt()
        original = self.workflow._save
        stop = KeyboardInterrupt('EXAMPLE custody persistence interrupted')
        def interrupted(name, body):
            if name != 'custody.json':
                return original(name, body)
            if not sync:
                raise stop
            original_sync = W.os.fsync
            def fail_directory_sync(descriptor):
                info = os.fstat(descriptor)
                if (info.st_dev, info.st_ino) == tuple(self.workflow.config.state_identity[:2]):
                    raise stop
                return original_sync(descriptor)
            with patch.object(W.os, 'fsync', side_effect=fail_directory_sync):
                return original(name, body)
        with patch.object(self.workflow, '_save', side_effect=interrupted):
            with self.assertRaises(KeyboardInterrupt) as caught:
                self.workflow.run()
        self.assertIs(caught.exception, stop)
        self.assertIsNotNone(self.workflow._artifact, 'Original issued observation remains diagnostic evidence.')
        accounting = self.fixture.attempt(self.case)
        with self.assertRaisesRegex(ValueError, 'Durable original custody'):
            self.allow_publication()
        with self.assertRaisesRegex(ValueError, 'Separate publication'):
            self.workflow.publish()
        self.assertFalse((self.case.host.target / 'result.txt').exists())
        self.assertEqual(self.fixture.attempt(self.case), accounting)
        self.assertEqual(len(self.fixture.spawned), 2)
        fresh = self.fresh_controller()
        if not sync:
            with self.assertRaisesRegex(ValueError, 'requires reconciliation'):
                fresh.recover()
        else:
            self.assertTrue(fresh.recover()['validation_complete'])
            fresh.adopt_publication(adoption_id='EXAMPLE_RECOVERED_CUSTODY')
            self.assertTrue(fresh.publish()['publication']['publication_complete'])
        self.assertEqual(self.fixture.attempt(self.case), accounting)
        self.assertEqual(len(self.fixture.spawned), 2)

    @read_only_evidence
    def test_r6_custody_write_interruption_keeps_publication_hold(self):
        """Missing original custody cannot publish through a live token."""
        self._failed_custody(sync=False)

    @read_only_evidence
    def test_r6_custody_sync_interruption_requires_authenticated_recovery(self):
        """Unconfirmed sync keeps the hold; recovery confirms original custody."""
        self._failed_custody(sync=True)

    @read_only_evidence
    def test_r6_preconsent_recovery_refuses_unrelated_target_drift(self):
        """Pre-consent checkpoints require freshness at the workflow join."""
        self.run_native(archive_schedule='settled')
        accounting = self.fixture.attempt(self.case)
        (self.case.host.target / 'EXAMPLE_UNRELATED.txt').write_text('EXAMPLE target drift')
        fresh = self.fresh_controller()
        with self.assertRaises(ValueError):
            fresh.recover()
        with self.assertRaisesRegex(ValueError, 'Durable original custody'):
            fresh.adopt_publication(adoption_id='EXAMPLE_DRIFT_REFUSAL')
        self.assertFalse((self.case.host.target / 'result.txt').exists())
        self.assertEqual(self.fixture.attempt(self.case), accounting)
        self.assertEqual(len(self.fixture.spawned), 2)

    @read_only_evidence
    def test_r1_controller_cleanup_preserves_exact_primary_and_accounting(self):
        """Unlock/close faults retain the controller custody guard."""
        self.run_native(archive_schedule='settled')
        accounting = self.fixture.attempt(self.case)
        original_flock, original_close = W.fcntl.flock, W.os.close
        identity = tuple(self.workflow.config.state_identity[:2])
        for mode in ('unlock', 'close', 'both'):
            with self.subTest(mode=mode):
                armed = [False]
                primary = KeyboardInterrupt('EXAMPLE original operation interruption')
                def matches(fd):
                    info = os.fstat(fd)
                    return armed[0] and (info.st_dev, info.st_ino) == identity
                def flock(fd, operation):
                    fail = operation == W.fcntl.LOCK_UN and matches(fd) and mode in ('unlock', 'both')
                    result = original_flock(fd, operation)
                    if fail:
                        raise OSError('EXAMPLE secondary unlock failure')
                    return result
                def close(fd):
                    fail = matches(fd) and mode in ('close', 'both')
                    result = original_close(fd)
                    if fail:
                        raise OSError('EXAMPLE secondary descriptor close failure')
                    return result
                caught = None
                with patch.object(W.fcntl, 'flock', side_effect=flock), patch.object(W.os, 'close', side_effect=close):
                    try:
                        with self.workflow._locked():
                            armed[0] = True
                            raise primary
                    except BaseException as error:
                        caught = error
                self.assertIs(caught, primary)
                self.assertTrue(primary.__notes__)
                self.assertEqual(self.fixture.attempt(self.case), accounting)
                self.assertEqual(len(self.fixture.spawned), 2)

        # composed fixture cleanup must restore process APIs for the next family.
        self.doCleanups()
        self.assertIs(os.kill, self._process_kill_before_fixture)

    def _persistence_cleanup_fault(self, stage):
        F.settle_original_archive(self.fixture, self.case)
        self.adopt()
        primary = KeyboardInterrupt('EXAMPLE original custody fsync interrupted')
        original_sync, original_close = W.os.fsync, W.os.close
        path = self.workflow.config.state / 'custody.json'
        pending = {'identity': None}
        def matches(fd):
            if not path.exists():
                return False
            info = os.fstat(fd)
            expected = path.stat() if stage == 'file' else self.workflow.config.state.stat()
            return (info.st_dev, info.st_ino) == (expected.st_dev, expected.st_ino)
        def sync(fd):
            if matches(fd):
                info = os.fstat(fd)
                pending['identity'] = (info.st_dev, info.st_ino)
                raise primary
            return original_sync(fd)
        def close(fd):
            info = os.fstat(fd)
            fail = pending['identity'] == (info.st_dev, info.st_ino)
            result = original_close(fd)
            if fail:
                pending['identity'] = None
                raise OSError('EXAMPLE secondary custody descriptor close failed')
            return result
        caught = None
        with patch.object(W.os, 'fsync', side_effect=sync), patch.object(W.os, 'close', side_effect=close):
            try:
                self.workflow.run()
            except BaseException as error:
                caught = error
        self.assertIs(caught, primary)
        self.assertTrue(primary.__notes__)
        accounting = self.fixture.attempt(self.case)
        self.assertEqual(accounting['outcome'], 'completed')
        with self.assertRaises(ValueError):
            self.allow_publication()
        self.assertFalse((self.case.host.target / 'result.txt').exists())
        self.assertEqual(self.fixture.attempt(self.case), accounting)
        self.assertEqual(len(self.fixture.spawned), 2)

    @read_only_evidence
    def test_r6_custody_file_fsync_and_close_preserve_original(self):
        """Actual file fsync/close faults preserve controller custody."""
        self._persistence_cleanup_fault('file')

    @read_only_evidence
    def test_r6_custody_directory_fsync_and_close_preserve_original(self):
        """Actual directory fsync/close faults retain hold and charge."""
        self._persistence_cleanup_fault('directory')

    def _private_locations(self):
        c = self.workflow.config
        return (('host.target', c.host, 'target'), ('host.state', c.host, 'state'),
                ('ledger.root', c.ledger, 'root'), ('store.directory', c.store, 'directory'),
                ('controller_state', c, 'state'), ('publication_state', c, 'publication_state'))

    @read_only_evidence
    def test_r6_all_private_roots_refuse_before_original_verification_and_custody(self):
        """No /usr writes; real inputs with an unreachable forbidden root."""
        before = self.settings['state_store'].read_state()
        for visible in (Path('/usr'), ROOT / 'scripts', ROOT / 'policy', ROOT / 'schemas'):
            for label, owner, field in self._private_locations():
                settings = dict(self.settings)
                forbidden = visible / 'EXAMPLE_PROTECTED'
                if label in settings:
                    settings[label] = forbidden
                with self.subTest(root=label), patch.object(owner, field, forbidden):
                    with patch.object(W.A, 'MaintenanceAuthorityVerifier',
                                      wraps=W.A.MaintenanceAuthorityVerifier) as verification:
                        with self.assertRaises(W.boundary.HostRootBoundaryError):
                            W.ControllerConfiguration(**settings)
                    verification.assert_not_called()
        self.assertEqual(self.settings['state_store'].read_state(), before)
        self.assertEqual(self.fixture.spawned, [])
        self.assertEqual(list(self.settings['controller_state'].iterdir()), [])
        self.assertEqual(list(self.settings['publication_state'].iterdir()), [])

    @read_only_evidence
    def test_r6_private_root_drift_veto_preserves_original_store_callbacks(self):
        """Original current veto rejects every private location before effects."""
        c, verifier = self.workflow.config, self.workflow.verifier
        self.assertIs(verifier._state_reader.__self__, c.store)
        self.assertIs(verifier._state_reader.__func__, W.A.MaintenanceStateStore.read_state)
        self.assertIs(verifier._claim.__self__, c.store)
        self.assertIs(verifier._claim.__func__, W.A.MaintenanceStateStore.claim_operation)
        before = c.store.read_state()
        for phase in ('before-adoption', 'after-adoption'):
            if phase == 'after-adoption':
                self.adopt()
            for label, owner, field in self._private_locations():
                with self.subTest(phase=phase, root=label):
                    with patch.object(owner, field, Path('/usr/EXAMPLE_PROTECTED')):
                        with self.assertRaises(W.boundary.HostRootBoundaryError):
                            verifier._current()
                        with self.assertRaises(W.boundary.HostRootBoundaryError):
                            self.workflow._save('EXAMPLE_RECORD.json', {})
            self.assertEqual(c.store.read_state(), before)
        self.assertEqual(self.fixture.spawned, [])
        self.assertFalse(list(c.state.iterdir()))
        self.assertFalse(list(c.publication_state.iterdir()))

    def test_r6_private_root_drift_during_original_startup_vetoes_before_turn(self):
        """Startup callout cannot bypass current custody-root rejection."""
        self.adopt()
        self.case.on_startup = lambda: setattr(self.workflow.config, 'publication_state',
                                               Path('/usr/EXAMPLE_PROTECTED'))
        with patch.object(W.R.os, 'write', wraps=W.R.os.write) as writes:
            with self.assertRaises(W.boundary.HostRootBoundaryError):
                self.workflow.run()
        self.assertNotIn(b'1', [call.args[1] for call in writes.call_args_list])
        self.assertNotIn('turn/start', self.fixture.spawned[0].methods)
        self.assertIsNone(self.workflow.factory.token)
        self.assertFalse((self.case.host.state / 'artifact').exists())
        self.assertFalse((self.case.host.target / 'result.txt').exists())


    def test_r6_fixed_mount_boundary_and_canonical_aliases(self):
        """Fixed runtime and alias layouts are unsupported."""
        boundary = W.boundary
        for root in ('/usr', '/lib', '/lib64'):
            canonical = Path(os.path.realpath(root))
            for path in (canonical, canonical / 'EXAMPLE_PROTECTED', Path('/')):
                with self.subTest(path=path):
                    with self.assertRaises(boundary.HostRootBoundaryError):
                        boundary.require_private_roots((path,))
            # Original canonical-path refusal also closes the lexical alias.
            with self.assertRaises(ValueError):
                boundary.require_private_roots((root + '/EXAMPLE_PROTECTED',))
        private = self.settings['controller_state']
        self.assertIsNone(boundary.require_private_roots((private,)))
        for visible in (ROOT / 'scripts', ROOT / 'policy', ROOT / 'schemas'):
            with self.assertRaises(boundary.HostRootBoundaryError):
                boundary.require_private_roots((visible / 'EXAMPLE_PROTECTED',), visible_paths=(visible,))
        original_realpath = os.path.realpath
        def runtime_alias(path, *args, **kwargs):
            if os.fspath(path) == '/lib64':
                return str(private)
            return original_realpath(path, *args, **kwargs)
        with patch.object(boundary.os.path, 'realpath', side_effect=runtime_alias):
            with self.assertRaises(boundary.HostRootBoundaryError):
                boundary.require_private_roots((private,))
        alias = private.parent / 'EXAMPLE_ALIAS'
        alias.symlink_to(private, target_is_directory=True)
        with self.assertRaises(W.H.OfflineHostError):
            boundary.require_private_roots((alias,))
        with self.assertRaises(FileNotFoundError):
            W.ControllerConfiguration(**dict(self.settings, controller_state=private / 'EXAMPLE_MISSING'))
        special = private / 'EXAMPLE_FIFO'
        os.mkfifo(special)
        with self.assertRaises(NotADirectoryError):
            W.ControllerConfiguration(**dict(self.settings, controller_state=special))
