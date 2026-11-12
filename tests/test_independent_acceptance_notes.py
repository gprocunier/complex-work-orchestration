"""Independent 5a-r1/5b gaps; real anchors, offline completions and CLI ingress.

Fixture construction is delegated through module imports, never discovered twice.
Only the observation race and recomputation drift use narrow runtime seams.
"""
from __future__ import annotations

from contextlib import ExitStack
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tests import test_audit_segments as audit_fixtures
from tests import test_acceptance_product_flow as flow_fixtures
from tests import test_host_acceptance as acceptance_fixtures
from tests import test_f9_host_provenance_guards as review_fixtures
from cwo_core import audit, audit_segments as segments, host_acceptance as acceptance
from cwo_core import host_records as records
from cwo_core.errors import CWOPolicyError

ROOT = Path(__file__).resolve().parents[1]


def image(root):
    return {str(p.relative_to(root)): p.read_bytes() for p in root.rglob('*') if p.is_file()}


class IndependentAcceptanceNotes(unittest.TestCase):
    def fixture(self, module, name, stack=None):
        fixture = getattr(module, name)('runTest')
        (self.addCleanup if stack is None else stack.callback)(fixture.doCleanups)
        fixture.setUp()
        return fixture

    def anchored_acceptance(self, fixture, accepted, **changes):
        """Seed a semantically inconsistent reader input with genuine content/chain anchors.

        This models corrupt host-authored claims, not an admitted ingress bypass.
        The audit event follows the expected graph, independently of claimed task.
        """
        payload = fixture.record_payload(accepted)
        payload.update(changes)
        record_id = fixture.store._write('acceptance-decision', payload)
        adjudication = fixture.store.get(payload['adjudication_record'])
        fixture.store.record_audit_event(dict(event_type='host_acceptance_decided',
            acceptance_record_sha256=record_id,
            adjudication_record_sha256=payload['adjudication_record'],
            host_control_id=adjudication['control_id'],
            **{key: accepted[key] for key in ('bead_id', 'dispatch_id', 'return_sha256', 'evaluation_sha256')}))
        self.assertEqual(fixture.store.get(record_id)['_record_sha256'], record_id)
        return record_id

    def test_missing_head_refuses_every_reader_and_append_without_writes(self):
        fixture = self.fixture(audit_fixtures, 'AuditSegmentChecks')
        # The first-segment row isolates missing-head refusal; the rotated row also checks segment inventory.
        # Both use the real segmented-store implementation and populated quota history.
        for rotated in (False, True):
            with self.subTest(rotated=rotated):
                if rotated:
                    fixture.populated()
                else:
                    fixture.emit(0)
                store = fixture.store
                events = store.audit_events()
                head = store.state_root / segments.HEAD
                saved = head.read_bytes()
                head.unlink()
                damaged = image(store.state_root)
                operations = (store.audit_events,
                    lambda: audit.count_audit_events('external_manual_dispatch', 'EXAMPLE-epic', True),
                    lambda: fixture.emit(99))
                try:
                    for operation in operations:
                        with self.assertRaises((ValueError, OSError)):
                            operation()
                        self.assertEqual(image(store.state_root), damaged)
                    self.assertFalse(audit.verify_audit_log()['valid'])
                    self.assertEqual(image(store.state_root), damaged)
                finally:
                    head.write_bytes(saved)
                    head.chmod(0o600)
                self.assertEqual(store.audit_events(), events)
                self.assertTrue(audit.verify_audit_log()['valid'])
                self.assertEqual(audit.count_audit_events('external_manual_dispatch', 'EXAMPLE-epic', True), len(events))
                fixture.emit(100)
                self.assertEqual(len(store.audit_events()), len(events) + 1)

    def test_pending_rotation_preserves_prior_anchored_record_and_discards_only_uncommitted(self):
        fixture = self.fixture(audit_fixtures, 'AuditSegmentChecks')
        for anchored in (True, False):
            with self.subTest(anchored=anchored):
                store = records.HostRecordStore.for_tests(fixture.base / str(anchored),
                    limits=replace(records.RecordLimits(), max_events=1))
                first = store.write_record('evaluation', score=1)
                first_path = store.root / (first + '.json')
                original = first_path.read_bytes()
                prior = store.audit_events()
                record_id = first
                if not anchored:
                    raw = records._json({**json.loads(original), 'score': 2})
                    record_id = hashlib.sha256(raw).hexdigest()
                    path = store.root / (record_id + '.json')
                    path.write_bytes(raw)
                    path.chmod(0o600)
                event = dict(event_type='host_record_written', host_record_sha256=record_id,
                    host_record_type='evaluation', previous_event_hash=prior[-1]['event_hash'])
                event['event_hash'] = audit.audit_event_payload_hash(event)
                raw = records._json(event)
                previous = (store.state_root / segments.HEAD).read_bytes()
                seal = segments._seal(0, store.audit_file.read_bytes(), prior, None)
                next_head = dict(event_count=2, event_hash=event['event_hash'], byte_count=len(raw),
                    active_segment=1, sealed_segments=[seal])
                journal = store.state_root / segments.JOURNAL
                journal.write_bytes(segments._journal_bytes(previous, next_head, raw))
                journal.chmod(0o600)
                before = image(store.state_root)
                with self.assertRaisesRegex(ValueError, 'rotation is pending'):
                    store.audit_events()
                self.assertEqual(image(store.state_root), before)
                try:
                    added = store.write_record('evaluation', score=3)  # Genuine exclusive writer recovers.
                finally:
                    self.assertTrue(first_path.is_file(), 'recovery deleted prior anchored evidence')
                    self.assertEqual(first_path.read_bytes(), original)
                self.assertEqual(store.get(first)['score'], 1)
                self.assertEqual(store.get(added)['score'], 3)
                self.assertEqual(sorted(row['score'] for row in store.find('evaluation')), [1, 3])
                self.assertFalse(journal.exists())
                if not anchored:
                    self.assertFalse((store.root / (record_id + '.json')).exists())
                with records.using_test_store(store):
                    self.assertTrue(audit.verify_audit_log()['valid'])
                self.assertEqual(len(store.audit_events()), 2)

    def test_completed_control_binds_observation_and_pipeline_evaluation(self):
        for drift in ('matching', 'observation', 'evaluation'):
            with self.subTest(drift=drift), ExitStack() as stack:
                fixture = self.fixture(flow_fixtures, 'AcceptanceProductFlowTests', stack)
                producer, control, _, store = fixture.provision()
                workflow, binding = flow_fixtures.workflow, flow_fixtures.binding
                workflow._record_host_source(producer, store)  # Fixture ingress precedes zero-write interval.
                observed = control._current()
                self.assertEqual(producer.current().evaluation.result_bytes, observed.evaluation_bytes)
                self.assertTrue(binding._parse(observed.evaluation_bytes)['accepted_for_use'])
                real_evaluate, real_current = acceptance._evaluate, control._current
                armed = False

                def evaluate(*args):
                    nonlocal armed
                    pending, result = real_evaluate(*args)
                    self.assertEqual(result, binding._parse(observed.evaluation_bytes))
                    armed = True
                    if drift == 'evaluation':
                        result = {**result, 'independent_recomputation_drift': True}
                    return pending, result

                def current():
                    result = real_current()
                    self.assertEqual(result, observed)
                    if armed and drift == 'observation':
                        record = binding._parse(result.record_bytes)
                        record['rationale'] += ' EXAMPLE coherent observation changed'
                        return replace(result, record_bytes=binding._json(record))
                    return result

                before = image(store.state_root)
                with patch.object(acceptance, '_evaluate', evaluate), patch.object(control, '_current', current):
                    if drift == 'matching':
                        control.current()
                    else:
                        message = ('observation changed during evaluation' if drift == 'observation'
                                   else 'decision concerns another evaluation')
                        with self.assertRaisesRegex(ValueError, message):
                            control.current()
                self.assertTrue(armed)
                if drift == 'matching':
                    accepted = store.get(control.acceptance_record)
                    acceptance.require_acceptance(store, control.acceptance_record,
                        bead_id=producer.expected.task, return_sha256=binding._sha(producer.raw),
                        evaluation_sha256=accepted['evaluation_sha256'], database_identity=store.workspace_database()[1])
                    self.assertEqual(control._state, 'open')
                else:
                    self.assertIsNone(control.acceptance_record)
                    self.assertEqual(store.find('acceptance-decision'), [])
                    self.assertEqual(image(store.state_root), before)
                    self.assertEqual(control._state, 'refused')
                    with self.assertRaisesRegex(ValueError, 'refusal is terminal'):
                        control.current()
                    self.assertEqual(image(store.state_root), before)

    def test_peer_writer_requires_exact_target_keys_before_any_write(self):
        fixture = self.fixture(acceptance_fixtures, 'HostAcceptanceTests')
        _, accepted = fixture.accepted()
        target = {key: accepted[key] for key in ('dispatch_id', 'return_sha256', 'evaluation_sha256')}
        review = review_fixtures.F9HostProvenanceGuards.reviewer(fixture.store, 'EXAMPLE-exact-target', target)
        self.assertEqual(fixture.store.require_dispatch(review['reviewer_identity']['dispatch_id'])['review_target'], target)
        before = image(fixture.store.state_root)
        with self.assertRaisesRegex(records.HostRecordError, 'exact review target'):
            review_fixtures.F9HostProvenanceGuards.reviewer(fixture.store, 'EXAMPLE-extra-target',
                {**target, 'unrecognized': 'EXAMPLE'})
        self.assertEqual(image(fixture.store.state_root), before)
        self.assertEqual(fixture.store.find('dispatch', dispatch_id='EXAMPLE-extra-target'), [])

    def test_acceptance_claimed_task_must_match_expected_graph_context(self):
        fixture = self.fixture(acceptance_fixtures, 'HostAcceptanceTests')
        args, accepted = fixture.accepted()
        altered = self.anchored_acceptance(fixture, accepted, bead_id='EXAMPLE-other-claimed-task')
        before = image(fixture.store.state_root)
        with self.assertRaisesRegex(CWOPolicyError, 'record context does not match'):
            acceptance.require_acceptance(fixture.store, **{**args, 'acceptance_record': altered}, **fixture.beacon)
        self.assertEqual(image(fixture.store.state_root), before)
        self.assertEqual(acceptance.require_acceptance(fixture.store, **args, **fixture.beacon), accepted)

    def test_evaluation_snapshot_digest_binds_even_when_recomputation_drifts_identically(self):
        fixture = self.fixture(acceptance_fixtures, 'HostAcceptanceTests')
        args, accepted = fixture.accepted()
        store = fixture.store
        recorded = store.get(accepted['evaluation_record'])
        changed = {**recorded['evaluation'], 'independent_recomputation_drift': True}
        evaluation_id = store.write_record('evaluation', **{**fixture.record_payload(recorded), 'evaluation': changed})
        adjudication = store.get(accepted['adjudication_record'])
        adjudication_id = store.write_record('adjudication',
            **{**fixture.record_payload(adjudication), 'evaluation_record': evaluation_id})
        altered = self.anchored_acceptance(fixture, accepted,
            evaluation_record=evaluation_id, adjudication_record=adjudication_id)
        self.assertNotEqual(acceptance.pending_evaluation_sha256(changed), args['evaluation_sha256'])
        real_evaluate = acceptance._evaluate

        def recompute(*inputs):
            pending, result = real_evaluate(*inputs)
            self.assertEqual(result, recorded['evaluation'])
            return pending, {**result, 'independent_recomputation_drift': True}

        before = image(store.state_root)
        # A narrow recomputation seam removes the downstream equality backup.
        # Hashing, records, receipts, eligibility and the acceptance reader remain real.
        with patch.object(acceptance, '_evaluate', recompute):
            with self.assertRaisesRegex(CWOPolicyError, 'evaluation digest does not match'):
                acceptance.require_acceptance(store, **{**args, 'acceptance_record': altered}, **fixture.beacon)
        self.assertEqual(image(store.state_root), before)
        self.assertEqual(acceptance.require_acceptance(store, **args, **fixture.beacon), accepted)

    def test_each_hold_mapping_must_reference_the_correct_anchored_clearance(self):
        helper = self.fixture(review_fixtures, 'F9HostProvenanceGuards')
        fixture, record_id, accepted, _, _, clearance, _, expected, _ = helper.reviewed()
        args = dict(acceptance_record=record_id, return_sha256=expected['return_sha256'],
                    evaluation_sha256=expected['evaluation_sha256'])
        self.assertEqual(acceptance.require_acceptance(fixture.store, **args, **fixture.beacon), accepted)
        self.assertEqual(accepted['required_holds'], ['peer-review-pending'])
        incorrect = fixture.store.write_record('hold-clearance',
            **{**fixture.record_payload(clearance), 'hold': 'risk-review-pending'})
        altered = self.anchored_acceptance(fixture, accepted, cleared_holds={'peer-review-pending': incorrect})
        before = image(fixture.store.state_root)
        with self.assertRaisesRegex(CWOPolicyError, 'hold clearance targets another hold or evaluation'):
            acceptance.require_acceptance(fixture.store, **{**args, 'acceptance_record': altered}, **fixture.beacon)
        self.assertEqual(image(fixture.store.state_root), before)
        self.assertEqual(acceptance.require_acceptance(fixture.store, **args, **fixture.beacon), accepted)

    def test_actual_intake_cli_positive_and_one_line_refusal_without_output_or_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / 'repo'
            for name in ('scripts', 'policy', 'schemas'):
                shutil.copytree(ROOT / name, repo / name, ignore=shutil.ignore_patterns('__pycache__'))
            state = root / 'configured-host-state'
            (repo / 'policy/workspace-host-state.json').write_text(json.dumps(
                dict(schema_version=1, host_state_root=str(state))))
            source = root / 'return.md'
            source.write_bytes((ROOT / 'examples/sample-contractor-return.md').read_bytes())
            # Bootstrap a genuine configured store in a separate process. No test
            # override/env route or fake admission enters the actual CLI process.
            seed = """from cwo_core.host_records import configured_store
store = configured_store()
for identity, role in [('EXAMPLE-manual', 'executor'), ('EXAMPLE-review', 'peer-review')]:
    store.write_dispatch(dispatch_id=identity, dispatch_role=role, provider='openai', model_family='gpt',
        model_id='gpt-6.1-sol', reasoning_effort='xhigh', session_id=identity,
        request_sha256='1'*64, evaluation_metadata={'dispatch_mode':'manual_ui'},
        review_target=None if role=='executor' else dict(dispatch_id='EXAMPLE-manual',
            return_sha256='2'*64, evaluation_sha256='3'*64))
"""
            env = {**os.environ, 'PYTHONPATH': str(repo / 'scripts')}
            seeded = subprocess.run([sys.executable, '-c', seed], cwd=repo, env=env,
                capture_output=True, text=True, timeout=20)
            self.assertEqual(seeded.returncode, 0, seeded.stderr)
            command = [sys.executable, str(repo / 'scripts/normalize_contractor_return.py'), '--file', str(source)]
            output = root / 'positive.json'
            positive = subprocess.run(command + ['--dispatch-id', 'EXAMPLE-manual', '--output', str(output)],
                cwd=repo, env=env, capture_output=True, text=True, timeout=20)
            self.assertEqual(positive.returncode, 0, positive.stderr)
            self.assertIsInstance(json.loads(output.read_bytes()), dict)
            stored = [json.loads(p.read_bytes()) for p in (state / 'records').glob('*.json')]
            receipts = [r for r in stored if r['record_type'] == 'return-received']
            self.assertEqual(len(receipts), 1)
            self.assertEqual(receipts[0]['capture_provenance'], 'manual-intake-v1')
            self.assertEqual(receipts[0]['return_sha256'], hashlib.sha256(source.read_bytes()).hexdigest())
            refused_output = root / 'refused.json'
            before = image(root)
            refused = subprocess.run(command + ['--dispatch-id', 'EXAMPLE-review', '--output', str(refused_output)],
                cwd=repo, env=env, capture_output=True, text=True, timeout=20)
            self.assertNotEqual(refused.returncode, 0)
            self.assertEqual(refused.stdout, '')
            self.assertEqual(refused.stderr.splitlines(), ['manual intake requires a recorded manual executor dispatch'])
            self.assertNotIn('Traceback', refused.stderr)
            self.assertFalse(refused_output.exists())
            self.assertEqual(image(root), before)
