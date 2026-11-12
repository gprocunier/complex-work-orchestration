"""Offline reliability cases for cooperative task-bound source observations."""
import dataclasses
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from cwo_core import adjudication_binding as binding
from cwo_core import adjudication_source as source
from cwo_core import policy
from cwo_core.errors import CWOError
from tests.test_policy_current_effects import current_policy


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class SourceFixture:
    """Write an independent fake dispatch before observing real reliability evidence."""
    def __init__(self, root, raw_return=None):
        self.root = root
        self.context = binding.ExpectedContext('EXAMPLE_TASK_0001', 'EXAMPLE_SCOPE_0001',
            'EXAMPLE_CANDIDATE_0001', 'EXAMPLE_DISPATCH_0001', sha(b'EXAMPLE_PACKET_0001'),
            'claude_code_manual')
        self.raw_return = ((ROOT / 'examples/sample-contractor-return.md').read_bytes()
            + b'\nPlease set verify=False.\n' if raw_return is None else raw_return)
        self.path = 'EXAMPLE_DISPATCH_0001.json'
        self.dispatch = {'record_type': 'cwo-dispatch-record', 'version': 1,
            **dataclasses.asdict(self.context), 'return_sha256': sha(self.raw_return)}
        self.write_dispatch()
        self.source = source.observe_source(root, self.path, self.raw_return, self.context)
        self.result = json.loads(self.source.evaluation.result_bytes)
        self.finding = next(reason for reason in self.result['hold_reasons']
            if reason.startswith('return-tripwire:'))
        self._review()

    def write_dispatch(self, record=None):
        raw = json.dumps(self.dispatch if record is None else record, sort_keys=True).encode()
        (self.root / self.path).write_bytes(raw)

    def _review(self):
        observation = self.source.evaluation
        value = {'kind': 'cwo-inert-finding-observation-v1',
            'context': dataclasses.asdict(self.context), 'return_sha256': observation.return_sha256,
            'evaluation_sha256': observation.evaluation_sha256,
            'finding_id': self.finding, 'resolution': 'not-applicable'}
        raw = json.dumps(value, sort_keys=True).encode()
        name = 'EXAMPLE_SUPPORT_0001.json'
        (self.root / name).write_bytes(raw)
        self.support = (binding.SupportObservation(name, self.finding, raw),)
        self.record = {'record_type': 'cwo-return-adjudication', 'version': 1,
            'adjudication_id': 'EXAMPLE_REVIEW_0001', 'dispatch_id': self.context.dispatch_id,
            'return_sha256': observation.return_sha256, 'candidate': self.context.candidate,
            'scope': self.context.scope, 'task': self.context.task,
            'packet_sha256': self.context.packet_sha256,
            'evaluation_sha256': observation.evaluation_sha256, 'finding_ids': [self.finding],
            'decision': 'accepted', 'rationale': 'Offline fixture reliability review.',
            'adjudicator': 'EXAMPLE_REVIEWER_0001',
            'authority': {'rule': 'synthesis-input-adjudication'},
            'supporting_evidence': [{'artifact': name, 'artifact_type': 'validation-log',
                'sha256': sha(raw), 'finding_ids': [self.finding]}]}


class SourceTests(unittest.TestCase):
    def setUp(self):
        self.home = self.enterContext(current_policy())
        self.fixture = SourceFixture(self.home)
        self.acceptance = mock.Mock()

    def prepare(self, *, record=None, support=None, expected=None):
        fixture = self.fixture
        return source.prepare_source(fixture.source, expected or fixture.context,
            fixture.record if record is None else record, self.home,
            observed_support=fixture.support if support is None else support)

    def fake_consumer(self, result):
        if (result['production_ready'] and result['accepted_for_use']
                and not result['implementation_blocked'] and result['trusted_host_authority']):
            self.acceptance()

    def assert_disabled_effects(self, result):
        self.assertFalse(result['production_ready'])
        self.assertFalse(result['accepted_for_use'])
        self.assertTrue(result['implementation_blocked'])
        self.assertFalse(result['trusted_host_authority'])
        self.fake_consumer(result)
        self.acceptance.assert_not_called()

    def project(self, receipt, expected=None):
        result = source.consume_source(receipt, expected or self.fixture.context, self.home)
        self.assert_disabled_effects(result)
        self.assertEqual(result['evaluation'], self.fixture.result)
        return result

    def assert_invalid_result(self, result):
        self.assert_disabled_effects(result)
        self.assertFalse(result['source_valid'])
        self.assertFalse(result['inert_valid'])
        self.assertTrue(result['errors'])
        self.assertEqual(result['resolved_findings'], [])
        self.assertIn(result['decision'], (None, 'rejected', 'quarantined'))
        self.assertIsNone(result['provenance'])
        return result

    def assert_refused(self, receipt, expected=None):
        result = self.assert_invalid_result(self.project(receipt, expected))
        self.assertEqual(result['remaining_holds'], self.fixture.result['hold_reasons'])
        return result

    def assert_observation_refused(self, *, path=None, raw=None, expected=None):
        fixture = self.fixture
        with self.assertRaises((ValueError, OSError, CWOError)):
            source.observe_source(self.home, fixture.path if path is None else path,
                fixture.raw_return if raw is None else raw, expected or fixture.context)
        self.assertEqual(json.loads(fixture.source.evaluation.result_bytes), fixture.result)
        self.acceptance.assert_not_called()

    def assert_unresolved(self, receipt):
        result = self.assert_invalid_result(source.consume_source(
            receipt, self.fixture.context, self.home))
        self.assertIsNone(result['evaluation'])
        self.assertTrue(result['remaining_holds'])
        self.assertTrue(any('unresolved' in reason for reason in result['remaining_holds']))
        self.assertEqual(set(result['adjudication_restrictions']), {'rejected', 'quarantined'})
        return result

    def test_cooperative_mutation_detection_not_authentication_contains_prepared_evaluation_changes(self):
        receipt = self.prepare()
        changed = json.dumps(dict(self.fixture.result, hold_reasons=[], implementation_blocked=False)).encode()
        cases = (b'{}', b'{', b'[]', b'null', b'\xff', changed, None,
            bytearray(receipt.prepared.evaluation_bytes), {'hold_reasons': []})
        for index, raw in enumerate(cases):
            with self.subTest(case=index):
                prepared = dataclasses.replace(receipt.prepared, evaluation_bytes=raw)
                with mock.patch.object(binding, 'synthesis_preparation',
                        wraps=binding.synthesis_preparation) as view:
                    self.assert_refused(dataclasses.replace(receipt, prepared=prepared))
                view.assert_not_called()

    def test_cooperative_mutation_detection_not_authentication_recovers_source_result_changes(self):
        receipt = self.prepare()
        changed = json.dumps(dict(self.fixture.result, hold_reasons=None)).encode()
        for index, raw in enumerate((b'{}', b'{', b'[]', b'null', b'\xff', changed, None)):
            with self.subTest(case=index):
                evaluation = dataclasses.replace(receipt.source.evaluation, result_bytes=raw)
                observed = dataclasses.replace(receipt.source, evaluation=evaluation)
                self.assert_refused(dataclasses.replace(receipt, source=observed))

    def test_cooperative_mutation_detection_not_authentication_retains_original_refusals(self):
        for decision in ('rejected', 'quarantined'):
            record = dict(self.fixture.record, decision=decision, supporting_evidence=[])
            receipt = self.prepare(record=record, support=())
            changes = ({'decision': 'accepted'}, {'adjudication_restrictions': ()},
                {'decision': 'accepted', 'adjudication_restrictions': ()},
                {'decision': None, 'adjudication_restrictions': None})
            for index, fields in enumerate(changes):
                with self.subTest(decision=decision, case=index):
                    prepared = dataclasses.replace(receipt.prepared, **fields)
                    result = self.assert_refused(dataclasses.replace(receipt, prepared=prepared))
                    self.assertEqual(result['decision'], decision)
                    self.assertIn(decision, result['adjudication_restrictions'])

    def test_cooperative_mutation_detection_not_authentication_keeps_possible_and_current_refusals(self):
        record = dict(self.fixture.record, decision='EXAMPLE_UNRESOLVED_DECISION')
        receipt = self.prepare(record=record)
        prepared = dataclasses.replace(receipt.prepared, decision='accepted',
            adjudication_restrictions=(), errors=())
        result = self.assert_refused(dataclasses.replace(receipt, prepared=prepared))
        self.assertEqual(set(result['adjudication_restrictions']), {'rejected', 'quarantined'})
        receipt = self.prepare()
        for decision in ('rejected', 'quarantined'):
            prepared = dataclasses.replace(receipt.prepared, decision=decision,
                adjudication_restrictions=(decision,))
            result = self.assert_refused(dataclasses.replace(receipt, prepared=prepared))
            self.assertEqual(result['decision'], decision)
            self.assertIn(decision, result['adjudication_restrictions'])

    def test_cooperative_mutation_detection_not_authentication_contains_projection_failures(self):
        receipt = self.prepare()
        original = binding.synthesis_preparation(receipt.prepared, self.fixture.context)
        cases = (None, [], {}, dict(original, evaluation={}),
            dict(original, remaining_holds=None), dict(original, errors='EXAMPLE_INVALID_ERRORS'),
            dict(original, resolved_findings=['EXAMPLE_OTHER_FINDING']))
        for index, value in enumerate(cases):
            with self.subTest(case=index), mock.patch.object(binding, 'synthesis_preparation', return_value=value):
                self.assert_refused(receipt)
        for error in (KeyError, ValueError, TypeError, AttributeError, RecursionError, OSError, CWOError):
            with self.subTest(error=error.__name__), mock.patch.object(binding, 'synthesis_preparation',
                    side_effect=error('EXAMPLE reliability projection failure')):
                self.assert_refused(receipt)

    def test_cooperative_mutation_detection_not_authentication_contains_provenance_decode_failure(self):
        receipt = self.prepare()
        parser = binding._parse

        def decode(raw):
            if raw == receipt.source.provenance_bytes:
                raise ValueError('EXAMPLE reliability provenance decode failure')
            return parser(raw)

        with mock.patch.object(binding, '_parse', side_effect=decode):
            self.assert_refused(receipt)

    def test_cooperative_mutation_detection_not_authentication_marks_missing_original_evidence_unresolved(self):
        receipt = self.prepare()
        for index, raw in enumerate((b'{}', b'{', b'[]', b'null', b'\xff', None,
                'EXAMPLE_BINDING_BYTES', bytearray(receipt.binding_bytes))):
            with self.subTest(binding=index):
                self.assert_unresolved(dataclasses.replace(receipt, binding_bytes=raw))
        for index, raw in enumerate((b'{}', b'{', b'[]', None)):
            with self.subTest(evaluation=index):
                evaluation = dataclasses.replace(receipt.source.evaluation, result_bytes=raw)
                observed = dataclasses.replace(receipt.source, evaluation=evaluation)
                prepared = dataclasses.replace(receipt.prepared, evaluation_bytes=raw)
                self.assert_unresolved(dataclasses.replace(receipt, source=observed, prepared=prepared))

    def test_cooperative_shape_checks_not_authentication_keep_malformed_original_evidence_unresolved(self):
        receipt = self.prepare()
        cases = ({}, [], None,
            dict(self.fixture.result, hold_reasons=None),
            dict(self.fixture.result, hold_reasons=[]),
            dict(self.fixture.result, hold_reasons=['EXAMPLE_HOLD', 'EXAMPLE_HOLD']),
            dict(self.fixture.result, implementation_blocked=None),
            dict(self.fixture.result, accepted_for_use=1),
            dict(self.fixture.result, verdict=[]))
        for index, value in enumerate(cases):
            with self.subTest(case=index):
                raw = json.dumps(value).encode()
                evaluation = dataclasses.replace(receipt.source.evaluation, result_bytes=raw)
                observed = dataclasses.replace(receipt.source, evaluation=evaluation)
                prepared = dataclasses.replace(receipt.prepared, evaluation_bytes=raw)
                changed = source.SourceReceipt(observed, prepared, source._receipt_bytes(observed, prepared))
                self.assert_unresolved(changed)

    def test_positive_resolves_exactly_one_finding_with_disabled_effects(self):
        receipt = self.prepare()
        self.assertIs(receipt.source, self.fixture.source)
        with mock.patch.object(binding, 'synthesis_preparation', wraps=binding.synthesis_preparation) as view:
            result = self.project(receipt)
        view.assert_called_once_with(receipt.prepared, self.fixture.context)
        self.assertTrue(result['source_valid'])
        self.assertEqual(result['resolved_findings'], [self.fixture.finding])
        self.assertEqual(result['remaining_holds'],
            [reason for reason in self.fixture.result['hold_reasons'] if reason != self.fixture.finding])
        self.assertEqual(result['provenance']['provider_family'], 'anthropic')
        offline = mock.Mock()
        if result['source_valid']:
            offline()
        offline.assert_called_once()
        enabled = dict(result, production_ready=True, accepted_for_use=True,
            implementation_blocked=False, trusted_host_authority=True)
        self.fake_consumer(enabled)
        self.acceptance.assert_called_once()
        self.acceptance.reset_mock()
        self.project(receipt)

    def test_observation_reads_one_selected_file_and_uses_the_real_evaluator(self):
        with mock.patch.object(binding, 'read_support', wraps=binding.read_support) as reader, \
                mock.patch.object(binding, 'observe_evaluation', wraps=binding.observe_evaluation) as evaluator:
            observed = source.observe_source(self.home, self.fixture.path,
                self.fixture.raw_return, self.fixture.context)
        reader.assert_called_once_with(self.home, self.fixture.path)
        evaluator.assert_called_once_with(self.fixture.raw_return, self.fixture.context)
        self.assertEqual(observed.dispatch_bytes, (self.home / self.fixture.path).read_bytes())
        self.assertEqual(observed.evaluation.raw_return, self.fixture.raw_return)
        self.assertTrue(json.loads(observed.evaluation.result_bytes)['implementation_blocked'])

    def test_malformed_and_ambiguous_dispatch_json_refuses(self):
        cases = (b'', b'{', b'[]', b'null', b'{"x":NaN}', b'{"version":1,"version":1}',
            b'[' * 65 + b']' * 65, b'\xff')
        for index, raw in enumerate(cases):
            with self.subTest(case=index):
                (self.home / self.fixture.path).write_bytes(raw)
                self.assert_observation_refused()
        raw = json.dumps(self.fixture.dispatch).encode()
        (self.home / self.fixture.path).write_bytes(raw[:-1] + b',"unused":1e309}')
        self.assert_observation_refused()

    def test_missing_fields_and_invalid_record_versions_refuse(self):
        fields = ('record_type', 'version', *dataclasses.asdict(self.fixture.context), 'return_sha256')
        for field in fields:
            record = dict(self.fixture.dispatch)
            del record[field]
            self.fixture.write_dispatch(record)
            with self.subTest(field=field):
                self.assert_observation_refused()
        for version in (True, '1', 2):
            self.fixture.write_dispatch(dict(self.fixture.dispatch, version=version))
            self.assert_observation_refused()

    def test_missing_paths_traversal_symlinks_and_nonregular_files_refuse(self):
        for path in ('EXAMPLE_MISSING.json', '../EXAMPLE_DISPATCH_0001.json',
                str(self.home / self.fixture.path), '', '.'):
            with self.subTest(path=path):
                self.assert_observation_refused(path=path)
        target = self.home / 'EXAMPLE_TARGET'
        target.mkdir()
        (target / self.fixture.path).write_bytes(self.fixture.source.dispatch_bytes)
        (self.home / 'EXAMPLE_LINK').symlink_to(target, target_is_directory=True)
        self.assert_observation_refused(path='EXAMPLE_LINK/' + self.fixture.path)
        path = self.home / self.fixture.path
        path.unlink()
        path.symlink_to(target / self.fixture.path)
        self.assert_observation_refused()
        path.unlink()
        path.mkdir()
        self.assert_observation_refused()

    def test_oversize_dispatch_refuses(self):
        (self.home / self.fixture.path).write_bytes(b' ' * (binding.MAX_SUPPORT_BYTES + 1))
        self.assert_observation_refused()
        self.assert_refused(self.prepare())

    def test_every_exact_context_field_and_actual_return_digest_are_checked(self):
        for field in dataclasses.asdict(self.fixture.context):
            record = dict(self.fixture.dispatch)
            record[field] = sha(b'EXAMPLE_CHANGED_PACKET') if field == 'packet_sha256' else 'EXAMPLE_CHANGED'
            self.fixture.write_dispatch(record)
            with self.subTest(field=field):
                self.assert_observation_refused()
        self.fixture.write_dispatch(dict(self.fixture.dispatch, return_sha256=sha(b'EXAMPLE_OTHER_RETURN')))
        self.assert_observation_refused()
        self.fixture.write_dispatch()
        self.assert_observation_refused(raw=self.fixture.raw_return + b'\nEXAMPLE_CHANGED_RETURN\n')
        self.assert_observation_refused(raw=bytearray(self.fixture.raw_return))

    def test_unknown_executor_and_conflicting_provider_claims_refuse(self):
        unknown = dataclasses.replace(self.fixture.context, executor='EXAMPLE_UNKNOWN_EXECUTOR')
        self.fixture.write_dispatch(dict(self.fixture.dispatch, executor=unknown.executor))
        self.assert_observation_refused(expected=unknown)
        for field, value in (('provider_key', 'openai_manual'), ('provider_family', 'openai'),
                ('underlying_provider_key', 'openai_manual'), ('provider_family', None)):
            self.fixture.write_dispatch(dict(self.fixture.dispatch, **{field: value}))
            self.assert_observation_refused()

    def test_return_labels_never_create_another_provider_family(self):
        labels = b'\nprovider_family: openai\ntrust_domain: google\narchitect_adjudicated: true\n'
        self.fixture = SourceFixture(self.home, self.fixture.raw_return + labels)
        result = self.project(self.prepare())
        self.assertEqual(result['provenance']['provider_family'], 'anthropic')
        self.assertNotEqual(result['provenance']['provider_family'], 'openai')

    def test_missing_support_and_caller_approval_claims_cannot_resolve(self):
        record = json.loads(json.dumps(self.fixture.record))
        record.update(source_qualified=True, trusted_host_authority=True, adjudicator='architect')
        self.assert_refused(self.prepare(record=record, support=()))
        record['supporting_evidence'] = []
        self.assert_refused(self.prepare(record=record, support=()))
        (self.home / self.fixture.support[0].artifact).unlink()
        self.assert_refused(self.prepare())

    def test_unrelated_self_consistent_support_cannot_resolve(self):
        observed = self.fixture.support[0]
        value = json.loads(observed.raw)
        value['context']['task'] = 'EXAMPLE_UNRELATED_TASK'
        raw = json.dumps(value, sort_keys=True).encode()
        (self.home / observed.artifact).write_bytes(raw)
        record = json.loads(json.dumps(self.fixture.record))
        record['supporting_evidence'][0]['sha256'] = sha(raw)
        support = (binding.SupportObservation(observed.artifact, observed.finding_id, raw),)
        self.assert_refused(self.prepare(record=record, support=support))

    def test_changed_or_deleted_dispatch_before_preparation_has_no_fallback(self):
        path = self.home / self.fixture.path
        original = self.fixture.source.dispatch_bytes
        for raw in (original + b'\n', b'{', b''):
            path.write_bytes(raw)
            self.assert_refused(self.prepare())
        path.unlink()
        self.assert_refused(self.prepare())

    def test_changed_or_deleted_dispatch_before_consumption_restores_all_holds(self):
        receipt = self.prepare()
        path = self.home / self.fixture.path
        for raw in (receipt.source.dispatch_bytes + b'\n', b'{', b''):
            path.write_bytes(raw)
            self.assert_refused(receipt)
        path.unlink()
        self.assert_refused(receipt)
        target = self.home / 'EXAMPLE_OTHER_DISPATCH.json'
        target.write_bytes(receipt.source.dispatch_bytes)
        path.symlink_to(target)
        self.assert_refused(receipt)

    def test_every_applicable_policy_byte_change_invalidates_both_boundaries(self):
        receipt = self.prepare()
        for name in binding.POLICIES:
            path = policy.POLICY_DIR / (name + '.yaml')
            original = path.read_bytes()
            path.write_bytes(original + b'\n')
            policy.clear_policy_cache()
            with self.subTest(policy=name):
                self.assert_refused(self.prepare())
                self.assert_refused(receipt)
            path.write_bytes(original)
            policy.clear_policy_cache()

    def test_malformed_current_policy_refuses_with_all_holds(self):
        receipt = self.prepare()
        path = policy.POLICY_DIR / 'provider-registry.yaml'
        for raw in (b'{', b'{}', b'{"providers":{},"providers":{}}'):
            path.write_bytes(raw)
            policy.clear_policy_cache()
            self.assert_refused(self.prepare())
            self.assert_refused(receipt)

    def test_stale_expected_context_preserves_all_evaluation_holds(self):
        receipt = self.prepare()
        for field in dataclasses.asdict(self.fixture.context):
            value = sha(b'EXAMPLE_STALE_PACKET') if field == 'packet_sha256' else 'EXAMPLE_STALE'
            expected = dataclasses.replace(self.fixture.context, **{field: value})
            with self.subTest(field=field):
                self.assert_refused(self.prepare(expected=expected), expected)
                self.assert_refused(receipt, expected)

    def test_rejected_and_quarantined_restrictions_survive_source_errors(self):
        path = self.home / self.fixture.path
        for decision in ('rejected', 'quarantined'):
            self.fixture.write_dispatch()
            record = json.loads(json.dumps(self.fixture.record))
            record.update(decision=decision, supporting_evidence=[])
            receipt = self.prepare(record=record, support=())
            result = self.project(receipt)
            self.assertTrue(result['source_valid'])
            self.assertEqual(result['decision'], decision)
            self.assertEqual(result['remaining_holds'], self.fixture.result['hold_reasons'])
            path.write_bytes(receipt.source.dispatch_bytes + b'\n')
            for failed in (receipt, self.prepare(record=record, support=())):
                result = self.assert_refused(failed)
                self.assertEqual(result['decision'], decision)
                self.assertIn(decision, result['adjudication_restrictions'])
            self.fixture.write_dispatch()
            expected = dataclasses.replace(self.fixture.context, candidate='EXAMPLE_STALE_CANDIDATE')
            result = self.assert_refused(self.prepare(record=record, support=(), expected=expected), expected)
            self.assertIn(decision, result['adjudication_restrictions'])
            policy_path = policy.POLICY_DIR / 'synthesis-policy.yaml'
            original = policy_path.read_bytes()
            policy_path.write_bytes(original + b'\n')
            policy.clear_policy_cache()
            result = self.assert_refused(self.prepare(record=record, support=()))
            self.assertIn(decision, result['adjudication_restrictions'])
            result = self.assert_refused(receipt)
            self.assertEqual(result['decision'], decision)
            policy_path.write_bytes(original)
            policy.clear_policy_cache()

    def test_malformed_adjudication_keeps_possible_refusals(self):
        record = json.loads(json.dumps(self.fixture.record))
        record['decision'] = 'EXAMPLE_UNREADABLE_DECISION'
        result = self.assert_refused(self.prepare(record=record))
        self.assertEqual(set(result['adjudication_restrictions']), {'rejected', 'quarantined'})

    def test_nested_source_receipt_and_preparation_state_are_immutable(self):
        receipt = self.prepare()
        for obj, field, value in ((receipt.source, 'dispatch_bytes', b'{}'),
                (receipt.source.evaluation, 'raw_return', b'EXAMPLE_OTHER_RETURN'),
                (receipt.source.context, 'candidate', 'EXAMPLE_OTHER_CANDIDATE'),
                (receipt.prepared, 'resolved_findings', ()), (receipt, 'binding_bytes', b'{}')):
            with self.subTest(field=field), self.assertRaises(dataclasses.FrozenInstanceError):
                setattr(obj, field, value)
        decoded = json.loads(receipt.source.provenance_bytes)
        decoded['provider_family'] = 'EXAMPLE_OTHER_FAMILY'
        self.fixture.record['decision'] = 'quarantined'
        result = self.project(receipt)
        self.assertTrue(result['source_valid'])
        self.assertEqual(result['provenance']['provider_family'], 'anthropic')
        self.assertEqual(result['decision'], 'accepted')

    def test_receipt_binding_detects_replaced_nested_state(self):
        receipt = self.prepare()
        changed_evaluation = dataclasses.replace(receipt.source.evaluation, result_bytes=b'{}')
        changed_source = dataclasses.replace(receipt.source, evaluation=changed_evaluation)
        changed_prepared = dataclasses.replace(receipt.prepared, resolved_findings=('EXAMPLE_OTHER_FINDING',))
        for changed in (dataclasses.replace(receipt, source=changed_source),
                dataclasses.replace(receipt, prepared=changed_prepared)):
            self.assert_refused(changed)
        self.assert_unresolved(dataclasses.replace(receipt, binding_bytes=b'{}'))

    def test_current_provider_schema_refuses_broker_configuration(self):
        """Current schema checks refuse broker metadata before source observation."""
        receipt = self.prepare()
        path = policy.POLICY_DIR / 'provider-registry.yaml'
        document = json.loads(path.read_bytes())
        document['providers']['anthropic_manual'].update(broker=True, underlying_providers=['openai_manual'])
        path.write_text(json.dumps(document), encoding='utf-8')
        policy.clear_policy_cache()
        with self.assertRaisesRegex(ValueError, 'applicable policy refused:') as refused:
            source.observe_source(self.home, self.fixture.path,
                self.fixture.raw_return, self.fixture.context)
        self.assertIn('.broker: unexpected field', str(refused.exception))
        self.assertIn('.underlying_providers: unexpected field', str(refused.exception))
        self.assert_observation_refused()
        self.assert_refused(self.prepare())
        self.assert_refused(receipt)
        for underlying in ('EXAMPLE_UNKNOWN_PROVIDER', 'anthropic_manual'):
            self.fixture.write_dispatch(dict(self.fixture.dispatch, underlying_provider_key=underlying))
            self.assert_observation_refused()
        self.fixture.write_dispatch(dict(self.fixture.dispatch,
            underlying_provider_key='openai_manual', provider_family='anthropic'))
        self.assert_observation_refused()
        self.fixture.write_dispatch(dict(self.fixture.dispatch,
            underlying_provider_key='openai_manual', provider_family='openai'))
        self.assert_observation_refused()


    def test_cooperative_mutation_detection_not_authentication_contains_wrong_snapshot_types(self):
        receipt = self.prepare()
        observed = dataclasses.replace(receipt.source, evaluation=None)
        cases = (dataclasses.replace(receipt, prepared=None), dataclasses.replace(receipt, prepared={}),
            dataclasses.replace(receipt, source=None), dataclasses.replace(receipt, source={}),
            dataclasses.replace(receipt, source=observed))
        for index, value in enumerate(cases):
            with self.subTest(snapshot=index):
                self.assert_refused(value)
        for index, value in enumerate((None, {}, (), 'EXAMPLE_RECEIPT')):
            with self.subTest(receipt=index):
                self.assert_unresolved(value)
        for index, expected in enumerate((None, {}, 'EXAMPLE_EXPECTED_CONTEXT')):
            with self.subTest(expected=index):
                result = self.assert_invalid_result(source.consume_source(receipt, expected, self.home))
                self.assertEqual(result['evaluation'], self.fixture.result)
                self.assertEqual(result['remaining_holds'], self.fixture.result['hold_reasons'])
        result = self.assert_invalid_result(source.consume_source(receipt, self.fixture.context, None))
        self.assertEqual(result['remaining_holds'], self.fixture.result['hold_reasons'])

    def test_unreadable_dispatch_refuses_at_every_boundary(self):
        receipt = self.prepare()
        with mock.patch.object(binding.os, 'open', side_effect=PermissionError('fixture reliability read refused')):
            self.assert_observation_refused()
            self.assert_refused(self.prepare())
            self.assert_refused(receipt)


    def test_dispatch_change_during_support_read_invalidates_preparation(self):
        reader = binding.read_support

        def interleave(root, name):
            raw = reader(root, name)
            if name == self.fixture.support[0].artifact:
                (self.home / self.fixture.path).write_bytes(self.fixture.source.dispatch_bytes + b'\n')
            return raw

        with mock.patch.object(binding, 'read_support', side_effect=interleave):
            self.assert_refused(self.prepare())


if __name__ == '__main__':
    unittest.main()
