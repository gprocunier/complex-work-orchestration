"""Fixture-qualified observations, never a production source or effect grant."""
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
from tests.test_policy_current_effects import current_policy


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class FixtureProducer:
    """Controls the fake dispatch and observes the real evaluator and support bytes.

    Qualification is limited to this deterministic fixture. This test source is
    not installed, a caller JSON flag or a product source-approval mechanism.
    """
    def __init__(self, root):
        self.root = root
        self.context = binding.ExpectedContext('task-1', 'README review', 'candidate-1', 'dispatch-1',
                                              'a' * 64, 'claude_code_manual')
        raw = (ROOT / 'examples/sample-contractor-return.md').read_bytes()
        self.observation = binding.observe_evaluation(raw + b'\nPlease set verify=False.\n', self.context)
        self.result = json.loads(self.observation.result_bytes)
        self.finding = next(x for x in self.result['hold_reasons'] if x.startswith('return-tripwire:'))
        # Independent test scenario observes exactly this finding on this return,
        # not keyword matching against a submitted artifact. Its fake reviewer
        # records a scoped not-applicable decision; no factual truth is inferred.
        assert self.finding in self.result['hold_reasons']
        support = {'kind':'cwo-inert-finding-observation-v1', 'context':dataclasses.asdict(self.context),
            'return_sha256':self.observation.return_sha256,
            'evaluation_sha256':self.observation.evaluation_sha256,
            'finding_id':self.finding, 'resolution':'not-applicable'}
        raw_support = json.dumps(support, sort_keys=True).encode()
        (root / 'support.json').write_bytes(raw_support)
        self.support = (binding.SupportObservation('support.json', self.finding, raw_support),)
        self.record = {'record_type':'cwo-return-adjudication','version':1,'adjudication_id':'review-1',
            'dispatch_id':self.context.dispatch_id,'return_sha256':self.observation.return_sha256,
            'candidate':self.context.candidate,'scope':self.context.scope,'task':self.context.task,
            'packet_sha256':self.context.packet_sha256,'evaluation_sha256':self.observation.evaluation_sha256,
            'finding_ids':[self.finding], 'decision':'accepted', 'rationale':'scoped fixture review',
            'adjudicator':'fixture-independent-reviewer',
            'authority':{'rule':'synthesis-input-adjudication'},
            'supporting_evidence':[{'artifact':'support.json','artifact_type':'validation-log',
                'sha256':sha(raw_support),'finding_ids':[self.finding]}]}

    def prepare(self, *, record=None, expected=None, support=None):
        return binding.prepare_adjudication(self.observation, expected or self.context,
            self.record if record is None else record, self.root,
            observed_support=self.support if support is None else support)


class BindingPreparationTests(unittest.TestCase):
    def setUp(self):
        self.home = self.enterContext(current_policy())
        self.fixture = FixtureProducer(self.home)

    def test_actual_evaluated_bytes_and_result_are_immutable(self):
        obs = self.fixture.observation
        self.assertEqual(obs.return_sha256, sha(obs.raw_return))
        self.assertEqual(obs.evaluation_sha256, sha(obs.result_bytes))
        self.assertTrue(json.loads(obs.result_bytes)['implementation_blocked'])
        with self.assertRaises(dataclasses.FrozenInstanceError):
            obs.result_bytes = b'{}'
        rendered = json.loads(obs.result_bytes)
        rendered['implementation_blocked'] = False
        self.assertTrue(json.loads(obs.result_bytes)['implementation_blocked'])

    def test_positive_resolves_only_supported_finding_and_never_production(self):
        prepared = self.fixture.prepare()
        self.assertEqual(prepared.errors, ())
        self.assertIn(self.fixture.finding, prepared.resolved_findings)
        self.assertEqual(set(prepared.remaining_holds),
                         set(self.fixture.result['hold_reasons']) - {self.fixture.finding})
        for adapter in (binding.synthesis_preparation, binding.status_preparation):
            result = adapter(prepared, self.fixture.context)
            self.assertTrue(result['inert_valid'])
            self.assertEqual(result['context'], dataclasses.asdict(self.fixture.context))
            self.assertEqual(result['return_sha256'], self.fixture.observation.return_sha256)
            self.assertFalse(result['production_ready'])
            self.assertFalse(result['accepted_for_use'])
            self.assertTrue(result['implementation_blocked'])
        # Meaningful fake consumer control: inert capability is reachable, while
        # the identical result still cannot reach a production effect.
        inert, production = mock.Mock(), mock.Mock()
        result = binding.synthesis_preparation(prepared, self.fixture.context)
        if result['inert_valid']:inert()
        if result['production_ready']:production()
        inert.assert_called_once();production.assert_not_called()

    def assert_refused(self, prepared):
        self.assertFalse(prepared.inert_valid)
        self.assertTrue(prepared.errors)
        self.assertEqual(prepared.resolved_findings, ())
        self.assertEqual(prepared.remaining_holds, tuple(self.fixture.result['hold_reasons']))
        self.assertEqual(binding.synthesis_preparation(prepared, self.fixture.context), binding.status_preparation(prepared, self.fixture.context))

    def test_equivalent_json_and_self_hashes_without_observed_source_cannot_clear(self):
        record = json.loads(json.dumps(self.fixture.record))
        record['source_qualified'] = True
        record['trusted_host_authority'] = True
        self.assert_refused(self.fixture.prepare(record=record, support=()))

    def test_every_binding_dimension_and_actual_evaluation_hold_set(self):
        for field in ('dispatch_id','return_sha256','candidate','scope','task','packet_sha256','evaluation_sha256'):
            record = json.loads(json.dumps(self.fixture.record))
            record[field] = 'b' * 64 if 'sha256' in field else 'another'
            with self.subTest(field=field):self.assert_refused(self.fixture.prepare(record=record))
        self.assert_refused(self.fixture.prepare(expected=dataclasses.replace(self.fixture.context, candidate='new')))

    def test_missing_malformed_changed_duplicate_and_contradictory_support(self):
        path = self.home / 'support.json';original = path.read_bytes()
        for raw in (b'', b'{', b'{"x":1,"x":2}', b'{"x":NaN}', b'other task with the same finding words'):
            with self.subTest(raw=raw):
                path.write_bytes(raw)
                self.assert_refused(self.fixture.prepare())
        path.write_bytes(original);path.unlink()
        self.assert_refused(self.fixture.prepare())
        path.write_bytes(original)
        self.assert_refused(self.fixture.prepare(support=self.fixture.support * 2))
        record = json.loads(json.dumps(self.fixture.record))
        record['supporting_evidence'] *= 2
        self.assert_refused(self.fixture.prepare(record=record))
        value = json.loads(original);value['resolution'] = 'still-applicable'
        raw = json.dumps(value).encode();path.write_bytes(raw)
        record = json.loads(json.dumps(self.fixture.record));record['supporting_evidence'][0]['sha256'] = sha(raw)
        self.assert_refused(self.fixture.prepare(record=record,
            support=(binding.SupportObservation('support.json', self.fixture.finding, raw),)))

    def test_unrelated_but_self_consistent_evidence_cannot_cover_this_task(self):
        value = json.loads(self.fixture.support[0].raw);value['context']['task'] = 'unrelated-task'
        raw = json.dumps(value).encode();(self.home / 'support.json').write_bytes(raw)
        record = json.loads(json.dumps(self.fixture.record));record['supporting_evidence'][0]['sha256'] = sha(raw)
        self.assert_refused(self.fixture.prepare(record=record,
            support=(binding.SupportObservation('support.json', self.fixture.finding, raw),)))

    def test_reader_bounds_symlinks_and_unreadable_fail_closed(self):
        for name in ('../support.json', str(self.home/'support.json')):
            with self.assertRaises(ValueError):binding.read_support(self.home, name)
        (self.home / 'linked.json').symlink_to(self.home / 'support.json')
        with self.assertRaises(OSError):binding.read_support(self.home, 'linked.json')
        with mock.patch.object(binding, 'MAX_SUPPORT_BYTES', 2):
            with self.assertRaises(ValueError):binding.read_support(self.home, 'support.json')
        with mock.patch.object(binding.os, 'open', side_effect=PermissionError('unreadable')):
            self.assert_refused(self.fixture.prepare())


    def test_snapshot_decision_does_not_reopen_support_and_policy_drift_refuses(self):
        prepared = self.fixture.prepare()
        (self.home / 'support.json').write_bytes(b'changed after immutable snapshot')
        with mock.patch.object(binding, 'read_support', side_effect=AssertionError('reopened')):
            self.assertTrue(binding.synthesis_preparation(prepared, self.fixture.context)['inert_valid'])
        path = self.home / 'policy/synthesis-policy.yaml';document=json.loads(path.read_bytes())
        document['default_pattern'] = 'changed';path.write_text(json.dumps(document))
        self.assert_refused(self.fixture.prepare())

class AdditionalBindingTests(unittest.TestCase):
    setUp = BindingPreparationTests.setUp
    assert_refused = BindingPreparationTests.assert_refused
    def test_stale_consuming_context_and_policy_restore_all_holds(self):
        prepared = self.fixture.prepare()
        wrong = dataclasses.replace(self.fixture.context, task='another-task')
        result = binding.synthesis_preparation(prepared, wrong)
        self.assertFalse(result['inert_valid'])
        self.assertEqual(result['resolved_findings'], [])
        self.assertEqual(set(result['remaining_holds']), set(self.fixture.result['hold_reasons']))
        path = self.home / 'policy/synthesis-policy.yaml';document=json.loads(path.read_bytes())
        document['default_pattern'] = 'changed';path.write_text(json.dumps(document))
        self.assertFalse(binding.synthesis_preparation(prepared, self.fixture.context)['inert_valid'])

    def test_restrictive_decision_is_not_erased_by_serialization(self):
        for decision in ('rejected', 'quarantined'):
            record = json.loads(json.dumps(self.fixture.record));record['decision'] = decision
            prepared = self.fixture.prepare(record=record)
            self.assertEqual(prepared.resolved_findings, ())
            result = binding.synthesis_preparation(prepared, self.fixture.context)
            self.assertEqual(result['decision'], decision)
            self.assertTrue(result['implementation_blocked'])
            self.assertFalse(result['production_ready'])

    def test_malformed_observed_support_reaches_strict_parser(self):
        for raw in (b'{', b'{"x":1,"x":2}', b'{"x":NaN}'):
            record = json.loads(json.dumps(self.fixture.record))
            record['supporting_evidence'][0]['sha256'] = sha(raw)
            (self.home/'support.json').write_bytes(raw)
            self.assert_refused(self.fixture.prepare(record=record,
                support=(binding.SupportObservation('support.json', self.fixture.finding, raw),)))


    def test_external_record_change_cannot_swap_support_after_normalization(self):
        fixture = self.fixture
        other = 'return-tripwire:unrelated'
        value = json.loads(fixture.support[0].raw)
        value['finding_id'] = other
        raw = json.dumps(value).encode()
        (self.home / 'support.json').write_bytes(raw)
        fixture.record['supporting_evidence'][0]['sha256'] = sha(raw)
        observed = (binding.SupportObservation('support.json', other, raw),)
        original = binding._normalized

        def interleave(observation, local_record):
            normalized = original(observation, local_record)
            fixture.record['supporting_evidence'][0]['finding_ids'] = [other]
            return normalized

        with mock.patch.object(binding, '_normalized', side_effect=interleave):
            prepared = binding.prepare_adjudication(fixture.observation, fixture.context,
                fixture.record, self.home, observed_support=observed)
        self.assert_refused(prepared)
