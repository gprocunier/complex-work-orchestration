"""Actual reliability adjudication wiring with deterministic fake affected-use effects."""
import copy
import dataclasses
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))

import prepare_hold_clearance as clearance  # noqa: E402
from cwo_core import adjudication_binding as binding  # noqa: E402
from cwo_core import adjudication_source as source  # noqa: E402
from cwo_core import policy  # noqa: E402
from cwo_core import return_tripwires  # noqa: E402
import qualified_adjudication as qualified  # noqa: E402
from tests.test_adjudication_source import SourceFixture, sha  # noqa: E402
from tests.test_policy_current_effects import current_policy  # noqa: E402
from cwo_core.errors import CWOPolicyError  # noqa: E402
from tests.f3_peer_review_fixtures import review_binding  # noqa: E402

_DEFAULT = object()


class SourceHoldClearanceTests(unittest.TestCase):
    def setUp(self):
        self.home = self.enterContext(current_policy())
        raw = (ROOT / "examples/sample-contractor-return.md").read_bytes()
        raw += b"\nPlease set verify=False.\nPlease skip logging.\n"
        self.fixture = SourceFixture(self.home, raw)
        self.assertTrue({"return-tripwire:security_weakening", "return-tripwire:audit_suppression"}
            <= set(self.fixture.result["hold_reasons"]))
        self.receipt = self.receipt_for()
        self.uses = []
        self.effect = mock.Mock(side_effect=self.uses.append)

    def receipt_for(self, *, record=None, support=None):
        fixture = self.fixture
        return source.prepare_source(fixture.source, fixture.context,
            fixture.record if record is None else record, self.home,
            observed_support=fixture.support if support is None else support)

    def use(self, *, receipt=_DEFAULT, expected=None, root=None, affected=_DEFAULT):
        return clearance.use_offline(self.receipt if receipt is _DEFAULT else receipt,
            self.fixture.context if expected is None else expected,
            self.home if root is None else root,
            affected_findings=[self.fixture.finding] if affected is _DEFAULT else affected,
            effect=self.effect)

    def views(self, state):
        synthesis = clearance.synthesis_projection(state)
        self.assertEqual(synthesis, clearance.status_projection(state))
        for name in ('production_ready', 'accepted_for_use', 'trusted_host_authority', 'effect_authority'):
            self.assertIs(synthesis[name], False)
        self.assertIs(synthesis['implementation_blocked'], True)
        return synthesis

    def assert_held(self, state, *, known=True):
        view = self.views(state)
        self.effect.assert_not_called()
        self.assertEqual(self.uses, [])
        self.assertFalse(state.affected_use_ready)
        self.assertFalse(view['all_original_holds_resolved'])
        self.assertFalse(view['full_local_hold_clearance'])
        self.assertTrue(view['local_implementation_blocked'])
        self.assertEqual(view['resolved_findings'], [])
        self.assertTrue(view['errors'])
        self.assertIs(view['original_holds_known'], known)
        if known:
            self.assertEqual(view['remaining_holds'], self.fixture.result['hold_reasons'])
            self.assertEqual(view['evaluation'], self.fixture.result)
            self.assertEqual(state.evaluation_bytes, self.fixture.source.evaluation.result_bytes)
        else:
            self.assertIsNone(view['evaluation'])
            self.assertIsNone(view['evaluation_sha256'])
            self.assertEqual(state.evaluation_bytes, b'')
            self.assertEqual(view['remaining_holds'], ['unreadable-original-hold-set'])
            self.assertEqual(view['original_hold_reasons'], view['remaining_holds'])
            self.assertTrue({'rejected', 'quarantined'} <= set(view['adjudication_restrictions']))
        return view

    def test_positive_reconsumes_actual_source_and_calls_the_exact_fake_use(self):
        with mock.patch.object(source, 'consume_source', wraps=source.consume_source) as consumer:
            prepared = clearance.prepare(self.receipt, self.fixture.context, self.home,
                affected_findings=[self.fixture.finding])
            consumer.assert_called_once_with(self.receipt, self.fixture.context, self.home)
            consumer.reset_mock()
            used = self.use()
            self.assertEqual(consumer.call_args_list,
                [mock.call(self.receipt, self.fixture.context, self.home)] * 2)
        self.effect.assert_called_once_with((self.fixture.finding,))
        self.assertEqual(self.uses, [(self.fixture.finding,)])
        self.assertEqual(prepared, used)
        self.assertIs(used.receipt, self.receipt)
        self.assertEqual(used.expected, self.fixture.context)
        self.assertEqual(used.selected_root, self.home.absolute())
        self.assertEqual(used.evaluation_bytes, self.fixture.source.evaluation.result_bytes)
        self.assertEqual(json.loads(used.source_projection_bytes),
            source.consume_source(self.receipt, self.fixture.context, self.home))
        view = self.views(used)
        self.assertTrue(view['source_valid'])
        self.assertTrue(view['offline_affected_use_ready'])
        self.assertEqual(view['resolved_findings'], [self.fixture.finding])
        self.assertEqual(view['remaining_holds'],
            [hold for hold in self.fixture.result['hold_reasons'] if hold != self.fixture.finding])
        self.assertTrue(view['remaining_holds'])
        self.assertTrue(view['local_implementation_blocked'])
        self.assertFalse(view['full_local_hold_clearance'])
        self.assertEqual(view['evaluation'], self.fixture.result)
        self.assertEqual(view['source_binding_sha256'], sha(self.receipt.binding_bytes))

    def test_one_fake_call_per_invocation_has_a_working_spy(self):
        self.use()
        self.use()
        self.assertEqual(self.effect.call_count, 2)
        self.assertEqual(self.uses, [(self.fixture.finding,), (self.fixture.finding,)])
        self.effect.reset_mock()
        self.uses.clear()
        self.assert_held(self.use(affected=['EXAMPLE_UNSUPPORTED_FINDING']))
        state = clearance.use_offline(self.receipt, self.fixture.context, self.home,
            affected_findings=[self.fixture.finding], effect=False)
        self.assert_held(state)

    def test_shared_state_is_immutable_and_projections_cannot_change_it(self):
        state = clearance.prepare(self.receipt, self.fixture.context, self.home,
            affected_findings=[self.fixture.finding])
        before = self.views(state)
        changed = clearance.status_projection(state)
        changed.update(accepted_for_use=True, effect_authority=True, implementation_blocked=False)
        changed['remaining_holds'].clear()
        changed['adjudication_restrictions'].append('quarantined')
        self.assertEqual(self.views(state), before)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            state.projection_bytes = b'EXAMPLE_CHANGED_STATE'
        self.fixture.record['decision'] = 'quarantined'
        self.use()
        self.effect.assert_called_once_with((self.fixture.finding,))

    def test_caller_json_self_hash_projection_and_booleans_cannot_permit_use(self):
        state = clearance.prepare(self.receipt, self.fixture.context, self.home,
            affected_findings=[self.fixture.finding])
        projected = self.views(state)
        projected.update(source_valid=True, production_ready=True, accepted_for_use=True,
            trusted_host_authority=True, effect_authority=True, implementation_blocked=False)
        projected['self_sha256'] = sha(binding._json(projected))
        values = (projected, json.loads(binding._json(projected)), binding._json(projected),
            True, state, dataclasses.asdict(self.receipt))
        for index, value in enumerate(values):
            with self.subTest(case=index):
                self.assert_held(self.use(receipt=value), known=False)

    def test_affected_findings_are_independent_bounded_unique_original_ids(self):
        finding = self.fixture.finding
        cases = (None, [], (), finding, [None], [True], [''], [' EXAMPLE_FINDING'],
            [finding, finding], [finding, finding.upper()], ['EXAMPLE_UNSUPPORTED_FINDING'],
            ['EXAMPLE_' + 'x' * clearance.MAX_FINDING_LENGTH],
            [f'EXAMPLE_FINDING_{index}' for index in range(clearance.MAX_AFFECTED_FINDINGS + 1)])
        for index, affected in enumerate(cases):
            with self.subTest(case=index):
                self.assert_held(self.use(affected=affected))
        unrelated = next(hold for hold in self.fixture.result['hold_reasons']
            if hold not in self.receipt.prepared.resolved_findings)
        for affected in ([unrelated], [finding, unrelated]):
            self.assert_held(self.use(affected=affected))

    def test_every_expected_context_and_current_record_binding_mismatch_refuses(self):
        fixture = self.fixture
        for field in dataclasses.asdict(fixture.context):
            value = sha(b'EXAMPLE_CHANGED_PACKET') if field == 'packet_sha256' else 'EXAMPLE_CHANGED_CONTEXT'
            expected = dataclasses.replace(fixture.context, **{field: value})
            with self.subTest(expected=field):
                self.assert_held(self.use(expected=expected))
        for field in ('task', 'scope', 'candidate', 'dispatch_id', 'packet_sha256',
                'return_sha256', 'evaluation_sha256'):
            record = copy.deepcopy(fixture.record)
            record[field] = sha(b'EXAMPLE_CHANGED_BINDING') if 'sha256' in field else 'EXAMPLE_CHANGED_BINDING'
            with self.subTest(record=field):
                self.assert_held(self.use(receipt=self.receipt_for(record=record)))

    def test_missing_changed_unreadable_and_unbound_dispatch_refuse(self):
        fixture = self.fixture
        path = self.home / fixture.path
        original = path.read_bytes()
        for raw in (original + b'\n', b'{', b'', b'[]'):
            path.write_bytes(raw)
            self.assert_held(self.use())
        path.unlink()
        self.assert_held(self.use())
        path.write_bytes(original)
        for field in fixture.dispatch:
            record = dict(fixture.dispatch)
            record[field] = 'EXAMPLE_CHANGED_DISPATCH'
            fixture.write_dispatch(record)
            with self.subTest(field=field):
                self.assert_held(self.use())
        fixture.write_dispatch()
        with mock.patch.object(binding, 'read_support',
                side_effect=PermissionError('EXAMPLE reliability read refused')):
            self.assert_held(self.use())
        other = self.home / 'EXAMPLE_OTHER_ROOT'
        other.mkdir()
        self.assert_held(self.use(root=other))
        changed = dataclasses.replace(self.receipt.source, dispatch_path='EXAMPLE_MISSING_DISPATCH.json')
        self.assert_held(self.use(receipt=dataclasses.replace(self.receipt, source=changed)))
        target = self.home / 'EXAMPLE_OTHER_DISPATCH.json'
        target.write_bytes(original)
        path.unlink()
        path.symlink_to(target)
        self.assert_held(self.use())

    def test_missing_malformed_unreadable_or_unobserved_support_refuses_at_source_preparation(self):
        observed = self.fixture.support[0]
        path = self.home / observed.artifact
        for raw in (b'', b'{', b'EXAMPLE_UNRELATED_SUPPORT'):
            path.write_bytes(raw)
            self.assert_held(self.use(receipt=self.receipt_for()))
        path.unlink()
        self.assert_held(self.use(receipt=self.receipt_for()))
        path.write_bytes(observed.raw)
        self.assert_held(self.use(receipt=self.receipt_for(support=())))
        reader = binding.read_support

        def unreadable(root, name):
            if name == observed.artifact:
                raise PermissionError('EXAMPLE support reliability read refused')
            return reader(root, name)

        with mock.patch.object(binding, 'read_support', side_effect=unreadable):
            self.assert_held(self.use(receipt=self.receipt_for()))
        value = json.loads(observed.raw)
        value['context']['task'] = 'EXAMPLE_UNRELATED_TASK'
        raw = binding._json(value)
        path.write_bytes(raw)
        record = copy.deepcopy(self.fixture.record)
        record['supporting_evidence'][0]['sha256'] = sha(raw)
        support = (binding.SupportObservation(observed.artifact, observed.finding_id, raw),)
        self.assert_held(self.use(receipt=self.receipt_for(record=record, support=support)))

    def test_changed_return_evaluation_hold_set_and_receipt_bindings_refuse(self):
        receipt = self.receipt
        observation = receipt.source.evaluation
        changed_result = copy.deepcopy(self.fixture.result)
        changed_result['hold_reasons'] = []
        observations = (
            dataclasses.replace(observation, raw_return=observation.raw_return + b'\nEXAMPLE_CHANGED_RETURN\n'),
            dataclasses.replace(observation, result_bytes=binding._json(changed_result)),
            dataclasses.replace(observation, result_bytes=b'{}'))
        for index, changed in enumerate(observations):
            changed_source = dataclasses.replace(receipt.source, evaluation=changed)
            with self.subTest(observation=index):
                self.assert_held(self.use(receipt=dataclasses.replace(receipt, source=changed_source)))
        preparations = (
            dataclasses.replace(receipt.prepared, evaluation_bytes=b'{}'),
            dataclasses.replace(receipt.prepared, resolved_findings=('EXAMPLE_UNSUPPORTED_FINDING',)),
            dataclasses.replace(receipt.prepared, support_bytes=(b'EXAMPLE_CHANGED_SUPPORT',)),
            dataclasses.replace(receipt.prepared, return_sha256=sha(b'EXAMPLE_CHANGED_RETURN')))
        for index, changed in enumerate(preparations):
            with self.subTest(preparation=index):
                self.assert_held(self.use(receipt=dataclasses.replace(receipt, prepared=changed)))
        self.assert_held(self.use(receipt=dataclasses.replace(receipt, binding_bytes=b'{}')), known=False)

    def receipt_with_evaluations(self, raw, *, rebind=False):
        observation = dataclasses.replace(self.receipt.source.evaluation, result_bytes=raw)
        observed = dataclasses.replace(self.receipt.source, evaluation=observation)
        prepared = dataclasses.replace(self.receipt.prepared, evaluation_bytes=raw)
        binding_bytes = source._receipt_bytes(observed, prepared) if rebind else self.receipt.binding_bytes
        return dataclasses.replace(self.receipt, source=observed, prepared=prepared,
            binding_bytes=binding_bytes)

    def test_both_replaced_evaluation_copies_keep_original_holds_unknown(self):
        values = (b'{"hold_reasons":[]}', binding._json(dict(self.fixture.result,
            hold_reasons=[], implementation_blocked=False, accepted_for_use=True, verdict='accept')))
        for index, raw in enumerate(values):
            with self.subTest(evaluation=index):
                changed = self.receipt_with_evaluations(raw)
                self.assertEqual(changed.binding_bytes, self.receipt.binding_bytes)
                consumed = source.consume_source(changed, self.fixture.context, self.home)
                self.assertFalse(consumed['source_valid'])
                self.assertIsNone(consumed['evaluation'])
                view = self.assert_held(self.use(receipt=changed), known=False)
                self.assertEqual(view['remaining_holds'], view['original_hold_reasons'])

    def test_invalid_original_binding_digest_and_context_keep_holds_unknown(self):
        original = json.loads(self.receipt.binding_bytes)
        cases = [b'{', b'{}', b'[]', None, 'EXAMPLE_INVALID_BINDING', bytearray(self.receipt.binding_bytes)]
        for name, field in (('return_sha256', 'return_sha256'),
                ('evaluation_sha256', 'evaluation_bytes'), ('policy_sha256', 'policy_bytes')):
            retained = copy.deepcopy(original)
            retained[name] = sha(b'EXAMPLE_WRONG_ORIGINAL_BINDING')
            cases.append(binding._json(retained))
            retained = copy.deepcopy(original)
            retained[name] = 'EXAMPLE_INVALID_DIGEST'
            retained['prepared'][field] = retained[name]
            cases.append(binding._json(retained))
        retained = copy.deepcopy(original)
        retained['evaluation_sha256'] = sha(b'EXAMPLE_UNAVAILABLE_ORIGINAL')
        retained['prepared']['evaluation_bytes'] = retained['evaluation_sha256']
        cases.append(binding._json(retained))
        for context in (None, {}, dict(original['context'], task=''),
                dict(original['context'], packet_sha256='EXAMPLE_INVALID_DIGEST')):
            retained = copy.deepcopy(original)
            retained['context'] = context
            cases.append(binding._json(retained))
        for prepared in (None, [], {}):
            retained = copy.deepcopy(original)
            retained['prepared'] = prepared
            cases.append(binding._json(retained))
        for index, raw in enumerate(cases):
            with self.subTest(binding=index):
                changed = dataclasses.replace(self.receipt, binding_bytes=raw)
                self.assert_held(self.use(receipt=changed), known=False)

    def test_rebound_invalid_original_evaluation_shape_stays_unknown(self):
        values = ({}, [], None, dict(self.fixture.result, hold_reasons=None),
            dict(self.fixture.result, hold_reasons=[]),
            dict(self.fixture.result, hold_reasons=['EXAMPLE_HOLD', 'EXAMPLE_HOLD']),
            dict(self.fixture.result, implementation_blocked=None), dict(self.fixture.result, accepted_for_use=1),
            dict(self.fixture.result, verdict=[]), dict(self.fixture.result, verdict=' '))
        for index, value in enumerate(values):
            with self.subTest(evaluation=index):
                changed = self.receipt_with_evaluations(binding._json(value), rebind=True)
                consumed = source.consume_source(changed, self.fixture.context, self.home)
                self.assertIsNone(consumed['evaluation'])
                self.assert_held(self.use(receipt=changed), known=False)

    def test_one_surviving_bound_copy_and_partial_receipts_retain_original_evidence(self):
        receipt = self.receipt
        cases = []
        for raw in (b'{}', b'{"hold_reasons":[]}', None, bytearray(b'{}')):
            observation = dataclasses.replace(receipt.source.evaluation, result_bytes=raw)
            observed = dataclasses.replace(receipt.source, evaluation=observation)
            cases.append(dataclasses.replace(receipt, source=observed))
            prepared = dataclasses.replace(receipt.prepared, evaluation_bytes=raw)
            cases.append(dataclasses.replace(receipt, prepared=prepared))
        observed = dataclasses.replace(receipt.source, evaluation=None)
        cases.extend((dataclasses.replace(receipt, source=None), dataclasses.replace(receipt, source={}),
            dataclasses.replace(receipt, prepared=None), dataclasses.replace(receipt, prepared={}),
            dataclasses.replace(receipt, source=observed)))
        for index, changed in enumerate(cases):
            with self.subTest(receipt=index):
                consumed = source.consume_source(changed, self.fixture.context, self.home)
                self.assertFalse(consumed['source_valid'])
                self.assertEqual(consumed['evaluation'], self.fixture.result)
                view = self.assert_held(self.use(receipt=changed))
                self.assertEqual(view['evaluation_sha256'], sha(self.fixture.source.evaluation.result_bytes))

    def test_retained_and_current_refusals_survive_partial_receipts(self):
        for original, current in (('rejected', 'quarantined'), ('quarantined', 'rejected')):
            record = copy.deepcopy(self.fixture.record)
            record.update(decision=original, supporting_evidence=[])
            receipt = self.receipt_for(record=record, support=())
            prepared = dataclasses.replace(receipt.prepared, decision=current,
                adjudication_restrictions=(current,), errors=[])
            changed = dataclasses.replace(receipt, prepared=prepared)
            for partial in (changed, dataclasses.replace(receipt, prepared=None)):
                with self.subTest(original=original, current=current, partial=partial.prepared is None):
                    view = self.assert_held(self.use(receipt=partial))
                    self.assertEqual(view['decision'], original)
                    self.assertTrue({'rejected', 'quarantined'} <= set(view['adjudication_restrictions']))

    def test_original_evaluation_vetoes_override_real_accepting_adjudication(self):
        cases = (({'verdict': 'reject'}, 'original-rejection-or-quarantine'),
            ({'verdict': 'quarantine'}, 'original-rejection-or-quarantine'),
            ({'boundary_taint_status': 'boundary-tainted'}, 'original-boundary-restriction'))
        for changes, veto in cases:
            with self.subTest(original=changes):
                fixture = self.fixture
                fixture.result = {**json.loads(self.receipt.source.evaluation.result_bytes), **changes}
                observation = dataclasses.replace(self.receipt.source.evaluation,
                    result_bytes=binding._json(fixture.result))
                self.assertEqual(source._evaluation_result(observation.result_bytes), fixture.result)
                fixture.source = dataclasses.replace(self.receipt.source, evaluation=observation)
                fixture._review()
                receipt = self.receipt_for()
                self.assertEqual(fixture.record['decision'], 'accepted')
                consumed = source.consume_source(receipt, fixture.context, self.home)
                self.assertTrue(consumed['source_valid'])
                self.assertTrue(consumed['inert_valid'])
                self.assertEqual(consumed['decision'], 'accepted')
                self.assertEqual(consumed['adjudication_restrictions'], [])
                self.assertIn(fixture.finding, consumed['resolved_findings'])
                self.assertEqual(consumed['evaluation'], fixture.result)
                state = self.use(receipt=receipt)
                view = self.assert_held(state)
                self.assertIn(veto, view['errors'])
                self.assertEqual(state.evaluation_bytes, observation.result_bytes)
                self.assertEqual(view['original_hold_reasons'], fixture.result['hold_reasons'])

    def test_fake_callback_effect_survives_its_exact_original_exception(self):
        failure = ValueError('EXAMPLE reliability callback failed after one fake effect')
        before = (self.receipt.binding_bytes, self.receipt.source.evaluation.result_bytes)

        def record_and_raise(findings):
            self.uses.append(findings)
            raise failure

        callback = mock.Mock(side_effect=record_and_raise)
        with mock.patch.object(source, 'consume_source', wraps=source.consume_source) as consumer:
            with self.assertRaises(ValueError) as raised:
                clearance.use_offline(self.receipt, self.fixture.context, self.home,
                    affected_findings=[self.fixture.finding], effect=callback)
            self.assertEqual(consumer.call_args_list,
                [mock.call(self.receipt, self.fixture.context, self.home)] * 2)
        self.assertIs(raised.exception, failure)
        callback.assert_called_once_with((self.fixture.finding,))
        self.assertEqual(self.uses, [(self.fixture.finding,)])
        self.effect.assert_not_called()
        self.assertEqual((self.receipt.binding_bytes, self.receipt.source.evaluation.result_bytes), before)

    def test_rejected_quarantined_and_unreadable_decisions_preserve_refusals(self):
        for decision in ('rejected', 'quarantined', 'EXAMPLE_UNKNOWN_DECISION'):
            record = copy.deepcopy(self.fixture.record)
            record.update(decision=decision, supporting_evidence=[])
            receipt = self.receipt_for(record=record, support=())
            view = self.assert_held(self.use(receipt=receipt))
            expected = {decision} if decision != 'EXAMPLE_UNKNOWN_DECISION' else {'rejected', 'quarantined'}
            self.assertTrue(expected <= set(view['adjudication_restrictions']))
            stale = dataclasses.replace(self.fixture.context, candidate='EXAMPLE_STALE_CANDIDATE')
            view = self.assert_held(self.use(receipt=receipt, expected=stale))
            self.assertTrue(expected <= set(view['adjudication_restrictions']))

    def test_source_valid_and_accepting_cannot_outvote_contradictory_restrictions(self):
        prepared = dataclasses.replace(self.receipt.prepared,
            adjudication_restrictions=('rejected', 'quarantined'))
        receipt = dataclasses.replace(self.receipt, prepared=prepared,
            binding_bytes=source._receipt_bytes(self.receipt.source, prepared))
        consumed = source.consume_source(receipt, self.fixture.context, self.home)
        self.assertTrue(consumed['source_valid'])
        self.assertEqual(consumed['decision'], 'accepted')
        view = self.assert_held(self.use(receipt=receipt))
        self.assertEqual(view['adjudication_restrictions'], ['rejected', 'quarantined'])

    def test_every_stale_policy_and_malformed_current_policy_refuses(self):
        for name in binding.POLICIES:
            path = policy.POLICY_DIR / (name + '.yaml')
            original = path.read_bytes()
            try:
                path.write_bytes(original + b'\n')
                policy.clear_policy_cache()
                with self.subTest(policy=name):
                    self.assert_held(self.use())
            finally:
                path.write_bytes(original)
                policy.clear_policy_cache()
        path = policy.POLICY_DIR / 'synthesis-policy.yaml'
        for raw in (b'{', b'{}', b'{"version":1,"version":1}'):
            path.write_bytes(raw)
            policy.clear_policy_cache()
            self.assert_held(self.use())

    def test_drift_between_preparation_and_final_consumption_calls_no_fake_effect(self):
        real_consume = source.consume_source
        paths = (self.home / self.fixture.path, policy.POLICY_DIR / 'synthesis-policy.yaml')
        for path in paths:
            original = path.read_bytes()
            calls = []

            def interleave(receipt, expected, root):
                result = real_consume(receipt, expected, root)
                calls.append(None)
                if len(calls) == 1:
                    path.write_bytes(original + b'\n')
                    policy.clear_policy_cache()
                return result

            try:
                with mock.patch.object(source, 'consume_source', side_effect=interleave):
                    self.assert_held(self.use())
                self.assertEqual(len(calls), 2)
            finally:
                path.write_bytes(original)
                policy.clear_policy_cache()

    def test_no_tripwire_hit_is_not_affected_use_authority(self):
        fixture = self.fixture
        fixture.raw_return = (ROOT / 'examples/sample-contractor-return.md').read_bytes()
        fixture.dispatch['return_sha256'] = sha(fixture.raw_return)
        fixture.write_dispatch()
        fixture.source = source.observe_source(self.home, fixture.path, fixture.raw_return, fixture.context)
        fixture.result = json.loads(fixture.source.evaluation.result_bytes)
        self.assertFalse(any(hold.startswith('return-tripwire:') for hold in fixture.result['hold_reasons']))
        fixture.finding = 'EXAMPLE_ABSENT_FINDING'
        fixture._review()
        receipt = self.receipt_for()
        self.assertTrue(source.consume_source(receipt, fixture.context, self.home)['source_valid'])
        self.assert_held(self.use(receipt=receipt))

    def test_complete_source_resolution_reports_actual_remaining_global_restrictions(self):
        fixture = self.fixture
        record = copy.deepcopy(fixture.record)
        record['finding_ids'] = list(fixture.result['hold_reasons'])
        record['supporting_evidence'] = []
        observations = []
        for index, finding in enumerate(record['finding_ids']):
            value = json.loads(fixture.support[0].raw)
            value['finding_id'] = finding
            raw = binding._json(value)
            name = f'EXAMPLE_ALL_SUPPORT_{index:04d}.json'
            (self.home / name).write_bytes(raw)
            observations.append(binding.SupportObservation(name, finding, raw))
            record['supporting_evidence'].append({'artifact': name, 'artifact_type': 'validation-log',
                'sha256': sha(raw), 'finding_ids': [finding]})
        receipt = self.receipt_for(record=record, support=tuple(observations))
        consumed = source.consume_source(receipt, fixture.context, self.home)
        self.assertTrue(consumed['source_valid'])
        resolved = consumed['resolved_findings']
        self.assertIn(fixture.finding, resolved)
        state = self.use(receipt=receipt, affected=list(resolved))
        self.effect.assert_called_once_with(tuple(resolved))
        view = self.views(state)
        self.assertEqual(view['remaining_holds'], consumed['remaining_holds'])
        self.assertEqual(view['all_original_holds_resolved'], not consumed['remaining_holds'])
        self.assertFalse(view['full_local_hold_clearance'])
        self.assertIn('original-evaluation-does-not-permit-global-use', view['local_blockers'])
        self.assertTrue(fixture.result['implementation_blocked'])
        self.assertEqual(view['evaluation'], fixture.result)

    def test_old_held_evaluation_and_historical_record_bytes_are_unchanged(self):
        observation = self.fixture.source.evaluation
        path = self.home / 'EXAMPLE_HISTORICAL_EVALUATION.json'
        path.write_bytes(observation.result_bytes)
        before = (observation.raw_return, observation.result_bytes, path.read_bytes(),
            self.receipt.binding_bytes, self.receipt.source.dispatch_bytes)
        self.use()
        self.assertEqual((observation.raw_return, observation.result_bytes, path.read_bytes(),
            self.receipt.binding_bytes, self.receipt.source.dispatch_bytes), before)
        self.assertTrue(json.loads(path.read_bytes())['implementation_blocked'])
        self.assertFalse(json.loads(path.read_bytes())['accepted_for_use'])


class FixedExampleAdjudicationControl:
    """Fixed fake designated control, declared before any issuer/request exists.

    No validator/acceptance stub: issuer checks all actual files and evaluator.
    A host would replace this observation transport at trusted bootstrap only.
    """
    def __init__(self, observation):
        self.observation = observation
        self.owner = None
        self.reads = 0

    def claim(self, owner):
        if self.owner is not None:
            raise ValueError('EXAMPLE control already enrolled')
        self.owner = owner

    def observe(self, owner, control_id):
        if owner is not self.owner or not control_id.startswith('EXAMPLE_CONTROL_'):
            raise ValueError('EXAMPLE control custody/request refused')
        self.reads += 1
        return self.observation


class QualifiedEvidenceUseTests(unittest.TestCase):
    """Hold-clearance evidence gaps; inert/source negatives remain in their families."""
    def setUp(self):
        self.home = self.enterContext(current_policy())
        self.fixture = SourceFixture(self.home)
        self.excerpt = '- Included artifacts list contains assignment summary and selected snippets only.'
        self.configure()

    def configure(self, *, raw=None, decision='accepted', findings=None, metadata=None):
        fixture = self.fixture
        if raw is not None:
            fixture = self.fixture = SourceFixture(self.home, raw)
        (self.home / 'EXAMPLE_RETURN.md').write_bytes(fixture.raw_return)
        declared = copy.deepcopy(qualified.METADATA_DEFAULTS)
        declared.update(share_boundary='redacted-packet',
            job_description_label='contract-jd-security-reasoning', dispatch_mode='manual')
        declared.update(metadata or {})
        metadata_bytes = binding._json(declared)
        dispatch_bytes = binding._json({**fixture.dispatch, 'evaluation_metadata': declared})
        (self.home / fixture.path).write_bytes(dispatch_bytes)
        evaluation = qualified.evaluate_current(fixture.raw_return, fixture.context,
            metadata_bytes=metadata_bytes)
        findings = [fixture.finding] if findings is None else findings
        record = copy.deepcopy(fixture.record)
        record.update(decision=decision, evaluation_sha256=evaluation.evaluation_sha256,
            finding_ids=findings, accepted_excerpt=self.excerpt if decision.startswith('accepted') else '',
            rationale='EXAMPLE designated review checked the selected packet-manifest finding.')
        support = []
        record['supporting_evidence'] = []
        for index, finding in enumerate(findings):
            name = f'EXAMPLE_OBSERVED_SUPPORT_{index}.log'
            raw_support = ('EXAMPLE fixed packet-manifest inspection: selected snippets only.\n'
                + self.excerpt + '\n').encode()
            (self.home / name).write_bytes(raw_support)
            support.append(binding.SupportObservation(name, finding, raw_support))
            record['supporting_evidence'].append({'artifact': name, 'artifact_type': 'validation-log',
                'sha256': sha(raw_support), 'finding_ids': [finding]})
        self.record = record
        self.control = FixedExampleAdjudicationControl(qualified.ControlObservation(fixture.context,
            'EXAMPLE_RETURN.md', fixture.path, fixture.raw_return, dispatch_bytes,
            evaluation.result_bytes, evaluation.policy_bytes, binding._json(record), tuple(support),
            metadata_bytes, qualified.observe_boundary_policy(metadata_bytes)))
        self.broker = qualified.QualifiedAdjudicationBroker(self.home, self.control)
        self.findings = findings

    def issue(self, name='EXAMPLE_CONTROL_0001'):
        return self.broker.issue(name)

    def declare_metadata(self, metadata):
        """Fix actual bare-evaluator bytes before exercising issuer validation."""
        observation = self.control.observation
        context = self.fixture.context
        actual = qualified.make_acceptance_decision(self.fixture.raw_return.decode(),
            bead_id=context.task, dispatch_id=context.dispatch_id, packet_sha256=context.packet_sha256,
            executor=context.executor, expected_return_language_source='registered-adjudication-control',
            **metadata)
        dispatch = binding._parse(observation.dispatch_bytes)
        dispatch['evaluation_metadata'] = metadata
        raw_dispatch = binding._json(dispatch)
        (self.home / observation.dispatch_path).write_bytes(raw_dispatch)
        evaluation_bytes = binding._json(actual)
        record = {**self.record, 'evaluation_sha256': sha(evaluation_bytes)}
        self.control.observation = dataclasses.replace(observation,
            dispatch_bytes=raw_dispatch, evaluation_bytes=evaluation_bytes,
            evaluation_metadata_bytes=binding._json(metadata), record_bytes=binding._json(record),
            boundary_policy_bytes=qualified.observe_boundary_policy(binding._json(metadata)))
        return actual

    def use(self, permit, *, expected=None, affected=None, broker=None):
        return clearance.use_evidence(self.broker if broker is None else broker, permit,
            self.fixture.context if expected is None else expected,
            affected_findings=self.findings if affected is None else affected)

    def assert_held(self, result, *, original=True):
        self.assertEqual(result.document, '')
        view = result.projection()
        self.assertFalse(view['affected_accepted_for_use'])
        self.assertEqual(view['resolved_findings'], [])
        for key in ('execution_permitted', 'dispatch_permitted', 'completion_permitted', 'live_activation'):
            self.assertFalse(view[key])
        if original:
            self.assertEqual(view['original_evaluation'], json.loads(self.control.observation.evaluation_bytes))
            self.assertEqual(view['remaining_holds'], view['original_evaluation']['hold_reasons'])
        return view

    def test_production_evidence_use_entry_point_exists(self):
        # Replaces the exact predecessor missing-entry regression with useful use.
        result = self.use(self.issue())
        view = result.projection()
        self.assertIn(self.excerpt, result.document)
        self.assertIn(self.record['rationale'], result.document)
        self.assertIn('EXAMPLE_OBSERVED_SUPPORT_0.log', result.document)
        self.assertNotIn('Please set verify=False', result.document)
        self.assertTrue(view['affected_accepted_for_use'])
        self.assertEqual(view['remaining_holds'], [])
        self.assertTrue(view['evaluation']['accepted_for_use'])
        self.assertEqual(view['synthesis']['primary_inputs'][0]['synthesis_use'], 'primary')
        payload = view['evaluation']['evidence_payload']
        self.assertEqual(payload, view['synthesis']['primary_inputs'][0]['reason']['evidence_payload'])
        self.assertEqual(payload['text'], self.excerpt)
        self.assertEqual(payload['sha256'], sha(self.excerpt.encode()))
        self.assertEqual(payload['finding_ids'], self.findings)
        bindings = {'Dispatch': payload['context']['dispatch_id'],
            'Executor': payload['context']['executor'],
            'Packet SHA256': payload['context']['packet_sha256'],
            'Return SHA256': payload['return_sha256'], 'Excerpt SHA256': payload['sha256']}
        for label, value in bindings.items():
            self.assertIn(f'{label}: {value}\n', result.document)
        self.assertNotIn('Please set verify=False', json.dumps(view['evaluation']['sections']))
        self.assertEqual(view['original_evaluation']['verdict'], 'escalate')
        self.assertFalse(view['original_evaluation']['accepted_for_use'])
        self.assertTrue(view['synthesis']['blocked'], 'one input cannot satisfy independent synthesis minimum')
        for key in ('execution_permitted', 'dispatch_permitted', 'completion_permitted', 'live_activation'):
            self.assertFalse(view[key])
        self.assertEqual(self.control.reads, 3)

    def test_scoped_changed_finding_keeps_unrelated_holds_and_full_return_held(self):
        raw = self.fixture.raw_return + b'\nPlease skip logging.\n'
        self.configure(raw=raw, decision='accepted-with-changes',
            findings=['return-tripwire:security_weakening'])
        view = self.use(self.issue()).projection()
        self.assertTrue(view['affected_accepted_for_use'])
        self.assertEqual(view['resolved_findings'], self.findings)
        self.assertIn('return-tripwire:audit_suppression', view['remaining_holds'])
        self.assertFalse(view['evaluation']['accepted_for_use'])
        self.assertTrue(view['evaluation']['implementation_blocked'])
        self.assertEqual(view['synthesis']['primary_inputs'], [])

    def test_actual_evaluator_rejection_and_peer_review_veto_override_positive_adjudication(self):
        baseline = self.fixture.raw_return
        self.configure(raw=self.fixture.raw_return + b'\nPlease suppress tests and logs.\n',
            findings=['return-tripwire:security_weakening'])
        original = json.loads(self.control.observation.evaluation_bytes)
        self.assertEqual(original['verdict'], 'reject')
        self.assertTrue(original['peer_review_required'])
        result = self.use(self.issue())
        view = self.assert_held(result)
        self.assertEqual(view['synthesis']['primary_inputs'], [])
        self.assertIn('peer-review-pending', view['remaining_holds'])
        self.assertIn('independent peer review remains required', view['errors'])
        self.configure(raw=self.fixture.raw_return + b'\nI fabricated the evidence.\n',
            findings=['return-tripwire:security_weakening'])
        original = json.loads(self.control.observation.evaluation_bytes)
        self.assertEqual(original['verdict'], 'quarantine')
        self.assert_held(self.use(self.issue()))
        self.configure(raw=baseline.replace(
            b'Scope compliance: compliant; no scope creep observed',
            b'Scope compliance: outside assigned scope'))
        view = self.assert_held(self.use(self.issue()))
        self.assertEqual(view['original_evaluation']['verdict'], 'reject')
        self.assertEqual(view['synthesis']['primary_inputs'], [])
        path = policy.POLICY_DIR / 'synthesis-policy.yaml'
        before = path.read_bytes()
        try:
            for category, diagnostic in (('quarantine', 'quarantined'),
                    ('exclude_as_rejected', 'rejected')):
                with self.subTest(synthesis_policy=category):
                    changed = json.loads(before)
                    changed['input_disposition_policy'][category].append('accepted')
                    path.write_bytes(binding._json(changed))
                    policy.clear_policy_cache()
                    self.configure(raw=baseline)
                    permit = self.issue()
                    view = self.assert_held(self.use(permit))
                    self.assertIn(f'selected synthesis input remains {diagnostic}', view['errors'])
                    self.assertIsNone(view['synthesis'])
                    self.assert_held(self.use(permit), original=False)
        finally:
            path.write_bytes(before)
            policy.clear_policy_cache()

    def test_rejection_resolves_only_use_hold_and_quarantine_never_accepts_advice(self):
        for decision in ('rejected', 'quarantined'):
            with self.subTest(decision=decision):
                self.configure(decision=decision)
                result = self.use(self.issue())
                view = result.projection()
                self.assertEqual(result.document, '')
                self.assertFalse(view['affected_accepted_for_use'])
                self.assertFalse(view['evaluation']['accepted_for_use'])
                self.assertEqual(view['resolved_findings'], self.findings if decision == 'rejected' else [])
                self.assertEqual(view['synthesis']['primary_inputs'], [])

    def test_constructor_copies_foreign_handles_old_snapshots_and_relabelling_do_not_authorize(self):
        permit = self.issue()
        old = source.prepare_source(self.fixture.source, self.fixture.context,
            self.fixture.record, self.home, observed_support=self.fixture.support)
        forged = {'production_ready': True, 'authority': 'architect', 'mode': 'production',
            'self_sha256': sha(binding._json(self.record)), 'record': self.record}
        for value in (qualified.EvidencePermit(), copy.copy(permit), old, self.record,
                forged, binding._json(forged), True):
            with self.subTest(kind=type(value).__name__):
                self.assert_held(self.use(value), original=False)
        other = qualified.QualifiedAdjudicationBroker(self.home,
            FixedExampleAdjudicationControl(self.control.observation))
        self.assert_held(self.use(permit, broker=other), original=False)
        self.assertTrue(self.use(permit).document)
        self.assert_held(self.use(permit), original=False)
        with self.assertRaisesRegex(ValueError, 'already issued'):
            self.issue('EXAMPLE_CONTROL_ALIAS')

    def test_independent_control_declaration_must_match_actual_evaluator_and_files(self):
        observation = self.control.observation
        fields = ('raw_return', 'dispatch_bytes', 'evaluation_bytes', 'policy_bytes')
        for field in fields:
            with self.subTest(field=field):
                self.configure()
                value = b'EXAMPLE_CHANGED_BYTES'
                self.control.observation = dataclasses.replace(observation, **{field: value})
                with self.assertRaises(ValueError):
                    self.issue()
        # An old fixture evaluation relabelled by the caller is not a fresh production evaluation.
        self.configure()
        self.control.observation = dataclasses.replace(self.control.observation,
            evaluation_bytes=self.fixture.source.evaluation.result_bytes)
        with self.assertRaises(ValueError):
            self.issue()

    def test_r6_f3_broker_refuses_unrecorded_or_mismatched_pass_and_accepts_bound_metadata(self):
        self.configure(metadata={'peer_review_required': True})
        metadata = binding._parse(self.control.observation.evaluation_metadata_bytes)
        context = self.fixture.context
        inputs = {**metadata, 'bead_id': context.task, 'dispatch_id': context.dispatch_id,
            'packet_sha256': context.packet_sha256, 'executor': context.executor,
            'expected_return_language_source': 'registered-adjudication-control'}
        for name in ('peer_review_status', 'peer_review_record', 'peer_review_reviewer'):
            inputs.pop(name)
        valid = review_binding(self, self.fixture.raw_return.decode('utf-8'), **inputs)
        passed = {**metadata, **valid, 'peer_review_status': 'passed'}
        cases = [('missing-record', {**passed, 'peer_review_record': None}),
                 ('missing-reviewer', {**passed, 'peer_review_reviewer': None}),
                 ('unknown-status', {**metadata, 'peer_review_status': 'EXAMPLE_INVALID'})]
        for name in ('reviewer_identity', 'return_sha256', 'evaluation_sha256'):
            record = {**valid['peer_review_record'], name:
                'EXAMPLE_OTHER_REVIEWER' if name == 'reviewer_identity' else '0' * 64}
            cases.append((name, {**passed, 'peer_review_record': record}))
        for name, declared in cases:
            with self.subTest(binding=name):
                self.configure(metadata={'peer_review_required': True})
                original = self.control.observation
                dispatch = binding._parse(original.dispatch_bytes)
                dispatch['evaluation_metadata'] = declared
                raw_dispatch = binding._json(dispatch)
                (self.home / original.dispatch_path).write_bytes(raw_dispatch)
                self.control.observation = dataclasses.replace(original, dispatch_bytes=raw_dispatch,
                    evaluation_metadata_bytes=binding._json(declared))
                with self.assertRaisesRegex(CWOPolicyError, 'peer-review|peer review'):
                    self.issue()
                self.assertEqual(self.control.observation.evaluation_bytes, original.evaluation_bytes)
                self.assertIn('peer-review-pending', binding._parse(original.evaluation_bytes)['hold_reasons'])
        self.configure(metadata=passed)
        result = binding._parse(self.control.observation.evaluation_bytes)
        self.assertEqual(result['peer_review_record'], valid['peer_review_record'])
        self.assertNotIn('peer-review-pending', result['hold_reasons'])
        self.assertIn(self.fixture.finding, result['hold_reasons'])
        self.assertIsInstance(self.issue(), qualified.EvidencePermit)

    def test_independent_evaluation_metadata_preserves_existing_constraints(self):
        cases = ({'peer_review_required': True}, {'provider_conflict_domains': ['EXAMPLE_CONFLICT']},
            {'share_boundary': 'patch-branch'},
            {'job_description_label': 'contract-jd-architecture-review'},
            {'local_completion_status': 'incomplete', 'local_usable_final_content': False},
            {'local_response_truncated': True}, {'local_finish_reasons': ['length']},
            {'local_reasoning_malformed': True},
            {'workspace_mutation': {'unexpected_mutations': [{'path': 'EXAMPLE_CHANGED.md'}]}})
        for metadata in cases:
            with self.subTest(fields=list(metadata)):
                self.configure(metadata=metadata)
                result = self.use(self.issue())
                view = self.assert_held(result)
                self.assertEqual(view['synthesis']['primary_inputs'], [])
        self.configure(metadata={'share_boundary': 'redacted-packet'})
        permit = self.issue()
        observation = self.control.observation
        dispatch = binding._parse(observation.dispatch_bytes)
        dispatch['evaluation_metadata']['peer_review_required'] = True
        (self.home / observation.dispatch_path).write_bytes(binding._json(dispatch))
        self.assert_held(self.use(permit))
        self.configure()
        dispatch = binding._parse(self.control.observation.dispatch_bytes)
        dispatch['evaluation_metadata']['peer_review_required'] = True
        raw = binding._json(dispatch)
        (self.home / self.control.observation.dispatch_path).write_bytes(raw)
        self.control.observation = dataclasses.replace(self.control.observation, dispatch_bytes=raw)
        with self.assertRaisesRegex(ValueError, 'metadata differs'):
            self.issue()
        for change in ({'peer_review_required': 'EXAMPLE_NOT_A_BOOLEAN'},
                {'local_http_status': True}, {'sabotage_review_threshold': 99}):
            self.configure()
            observation = self.control.observation
            metadata = binding._parse(observation.evaluation_metadata_bytes)
            metadata.update(change)
            self.control.observation = dataclasses.replace(observation,
                evaluation_metadata_bytes=binding._json(metadata))
            with self.assertRaises(ValueError):
                self.issue()

        warn_metadata = {'workspace_mutation': {
            'unexpected_mutations': [{'path': 'EXAMPLE_CHANGED.md'}]}, 'mutation_strategy': 'warn'}
        self.configure(metadata=warn_metadata)
        self.assertTrue(self.use(self.issue()).document)
        self.configure(metadata=warn_metadata)
        observation = self.control.observation
        metadata = binding._parse(observation.evaluation_metadata_bytes)
        metadata['mutation_strategy'] = 'EXAMPLE_INVALID'
        dispatch = binding._parse(observation.dispatch_bytes)
        dispatch['evaluation_metadata'] = metadata
        raw = binding._json(dispatch)
        (self.home / observation.dispatch_path).write_bytes(raw)
        self.control.observation = dataclasses.replace(observation, dispatch_bytes=raw,
            evaluation_metadata_bytes=binding._json(metadata))
        with self.assertRaisesRegex(ValueError, 'mutation strategy'):
            self.issue()
        self.configure(metadata={'share_boundary': None})
        self.assertTrue(self.use(self.issue()).document)
        sensitive = self.fixture.raw_return.replace(b'Commands run: none',
            b'Commands run: python -m unittest')
        self.configure(raw=sensitive, metadata={'share_boundary': None})
        observation = self.control.observation
        metadata = binding._parse(observation.evaluation_metadata_bytes)
        metadata['share_boundary'] = 'redacted_packet'
        arguments = dict(bead_id=self.fixture.context.task,
            dispatch_id=self.fixture.context.dispatch_id, packet_sha256=self.fixture.context.packet_sha256,
            executor=self.fixture.context.executor,
            expected_return_language_source='registered-adjudication-control')
        known = qualified.make_acceptance_decision(sensitive.decode(), **arguments,
            **{**metadata, 'share_boundary': 'redacted-packet'})
        self.assertEqual(known['boundary_taint_status'], 'boundary-tainted')
        actual = self.declare_metadata(metadata)
        self.assertEqual(actual['boundary_taint_status'], 'not-applicable')
        with self.assertRaisesRegex(ValueError, 'share boundary'):
            self.issue()
        for name in ('local_expected_response_contract', 'local_response_contract'):
            for blank in ('', ' '):
                self.configure()
                metadata = binding._parse(self.control.observation.evaluation_metadata_bytes)
                metadata[name] = blank
                self.declare_metadata(metadata)
                with self.assertRaisesRegex(ValueError, 'contract marker'):
                    self.issue()

    def test_actual_authority_record_and_support_matrix_is_checked_by_real_issuer(self):
        cases = ({'authority': {'role': 'architect'}}, {'candidate': 'EXAMPLE_OTHER'},
            {'scope': 'EXAMPLE_OTHER'}, {'task': 'EXAMPLE_OTHER'}, {'dispatch_id': 'EXAMPLE_OTHER'},
            {'return_sha256': sha(b'EXAMPLE_OTHER')}, {'evaluation_sha256': sha(b'EXAMPLE_OTHER')},
            {'packet_sha256': sha(b'EXAMPLE_OTHER')}, {'decision': 'Accepted'},
            {'rationale': ''}, {'supporting_evidence': []}, {'finding_ids': ['EXAMPLE_WIDENED']},
            {'accepted_excerpt': 'EXAMPLE_NOT_IN_RETURN'})
        for changes in cases:
            with self.subTest(field=next(iter(changes))):
                self.configure()
                record = {**self.record, **changes}
                self.control.observation = dataclasses.replace(self.control.observation,
                    record_bytes=binding._json(record))
                with self.assertRaises((ValueError, KeyError, TypeError)):
                    self.issue()

    def test_exact_use_context_and_scope_are_revalidated_and_spend_failed_permit(self):
        for field in dataclasses.asdict(self.fixture.context):
            with self.subTest(field=field):
                self.configure()
                value = sha(b'EXAMPLE_OTHER') if field == 'packet_sha256' else 'EXAMPLE_OTHER'
                context = dataclasses.replace(self.fixture.context, **{field: value})
                permit = self.issue()
                self.assert_held(self.use(permit, expected=context))
                self.assert_held(self.use(permit), original=False)
        self.configure()
        self.assert_held(self.use(self.issue(), affected=[*self.findings, 'EXAMPLE_WIDENED']))

    def test_changed_missing_support_return_dispatch_policy_or_control_at_use_preserves_holds(self):
        for selected in ('support', 'return', 'dispatch', 'policy', 'boundary-policy', 'control'):
            with self.subTest(selected=selected):
                self.configure()
                permit = self.issue()
                control = self.control.observation
                if selected == 'control':
                    self.control.observation = dataclasses.replace(control,
                        record_bytes=binding._json({**self.record, 'decision': 'quarantined'}))
                else:
                    paths = {'support': self.home / control.support[0].artifact,
                        'return': self.home / control.return_path,
                        'dispatch': self.home / control.dispatch_path,
                        'policy': policy.POLICY_DIR / 'synthesis-policy.yaml',
                        'boundary-policy': policy.POLICY_DIR / 'share-boundaries.yaml'}
                    path = paths[selected]
                    before = path.read_bytes()
                    path.write_bytes(before + b'\nEXAMPLE_CHANGED')
                self.assert_held(self.use(permit))
                if selected != 'control':
                    path.write_bytes(before)
                self.assert_held(self.use(permit), original=False)

    def test_source_refusal_is_terminal_even_when_a_later_read_would_recover(self):
        permit = self.issue()
        reads = []
        actual = binding.read_support
        def refuse_once(root, path):
            reads.append(path)
            if len(reads) == 1:
                raise PermissionError('EXAMPLE source read refused')
            return actual(root, path)
        with mock.patch.object(binding, 'read_support', side_effect=refuse_once):
            view = self.assert_held(self.use(permit))
        self.assertEqual(reads, ['EXAMPLE_RETURN.md'])
        self.assertEqual(view['diagnostic'], {'type': 'PermissionError', 'message': 'EXAMPLE source read refused'})
        self.assert_held(self.use(permit), original=False)

    def test_final_revalidation_preserves_facts_and_never_emits_prepared_advice(self):
        permit = self.issue()
        actual = self.control.observe
        def change_at_final(owner, name):
            if self.control.reads == 2:
                (self.home / self.control.observation.support[0].artifact).unlink()
            return actual(owner, name)
        with mock.patch.object(self.control, 'observe', side_effect=change_at_final):
            view = self.assert_held(self.use(permit))
        self.assertIsNone(view['synthesis'])
        self.assertEqual(view['diagnostic']['type'], 'FileNotFoundError')
        self.assert_held(self.use(permit), original=False)

    def test_issue_refusal_cannot_be_retried_or_replayed_under_a_new_control_label(self):
        path = self.home / self.control.observation.support[0].artifact
        original = path.read_bytes()
        path.unlink()
        with self.assertRaises(FileNotFoundError):
            self.issue()
        path.write_bytes(original)
        with self.assertRaisesRegex(ValueError, 'already attempted'):
            self.issue()
        with self.assertRaisesRegex(ValueError, 'already issued'):
            self.issue('EXAMPLE_CONTROL_ALIAS')
        self.configure()
        observation = self.control.observation
        self.control.observation = dataclasses.replace(observation, support=list(observation.support))
        with self.assertRaises(ValueError):
            self.issue()
        self.control.observation = observation
        with self.assertRaisesRegex(ValueError, 'already issued'):
            self.issue('EXAMPLE_CONTROL_ALIAS')

    def test_fresh_policy_refresh_recompiles_the_actual_tripwire_rules(self):
        path = policy.POLICY_DIR / 'return-tripwires.yaml'
        before = path.read_bytes()
        raw = self.fixture.raw_return + b'\nEXAMPLE_POLICY_B_ONLY\n'
        warm = qualified.evaluate_current(raw, self.fixture.context,
            metadata_bytes=self.control.observation.evaluation_metadata_bytes)
        new_hold = 'return-tripwire:scope_expansion'
        self.assertNotIn(new_hold, binding._parse(warm.result_bytes)['hold_reasons'])
        changed = json.loads(before)
        changed['rules'].append({'id': 'example-policy-b-only', 'category': 'scope_expansion',
            'pattern': 'example_policy_b_only', 'negatable': False, 'directive': False,
            'description': 'EXAMPLE policy B sentinel rule.'})
        try:
            path.write_bytes(binding._json(changed))
            policy.clear_policy_cache()
            self.assertEqual(policy.load_policy('return-tripwires'), changed)
            self.configure(raw=raw, findings=['return-tripwire:security_weakening'])
            view = self.use(self.issue()).projection()
            self.assertIn(new_hold, view['original_evaluation']['hold_reasons'])
            self.assertIn(new_hold, view['remaining_holds'])
            self.assertFalse(view['evaluation']['accepted_for_use'])
            self.assertTrue(view['affected_accepted_for_use'])
        finally:
            path.write_bytes(before)
            policy.clear_policy_cache()
            return_tripwires._policy.cache_clear()

    def test_source_change_during_final_support_read_preserves_original_holds(self):
        for selected in ('return', 'dispatch', 'policy', 'boundary-policy'):
            with self.subTest(selected=selected):
                self.configure()
                permit = self.issue()
                control = self.control.observation
                path = {'return': self.home / control.return_path,
                    'dispatch': self.home / control.dispatch_path,
                    'policy': policy.POLICY_DIR / 'synthesis-policy.yaml',
                    'boundary-policy': policy.POLICY_DIR / 'share-boundaries.yaml'}[selected]
                before = path.read_bytes()
                actual = binding.read_support
                def change_during_support(root, name):
                    raw = actual(root, name)
                    if self.control.reads == 3 and name == control.support[-1].artifact:
                        path.write_bytes(before + b'\nEXAMPLE_CHANGED_DURING_SUPPORT')
                    return raw
                try:
                    with mock.patch.object(binding, 'read_support', side_effect=change_during_support):
                        view = self.assert_held(self.use(permit))
                    self.assertIsNone(view['synthesis'])
                    self.assert_held(self.use(permit), original=False)
                finally:
                    path.write_bytes(before)
                    policy.clear_policy_cache()


if __name__ == '__main__':
    unittest.main()
