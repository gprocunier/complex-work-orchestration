"""P0: autonomous acceptance recomputes inputs and closure verifies every link."""
from __future__ import annotations

import copy
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from cwo_core.errors import CWOPolicyError  # noqa: E402
from cwo_core.host_acceptance import HostAcceptancePipeline, HostAdjudicationDecision, require_acceptance, _verified_evaluation, _verified_receipts, _required_clearances  # noqa: E402
from cwo_core.host_records import HostRecordStore, using_test_store  # noqa: E402
from cwo_core.peer_review import pending_evaluation_sha256  # noqa: E402
from cwo_core.returns import make_acceptance_decision  # noqa: E402
from tests.host_acceptance_fixtures import provision_acceptance  # noqa: E402


import json
from cwo_core.host_return_intake import record_received_return

class HostAcceptanceTests(unittest.TestCase):
    def setUp(self):
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.store = HostRecordStore.for_tests(root / 'host')
        self.enterContext(using_test_store(self.store))
        database = root / 'database'
        database.mkdir(mode=0o700)
        self.database_identity = self.store.setup_database_identity(database)
        self.beacon = {'bead_id': 'EXAMPLE_ACCEPT', 'database_identity': self.database_identity}
        self.text = (ROOT / 'examples/sample-contractor-return.md').read_text()

    def accepted(self):
        args = provision_acceptance(self.store, **self.beacon)
        result = require_acceptance(self.store, **args, **self.beacon)
        self.assertEqual(result['adjudication_result'], 'accepted')
        return args, result

    def record_payload(self, record):
        return {k: copy.deepcopy(v) for k, v in record.items()
                if k not in ('record_type', 'schema_version', 'created_at', '_record_sha256')}

    def test_p0_exact_context_database_and_all_linked_records_required(self):
        args, accepted = self.accepted()
        for field, value in (('bead_id', 'EXAMPLE_OTHER'), ('return_sha256', '0' * 64),
                             ('evaluation_sha256', '0' * 64), ('database_identity', {'database_id': 'OTHER'})):
            with self.subTest(check=field), self.assertRaises(CWOPolicyError):
                require_acceptance(self.store, **{**args, **self.beacon, field: value})
        for changes in ({'adjudication_result': 'rejected'}, {'evaluation_record': '0' * 64},
                        {'adjudication_record': '0' * 64}, {'required_holds': ['peer-review-pending']},
                        {'cleared_holds': {'peer-review-pending': '0' * 64}}):
            with self.subTest(check=changes):
                forged = self.store._write('acceptance-decision', {**self.record_payload(accepted), **changes})
                with self.assertRaises(CWOPolicyError):
                    require_acceptance(self.store, **{**args, 'acceptance_record': forged}, **self.beacon)

    def test_p0_evaluation_and_adjudication_individually_reverified(self):
        args, accepted = self.accepted()
        for kind, reference, changes in (
            ('evaluation', 'evaluation_record', {'policy_sha256': '0' * 64}),
            ('evaluation', 'evaluation_record', {'bead_id': 'EXAMPLE_OTHER'}),
            ('evaluation', 'evaluation_record', {'dispatch_record_sha256': '0' * 64}),
            ('evaluation', 'evaluation_record', {'return_record_sha256': '0' * 64}),
            ('evaluation', 'evaluation_record', {'evaluation': {**self.store.get(accepted['evaluation_record'])['evaluation'], 'score': 99}}),
            ('adjudication', 'adjudication_record', {'decision': 'rejected'}),
            ('adjudication', 'adjudication_record', {'evaluation_record': '0' * 64}),
            ('adjudication', 'adjudication_record', {'return_sha256': '0' * 64})):
            with self.subTest(check=(kind, changes)):
                source = self.store.get(accepted[reference])
                altered = self.store.write_record(kind, **{**self.record_payload(source), **changes})
                changes_to_acceptance = {reference: altered}
                if kind == 'evaluation':
                    # Keep every other link consistent, so this negative case
                    # cannot be masked by a later adjudication-link refusal.
                    adjudication = self.store.get(accepted['adjudication_record'])
                    changes_to_acceptance['adjudication_record'] = self.store.write_record('adjudication',
                        **{**self.record_payload(adjudication), 'evaluation_record': altered})
                forged = self.store._write('acceptance-decision', {**self.record_payload(accepted), **changes_to_acceptance})
                with self.assertRaises(CWOPolicyError):
                    require_acceptance(self.store, **{**args, 'acceptance_record': forged}, **self.beacon)
                if kind == 'evaluation':
                    # Exercise the backup reader directly as well as closure:
                    # unrelated later linkage checks cannot mask its refusal.
                    with self.assertRaises(CWOPolicyError):
                        checker = _verified_receipts if set(changes) & {"dispatch_record_sha256", "return_record_sha256"} else _verified_evaluation
                        selected = self.store.get(altered) if checker is _verified_receipts else self.store.get(forged)
                        checker(self.store, selected,
                            {'bead_id': self.beacon['bead_id'], 'dispatch_id': accepted['dispatch_id'],
                             'return_sha256': args['return_sha256'], 'evaluation_sha256': args['evaluation_sha256']})

    def test_p0_hold_set_and_host_control_shape_checks_are_independent(self):
        with self.assertRaises(CWOPolicyError):
            HostAcceptancePipeline(None)
        for required, cleared, pending in ((None, {}, []), ([], None, []),
                (['peer-review-pending'] * 2, {'peer-review-pending': '1' * 64}, ['peer-review-pending']),
                (['peer-review-pending'], {}, ['peer-review-pending']),
                ([], {}, ['peer-review-pending']), (['unknown-hold'], {'unknown-hold': '1' * 64}, ['unknown-hold'])):
            with self.subTest(check=(required, cleared, pending)), self.assertRaises(CWOPolicyError):
                _required_clearances({'required_holds': required, 'cleared_holds': cleared}, {'hold_reasons': pending})
        self.assertEqual(_required_clearances({'required_holds': [], 'cleared_holds': {}}, {'hold_reasons': []}), ([], {}))

    def test_p0_generic_persistence_neither_grants_acceptance_nor_removes_host_required_review(self):
        args, accepted = self.accepted()
        copied = self.store._write('acceptance-decision', {**self.record_payload(accepted),
            'fixture_source': 'generic-record-writer'})
        with self.assertRaisesRegex(CWOPolicyError, 'audit receipt'):
            require_acceptance(self.store, **{**args, 'acceptance_record': copied}, **self.beacon)
        dispatch_id = self.dispatch(evaluation_metadata={'peer_review_required': True})
        dispatch = self.store.require_dispatch(dispatch_id)
        receipt = self.store.require_return(dispatch_id, hashlib.sha256(self.text.encode()).hexdigest())
        favorable = make_acceptance_decision(self.text, bead_id=self.beacon['bead_id'],
            dispatch_id=dispatch_id, executor='codex_architecture_critic')
        self.assertTrue(favorable['accepted_for_use'])
        context = {'bead_id': self.beacon['bead_id'], 'dispatch_id': dispatch_id,
            'return_sha256': hashlib.sha256(self.text.encode()).hexdigest(),
            'evaluation_sha256': pending_evaluation_sha256(favorable)}
        from cwo_core.host_acceptance import _policy_sha256
        evaluation_id = self.store.write_record('evaluation', **context, return_text=self.text,
            evaluation=favorable, pending_evaluation=favorable, policy_sha256=_policy_sha256(),
            dispatch_record_sha256=dispatch['_record_sha256'], return_record_sha256=receipt['_record_sha256'])
        adjudication_id = self.store.write_record('adjudication', **context, decision='accepted',
            rationale='EXAMPLE fabricated favorable snapshot', control_id='EXAMPLE_NO_CONTROL',
            evaluation_record=evaluation_id)
        forged = self.store.write_acceptance(**context, database_identity=self.database_identity,
            adjudication_result='accepted', required_holds=[], cleared_holds={},
            evaluation_record=evaluation_id, adjudication_record=adjudication_id)
        expected = {**context}
        with self.assertRaisesRegex(CWOPolicyError, 'current host-metadata'):
            _verified_evaluation(self.store, self.store.get(forged), expected)
        with self.assertRaises(CWOPolicyError):
            require_acceptance(self.store, forged, bead_id=context['bead_id'],
                return_sha256=context['return_sha256'], evaluation_sha256=context['evaluation_sha256'],
                database_identity=self.database_identity)

    def dispatch(self, **changes):
        fields = dict(dispatch_id='EXAMPLE_PIPELINE_EXECUTOR_' + str(len(self.store.find('dispatch'))), dispatch_role='executor', provider='openai',
            model_family='gpt', model_id='gpt-6.1-sol', reasoning_effort='xhigh', session_id='EXAMPLE_EXECUTOR',
            request_sha256='1' * 64, bead_id=self.beacon['bead_id'], executor='codex_architecture_critic')
        self.store.write_dispatch(**{**fields, **changes})
        self.store.write_return_received(fields['dispatch_id'], hashlib.sha256(self.text.encode()).hexdigest())
        return fields['dispatch_id']

    def test_p0_pipeline_requires_recorded_identity_return_eligible_evaluation_and_host_decision(self):
        dispatch_id = self.dispatch()
        for decision in (None, {'decision': 'accepted'}, HostAdjudicationDecision('rejected', 'No', 'HOST'),
                         HostAdjudicationDecision('accepted', '', 'HOST'), HostAdjudicationDecision('accepted', 'Yes', '')):
            with self.subTest(check=decision), self.assertRaises(CWOPolicyError):
                HostAcceptancePipeline(lambda evaluation: decision).accept(self.text,
                    dispatch_id=dispatch_id, **self.beacon)
        for text, bead in ((self.text + '\n', self.beacon['bead_id']), (self.text, 'EXAMPLE_OTHER')):
            with self.subTest(check=(text == self.text, bead)), self.assertRaises(CWOPolicyError):
                HostAcceptancePipeline(lambda evaluation: HostAdjudicationDecision('accepted', 'Yes', 'HOST')).accept(
                    text, dispatch_id=dispatch_id, **{**self.beacon, 'bead_id': bead})
        self.assertEqual(self.store.find('acceptance-decision'), [])
        unknown = self.dispatch(model_id='EXAMPLE_UNREGISTERED')
        with self.assertRaisesRegex(CWOPolicyError, 'registered'):
            HostAcceptancePipeline(lambda evaluation: HostAdjudicationDecision('accepted', 'Yes', 'HOST')).accept(
                self.text, dispatch_id=unknown, **self.beacon)
        self.assertEqual(self.store.find('acceptance-decision'), [])
        healthy = self.dispatch()
        accepted = HostAcceptancePipeline(lambda evaluation: HostAdjudicationDecision('accepted', 'Yes', 'HOST')).accept(
            self.text, dispatch_id=healthy, **self.beacon)
        self.assertEqual(self.store.get(accepted)['adjudication_result'], 'accepted')

    def test_p0_host_policy_drift_during_control_refuses_before_acceptance_records(self):
        from tests.test_policy_current_effects import current_policy
        from cwo_core import policy
        for clear_cache in (False, True):
            with self.subTest(clear_cache=clear_cache), current_policy(), using_test_store(self.store):
                dispatch_id = self.dispatch()
                def changing_control(evaluation):
                    path = policy.POLICY_DIR / 'acceptance-policy.yaml'
                    import json
                    document = json.loads(path.read_text())
                    document['score']['thresholds']['accept'] = 99
                    path.write_text(json.dumps(document))
                    if clear_cache:
                        policy.clear_policy_cache()
                    return HostAdjudicationDecision('accepted', 'EXAMPLE observed acceptance', 'HOST')
                with self.assertRaisesRegex(CWOPolicyError, 'policy (changed|cache)'):
                    HostAcceptancePipeline(changing_control).accept(self.text, dispatch_id=dispatch_id, **self.beacon)
                self.assertEqual(self.store.find('acceptance-decision'), [])
                self.assertEqual(self.store.find('adjudication'), [])


    def test_p0_raw_boolean_policy_cannot_equal_cached_integer_for_new_acceptance(self):
        from tests.test_policy_current_effects import current_policy
        from cwo_core import policy
        from cwo_core.host_acceptance import _policy_sha256
        import json
        with current_policy(), using_test_store(self.store):
            dispatch_id = self.dispatch()
            _policy_sha256()
            path = policy.POLICY_DIR / 'return-tripwires.yaml'
            changed = json.loads(path.read_text())
            self.assertIs(type(changed['version']), int)
            changed['version'] = True
            path.write_text(json.dumps(changed))
            calls = []
            def decide(evaluation):
                calls.append(evaluation)
                return HostAdjudicationDecision('accepted', 'EXAMPLE never reached', 'HOST')
            with self.assertRaisesRegex(CWOPolicyError, 'policy cache'):
                HostAcceptancePipeline(decide).accept(self.text, dispatch_id=dispatch_id, **self.beacon)
            self.assertEqual(calls, [])
            self.assertEqual(self.store.find('acceptance-decision'), [])

    def test_p0_received_evaluation_context_checks_have_positive_and_zero_write_controls(self):
        from cwo_core.host_acceptance import record_received_evaluation
        from evaluate_return import _record_host_evaluation
        dispatch_id = self.dispatch()
        result = make_acceptance_decision(self.text, bead_id=self.beacon['bead_id'],
            dispatch_id=dispatch_id, executor='codex_architecture_critic')
        record_id = record_received_evaluation(self.text, result)
        self.assertEqual(self.store.get(record_id)['evaluation_sha256'], pending_evaluation_sha256(result))
        before = {str(path): path.read_bytes() for path in self.store.state_root.rglob('*') if path.is_file()}
        for key, value in (('bead_id', 'EXAMPLE_WRONG_TASK'), ('executor', 'claude_architecture_critic')):
            with self.subTest(check=key):
                changed = {**result, key: value}
                with self.assertRaises(CWOPolicyError):
                    record_received_evaluation(self.text, changed)
                with self.assertRaises(SystemExit):
                    _record_host_evaluation(self.text, changed)
                self.assertEqual({str(path): path.read_bytes() for path in self.store.state_root.rglob('*') if path.is_file()}, before)
        self.assertIsNone(record_received_evaluation(self.text, {**result, 'dispatch_id': None}))
        self.assertIsNone(record_received_evaluation(self.text, {**result, 'dispatch_id': 'EXAMPLE_LEGACY'}))

    def test_p0_closure_reader_sees_policy_changes_without_caller_cache_refresh(self):
        from tests.test_policy_current_effects import current_policy
        from cwo_core import policy
        import json
        with current_policy(), using_test_store(self.store):
            args, _ = self.accepted()
            path = policy.POLICY_DIR / 'acceptance-policy.yaml'
            original = path.read_text()
            changed = json.loads(original)
            changed['score']['thresholds']['accept'] = 99
            path.write_text(json.dumps(changed))
            with self.assertRaisesRegex(CWOPolicyError, 'policy cache'):
                require_acceptance(self.store, **args, **self.beacon)
            policy.clear_policy_cache()
            with self.assertRaisesRegex(CWOPolicyError, 'policy is stale'):
                require_acceptance(self.store, **args, **self.beacon)
            path.write_text(original)
            policy.clear_policy_cache()
            self.assertEqual(require_acceptance(self.store, **args, **self.beacon)['adjudication_result'], 'accepted')


    def test_p0_required_review_has_verified_clearance_and_received_decision(self):
        self.text = self.text.replace('not required for this sample return', 'independent review required before use')
        dispatch_id = self.dispatch(evaluation_metadata={'peer_review_required': True})
        pending = make_acceptance_decision(self.text, bead_id=self.beacon['bead_id'], dispatch_id=dispatch_id,
            executor='codex_architecture_critic', peer_review_required=True, peer_review_status='pending')
        returned = hashlib.sha256(self.text.encode()).hexdigest()
        target = {'dispatch_id': dispatch_id, 'return_sha256': returned,
                  'evaluation_sha256': pending_evaluation_sha256(pending)}
        self.store.write_dispatch(dispatch_id='EXAMPLE_PIPELINE_REVIEW', dispatch_role='peer-review', provider='openai',
            model_family='gpt', model_id='gpt-6-astra', reasoning_effort='max', session_id='EXAMPLE_REVIEWER',
            request_sha256='2' * 64, review_target=target, executor='codex_architecture_critic')
        record = {'record_type': 'cwo-peer-review', 'version': 2, 'decision': 'passed',
            'reviewer_identity': {'provider': 'openai', 'model_family': 'gpt', 'model_id': 'gpt-6-astra',
                'reasoning_effort': 'max', 'dispatch_id': 'EXAMPLE_PIPELINE_REVIEW'},
            'return_sha256': returned, 'evaluation_sha256': target['evaluation_sha256']}
        pipeline = HostAcceptancePipeline(lambda observed: HostAdjudicationDecision('accepted', 'Yes', 'HOST'))
        for review in (None, record):
            with self.subTest(check='missing review' if review is None else 'missing receipt'), self.assertRaises(CWOPolicyError):
                pipeline.accept(self.text, dispatch_id=dispatch_id, peer_review_record=review, **self.beacon)
        record_received_return(
            self.store, 'EXAMPLE_PIPELINE_REVIEW', json.dumps(record).encode())
        accepted = pipeline.accept(self.text, dispatch_id=dispatch_id, peer_review_record=record, **self.beacon)
        value = self.store.get(accepted)
        args = dict(acceptance_record=accepted, return_sha256=returned, evaluation_sha256=value['evaluation_sha256'])
        checked = require_acceptance(self.store, **args, **self.beacon)
        self.assertEqual(set(checked['required_holds']), {'peer-review-pending'})
        self.assertEqual(set(checked['cleared_holds']), {'peer-review-pending'})
        clearance = self.store.get(checked['cleared_holds']['peer-review-pending'])
        self.assertEqual(clearance['peer_review_separation']['level'], 'escalation')
        altered = self.store.write_record('hold-clearance', **{**self.record_payload(clearance), 'hold': 'risk-review-pending'})
        forged = self.store._write('acceptance-decision', {**self.record_payload(checked),
            'cleared_holds': {'peer-review-pending': altered}})
        with self.assertRaises(CWOPolicyError):
            require_acceptance(self.store, **{**args, 'acceptance_record': forged}, **self.beacon)
