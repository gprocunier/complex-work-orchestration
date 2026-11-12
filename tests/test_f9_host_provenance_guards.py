"""Late host provenance refusals with real anchored records and paired controls."""
from __future__ import annotations

import copy
import hashlib
import json
import os
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tests import test_host_acceptance as acceptance_fixtures
from tests import test_host_records as record_fixtures
from cwo_core import host_acceptance as acceptance, host_records as records
from cwo_core.errors import CWOPolicyError
from cwo_core.host_return_intake import record_received_return
from cwo_core.peer_review import pending_evaluation_sha256
from cwo_core.returns import make_acceptance_decision


class F9HostProvenanceGuards(unittest.TestCase):
    def fixture(self, module, name):
        fixture = getattr(module, name)('runTest')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        return fixture

    @staticmethod
    def image(store):
        return {str(path): path.read_bytes() for path in store.state_root.rglob('*') if path.is_file()}

    def reviewed(self):
        fixture = self.fixture(acceptance_fixtures, 'HostAcceptanceTests')
        fixture.text = fixture.text.replace('not required for this sample return', 'independent review required before use')
        dispatch = fixture.dispatch(evaluation_metadata={'peer_review_required': True})
        pending = make_acceptance_decision(fixture.text, bead_id=fixture.beacon['bead_id'], dispatch_id=dispatch,
            executor='codex_architecture_critic', peer_review_required=True, peer_review_status='pending')
        returned = hashlib.sha256(fixture.text.encode()).hexdigest()
        expected = dict(bead_id=fixture.beacon['bead_id'], dispatch_id=dispatch, return_sha256=returned)
        target = dict(dispatch_id=dispatch, return_sha256=returned, evaluation_sha256=pending_evaluation_sha256(pending))
        review = self.reviewer(fixture.store, 'EXAMPLE_F9_REVIEW', target)
        record_received_return(fixture.store, review['reviewer_identity']['dispatch_id'], json.dumps(review).encode())
        pipeline = acceptance.HostAcceptancePipeline(lambda _: acceptance.HostAdjudicationDecision('accepted', 'Yes', 'HOST'))
        record_id = pipeline.accept(fixture.text, dispatch_id=dispatch, peer_review_record=review, **fixture.beacon)
        accepted = fixture.store.get(record_id)
        evaluation = fixture.store.get(accepted['evaluation_record'])['evaluation']
        clearance = fixture.store.get(accepted['cleared_holds']['peer-review-pending'])
        expected['evaluation_sha256'] = accepted['evaluation_sha256']
        return fixture, record_id, accepted, review, evaluation, clearance, pending, expected, target

    @staticmethod
    def reviewer(store, dispatch_id, target):
        identity = dict(provider='openai', model_family='gpt', model_id='gpt-6-astra', reasoning_effort='max', dispatch_id=dispatch_id)
        store.write_dispatch(**identity, dispatch_role='peer-review', session_id=dispatch_id,
            request_sha256='2' * 64, review_target=target, executor='codex_architecture_critic')
        return dict(record_type='cwo-peer-review', version=2, decision='passed', reviewer_identity=identity,
            return_sha256=target['return_sha256'], evaluation_sha256=target['evaluation_sha256'])

    @staticmethod
    def seed_reader_fault(store, record):
        # Inject one semantically inconsistent anchored receipt to isolate a late
        # reader guard. Valid ingress rejects this state; positive controls use
        # record_received_return and never replace a captured dispatch receipt.
        digest = pending_evaluation_sha256(record)
        store.write_return_received(record['reviewer_identity']['dispatch_id'], digest,
            capture_provenance='host-capture-v1', canonical_return_sha256=digest)

    def test_F9_09be0a7501964c33_audit_lock_owner_before_flock(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY)
            self.addCleanup(os.close, directory)
            lock = records._audit_lock(directory, create=True, exclusive=True)
            os.close(lock)
            real_fstat = os.fstat
            for foreign in (False, True):
                def observed(fd):
                    info = real_fstat(fd)
                    return SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_nlink=1,
                        st_uid=info.st_uid + int(foreign))
                with self.subTest(foreign=foreign), patch.object(records.os, 'fstat', side_effect=observed), \
                        patch.object(records.fcntl, 'flock') as flock:
                    if foreign:
                        with self.assertRaises(records.HostRecordError):
                            records._audit_lock(directory, create=False, exclusive=False)
                        flock.assert_not_called()
                    else:
                        lock = records._audit_lock(directory, create=False, exclusive=False)
                        os.close(lock)
                        flock.assert_called_once()

    def test_F9_09b444b9c3d7f3b2_hold_writer_exact_list_before_write(self):
        fixture = self.fixture(record_fixtures, 'HostRecordTests')
        fixture.dispatch()
        fixture.store.write_return_received('executor', fixture.digest)
        fixture.acceptance()
        before = self.image(fixture.store)
        with self.assertRaises(records.HostRecordError):
            fixture.acceptance(required_holds=('review',))
        self.assertEqual(self.image(fixture.store), before)

    def test_F9_9aa3858a66b3dd10_d62b014fec8502b2_decisions_with_matching_receipts(self):
        fixture = self.fixture(acceptance_fixtures, 'HostAcceptanceTests')
        args, accepted = fixture.accepted()
        adjudication = fixture.store.get(accepted['adjudication_record'])
        for changes in ({'adjudication_result': 'rejected'}, {'decision': 'rejected'}, {'evaluation_record': '0' * 64}):
            with self.subTest(changes=changes):
                payload = fixture.record_payload(accepted)
                if 'adjudication_result' in changes:
                    payload.update(changes)
                else:
                    payload['adjudication_record'] = fixture.store.write_record('adjudication',
                        **{**fixture.record_payload(adjudication), **changes})
                altered = fixture.store._write('acceptance-decision', payload)
                fixture.store.record_audit_event(dict(event_type='host_acceptance_decided', acceptance_record_sha256=altered,
                    adjudication_record_sha256=payload['adjudication_record'], host_control_id=adjudication['control_id'],
                    **{key: payload[key] for key in ('bead_id', 'dispatch_id', 'return_sha256', 'evaluation_sha256')}))
                before = self.image(fixture.store)
                with self.assertRaises(CWOPolicyError):
                    acceptance.require_acceptance(fixture.store, **{**args, 'acceptance_record': altered}, **fixture.beacon)
                self.assertEqual(self.image(fixture.store), before)
        self.assertEqual(acceptance.require_acceptance(fixture.store, **args, **fixture.beacon), accepted)

    def test_F9_48e39749d8e6279a_77fe8b415cde73ab_late_review_decision_and_return(self):
        fixture, _, _, _, evaluation, clearance, pending, expected, target = self.reviewed()
        acceptance._verified_peer_clearance(fixture.store, clearance, evaluation, pending, expected)
        for key, value in (('decision', 'rejected'), ('return_sha256', '0' * 64)):
            changed = self.reviewer(fixture.store, 'EXAMPLE_F9_CHANGED_' + key.upper(), target)
            changed[key] = value
            self.seed_reader_fault(fixture.store, changed)
            identity = changed['reviewer_identity']
            separation = copy.deepcopy(clearance['peer_review_separation'])
            separation['reviewer_dispatch_sha256'] = fixture.store.require_dispatch(identity['dispatch_id'])['_record_sha256']
            separation['reviewer_session_id'] = identity['dispatch_id']
            evidence = dict(peer_review_record=changed, peer_review_separation=separation)
            before = self.image(fixture.store)
            with self.subTest(key=key), self.assertRaises(CWOPolicyError):
                acceptance._verified_peer_clearance(fixture.store, {**clearance, **evidence},
                    {**evaluation, **evidence}, pending, expected)
            self.assertEqual(self.image(fixture.store), before)

    def test_F9_c6f003ffcd9cff50_clearance_uses_exact_evaluated_review(self):
        fixture, _, _, _, evaluation, clearance, pending, expected, target = self.reviewed()
        alternate = self.reviewer(fixture.store, 'EXAMPLE_F9_ALTERNATE', target)
        record_received_return(fixture.store, alternate['reviewer_identity']['dispatch_id'], json.dumps(alternate).encode())
        result = make_acceptance_decision(fixture.text, peer_review_status='passed', peer_review_record=alternate,
            peer_review_reviewer=alternate['reviewer_identity'], **acceptance._host_inputs(
                fixture.store.require_dispatch(expected['dispatch_id']), expected['bead_id'], expected['dispatch_id']))
        alternate_clearance = {**clearance, 'peer_review_record': alternate,
            'peer_review_separation': result['peer_review_separation']}
        acceptance._verified_peer_clearance(fixture.store, alternate_clearance, result, pending, expected)
        before = self.image(fixture.store)
        with self.assertRaises(CWOPolicyError):
            acceptance._verified_peer_clearance(fixture.store, alternate_clearance, evaluation, pending, expected)
        self.assertEqual(self.image(fixture.store), before)

    def test_F9_380c65c6ca0ab464_a3da30e103d3b1cd_late_dispatch_target_and_receipt(self):
        fixture, _, _, review, _, clearance, _, expected, target = self.reviewed()
        separation = clearance['peer_review_separation']
        acceptance._verify_review_dispatch(fixture.store, review['reviewer_identity'], review, separation, expected)
        for suffix, altered_target, receipt in (('TARGET', {**target, 'return_sha256': '0' * 64}, True),
                                                ('RECEIPT', target, False)):
            alternate = self.reviewer(fixture.store, 'EXAMPLE_F9_' + suffix, altered_target)
            # Keep review evidence's target exact; only the recorded dispatch target differs.
            alternate['return_sha256'] = target['return_sha256']
            alternate['evaluation_sha256'] = target['evaluation_sha256']
            identity = alternate['reviewer_identity']
            copied = copy.deepcopy(separation)
            copied['reviewer_dispatch_sha256'] = fixture.store.require_dispatch(identity['dispatch_id'])['_record_sha256']
            copied['reviewer_session_id'] = identity['dispatch_id']
            if receipt:
                self.seed_reader_fault(fixture.store, alternate)
            before = self.image(fixture.store)
            with self.subTest(check=suffix), self.assertRaises(CWOPolicyError):
                acceptance._verify_review_dispatch(fixture.store, identity, alternate, copied, expected)
            self.assertEqual(self.image(fixture.store), before)

    def test_F9_240a102667eeff43_review_recheck_after_adjudication(self):
        fixture, _, _, review, _, _, _, expected, _ = self.reviewed()
        before = self.image(fixture.store)
        def changed_review(_evaluation):
            review['decision'] = 'rejected'
            return acceptance.HostAdjudicationDecision('accepted', 'Yes', 'HOST')
        with self.assertRaises(CWOPolicyError):
            acceptance.HostAcceptancePipeline(changed_review).accept(fixture.text, dispatch_id=expected['dispatch_id'],
                peer_review_record=review, **fixture.beacon)
        self.assertEqual(self.image(fixture.store), before)
