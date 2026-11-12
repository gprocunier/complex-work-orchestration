"""Prepared requirements and current-observation receipt binding; no real model effects."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'tests')]
import dispatch_work as dispatch  # noqa: E402
import qualified_review_dispatch as review  # noqa: E402
import test_qualified_review_dispatch as fixtures  # noqa: E402
from cwo_core.host_records import HostRecordStore, configured_store, using_test_store  # noqa: E402
from cwo_core.host_return_intake import record_received_return  # noqa: E402


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class ObservedWriterChecks(unittest.TestCase):
    def fixture(self):
        fixture = fixtures.QualifiedReviewTest('runTest')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        return fixture

    def test_actual_qualified_scope_pins_requirements_before_resolution(self):
        """Check: actual host requirements replace the generic conservative fallback before effects."""
        fixture = self.fixture()
        wire = json.loads(fixture.host._bindings['plan'])
        requirements = wire['evaluation_requirements']
        self.assertIs(requirements['peer_review_required'], False)
        store = configured_store()
        def resolve(*args, **kwargs):
            recorded = store.require_dispatch(wire['envelope']['dispatch_id'])
            metadata = recorded['evaluation_metadata']
            self.assertEqual({key: metadata[key] for key in requirements}, requirements)
            self.assertEqual(recorded['provider'], 'local-openai-compatible')
            self.assertEqual(recorded['provider_key'], 'local_inference')
            self.assertIsNone(recorded['model_id'])
            return fixture.resolve(*args, **kwargs)
        with patch.object(dispatch, 'pinned_local_endpoint_address', side_effect=resolve):
            result = fixture.run_ticket()
        self.assertTrue(result['review']['usable_final_content'])
        self.assertEqual(len(fixture.http.calls), 1)
        generic = {**wire['envelope'], 'dispatch_id': 'generic'}
        generic_id = dispatch.record_local_execution(generic, wire['selected'], sha(b'generic request'))
        self.assertIs(store.get(generic_id)['evaluation_metadata']['peer_review_required'], True)
        typed = {**generic, 'dispatch_id': 'typed-reuse'}
        numeric_metadata = {**store.get(generic_id)['evaluation_metadata'], 'peer_review_required': 1}
        store.write_dispatch(dispatch_id=typed['dispatch_id'], dispatch_role='executor',
            provider='local-openai-compatible', provider_key=typed['provider_key'], executor=typed['executor_key'],
            bead_id=typed['bead_id'], model_family=None, model_id=None, reasoning_effort=None, session_id=None,
            request_sha256=sha(b'typed request'), evaluation_metadata=numeric_metadata)
        with self.assertRaisesRegex(SystemExit, 'differs from its recorded host dispatch'):
            dispatch.record_local_execution(typed, wire['selected'], sha(b'typed request'))
        # An existing generic record may not be reused to weaken its pinned holds.
        ticket = fixture.ticket('review')
        review_wire = json.loads(fixture.host._bindings['review'])
        scope = review._ReviewScope(fixture.host, ticket, review_wire, None, None)
        request_digest = dispatch.local_request_sha256(review_wire['envelope'])
        dispatch.record_local_execution(review_wire['envelope'], review_wire['selected'], request_digest)
        with self.assertRaisesRegex(SystemExit, 'differs from its recorded host dispatch'):
            dispatch.record_local_execution(review_wire['envelope'], review_wire['selected'], request_digest,
                                            qualified_review=scope)

    def test_requirements_api_refuses_caller_claims_or_drift_and_returns_a_copy(self):
        """Checks: only an exact original scope/envelope yields pinned requirements, without mutable aliases."""
        fixture = self.fixture()
        ticket = fixture.ticket()
        wire = json.loads(fixture.host._bindings[ticket.node_id])
        scope = review._ReviewScope(fixture.host, ticket, wire, None, None)
        observed = review.evaluation_requirements(scope, wire['envelope'])
        self.assertEqual(set(observed), {'peer_review_required', 'provider_conflict_domains'})
        observed['peer_review_required'] = True
        observed['provider_conflict_domains'].append('caller-added')
        self.assertEqual(review.evaluation_requirements(scope, wire['envelope']), wire['evaluation_requirements'])
        forged = SimpleNamespace(binding={'envelope': wire['envelope'],
                                           'evaluation_requirements': {'peer_review_required': False}})
        for invalid in ({'peer_review_required': False}, forged):
            with self.subTest(scope=type(invalid).__name__), self.assertRaises(review.admission.AdmissionError):
                dispatch.record_local_execution(wire['envelope'], wire['selected'], sha(b'request'),
                                                qualified_review=invalid)
        with self.assertRaisesRegex(review.admission.AdmissionError, 'envelope drifted'):
            review.evaluation_requirements(scope, {**wire['envelope'], 'bead_id': 'another'})
        scope.binding['evaluation_requirements']['peer_review_required'] = True
        with self.assertRaisesRegex(review.admission.AdmissionError, 'finite host registration'):
            review.evaluation_requirements(scope, wire['envelope'])
        self.assertFalse(configured_store().state_root.exists())

    def test_intake_rebinds_the_same_bytes_to_the_current_verified_observation(self):
        """Check: an old prepared-only receipt cannot substitute for a current observed-dispatch receipt."""
        with tempfile.TemporaryDirectory() as temporary:
            store = HostRecordStore.for_tests(Path(temporary) / 'host')
            with using_test_store(store):
                prepared = store.write_dispatch(dispatch_id='work', dispatch_role='executor', provider='openai',
                    model_family=None, model_id=None, reasoning_effort=None, session_id=None,
                    request_sha256=sha(b'request'), evaluation_metadata={'peer_review_required': False})
                raw = b'exact original return\r\n'
                old_receipt = record_received_return(store, 'work', raw)
                current = store.write_observed_dispatch('work', prepared_record_sha256=prepared,
                    observation_sha256=sha(b'original host completion'), provider='openai', model_family='gpt',
                    model_id='gpt-6.1-sol', reasoning_effort='xhigh', session_id='original-session')
                with self.assertRaisesRegex(ValueError, 'receipt is missing'):
                    store.require_return('work', sha(raw))
                receipt = record_received_return(store, 'work', raw)
                self.assertNotEqual(receipt, old_receipt)
                self.assertEqual(store.require_return('work', sha(raw))['dispatch_record_sha256'], current)
                self.assertEqual(record_received_return(store, 'work', raw), receipt)
                self.assertEqual(len(store.find('return-received', dispatch_id='work', return_sha256=sha(raw))), 2)

    def test_provider_family_is_registry_derived_and_unknown_stays_unknown(self):
        """Check: route provider keys never masquerade as vendor identity."""
        with tempfile.TemporaryDirectory() as temporary:
            store = HostRecordStore.for_tests(Path(temporary) / 'host')
            with using_test_store(store):
                for executor, provider, expected in (
                        ('local_secure_review_worker', 'local_inference', 'local-openai-compatible'),
                        ('claude_code_manual', 'anthropic_manual', 'anthropic'),
                        ('unknown-executor', 'anthropic_manual', None),
                        ('local_secure_review_worker', 'anthropic_manual', None)):
                    dispatch_id = executor + '-' + provider
                    record_id = dispatch.record_prepared_dispatch(dispatch_id, provider=provider, executor=executor,
                                                                  request_sha256=sha(b'request'))
                    record = store.get(record_id)
                    self.assertEqual(record['provider'], expected)
                    self.assertEqual(record['provider_key'], provider)
                    self.assertIsNone(record['session_id'])


if __name__ == '__main__':
    unittest.main()
