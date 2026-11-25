"""Offline witness for original Gemini critic completion intake."""
from hashlib import sha256
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))

from cwo_core.errors import CWOPolicyError
from cwo_core.host_records import HostRecordStore
from cwo_core.manual_gemini_critic import _completed_return, record_gemini_critic_completion
from cwo_core.policy import configured_gemini_critic


class ManualGeminiCriticTests(unittest.TestCase):
    def setUp(self):
        self.store = HostRecordStore.for_tests(Path(self.enterContext(tempfile.TemporaryDirectory())) / 'host')
        self.dispatch_id = 'prepared-gemini'
        self.conversation = '0d8a007f-8426-4fd1-933a-e2da67d88714'
        self.prompt = 'Review the screened design.\nReturn evidence.'
        self.answer = 'The design needs an independent check.\n'
        self.config = configured_gemini_critic()
        self.metadata = dict(dispatch_mode='manual_ui', peer_review_required=True,
                             provider_conflict_domains=['model-provider-competition'])
        self.prepared = self.store.write_dispatch(dispatch_id=self.dispatch_id, dispatch_role='executor',
            provider='google', model_family=None, model_id=None, reasoning_effort=None, session_id=None,
            packet_sha256='a' * 64, request_sha256=sha256(self.prompt.encode()).hexdigest(),
            executor='gemini_architecture_critic', provider_key='google_gemini_manual',
            bead_id='task', evaluation_metadata=self.metadata)
        self.stdout = dict(conversation_id=self.conversation, status='SUCCESS', num_turns=1,
                           response=self.answer, usage={}, duration_seconds=0.5)
        self.rows = [
            dict(type='USER_INPUT', source='USER_EXPLICIT', status='DONE', step_index=0,
                 content=f'<USER_REQUEST>\n{self.prompt}\n</USER_REQUEST>\n<ADDITIONAL_METADATA>\n'
                         'The current local time is: 2026-11-25T12:12:07-05:00.\n</ADDITIONAL_METADATA>'),
            dict(type='PLANNER_RESPONSE', source='MODEL', status='DONE', step_index=1,
                 content=self.answer[:-1], model=self.config['model']),
        ]

    def _record(self, *, stdout=None, rows=None, **changes):
        args = dict(screened_prompt=self.prompt.encode(), conversation_id=self.conversation,
                    stdout=json.dumps(self.stdout if stdout is None else stdout).encode(),
                    full_transcript=b''.join(json.dumps(row).encode() + b'\n'
                                             for row in (self.rows if rows is None else rows)))
        return record_gemini_critic_completion(self.store, self.dispatch_id, **(args | changes))

    def test_captures_original_completion_and_keeps_prepared_hold(self):
        result = self._record()
        digest = sha256(self.answer.encode()).hexdigest()
        receipt = self.store.require_return(self.dispatch_id, digest)
        observed = self.store.require_dispatch(self.dispatch_id)
        self.assertEqual(result, receipt['_record_sha256'])
        self.assertEqual(receipt['return_sha256'], digest)
        self.assertEqual(receipt['capture_provenance'], 'host-capture-v1')
        self.assertEqual(receipt['dispatch_record_sha256'], observed['_record_sha256'])
        self.assertEqual(observed['prepared_record_sha256'], self.prepared)
        self.assertEqual(observed['evaluation_metadata'], self.metadata)
        self.assertEqual(observed['stage'], 'observed')
        self.assertEqual((observed['model_id'], observed['reasoning_effort'], observed['session_id']),
                         (self.config['model'], self.config['effort'], self.conversation))
        audit = self.store.audit_events()
        self.assertEqual(self._record(), result)
        self.assertEqual(self.store.audit_events(), audit)
        with self.assertRaisesRegex(CWOPolicyError, 'differs from the original observation'):
            self._record(stdout=dict(self.stdout, duration_seconds=0.6))
        self.assertEqual(self.store.audit_events(), audit)

    def test_held_return_receipt_write_can_retry_same_observed_completion(self):
        with patch.object(self.store, 'write_return_received', side_effect=OSError('temporary error')):
            with self.assertRaisesRegex(OSError, 'temporary error'):
                self._record()
        self.assertEqual(self.store.require_dispatch(self.dispatch_id)['stage'], 'observed')
        self.assertEqual(self._record(), self.store.require_return(self.dispatch_id,
                         sha256(self.answer.encode()).hexdigest())['_record_sha256'])

    def test_valid_completion_from_a_different_prompt_does_not_promote_dispatch(self):
        request, response = self.rows
        other = 'Review a different screened request.'
        request = dict(request, content=request['content'].replace(self.prompt, other))
        before = self.store.audit_events()
        with self.assertRaisesRegex(CWOPolicyError, 'prompt differs from the prepared dispatch'):
            self._record(rows=[request, response], screened_prompt=other.encode())
        self.assertEqual(self.store.audit_events(), before)

    def test_plan_mode_wraps_exact_screened_text_and_multiline_metadata(self):
        prompt = self.prompt + '\n'
        content = (f'<USER_REQUEST>\n/plan {prompt}</USER_REQUEST>\n'
                   '<ADDITIONAL_METADATA>\nTimestamp line.\n<PLAN>\nFirst line.\nSecond line.\n</PLAN>\n'
                   '</ADDITIONAL_METADATA>\n<USER_SETTINGS_CHANGE>\nFirst setting.\nSecond setting.\n'
                   '</USER_SETTINGS_CHANGE>')
        _, response = self.rows

        def validate(text):
            request = dict(self.rows[0], content=text)
            transcript = b''.join(json.dumps(row).encode() + b'\n' for row in (request, response))
            return _completed_return(prompt.encode(), json.dumps(self.stdout).encode(), transcript,
                                     self.conversation, self.config['model'])

        self.assertEqual(validate(content), (self.config['model'], self.answer.encode()))
        for alternate in (
            content.replace('/plan ', '/other '),
            content.replace('/plan ', '/plan  '),
            content.replace(prompt, prompt.rstrip('\n')),
            content.replace('First line.', '<USER_REQUEST>\nAnother request.\n</USER_REQUEST>'),
            content.replace('First line.', '<PLAN>\nNested plan.\n</PLAN>'),
            content.replace('First setting.', '<ADDITIONAL_METADATA>\nDuplicate.\n</ADDITIONAL_METADATA>'),
            content + '\n<OTHER_SOURCE>extraneous source</OTHER_SOURCE>',
        ):
            with self.subTest(case=len(alternate)), self.assertRaisesRegex(CWOPolicyError, 'exact screened prompt'):
                validate(alternate)

    def test_discards_invalid_artifacts_before_any_host_write(self):
        before = self.store.audit_events()
        request, response = self.rows
        invalid = (
            dict(screened_prompt=b'Changed request'),
            dict(rows=[dict(request, content='x' + request['content']), response]),
            dict(rows=[dict(request, content=request['content'] + '\nunauthorized'), response]),
            dict(rows=[request, dict(response, model='unobserved-model')]),
            dict(rows=[request, dict(response, model=None)]),
            dict(rows=[request, dict(response, status='FAILED')]),
            dict(rows=[request, dict(response, truncated_fields=['content'])]),
            dict(rows=[request, dict(response, truncated_fields=[])]),
            dict(rows=[request, response, dict(response, step_index=2)]),
            dict(rows=[request, dict(response, step_index=True)]),
            dict(stdout=dict(self.stdout, response=response['content'])),
            dict(stdout=dict(self.stdout, response=self.answer + '\n')),
            dict(stdout=dict(self.stdout, num_turns=True)),
            dict(stdout=dict(self.stdout, status='FAILURE')),
            dict(conversation_id='419321fa-8876-4c0f-a37c-c800d681a6cf'),
            dict(full_transcript=b'x' * (4 * 1024 * 1024 + 1)),
            dict(full_transcript=b'\xff'),
            dict(full_transcript=b'{"status":"DONE","status":"FAILED"}\n{}\n'),
        )
        for index, options in enumerate(invalid):
            with self.subTest(case=index), self.assertRaises(CWOPolicyError):
                self._record(**options)
        self.assertEqual(self.store.audit_events(), before)
        self.assertEqual(self.store.require_dispatch(self.dispatch_id)['_record_sha256'], self.prepared)


if __name__ == '__main__':
    unittest.main()
