"""Evidence parsing and operative-segment budget selection."""
from __future__ import annotations

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from cwo_core import native_session as session


class F9SessionEvidence(unittest.TestCase):
    @staticmethod
    def budget():
        return dict(tool_calls_soft=0, tool_calls_hard=0, runtime_seconds_soft=100,
            runtime_seconds_hard=200, max_compactions=0, max_full_suite_runs=0)

    def test_F9_1a5ca33283269505_nonzero_token_counts_are_observed(self):
        value = session._parse_token_count({'token_count': {'input': 5, 'output': 7, 'total': 12}})
        self.assertEqual((value['input'], value['output'], value['total']), (5, 7, 12))
        self.assertIsNone(session._parse_token_count(None))
        self.assertIsNone(session._parse_token_count({}))

    def test_F9_e44083f6267c4307_9177e82c37720a14_fallback_model_is_not_direct_attestation(self):
        for explicit in (False, True):
            for direct in (False, True):
                context = {'model' if direct else 'attested_model': 'gpt-6.1-sol'}
                first = dict(timestamp=0, turn_context=context)
                if explicit:
                    first['event_msg'] = 'task_started'
                else:
                    first['response_item'] = {'type': 'message', 'role': 'user'}
                records = [first, dict(timestamp=1, event_msg='task_complete')]
                with self.subTest(explicit=explicit, direct=direct):
                    segments, _, _, _ = session._evaluate_records(records, self.budget(), 'gpt-6.1-sol', None)
                    self.assertEqual(segments[0]['attestation_source'], 'turn_context' if direct else 'untrusted')

    def test_F9_5097b8860c4bc91e_empty_trailing_segment_cannot_clear_exhausted_work(self):
        model = {'model': 'gpt-6.1-sol'}
        records = [
            dict(timestamp=0, event_msg='task_started', turn_context=model),
            dict(timestamp=1, response_item={'type': 'function_call', 'name': 'exec_command', 'arguments': '{}'}),
            dict(timestamp=2, event_msg='task_complete'),
            dict(timestamp=3, event_msg='task_started', turn_context=model),
            dict(timestamp=4, event_msg='task_complete'),
        ]
        segments, aggregate, status, selected = session._evaluate_records(records, self.budget(), 'gpt-6.1-sol', None)
        self.assertEqual(aggregate['tool_calls'], 1)
        self.assertIs(selected, segments[0])
        self.assertEqual(status, 'budget-exhausted')
        self.assertNotEqual(selected['session_disposition'], 'active')
        # A genuinely operative final segment becomes the current selection.
        records.insert(-1, dict(timestamp=3.5, response_item={'type': 'function_call', 'name': 'exec_command', 'arguments': '{}'}))
        segments, _, _, selected = session._evaluate_records(records, self.budget(), 'gpt-6.1-sol', None)
        self.assertIs(selected, segments[-1])
