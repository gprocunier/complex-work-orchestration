"""Offline synthesis from original-host observations of two critic camps."""
from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))

from build_contractor_packet import main as build_main
from cwo_core.codex_critic_capture import (
    prepare_codex_peer_review_request,
    record_codex_critic_completion,
    record_codex_peer_review_completion,
)
from cwo_core.host_acceptance import _host_inputs, record_received_evaluation
from cwo_core.host_records import HostRecordStore, using_test_store
from cwo_core.manual_gemini_critic import record_gemini_critic_completion
from cwo_core.model_identities import resolve_model
from cwo_core.peer_review import pending_evaluation_sha256
from cwo_core.policy import configured_gemini_critic
from cwo_core.returns import make_acceptance_decision
from dispatch_work import main as dispatch_main
from evaluate_return import main as evaluate_main
from evaluate_synthesis import main as synthesis_main
from tests.test_codex_critic_capture import OriginalCodexProcess, jsonl, sha
from tests.test_zero_trust_consensus import claim


CANDIDATE = 'retry-plan-original'
SCOPE = 'retry-log-design'
QUESTION = 'What is the proposed retry-log encryption key rotation interval?'
JOB = 'contract-jd-architecture-reasoning'


class OriginalCriticSynthesisTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.store = HostRecordStore.for_tests(self.root / 'host')
        self.enterContext(using_test_store(self.store))
        self.validation = b'Independent fixture inspection of the retry-log key rotation requirement.\n'
        (self.root / 'validation.txt').write_bytes(self.validation)

    def _write_json(self, name, value):
        path = self.root / name
        path.write_text(json.dumps(value), encoding='utf-8')
        return str(path)

    @staticmethod
    def _run_cli(name, entry, *args):
        stdout = StringIO()
        with patch.object(sys, 'argv', [name, *args]), redirect_stdout(stdout):
            entry()
        return json.loads(stdout.getvalue())

    @staticmethod
    def _return(value):
        sample = (ROOT / 'examples' / 'sample-contractor-return.md').read_text(encoding='utf-8')
        return (sample.replace('contract-jd-security-reasoning', JOB)
                .replace('not required for this sample return', 'independent review when required')
                .replace('Risks or gaps:', f'Validation finding: Rotate the retry-log key every {value} days.\nRisks or gaps:'))

    def _codex(self):
        request = (QUESTION + '\nUse the original contractor return template.\n').encode()
        self.store.write_dispatch(dispatch_id='codex', dispatch_role='executor', provider='openai',
            model_family=None, model_id=None, reasoning_effort=None, session_id=None,
            request_sha256=sha(request), bead_id='retry-architecture', executor='codex_architecture_critic',
            provider_key='internal_codex', evaluation_metadata=dict(dispatch_mode='main_thread_review',
                share_boundary='redacted-packet', job_description_label=JOB, peer_review_required=False))
        process = OriginalCodexProcess(self.root, request, self._return('3'))
        observed = record_codex_critic_completion(self.store, 'codex', request=request, **process.inputs())
        dispatch = self.store.require_dispatch('codex')
        report = observed.final.decode()
        evaluation = make_acceptance_decision(report, **_host_inputs(dispatch, dispatch['bead_id'], 'codex'))
        self.assertTrue(evaluation['accepted_for_use'], evaluation['penalty_reasons'])
        evaluation_id = record_received_evaluation(report, evaluation)
        return self._lane('codex', '3', observed.final, evaluation_id)

    def _prepare_gemini(self):
        bead = self._write_json('gemini-bead.json', dict(id='retry-architecture', title=QUESTION,
            description='Review the public plan for the local retry log.', labels=['contractor-only', 'no-codex-exec', JOB]))
        packet = self._run_cli('build_contractor_packet.py', build_main, '--bead', 'retry-architecture',
            '--bead-json-file', bead, '--executor', 'gemini_architecture_critic', '--external-ok',
            '--epic', 'original-critic-synthesis', '--share-boundary', 'redacted-packet', '--format', 'json',
            '--dispatch-id', 'gemini')
        packet_path = self._write_json('gemini-packet.json', packet)
        preparation = self._run_cli('dispatch_work.py', dispatch_main, '--packet', packet_path, '--json')
        return packet_path, preparation['manual_prompt']

    def _gemini(self, value):
        packet, prompt = self._prepare_gemini()
        report = self._return(value)
        conversation = '0d8a007f-8426-4fd1-933a-e2da67d88714'
        steps = [dict(type='USER_INPUT', source='USER_EXPLICIT', status='DONE', step_index=0,
                      content=f'<USER_REQUEST>\n{prompt}\n</USER_REQUEST>'),
                 dict(type='PLANNER_RESPONSE', source='MODEL', status='DONE', step_index=1,
                      model=configured_gemini_critic()['model'], content=report[:-1])]
        stdout = dict(conversation_id=conversation, status='SUCCESS', num_turns=1, response=report)
        record_gemini_critic_completion(self.store, 'gemini', screened_prompt=prompt.encode(),
            stdout=json.dumps(stdout).encode(), full_transcript=jsonl(steps), conversation_id=conversation)
        return packet, report.encode()

    def _gemini_reviewed(self, value):
        packet, raw = self._gemini(value)
        return_path = self.root / 'gemini.md'
        return_path.write_bytes(raw)
        evaluator = ('--contractor-packet', packet, '--file', str(return_path), '--json', '--peer-review-required')
        pending = self._run_cli('evaluate_return.py', evaluate_main, *evaluator, '--peer-review-status', 'pending')
        self.assertIn('peer-review-pending', pending['hold_reasons'])
        self.assertFalse(pending['accepted_for_use'])
        request = prepare_codex_peer_review_request(self.store, 'peer', target_dispatch_id='gemini', target_return=raw)
        reviewer = dict(provider='openai', model_family='gpt', model_id=resolve_model('sol'),
                        reasoning_effort='xhigh', dispatch_id='peer')
        decision = dict(record_type='cwo-peer-review', version=2, decision='passed', reviewer_identity=reviewer,
                        return_sha256=sha(raw), evaluation_sha256=pending_evaluation_sha256(pending))
        self.assertEqual(request.target, dict(dispatch_id='gemini', return_sha256=sha(raw),
                                              evaluation_sha256=decision['evaluation_sha256']))
        original = OriginalCodexProcess(self.root, request.request, json.dumps(decision),
                                        session='019a0000-0000-7000-8000-000000000002')
        record_codex_peer_review_completion(self.store, request, target_return=raw, **original.inputs())
        evaluated = self._run_cli('evaluate_return.py', evaluate_main, *evaluator, '--peer-review-status', 'passed',
            '--peer-review-reviewer', json.dumps(reviewer), '--peer-review-record', self._write_json('peer.json', decision))
        self.assertTrue(evaluated['accepted_for_use'], evaluated['hold_reasons'])
        self.assertEqual(evaluated['recommended_synthesis_use'], 'salvage-only')
        evaluation, = self.store.find('evaluation', dispatch_id='gemini', evaluation_sha256=pending_evaluation_sha256(evaluated))
        lane, adjudication = self._lane('gemini', value, raw, evaluation['_record_sha256'])
        return dict(lane, synthesis_use='primary'), adjudication

    def _lane(self, lane, value, raw, evaluation_ref):
        path = self.root / f'{lane}.md'
        path.write_bytes(raw)
        item = {'return': path.name, 'evaluation_record_sha256': evaluation_ref,
                'zero_trust_claims': [dict(claim('crypto', 'key_rotation_days', value), evidence='Validation finding')]}
        decision = dict(record_type='cwo-return-adjudication', version=1, adjudication_id=f'lead-{lane}',
            dispatch_id=lane, return_sha256=sha(raw), candidate=CANDIDATE, scope=SCOPE,
            finding_ids=['finding:key-rotation'], decision='accepted', rationale='Reviewed the exact reported finding.',
            supporting_evidence=[dict(artifact='validation.txt', artifact_type='validation-log',
                sha256=sha(self.validation), finding_ids=['finding:key-rotation'])],
            authority={'rule': 'synthesis-input-adjudication'}, adjudicator='lead')
        return item, decision

    def _synthesize(self, gemini_value):
        inputs, adjudications = zip(self._codex(), self._gemini_reviewed(gemini_value))
        return self._run_cli('evaluate_synthesis.py', synthesis_main, '--candidate', CANDIDATE, '--scope', SCOPE,
            '--inputs', self._write_json('inputs.json', inputs), '--zero-trust-required',
            '--adjudications', self._write_json('adjudications.json', adjudications))

    def test_two_original_camps_agree_after_independent_review(self):
        result = self._synthesize('3')
        self.assertEqual(result['status'], 'ready', result['blocked_reasons'])
        self.assertEqual(result['primary_input_count'], 2)
        self.assertFalse(result['execution_permitted'])
        consensus = result['zero_trust_consensus']
        self.assertEqual(consensus['independent_trust_domains'], ['google', 'openai'])
        self.assertEqual(consensus['comparable_claim_count'], 1)
        self.assertEqual(consensus['consensus_status'], 'informational')

    def test_material_disagreement_between_original_camps_blocks(self):
        result = self._synthesize('4')
        self.assertEqual(result['primary_input_count'], 2)
        self.assertEqual(result['status'], 'blocked')
        consensus = result['zero_trust_consensus']
        self.assertEqual(consensus['recommended_action'], 'escalate')
        self.assertEqual(consensus['divergence_report'][0]['resolution_authority'], 'architect')


if __name__ == '__main__':
    unittest.main()
