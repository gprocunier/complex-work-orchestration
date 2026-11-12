"""Production alternate selectors cannot substitute caller JSON for provenance."""
import contextlib
import io
import json
import sys
import tempfile
import unittest
from unittest import mock

import tests.test_packet_production_provenance as fixture
from tests.test_policy_current_effects import current_policy, RETURN_TEXT
import evaluate_return
import dispatch_work
import normalize_contractor_return
import prepare_native_worker
from tests.historical_policy_fixtures import historical_v2_policy


class AlternateEvaluatorTests(unittest.TestCase):
    def invoke(self, argv):
        stdout = io.StringIO()
        with mock.patch.object(sys, 'argv', argv), contextlib.redirect_stdout(stdout), \
                mock.patch.object(evaluate_return, 'make_acceptance_decision', wraps=evaluate_return.make_acceptance_decision) as score, \
                mock.patch.object(evaluate_return, 'record_audit_event', wraps=evaluate_return.record_audit_event) as audit:
            raised = None
            try: evaluate_return.main()
            except SystemExit as exc: raised = exc
        return raised, stdout.getvalue(), score.call_count, audit.call_count

    def test_local_artifacts_refused_before_score_audit_output(self):
        helper = fixture.ProvenanceCase()
        with current_policy() as home:
            return_file = home/'return.md';return_file.write_text(RETURN_TEXT)
            packet = helper.build(home, '--rehearsal', dispatch_id='alternate-rehearsal')
            artifacts = {'labelled packet': helper.write(home, packet, 'labelled.json'),
                         'stripped packet': helper.write(home, helper.strip_and_rehash(packet), 'stripped.json')}
            artifacts.update(fixture.RehearsalOutputTests().rehearsal_outputs(home))
            # A real browser dry-run output is generated through the common
            # production-packet fixture; it remains an unrelated result shape.
            browser = helper.write(home, helper.build(home, dispatch_id='browser-prod', executor=fixture.BROWSER_EXECUTOR), 'browser.json')
            config = fixture.write_browser_config(home)
            out = io.StringIO()
            with mock.patch.object(sys, 'argv', ['chatgpt_browser_review.py', '--packet', str(browser), '--config', str(config), '--dry-run']), contextlib.redirect_stdout(out):
                fixture.chatgpt_browser_review.main()
            artifacts['browser dry run'] = helper.write(home, json.loads(out.getvalue()), 'browser-result.json')
            for label, artifact in artifacts.items():
                with self.subTest(label=label):
                    before = fixture.audit_bytes(home)
                    raised, output, scores, audits = self.invoke(['evaluate_return.py', '--file', str(return_file), '--local-dispatch-result', str(artifact), '--json'])
                    self.assertIsNotNone(raised, 'unqualified local result reached production acceptance')
                    self.assertIn('production provenance', str(raised))
                    self.assertEqual((output, scores, audits), ('', 0, 0))
                    self.assertEqual(fixture.audit_bytes(home), before)

    def test_raw_metadata_refused_before_score_audit_output(self):
        with current_policy() as home:
            return_file = home/'return.md';return_file.write_text(RETURN_TEXT)
            combinations = [[], ['--bead','task'], ['--executor','claude_code_manual'],
                            ['--dispatch-id','d','--packet-sha256','a'*64],
                            ['--provider-key','anthropic_api','--provider-trust-tier','external'],
                            ['--share-boundary','redacted-packet','--dispatch-mode','manual'],
                            ['--local-profile','openshift-ai-vllm','--model-profile','glm']]
            for flags in combinations:
                with self.subTest(flags=flags):
                    before = fixture.audit_bytes(home)
                    raised, output, scores, audits = self.invoke(['evaluate_return.py','--file',str(return_file),'--json',*flags])
                    self.assertIsNotNone(raised, 'raw metadata reached production acceptance')
                    self.assertIn('production provenance', str(raised))
                    self.assertEqual((output,scores,audits),('',0,0))
                    self.assertEqual(fixture.audit_bytes(home),before)

    def test_production_score_audit_and_advisory_controls(self):
        helper = fixture.ProvenanceCase()
        with current_policy() as home:
            return_file=home/'return.md';return_file.write_text(RETURN_TEXT)
            packet=helper.write(home,helper.build(home,dispatch_id='production-control'),'prod.json')
            raised, output, scores, audits = self.invoke(['evaluate_return.py','--file',str(return_file),'--contractor-packet',str(packet),'--json'])
            self.assertIsNone(raised);self.assertEqual((scores,audits),(1,1));self.assertIn('verdict',json.loads(output))
            raised, output, scores, audits = self.invoke(['evaluate_return.py','--file',str(return_file),'--advisory','--no-audit','--waiver-reason','advisory fixture','--json'])
            self.assertIsNone(raised);self.assertEqual((scores,audits),(1,0))
            result=json.loads(output);self.assertEqual(result['result_class'],'advisory-nonproduction')
            self.assertTrue(result['implementation_blocked']);self.assertIn('nonproduction-advisory: unqualified source',result['hold_reasons'])

    def test_advisory_does_not_weaken_existing_restrictions(self):
        for use in ('reject','quarantine','partial-only','open-risk'):
            with self.subTest(use=use):
                result={'recommended_synthesis_use':use,'hold_classification':'original',
                        'hold_reasons':['unrelated hold']}
                evaluate_return._mark_advisory(result)
                self.assertEqual(result['recommended_synthesis_use'],use)
                self.assertEqual(result['hold_classification'],'original')
                self.assertIn('unrelated hold',result['hold_reasons'])
                self.assertTrue(result['implementation_blocked'])

    def test_normalizer_real_writer_control_and_sentinel(self):
        helper = fixture.ProvenanceCase()
        with current_policy() as home:
            return_file=home/'return.md';return_file.write_text(RETURN_TEXT)
            prod=helper.write(home,helper.build(home,dispatch_id='writer-prod'),'prod.json')
            with mock.patch.object(sys, 'argv', ['dispatch_work.py', '--packet', str(prod)]), \
                    contextlib.redirect_stdout(io.StringIO()):
                dispatch_work.main()
            output=home/'normalized.json'
            def call(packet):
                with mock.patch.object(sys,'argv',['normalize_contractor_return.py','--file',str(return_file),'--contractor-packet',str(packet),'--output',str(output)]), \
                        mock.patch.object(normalize_contractor_return,'atomic_write_text',wraps=normalize_contractor_return.atomic_write_text) as writer:
                    error=None
                    try:normalize_contractor_return.main()
                    except SystemExit as exc:error=exc
                return error,writer.call_count
            error,writes=call(prod);self.assertIsNone(error);self.assertEqual(writes,1);self.assertTrue(output.exists())
            output.write_text('sentinel stays unchanged')
            bad=helper.write(home,helper.strip_and_rehash(helper.build(home,'--rehearsal',dispatch_id='writer-red')),'bad.json')
            error,writes=call(bad);self.assertIsNotNone(error);self.assertEqual(writes,0);self.assertEqual(output.read_text(),'sentinel stays unchanged')


class DeprecatedCreationTests(unittest.TestCase):
    def test_spark_refused_before_reservation_or_packet(self):
        with tempfile.TemporaryDirectory() as workdir, \
                mock.patch.object(prepare_native_worker,'reserve_precommit_receipt') as reserve, \
                mock.patch.object(prepare_native_worker,'_build_native_worker_packet_unreserved', wraps=prepare_native_worker._build_native_worker_packet_unreserved) as build:
            with self.assertRaisesRegex(SystemExit,'historical-nonoperative'):
                prepare_native_worker.build_native_worker_packet(bead_id='deprecated',lane='review',workdir=workdir,allowed_paths=['.'],acceptance_checks=['review'],requested_model='gpt-5.3-codex-spark')
            self.assertEqual(reserve.call_count,0);self.assertEqual(build.call_count,0)

    def test_historical_packet_still_readable(self):
        with tempfile.TemporaryDirectory() as workdir:
            with historical_v2_policy():
                packet=prepare_native_worker.build_native_worker_packet(bead_id='historical',lane='review',workdir=workdir,allowed_paths=['.'],acceptance_checks=['review'])
            self.assertEqual(prepare_native_worker.validate_native_worker_packet(packet),[])
            self.assertTrue(prepare_native_worker.validate_native_worker_packet(packet,dispatchable=True))


if __name__=='__main__':unittest.main()
