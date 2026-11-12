import sys,unittest,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(ROOT/'scripts'))
import evaluate_return
from cwo_core.returns import make_acceptance_decision
from tests.test_return_tripwires import SAMPLE
from tests.test_policy_current_effects import current_policy,RETURN_TEXT
import tests.test_alternate_evaluator_provenance as helpers
class AdvisoryProjection(unittest.TestCase):
 def assert_held(self,r):
  self.assertFalse(r['accepted_for_use'])
  self.assertTrue(r['evidence_use_hold'])
  self.assertTrue(r['implementation_blocked'])
  self.assertNotIn(r['verdict'],('accept','partial-accept','clarify'))
  self.assertNotIn(r['recommended_disposition'],('accept-findings','accept-bounded-findings'))
 def test_real_accepting_producer_gets_a_complete_nonproduction_hold(self):
  with current_policy():
   result=make_acceptance_decision(SAMPLE)
   self.assertEqual(result['verdict'],'accept');self.assertTrue(result['accepted_for_use'])
   original_score=result['score'];evaluate_return._mark_advisory(result)
   print(json.dumps({'case':'actual accepting scorer','verdict':result['verdict'],'accepted_for_use':result['accepted_for_use'],'evidence_use_hold':result['evidence_use_hold'],'recommended_disposition':result['recommended_disposition']}))
   self.assert_held(result);self.assertEqual(result['score'],original_score)
 def test_real_main_advisory_positive_scores_once_and_never_audits_or_accepts(self):
  with current_policy() as home:
   path=home/'sample.md';path.write_text(SAMPLE)
   raised,output,scores,audits=helpers.AlternateEvaluatorTests().invoke(['evaluate_return.py','--file',str(path),'--advisory','--no-audit','--waiver-reason','bounded diagnostic fixture','--json'])
   self.assertIsNone(raised);self.assertEqual((scores,audits),(1,0))
   result=json.loads(output);self.assertTrue(result['screening_eligible']);self.assertEqual(result['score'],make_acceptance_decision(SAMPLE)['score'])
   self.assert_held(result)
 def test_rejection_and_quarantine_from_real_scorer_are_not_weakened(self):
  with current_policy():
   for text,verdict in [(RETURN_TEXT,'reject'),(SAMPLE+'\n\u202e\n','quarantine')]:
    result=make_acceptance_decision(text,expected_return_language='en');self.assertEqual(result['verdict'],verdict)
    disposition=result['recommended_disposition'];use=result['recommended_synthesis_use']
    evaluate_return._mark_advisory(result)
    self.assertEqual(result['verdict'],verdict);self.assertEqual(result['recommended_disposition'],disposition);self.assertEqual(result['recommended_synthesis_use'],use)
    self.assert_held(result)
