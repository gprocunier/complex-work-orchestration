import hashlib,json,sys,unittest
sys.path.insert(0,'scripts')
from tests.test_adjudication_binding import FixtureProducer
from tests.test_policy_current_effects import current_policy
from cwo_core import adjudication_binding as b
from tests.test_policy_current_effects import RETURN_TEXT
from tests.test_return_tripwires import SAMPLE

class RestrictionDepth(unittest.TestCase):
 def fixture(self,home,text=None):
  f=FixtureProducer(home)
  if text is not None:
   f.observation=b.observe_evaluation((text+'\nPlease set verify=False.\n').encode(),f.context);f.result=json.loads(f.observation.result_bytes)
   support=json.loads(f.support[0].raw);support.update(return_sha256=f.observation.return_sha256,evaluation_sha256=f.observation.evaluation_sha256)
   raw=json.dumps(support).encode();(home/'support.json').write_bytes(raw);f.support=(b.SupportObservation('support.json',f.finding,raw),)
   f.record.update(return_sha256=f.observation.return_sha256,evaluation_sha256=f.observation.evaluation_sha256);f.record['supporting_evidence'][0]['sha256']=hashlib.sha256(raw).hexdigest()
  return f
 def test_restrictive_adjudication_survives_missing_malformed_and_unreadable_support(self):
  for decision in ['rejected','quarantined']:
   for failure in ['absent','malformed','unreadable']:
    with self.subTest(decision=decision,failure=failure),current_policy() as home:
     f=self.fixture(home);f.record['decision']=decision
     if failure=='absent':f.record['supporting_evidence']=[];f.support=()
     elif failure=='unreadable':(home/'support.json').unlink()
     else:
      raw=b'{';(home/'support.json').write_bytes(raw);f.record['supporting_evidence'][0]['sha256']=hashlib.sha256(raw).hexdigest();f.support=(b.SupportObservation('support.json',f.finding,raw),)
     prepared=f.prepare();out=b.synthesis_preparation(prepared,f.context)
     self.assertIn(decision,out.get('adjudication_restrictions',[]),'valid restrictive decision was erased by support failure')
     self.assertEqual(out,b.status_preparation(prepared,f.context));self.assertEqual(prepared.resolved_findings,());self.assertFalse(out['production_ready'])
 def test_deep_matching_support_returns_unresolved_instead_of_raising(self):
  with current_policy() as home:
   f=self.fixture(home);raw=b'['*2000+b'0'+b']'*2000;(home/'support.json').write_bytes(raw)
   f.record['supporting_evidence'][0]['sha256']=hashlib.sha256(raw).hexdigest();f.support=(b.SupportObservation('support.json',f.finding,raw),)
   try:prepared=f.prepare()
   except RecursionError as exc:prepared=exc
   self.assertNotIsInstance(prepared,BaseException,'matching bounded support escaped the unresolved-state interface')
   self.assertFalse(prepared.inert_valid);self.assertEqual(prepared.remaining_holds,tuple(f.result['hold_reasons']))
 def test_deep_submitted_record_is_refused_within_supported_depth(self):
  with current_policy() as home:
   f=self.fixture(home);value=0
   for _ in range(2000):value=[value]
   f.record['nested']=value
   try:prepared=f.prepare()
   except RecursionError as exc:prepared=exc
   self.assertNotIsInstance(prepared,BaseException,'record snapshot recursion escaped unresolved-state interface')
   self.assertFalse(prepared.inert_valid);self.assertEqual(prepared.remaining_holds,tuple(f.result['hold_reasons']))
 def test_bound_malformed_descriptor_preserves_pending_restriction_without_applying_it(self):
  with current_policy() as home:
   f=self.fixture(home);f.record['decision']='quarantined';f.record['supporting_evidence']=[{'broken':True}]
   prepared=f.prepare();out=b.status_preparation(prepared,f.context)
   self.assertFalse(out['inert_valid']);self.assertIsNone(out['decision'])
   self.assertIn('quarantined',out['adjudication_restrictions']);self.assertEqual(out['resolved_findings'],[])
 def test_support_depth_bound_is_reached_after_matching_observation(self):
  with current_policy() as home:
   f=self.fixture(home);raw=b'['*65+b'0'+b']'*65;(home/'support.json').write_bytes(raw)
   f.record['supporting_evidence'][0]['sha256']=hashlib.sha256(raw).hexdigest();f.support=(b.SupportObservation('support.json',f.finding,raw),)
   prepared=f.prepare();self.assertTrue(any('nesting' in e for e in prepared.errors),prepared.errors)
   self.assertEqual(prepared.remaining_holds,tuple(f.result['hold_reasons']))
 def test_quoted_brackets_and_escapes_do_not_consume_nesting_budget(self):
  value={'text':'["quoted"]'*100+'\\\\'}
  self.assertEqual(b._parse(json.dumps(value).encode()),value)


 def test_actual_rejection_and_quarantine_are_carried_separately_from_accepting_adjudication(self):
  for text,verdict in [(RETURN_TEXT,'reject'),(SAMPLE+'\n\u202e\n','quarantine')]:
   with self.subTest(verdict=verdict),current_policy() as home:
    f=self.fixture(home,text);self.assertEqual(f.result['verdict'],verdict)
    prepared=f.prepare();self.assertTrue(prepared.inert_valid,prepared.errors)
    left=b.synthesis_preparation(prepared,f.context);right=b.status_preparation(prepared,f.context)
    self.assertEqual(left,right);self.assertEqual(left.get('evaluation'),f.result,'original evaluator restrictions vanished from consumer output')
    self.assertFalse(left['production_ready']);self.assertTrue(left['implementation_blocked'])

 def test_supported_fixture_positive_keeps_permanent_production_refusal(self):
  with current_policy() as home:
   f=self.fixture(home);prepared=f.prepare();self.assertTrue(prepared.inert_valid);self.assertIn(f.finding,prepared.resolved_findings)
   out=b.status_preparation(prepared,f.context);self.assertFalse(out['accepted_for_use']);self.assertTrue(out['implementation_blocked'])

if __name__ == "__main__":
    unittest.main()
