import json,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,'scripts')
from tests.test_comparative_evaluation_locked_inputs import StudyCopy,reporting_amendment,reseal,run_cli,ce
class HistoryBoundary(unittest.TestCase):
 def score(self,study,lock):
  try:return study.score(study.records(lock),lock)
  except Exception as exc:self.fail(f'controller escaped structured refusal: {type(exc).__name__}: {exc}')
 def version_two(self,study):
  first=study.protocol();study.write_json('history/v1.json',first);second=reporting_amendment(first);study.write_json('protocol.json',second);return first,second
 def test_malformed_intermediate_amendments_refuse_structurally(self):
  with tempfile.TemporaryDirectory() as temp:
   study=StudyCopy(temp);lock=study.lock();first=study.protocol();second=reporting_amendment(first);third=reporting_amendment(second)
   second['preregistration']['amendments']={'bad':'not-array'};reseal(second)
   third['preregistration']['amendments'][-1]['prior_digest']=ce.preregistration_digest(second);reseal(third)
   study.write_json('history/v1.json',first);study.write_json('history/v2.json',second);study.write_json('protocol.json',third)
   code,report=self.score(study,lock);self.assertEqual(code,1);self.assertTrue(report['errors']);self.assertNotIn('runs',report)
 def test_bad_declared_predecessor_digest_refuses_lock(self):
  with tempfile.TemporaryDirectory() as temp:
   study=StudyCopy(temp);first,_=self.version_two(study);first['preregistration']['digest']='f'*64;study.write_json('history/v1.json',first)
   code,out,_=run_cli(['--root',str(study.study),'lock']);self.assertEqual(code,1,'lock accepted invalid declared predecessor digest');self.assertTrue(json.loads(out)['errors'])
 def test_unchanged_locked_v2_rechecks_history_and_keeps_valid_positive(self):
  with tempfile.TemporaryDirectory() as temp:
   study=StudyCopy(temp);first,_=self.version_two(study);lock=study.lock();code,report=self.score(study,lock);self.assertEqual(code,0,report);self.assertIn('runs',report)
   first['preregistration']['digest']='f'*64;study.write_json('history/v1.json',first)
   code,report=self.score(study,lock);self.assertEqual(code,1,'unchanged current manifest bypassed ancestor digest check');self.assertNotIn('runs',report)
 def test_one_actual_snapshot_of_prelock_history_for_reporting_revision(self):
  with tempfile.TemporaryDirectory() as temp:
   study=StudyCopy(temp);_,second=self.version_two(study);lock=study.lock();study.write_json('history/v2.json',second);study.write_json('protocol.json',reporting_amendment(second));wanted=study.study/'history/v1.json';reads=[];original=Path.open
   def observe(path,*args,**kwargs):
    if path==wanted:reads.append((args,kwargs))
    return original(path,*args,**kwargs)
   with patch.object(Path,'open',observe):code,report=self.score(study,lock)
   self.assertEqual(code,0,report);self.assertEqual(len(reads),1,'pre-lock predecessor was read more than once in one validation')
 def test_scoring_amendment_before_outcomes_still_refuses_after_lock(self):
  with tempfile.TemporaryDirectory() as temp:
   study=StudyCopy(temp);lock=study.lock();first=study.protocol();second=reporting_amendment(first,['scoring']);second['preregistration']['amendments'][-1]['recorded_before_outcomes']=True;reseal(second);study.write_json('history/v1.json',first);study.write_json('protocol.json',second)
   self.assertEqual(ce.validate_protocol(second,json.loads((study.study/'hidden/checks.json').read_text()),root=study.study),[],'positive prospective amendment must otherwise validate')
   code,report=self.score(study,lock);self.assertEqual(code,1);self.assertNotIn('runs',report)
 def test_snapshot_is_single_call_provenance_not_a_permanent_cache(self):
  with tempfile.TemporaryDirectory() as temp:
   study=StudyCopy(temp);_,second=self.version_two(study);lock=study.lock();study.write_json('history/v2.json',second);study.write_json('protocol.json',reporting_amendment(second));wanted=study.study/'history/v1.json';original=ce._read_regular;seen=[]
   def mutate_after_read(path):
    raw=original(path)
    if path==wanted:
     seen.append(path);bad=json.loads(raw);bad['preregistration']['digest']='f'*64;wanted.write_text(json.dumps(bad))
    return raw
   with patch.object(ce,'_read_regular',side_effect=mutate_after_read):bundle,errors=ce.load_locked_bundle(lock,study.repo)
   self.assertEqual(errors,[]);self.assertIsNotNone(bundle);self.assertEqual(len(seen),1)
   bundle,errors=ce.load_locked_bundle(lock,study.repo);self.assertIsNone(bundle);self.assertTrue(errors)
 def test_read_refusal_is_retained_within_call_but_not_across_calls(self):
  with tempfile.TemporaryDirectory() as temp:
   study=StudyCopy(temp);_,second=self.version_two(study);lock=study.lock();study.write_json('history/v2.json',second);study.write_json('protocol.json',reporting_amendment(second));wanted=study.study/'history/v1.json';original=ce._read_regular;seen=[]
   def temporarily_unreadable(path):
    if path==wanted:
     seen.append(path)
     if len(seen)==1:raise OSError('fixture first read refused')
    return original(path)
   with patch.object(ce,'_read_regular',side_effect=temporarily_unreadable):bundle,errors=ce.load_locked_bundle(lock,study.repo)
   self.assertIsNone(bundle);self.assertTrue(errors);self.assertEqual(len(seen),1)
   bundle,errors=ce.load_locked_bundle(lock,study.repo);self.assertIsNotNone(bundle);self.assertEqual(errors,[])

if __name__=='__main__':unittest.main()
