"""Current revision containers must refuse before dependent consumers iterate them."""
import copy,sys,tempfile,unittest
sys.path.insert(0,'scripts')
from tests.test_comparative_evaluation_locked_inputs import StudyCopy,ce,reporting_amendment,reseal
class ContainerConsumerTests(unittest.TestCase):
 def call(self,action,*args,**kwargs):
  try:return action(*args,**kwargs)
  except Exception as exc:self.fail(f'container validation escaped structured result: {type(exc).__name__}: {exc}')
 def check_revision(self,study,first,lock,mutate):
  second=reporting_amendment(first);study.write_json('history/v1.json',first);study.write_json('protocol.json',second)
  code,good=self.call(study.score,study.records(lock),lock);self.assertEqual(code,0,good)
  mutate(second);study.write_json('protocol.json',reseal(second));hidden=ce.load_json(study.study/'hidden/checks.json')
  for entry in ['controller','direct-validator']:
   with self.subTest(entry=entry):
    if entry=='controller':
     code,report=self.call(study.score,study.records(lock),lock);self.assertEqual(code,1,report);self.assertTrue(report.get('errors'));self.assertNotIn('runs',report)
    else:self.assertTrue(self.call(ce.validate_protocol,second,hidden,root=study.study,history=[first]))
 def test_malformed_task_containers_refuse_at_controller_and_direct_validator(self):
  with tempfile.TemporaryDirectory() as temp:
   study=StudyCopy(temp);first=study.protocol();lock=study.lock()
   for value in [1,None,False,'not-an-array',{},[],[None]]:
    with self.subTest(tasks=value):self.check_revision(study,first,lock,lambda protocol:protocol.update(tasks=value))
 def test_every_malformed_stratum_is_rejected_not_filtered(self):
  with tempfile.TemporaryDirectory() as temp:
   study=StudyCopy(temp);first=study.protocol();lock=study.lock()
   for value in [None,1,[],{},'not-an-object']:
    with self.subTest(stratum=value):self.check_revision(study,first,lock,lambda protocol:protocol['strata'].append(value))
 def test_estimand_container_rows_reject_non_objects_without_losing_valid_projection(self):
  with tempfile.TemporaryDirectory() as temp:
   study=StudyCopy(temp);first=study.protocol();hidden=ce.load_json(study.study/'hidden/checks.json');self.assertEqual(self.call(ce.validate_protocol,first,hidden,root=study.study),[])
   for value in [None,1,[],'not-an-object']:
    with self.subTest(contrast=value):
     bad=copy.deepcopy(first);bad['estimands']['contrasts'].append(value);reseal(bad)
     self.assertTrue(self.call(ce.validate_protocol,bad,hidden,root=study.study),'a non-object estimand was silently filtered before comparison')
if __name__=='__main__':unittest.main()
