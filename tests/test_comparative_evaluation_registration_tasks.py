import copy,sys,tempfile,unittest
sys.path.insert(0,'scripts')
from tests.test_comparative_evaluation_locked_inputs import StudyCopy,reporting_amendment,reseal
class RegistrationAndTask(unittest.TestCase):
 def score(self,study,runs,lock):
  try:return study.score(runs,lock)
  except Exception as exc:self.fail(f'controller escaped structured refusal: {type(exc).__name__}: {exc}')
 def test_reporting_revision_cannot_change_other_registration_metadata(self):
  with tempfile.TemporaryDirectory() as temp:
   study=StudyCopy(temp);lock=study.lock();first=study.protocol();study.write_json('history/v1.json',first);second=reporting_amendment(first);study.write_json('protocol.json',second)
   code,good=self.score(study,study.records(lock),lock);self.assertEqual(code,0,good)
   second['preregistration']['frozen_on']='2099-01-01';reseal(second);study.write_json('protocol.json',second)
   code,report=self.score(study,study.records(lock),lock);self.assertEqual(code,1,'reporting-only revision changed frozen registration metadata');self.assertNotIn('runs',report)
 def test_malformed_task_values_refuse_with_errors_and_no_rows(self):
  with tempfile.TemporaryDirectory() as temp:
   study=StudyCopy(temp);lock=study.lock();original=study.records(lock);code,good=self.score(study,original,lock);self.assertEqual(code,0,good)
   for value in [[],{},['task'],{'task':'fake'},None,False,0]:
    with self.subTest(value=value):
     runs=copy.deepcopy(original);runs[0]['task']=value;code,report=self.score(study,runs,lock);self.assertEqual(code,1);self.assertTrue(report['errors']);self.assertNotIn('runs',report)
if __name__=='__main__':unittest.main()
