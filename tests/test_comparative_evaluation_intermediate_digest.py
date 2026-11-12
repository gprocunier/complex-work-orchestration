import sys,tempfile,unittest
sys.path.insert(0,'scripts')
from tests.test_comparative_evaluation_locked_inputs import StudyCopy,reporting_amendment
class IntermediateDigest(unittest.TestCase):
 def test_intermediate_declared_digest_must_match_its_verified_bytes(self):
  with tempfile.TemporaryDirectory() as temp:
   study=StudyCopy(temp);lock=study.lock();first=study.protocol();study.write_json('history/v1.json',first)
   second=reporting_amendment(first);second['preregistration']['digest']='f'*64
   study.write_json('history/v2.json',second);study.write_json('protocol.json',reporting_amendment(second))
   code,report=study.score(study.records(lock),lock)
   self.assertEqual(code,1,'invalid intermediate declared digest was accepted as valid ancestry');self.assertNotIn('runs',report)

if __name__ == "__main__":
    unittest.main()
