
from typing import NamedTuple
import copy,json,sys,tempfile,unittest
sys.path.insert(0,'scripts')
from tests.test_comparative_evaluation_locked_inputs import StudyCopy,reporting_amendment,reseal
class LockedCopyCase(NamedTuple):
    original: str
    copy_version: int


class LockedAncestorTests(unittest.TestCase):
 def fork(self,wrong_version):
  with tempfile.TemporaryDirectory() as temp:
   study=StudyCopy(temp);lock=study.lock();runs=study.records(lock)
   original=(study.study/'protocol.json').read_bytes();fork=json.loads(original)
   fork['scoring']['interventions']='any message or action from a person during a run';reseal(fork)
   study.write_json('history/v1.json',fork);(study.study/'history'/f'v{wrong_version}.json').write_bytes(original)
   study.write_json('protocol.json',reporting_amendment(fork))
   code,report=study.score(runs,lock)
   print(json.dumps({'case':'fork with wrong-version copy','copy_version':wrong_version,'code':code,'reporting_revision':report.get('reporting_revision'),'included':next((r['comparison'] for r in report.get('runs',[]) if r['run_id']=='r17-overhead-slugify-baseline'),None)}))
   self.assertEqual(code,1,'substituted locked-version history was accepted as reporting ancestry')
   self.assertNotIn('runs',report)
 def test_wrong_locked_version_copy_rows(self):
     rows = (
            LockedCopyCase('test_substituted_locked_version_cannot_be_rescued_by_v0_copy', 0),
            LockedCopyCase('test_identical_wrong_version_v9_cannot_rescue_the_chain', 9),
     )
     for row in rows:
         with self.subTest(original=row.original):
             self.fork(row.copy_version)
 def test_intermediate_scoring_amendment_followed_by_reporting_refuses(self):
  with tempfile.TemporaryDirectory() as temp:
   study=StudyCopy(temp);lock=study.lock();original=(study.study/'protocol.json').read_bytes();old=json.loads(original)
   study.write_json('history/v1.json',old);second=reporting_amendment(old,['scoring']);study.write_json('history/v2.json',second)
   study.write_json('protocol.json',reporting_amendment(second));code,report=study.score(study.records(lock),lock)
   self.assertEqual(code,1);self.assertNotIn('runs',report)
 def test_valid_reporting_chain_keeps_original_scoring_and_unknowns(self):
  with tempfile.TemporaryDirectory() as temp:
   study=StudyCopy(temp);lock=study.lock();runs=study.records(lock);code,before=study.score(runs,lock);self.assertEqual(code,0)
   old=study.protocol();study.write_json('history/v1.json',old);second=reporting_amendment(old);study.write_json('history/v2.json',second)
   study.write_json('protocol.json',reporting_amendment(second));code,after=study.score(runs,lock);self.assertEqual(code,0,after)
   for key in ['runs','summary','estimands','protocol_digest']:self.assertEqual(after[key],before[key])
   self.assertEqual(after['reporting_revision']['version'],3)
 def test_locked_version_two_is_anchored_at_its_own_slot(self):
  with tempfile.TemporaryDirectory() as temp:
   study=StudyCopy(temp);first=study.protocol();study.write_json('history/v1.json',first);second=reporting_amendment(first);study.write_json('protocol.json',second)
   lock=study.lock();runs=study.records(lock);original=(study.study/'protocol.json').read_bytes()
   fork=copy.deepcopy(second);fork['reporting']['public_release_note']+=' substituted locked second version';reseal(fork)
   study.write_json('history/v2.json',fork);(study.study/'history/v0.json').write_bytes(original);study.write_json('protocol.json',reporting_amendment(fork))
   code,report=study.score(runs,lock);self.assertEqual(code,1,'locked version2 copied atv0 still rescued a fork');self.assertNotIn('runs',report)

 def test_missing_canonical_ancestor_cannot_be_rescued_by_another_copy(self):
  with tempfile.TemporaryDirectory() as temp:
   study=StudyCopy(temp);lock=study.lock();original=(study.study/'protocol.json').read_bytes();first=json.loads(original)
   study.write_json('history/v0.json',first);study.write_json('protocol.json',reporting_amendment(first))
   code,report=study.score(study.records(lock),lock);self.assertEqual(code,1);self.assertNotIn('runs',report)
 def test_valid_locked_version_two_reporting_descendant_preserves_scores(self):
  with tempfile.TemporaryDirectory() as temp:
   study=StudyCopy(temp);first=study.protocol();study.write_json('history/v1.json',first)
   second=reporting_amendment(first);study.write_json('protocol.json',second)
   lock=study.lock();runs=study.records(lock);code,before=study.score(runs,lock);self.assertEqual(code,0,before)
   (study.study/'history/v2.json').write_bytes((study.study/'protocol.json').read_bytes())
   study.write_json('protocol.json',reporting_amendment(second));code,after=study.score(runs,lock);self.assertEqual(code,0,after)
   for key in ['runs','summary','estimands','protocol_digest']:self.assertEqual(after[key],before[key])
   self.assertEqual(after['reporting_revision']['version'],3)

if __name__ == "__main__":
    unittest.main()
