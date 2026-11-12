import json,sys,unittest
from unittest.mock import patch
sys.path.insert(0,'scripts')
from tests.test_adjudication_binding import FixtureProducer
from tests.test_policy_current_effects import current_policy
from cwo_core import adjudication_binding as b,policy
class PolicyAndAlias(unittest.TestCase):
 def test_cache_cleared_policy_refusals_return_unresolved_at_every_boundary(self):
  for kind in ['schema','top-level']:
   for boundary in ['prepare','synthesis','status']:
    with self.subTest(kind=kind,boundary=boundary),current_policy() as home:
     f=FixtureProducer(home);prepared=f.prepare();p=home/'policy/synthesis-policy.yaml';value=json.loads(p.read_bytes());value['default_pattern']=False
     p.write_text(json.dumps(value) if kind=='schema' else '[]');policy.clear_policy_cache()
     try:
      result=f.prepare() if boundary=='prepare' else (b.synthesis_preparation if boundary=='synthesis' else b.status_preparation)(prepared,f.context)
     except SystemExit as exc:result=exc
     self.assertNotIsInstance(result,BaseException,'expected loader refusal escaped unresolved interface')
     out=b.status_preparation(result,f.context) if boundary=='prepare' else result
     self.assertFalse(out['inert_valid']);self.assertIsNone(out['decision']);self.assertEqual(out['resolved_findings'],[]);self.assertEqual(set(out['remaining_holds']),set(f.result['hold_reasons']))
 def test_equivalent_duplicate_support_paths_refuse_before_support_io(self):
  for names in [('support.json','./support.json'),('sub/support.json','sub//support.json')]:
   with self.subTest(names=names),current_policy() as home:
    f=FixtureProducer(home);raw=f.support[0].raw
    if names[0].startswith('sub/'):(home/'sub').mkdir();(home/'sub/support.json').write_bytes(raw)
    item=f.record['supporting_evidence'][0];f.record['supporting_evidence']=[dict(item,artifact=name) for name in names];f.support=tuple(b.SupportObservation(name,f.finding,raw) for name in names)
    with patch.object(b,'read_support',wraps=b.read_support) as reader:prepared=f.prepare()
    self.assertFalse(prepared.inert_valid,'two spellings of the same support were accepted');self.assertEqual(reader.call_count,0)
 def test_single_equivalent_path_remains_a_valid_fixture_positive(self):
  with current_policy() as home:
   f=FixtureProducer(home);f.record['supporting_evidence'][0]['artifact']='./support.json';f.support=(b.SupportObservation('./support.json',f.finding,f.support[0].raw),)
   prepared=f.prepare();self.assertTrue(prepared.inert_valid,prepared.errors);self.assertIn(f.finding,prepared.resolved_findings)

if __name__ == "__main__":
    unittest.main()
