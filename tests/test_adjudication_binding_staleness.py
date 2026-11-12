import dataclasses,json,sys,unittest
sys.path.insert(0,'scripts')
from tests.test_adjudication_binding import FixtureProducer
from tests.test_policy_current_effects import current_policy
from cwo_core import adjudication_binding as b
class StaleDecision(unittest.TestCase):
 def test_stale_acceptance_is_unapplied_in_both_consumers(self):
  for drift in ['context','policy']:
   with self.subTest(drift=drift),current_policy() as home:
    f=FixtureProducer(home);prepared=f.prepare();self.assertEqual(prepared.decision,'accepted')
    expected=f.context
    if drift=='context':expected=dataclasses.replace(expected,task='different-task')
    else:
     p=home/'policy/synthesis-policy.yaml';value=json.loads(p.read_bytes());value['default_pattern']='changed';p.write_text(json.dumps(value))
    for adapter in [b.synthesis_preparation,b.status_preparation]:
     result=adapter(prepared,expected);self.assertFalse(result['inert_valid']);self.assertEqual(result['resolved_findings'],[])
     self.assertIsNone(result['decision'],'invalidated consumer retained accepting adjudication')
     self.assertEqual(set(result['remaining_holds']),set(f.result['hold_reasons']))
 def test_stale_restrictions_stay_restrictive(self):
  with current_policy() as home:
   f=FixtureProducer(home);f.record['decision']='quarantined';prepared=f.prepare();expected=dataclasses.replace(f.context,task='different-task')
   result=b.status_preparation(prepared,expected);self.assertEqual(result['decision'],'quarantined');self.assertIn('quarantined',result['adjudication_restrictions']);self.assertFalse(result['production_ready'])

if __name__ == "__main__":
    unittest.main()
