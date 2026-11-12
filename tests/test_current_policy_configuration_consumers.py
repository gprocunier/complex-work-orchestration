"""Current canonical-loader regressions: real consumers, positives then malformed refusal."""
import sys,unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from tests.test_policy_schema import malformed_policy,_read
from cwo_core import policy,returns,synthesis,harness,access_profiles
from cwo_core.policy_schema import PolicySchemaError

class CanonicalConfigurationTests(unittest.TestCase):
 def tearDown(self):policy.clear_policy_cache()
 def test_share_false_string_never_becomes_external_permission(self):
  with malformed_policy('share-boundaries'):
   self.assertIs(policy.boundary_allows_external('no-outside-sharing'),False)
   self.assertIs(policy.boundary_allows_external('redacted-packet'),True)
  print('MEANINGFUL_POSITIVE share defaultfalse andexplicitredactedtrue',flush=True)
  with malformed_policy('share-boundaries',lambda d:d['boundaries']['no-outside-sharing'].__setitem__('allows_external','false')):
   with self.assertRaises(PolicySchemaError):policy.boundary_allows_external('no-outside-sharing')
 def test_acceptance_boolean_threshold_not_coerced(self):
  with malformed_policy('acceptance-policy'):
   self.assertEqual(returns.evidence_quality_thresholds(),{'primary':85,'salvage':60,'reject_below':40})
  print('MEANINGFUL_POSITIVE acceptanceactual85/60/40 unchanged',flush=True)
  with malformed_policy('acceptance-policy',lambda d:d['evidence_quality']['thresholds'].__setitem__('primary',False)):
   with self.assertRaises(PolicySchemaError):returns.evidence_quality_thresholds()
 def test_consensus_bool_version_refused_by_real_loader_reader(self):
  with malformed_policy('zero-trust-consensus-policy'):
   value=synthesis.zero_trust_consensus_policy();self.assertIs(type(value['version']),int)
   self.assertEqual(value['defaults']['minimum_independent_domains'],2)
  print('MEANINGFUL_POSITIVE consensusactualintversion andminimum2 informationalmetadata',flush=True)
  with malformed_policy('zero-trust-consensus-policy',lambda d:d.__setitem__('version',True)):
   with self.assertRaises(PolicySchemaError):synthesis.zero_trust_consensus_policy()
 def test_executor_false_string_never_becomes_external(self):
  key=next(k for k,v in _read('executor-registry')['executors'].items() if v['external'] is False and not v.get('alias_for'))
  with malformed_policy('executor-registry'):self.assertIs(policy.executor_external(key),False)
  print('MEANINGFUL_POSITIVE executoractualinternalflag '+key,flush=True)
  with malformed_policy('executor-registry',lambda d:d['executors'][key].__setitem__('external','false')):
   with self.assertRaises(PolicySchemaError):policy.executor_external(key)
 def test_environment_bool_version_refused_by_real_registry_reader(self):
  with malformed_policy('execution-environments'):
   value=harness.execution_environment_registry();self.assertIs(type(value['version']),int)
   self.assertIsInstance(value['profiles'],dict);self.assertTrue(value['profiles'])
  print('MEANINGFUL_POSITIVE environmentactualcurrentversion/profiles',flush=True)
  with malformed_policy('execution-environments',lambda d:d.__setitem__('version',True)):
   with self.assertRaises(PolicySchemaError):harness.execution_environment_registry()

 def test_model_profile_bool_version_refused_by_real_reader(self):
  with malformed_policy('model-profiles'):
   value=harness.model_profile_registry();self.assertIs(type(value['version']),int)
   self.assertIsInstance(value['profiles'],dict);self.assertTrue(value['profiles'])
  print('MEANINGFUL_POSITIVE modelprofiles actualcurrentversion/profiles',flush=True)
  with malformed_policy('model-profiles',lambda d:d.__setitem__('version',True)):
   with self.assertRaises(PolicySchemaError):harness.model_profile_registry()
 def test_access_profile_bool_version_refused_by_real_reader(self):
  with malformed_policy('access-profiles'):
   value=access_profiles.access_profile_registry();self.assertIs(type(value['version']),int)
   self.assertIsInstance(value['profiles'],dict);self.assertTrue(value['profiles'])
  print('MEANINGFUL_POSITIVE accessprofiles actualcurrentversion/profiles',flush=True)
  with malformed_policy('access-profiles',lambda d:d.__setitem__('version',True)):
   with self.assertRaises(PolicySchemaError):access_profiles.access_profile_registry()

if __name__=='__main__':unittest.main(verbosity=2)
