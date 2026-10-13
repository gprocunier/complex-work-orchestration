"""Providerless maintenance isolation: retain UNKNOWN leases, do not forge closure."""
from pathlib import Path
import sys,json
from copy import deepcopy
from unittest import mock
import unittest
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'scripts'))
from tests import test_maintenance_authority as authority_fixture
from cwo_core import native_precommit as n
from cwo_core.native_pool_contracts import canonical_sha256

class MaintenancePrecommitIsolation(unittest.TestCase):
 def setUp(self):
  self.f=authority_fixture.MaintenanceAuthorityTests();self.f.setUp();self.addCleanup(self.f.doCleanups)
  plan,scope,directive=self.f.operation();plan['children'][0].update(bead_id='mission-leaf',work_plan_sha256='a'*64)
  directive=self.f.reseal(plan,scope);self.cap=self.f.verifier.verify_operation(plan,scope,directive);self.cap.claim()
  self.registry=self.f.controller/'registry';self.registry.mkdir(mode=0o700)
  self.old={'owner_identity':{'fixture_dead':True},'state_file':str(self.f.root/'unproved-old-state'),'session_file':str(self.f.root/'old-session'),'workdir':str(self.f.root/'old-workspace'),'packet_id':'spent-old','attempt_nonce':'spent-nonce'}
  (self.registry/'leases.json').write_text(json.dumps([self.old]));(self.registry/'identities.json').write_text(json.dumps({'packet_ids':['spent-old'],'attempt_nonces':['spent-nonce']}))
  self.state={'state_id':'new-state','state_file':str(self.f.controller/'new-state'),'packet_id':'new-packet','attempt_nonce':'new-nonce','session_file':str(self.f.root/'new-session'),'workdir':str(self.f.workspace),'owner_pid':1,'owner_identity':{},'control_execution_handle':'new-control','control_topology':'single-host-process-v1','status':'armed','requested_model':'test-model','bead_id':'mission-leaf','work_plan_sha256':'a'*64}
 def call(self,*,maintenance=True):
  kwargs={'maintenance_operation':self.cap,'maintenance_verifier':self.f.verifier} if maintenance else {}
  with mock.patch.dict('os.environ',{'CWO_PRECOMMIT_REGISTRY_ROOT':str(self.registry)}),mock.patch.object(n,'_owner_identity_matches',return_value=False),mock.patch.object(n,'_terminal_state_file',return_value=False):
   n._register_identity_and_lease(self.state,**kwargs)
 def test_authorized_disjoint_lease_retains_unknown_and_consumed_ids(self):
  self.call();leases=json.loads((self.registry/'leases.json').read_text());self.assertEqual(leases[0],self.old);self.assertEqual(len(leases),2)
  self.assertEqual(json.loads((self.registry/'identities.json').read_text())['packet_ids'],['new-packet','spent-old'])
 def test_ordinary_finite_behavior_still_rejects_unproved_lease(self):
  with self.assertRaisesRegex(ValueError,'stale precommit'):self.call(maintenance=False)
  self.assertEqual(json.loads((self.registry/'leases.json').read_text()),[self.old])
 def test_overlap_and_same_session_reject_even_with_real_capability(self):
  for key,value in [('workdir',str(self.f.workspace)),('session_file',self.state['session_file'])]:
   old=deepcopy(self.old);old[key]=value;(self.registry/'leases.json').write_text(json.dumps([old]))
   with self.subTest(key=key),self.assertRaisesRegex(ValueError,'stale precommit'):self.call()
 def test_wrong_scope_fake_and_revoked_capability_reject_before_write(self):
  self.state['bead_id']='wrong'
  with self.assertRaisesRegex(ValueError,'scope/plan mismatch'):self.call()
  self.assertEqual(json.loads((self.registry/'leases.json').read_text()),[self.old])
  self.state['bead_id']='mission-leaf';self.f.store.revoke()
  with self.assertRaises(ValueError):self.call()
 def test_missing_malformed_and_symlink_session_reject(self):
  for value in (None,[],{},'relative-path'):
   old=deepcopy(self.old);old['session_file']=value;(self.registry/'leases.json').write_text(json.dumps([old]))
   with self.subTest(value=value),self.assertRaisesRegex(ValueError,'stale precommit'):self.call()
  alias=self.f.root/'old-session-alias';alias.symlink_to(self.state['session_file'])
  old=deepcopy(self.old);old['session_file']=str(alias);(self.registry/'leases.json').write_text(json.dumps([old]))
  with self.assertRaisesRegex(ValueError,'stale precommit'):self.call()
 def test_synchronous_nested_registration_and_registry_writer_fail_promptly(self):
  with n._registration_guard(),self.assertRaisesRegex(ValueError,'reentrant'):
   self.call()
  with n._registration_guard(),self.assertRaisesRegex(ValueError,'reentrant'):
   with n._registry_lock():pass
 def test_partial_write_preserves_consumed_identity_and_no_replay(self):
  original=n._registry_write
  def fail_lease(path,value):
   if path.name=='leases.json':raise OSError('fixture lease write failure')
   return original(path,value)
  with mock.patch.object(n,'_registry_write',side_effect=fail_lease),self.assertRaises(OSError):self.call()
  self.assertIn('new-packet',json.loads((self.registry/'identities.json').read_text())['packet_ids'])
  self.assertEqual(json.loads((self.registry/'leases.json').read_text()),[self.old])
  with self.assertRaisesRegex(ValueError,'duplicate precommit packet'):self.call()
 def test_worktree_ancestry_and_symlink_overlap_reject(self):
  alias=self.f.root/'workspace-alias';alias.symlink_to(self.f.workspace,target_is_directory=True)
  for value in (str(self.f.root),str(self.f.workspace/'child'),str(alias)):
   old=deepcopy(self.old);old['workdir']=value;(self.registry/'leases.json').write_text(json.dumps([old]))
   with self.subTest(value=value),self.assertRaisesRegex(ValueError,'stale precommit'):self.call()
  self.assertEqual(json.loads((self.registry/'identities.json').read_text())['packet_ids'],['spent-old'])
 def test_every_scope_commitment_is_checked_before_registry_effects(self):
  for key,value in [('workdir',str(self.f.controller)),('requested_model','other'),('bead_id','other'),('work_plan_sha256','b'*64)]:
   original=self.state[key];self.state[key]=value
   with self.subTest(key=key),self.assertRaisesRegex(ValueError,'scope/plan mismatch'):self.call()
   self.state[key]=original
  self.assertEqual(json.loads((self.registry/'leases.json').read_text()),[self.old])
  self.assertEqual(json.loads((self.registry/'identities.json').read_text())['attempt_nonces'],['spent-nonce'])
 def test_final_revalidation_revocation_denies_before_either_write(self):
  cls=type(self.cap);original=cls.revalidate;calls=[]
  def revoke_on_final(cap,*args,**kwargs):
   calls.append(cap)
   if len(calls)==2:self.f.store.revoke()
   return original(cap,*args,**kwargs)
  with mock.patch.object(cls,'revalidate',new=revoke_on_final),mock.patch.object(n,'_registry_write') as write,self.assertRaises(ValueError):self.call()
  self.assertEqual(len(calls),2);write.assert_not_called()
  self.assertEqual(json.loads((self.registry/'leases.json').read_text()),[self.old])
 def test_actual_verification_callback_cannot_reenter_registry(self):
  cls=type(self.cap);original=cls.revalidate;seen=[]
  def nested(cap,*args,**kwargs):
   with self.assertRaisesRegex(ValueError,'reentrant'):self.call()
   with self.assertRaisesRegex(ValueError,'reentrant'):
    with n._registry_lock():pass
   seen.append(cap)
   return original(cap,*args,**kwargs)
  with mock.patch.object(cls,'revalidate',new=nested):self.call()
  self.assertEqual(len(seen),2)
  self.assertEqual(json.loads((self.registry/'leases.json').read_text())[0],self.old)
