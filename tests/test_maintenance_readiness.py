"""Evidence persistence ordering fixtures; mocked precommit is NOT qualification."""
from copy import deepcopy
from pathlib import Path
import sys,unittest
from unittest import mock
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'scripts'))
from tests import test_maintenance_authority as fixture
from cwo_core.maintenance_readiness import persist_precommit_readiness
from cwo_core.native_pool_transaction import execution_authoritative_bead_sha256
from cwo_core.native_pool_contracts import canonical_sha256

class ReadinessPersistenceTests(unittest.TestCase):
 def setUp(self):
  self.f=fixture.MaintenanceAuthorityTests('test_review_positive_no_write_authority');self.f.setUp();self.addCleanup(self.f.doCleanups)
  self.plan,self.scope,_=self.f.operation(role='review');self.work={'bead_id':'mission-leaf','fit_mode':'semantic'}
  self.issue={'id':'mission-leaf','title':'Controlled mechanics fixture','status':'open','assignee':'','issue_type':'task','labels':[],'dependencies':[],
   'metadata':{'unrelated':{'preserved':True},'cwo_ready_set_admission':{'work_plan':deepcopy(self.work),'declared_write_paths':[],'declared_read_paths':[],'integration_target_paths':[],'share_boundary':'no-outside-sharing'}}}
  self.plan['children'][0].update(bead_id='mission-leaf',work_plan_sha256=canonical_sha256(self.work),bead_projection_sha256=execution_authoritative_bead_sha256(self.issue))
  d=self.f.reseal(self.plan,self.scope);self.cap=self.f.verifier.verify_operation(self.plan,self.scope,d);self.cap.claim()
  self.evidence=self.f.controller/'evidence';self.evidence.mkdir(mode=0o700);self.show_count=0;self.revoke_at=None;self.drift_at=None
  def show(bead_id):
   self.show_count+=1
   if self.show_count==self.revoke_at:self.f.store.revoke()
   value=deepcopy(self.issue)
   if self.show_count==self.drift_at:value['title']='Foreign drift'
   return value
  self.adapter=mock.Mock();self.adapter.show_exact.side_effect=show;self.persisted=0
  def persist(bead_id,admission,expected):
   self.assertEqual(expected,canonical_sha256(self.issue));self.persisted+=1
   self.issue['metadata']['cwo_ready_set_admission']=deepcopy(admission)
  self.writer=persist
 def call(self,**overrides):
  args=dict(operation=self.cap,verifier=self.f.verifier,claim_adapter=self.adapter,work_plan=self.work,
   precommit_receipt={'receipt_sha256':'r'*64},operative_routing={},current_authority={},evidence_dir=self.evidence,persist_admission=self.writer)
  args.update(overrides)
  with mock.patch('cwo_core.maintenance_readiness.validate_precommit_receipt',return_value=[]),mock.patch('cwo_core.maintenance_readiness.build_worker_commitment_from_receipt',return_value={'decision':'accept'}),mock.patch('cwo_core.maintenance_readiness.validate_worker_commitment',return_value=[]):
   return persist_precommit_readiness(**args)
 def test_scope_unchanged_and_only_evidence_slots_added(self):
  before=deepcopy(self.issue);after=self.call();self.assertEqual(self.persisted,1)
  self.assertEqual(execution_authoritative_bead_sha256(before),execution_authoritative_bead_sha256(after));self.assertEqual(after['metadata']['unrelated'],before['metadata']['unrelated'])
  self.assertTrue((self.evidence/'readiness-intent.json').exists());self.assertTrue((self.evidence/'readiness-persisted.json').exists())
 def test_reentrant_revocation_before_trigger_prevents_persistence(self):
  self.revoke_at=2
  with self.assertRaises(ValueError):self.call()
  self.assertEqual(self.persisted,0);self.assertFalse((self.evidence/'readiness-persisted.json').exists())
 def test_pre_write_source_drift_prevents_persistence(self):
  self.drift_at=2
  with self.assertRaisesRegex(ValueError,'pre-write-drift'):self.call()
  self.assertEqual(self.persisted,0)
 def test_failure_and_noop_write_never_mint_completion(self):
  def fail(*args):raise OSError('fixture write failure')
  with self.assertRaises(OSError):self.call(persist_admission=fail)
  self.assertFalse((self.evidence/'readiness-persisted.json').exists())
 def test_foreign_field_change_after_effect_is_rejected(self):
  writer=self.writer
  def wrong(*args):writer(*args);self.issue['metadata']['unrelated']={'changed':True}
  with self.assertRaisesRegex(ValueError,'exact-metadata'):self.call(persist_admission=wrong)
  self.assertFalse((self.evidence/'readiness-persisted.json').exists())
 def test_intent_replay_and_owned_leaf_reject_before_effect(self):
  self.issue['assignee']='foreign'
  with self.assertRaises(ValueError):self.call()
  self.assertEqual(self.persisted,0)
 def test_integral_float_rewrite_in_seed_is_not_equal_hash_authority(self):
  self.work['ratio']=1.0
  self.plan['children'][0]['work_plan_sha256']=canonical_sha256(self.work)
  self.issue['metadata']['cwo_ready_set_admission']['work_plan']=dict(self.work,ratio=1)
  self.plan['children'][0]['bead_projection_sha256']=execution_authoritative_bead_sha256(self.issue)
  self.scope['operation_id']='new-storage-test';self.plan['transaction_id']='new-storage-test'
  d=self.f.reseal(self.plan,self.scope);self.cap=self.f.verifier.verify_operation(self.plan,self.scope,d);self.cap.claim()
  with self.assertRaisesRegex(ValueError,'seeded-plan-mismatch'):self.call()
  self.assertEqual(self.persisted,0)
 def test_boolean_numeric_tamper_in_readback_never_mints_receipt(self):
  writer=self.writer
  def wrong(*args):writer(*args);self.issue['metadata']['unrelated']['preserved']=1
  with self.assertRaisesRegex(ValueError,'exact-metadata'):self.call(persist_admission=wrong)
  self.assertFalse((self.evidence/'readiness-persisted.json').exists())
