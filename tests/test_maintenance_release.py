"""Closed release parsing and real opaque owner checks; synthetic evidence only."""
from copy import deepcopy
import datetime as dt
from pathlib import Path
import sys,unittest
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'scripts'))
from tests import test_maintenance_authority as fixture
from cwo_core.maintenance_release import validate_maintenance_release_evidence,FIELDS,OPERATIONS,SCHEMA,seal

class MaintenanceReleaseTests(unittest.TestCase):
 def setUp(self):
  self.f=fixture.MaintenanceAuthorityTests('test_review_positive_no_write_authority');self.f.setUp();self.addCleanup(self.f.doCleanups)
  self.plan,self.scope,_=self.f.operation(role='review');self.plan['children'][0]['bead_id']='test-bead';directive=self.f.reseal(self.plan,self.scope)
  self.cap=self.f.verifier.verify_operation(self.plan,self.scope,directive);self.cap.claim()
  self.now=dt.datetime.now(dt.timezone.utc)
  value={key:'a'*64 for key in FIELDS}
  value.update(evidence_type='cwo-native-release-evidence',version=2,schema=SCHEMA,
   evidence_id='test-release',release_state='operative-authorized',authority='cwo-maintenance-controller',
   authority_bead='test-bead',adjudication_bead='test-bead',packet_id='packet',attempt_nonce='attempt',requested_model='test-model',
   operation_class='native-operative-release',authorized_operations=list(OPERATIONS),workdir=str(self.f.workspace),
   repository_work_authorized=True,source_mutation_authorized=False,issued_at=self.now.isoformat(),
   expires_at=(self.now+dt.timedelta(minutes=5)).isoformat(),release_requires=self.scope['mission_id'],mission_id=self.scope['mission_id'],
   operation_sha256=self.cap.operation_sha256,plan_sha256=self.scope['plan_sha256'],role='review')
  value['evidence_sha256']=seal(value);self.value=value
 def errors(self,v=None,**kw):return validate_maintenance_release_evidence(v or self.value,maintenance_operation=self.cap,maintenance_verifier=self.f.verifier,now=self.now,**kw)
 def test_live_owner_bound_shape_is_valid_not_product_acceptance(self):self.assertEqual(self.errors(),[])
 def test_free_json_cannot_dispatch(self):self.assertTrue(validate_maintenance_release_evidence(self.value,operation='native-dispatch',now=self.now))
 def test_historical_parse_cannot_dispatch(self):
  self.assertEqual(validate_maintenance_release_evidence(self.value,live=False,historical_parse=True),[])
  self.assertTrue(validate_maintenance_release_evidence(self.value,live=False,historical_parse=True,operation='native-dispatch'))
 def test_types_and_resealed_tampering_rejected(self):
  for key in ['version','role','mission_id','authority_bead','requested_model','issued_at','source_mutation_authorized','repository_work_authorized']:
   for bad in [None,False,0,0.0,[],{},'']:
    if key=='source_mutation_authorized' and bad is False:continue
    with self.subTest(key=key,bad=bad):
     v=deepcopy(self.value);v[key]=bad;v['evidence_sha256']=seal(v);self.assertTrue(self.errors(v))
 def test_extra_missing_hash_and_bead_changes_rejected(self):
  for kind in ['extra','missing','hash','bead']:
   v=deepcopy(self.value)
   if kind=='extra':v['extra']=1
   if kind=='missing':del v['role']
   if kind=='hash':v['packet_id']='tampered'
   if kind=='bead':v['authority_bead']=v['adjudication_bead']='different';v['evidence_sha256']=seal(v)
   self.assertTrue(self.errors(v))
 def test_revocation_and_settlement_invalidate_live_release(self):
  self.f.store.settle(self.scope['operation_id'],self.cap.operation_sha256,outcome='accepted')
  self.assertTrue(self.errors())
 def test_detached_bound_plan_cannot_mutate_authority(self):
  copy=self.cap.bound_plan();copy['children'][0]['bead_id']='changed';self.assertEqual(self.cap.bound_plan()['children'][0]['bead_id'],'test-bead')
 def test_retry_not_inherited(self):self.assertTrue(self.errors(operation='native-retry'))
