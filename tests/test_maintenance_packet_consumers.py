"""Providerless public packet consumers: exact JSON types and profile forwarding."""
import copy
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'scripts'))
import prepare_native_worker as packet_module
from tests.historical_policy_fixtures import historical_v2_policy
from tests.test_prepare_native_worker import set_disposition

class MaintenancePacketConsumers(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
  with historical_v2_policy():
   self.packet=packet_module.build_native_worker_packet(bead_id='return-type-control',lane='implementation',workdir=self.temp.name,allowed_paths=['.'],acceptance_checks=['fixture complete'])
  p=self.packet
  self.result={'return_type':'cwo-native-worker-return','version':1,'packet_id':p['packet_id'],'bead_id':p['bead_id'],'session_id':'fixture-session','segment_id':'fixture-segment','status':'completed','requested_model':p['requested_model'],'actual_model':p['requested_model'],'attestation_source':'trusted-control-plane-session-metadata','attestation_status':'trusted','completed_evidence':'providerless positive shape control','files_touched':[],'mutation_state':'clean','commands_run':['git diff --check'],'validation':{'status':'pass'},'decision_required':[],'bounded_options':[],'recommendation':'','remaining_scope':{},'usage':{'tool_calls':1,'elapsed_seconds':1,'context_compactions':0,'full_suite_runs':0,'cached_input_tokens':0,'reasoning_tokens':0},'residual_risks':[]}
  set_disposition(p,self.result)
 def test_positive_control(self):
  self.assertEqual(packet_module.validate_native_worker_return(self.packet,self.result),[])
 def test_malformed_nested_and_enum_types_controlled(self):
  for field in ('status','mutation_state','attestation_status','artifact_disposition','session_disposition','validation','usage','files_touched','decision_required'):
   for value in (None,0,0.0,False,[],{},'unexpected'):
    if field in ('validation','usage') and value=={}:continue
    if field in ('files_touched','decision_required') and type(value) is list:continue
    with self.subTest(field=field,value=value):
     result=copy.deepcopy(self.result);result[field]=value
     errors=packet_module.validate_native_worker_return(self.packet,result)
     self.assertIsInstance(errors,list);self.assertTrue(errors)
 def test_numeric_boolean_confusion(self):
  for value in (True,False,1.0,'1',None,[],{}):
   with self.subTest(value=value):
    result=copy.deepcopy(self.result);result['version']=value
    self.assertTrue(packet_module.validate_native_worker_return(self.packet,result))
 def test_core_profile_consumed_without_relabeling(self):
  with historical_v2_policy():
   packet=packet_module.build_native_worker_packet(bead_id='profile-shape',lane='implementation',workdir=self.temp.name,allowed_paths=['.'],acceptance_checks=['fixture complete'],tool_profile='mutating-core-resources-v2')
  self.assertEqual(packet['tool_policy']['version'],2)
  self.assertEqual(packet['tool_policy']['tool_profile'],'mutating-core-resources-v2')
  self.assertEqual(len(packet['tool_policy']['permitted_tools']),6)
  self.assertIn('apply_patch',packet_module._render_prompt(packet))
 def test_private_cli_half_input_rejected_before_build(self):
  args=mock.Mock(command='build',current_authority_file='/not/a/real/authority',current_authority_sha256=None)
  with mock.patch.object(packet_module,'_parse_args',return_value=args),mock.patch.object(packet_module,'build_native_worker_packet') as build:
   with self.assertRaisesRegex(SystemExit,'supplied together'):packet_module.main()
   build.assert_not_called()

class ActualReceiptCommitmentSelection(unittest.TestCase):
 def test_deterministic_luna_selects_live_receipt_builder(self):
  with tempfile.TemporaryDirectory() as workdir,mock.patch.object(packet_module,'build_policy_fit_commitment') as policy_builder,mock.patch.object(packet_module,'build_worker_commitment_from_receipt',side_effect=ValueError('actual-live-selector')) as live_builder:
   with self.assertRaisesRegex(SystemExit,'actual-live-selector'):
    packet_module._build_native_worker_packet_unreserved(bead_id='live-selector',lane='implementation',workdir=workdir,allowed_paths=['.'],acceptance_checks=['check'],work_plan={'fit_mode':'deterministic'},precommit_receipt={'submission_id':'live-provider-turn','requested_model':'gpt-5.6-luna'})
   live_builder.assert_called_once();policy_builder.assert_not_called()
 def test_historical_zero_length_policy_receipt_retains_policy_builder(self):
  with tempfile.TemporaryDirectory() as workdir,mock.patch.object(packet_module,'build_policy_fit_commitment',side_effect=ValueError('actual-policy-selector')) as policy_builder,mock.patch.object(packet_module,'build_worker_commitment_from_receipt') as live_builder:
   with self.assertRaisesRegex(SystemExit,'actual-policy-selector'):
    packet_module._build_native_worker_packet_unreserved(bead_id='policy-selector',lane='implementation',workdir=workdir,allowed_paths=['.'],acceptance_checks=['check'],work_plan={'fit_mode':'deterministic'},precommit_receipt={'submission_id':'deterministic-policy','requested_model':'gpt-5.3-codex-spark'})
   policy_builder.assert_called_once();live_builder.assert_not_called()
