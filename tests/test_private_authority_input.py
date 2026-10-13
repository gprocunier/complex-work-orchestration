"""Private evidence input is not an operation grant."""
from copy import deepcopy
import hashlib,json,os
from pathlib import Path
import sys,tempfile,unittest
from unittest import mock
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'scripts'))
from cwo_core.private_authority_input import load_private_current_authority,private_authority_arguments,PrivateAuthorityInputError
from cwo_core.native_precommit import canonical_sha256
import supervise_native_worker as worker_cli
import supervise_native_precommit as precommit_cli

class PrivateAuthorityInputTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);self.path=self.root/'authority.json'
 def write(self,value):
  data=json.dumps(value).encode();self.path.write_bytes(data);self.path.chmod(0o600);return hashlib.sha256(data).hexdigest()
 def test_valid_raw_and_closed_envelope_readback_is_evidence_only(self):
  from tests.test_routing_current_authority import synthetic_authority
  value=synthetic_authority();h=self.write(value)
  self.assertEqual(load_private_current_authority(self.path,h),value)
  envelope={'authority_type':'cwo-private-current-authority','version':1,'current_authority':value,'current_authority_sha256':canonical_sha256(value)}
  h=self.write(envelope);self.assertEqual(load_private_current_authority(self.path,h),value)
  envelope['version']=True;h=self.write(envelope)
  with self.assertRaises(ValueError):load_private_current_authority(self.path,h)
  envelope['version']=1;envelope['current_authority_sha256']='f'*64;h=self.write(envelope)
  with self.assertRaises(ValueError):load_private_current_authority(self.path,h)
 def test_omission_is_not_a_grant(self):self.assertEqual(private_authority_arguments(None,None),{})
 def test_half_pair_and_bad_inputs_are_controlled(self):
  for args in [(None,'a'*64),('',None),([],None),('missing',None)]:
   with self.subTest(args=args),self.assertRaises(ValueError):private_authority_arguments(*args)
 def test_invalid_json_shapes_rejected(self):
  for value in [None,False,0,[],{},'authority']:
   with self.subTest(value=value):
    h=self.write(value)
    with self.assertRaises(ValueError):load_private_current_authority(self.path,h)
 def test_fifo_is_rejected_without_waiting_for_writer(self):
  os.mkfifo(self.path,0o600)
  with self.assertRaisesRegex(ValueError,'regular'):load_private_current_authority(self.path,'a'*64)
 def test_symlink_and_public_and_wrong_hash_rejected(self):
  h=self.write({})
  other=self.root/'link';other.symlink_to(self.path)
  with self.assertRaisesRegex(ValueError,'symlink'):load_private_current_authority(other,h)
  self.path.chmod(0o644)
  with self.assertRaisesRegex(ValueError,'private'):load_private_current_authority(self.path,h)
  self.path.chmod(0o600)
  with self.assertRaisesRegex(ValueError,'hash mismatch'):load_private_current_authority(self.path,'f'*64)
 def test_fd_is_closed_after_invalid_json(self):
  self.path.write_text('{');self.path.chmod(0o600);before=len(os.listdir('/proc/self/fd'))
  with self.assertRaises(ValueError):load_private_current_authority(self.path,hashlib.sha256(b'{').hexdigest())
  self.assertEqual(before,len(os.listdir('/proc/self/fd')))
 def test_bounds_types_and_duplicate_keys(self):
  for raw in [b'{"a":1,"a":2}',b'{"a":NaN}',b'{"a":Infinity}']:
   self.path.write_bytes(raw);self.path.chmod(0o600)
   with self.assertRaises(ValueError):load_private_current_authority(self.path,hashlib.sha256(raw).hexdigest())
  with self.assertRaises(ValueError):load_private_current_authority(self.path,'a'*64,maximum_bytes=False)
 def test_changed_descriptor_snapshot_is_rejected(self):
  h=self.write({});real=os.fstat;calls=[0]
  def changed(fd):
   value=real(fd);calls[0]+=1
   if calls[0]==2:
    values=list(value);values[6]+=1;return os.stat_result(values)
   return value
  with mock.patch('cwo_core.private_authority_input.os.fstat',side_effect=changed),self.assertRaises(ValueError):load_private_current_authority(self.path,h)
 def test_all_worker_parser_transitions_expose_pair(self):
  commands={
   'start':['--packet','p','--session-id','s','--session-file','s.jsonl','--agent-id','a'],
   'arm':['--state-file','s','--control-turn-id','t'],
   'mark-dispatched':['--state-file','s','--control-turn-id','t','--submission-id','u'],
   'check':['--state-file','s','--control-turn-id','t'],
   'finalize':['--state-file','s','--control-turn-id','t','--control-action','close-confirmed'],
   'assess-retry':['--state-file','s','--control-turn-id','t','--workspace-report','w','--semantic-result','r'],
   'authorize-retry':['--state-file','s','--control-turn-id','t','--workspace-report','w','--semantic-result','r','--fresh-attestation','a','--retry-packet','p']}
  for cmd,args in commands.items():
   with self.subTest(cmd=cmd),mock.patch.object(sys,'argv',['supervise_native_worker.py',cmd,*args,'--current-authority-file',str(self.path),'--current-authority-sha256','a'*64]):
    parsed=worker_cli.parse_args();self.assertEqual(parsed.current_authority_file,str(self.path))
 def test_invalid_cli_evidence_fails_before_any_transition(self):
  h=self.write(None)
  with mock.patch.object(sys,'argv',['supervise_native_worker.py','check','--state-file','not-present','--control-turn-id','t','--current-authority-file',str(self.path),'--current-authority-sha256',h]),mock.patch.object(worker_cli,'check') as transition,self.assertRaises(SystemExit):worker_cli.main()
  transition.assert_not_called()
 def test_precommit_parser_three_authority_consumers(self):
  base=['--packet-id','p','--work-plan','w','--session-id','s','--session-file','f','--agent-id','a','--workdir',str(self.root)]
  for command,args in [('create',base),('deterministic-receipt',base+['--fit-result','r','--control-turn-id','t']),('validate-receipt',['--receipt','r'])]:
   with self.subTest(command=command),mock.patch.object(sys,'argv',['supervise_native_precommit.py',command,*args,'--operative-routing','route','--current-authority-file','auth','--current-authority-sha256','a'*64]):
    parsed=precommit_cli.parse_args();self.assertEqual(parsed.operative_routing,'route');self.assertEqual(parsed.current_authority_file,'auth')
