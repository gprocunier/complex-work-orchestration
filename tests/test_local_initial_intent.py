import json,os,sys,unittest
from unittest.mock import patch
from typing import NamedTuple
sys.path.insert(0,'scripts')
from tests.test_local_invocation_reservation import RouteTestCase
from tests.test_local_dispatch import FakeHardenedOpener
from cwo_core import local_invocation as local
import urllib.request
from tests import test_local_gate_boundaries as gate_tests
class IntentHostCase(NamedTuple):
 original: str
 host: str

class InitialIntent(RouteTestCase):
 def revoke(self,host):
  opener=FakeHardenedOpener()
  def abort(event):
   if event['event']=='invocation-intent':local.open_ledger().finish(event['attempt']['reservation_id'],'aborted-before-effect',reason='fixture revocation')
  with patch.dict(os.environ,{'CWO_OPENSHIFT_AI_VLLM_BASE_URL':f'http://{host}:8000'}),patch.object(local,'OBSERVERS',[abort]):
   outcome,boundaries=self.execute(self.envelope('initial-intent-'+host),opener)
  attempt=self.attempts()[0]
  print(json.dumps({'case':'initial intent revocation','host':host,'effects':dict(boundaries.calls),'state':attempt['state'],'outcome':attempt['outcome'],'charge':attempt['charge']}))
  self.assertEqual(attempt['outcome'],'aborted-before-effect');self.assertEqual(attempt['charge'],attempt['amount'])
  self.assertEqual(dict(boundaries.calls),dict.fromkeys(boundaries.calls,0),'effect reached after initial observer revoked intent')
  self.assertIsInstance(outcome,SystemExit)
 def test_initial_observer_revocation_host_rows(self):
  rows = (
   IntentHostCase("test_initial_observer_revocation_precedes_hostname_dns", "localhost"),
  )
  original_root = self.root
  try:
   for row in rows:
    with self.subTest(original=row.original):
     self.root = original_root.with_name("ledger-" + row.host)
     self.revoke(row.host)
  finally:
   self.root = original_root


 def test_normal_real_intent_still_reaches_post(self):
  opener=FakeHardenedOpener();outcome,_=self.execute(self.envelope('normal-initial'),opener)
  self.assertIsInstance(outcome,dict,repr(outcome));self.assertTrue(opener.chat_called)


 def test_initial_observer_revocation_precedes_literal_resolution(self):self.revoke('127.0.0.1')
class FractionalDeadline(unittest.TestCase):

 def test_fractional_expiry_refuses_before_actual_post(self):
  for maximum,gap in [(1000,1.0005),(0,0.0005)]:
   with self.subTest(maximum=maximum):
    preflight=urllib.request.Request('http://127.0.0.1:8000/models',method='GET')
    req,gate,http=gate_tests.GateBoundaryTests().fixture(preflight=preflight);clock=[1000.0]
    with patch.object(local.time,'monotonic',lambda:clock[0]):
     with gate.open(preflight,timeout=5):pass
     gate.validated_preflight(completed_monotonic=clock[0],maximum_gap_ms=maximum);clock[0]+=gap
     error=None
     try:
      with gate.open(req,timeout=5):pass
     except SystemExit as exc:error=exc
    self.assertEqual([row[0] for row in http.requests],['GET'],'fractional expiry allowed a POST');self.assertIsInstance(error,SystemExit)

if __name__ == "__main__":
    unittest.main()
