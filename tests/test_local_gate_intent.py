import sys,json
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'scripts'))
from unittest.mock import patch
from tests.test_local_invocation_reservation import RouteTestCase
from tests.test_local_dispatch import FakeHardenedOpener
from cwo_core import local_invocation as local
from cwo_core.invocation_ledger import InvocationHandle
import dispatch_work
class PersistedIntent(RouteTestCase):
 def test_request_observer_terminal_transition_prevents_post_and_keeps_charge(self):
  opener=FakeHardenedOpener()
  def abort(event):
   if event['event']=='request' and event['detail'].get('kind')=='post':
    local.open_ledger().finish(event['attempt']['reservation_id'],'aborted-before-effect',reason='fixture stop')
  with patch.object(local,'OBSERVERS',[abort]):outcome,_=self.execute(self.glm_envelope('observer-terminal'),opener)
  attempt=self.attempts()[0]
  print(json.dumps({'case':'terminal observer','post_sent':opener.chat_called,'state':attempt['state'],'outcome':attempt['outcome'],'charge':self.ledger().summary(attempt['budget_id'])['charged']}))
  self.assertFalse(opener.chat_called,'gate sent HTTP after its persisted intent became terminal')
  self.assertIsInstance(outcome,SystemExit)
  self.assertEqual(attempt['outcome'],'aborted-before-effect')
  self.assertEqual(self.ledger().summary(attempt['budget_id'])['charged'],attempt['amount'])
 def test_actual_send_expiry_includes_final_intent_recheck_work(self):
  clock=[1000.0];post_observed=[False];delayed=[False];opener=FakeHardenedOpener();original=InvocationHandle.require_intent
  def observe(event):
   if event['event']=='request' and event['detail'].get('kind')=='post':post_observed[0]=True
  def recheck(handle):
   value=original(handle)
   if post_observed[0] and not delayed[0]:clock[0]+=2;delayed[0]=True
   return value
  with patch.object(dispatch_work.time,'monotonic',lambda:clock[0]),patch.object(local,'OBSERVERS',[observe]),patch.object(InvocationHandle,'require_intent',recheck):
   outcome,_=self.execute(self.glm_envelope('last-intent-age'),opener)
  print(json.dumps({'case':'final ledger delay','post_sent':opener.chat_called,'final_check_observed':delayed[0]}))
  self.assertFalse(opener.chat_called,'freshness did not include the final persisted-intent read')
  self.assertTrue(delayed[0]);self.assertIsInstance(outcome,SystemExit)


 def test_positive_real_ledger_and_exact_post_still_reachable(self):
  opener=FakeHardenedOpener();outcome,_=self.execute(self.glm_envelope('positive-intent'),opener)
  self.assertTrue(opener.chat_called);self.assertIsInstance(outcome,dict,repr(outcome))
