import subprocess,sys,unittest
sys.path.insert(0,'scripts')
from tests.test_local_invocation_reservation import RouteTestCase
from tests.test_invocation_ledger import LedgerTestCase,REQUEST,FakeEffect
from unittest.mock import patch
from tests.test_local_dispatch import FakeHardenedOpener
from cwo_core import local_invocation as local
class LocalStopIteration(RouteTestCase):

 def test_stopiteration_identity_at_both_observer_phases(self):
  self.set_quota(20)
  for phase in ['invocation-intent','request']:
   for kind in [StopIteration,StopAsyncIteration]:
    with self.subTest(phase=phase,kind=kind.__name__):
     error=kind('primary');opener=FakeHardenedOpener()
     def observe(event):
      if event['event']==phase:raise error
      if event['event']=='terminal':raise RuntimeError('secondary-terminal')
     with patch.object(local,'OBSERVERS',[observe]):outcome,_=self.execute(self.envelope('stop-'+phase+kind.__name__),opener)
     self.assertIs(outcome,error);self.assertFalse(opener.chat_called);attempt=self.attempts()[-1];self.assertEqual(attempt['outcome'],'aborted-before-effect' if phase=='invocation-intent' else 'unknown');self.assertEqual(attempt['charge'],attempt['amount'])
     if phase=='request':self.assertTrue(any('secondary-terminal' in note for note in error.__notes__))
class LedgerStopIteration(LedgerTestCase):
 def test_initial_observer_identity_for_invoke_and_context(self):
  for mode in ['invoke','context']:
   with self.subTest(mode=mode):
    error=StopIteration('initial-primary');reservation=self.reserve(mode);effect=FakeEffect()
    def observe(event):
     if event['event']=='invocation-intent':raise error
    try:
     if mode=='invoke':self.ledger.invoke(reservation['reservation_id'],REQUEST,effect,observers=[observe])
     else:
      with self.ledger.invocation(reservation['reservation_id'],REQUEST,observers=[observe]):self.fail('body ran after failed initial observer')
    except BaseException as outcome:self.assertIs(outcome,error)
    else:self.fail('primary did not propagate')
    self.assertEqual(effect.calls,[]);attempt=self.ledger.attempt(reservation['reservation_id']);self.assertEqual(attempt['outcome'],'aborted-before-effect');self.assertEqual(attempt['charge'],attempt['amount'])
 def test_direct_context_body_stopiteration_and_decorator_remain_compatible(self):
  reservation=self.reserve('body');error=StopIteration('body-primary')
  try:
   with self.ledger.invocation(reservation['reservation_id'],REQUEST):raise error
  except BaseException as outcome:self.assertIs(outcome,error)
  else:self.fail('body failure lost')
  reservation=self.reserve('decorator');called=[]
  @self.ledger.invocation(reservation['reservation_id'],REQUEST)
  def call():called.append(True)
  call();self.assertEqual(called,[True])
  with self.assertRaises(self.mod.InvocationLedgerError):call()
  self.assertEqual(called,[True])
 def test_initial_observer_reentry_refuses_without_holding_entry_lock(self):
  script="""import sys,unittest
sys.path.insert(0,'scripts')
from tests.test_invocation_ledger import LedgerTestCase,REQUEST,BUDGET
class Reentry(LedgerTestCase):
 def test_reentry(self):
  reservation=self.reserve('entry-reentry');seen=[];context=None
  def observe(event):
   if event['event']=='invocation-intent':
    seen.append(True)
    with self.assertRaisesRegex(self.mod.InvocationLedgerError,'one-shot'):context.__enter__()
    self.ledger.summary(BUDGET)
  context=self.ledger.invocation(reservation['reservation_id'],REQUEST,observers=[observe])
  with context:pass
  self.assertEqual(seen,[True]);self.assertEqual(self.ledger.attempt(reservation['reservation_id'])['outcome'],'completed')
unittest.main()
"""
  try:result=subprocess.run([sys.executable,'-c',script],capture_output=True,text=True,timeout=5,check=False)
  except subprocess.TimeoutExpired:self.fail('initial observer reentry blocked on context entry/file lock')
  self.assertEqual(result.returncode,0,result.stdout+result.stderr)

if __name__=='__main__':unittest.main()
