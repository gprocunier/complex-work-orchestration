import sys,unittest
from unittest.mock import patch
sys.path.insert(0,'scripts')
from tests.test_local_invocation_reservation import RouteTestCase
from tests.test_local_dispatch import FakeHardenedOpener
from cwo_core import local_invocation as local
from cwo_core.invocation_ledger import InvocationLedgerError
class OriginalFailure(RouteTestCase):
 def test_gate_generated_refusal_survives_terminal_settlement(self):
  opener=FakeHardenedOpener();captured=[];original=local.LocalHttpGate.open
  def abort(event):
   if event['event']=='request':local.open_ledger().finish(event['attempt']['reservation_id'],'aborted-before-effect',reason='fixture terminal')
  def capture(gate,*args,**kwargs):
   try:return original(gate,*args,**kwargs)
   except SystemExit as exc:captured.append(exc);raise
  with patch.object(local,'OBSERVERS',[abort]),patch.object(local.LocalHttpGate,'open',capture):outcome,_=self.execute(self.envelope('generated-refusal'),opener)
  self.assertEqual(len(captured),1);self.assertIs(outcome,captured[0]);self.assertIn('nothing more is sent',str(outcome))
  self.assertFalse(opener.chat_called)

 def test_secondary_settlement_error_does_not_replace_primary_and_adds_note(self):
  from cwo_core.invocation_ledger import InvocationLedger
  self.set_quota(20)
  for index,error in enumerate([RuntimeError('primary-runtime'),SystemExit('primary-stop')]):
   with self.subTest(error=type(error).__name__):
    opener=FakeHardenedOpener();called=[];finish=InvocationLedger.finish
    def observe(event):
     if event['event']=='request':called.append(True);raise error
    def broken(ledger,reservation_id,outcome,**kwargs):
     if outcome=='unknown':raise OSError('fixture-secondary-storage')
     return finish(ledger,reservation_id,outcome,**kwargs)
    with patch.object(local,'OBSERVERS',[observe]),patch.object(InvocationLedger,'finish',broken):
     outcome,_=self.execute(self.envelope(f'settlement-failure-{index}', epic=f'epic-secondary-{index}'),opener)
    self.assertTrue(called);self.assertIs(outcome,error);self.assertFalse(opener.chat_called)
    self.assertTrue(any('fixture-secondary-storage' in note for note in getattr(error,'__notes__',[])))
    attempt=self.attempts()[-1];self.assertEqual(attempt['state'],'reconciliation-required');self.assertEqual(attempt['charge'],attempt['amount'])
 def test_secondary_terminal_observer_with_broken_repr_keeps_primary(self):
  class Unrenderable(RuntimeError):
   def __repr__(self):raise RuntimeError('repr failed')
  error=RuntimeError('primary-stays');opener=FakeHardenedOpener()
  def observe(event):
   if event['event']=='request':raise error
   if event['event']=='terminal':raise Unrenderable('secondary')
  with patch.object(local,'OBSERVERS',[observe]):outcome,_=self.execute(self.envelope('unrenderable-secondary'),opener)
  self.assertIs(outcome,error);self.assertTrue(any('unrenderable secondary' in note for note in error.__notes__))
  self.assertFalse(opener.chat_called);attempt=self.attempts()[-1];self.assertEqual(attempt['outcome'],'unknown');self.assertEqual(attempt['charge'],attempt['amount'])

 def test_terminal_observer_keeps_original_exception_identity_and_charge(self):
  self.set_quota(20)
  for phase in ['invocation-intent','request']:
   for index,error in enumerate([RuntimeError('fixture-runtime'),SystemExit('fixture-stop'),InvocationLedgerError('fixture-ledger')]):
    with self.subTest(phase=phase,error=type(error).__name__):
     opener=FakeHardenedOpener()
     def abort(event):
      if event['event']==phase:
       local.open_ledger().finish(event['attempt']['reservation_id'],'aborted-before-effect',reason='fixture terminal')
       raise error
     with patch.object(local,'OBSERVERS',[abort]):outcome,_=self.execute(self.envelope(f'failure-{phase}-{index}'),opener)
     self.assertIs(outcome,error,'settlement replaced the original observer failure')
     attempt=self.attempts()[-1];self.assertEqual(attempt['outcome'],'aborted-before-effect');self.assertEqual(attempt['charge'],attempt['amount']);self.assertFalse(opener.chat_called)

if __name__ == "__main__":
    unittest.main()
