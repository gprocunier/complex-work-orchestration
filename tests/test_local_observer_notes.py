import sys,unittest
from unittest.mock import patch
sys.path.insert(0,'scripts')
from tests.test_local_invocation_reservation import RouteTestCase
from tests.test_local_dispatch import FakeHardenedOpener
from tests.test_invocation_ledger import LedgerTestCase,REQUEST,FakeEffect
from cwo_core import local_invocation as local

def primary(kind,base=RuntimeError):
 if kind=='tuple':
  error=base('primary-note-failure');error.__notes__=();return error
 def bad_notes(self):raise RuntimeError('secondary-notes-access')
 return type('BadNotes',(base,),{'__notes__':property(bad_notes)})('primary-note-failure')

class LocalNotes(RouteTestCase):
    pass


    def test_primary_retained_across_terminal_note_failure(self):
     self.set_quota(20)
     for phase in ['invocation-intent','request']:
      for kind in ['tuple','property']:
       with self.subTest(phase=phase,kind=kind):
        error=primary(kind);opener=FakeHardenedOpener()
        def observe(event):
         if event['event']==phase:raise error
         if event['event']=='terminal':raise RuntimeError('secondary-terminal')
        with patch.object(local,'OBSERVERS',[observe]):outcome,_=self.execute(self.envelope(f'notes-{phase}-{kind}'),opener)
        self.assertIs(outcome,error);self.assertFalse(opener.chat_called)
        attempt=self.attempts()[-1];self.assertEqual(attempt['outcome'],'aborted-before-effect' if phase=='invocation-intent' else 'unknown');self.assertEqual(attempt['charge'],attempt['amount'])

class LedgerNotes(LedgerTestCase):
 def test_invoke_and_context_keep_primary_when_terminal_annotation_fails(self):
  for route in ['invoke','context']:
   for kind in ['tuple','property']:
    with self.subTest(route=route,kind=kind):
     error=primary(kind);reservation=self.reserve(route+kind)
     def observe(event):
      if event['event']=='terminal':raise RuntimeError('secondary-terminal')
     try:
      if route=='invoke':self.ledger.invoke(reservation['reservation_id'],REQUEST,FakeEffect(raises=error),observers=[observe])
      else:
       with self.ledger.invocation(reservation['reservation_id'],REQUEST,observers=[observe]):raise error
     except BaseException as caught:outcome=caught
     else:self.fail('primary did not propagate')
     self.assertIs(outcome,error);attempt=self.ledger.attempt(reservation['reservation_id']);self.assertEqual(attempt['outcome'],'unknown');self.assertEqual(attempt['charge'],attempt['amount'])
 def test_interruption_identity_survives_failed_pending_save_and_bad_notes(self):
  original_save=self.ledger._save
  def broken_save(root,document):
   if any(item['state']=='reconciliation-required' for item in document['attempts'].values()):raise OSError('pending-save-failed')
   return original_save(root,document)
  for kind in ['tuple','property']:
   with self.subTest(kind=kind):
    error=primary(kind,KeyboardInterrupt);reservation=self.reserve('interrupt-'+kind)
    with patch.object(self.ledger,'_save',side_effect=broken_save):
     try:self.ledger.invoke(reservation['reservation_id'],REQUEST,FakeEffect(raises=error))
     except BaseException as caught:outcome=caught
     else:self.fail('interruption did not propagate')
    self.assertIs(outcome,error);attempt=self.ledger.attempt(reservation['reservation_id']);self.assertEqual(attempt['state'],'invocation-intent');self.assertEqual(attempt['charge'],attempt['amount'])
if __name__=='__main__':unittest.main()
