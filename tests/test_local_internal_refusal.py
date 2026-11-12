import sys,unittest
from unittest.mock import patch
sys.path.insert(0,'scripts')
from tests.test_local_invocation_reservation import RouteTestCase
from tests.test_local_dispatch import FakeHardenedOpener
from cwo_core import local_invocation as local
from cwo_core.invocation_ledger import InvocationLedgerError
class InternalRefusal(RouteTestCase):
 def test_internal_ledger_refusal_stays_distinct_from_observer_failure(self):
  opener=FakeHardenedOpener()
  with patch.object(local.LocalHttpGate,'open',side_effect=InvocationLedgerError('fixture-internal-refusal')):
   outcome,_=self.execute(self.envelope('internal-refusal'),opener)
  self.assertIsInstance(outcome,SystemExit);self.assertIn('controlled local invocation refused: fixture-internal-refusal',str(outcome));self.assertFalse(opener.chat_called);attempt=self.attempts()[-1];self.assertEqual(attempt['outcome'],'unknown');self.assertEqual(attempt['charge'],attempt['amount'])
if __name__=='__main__':unittest.main()
