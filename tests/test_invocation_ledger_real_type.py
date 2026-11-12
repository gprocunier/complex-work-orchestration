import sys,unittest
sys.path.insert(0,'scripts')
from tests.test_invocation_ledger import LedgerTestCase,REQUEST,FakeEffect
class SharedTypeClassification(LedgerTestCase):
 def test_direct_ledger_uses_real_exception_type_for_unknown_settlement(self):
  class Primary(RuntimeError):
   @property
   def __class__(self):raise RuntimeError('secondary-class-access')
  error=Primary('direct-primary');reservation=self.reserve('class-direct');effect=FakeEffect(raises=error)
  try:self.ledger.invoke(reservation['reservation_id'],REQUEST,effect)
  except BaseException as outcome:self.assertIs(outcome,error)
  else:self.fail('primary exception did not propagate')
  attempt=self.ledger.attempt(reservation['reservation_id']);self.assertEqual(attempt['state'],'terminal');self.assertEqual(attempt['outcome'],'unknown');self.assertEqual(attempt['charge'],attempt['amount']);self.assertEqual(effect.calls,[REQUEST])
if __name__=='__main__':unittest.main()
