import sys,unittest
sys.path.insert(0,'scripts')
from tests.test_local_invocation_reservation import RouteTestCase
from unittest.mock import patch
from tests.test_local_dispatch import FakeHardenedOpener
from cwo_core import local_invocation as local
class ClassAccessor(RouteTestCase):

 def test_original_failure_survives_raising_class_metadata(self):
  class RaisingClass(RuntimeError):
   @property
   def __class__(self):raise RuntimeError('secondary-class-access')
  self.set_quota(20)
  for phase in ['invocation-intent','request']:
   with self.subTest(phase=phase):
    failure=RaisingClass('original-observer');opener=FakeHardenedOpener()
    def observe(event):
     if event['event']==phase:raise failure
    with patch.object(local,'OBSERVERS',[observe]):outcome,_=self.execute(self.envelope('class-'+phase),opener)
    self.assertIs(outcome,failure);self.assertFalse(opener.chat_called)
    attempt=self.attempts()[-1];self.assertEqual(attempt['outcome'],'aborted-before-effect' if phase=='invocation-intent' else 'unknown');self.assertEqual(attempt['charge'],attempt['amount'])
if __name__=='__main__':unittest.main()
