import io,sys,unittest
sys.path.insert(0,'scripts')
from tests.test_local_invocation_reservation import RouteTestCase
import json
from urllib.error import URLError
from urllib.error import HTTPError
from unittest.mock import patch
from tests.test_local_dispatch import FakeHardenedOpener
from cwo_core import local_invocation as local
class Body(io.BytesIO):
 def __init__(self):super().__init__(b'opaque observer payload');self.reads=0;self.closes=0
 def read(self,*args):self.reads+=1;return super().read(*args)
 def close(self):self.closes+=1;return super().close()
class ObserverHttp(RouteTestCase):
 def test_observer_http_exception_identity_and_no_body_handling(self):
  self.set_quota(20)
  for phase in ['invocation-intent','request']:
   for kind in ['url','http']:
    with self.subTest(phase=phase,kind=kind):
     body=Body();self.addCleanup(body.close);error=URLError('observer-url') if kind=='url' else HTTPError('http://127.0.0.1:8000/post',403,'observer-http',{},body)
     def observe(event):
      if event['event']==phase:
       local.open_ledger().finish(event['attempt']['reservation_id'],'aborted-before-effect',reason='fixture terminal')
       raise error
     opener=FakeHardenedOpener()
     with patch.object(local,'OBSERVERS',[observe]):outcome,_=self.execute(self.envelope(f'http-observer-{phase}-{kind}'),opener)
     print(json.dumps({'phase':phase,'kind':kind,'original_identity':outcome is error,'body_reads':body.reads,'body_closes':body.closes}))
     self.assertIs(outcome,error);self.assertEqual((body.reads,body.closes),(0,0));self.assertFalse(opener.chat_called)
     attempt=self.attempts()[-1];self.assertEqual(attempt['outcome'],'aborted-before-effect');self.assertEqual(attempt['charge'],attempt['amount'])

class ObserverClassification(RouteTestCase):
 def test_nonterminal_observer_classification_and_unrenderable_primary(self):
  from cwo_core.invocation_ledger import InvocationTimeout,InvocationCancelled
  class BadText(RuntimeError):
   def __str__(self):raise RuntimeError('str failed')
   def __repr__(self):raise RuntimeError('repr failed')
  cases=[(InvocationTimeout('timeout'),'timeout'),(URLError(TimeoutError('reason')),'timeout'),
         (InvocationCancelled('cancelled'),'cancelled'),(BadText(),'unknown')]
  self.set_quota(20)
  for phase in ['invocation-intent','request']:
   for index,(error,expected) in enumerate(cases):
    with self.subTest(phase=phase,index=index):
     opener=FakeHardenedOpener()
     def observe(event):
      if event['event']==phase:raise error
     with patch.object(local,'OBSERVERS',[observe]):
      outcome,_=self.execute(self.envelope(f'classification-{phase}-{index}'),opener)
     self.assertIs(outcome,error);self.assertFalse(opener.chat_called)
     attempt=self.attempts()[-1];self.assertEqual(attempt['outcome'],'aborted-before-effect' if phase=='invocation-intent' else expected);self.assertEqual(attempt['charge'],attempt['amount'])


 def test_genuine_transport_urlerror_keeps_dispatch_translation(self):
  opener=FakeHardenedOpener()
  with patch.object(opener,'open',side_effect=URLError('transport-unavailable')):
   outcome,_=self.execute(self.envelope('genuine-transport-urlerror'),opener)
  self.assertIsInstance(outcome,SystemExit);self.assertIn('transport-unavailable',str(outcome))
  attempt=self.attempts()[-1];self.assertEqual(attempt['outcome'],'unknown');self.assertEqual(attempt['charge'],attempt['amount'])

if __name__ == "__main__":
    unittest.main()
