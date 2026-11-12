"""Actual opener request processing with fake HTTP and synchronous observers."""
import io
import json
import subprocess
import sys
import threading
import time
import unittest
import urllib.request
from urllib.response import addinfourl
from unittest.mock import patch

from tests.test_local_invocation_reservation import RouteTestCase
from tests.test_local_dispatch import FakeHardenedOpener
import dispatch_work
from cwo_core import local_invocation as local


class Handle:
    def __init__(self, callback=None):self.callback=callback
    def require_intent(self):
        return None  # Deliberately trusted fake; real-ledger cases live in test_local_gate_intent.
    def report(self, *args):
        if self.callback:self.callback(*args)


class Http(urllib.request.HTTPHandler):
    def __init__(self):super().__init__();self.requests=[]
    def http_open(self, req):
        self.requests.append((req.get_method(),req.full_url,dict(req.header_items()),req.data))
        response=addinfourl(io.BytesIO(b'{}'),{},req.full_url,200)
        response.msg='OK'
        return response


class GateBoundaryTests(unittest.TestCase):
    def fixture(self, callback=None, preflight=None):
        req=urllib.request.Request('http://127.0.0.1:8000/post',data=b'bound body',headers={'X-Bound':'yes'},method='POST')
        http=Http();opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),http)
        gate=local.LocalHttpGate(Handle(callback),local.reserved_requests(req,preflight)).bind(opener)
        return req,gate,http

    def test_observer_mutation_cannot_change_effective_request(self):
        for field in ('body','url','headers','method'):
            with self.subTest(field=field):
                req,gate,http=self.fixture()
                def mutate(*_):
                    if field=='body':req.data=b'unapproved'
                    elif field=='url':req.full_url='http://127.0.0.1:8000/unapproved'
                    elif field=='headers':req.add_header('X-Bound','unapproved')
                    else:req.method='DELETE'
                gate._handle.callback=mutate
                error=None
                try:gate.open(req,timeout=5)
                except (SystemExit,TypeError) as exc:error=exc
                self.assertEqual(http.requests,[], 'observer changed the actual transport request')
                self.assertIsNotNone(error)

    def test_transport_body_override_is_refused_before_opener_processing(self):
        req,gate,http=self.fixture();error=None
        try:gate.open(req,data=b'unapproved',timeout=5)
        except (SystemExit,TypeError) as exc:error=exc
        self.assertEqual(http.requests,[]);self.assertIsNotNone(error)


    def test_lock_across_callback_mutant_is_detected_within_bound(self):
        with self.assertRaises(subprocess.TimeoutExpired) as raised:
            _run_bounded_reentry(hold_lock=True, timeout=3)
        self.assertIn(b"reentry-callback-entered", raised.exception.stdout or b"")


    def test_validated_preflight_then_exact_post_positive(self):
        preflight=urllib.request.Request('http://127.0.0.1:8000/models',method='GET')
        req,gate,http=self.fixture(preflight=preflight)
        with gate.open(preflight,timeout=5):pass
        gate.validated_preflight(completed_monotonic=time.monotonic(), maximum_gap_ms=1000)
        with gate.open(req,timeout=5):pass
        self.assertEqual([r[0] for r in http.requests],['GET','POST'])
        self.assertEqual(http.requests[1][3],b'bound body')
        self.assertIsInstance(gate.preflight_to_post_ms, int)


    def test_observer_cannot_rearm_freshness_after_validation(self):
        preflight = urllib.request.Request('http://127.0.0.1:8000/models', method='GET')
        req, gate, http = self.fixture(preflight=preflight)
        with gate.open(preflight, timeout=5):
            pass

        gate.validated_preflight(completed_monotonic=time.monotonic() - 2, maximum_gap_ms=1000)
        gate._handle.callback = lambda *_: gate.validated_preflight(
            completed_monotonic=time.monotonic(), maximum_gap_ms=1000)
        with self.assertRaises(SystemExit):
            gate.open(req, timeout=5)
        self.assertEqual([r[0] for r in http.requests], ['GET'])


    def test_simultaneous_open_is_one_use(self):
        req,gate,http=self.fixture();entered=threading.Event();release=threading.Event();errors=[]
        def observer(*_):
            if not entered.is_set():entered.set();self.assertTrue(release.wait(2))
        gate._handle.callback=observer
        def invoke():
            try:
                with gate.open(req,timeout=5):pass
            except BaseException as exc:errors.append(exc)
        first=threading.Thread(target=invoke);second=threading.Thread(target=invoke)
        first.start();self.assertTrue(entered.wait(2));second.start();second.join(1);release.set();first.join(2);second.join(2)
        self.assertFalse(first.is_alive() or second.is_alive(),'gate deadlocked')
        self.assertEqual(len(http.requests),1);self.assertEqual(len(errors),1)

    def test_claimed_preflight_is_not_a_validated_model_result(self):
        preflight=urllib.request.Request('http://127.0.0.1:8000/models',method='GET')
        req,gate,http=self.fixture(preflight=preflight)
        with gate.open(preflight,timeout=5):pass
        error=None
        try:gate.open(req,timeout=5)
        except SystemExit as exc:error=exc
        self.assertEqual([r[0] for r in http.requests],['GET']);self.assertIsNotNone(error)


    def test_reentry_consumes_at_most_one_post_without_deadlock(self):
        try:
            completed = _run_bounded_reentry(timeout=10)
        except subprocess.TimeoutExpired as exc:
            self.fail(f"synchronous observer reentry deadlocked within bound: {exc.stdout!r}")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads(completed.stdout.splitlines()[-1])
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["refused"], [True])
        self.assertEqual(result["request"], ["POST", "http://127.0.0.1:8000/post", "bound body"])

    def test_observer_cannot_replace_bound_transport(self):
        req, gate, http = self.fixture()
        other = Http()
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), other)
        gate._handle.callback = lambda *_: gate.bind(opener)
        with self.assertRaises(SystemExit):
            gate.open(req, timeout=5)
        self.assertEqual(http.requests + other.requests, [])


class ChangingBodyProcessor(urllib.request.BaseHandler):
    def http_request(self, req):
        req.data = b'unreserved'
        return req


class PublicOpenerMutationTests(unittest.TestCase):
    def test_observer_added_processor_is_refused_before_transport(self):
        req, gate, http = GateBoundaryTests().fixture()
        opener = gate._opener
        gate._handle.callback = lambda *_: opener.add_handler(ChangingBodyProcessor())
        with self.assertRaises(SystemExit):
            gate.open(req, timeout=5)
        self.assertEqual(http.requests, [])

    def test_callback_deadline_api_is_refused_and_numeric_positive_still_works(self):
        preflight = urllib.request.Request('http://127.0.0.1:8000/models', method='GET')
        req, gate, http = GateBoundaryTests().fixture(preflight=preflight)
        opener = gate._opener
        with gate.open(preflight, timeout=5):
            pass
        with self.assertRaises(TypeError):
            gate.validated_preflight(lambda: opener.add_handler(ChangingBodyProcessor()))
        gate.validated_preflight(completed_monotonic=time.monotonic(), maximum_gap_ms=1000)
        with gate.open(req, timeout=5):
            pass
        self.assertEqual([r[0] for r in http.requests], ['GET', 'POST'])
        self.assertEqual(http.requests[-1][3], b'bound body')


class ActualSendDeadlineTests(RouteTestCase):
    def test_expiry_during_post_observer_sends_no_post(self):
        clock=[1000.0];opener=FakeHardenedOpener()
        def advance(event):
            if event['event']=='request' and event['detail'].get('kind')=='post':clock[0]+=2
        with patch.object(dispatch_work.time,'monotonic',lambda:clock[0]),patch.object(local,'OBSERVERS',[advance]):
            outcome,_=self.execute(self.glm_envelope('expiry-in-gate'),opener)
        self.assertFalse(opener.chat_called,'POST passed after observer expired preflight')
        self.assertIsInstance(outcome,SystemExit);self.assertIn('expired before POST',str(outcome))

    def test_allowed_send_records_age_after_observer_work(self):
        clock=[1000.0];opener=FakeHardenedOpener()
        def advance(event):
            if event['event']=='request' and event['detail'].get('kind')=='post':clock[0]+=0.5
        with patch.object(dispatch_work.time,'monotonic',lambda:clock[0]),patch.object(local,'OBSERVERS',[advance]):
            outcome,_=self.execute(self.glm_envelope('age-at-transport'),opener)
        self.assertIsInstance(outcome,dict,repr(outcome));self.assertTrue(opener.chat_called)
        self.assertEqual(outcome['model_preflight']['to_post_ms'],500)


def _run_bounded_reentry(*, hold_lock=False, timeout=10):
    script = ("from tests.test_local_gate_boundaries import _reentry_child; "
              f"_reentry_child(hold_lock={hold_lock!r})")
    # subprocess.run kills and reaps the disposable child on timeout.
    return subprocess.run([sys.executable, "-c", script], capture_output=True, timeout=timeout)


def _reentry_child(*, hold_lock=False):
    req, gate, http = GateBoundaryTests().fixture()
    entered, refused = [], []
    def reenter(*_):
        if not entered:
            entered.append(True)
            print("reentry-callback-entered", flush=True)
            try:
                gate.open(req, timeout=5)
            except SystemExit:
                refused.append(True)
    gate._handle.callback = reenter
    if hold_lock:
        report = gate._handle.report
        def locked_report(*args):
            with gate._lock:
                report(*args)
        gate._handle.report = locked_report
    with gate.open(req, timeout=5):
        pass
    row = http.requests[0]
    print(json.dumps({"count": len(http.requests), "refused": refused,
                      "request": [row[0], row[1], row[3].decode()]}), flush=True)
