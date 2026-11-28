"""Missing workload sizing reaches neither HTTP dispatch boundary."""
from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))

import dispatch_work as dispatch  # noqa: E402
import qualified_review_dispatch as review  # noqa: E402
from cwo_core import audit  # noqa: E402
from cwo_core.host_records import HostRecordStore, using_test_store  # noqa: E402
from cwo_core.invocation_ledger import InvocationLedger  # noqa: E402
from tests.test_local_http_admission import workload_record  # noqa: E402
from tests.test_qualified_review_dispatch import workflow  # noqa: E402
from tests.test_route_feasibility_preparation import bind  # noqa: E402


class Issue41HttpAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory(prefix='EXAMPLE-issue41-http-')))
        self.ledger = InvocationLedger(self.root / 'ledger')
        self.dns = self.enterContext(patch.object(dispatch, 'pinned_local_endpoint_address'))
        self.opener = self.enterContext(patch.object(dispatch, '_build_local_opener'))

    def local_cli(self, action):
        args = ['dispatch_work.py', '--local-workload', str(self.root / 'workload.json'),
                '--local-ok', '--prefer-local', '--local-profile', 'openshift-ai-vllm',
                '--requested-role', 'documentation', '--local-model', 'EXAMPLE-vllm',
                '--local-max-tokens', '32', '--local-timeout', '5',
                '--local-base-url', 'http://127.0.0.1:1', '--json', action]
        with patch.object(sys, 'argv', args), redirect_stdout(StringIO()):
            dispatch.main()

    def test_local_execute_rejects_missing_estimate_source_even_with_staged_admission(self):
        host = HostRecordStore.for_tests(self.root / 'host')
        self.enterContext(using_test_store(host))
        self.enterContext(patch.object(audit, 'AUDIT_LOG', host.audit_file))
        self.enterContext(patch.object(audit, 'HOST_AUDIT_LOG', host.audit_file))
        self.enterContext(patch.dict('os.environ', {'CWO_OPENSHIFT_AI_VLLM_API_KEY': ''}))
        self.enterContext(patch.object(dispatch.local_http_admission.http, 'open_ledger', return_value=self.ledger))
        workload = workload_record()
        workload_path = self.root / 'workload.json'
        workload_path.write_text(json.dumps(workload), encoding='utf-8')
        with self.assertRaises(SystemExit) as staged:
            self.local_cli('--prepare-local-admission')
        self.assertEqual(staged.exception.code, 0)
        self.assertEqual(len(host.find('dispatch')), 1)

        del workload['route_input']['nodes'][0]['estimate_source']
        bind(workload['route_input'])
        workload_path.write_text(json.dumps(workload), encoding='utf-8')
        with self.assertRaisesRegex(SystemExit, 'original workload failed planning'):
            self.local_cli('--execute-local')

        self.dns.assert_not_called()
        self.opener.assert_not_called()
        attempts = self.ledger.summary(workload['route_input']['aggregate_id'])['attempts_by_state']
        self.assertEqual(sum(attempts.values()), 0)

    def test_registered_review_cannot_issue_a_host_with_missing_workload_sizing(self):
        self.enterContext(patch.object(dispatch, 'QUALIFIED_REVIEW_INVOCATION_AVAILABLE', True))
        original = workflow()
        # A valid host can issue its original ticket without an invocation or a network effect.
        host = review.RegisteredReviewHost(original, ledger=self.ledger, base_url='http://127.0.0.1:1')
        now = self.ledger.current_time()
        self.assertEqual(host.issue('plan', now=now, expires_at=now + 60).node_id, 'plan')

        del original['nodes'][0]['estimate_source']
        bind(original)
        with self.assertRaisesRegex(review.admission.AdmissionError, 'complete feasibility check'):
            review.RegisteredReviewHost(original, ledger=self.ledger, base_url='http://127.0.0.1:1')
        with self.assertRaisesRegex(review.admission.AdmissionError, 'ticket from this registered review host'):
            host.dispatch({'ready': True, 'timeout_seconds': 600})

        self.dns.assert_not_called()
        self.opener.assert_not_called()
        self.assertFalse(self.ledger.root.exists())
