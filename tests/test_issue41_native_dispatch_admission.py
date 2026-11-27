"""Native dispatch refuses missing sizing before it reaches a worker."""
from contextlib import ExitStack
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))

import registered_contained_pool_host as pool  # noqa: E402
import registered_contained_pool_preparation as prepare  # noqa: E402
import registered_native_pool_client as client  # noqa: E402
import registered_pool_ordinary_runtime as runtime  # noqa: E402
from tests import test_ordinary_pool_hosted_e2e as hosted  # noqa: E402


class Issue41NativeAdmissionTests(unittest.TestCase):
    def test_signed_pool_scope_needs_each_bead_work_plan_before_dispatch(self):
        with hosted._pool_test_directory() as directory, ExitStack() as stack:
            stack.enter_context(patch.object(hosted, '_LAUNCHER', Path('/usr/bin/true')))
            fixture = hosted._HostedPoolFixture(directory, 2, stack)
            issue = fixture.database.commands.issues['pool-task-1']
            del issue['metadata']['cwo_ready_set_admission']['work_plan']
            # Keep the aggregate allowance and reissue the normal signed scope.
            with prepare.prepare_pool(fixture.project, fixture.args) as pending:
                request_path = prepare.retain_approved_pool(pending, 'EXAMPLE-issue41-native-adoption')
            request = json.loads(request_path.read_bytes())
            host = pool.open_approved_pool(fixture.project, request['pool_id'])
            self.assertTrue(client.submit(dict(request, mode='validate-only'), host=host)['authority_validated'])

            launch = stack.enter_context(patch.object(runtime, 'run_registered_contained_pool'))
            with self.assertRaisesRegex(ValueError, 'Each Bead needs original pool readiness metadata'):
                client.submit(request, host=host)

            launch.assert_not_called()
            self.assertEqual(fixture.database.commands.claim_order, [])
            for name in ('execution-intent.json', 'admission.json', 'ledger'):
                self.assertFalse((request_path.parent / name).exists(), name)
