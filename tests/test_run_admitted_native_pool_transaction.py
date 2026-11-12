"""Pre-import authority and controlled validate-only CLI regressions.

Historical plan versions still parse. A submitted adapter may NOT manufacture
its own recovery authority by executing before denial.
"""
from __future__ import annotations
import copy
import hashlib
import io
import json
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import run_admitted_native_pool_transaction as launcher
import registered_native_pool_client as client
from cwo_core.native_pool_transaction import (
    MAINTENANCE_PLAN_SCHEMA, TransactionRuntime, seal_transaction_plan,
    validate_transaction_plan,
)
from cwo_core.native_pool_contracts import canonical_sha256
from tests.test_native_pool_transaction import (
    bead, transaction_plan, recovery_plan, campaign_recovery_plan,
    final_campaign_recovery_plan, seventh_campaign_recovery_plan,
    eighth_campaign_recovery_plan,
)
from tests import test_maintenance_authority as maintenance_fixtures


def write_adapter(plan, marker=None):
    path=Path(plan['runtime_adapter_path'])
    prefix=f"from pathlib import Path\nPath({str(marker)!r}).touch()\n" if marker else ''
    path.write_text(prefix+"from cwo_core.native_pool_transaction import TransactionRuntime\n"
        "def build_transaction_runtime(plan):\n"
        "    noop=lambda *a, **k: {}\n"
        "    return TransactionRuntime(lambda: plan['budget']['cumulative_before'], noop, noop, noop, noop, noop, noop, noop, noop, noop)\n")
    plan['runtime_adapter_sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
    plan['plan_sha256']=canonical_sha256({k:v for k,v in plan.items() if k!='plan_sha256'})


class LauncherAuthorityTests(unittest.TestCase):
    def test_w17_r3_public_structural_validation_and_no_host_execute_before_imports(self):
        """New public ingress, including hostless zero-spend pre-import checks."""
        request = {'version': 1, 'mode': 'execute', 'pool_id': 'EXAMPLE-pool',
                   'workers': ['EXAMPLE-worker']}
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'EXAMPLE-request.json'
            path.write_text(json.dumps(request))
            original = __import__
            def guarded(name, *args, **kwargs):
                if name.startswith(('registered_native_pool_host', 'registered_n1', 'run_native_pool_live')):
                    raise AssertionError('Structural ingress imported a runtime')
                return original(name, *args, **kwargs)
            with patch('builtins.__import__', side_effect=guarded):
                out = io.StringIO()
                with redirect_stdout(out):
                    self.assertEqual(launcher.main(['--pool-request', str(path), '--validate-only']), 0)
                self.assertEqual(json.loads(out.getvalue()), client.validate_structure(dict(request, mode='validate-only')))
                self.assertFalse(json.loads(out.getvalue())['authority_validated'])
                with redirect_stderr(io.StringIO()) as err:
                    self.assertEqual(launcher.main(['--pool-request', str(path)]), 2)
                self.assertIn('registered-pool-host-required', err.getvalue())
            # Exercise the actual executable caller, outside this imported main.
            result = subprocess.run([sys.executable, str(Path(launcher.__file__)),
                '--pool-request', str(path), '--validate-only'], cwd=ROOT,
                capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)['model_calls'], 0)

    def test_w17_r4_client_data_cannot_supply_host_or_fabricate_factories(self):
        """Finite ingress closes caller-controlled configuration/authority fields."""
        request = {'version': 1, 'mode': 'validate-only', 'pool_id': 'EXAMPLE-pool',
                   'workers': ['EXAMPLE-worker']}
        bad = [dict(request, **{field: 'EXAMPLE-untrusted'}) for field in (
            'host', 'configuration', 'runtime_adapter_path', 'runtime_adapter_sha256',
            'factory', 'authority', 'trusted_factories', 'maintenance_operation')]
        bad += [dict(request, **changes) for changes in (
            {'version': True}, {'mode': 'EXAMPLE-mode'}, {'pool_id': '../EXAMPLE'},
            {'workers': []}, {'workers': ['EXAMPLE-worker'] * 2},
            {'workers': ['EXAMPLE-' + str(i) for i in range(4)]}, {'workers': [{}]})]
        for invalid in bad:
            with self.subTest(request=invalid), self.assertRaises(ValueError):
                client.submit(invalid)
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'EXAMPLE-request.json'
            path.write_text(json.dumps(bad[0]))
            with redirect_stderr(io.StringIO()):
                self.assertEqual(launcher.main(['--pool-request', str(path), '--validate-only']), 2)
            path.write_text(json.dumps(request))
            with redirect_stderr(io.StringIO()):
                self.assertEqual(launcher.main(['--pool-request', str(path), '--output', str(Path(d) / 'EXAMPLE-output')]), 2)
            self.assertFalse((Path(d) / 'EXAMPLE-output').exists())

    def test_w17_r4_c1_public_caller_actual_host_n1_n2_n3_and_authority_split(self):
        """Public caller consumes the registered pool host and original N1 APIs; only OS/RPC fake."""
        from tests import test_registered_native_pool_host as pools
        with pools.F.WorkflowTests.read_only_source_family(self) as source:
            for size in (1, 2, 3):
                with self.subTest(size=size):
                    fixture = pools.PoolTests('runTest')
                    fixture._outcome = self._outcome
                    try:
                        host = fixture.cohort(size, archive_schedule='settled', shared_source=True, source_evidence=source())
                        before = [f.settings['state_store'].read_state() for f in fixture.fixtures]
                        request = host.config.request('execute')
                        path = host.config.state.parent / 'EXAMPLE-request.json'
                        path.write_text(json.dumps(request))
                        out = io.StringIO()
                        with redirect_stdout(out):
                            self.assertEqual(launcher.main(['--pool-request', str(path), '--validate-only'], host=host), 0)
                        self.assertTrue(json.loads(out.getvalue())['authority_validated'])
                        self.assertEqual(before, [f.settings['state_store'].read_state() for f in fixture.fixtures])
                        self.assertFalse(list(host.config.state.iterdir()))
                        self.assertFalse(fixture.ledger.root.exists())
                        self.assertTrue(all(not getattr(f.fixture, 'spawned', []) for f in fixture.fixtures))
                        for fake in (object(), {'host': host, 'accepted': True}):
                            with self.assertRaisesRegex(ValueError, 'exact original'):
                                client.submit(request, host=fake)
                        with patch.object(host, 'run', return_value={'accepted': True}):
                            with self.assertRaisesRegex(ValueError, 'original bound'):
                                client.submit(request, host=host)
                        with redirect_stderr(io.StringIO()):
                            self.assertEqual(launcher.main(['--pool-request', str(path)], host=host), 2)
                        self.assertFalse(fixture.ledger.root.exists())
                        fixture.adopt()
                        out = io.StringIO()
                        with redirect_stdout(out):
                            self.assertEqual(launcher.main(['--pool-request', str(path)], host=host), 0)
                        report = json.loads(out.getvalue())
                        self.assertEqual(report, host.status())
                        self.assertEqual(report['states'], ['validated'] * size)
                        fixture.assert_accounting(size)
                        for member in fixture.fixtures:
                            self.assertEqual(len(member.fixture.spawned), 2)
                            self.assertFalse((member.case.host.target / 'result.txt').exists())
                        with redirect_stderr(io.StringIO()) as err:
                            self.assertEqual(launcher.main(['--pool-request', str(path)], host=host), 2)
                        self.assertIn('never redispatch', err.getvalue())
                    finally:
                        fixture.doCleanups()

    def test_missing_authority_rejected_before_module_execution_in_separate_process(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            builders=[transaction_plan, recovery_plan, campaign_recovery_plan,
                      final_campaign_recovery_plan,seventh_campaign_recovery_plan,
                      eighth_campaign_recovery_plan]
            for number,builder in enumerate(builders):
                here=root/str(number);here.mkdir()
                if builder==transaction_plan:
                    plan=builder(here,[bead('b','result.txt')])
                elif builder==recovery_plan:
                    plan=builder(here,bead('b','result.txt'))
                else:
                    plan,_=builder(here)
                marker=here/'imported'
                write_adapter(plan,marker)
                self.assertEqual(validate_transaction_plan(plan),[])
                filename=here/'plan.json';filename.write_text(json.dumps(plan))
                for validate_only in (False,True):
                    args=[sys.executable,str(ROOT/'scripts/run_admitted_native_pool_transaction.py'),
                          '--plan',str(filename),'--journal',str(here/'journal'),
                          '--output',str(here/'result')]
                    if validate_only:args+=['--validate-only']
                    result=subprocess.run(args,cwd=ROOT,capture_output=True,text=True,timeout=20)
                    self.assertEqual(result.returncode,2,result.stdout)
                    self.assertIn('controller-adapter-authority-missing',result.stderr)
                    self.assertFalse(marker.exists(),result.stderr)
                    self.assertFalse((here/'journal').exists())
                    self.assertFalse((here/'result').exists())

    def test_registered_finite_positive_and_validate_only_no_import(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            for size in (1,2,3):
                plan=transaction_plan(root/str(size),[bead(str(i),str(i)+'.txt') for i in range(size)])
                marker=root/f'import-{size}'
                write_adapter(plan,marker)
                registry={plan['runtime_adapter_path']:plan['runtime_adapter_sha256']}
                result=launcher.validate_authorized_plan(plan,trusted_factories=registry)
                self.assertTrue(result['validation_passed'])
                self.assertFalse(result['dispatch_authorized'])
                self.assertFalse(result['runtime_loaded'])
                self.assertFalse(marker.exists())
                runtime=launcher._load_runtime(plan,trusted_factories=registry)
                self.assertIs(type(runtime),TransactionRuntime)
                self.assertTrue(marker.exists())

    def test_adapter_drift_rejected_before_execution(self):
        with tempfile.TemporaryDirectory() as d:
            plan=transaction_plan(Path(d),[bead('b','result.txt')]);write_adapter(plan)
            registry={plan['runtime_adapter_path']:plan['runtime_adapter_sha256']}
            Path(plan['runtime_adapter_path']).write_text("raise AssertionError('must-not-import')")
            with self.assertRaisesRegex(ValueError,'trusted registry'):
                launcher._load_runtime(plan,trusted_factories=registry)

    def test_f5_held_route_v8_opaque_authority_positive_no_import_before_claim(self):
        from cwo_core import native_live_availability
        self.enterContext(patch.object(native_live_availability, 'N1_LIVE_AVAILABLE', True))
        fixture=maintenance_fixtures.MaintenanceAuthorityTests('test_product_authority_claim_settlement_and_fresh_continuation')
        fixture.setUp();self.addCleanup(fixture.doCleanups)
        issue=bead('b','result.txt')
        plan=transaction_plan(fixture.controller/'plan',[issue],cumulative_before=0)
        plan.update(version=8,schema=MAINTENANCE_PLAN_SCHEMA,authority_sha256=fixture.mission_hash,
                    runtime_adapter_path=str(fixture.adapter))
        plan['budget']={'mode':'maintenance-unbounded','cumulative_before':0,'reserved_sessions':1}
        marker=fixture.marker;write_adapter(plan,marker)
        fixture.registry['installed-native-v1']['adapter_sha256']=plan['runtime_adapter_sha256']
        fixture.verifier=fixture.make_verifier()
        plan=seal_transaction_plan(plan)
        _,operation,_=fixture.operation()
        operation.update(plan_sha256=plan['plan_sha256'],model=plan['selected_model'])
        # This fixture mission only authorizes test-model; join real plan to it.
        plan['selected_model']='test-model'
        plan['children'][0]['requested_model']='test-model'
        plan=seal_transaction_plan(plan);operation['plan_sha256']=plan['plan_sha256']
        operation['model']='test-model'
        operation['reservation']['sessions']=1
        directive=fixture.sign_operation(operation)
        cap=fixture.verifier.verify_operation(plan,operation,directive)
        result=launcher.validate_authorized_plan(plan,maintenance_operation=cap,
            maintenance_verifier=fixture.verifier)
        self.assertTrue(result['validation_passed']);self.assertFalse(marker.exists())
        runtime=launcher._load_runtime(plan,maintenance_operation=cap,
            maintenance_verifier=fixture.verifier)
        self.assertTrue(marker.exists());self.assertIs(runtime.maintenance_operation,cap)
        self.assertEqual(fixture.store.read_state()['operations'][operation['operation_id']]['state'],'claimed')
        with self.assertRaisesRegex(ValueError,'consumed|claimed'):
            launcher._load_runtime(plan,maintenance_operation=cap,maintenance_verifier=fixture.verifier)

    def test_v8_cli_refuses_without_an_embedding_controller(self):
        with tempfile.TemporaryDirectory() as d:
            here=Path(d)
            plan=transaction_plan(here,[bead('b','result.txt')])
            plan.update(version=8,schema=MAINTENANCE_PLAN_SCHEMA,authority_sha256='a'*64)
            plan['budget']={'mode':'maintenance-unbounded','cumulative_before':0,'reserved_sessions':1}
            marker=here/'imported';write_adapter(plan,marker)
            plan=seal_transaction_plan(plan)
            self.assertEqual(validate_transaction_plan(plan),[])
            filename=here/'plan.json';filename.write_text(json.dumps(plan))
            for validate_only in (False,True):
                args=[sys.executable,str(ROOT/'scripts/run_admitted_native_pool_transaction.py'),
                      '--plan',str(filename),'--journal',str(here/'journal'),'--output',str(here/'result')]
                if validate_only:args+=['--validate-only']
                result=subprocess.run(args,cwd=ROOT,capture_output=True,text=True,timeout=20)
                self.assertEqual(result.returncode,2,result.stdout)
                self.assertIn('opaque-operation-required',result.stderr)
                self.assertFalse(marker.exists(),result.stderr)
                self.assertFalse((here/'journal').exists())
                self.assertFalse((here/'result').exists())

    def test_v8_does_not_accept_worker_json_as_capability(self):
        with tempfile.TemporaryDirectory() as d:
            plan=transaction_plan(Path(d),[bead('b','result.txt')])
            plan.update(version=8,schema=MAINTENANCE_PLAN_SCHEMA)
            plan['budget']={'mode':'maintenance-unbounded','cumulative_before':239,'reserved_sessions':1}
            plan=seal_transaction_plan(plan)
            with self.assertRaisesRegex(ValueError,'opaque-operation-required'):
                launcher._load_runtime(plan,maintenance_operation={'accepted':True})


if __name__=='__main__':unittest.main()
