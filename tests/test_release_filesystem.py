"""Standing release-gate contract tests; synthetic rows are not OS qualification."""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import check_release_filesystem as gate  # noqa: E402
import validate_repository as validator  # noqa: E402


class ReleaseFilesystemTests(unittest.TestCase):
    def test_required_methods_preserve_original_eleven_and_sensitive_paths(self):
        original = [
            'atomic_publication_crash_leaves_one_readable_link_and_complete_bytes',
            'atomic_publication_mode_conflict_and_unavailable_primitive_refuse_without_final_entry',
            'pending_rotation_and_unreferenced_entry_recover_through_one_locked_maintenance_path',
            'maintenance_rotation_recovery_still_refuses_reference_and_scan_bound_failures_before_cleanup',
            'unsafe_unreferenced_entry_refusal_names_the_entry_and_manual_remedy_without_changes',
            'initial_rotation_journal_never_replaces_an_unrelated_existing_claim',
            'unrelated_transaction_of_the_same_quarantine_event_type_cannot_complete_pending_transaction',
            'only_unexpected_bytes_exceed_the_original_scan_bound_and_refuse_without_mutation',
            'dot_named_unreferenced_entry_is_quarantined_and_audited_with_the_other_entries',
            'first_quarantine_and_rotation_journals_publish_atomically_across_a_real_torn_write',
        ]
        expected = {'tests.test_host_record_recovery_followup.HostRecordRecoveryFollowupTests.test_' + name
                    for name in original}
        expected.update({
            'tests.test_offline_artifact_validation.DirectoryInventoryTests.test_F6_D1_reused_descriptor_refreshes_names_and_enforces_entry_bound',
            'tests.test_host_records.HostRecordTests.test_check_descriptor_io_refuses_symlinks_hardlinks_and_private_mode_changes',
            'tests.test_host_records.HostRecordTests.test_check_descriptor_change_during_read_and_zero_progress_during_write',
            'tests.test_host_records.HostRecordTests.test_check_database_init_rejects_noncanonical_private_and_changing_objects',
            'tests.test_host_record_quarantine.HostRecordQuarantineTests.test_destination_collision_and_source_replacement_preserve_foreign_bytes',
            'tests.test_host_record_quarantine.HostRecordQuarantineTests.test_actual_fsync_failures_restore_noncommit_and_retain_committed_head',
            'tests.test_host_record_quarantine.HostRecordQuarantineTests.test_database_initialization_pending_zero_write_and_same_lock_through_commit',
            'tests.test_workspace_inert_inspection.MetadataScopeTests.test_within_capture_indirection_retarget_is_incomplete',
            'tests.test_release_effect_routes.ReleaseEffectRoutesTests.test_generated_data_stays_external_and_unsafe_reads_refuse',
        })
        self.assertEqual(set(gate.REQUIRED_TESTS), expected)
        self.assertEqual(len(gate.REQUIRED_TESTS), len(expected), 'duplicate methods cannot pad execution')

    def test_wrong_distribution_version_or_kernel_refuses(self):
        positive = {'sys_platform': 'linux', 'os_release': {'ID': 'debian', 'VERSION_ID': '13'}}
        gate.require_debian(positive)
        for field, value in [('ID', 'fedora'), ('VERSION_ID', '12'), ('sys_platform', 'darwin')]:
            with self.subTest(field=field):
                row = {'sys_platform': 'linux', 'os_release': dict(positive['os_release'])}
                if field == 'sys_platform':
                    row[field] = value
                else:
                    row['os_release'][field] = value
                with self.assertRaisesRegex(ValueError, 'Debian 13 Linux runtime required'):
                    gate.require_debian(row)

    def test_execution_refuses_failure_skip_expected_failure_omission_and_duplicate(self):
        class Case(unittest.TestCase):
            def runTest(self):
                if outcome == 'failure':
                    self.fail('EXAMPLE actual assertion failure')
                if outcome == 'skip':
                    self.skipTest('EXAMPLE unavailable publication')
                if outcome == 'expected-failure':
                    self.fail('EXAMPLE expected failure still is not coverage')
            def id(self):
                return 'EXAMPLE.required'
        for outcome in ('pass', 'failure', 'skip', 'expected-failure', 'omitted', 'duplicate', 'wrong-method', 'extra-failure', 'extra-skip'):
            with self.subTest(outcome=outcome):
                case = Case()
                if outcome == 'expected-failure':
                    case = unittest.FunctionTestCase(unittest.expectedFailure(lambda: self.fail('EXAMPLE')))
                    case.id = lambda: 'EXAMPLE.required'
                if outcome == 'wrong-method':
                    case.id = lambda: 'EXAMPLE.unrelated'
                suite = unittest.TestSuite([] if outcome == 'omitted' else [case, Case()] if outcome == 'duplicate' else [case])
                if outcome.startswith('extra-'):
                    extra = unittest.FunctionTestCase(lambda: self.fail('EXAMPLE extra failure') if outcome == 'extra-failure' else self.skipTest('EXAMPLE extra skip'))
                    # The declared required method passed; an extra result must
                    # still prevent credit for this exact finite probe.
                    class Passed(unittest.TestCase):
                        def runTest(self):
                            pass
                        def id(self):
                            return 'EXAMPLE.required'
                    suite = unittest.TestSuite([Passed(), extra])
                receipt = {}
                with mock.patch.object(gate, 'REQUIRED_TESTS', ('EXAMPLE.required',)), \
                     mock.patch.object(unittest.defaultTestLoader, 'loadTestsFromNames', return_value=suite), \
                     contextlib.redirect_stderr(io.StringIO()):
                    if outcome == 'pass':
                        try:
                            positive = gate.run_probe(receipt)
                        except ValueError as exc:
                            self.fail('valid successful method identity was lost: ' + str(exc))
                        self.assertEqual(positive['passed'], ['EXAMPLE.required'])
                    else:
                        with self.assertRaisesRegex(ValueError, 'all required filesystem methods must execute and pass'):
                            gate.run_probe(receipt)
                self.assertIn('results', receipt, 'failed execution retains result identity')

    def test_actual_source_snapshot_and_runtime_identities_are_bound(self):
        source = gate.source_identity(ROOT)
        path = 'scripts/check_release_filesystem.py'
        self.assertEqual(source['files'][path]['sha256'], hashlib.sha256((ROOT / path).read_bytes()).hexdigest())
        self.assertEqual(source['files_sha256'], hashlib.sha256(gate.source_io.encoded(source['files'])).hexdigest())
        environment = gate.observe_environment()
        self.assertEqual(environment['probe_sha256'], hashlib.sha256((ROOT / path).read_bytes()).hexdigest())
        self.assertEqual(environment['executable_sha256'], hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest())
        self.assertEqual(environment['unittest_runner_sha256'], hashlib.sha256(Path(unittest.runner.__file__).read_bytes()).hexdigest())
        self.assertTrue(environment['os_release']['ID'])
        self.assertTrue(environment['kernel'][2])
        self.assertTrue(environment['scratch_filesystem'])
        self.assertEqual(environment['mountinfo_sha256'], hashlib.sha256(Path('/proc/self/mountinfo').read_bytes()).hexdigest())

    def test_source_drift_and_wrong_os_refuse_before_credit_with_bound_receipt(self):
        environment = {'sys_platform': 'linux', 'os_release': {'ID': 'debian', 'VERSION_ID': '13'}}
        for fault in ('none', 'source-drift', 'wrong-os'):
            with self.subTest(fault=fault):
                receipt = {}
                current = dict(environment, os_release=dict(environment['os_release']))
                if fault == 'wrong-os':
                    current['os_release']['ID'] = 'fedora'
                with mock.patch.object(gate, 'source_identity', side_effect=[{'bytes': 'before'}, {'bytes': 'after' if fault == 'source-drift' else 'before'}]), \
                     mock.patch.object(gate, 'observe_environment', return_value=current), \
                     mock.patch.object(gate, 'run_probe', return_value={'EXAMPLE': 'passed'}) as run:
                    if fault == 'none':
                        self.assertTrue(gate.check(receipt=receipt)['passed'])
                    else:
                        with self.assertRaisesRegex(ValueError, 'source changed' if fault == 'source-drift' else 'Debian 13 Linux runtime required'):
                            gate.check(receipt=receipt)
                        self.assertFalse(receipt['passed'])
                    self.assertEqual(receipt['source'], {'bytes': 'before'})
                    self.assertEqual(receipt['environment'], current)
                    self.assertEqual(run.call_count, 0 if fault == 'wrong-os' else 1)

    def test_cli_refusal_is_nonzero_and_keeps_observed_identity(self):
        def refused(*, receipt):
            receipt['source'] = {'EXAMPLE': 'observed-before-refusal'}
            raise ValueError('EXAMPLE failed actual probe')
        output = io.StringIO()
        with mock.patch.object(gate, 'check', side_effect=refused), contextlib.redirect_stdout(output):
            self.assertEqual(gate.main(), 1)
        row = json.loads(output.getvalue())
        self.assertFalse(row['passed'])
        self.assertEqual(row['source'], {'EXAMPLE': 'observed-before-refusal'})
        self.assertEqual(row['error'], 'EXAMPLE failed actual probe')

    def _run_noisy_cli(self, outcome):
        # Exercise real loading, unittest execution and child processes, without
        # invoking check()'s OS probe or claiming filesystem qualification.
        fixture = textwrap.dedent('''\
            import os
            import subprocess
            import sys
            import unittest

            def diagnostics(stage):
                print('EXAMPLE ' + stage + ' Python stdout')
                sys.__stdout__.write('EXAMPLE ' + stage + ' cached stdout\\n')
                os.write(1, ('EXAMPLE ' + stage + ' descriptor stdout\\n').encode())
                subprocess.run([sys.executable, '-B', '-c',
                    "print('EXAMPLE " + stage + " inherited child stdout')"],
                    check=True, timeout=10)
                print('EXAMPLE ' + stage + ' stderr', file=sys.stderr)

            diagnostics('import')
            if sys.argv[2] == 'import-error':
                raise ImportError('EXAMPLE synthetic import failure')

            class NoisyProbe(unittest.TestCase):
                def test_diagnostics(self):
                    diagnostics('test')
                    if sys.argv[2] == 'assertion-failure':
                        self.fail('EXAMPLE synthetic assertion failure')
            ''')
        driver = textwrap.dedent('''\
            import os
            import sys
            sys.path.insert(0, sys.argv[3])
            sys.path.insert(0, sys.argv[1])
            import check_release_filesystem as gate

            def bounded_check(*, receipt):
                receipt['source'] = {'EXAMPLE': 'bounded I/O fixture; no OS qualification'}
                print('EXAMPLE check Python stdout')
                results = gate.run_probe(receipt)
                if sys.argv[2] == 'check-error':
                    raise OSError('EXAMPLE synthetic check refusal')
                receipt.update(passed=True, results=results)

            def descriptor_identity(fd):
                info = os.fstat(fd)
                return info.st_dev, info.st_ino, info.st_mode, os.get_inheritable(fd)

            gate.check = bounded_check
            gate.REQUIRED_TESTS = ('noisy_probe.NoisyProbe.test_diagnostics',)
            stdout, stderr = sys.stdout, sys.stderr
            descriptors = [descriptor_identity(fd) for fd in (1, 2)]
            status = gate.main()
            assert sys.stdout is stdout and sys.stderr is stderr, 'streams not restored'
            assert descriptors == [descriptor_identity(fd) for fd in (1, 2)], 'descriptors not restored'
            print('EXAMPLE streams and descriptors restored', file=sys.stderr)
            raise SystemExit(status)
            ''')
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / 'noisy_probe.py').write_text(fixture)
            return subprocess.run(
                [sys.executable, '-B', '-c', driver, directory, outcome, str(ROOT / 'scripts')],
                cwd=ROOT, capture_output=True, text=True, timeout=30)

    def _assert_noisy_cli_receipt(self, process, outcome):
        self.assertEqual(process.returncode, 0 if outcome == 'pass' else 1, process.stderr)
        row = json.loads(process.stdout)  # Parse the entire raw producer stream.
        self.assertEqual(process.stdout, json.dumps(row, sort_keys=True) + '\n')
        self.assertEqual(row['passed'], outcome == 'pass')
        self.assertEqual(row['source'], {'EXAMPLE': 'bounded I/O fixture; no OS qualification'})
        self.assertEqual(row['results']['tests_run'], 1)
        self.assertEqual(row['results']['skips'], 0)
        self.assertEqual(row['results']['passed'], [] if outcome in ('assertion-failure', 'import-error')
                         else ['noisy_probe.NoisyProbe.test_diagnostics'])
        self.assertEqual(process.stderr.count('EXAMPLE check Python stdout'), 1)
        for stage in ('import',) if outcome == 'import-error' else ('import', 'test'):
            # A failed import can be retried while unittest resolves the dotted
            # selector. Each attempt emits once to every diagnostic stream.
            expected = process.stderr.count('EXAMPLE import stderr') if outcome == 'import-error' else 1
            self.assertGreater(expected, 0)
            for stream in ('Python stdout', 'cached stdout', 'descriptor stdout', 'inherited child stdout', 'stderr'):
                self.assertEqual(process.stderr.count('EXAMPLE ' + stage + ' ' + stream), expected, process.stderr)
        self.assertIn('Ran 1 test', process.stderr)
        self.assertIn('EXAMPLE streams and descriptors restored', process.stderr)
        return row

    def test_cli_success_retains_import_test_descriptor_and_child_diagnostics_on_stderr(self):
        process = self._run_noisy_cli('pass')
        row = self._assert_noisy_cli_receipt(process, 'pass')
        self.assertNotIn('error', row)
        self.assertIn('\nOK\n', process.stderr)

    def test_cli_failures_retain_diagnostics_and_restore_stdout_before_json(self):
        for outcome, diagnostic in (
                ('assertion-failure', 'EXAMPLE synthetic assertion failure'),
                ('import-error', 'EXAMPLE synthetic import failure'),
                ('check-error', 'EXAMPLE synthetic check refusal')):
            with self.subTest(outcome=outcome):
                process = self._run_noisy_cli(outcome)
                row = self._assert_noisy_cli_receipt(process, outcome)
                if outcome == 'check-error':
                    self.assertEqual(row['error'], diagnostic)
                    self.assertIn('\nOK\n', process.stderr)
                else:
                    self.assertIn(diagnostic, process.stderr)
                    self.assertIn('FAILED (', process.stderr)
                    self.assertIn('all required filesystem methods must execute and pass', row['error'])

    def test_repository_validator_requires_recurring_probe_command(self):
        command = 'timeout --kill-after=10 300 python -B scripts/check_release_filesystem.py'
        self.assertIn(command, validator.CI_REQUIRED_COMMANDS)
        ci = (ROOT / '.github/workflows/ci.yml').read_text()
        self.assertIn(command, ci)
        self.assertIn('  debian-filesystem:\n', ci)
        self.assertIn('python:3.11@sha256:4c366015f27c672f4e07184054953aad7f4b0cd7a2d05da3375f3a0e04be9342', ci)
        self.assertNotIn('continue-on-error:', ci)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'ci.yml'
            path.write_text(ci.replace(command, 'echo EXAMPLE omitted required probe'))
            errors = []
            validator.validate_ci_workflow(errors, path)
            self.assertIn('CI workflow is missing required command: ' + command, errors)
