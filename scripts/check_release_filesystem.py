#!/usr/bin/env python3
"""Required Debian 13 release probe; runs real disposable filesystem witnesses.

This bounded gate adds no live authority. Its JSON stdout is a receipt of this
execution, never an input that can substitute for running the probe again.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import unittest

from cwo_core import release_effect_routes as source_io

ROOT = Path(__file__).resolve().parents[1]
# Preserve the original D1 + ten recovery methods; enumerate so disappearance,
# replacement by an empty module, skips and expected failures cannot pass.
REQUIRED_TESTS = (
    'tests.test_offline_artifact_validation.DirectoryInventoryTests.test_F6_D1_reused_descriptor_refreshes_names_and_enforces_entry_bound',
    'tests.test_host_record_recovery_followup.HostRecordRecoveryFollowupTests.test_atomic_publication_crash_leaves_one_readable_link_and_complete_bytes',
    'tests.test_host_record_recovery_followup.HostRecordRecoveryFollowupTests.test_atomic_publication_mode_conflict_and_unavailable_primitive_refuse_without_final_entry',
    'tests.test_host_record_recovery_followup.HostRecordRecoveryFollowupTests.test_pending_rotation_and_unreferenced_entry_recover_through_one_locked_maintenance_path',
    'tests.test_host_record_recovery_followup.HostRecordRecoveryFollowupTests.test_maintenance_rotation_recovery_still_refuses_reference_and_scan_bound_failures_before_cleanup',
    'tests.test_host_record_recovery_followup.HostRecordRecoveryFollowupTests.test_unsafe_unreferenced_entry_refusal_names_the_entry_and_manual_remedy_without_changes',
    'tests.test_host_record_recovery_followup.HostRecordRecoveryFollowupTests.test_initial_rotation_journal_never_replaces_an_unrelated_existing_claim',
    'tests.test_host_record_recovery_followup.HostRecordRecoveryFollowupTests.test_unrelated_transaction_of_the_same_quarantine_event_type_cannot_complete_pending_transaction',
    'tests.test_host_record_recovery_followup.HostRecordRecoveryFollowupTests.test_only_unexpected_bytes_exceed_the_original_scan_bound_and_refuse_without_mutation',
    'tests.test_host_record_recovery_followup.HostRecordRecoveryFollowupTests.test_dot_named_unreferenced_entry_is_quarantined_and_audited_with_the_other_entries',
    'tests.test_host_record_recovery_followup.HostRecordRecoveryFollowupTests.test_first_quarantine_and_rotation_journals_publish_atomically_across_a_real_torn_write',
    'tests.test_host_records.HostRecordTests.test_check_descriptor_io_refuses_symlinks_hardlinks_and_private_mode_changes',
    'tests.test_host_records.HostRecordTests.test_check_descriptor_change_during_read_and_zero_progress_during_write',
    'tests.test_host_records.HostRecordTests.test_check_database_init_rejects_noncanonical_private_and_changing_objects',
    'tests.test_host_record_quarantine.HostRecordQuarantineTests.test_destination_collision_and_source_replacement_preserve_foreign_bytes',
    'tests.test_host_record_quarantine.HostRecordQuarantineTests.test_actual_fsync_failures_restore_noncommit_and_retain_committed_head',
    'tests.test_host_record_quarantine.HostRecordQuarantineTests.test_database_initialization_pending_zero_write_and_same_lock_through_commit',
    'tests.test_workspace_inert_inspection.MetadataScopeTests.test_within_capture_indirection_retarget_is_incomplete',
    'tests.test_release_effect_routes.ReleaseEffectRoutesTests.test_generated_data_stays_external_and_unsafe_reads_refuse',
)


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def source_identity(root):
    files, _contents = source_io.source(root)
    git = ['git', '-C', str(root), '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false']
    commits = [subprocess.check_output(git + ['rev-parse', name], text=True).strip()
               for name in ('HEAD', 'HEAD^{tree}')]
    return {'head': commits[0], 'tree': commits[1], 'files': files,
            'files_sha256': hashlib.sha256(source_io.encoded(files)).hexdigest()}


def observe_environment():
    return {'os_release': platform.freedesktop_os_release(), 'kernel': list(platform.uname()),
            'sys_platform': sys.platform, 'libc': list(platform.libc_ver()),
            'python': sys.version, 'executable': sys.executable,
            'executable_sha256': sha256(sys.executable), 'uid': os.getuid(),
            'scratch': tempfile.gettempdir(),
            'scratch_filesystem': subprocess.check_output(
                ['stat', '-f', '-c', '%T', tempfile.gettempdir()], text=True).strip(),
            'mountinfo_sha256': sha256('/proc/self/mountinfo'),
            'probe_sha256': sha256(__file__),
            'unittest_runner_sha256': sha256(unittest.runner.__file__)}


def require_debian(environment):
    release = environment['os_release']
    if (environment['sys_platform'] != 'linux' or release.get('ID') != 'debian'
            or release.get('VERSION_ID') != '13'):
        raise ValueError('Debian 13 Linux runtime required; Fedora/portable Python is not coverage')


class ProbeResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.passed = []

    def addSuccess(self, test):
        super().addSuccess(test)
        self.passed.append(test.id())


def run_probe(receipt):
    sys.path.insert(0, str(ROOT))
    suite = unittest.defaultTestLoader.loadTestsFromNames(REQUIRED_TESTS)
    result = unittest.TextTestRunner(stream=sys.stderr, verbosity=2, resultclass=ProbeResult).run(suite)
    receipt['results'] = {'tests_run': result.testsRun, 'passed': result.passed,
                          'skips': len(result.skipped)}
    if result.testsRun != len(REQUIRED_TESTS) or sorted(result.passed) != sorted(REQUIRED_TESTS):
        raise ValueError('all required filesystem methods must execute and pass; no skips or expected failures')
    return receipt['results']


def check(root=ROOT, receipt=None):
    before = source_identity(root)
    environment = observe_environment()
    if receipt is None:
        receipt = {}
    receipt.update(gate='debian13-release-filesystem-v1', passed=False,
                   source=before, environment=environment)
    require_debian(environment)
    results = run_probe(receipt)
    after = source_identity(root)
    if before != after:
        raise ValueError('source changed during required filesystem probe')
    receipt.update(passed=True, results=results)
    return receipt


@contextlib.contextmanager
def diagnostic_stdout():
    """Keep Python, descriptor and inherited child diagnostics off receipt stdout."""
    stdout = sys.stdout
    stdout.flush()
    sys.stderr.flush()
    inheritable = os.get_inheritable(1)
    saved_stdout = os.dup(1)
    try:
        os.dup2(2, 1)
        with contextlib.redirect_stdout(sys.stderr):
            try:
                yield
            finally:
                # Cached references (including sys.__stdout__) may still buffer
                # writes to fd 1. Drain them before restoring the receipt fd.
                try:
                    stdout.flush()
                finally:
                    sys.stdout.flush()
    finally:
        try:
            os.dup2(saved_stdout, 1, inheritable=inheritable)
        finally:
            os.close(saved_stdout)


def main():
    receipt = {'gate': 'debian13-release-filesystem-v1', 'passed': False}
    try:
        with diagnostic_stdout():
            check(receipt=receipt)
    except (ValueError, OSError, subprocess.SubprocessError, source_io.Refused) as exc:
        receipt.update(passed=False, error=str(exc))
        print(json.dumps(receipt, sort_keys=True))
        return 1
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
