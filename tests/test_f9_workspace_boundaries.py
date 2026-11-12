"""Workspace hold, lease ownership, private-state and deadline boundaries."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from cwo_core import workspace, workspace_capture as capture


class F9WorkspaceBoundaries(unittest.TestCase):
    @staticmethod
    def budget(deadline=10):
        return capture.Budget(max_files=10, max_bytes=4096, max_entries=4096, deadline=deadline)

    def test_F9_b1374079b36aa0ef_release_requires_pid_and_owner(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            registry, lock = root / 'leases.json', root / 'leases.lock'
            rows = [{'owner': owner, 'pid': pid, 'paths': ['src']} for owner, pid in
                (('EXAMPLE-owner', os.getpid()), ('EXAMPLE-owner', os.getpid() + 1), ('EXAMPLE-other', os.getpid()))]
            registry.write_text(json.dumps(rows))
            with patch.object(workspace, '_lease_registry_paths', return_value=(registry, lock)), \
                    patch.object(workspace, '_process_alive', return_value=True):
                lease = workspace.WriteScopeLease(root, ['src'], owner='EXAMPLE-owner')
                lease._acquired = True
                lease.release()
                self.assertEqual(json.loads(registry.read_text()), rows[1:])
                before = registry.read_bytes()
                lease.release()
                self.assertEqual(registry.read_bytes(), before)

    def test_F9_d34aaa7238c94055_capture_error_never_clean(self):
        state = dict(incomplete=False, tracked_status=[], git_cleanliness='raw-equals-git')
        for error, clean in ((None, True), ('EXAMPLE capture error', False)):
            with self.subTest(error=error), patch.object(workspace, 'capture_tracked_workspace_state',
                    return_value={**state, 'error': error}):
                self.assertIs(workspace.workspace_is_clean('/EXAMPLE', include_untracked=True), clean)

    def test_F9_22243f9d8dbf1537_e328b7c678a670d4_optional_cleanliness(self):
        for content in (False, True):
            state = dict(evidence_version=workspace.EVIDENCE_VERSION, tracked_status=[], incomplete=False, git_cleanliness='unknown')
            if content:
                state.update(content_fingerprints={'src/file': 'same'}, tracked_paths=['src/file'], tracked_paths_complete=True)
            for required in (False, True):
                with self.subTest(content=content, required=required):
                    report = workspace.diff_workspace_state(state, copy.deepcopy(state), allowed_paths=['src'], require_clean=required)
                    self.assertIs(report['unexpected_mutation_detected'], required)

    def test_F9_63ca49aaf9f0db74_status_only_attribution(self):
        before = dict(version=1, cwd='/EXAMPLE', tracked_status=[], content_fingerprints={},
            tracked_paths=[], tracked_paths_complete=True, incomplete=False)
        after = {**before, 'tracked_status': [' M src/file'], 'incomplete': True}
        report = workspace.compare_workspace_baseline(before, after, allowed_paths=['src'])
        self.assertEqual(report['mutations'][0]['category'], 'attribution-ambiguous')
        created = {**after, 'content_fingerprints': {'src/file': 'new'}}
        self.assertEqual(workspace.compare_workspace_baseline(before, created, allowed_paths=['src'])['mutations'][0]['category'], 'scoped')

    def test_F9_0b515954506e78a6_created_directory_must_be_private(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY)
            self.addCleanup(os.close, parent)
            expected = [(info.st_dev, info.st_ino) for info in capture._ancestry(parent)]
            fd, name, _identity = capture._create_private_directory(parent, temporary, expected, set())
            os.close(fd)
            os.rmdir(name, dir_fd=parent)
            real_mkdir = os.mkdir
            def exposed(name, mode, *, dir_fd):
                real_mkdir(name, mode, dir_fd=dir_fd)
                os.chmod(name, 0o750, dir_fd=dir_fd)
            with patch.object(capture.os, 'mkdir', side_effect=exposed), \
                    self.assertRaisesRegex(capture._CaptureFailure, 'not private'):
                capture._create_private_directory(parent, temporary, expected, set())
            self.assertEqual(list(Path(temporary).iterdir()), [])

    def test_F9_b3582e864710e021_cleanup_none_and_expired_deadlines(self):
        for expired in (False, True):
            snapshot = capture._Snapshot(())
            self.addCleanup(shutil.rmtree, snapshot.root, True)
            Path(snapshot.root, 'EXAMPLE-file').write_bytes(b'owned')
            snapshot.close(0 if expired else None)
            with self.subTest(expired=expired):
                self.assertIs(Path(snapshot.root).exists(), expired)
                if expired:
                    self.assertIn('deadline', snapshot.abandon_reason)
                else:
                    self.assertEqual(snapshot.problems, [])

    def test_F9_a410e2d093e77d68_special_metadata_entry_refuses(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            capture_object = capture.WorktreeCapture(root, budget=self.budget(), scope=capture.CaptureScope())
            with patch.object(capture.time, 'monotonic', return_value=0):
                (root / 'regular').write_bytes(b'EXAMPLE metadata')
                capture_object._check_tree(str(root))
                os.mkfifo(root / 'special', 0o600)
                with self.assertRaisesRegex(capture._CaptureFailure, 'not a regular file'):
                    capture_object._check_tree(str(root))

    def test_F9_e1f70e452437cda8_declared_path_deadline_precedes_path_work(self):
        capture_object = capture.WorktreeCapture('/EXAMPLE', budget=self.budget(),
            scope=capture.CaptureScope(allowed_paths=('src/file',)))
        capture_object.gitlinks = set()
        with patch.object(capture.time, 'monotonic', return_value=0):
            capture_object._check_declared_paths()
        with patch.object(capture.time, 'monotonic', return_value=11), \
                patch.object(capture, 'path_components', wraps=capture.path_components) as paths:
            with self.assertRaises(capture.BudgetExhausted):
                capture_object._check_declared_paths()
            paths.assert_not_called()

    def test_F9_8d2017f882867fe4_skipped_index_paths_still_check_deadline(self):
        count = capture.git_store.TIME_CHECK_INTERVAL + 1
        capture_object = capture.WorktreeCapture('/EXAMPLE', budget=self.budget(), scope=capture.CaptureScope())
        capture_object.index_paths = {f'file-{index:06}' for index in range(count)}
        capture_object.inventory = {}
        with patch.object(capture.time, 'monotonic', return_value=0), patch.object(capture, 'read_beneath') as read:
            capture_object._read_excluded_tracked()
            read.assert_not_called()
        for clock in ((11,), (0, 11)):
            with self.subTest(clock=clock), patch.object(capture.time, 'monotonic', side_effect=clock), \
                    patch.object(capture, 'read_beneath') as read:
                with self.assertRaises(capture.BudgetExhausted):
                    capture_object._read_excluded_tracked()
                read.assert_not_called()
