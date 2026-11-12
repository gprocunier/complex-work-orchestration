"""Explicit fixture archive observation preserves other hosts and original errors."""
from __future__ import annotations

from types import SimpleNamespace
import sys
import threading
import unittest

import tests.test_registered_n1_factory as F


class ArchiveScheduleTests(unittest.TestCase):
    def archive(self, host, effect):
        archive_type = sys.modules[F.runtime.RegisteredAdapter.finalize.__module__].StagedThreadArchive
        server = SimpleNamespace(factory=SimpleNamespace(host=host), archive_thread=effect)
        return archive_type(server, 'EXAMPLE-thread')

    def test_other_host_retains_actual_pending_archive(self):
        selected, other = object(), object()
        entered, release = threading.Event(), threading.Event()
        def original_archive(_thread):
            entered.set()
            if not release.wait(5):
                raise AssertionError('EXAMPLE original archive release missing')
            return 0.0
        F.settle_original_archive(self, SimpleNamespace(host=selected))
        archive = self.archive(other, original_archive)
        archive.start()
        self.addCleanup(archive.require_complete, timeout_seconds=8)
        self.addCleanup(release.set)
        self.assertTrue(entered.wait(5))
        self.assertFalse(archive.completion_ready())
        release.set()
        self.assertEqual(archive.require_complete(timeout_seconds=8), 0.0)

    def test_selected_host_rethrows_original_archive_failure(self):
        host, primary = object(), RuntimeError('EXAMPLE actual archive failure')
        def original_archive(_thread):
            raise primary
        F.settle_original_archive(self, SimpleNamespace(host=host))
        archive = self.archive(host, original_archive)
        with self.assertRaises(RuntimeError) as caught:
            archive.start()
        self.assertIs(caught.exception, primary)
        self.assertTrue(archive.completion_ready())
        self.assertIs(archive._error, primary)
