"""Real private-file fixtures with narrow, deterministic boundary faults."""

from contextlib import contextmanager
import errno
import hashlib
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
from typing import NamedTuple
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import host_spool_snapshot as spool


_OPEN, _READ, _FSTAT, _CLOSE = os.open, os.read, os.fstat, os.close
_NAME = "private-spool-name"
_DATA = b"\x00\xffprivate-payload\n"
_DIGEST = hashlib.sha256(_DATA).hexdigest()
_FIELDS = (
    "st_dev", "st_ino", "st_uid", "st_mode",
    "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns",
)
_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
_COMPLETE = (
    "root-fstat", "open", "file-fstat-1", "read", "read",
    "file-fstat-2", "close",
)
_BEFORE_READ = ("root-fstat", "open", "file-fstat-1", "close")


class CaptureProbe:
    """Observe real operations and inject only the selected boundary fault."""

    def __init__(self, root_fd, fault):
        self.root_fd = root_fd
        self.fault = fault
        self.events = []
        self.opens = []
        self.reads = []
        self.fstats = []
        self.closes = []
        self.returned = []
        self.file_stats = 0

    def opening(self, name, flags, *, dir_fd):
        self.events.append("open")
        fd = _OPEN(name, flags, dir_fd=dir_fd)
        self.opens.append((fd, name, flags, dir_fd))
        return fd

    def reading(self, fd, count):
        self.events.append("read")
        part = _READ(fd, count)
        self.reads.append((fd, count, part))
        return part

    def stating(self, fd):
        if fd == self.root_fd:
            phase = "root-fstat"
        else:
            self.file_stats += 1
            phase = f"file-fstat-{self.file_stats}"
        self.events.append(phase)
        self.fstats.append((fd, phase))
        info = _FSTAT(fd)
        if self.fault == phase:
            raise OSError(errno.EIO, f"{_NAME} {_DATA!r}")
        owner_phase = {
            "root-owner": "root-fstat",
            "file-owner": "file-fstat-1",
        }.get(self.fault)
        if phase == owner_phase:
            fields = {field: getattr(info, field) for field in _FIELDS}
            fields["st_uid"] += 1
            return SimpleNamespace(**fields)
        return info

    def closing(self, fd):
        self.events.append("close")
        self.closes.append(fd)
        if self.fault == "close-before":
            raise OSError(errno.EIO, f"{_NAME} {_DATA!r}")
        _CLOSE(fd)
        if self.fault == "close-after":
            raise OSError(errno.EIO, f"{_NAME} {_DATA!r}")

    def capture(self):
        self.events.append("call")
        try:
            value = spool.capture_spool_snapshot(
                self.root_fd, _NAME, _DIGEST, maximum_bytes=len(_DATA)
            )
        except spool.SpoolSnapshotError:
            self.events.append("refused")
            raise
        self.returned.append(value)
        self.events.append("returned")
        return value

    def cleanup(self):
        """Saved OS calls run only after patch restoration and observations."""
        for fd, _, _, _ in self.opens:
            try:
                _FSTAT(fd)
            except OSError as error:
                if error.errno != errno.EBADF:
                    raise
            else:
                _CLOSE(fd)


class CaptureFaultCase(NamedTuple):
    original: str
    fault: str
    phases: tuple[str, ...]
    diagnostic: str
    left_open: bool = False


class HostSpoolSnapshotFailureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="w15-spool-failures-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.root.chmod(0o700)
        path = self.root / _NAME
        path.write_bytes(_DATA)
        path.chmod(0o600)
        self.root_fd = _OPEN(
            self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
        )
        self.addCleanup(_CLOSE, self.root_fd)
        info = path.stat()
        self.identity = tuple(getattr(info, field) for field in _FIELDS)

    @contextmanager
    def observe(self, fault=None):
        probe = CaptureProbe(self.root_fd, fault)
        try:
            with (
                mock.patch.object(spool.os, "open", side_effect=probe.opening),
                mock.patch.object(spool.os, "read", side_effect=probe.reading),
                mock.patch.object(spool.os, "fstat", side_effect=probe.stating),
                mock.patch.object(spool.os, "close", side_effect=probe.closing),
            ):
                yield probe
        finally:
            probe.cleanup()

    def assert_observed(self, probe, phases, *, returned=False, left_open=False):
        terminal = "returned" if returned else "refused"
        self.assertEqual(probe.events, ["call", *phases, terminal])
        self.assertEqual(len(probe.returned), int(returned))
        self.assertEqual(len(probe.opens), int("open" in phases))
        fd = probe.opens[0][0] if probe.opens else None
        expected_stats = [
            (self.root_fd if phase == "root-fstat" else fd, phase)
            for phase in phases if phase.startswith(("root-fstat", "file-fstat-"))
        ]
        self.assertEqual(probe.fstats, expected_stats)
        expected_reads = []
        if "read" in phases:
            expected_reads = [(fd, len(_DATA) + 1, _DATA), (fd, 1, b"")]
        self.assertEqual(probe.reads, expected_reads)
        if probe.opens:
            self.assertEqual(probe.opens, [(fd, _NAME, _FLAGS, self.root_fd)])
            self.assertEqual(probe.closes, [fd])
            if left_open:
                info = _FSTAT(fd)
                self.assertEqual(
                    tuple(getattr(info, field) for field in _FIELDS), self.identity
                )
            else:
                with self.assertRaises(OSError) as caught:
                    _FSTAT(fd)
                self.assertEqual(caught.exception.errno, errno.EBADF)
        else:
            self.assertEqual(probe.closes, [])
        root_info = _FSTAT(self.root_fd)
        self.assertTrue(stat.S_ISDIR(root_info.st_mode))
        self.assertEqual(stat.S_IMODE(root_info.st_mode), 0o700)
        self.assertEqual(root_info.st_uid, os.geteuid())

    def assert_useful_capture(self):
        with self.observe() as probe:
            value = probe.capture()
            self.assertIsInstance(value, spool.SpoolSnapshot)
            self.assertIs(type(value.data), bytes)
            self.assertEqual(value.data, _DATA)
            self.assertEqual(value.sha256, _DIGEST)
            self.assertEqual(value.identity, self.identity)
            self.assertEqual(value.identity[2], os.geteuid())
            self.assertEqual(stat.S_IMODE(value.identity[3]), 0o600)
            self.assertTrue(stat.S_ISREG(value.identity[3]))
            self.assertEqual(value.identity[4], 1)
            self.assert_observed(probe, _COMPLETE, returned=True)

    def assert_refusal(self, fault, phases, message, *, left_open=False):
        with self.observe(fault) as probe:
            with self.assertRaises(spool.SpoolSnapshotError) as caught:
                probe.capture()
            self.assertEqual(str(caught.exception), message)
            self.assertNotIn(_NAME, str(caught.exception))
            self.assertNotIn("private-payload", str(caught.exception))
            self.assertNotIn(repr(_DATA), str(caught.exception))
            if not fault.endswith("owner"):
                self.assertTrue(caught.exception.__suppress_context__)
            self.assert_observed(probe, phases, left_open=left_open)

    def test_private_spool_capture_fault_rows(self):
        rows = (
            CaptureFaultCase('test_root_fstat_error_before_open', "root-fstat", ("root-fstat",), "spool capture unavailable or refused"),
            CaptureFaultCase('test_first_file_fstat_error_before_read', "file-fstat-1", _BEFORE_READ, "spool capture unavailable or refused"),
            CaptureFaultCase('test_final_file_fstat_error_after_real_reads', "file-fstat-2", _COMPLETE, "spool capture unavailable or refused"),
            CaptureFaultCase('test_injected_wrong_root_owner_before_open', "root-owner", ("root-fstat",), "spool root must be owned and private"),
            CaptureFaultCase('test_injected_wrong_file_owner_keeps_root_valid', "file-owner", _BEFORE_READ, "spool input must be owned and private"),
            CaptureFaultCase('test_close_error_after_real_close_overrides_return', "close-after", _COMPLETE, "spool descriptor close failed"),
            CaptureFaultCase('test_close_error_before_real_close_leaves_fd_for_cleanup', "close-before", _COMPLETE, "spool descriptor close failed", left_open=True),
        )
        for row in rows:
            with self.subTest(original=row.original):
                self.assert_useful_capture()
                self.assert_refusal(row.fault, row.phases, row.diagnostic, left_open=row.left_open)


if __name__ == "__main__":
    unittest.main()
