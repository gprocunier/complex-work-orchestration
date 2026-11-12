"""Disposable OS fixtures for the inert, unwired spool byte primitive."""

from contextlib import contextmanager
from dataclasses import FrozenInstanceError
import errno
import hashlib
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import host_spool_snapshot as spool


def digest(data):
    return hashlib.sha256(data).hexdigest()


class HostSpoolSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="w15-spool-")
        self.root = Path(self.tmp.name)
        self.root.chmod(0o700)
        self.path = self.root / "payload"
        self.root_fd = os.open(
            self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
        )

    def tearDown(self):
        try:
            os.close(self.root_fd)
        finally:
            self.tmp.cleanup()

    def write(self, data, name="payload"):
        path = self.root / name
        path.write_bytes(data)
        path.chmod(0o600)
        return digest(data)

    def capture(self, expected, **kwargs):
        return spool.capture_spool_snapshot(
            self.root_fd, "payload", expected, **kwargs
        )

    def assert_root_open(self):
        self.assertTrue(stat.S_ISDIR(os.fstat(self.root_fd).st_mode))

    @contextmanager
    def observed_open(self, after_open=None):
        records = []
        real_open = os.open

        def opening(name, flags, *, dir_fd):
            fd = real_open(name, flags, dir_fd=dir_fd)
            records.append((fd, name, flags, dir_fd))
            if after_open is not None:
                after_open(fd)
            return fd

        with mock.patch.object(spool.os, "open", side_effect=opening):
            try:
                yield records
            finally:
                for fd, _, _, _ in records:
                    try:
                        os.close(fd)
                    except OSError as error:
                        if error.errno != errno.EBADF:
                            raise

    def assert_file_closed(self, records):
        self.assertEqual(len(records), 1)
        with self.assertRaises(OSError) as caught:
            os.fstat(records[0][0])
        self.assertEqual(caught.exception.errno, errno.EBADF)
        self.assert_root_open()

    def refuse_without_open(self, root_fd, name, expected, **kwargs):
        with mock.patch.object(spool.os, "open", wraps=os.open) as opening:
            with self.assertRaises(spool.SpoolSnapshotError) as caught:
                spool.capture_spool_snapshot(root_fd, name, expected, **kwargs)
            opening.assert_not_called()
        self.assert_root_open()
        return caught.exception

    def test_opaque_positive_identity_flags_and_immutability(self):
        data = b"\x00\xff{not JSON}\n"
        expected = self.write(data)
        info = self.path.stat()
        inherited = []
        with self.observed_open(
            lambda fd: inherited.append(os.get_inheritable(fd))
        ) as records:
            value = self.capture(expected)
            self.assert_file_closed(records)
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        self.assertEqual(records[0][1:], ("payload", flags, self.root_fd))
        self.assertEqual(inherited, [False])
        self.assertIsInstance(value, spool.SpoolSnapshot)
        self.assertIs(type(value.data), bytes)
        self.assertEqual(value.data, data)
        self.assertEqual(value.sha256, expected)
        self.assertEqual(value.identity, (
            info.st_dev, info.st_ino, info.st_uid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
        ))
        self.assertTrue(all(type(field) is int for field in value.identity))
        self.assertEqual(value.identity[2], os.geteuid())
        with self.assertRaises(FrozenInstanceError):
            value.data = b"replacement"
        with self.assertRaises(FrozenInstanceError):
            value.sha256 = "0" * 64
        with self.assertRaises(FrozenInstanceError):
            value.identity = ()
        with self.assertRaises(TypeError):
            value.identity[0] = 0
        self.path.write_bytes(b"later replacement")
        self.assertEqual(value.data, data)
        self.assertEqual(value.sha256, expected)

    def test_empty_bytes_and_ordinary_unicode_names(self):
        for name, data in (("empty", b""), ("caf\u00e9..bin", b"\xff"), ("a..b", b"x")):
            with self.subTest(name=name):
                expected = self.write(data, name)
                value = spool.capture_spool_snapshot(self.root_fd, name, expected)
                self.assertEqual(value.data, data)
                self.assertEqual(value.sha256, expected)
                self.assert_root_open()

    def test_bound_edges_preflight_and_default(self):
        for cap in (1, 8, 32_768, 1_048_576):
            with self.subTest(cap=cap):
                data = b"x" * cap
                expected = self.write(data)
                self.assertEqual(self.capture(expected, maximum_bytes=cap).data, data)
                expected = self.write(data + b"x")
                with self.observed_open() as records:
                    with mock.patch.object(spool.os, "read", wraps=os.read) as reading:
                        with self.assertRaisesRegex(spool.SpoolSnapshotError, "byte bound"):
                            self.capture(expected, maximum_bytes=cap)
                        reading.assert_not_called()
                    self.assert_file_closed(records)
        expected = self.write(b"x" * 32_768)
        self.assertEqual(len(self.capture(expected).data), 32_768)
        expected = self.write(b"x" * 32_769)
        with self.assertRaisesRegex(spool.SpoolSnapshotError, "byte bound"):
            self.capture(expected)
        self.assert_root_open()

    def test_actual_reads_use_opened_fd_and_remaining_bound(self):
        expected = self.write(b"12345678")
        real_read = os.read
        reads = []

        def reading(fd, count):
            part = real_read(fd, count)
            reads.append((fd, count, len(part)))
            return part

        with self.observed_open() as records:
            with mock.patch.object(spool.os, "read", side_effect=reading):
                self.assertEqual(self.capture(expected, maximum_bytes=8).data, b"12345678")
            self.assert_file_closed(records)
        self.assertTrue(reads)
        used = 0
        for fd, count, size in reads:
            self.assertEqual(fd, records[0][0])
            self.assertGreater(count, 0)
            self.assertLessEqual(count, 9 - used)
            used += size
        self.assertEqual(used, 8)

    def test_bad_names_are_controlled_before_open(self):
        names = (
            "", ".", "..", "/outside", "a/b", "../payload", "a\\b", "a\0b",
            None, True, 1, 1.5, b"payload", "\ud800",
        )
        for name in names:
            with self.subTest(name=name):
                error = self.refuse_without_open(self.root_fd, name, "a" * 64)
                self.assertEqual(str(error), "spool basename is invalid")

    def test_bad_hashes_are_controlled_before_open(self):
        hashes = (None, True, 1, 1.5, b"a" * 64, "A" * 64, "g" * 64, "a" * 63, "a" * 65)
        for expected in hashes:
            with self.subTest(expected=expected):
                error = self.refuse_without_open(self.root_fd, "payload", expected)
                self.assertEqual(str(error), "spool expected hash is invalid")

    def test_bad_bounds_are_controlled_before_open(self):
        for cap in (None, True, False, 0, -1, 1.5, "8", 1_048_577):
            with self.subTest(cap=cap):
                error = self.refuse_without_open(
                    self.root_fd, "payload", "a" * 64, maximum_bytes=cap
                )
                self.assertEqual(str(error), "spool byte bound is invalid")

    def test_bad_root_types_and_actual_closed_root_are_controlled(self):
        for root_fd in (None, True, False, -1, 1.5, "3", 1 << 100):
            with self.subTest(root_fd=root_fd):
                self.refuse_without_open(root_fd, "payload", "a" * 64)
        closed = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        os.close(closed)
        self.refuse_without_open(closed, "payload", "a" * 64)

    def test_root_must_be_private_directory(self):
        expected = self.write(b"useful")
        self.assertEqual(self.capture(expected).data, b"useful")
        file_fd = os.open(self.path, os.O_RDONLY | os.O_CLOEXEC)
        try:
            error = self.refuse_without_open(file_fd, "payload", expected)
            self.assertEqual(str(error), "spool root must be a directory")
            self.assertTrue(stat.S_ISREG(os.fstat(file_fd).st_mode))
        finally:
            os.close(file_fd)
        try:
            for mode in (0o750, 0o707, 0o777):
                self.root.chmod(mode)
                error = self.refuse_without_open(self.root_fd, "payload", expected)
                self.assertEqual(str(error), "spool root must be owned and private")
        finally:
            self.root.chmod(0o700)

    def test_file_permissions_are_private(self):
        expected = self.write(b"useful")
        self.assertEqual(self.capture(expected).data, b"useful")
        for mode in (0o640, 0o604, 0o666, 0o755):
            with self.subTest(mode=mode):
                self.path.chmod(mode)
                with self.observed_open() as records:
                    with self.assertRaisesRegex(spool.SpoolSnapshotError, "owned and private"):
                        self.capture(expected)
                    self.assert_file_closed(records)
        self.path.chmod(0o600)

    def test_symlink_outside_root_is_not_read(self):
        expected = self.write(b"useful")
        self.assertEqual(self.capture(expected).data, b"useful")
        with tempfile.TemporaryDirectory(prefix="w15-outside-") as outside:
            target = Path(outside) / "outside-payload"
            target.write_bytes(b"outside")
            target.chmod(0o600)
            (self.root / "link").symlink_to(target)
            with self.observed_open() as records:
                with mock.patch.object(spool.os, "read", wraps=os.read) as reading:
                    with self.assertRaises(spool.SpoolSnapshotError):
                        spool.capture_spool_snapshot(self.root_fd, "link", digest(b"outside"))
                    reading.assert_not_called()
                self.assertEqual(records, [])
                self.assert_root_open()
            self.assertEqual(target.read_bytes(), b"outside")

    def test_hardlinks_are_refused(self):
        expected = self.write(b"useful")
        self.assertEqual(self.capture(expected).data, b"useful")
        os.link(self.path, self.root / "alias")
        for name in ("payload", "alias"):
            with self.subTest(name=name), self.observed_open() as records:
                with self.assertRaisesRegex(spool.SpoolSnapshotError, "one link"):
                    spool.capture_spool_snapshot(self.root_fd, name, expected)
                self.assert_file_closed(records)

    def test_directory_and_real_fifo_refuse_without_reading(self):
        expected = self.write(b"useful")
        self.assertEqual(self.capture(expected).data, b"useful")
        self.path.unlink()
        self.path.mkdir(mode=0o700)
        self.assert_nonregular_closed(expected)
        self.path.rmdir()
        os.mkfifo(self.path, 0o600)
        self.assert_nonregular_closed(expected)

    def assert_nonregular_closed(self, expected):
        with self.observed_open() as records:
            with mock.patch.object(spool.os, "read", wraps=os.read) as reading:
                with self.assertRaisesRegex(spool.SpoolSnapshotError, "regular file"):
                    self.capture(expected)
                reading.assert_not_called()
            self.assertNotEqual(records[0][2] & os.O_NONBLOCK, 0)
            self.assert_file_closed(records)

    def test_hash_mismatch_closes_only_file_fd(self):
        expected = self.write(b"useful")
        self.assertEqual(self.capture(expected).data, b"useful")
        with self.observed_open() as records:
            with self.assertRaisesRegex(spool.SpoolSnapshotError, "hash mismatch"):
                self.capture(digest(b"different"))
            self.assert_file_closed(records)

    def test_actual_read_then_oserror_is_controlled_and_closed(self):
        expected = self.write(b"useful")
        self.assertEqual(self.capture(expected).data, b"useful")
        real_read = os.read
        reads = []

        def failing(fd, count):
            reads.append((fd, real_read(fd, count)))
            raise OSError(errno.EIO, "private-name private-payload")

        with self.observed_open() as records:
            with mock.patch.object(spool.os, "read", side_effect=failing):
                with self.assertRaises(spool.SpoolSnapshotError) as caught:
                    self.capture(expected)
            self.assert_file_closed(records)
        self.assertEqual(reads, [(records[0][0], b"useful")])
        self.assertEqual(str(caught.exception), "spool capture unavailable or refused")
        self.assertTrue(caught.exception.__suppress_context__)

    def test_real_open_error_does_not_echo_name(self):
        name = "private-missing-name"
        with self.assertRaises(spool.SpoolSnapshotError) as caught:
            spool.capture_spool_snapshot(self.root_fd, name, digest(b""))
        self.assertEqual(str(caught.exception), "spool capture unavailable or refused")
        self.assertTrue(caught.exception.__suppress_context__)
        self.assert_root_open()

    def test_missing_platform_capabilities_fail_closed(self):
        for attribute in ("O_NOFOLLOW", "O_CLOEXEC", "O_NONBLOCK", "geteuid"):
            with self.subTest(attribute=attribute):
                with mock.patch.object(spool.os, attribute, None):
                    error = self.refuse_without_open(self.root_fd, "payload", "a" * 64)
                self.assertEqual(str(error), "spool capture platform is unsupported")
        with mock.patch.object(spool.os, "supports_dir_fd", set()):
            error = self.refuse_without_open(self.root_fd, "payload", "a" * 64)
        self.assertEqual(str(error), "spool capture platform is unsupported")

    def test_inplace_mutation_truncation_and_growth_after_actual_read(self):
        for replacement, message in (
            (b"changed!", "changed during capture"),
            (b"x", "changed during capture"),
            (b"original+", "exceeds its byte bound"),
        ):
            with self.subTest(replacement=replacement):
                expected = self.write(b"original")
                self.assertEqual(self.capture(expected).data, b"original")
                before = self.path.stat()
                reads = []
                real_read = os.read

                def changing(fd, count):
                    part = real_read(fd, count)
                    reads.append((fd, count, len(part)))
                    if len(reads) == 1:
                        with self.path.open("r+b") as writer:
                            writer.write(replacement)
                            writer.truncate()
                        os.utime(self.path, ns=(
                            before.st_atime_ns, before.st_mtime_ns + 1_000_000,
                        ))
                        self.assertEqual(self.path.stat().st_ino, before.st_ino)
                    return part

                with self.observed_open() as records:
                    with mock.patch.object(spool.os, "read", side_effect=changing):
                        with self.assertRaisesRegex(spool.SpoolSnapshotError, message):
                            self.capture(expected, maximum_bytes=8)
                    self.assert_file_closed(records)
                self.assertTrue(reads)
                self.assertTrue(all(fd == records[0][0] for fd, _, _ in reads))
                self.assertLessEqual(sum(size for _, _, size in reads), 9)

    def test_path_replacement_after_actual_open_cannot_redirect_capture(self):
        original = b"original"
        replacement = b"substituted"
        expected = self.write(original)
        self.assertEqual(self.capture(expected).data, original)
        before = self.path.stat()

        def replacing(fd):
            self.assertEqual(os.fstat(fd).st_ino, before.st_ino)
            self.path.rename(self.root / "retired")
            self.write(replacement)

        with self.observed_open(replacing) as records:
            try:
                value = self.capture(expected)
            except spool.SpoolSnapshotError as error:
                self.assertEqual(str(error), "spool file changed during capture")
            else:
                self.assertEqual(value.data, original)
                self.assertNotEqual(value.data, replacement)
                self.assertEqual(value.sha256, expected)
                self.assertEqual(value.identity[0:2], (before.st_dev, before.st_ino))
            self.assert_file_closed(records)
        self.assertEqual(self.path.read_bytes(), replacement)
        self.assertEqual((self.root / "retired").read_bytes(), original)
