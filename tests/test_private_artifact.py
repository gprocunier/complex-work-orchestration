from __future__ import annotations

import os
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.private_artifact import (  # noqa: E402
    PrivateArtifactError,
    PrivateDirectory,
    ensure_private_directory,
    read_private_artifact,
    sha256_bytes,
    write_private_artifact,
)


class PrivateArtifactTests(unittest.TestCase):
    def test_round_trip_uses_owner_only_modes(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            directory = Path(tmpdir) / "returns"
            path = write_private_artifact(directory, "run.response.txt", b"complete response")
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(read_private_artifact(path), b"complete response")
            self.assertEqual(sha256_bytes(b"complete response"), sha256_bytes(read_private_artifact(path)))
            self.assertEqual(sorted(p.name for p in directory.iterdir()), ["run.response.txt"], "no temporary file remains")

    def test_existing_artifact_is_never_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            directory = Path(tmpdir)
            path = write_private_artifact(directory, "run.response.txt", b"first")
            with self.assertRaises(PrivateArtifactError):
                write_private_artifact(directory, "run.response.txt", b"second")
            self.assertEqual(read_private_artifact(path), b"first")

    def test_unsafe_names_are_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            for name in ("", ".", "..", "../escape", "sub/file", ".hidden", "nul\x00byte"):
                with self.subTest(name=name), self.assertRaises(PrivateArtifactError):
                    write_private_artifact(Path(tmpdir), name, b"x")

    def test_symlinked_directory_component_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            real = Path(tmpdir) / "real"
            real.mkdir()
            link = Path(tmpdir) / "link"
            link.symlink_to(real)
            with self.assertRaises(PrivateArtifactError):
                ensure_private_directory(link / "returns")

    def test_reads_refuse_substitutions(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            directory = Path(tmpdir)
            path = write_private_artifact(directory, "run.response.txt", b"genuine")
            symlink = directory / "link.txt"
            symlink.symlink_to(path)
            hardlink = directory / "hard.txt"
            os.link(path, hardlink)
            readable = directory / "readable.txt"
            readable.write_bytes(b"group readable")
            os.chmod(readable, 0o640)
            cases = {"symlink": symlink, "hard link": path, "group readable": readable, "directory": directory}
            for label, candidate in cases.items():
                with self.subTest(case=label), self.assertRaises(PrivateArtifactError):
                    read_private_artifact(candidate)

    def test_symlinked_parent_is_refused_for_reads(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            real = Path(tmpdir) / "real"
            write_private_artifact(real, "run.txt", b"genuine")
            alias = Path(tmpdir) / "alias"
            alias.symlink_to(real)
            with self.assertRaises(PrivateArtifactError):
                read_private_artifact(alias / "run.txt")

    def test_directory_swapped_after_opening_cannot_redirect_writes_or_reads(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            original = base / "returns"
            decoy = base / "decoy"
            decoy.mkdir(mode=0o700)
            with PrivateDirectory.open(original, create=True) as handle:
                # Swap the directory for a symlink to somewhere else after it was pinned.
                original.rename(base / "moved")
                original.symlink_to(decoy)
                handle.write("run.txt", b"pinned bytes")
                self.assertEqual(handle.read("run.txt"), b"pinned bytes")
            self.assertEqual((base / "moved" / "run.txt").read_bytes(), b"pinned bytes")
            self.assertEqual(list(decoy.iterdir()), [], "the decoy received nothing")

    def test_fifo_is_refused_without_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            directory = ensure_private_directory(Path(tmpdir) / "returns")
            os.mkfifo(directory / "pipe.txt", 0o600)
            started = time.monotonic()
            with self.assertRaises(PrivateArtifactError):
                read_private_artifact(directory / "pipe.txt")
            self.assertLess(time.monotonic() - started, 5)

    def test_operating_system_failures_become_artifact_errors(self) -> None:
        import errno
        from unittest import mock

        import cwo_core.private_artifact as module

        with tempfile.TemporaryDirectory() as tmpdir:
            directory = ensure_private_directory(Path(tmpdir) / "returns")
            for call in ("fsync", "link"):
                with self.subTest(failing=call):
                    with mock.patch.object(module.os, call, side_effect=OSError(errno.ENOSPC, "No space left on device")):
                        with self.assertRaises(PrivateArtifactError):
                            write_private_artifact(directory, f"{call}.txt", b"x")
                    self.assertEqual([p.name for p in directory.iterdir()], [], "no temporary file is left behind")
            with self.assertRaises(PrivateArtifactError):
                read_private_artifact(directory / "missing.txt")

    def _failing_directory_sync(self, handle: PrivateDirectory, before_failing: object, error: BaseException) -> object:
        real_fsync = os.fsync

        def sync(fd: int) -> None:
            if fd == handle.descriptor:
                before_failing()
                raise error
            real_fsync(fd)

        return sync

    def test_rollback_leaves_a_replaced_published_name_alone(self) -> None:
        import errno
        from unittest import mock

        import cwo_core.private_artifact as module

        with tempfile.TemporaryDirectory() as tmpdir:
            with PrivateDirectory.open(Path(tmpdir) / "returns", create=True) as handle:
                final = handle.path / "run.txt"

                def replace() -> None:
                    final.unlink()
                    final.write_bytes(b"another writer")

                sync = self._failing_directory_sync(handle, replace, OSError(errno.EIO, "Input/output error"))
                with mock.patch.object(module.os, "fsync", side_effect=sync):
                    with self.assertRaises(PrivateArtifactError):
                        handle.write("run.txt", b"ours")
                self.assertEqual(final.read_bytes(), b"another writer")

    def test_interrupted_rollback_reports_the_retained_path(self) -> None:
        import errno
        from unittest import mock

        import cwo_core.private_artifact as module

        real_unlink = os.unlink
        with tempfile.TemporaryDirectory() as tmpdir:
            with PrivateDirectory.open(Path(tmpdir) / "returns", create=True) as handle:
                def fail_final_unlink(path: str, *, dir_fd: int | None = None) -> None:
                    if path == "run.txt":
                        raise OSError(errno.EIO, "Input/output error")
                    real_unlink(path, dir_fd=dir_fd)

                sync = self._failing_directory_sync(handle, lambda: None, KeyboardInterrupt())
                with mock.patch.object(module.os, "fsync", side_effect=sync), \
                        mock.patch.object(module.os, "unlink", side_effect=fail_final_unlink):
                    with self.assertRaises(KeyboardInterrupt) as raised:
                        handle.write("run.txt", b"data")
                notes = getattr(raised.exception, "__notes__", [])
                self.assertTrue(any(str(handle.path / "run.txt") in note for note in notes), notes)

    def test_parent_directory_components_are_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            (base / "outside" / "nested").mkdir(parents=True)
            (base / "repo").mkdir()
            (base / "repo" / "alias").symlink_to(base / "outside" / "nested")
            # Collapsing ".." here would drop the symlinked component the walk must refuse.
            target = base / "repo" / "alias" / ".." / "returns"
            with self.assertRaises(PrivateArtifactError):
                PrivateDirectory.open(target, create=True)
            with self.assertRaises(PrivateArtifactError):
                write_private_artifact(target, "run.txt", b"x")
            with self.assertRaises(PrivateArtifactError):
                read_private_artifact(target / "run.txt")
            with self.assertRaises(PrivateArtifactError):
                ensure_private_directory(base / "repo" / ".." / "repo" / "returns")
            self.assertFalse((base / "repo" / "returns").exists())
            self.assertFalse((base / "outside" / "returns").exists())

    def test_failure_after_publication_retains_and_reports_the_file(self) -> None:
        import errno
        from unittest import mock

        import cwo_core.private_artifact as module

        with tempfile.TemporaryDirectory() as tmpdir:
            with PrivateDirectory.open(Path(tmpdir) / "returns", create=True) as handle:
                sync = self._failing_directory_sync(handle, lambda: None, OSError(errno.EIO, "Input/output error"))
                with mock.patch.object(module.os, "fsync", side_effect=sync):
                    with self.assertRaises(PrivateArtifactError) as raised:
                        handle.write("run.txt", b"published, not durable")
                self.assertIn(f"{handle.path / 'run.txt'} was published and is retained", str(raised.exception))
                self.assertEqual([p.name for p in handle.path.iterdir()], ["run.txt"], "nothing is deleted by name")

    def test_anonymous_publication_never_exposes_a_temporary_name(self) -> None:
        from unittest import mock

        import cwo_core.private_artifact as module

        real_link = os.link
        listings: list[list[str]] = []
        with tempfile.TemporaryDirectory() as tmpdir:
            with PrivateDirectory.open(Path(tmpdir) / "returns", create=True) as handle:
                def link(*args: object, **kwargs: object) -> None:
                    listings.append(sorted(p.name for p in handle.path.iterdir()))
                    real_link(*args, **kwargs)

                with mock.patch.object(module.os, "link", side_effect=link):
                    handle.write("run.txt", b"complete")
                self.assertEqual(listings, [[]], "the data was complete before any name existed")
                self.assertEqual([p.name for p in handle.path.iterdir()], ["run.txt"])
                self.assertEqual((handle.path / "run.txt").read_bytes(), b"complete")

    def test_publication_is_refused_without_anonymous_files(self) -> None:
        from unittest import mock

        with tempfile.TemporaryDirectory() as tmpdir:
            with PrivateDirectory.open(Path(tmpdir) / "returns", create=True) as handle, \
                    mock.patch.object(PrivateDirectory, "_anonymous_file", return_value=None):
                with self.assertRaisesRegex(PrivateArtifactError, "atomic artifact publication is unavailable"):
                    handle.write("run.txt", b"data")
                self.assertEqual(list(handle.path.iterdir()), [], "no partially written name is exposed")

    def test_interruption_while_closing_the_artifact_reports_publication(self) -> None:
        from unittest import mock

        import cwo_core.private_artifact as module

        real_link, real_close = os.link, os.close
        linked: list[int] = []

        def link(source: str, *args: object, **kwargs: object) -> None:
            real_link(source, *args, **kwargs)
            linked.append(int(str(source).rsplit("/", 1)[-1]))

        def close(fd: int) -> None:
            real_close(fd)
            if linked and fd == linked[0]:
                raise KeyboardInterrupt

        with tempfile.TemporaryDirectory() as tmpdir:
            with PrivateDirectory.open(Path(tmpdir) / "returns", create=True) as handle:
                with mock.patch.object(module.os, "link", side_effect=link), mock.patch.object(module.os, "close", side_effect=close):
                    with self.assertRaises(KeyboardInterrupt) as raised:
                        handle.write("run.txt", b"published before close")
                self.assertEqual((handle.path / "run.txt").read_bytes(), b"published before close")
        notes = getattr(raised.exception, "__notes__", [])
        self.assertTrue(any("run.txt was published and is retained" in note for note in notes), notes)

    def test_directory_sync_failure_retains_and_reports(self) -> None:
        import errno
        from unittest import mock

        import cwo_core.private_artifact as module

        with tempfile.TemporaryDirectory() as tmpdir:
            with PrivateDirectory.open(Path(tmpdir) / "returns", create=True) as handle:
                sync = self._failing_directory_sync(handle, lambda: None, OSError(errno.EIO, "Input/output error"))
                with mock.patch.object(module.os, "fsync", side_effect=sync):
                    with self.assertRaises(PrivateArtifactError) as raised:
                        handle.write("run.txt", b"ours")
                self.assertIn("retained", str(raised.exception))
                self.assertEqual((handle.path / "run.txt").read_bytes(), b"ours")
                self.assertEqual(handle.contains("run.txt"), True)
                self.assertEqual(handle.contains("absent.txt"), False)

    def test_interruption_just_after_the_link_reports_publication(self) -> None:
        from unittest import mock

        import cwo_core.private_artifact as module

        real_link = os.link

        def link_then_interrupt(*args: object, **kwargs: object) -> None:
            real_link(*args, **kwargs)
            raise KeyboardInterrupt

        with tempfile.TemporaryDirectory() as tmpdir:
            with PrivateDirectory.open(Path(tmpdir) / "returns", create=True) as handle:
                with mock.patch.object(module.os, "link", side_effect=link_then_interrupt):
                    with self.assertRaises(KeyboardInterrupt) as raised:
                        handle.write("run.txt", b"linked")
                self.assertTrue((handle.path / "run.txt").exists())
        notes = getattr(raised.exception, "__notes__", [])
        self.assertTrue(any("run.txt was published and is retained" in note for note in notes), notes)

    def test_generic_writer_reports_publication_when_close_is_interrupted(self) -> None:
        from unittest import mock

        with tempfile.TemporaryDirectory() as tmpdir:
            directory = Path(tmpdir) / "returns"
            with mock.patch.object(PrivateDirectory, "close", side_effect=KeyboardInterrupt):
                with self.assertRaises(KeyboardInterrupt) as raised:
                    write_private_artifact(directory, "run.txt", b"data")
            self.assertEqual((directory / "run.txt").read_bytes(), b"data")
        notes = getattr(raised.exception, "__notes__", [])
        self.assertTrue(any("run.txt was published and is retained" in note for note in notes), notes)

    def test_unsettled_link_is_reported_as_possibly_retained(self) -> None:
        import errno
        from unittest import mock

        import cwo_core.private_artifact as module

        real_link, real_stat = os.link, os.stat

        def link_then_interrupt(*args: object, **kwargs: object) -> None:
            real_link(*args, **kwargs)
            raise KeyboardInterrupt

        def failing_stat(path: object, *args: object, **kwargs: object) -> os.stat_result:
            if path == "run.txt":
                raise OSError(errno.EIO, "Input/output error")
            return real_stat(path, *args, **kwargs)

        with tempfile.TemporaryDirectory() as tmpdir:
            with PrivateDirectory.open(Path(tmpdir) / "returns", create=True) as handle:
                with mock.patch.object(module.os, "link", side_effect=link_then_interrupt), \
                        mock.patch.object(module.os, "stat", side_effect=failing_stat):
                    with self.assertRaises(KeyboardInterrupt) as raised:
                        handle.write("run.txt", b"linked")
        notes = getattr(raised.exception, "__notes__", [])
        self.assertTrue(any("run.txt may have been published and retained" in note for note in notes), notes)
        self.assertEqual(raised.exception.retained_artifact.name, "run.txt")

    def test_link_is_settled_before_the_anonymous_file_closes(self) -> None:
        from unittest import mock

        import cwo_core.private_artifact as module

        real_link, real_stat, real_close = os.link, os.stat, os.close
        events: list[str] = []
        anonymous: list[int] = []

        def link_then_interrupt(source: str, *args: object, **kwargs: object) -> None:
            anonymous.append(int(str(source).rsplit("/", 1)[-1]))
            real_link(source, *args, **kwargs)
            raise KeyboardInterrupt

        def stat(path: object, *args: object, **kwargs: object) -> os.stat_result:
            if path == "run.txt":
                events.append("settle")
            return real_stat(path, *args, **kwargs)

        def close(fd: int) -> None:
            if anonymous and fd == anonymous[0]:
                events.append("close")
            real_close(fd)

        with tempfile.TemporaryDirectory() as tmpdir:
            with PrivateDirectory.open(Path(tmpdir) / "returns", create=True) as handle:
                with mock.patch.object(module.os, "link", side_effect=link_then_interrupt), \
                        mock.patch.object(module.os, "stat", side_effect=stat), mock.patch.object(module.os, "close", side_effect=close):
                    with self.assertRaises(KeyboardInterrupt):
                        handle.write("run.txt", b"linked")
        self.assertEqual(events, ["settle", "close"], "the inode is compared while the descriptor still pins it")

    def test_interruption_at_the_writer_return_is_reported_by_the_caller(self) -> None:
        from unittest import mock

        import cwo_core.private_artifact as module

        real_write = PrivateDirectory.write
        for move_file in (False, True):
            with self.subTest(move_file=move_file), tempfile.TemporaryDirectory() as tmpdir:
                directory = Path(tmpdir) / "returns"
                original = directory / "EXAMPLE.txt"
                moved = Path(tmpdir) / "EXAMPLE-moved.txt"
                primary = KeyboardInterrupt("EXAMPLE interruption after successful write")

                def write_then_interrupt(handle: PrivateDirectory, name: str, data: bytes) -> Path:
                    path = real_write(handle, name, data)
                    if move_file:
                        path.rename(moved)
                        self.assertIs(handle.contains(name), False)
                        self.assertFalse(path.exists())
                    raise primary  # after the actual writer returns, before caller bookkeeping

                with mock.patch.object(module.PrivateDirectory, "write", write_then_interrupt):
                    with self.assertRaises(KeyboardInterrupt) as raised:
                        write_private_artifact(directory, original.name, b"EXAMPLE bytes")
                self.assertIs(raised.exception, primary)
                notes = " ".join(getattr(primary, "__notes__", []))
                self.assertIn(str(original), notes)
                if move_file:
                    self.assertIn(f"{original} was published, but is no longer at that path", notes)
                    self.assertNotIn(f"{original} was published and is retained", notes)
                actual = moved if move_file else original
                self.assertEqual(actual.read_bytes(), b"EXAMPLE bytes")
                self.assertEqual(stat.S_IMODE(actual.stat().st_mode), 0o600)

    def test_close_failure_does_not_mask_a_cancellation(self) -> None:
        import errno
        from unittest import mock

        import cwo_core.private_artifact as module

        real_link, real_close = os.link, os.close
        anonymous: list[int] = []

        def link_then_interrupt(source: str, *args: object, **kwargs: object) -> None:
            anonymous.append(int(str(source).rsplit("/", 1)[-1]))
            real_link(source, *args, **kwargs)
            raise KeyboardInterrupt

        def close(fd: int) -> None:
            real_close(fd)
            if anonymous and fd == anonymous[0]:
                raise OSError(errno.EIO, "Input/output error")

        with tempfile.TemporaryDirectory() as tmpdir:
            with PrivateDirectory.open(Path(tmpdir) / "returns", create=True) as handle:
                with mock.patch.object(module.os, "link", side_effect=link_then_interrupt), \
                        mock.patch.object(module.os, "close", side_effect=close):
                    with self.assertRaises(KeyboardInterrupt) as raised:
                        handle.write("run.txt", b"linked")
        notes = " ".join(getattr(raised.exception, "__notes__", []))
        self.assertIn("closing the anonymous artifact file also failed", notes)
        self.assertIn("run.txt was published and is retained", notes)

    def test_oversize_artifact_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = write_private_artifact(Path(tmpdir), "big.txt", b"x" * 64)
            with self.assertRaises(PrivateArtifactError):
                read_private_artifact(path, max_bytes=63)
            self.assertEqual(len(read_private_artifact(path, max_bytes=64)), 64)


if __name__ == "__main__":
    unittest.main()
