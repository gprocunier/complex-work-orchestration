from __future__ import annotations

import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock
import uuid

from tests.test_run_native_pool_live_canaries import (
    deterministic_calibration_measurement,
    FakeCalibrationServer,
    LIVE,
)


class EmptySessionCalibrationServer(FakeCalibrationServer):
    """Production-shaped Gen11 reproducer: turn exists before JSONL records."""

    def start_turn(self, thread_id: str, _prompt: str) -> tuple[dict, float]:
        if thread_id != self.thread_id:
            raise AssertionError("thread mismatch")
        self.turn_start_count += 1
        self.path.touch(mode=0o600)
        self.path.chmod(0o600)
        return {"id": self.turn_id}, 1.0

    def _materialize(self) -> None:
        if self.path.stat().st_size == 0:
            self._write(
                [
                    {
                        "type": "session_meta",
                        "payload": {"id": self.thread_id},
                    },
                    {
                        "type": "event_msg",
                        "payload": {
                            "type": "task_started",
                            "turn_id": self.turn_id,
                        },
                    },
                    {
                        "type": "response_item",
                        "payload": {"type": "message", "role": "user"},
                    },
                ]
            )
        super()._materialize()


class StartupScaffoldCalibrationServer(EmptySessionCalibrationServer):
    """Observed two-record startup scaffold, including harmless extra metadata."""

    def start_turn(self, thread_id: str, _prompt: str) -> tuple[dict, float]:
        if thread_id != self.thread_id:
            raise AssertionError("thread mismatch")
        if self.started_cwd is None:
            raise AssertionError("thread cwd missing")
        self.turn_start_count += 1
        self._write(
            [
                {
                    "timestamp": "2026-07-18T00:00:00Z",
                    "type": "session_meta",
                    "harmless_top_level_extension": {"format": 1},
                    "payload": {
                        "id": self.thread_id,
                        "session_id": self.thread_id,
                        "cwd": str(self.started_cwd),
                        "history_mode": "legacy",
                        "harmless_payload_extension": "retained",
                    },
                },
                {
                    "timestamp": "2026-07-18T00:00:00Z",
                    "type": "event_msg",
                    "harmless_top_level_extension": True,
                    "payload": {
                        "type": "task_started",
                        "turn_id": self.turn_id,
                        "harmless_payload_extension": 7,
                    },
                },
            ]
        )
        return {"id": self.turn_id}, 1.0


class OperativeActivityAtFaultServer(EmptySessionCalibrationServer):
    def start_turn(self, thread_id: str, _prompt: str) -> tuple[dict, float]:
        if thread_id != self.thread_id:
            raise AssertionError("thread mismatch")
        self.turn_start_count += 1
        self._write(
            [
                {"type": "session_meta", "payload": {"id": self.thread_id}},
                {
                    "type": "response_item",
                    "payload": {
                        "type": "custom_tool_call",
                        "name": "forbidden",
                        "call_id": "call-before-attestation",
                    },
                },
            ]
        )
        self.path.chmod(0o600)
        return {"id": self.turn_id}, 1.0


class MissingSessionCalibrationServer(FakeCalibrationServer):
    def start_turn(self, thread_id: str, _prompt: str) -> tuple[dict, float]:
        if thread_id != self.thread_id:
            raise AssertionError("thread mismatch")
        self.turn_start_count += 1
        return {"id": self.turn_id}, 1.0


class AliasOnInterruptServer(FakeCalibrationServer):
    def interrupt_turn(self, thread_id: str, turn_id: str) -> float:
        os.link(self.path, self.path.with_suffix(".post-observation-alias"))
        return super().interrupt_turn(thread_id, turn_id)


class SubstituteOnArchiveServer(FakeCalibrationServer):
    def archive_thread(self, thread_id: str) -> float:
        if thread_id != self.thread_id:
            raise AssertionError("thread mismatch")
        target = self.archive / self.path.name
        target.write_bytes(self.path.read_bytes())
        target.chmod(0o600)
        self.path.unlink()
        self.path = target
        return 1.0


class Generation12EmptySessionBoundaryTests(unittest.TestCase):
    @staticmethod
    def baseline() -> dict:
        return {
            "record_count": 0,
            "byte_offset": 0,
            "boundary_sha256": LIVE.sha256_bytes(b""),
            "token_snapshot": None,
        }

    @staticmethod
    def session_layout(root: Path) -> tuple[Path, str, Path]:
        codex_home = root / "codex-home"
        active = codex_home / "sessions" / "2026" / "07"
        active.mkdir(parents=True)
        (codex_home / "archived_sessions").mkdir(parents=True)
        session_id = str(uuid.uuid4())
        path = active / f"rollout-{session_id}.jsonl"
        return codex_home, session_id, path

    def test_missing_private_empty_and_materialized_boundaries_share_one_pin(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            codex_home, session_id, path = self.session_layout(Path(temporary))
            tracker = LIVE.PreAttestationSessionBoundaryTracker(
                codex_home, session_id
            )
            located, boundary, records, materialized = tracker.capture(
                baseline=self.baseline()
            )
            self.assertIsNone(located)
            self.assertFalse(materialized)
            self.assertEqual(records, [])
            self.assertEqual(boundary, self.baseline())

            path.touch(mode=0o600)
            path.chmod(0o600)
            located, boundary, records, materialized = tracker.capture(
                baseline=boundary
            )
            self.assertIsNotNone(located)
            self.assertFalse(materialized)
            self.assertEqual(records, [])
            self.assertEqual(boundary, self.baseline())
            source_identity = located.source_identity_sha256

            path.write_text(
                json.dumps(
                    {"type": "session_meta", "payload": {"id": session_id}}
                )
                + "\n",
                encoding="utf-8",
            )
            located, boundary, records, materialized = tracker.capture(
                baseline=boundary
            )
            self.assertTrue(materialized)
            self.assertEqual(boundary["record_count"], 1)
            self.assertEqual(len(records), 1)
            self.assertEqual(located.source_identity_sha256, source_identity)
            tracker.close()

    def test_partial_nonempty_boundary_never_uses_empty_allowance(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            codex_home, session_id, path = self.session_layout(Path(temporary))
            path.write_bytes(b"{")
            path.chmod(0o600)
            tracker = LIVE.PreAttestationSessionBoundaryTracker(
                codex_home, session_id
            )
            with self.assertRaisesRegex(
                LIVE.NativeSessionBoundaryError, "trailing partial record"
            ):
                tracker.capture(baseline=self.baseline())

    def test_empty_allowance_rejects_public_alias_and_nonregular_sources(
        self,
    ) -> None:
        for kind, expected in (
            ("public", "not private"),
            ("hardlink", "filesystem aliases"),
            ("duplicate", "duplicate active/archive"),
            ("symlink", "symlink"),
            ("fifo", "not a regular file"),
        ):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                codex_home, session_id, path = self.session_layout(root)
                if kind == "public":
                    path.touch(mode=0o600)
                    path.chmod(0o644)
                elif kind == "hardlink":
                    path.touch(mode=0o600)
                    path.chmod(0o600)
                    os.link(path, root / "same-object-alias")
                elif kind == "duplicate":
                    path.touch(mode=0o600)
                    path.chmod(0o600)
                    duplicate = (
                        codex_home
                        / "archived_sessions"
                        / f"archived-{session_id}.jsonl"
                    )
                    duplicate.touch(mode=0o600)
                    duplicate.chmod(0o600)
                elif kind == "symlink":
                    target = root / "target"
                    target.touch(mode=0o600)
                    path.symlink_to(target)
                else:
                    os.mkfifo(path, mode=0o600)
                tracker = LIVE.PreAttestationSessionBoundaryTracker(
                    codex_home, session_id
                )
                with self.assertRaisesRegex(
                    LIVE.NativeSessionBoundaryError, expected
                ):
                    tracker.capture(baseline=self.baseline())

    def test_pinned_empty_rejects_replacement_rewrite_and_permission_drift(
        self,
    ) -> None:
        for kind, expected in (
            ("replacement", "unlinked"),
            ("rewrite", "rewritten after observation"),
            ("permission", "identity changed after pinning"),
        ):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                codex_home, session_id, path = self.session_layout(root)
                path.touch(mode=0o600)
                path.chmod(0o600)
                tracker = LIVE.PreAttestationSessionBoundaryTracker(
                    codex_home, session_id
                )
                tracker.capture(baseline=self.baseline())
                if kind == "replacement":
                    replacement = root / "replacement"
                    replacement.touch(mode=0o600)
                    replacement.chmod(0o600)
                    replacement.replace(path)
                elif kind == "rewrite":
                    prior = path.stat()
                    path.write_bytes(b"transient")
                    path.write_bytes(b"")
                    os.utime(
                        path,
                        ns=(prior.st_atime_ns, prior.st_mtime_ns + 1_000_000_000),
                    )
                else:
                    path.chmod(0o644)
                with self.assertRaisesRegex(
                    LIVE.NativeSessionBoundaryError, expected
                ):
                    tracker.capture(baseline=self.baseline())

    def test_materialized_boundary_rejects_same_inode_truncation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            codex_home, session_id, path = self.session_layout(Path(temporary))
            path.write_text(
                json.dumps(
                    {"type": "session_meta", "payload": {"id": session_id}}
                )
                + "\n",
                encoding="utf-8",
            )
            path.chmod(0o600)
            tracker = LIVE.PreAttestationSessionBoundaryTracker(
                codex_home, session_id
            )
            _located, boundary, _records, materialized = tracker.capture(
                baseline=self.baseline()
            )
            self.assertTrue(materialized)
            path.write_bytes(b"")
            with self.assertRaisesRegex(
                LIVE.NativeSessionBoundaryError, "truncated after observation"
            ):
                tracker.capture(baseline=boundary)

    def test_descriptor_read_rejects_ancestor_path_substitution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            codex_home, session_id, path = self.session_layout(root)
            path.touch(mode=0o600)
            path.chmod(0o600)
            tracker = LIVE.PreAttestationSessionBoundaryTracker(
                codex_home, session_id
            )
            _located, baseline, _records, materialized = tracker.capture(
                baseline=self.baseline()
            )
            self.assertFalse(materialized)
            raw = (
                json.dumps(
                    {"type": "session_meta", "payload": {"id": session_id}}
                )
                + "\n"
            ).encode("utf-8")
            path.write_bytes(raw)
            real_pread = os.pread
            substituted = False

            def substitute_after_descriptor_read(
                fd: int, length: int, offset: int
            ) -> bytes:
                nonlocal substituted
                result = real_pread(fd, length, offset)
                if not substituted:
                    active = path.parent
                    detached = root / "detached-session-directory"
                    active.replace(detached)
                    active.mkdir(parents=True)
                    replacement = active / path.name
                    replacement.write_bytes(raw)
                    replacement.chmod(0o600)
                    substituted = True
                return result

            with mock.patch.object(
                LIVE.os,
                "pread",
                side_effect=substitute_after_descriptor_read,
            ), self.assertRaisesRegex(
                LIVE.NativeSessionBoundaryError, "changed after pinning"
            ):
                tracker.capture(baseline=baseline)
            self.assertTrue(substituted)

    def test_descriptor_capture_retries_one_append_to_a_stable_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            codex_home, session_id, path = self.session_layout(Path(temporary))
            first = (
                json.dumps({"type": "session_meta", "payload": {"id": session_id}})
                + "\n"
            ).encode("utf-8")
            second = (
                json.dumps({"type": "event_msg", "payload": {"type": "task_started"}})
                + "\n"
            ).encode("utf-8")
            path.write_bytes(first)
            path.chmod(0o600)
            tracker = LIVE.PreAttestationSessionBoundaryTracker(
                codex_home, session_id
            )
            real_pread = os.pread
            appended = False

            def append_after_first_read(fd: int, length: int, offset: int) -> bytes:
                nonlocal appended
                result = real_pread(fd, length, offset)
                if not appended:
                    with path.open("ab") as handle:
                        handle.write(second)
                        handle.flush()
                        os.fsync(handle.fileno())
                    appended = True
                return result

            with mock.patch.object(
                LIVE.os,
                "pread",
                side_effect=append_after_first_read,
            ), mock.patch.object(
                LIVE,
                "DESCRIPTOR_CAPTURE_RETRY_GAP_SECONDS",
                0.0,
            ):
                _located, boundary, records, materialized = tracker.capture(
                    baseline=self.baseline()
                )
            self.assertTrue(appended)
            self.assertTrue(materialized)
            self.assertEqual(boundary["record_count"], 2)
            self.assertEqual(len(records), 2)
            self.assertEqual(boundary["byte_offset"], len(first + second))

    def test_descriptor_capture_rejects_rewrite_hidden_by_growth(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            codex_home, session_id, path = self.session_layout(Path(temporary))
            first = (
                json.dumps({"type": "session_meta", "payload": {"id": session_id}})
                + "\n"
            ).encode("utf-8")
            rewritten = (
                json.dumps(
                    {"type": "session_meta", "payload": {"id": session_id}},
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8")
            appended = b'{"type":"event_msg","payload":{"type":"task_started"}}\n'
            path.write_bytes(first)
            path.chmod(0o600)
            tracker = LIVE.PreAttestationSessionBoundaryTracker(
                codex_home, session_id
            )
            real_pread = os.pread
            replaced = False

            def rewrite_and_grow(fd: int, length: int, offset: int) -> bytes:
                nonlocal replaced
                result = real_pread(fd, length, offset)
                if not replaced:
                    path.write_bytes(rewritten + appended)
                    replaced = True
                return result

            with mock.patch.object(
                LIVE.os,
                "pread",
                side_effect=rewrite_and_grow,
            ), mock.patch.object(
                LIVE,
                "DESCRIPTOR_CAPTURE_RETRY_GAP_SECONDS",
                0.0,
            ), self.assertRaisesRegex(
                LIVE.NativeSessionBoundaryError,
                "prefix was rewritten during append retry",
            ):
                tracker.capture(baseline=self.baseline())
            self.assertTrue(replaced)

    def test_descriptor_capture_bounds_continuous_append_retries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            codex_home, session_id, path = self.session_layout(Path(temporary))
            path.write_text(
                json.dumps({"type": "session_meta", "payload": {"id": session_id}})
                + "\n",
                encoding="utf-8",
            )
            path.chmod(0o600)
            tracker = LIVE.PreAttestationSessionBoundaryTracker(
                codex_home, session_id
            )
            real_pread = os.pread
            append_count = 0

            def keep_appending(fd: int, length: int, offset: int) -> bytes:
                nonlocal append_count
                result = real_pread(fd, length, offset)
                with path.open("ab") as handle:
                    handle.write(
                        (
                            json.dumps(
                                {
                                    "type": "event_msg",
                                    "payload": {
                                        "type": "progress",
                                        "ordinal": append_count,
                                    },
                                }
                            )
                            + "\n"
                        ).encode("utf-8")
                    )
                    handle.flush()
                    os.fsync(handle.fileno())
                append_count += 1
                return result

            with mock.patch.object(
                LIVE.os,
                "pread",
                side_effect=keep_appending,
            ), mock.patch.object(
                LIVE,
                "DESCRIPTOR_CAPTURE_RETRY_GAP_SECONDS",
                0.0,
            ), self.assertRaisesRegex(
                LIVE.NativeSessionBoundaryError,
                "did not stabilize after append retries",
            ):
                tracker.capture(baseline=self.baseline())
            self.assertEqual(append_count, LIVE.DESCRIPTOR_CAPTURE_ATTEMPT_MAX)

    def test_descriptor_capture_rejects_same_size_rewrite_during_retry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            codex_home, session_id, path = self.session_layout(Path(temporary))
            first = (
                json.dumps({"type": "session_meta", "payload": {"id": session_id}})
                + "\n"
            ).encode("utf-8")
            second = (
                json.dumps({"type": "event_msg", "payload": {"type": "task_started"}})
                + "\n"
            ).encode("utf-8")
            path.write_bytes(first)
            path.chmod(0o600)
            tracker = LIVE.PreAttestationSessionBoundaryTracker(
                codex_home, session_id
            )
            real_pread = os.pread
            real_pin = tracker._pin_or_verify
            appended = False
            pin_count = 0

            def append_after_first_read(fd: int, length: int, offset: int) -> bytes:
                nonlocal appended
                result = real_pread(fd, length, offset)
                if not appended:
                    with path.open("ab") as handle:
                        handle.write(second)
                        handle.flush()
                        os.fsync(handle.fileno())
                    appended = True
                return result

            def rewrite_after_post_read_stat(located: object) -> os.stat_result:
                nonlocal pin_count
                current = real_pin(located)  # type: ignore[arg-type]
                pin_count += 1
                if pin_count == 2:
                    raw = bytearray(path.read_bytes())
                    raw[-2] = ord(" ")
                    path.write_bytes(raw)
                return current

            with mock.patch.object(
                LIVE.os,
                "pread",
                side_effect=append_after_first_read,
            ), mock.patch.object(
                tracker,
                "_pin_or_verify",
                side_effect=rewrite_after_post_read_stat,
            ), mock.patch.object(
                LIVE,
                "DESCRIPTOR_CAPTURE_RETRY_GAP_SECONDS",
                0.0,
            ), self.assertRaisesRegex(
                LIVE.NativeSessionBoundaryError,
                "changed during descriptor capture",
            ):
                tracker.capture(baseline=self.baseline())
            self.assertTrue(appended)
            self.assertGreaterEqual(pin_count, 3)

    def test_same_pinned_object_allows_only_explicit_archive_transition(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            codex_home, session_id, path = self.session_layout(Path(temporary))
            path.write_text(
                json.dumps(
                    {"type": "session_meta", "payload": {"id": session_id}}
                )
                + "\n",
                encoding="utf-8",
            )
            path.chmod(0o600)
            tracker = LIVE.PreAttestationSessionBoundaryTracker(
                codex_home, session_id
            )
            located, boundary, _records, materialized = tracker.capture(
                baseline=self.baseline()
            )
            self.assertTrue(materialized)
            source_identity = located.source_identity_sha256
            archived = codex_home / "archived_sessions" / path.name
            path.replace(archived)
            located, current, _records, materialized = tracker.capture(
                baseline=boundary,
                allow_archive_transition=True,
            )
            self.assertTrue(materialized)
            self.assertEqual(current, boundary)
            self.assertEqual(located.store, "archived_sessions")
            self.assertEqual(located.source_identity_sha256, source_identity)

    def test_app_server_child_and_control_artifacts_are_private(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            process = mock.Mock()
            process.stdin = io.StringIO()
            process.stdout = io.StringIO()
            process.stderr = io.StringIO()
            fake_thread = mock.Mock()
            with mock.patch.object(
                LIVE.subprocess, "Popen", return_value=process
            ) as popen, mock.patch.object(
                LIVE.threading, "Thread", return_value=fake_thread
            ), mock.patch.object(
                LIVE.AppServer,
                "request",
                return_value=({"codexHome": str(root / "codex-home")}, 1.0),
            ), mock.patch.object(LIVE.AppServer, "notify"):
                LIVE.AppServer()
            self.assertEqual(popen.call_args.kwargs["umask"], 0o077)

            control = root / "world-visible-parent" / "control.json"
            LIVE.write_private_artifact(control, {"accepted": True})
            self.assertEqual(stat.S_IMODE(control.stat().st_mode), 0o600)
            self.assertEqual(
                stat.S_IMODE(control.parent.stat().st_mode), 0o700
            )


class Generation12CalibrationRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        patcher = mock.patch.object(
            LIVE,
            "_measure_action_ms",
            side_effect=deterministic_calibration_measurement,
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    @staticmethod
    def owner() -> dict:
        return {"pid": 1, "start_ticks": 1, "boot_id_sha256": "a" * 64}

    def run_calibration(
        self,
        server: FakeCalibrationServer,
        root: Path,
    ) -> tuple[dict, dict]:
        record_dir = root / "records"
        record_dir.mkdir()
        return LIVE.calibration(
            server,
            root,
            record_dir,
            self.owner(),
            run_nonce=str(uuid.uuid4()),
            phase_nonce=str(uuid.uuid4()),
            materialization_timeout_seconds=3.0,
        )

    def test_exact_gen11_zero_byte_fault_recovers_across_both_edges(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            server = EmptySessionCalibrationServer(
                root,
                read_faults={1: ("thread/read", -32603, 137.0)},
            )
            receipt, evidence = self.run_calibration(server, root)
            recovery = evidence["thread_read_recovery"]
            self.assertEqual(receipt["validation_outcome"], "accepted")
            self.assertEqual(recovery["outcome"], "recovered")
            self.assertEqual(recovery["replacement_attempt_count"], 1)
            self.assertTrue(recovery["token_consumed"])
            self.assertEqual(recovery["fault_boundary_record_count"], 0)
            self.assertEqual(recovery["fault_boundary_byte_offset"], 0)
            self.assertEqual(recovery["pre_attempt_boundary_record_count"], 0)
            self.assertEqual(recovery["pre_attempt_boundary_byte_offset"], 0)
            self.assertEqual(
                recovery["prior_boundary_sha256"], LIVE.sha256_bytes(b"")
            )
            self.assertEqual(
                recovery["pre_attempt_boundary_sha256"],
                LIVE.sha256_bytes(b""),
            )
            self.assertRegex(
                recovery["prior_source_identity_sha256"], r"^[0-9a-f]{64}$"
            )
            self.assertEqual(
                recovery["pre_attempt_source_identity_sha256"],
                recovery["prior_source_identity_sha256"],
            )
            self.assertEqual(
                LIVE.validate_calibration_read_recovery_telemetry(recovery), []
            )
            self.assertEqual(server.thread_start_count, 1)
            self.assertEqual(server.turn_start_count, 1)

            disappeared = dict(recovery)
            disappeared["pre_attempt_source_identity_sha256"] = None
            disappeared["telemetry_sha256"] = LIVE.canonical_sha256(
                {
                    key: value
                    for key, value in disappeared.items()
                    if key != "telemetry_sha256"
                }
            )
            self.assertIn(
                "read-recovery-pre-attempt-source-changed",
                LIVE.validate_calibration_read_recovery_telemetry(disappeared),
            )
            self.assertIn(
                "read-recovery-empty-pre-attempt-boundary-invalid",
                LIVE.validate_calibration_read_recovery_telemetry(disappeared),
            )
            missing_fault_source = dict(recovery)
            missing_fault_source["prior_source_identity_sha256"] = None
            missing_fault_source["telemetry_sha256"] = LIVE.canonical_sha256(
                {
                    key: value
                    for key, value in missing_fault_source.items()
                    if key != "telemetry_sha256"
                }
            )
            self.assertIn(
                "read-recovery-empty-fault-boundary-invalid",
                LIVE.validate_calibration_read_recovery_telemetry(
                    missing_fault_source
                ),
            )
            materialized_pre_attempt = dict(recovery)
            materialized_pre_attempt["pre_attempt_boundary_record_count"] = 1
            materialized_pre_attempt["pre_attempt_boundary_byte_offset"] = 1
            materialized_pre_attempt["pre_attempt_boundary_sha256"] = "f" * 64
            materialized_pre_attempt["telemetry_sha256"] = LIVE.canonical_sha256(
                {
                    key: value
                    for key, value in materialized_pre_attempt.items()
                    if key != "telemetry_sha256"
                }
            )
            self.assertIn(
                "read-recovery-pre-attempt-boundary-changed",
                LIVE.validate_calibration_read_recovery_telemetry(
                    materialized_pre_attempt
                ),
            )

    def test_observed_two_record_scaffold_recovers_once_without_new_work(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            server = StartupScaffoldCalibrationServer(
                root,
                read_faults={1: ("thread/read", -32603, 137.0)},
            )
            receipt, evidence = self.run_calibration(server, root)
            recovery = evidence["thread_read_recovery"]
            self.assertEqual(receipt["validation_outcome"], "accepted")
            self.assertEqual(recovery["outcome"], "recovered")
            self.assertEqual(
                recovery["fault_boundary_classification"],
                "canonical-session-meta-task-started",
            )
            self.assertEqual(recovery["fault_boundary_record_count"], 2)
            self.assertGreater(recovery["fault_boundary_byte_offset"], 0)
            self.assertEqual(
                recovery["pre_attempt_boundary_sha256"],
                recovery["prior_boundary_sha256"],
            )
            self.assertEqual(
                recovery["pre_dispatch_boundary_sha256"],
                recovery["prior_boundary_sha256"],
            )
            self.assertEqual(recovery["wire_dispatch_count"], 1)
            self.assertEqual(recovery["transport_outcome"], "response-correlated")
            self.assertEqual(server.guarded_read_count, 1)
            self.assertEqual(server.thread_start_count, 1)
            self.assertEqual(server.turn_start_count, 1)
            self.assertEqual(
                LIVE.validate_calibration_read_recovery_telemetry(recovery), []
            )

    def test_recovery_rejects_missing_source_at_either_authorization_edge(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            server = MissingSessionCalibrationServer(
                root,
                read_faults={1: ("thread/read", -32603, 1.0)},
            )
            with self.assertRaisesRegex(
                LIVE.AppServerError,
                "read-recovery-session-source-missing-at-fault",
            ):
                self.run_calibration(server, root)
            self.assertEqual(server.read_count, 1)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            server = EmptySessionCalibrationServer(
                root,
                read_faults={1: ("thread/read", -32603, 1.0)},
            )
            removed = False
            original_guarded_read = server.read_thread_once_with_guard

            def remove_before_dispatch(*args, **kwargs):
                nonlocal removed
                if server.path.exists() and not removed:
                    server.path.unlink()
                    removed = True
                return original_guarded_read(*args, **kwargs)

            record_dir = root / "records"
            record_dir.mkdir()
            with mock.patch.object(
                server,
                "read_thread_once_with_guard",
                side_effect=remove_before_dispatch,
            ), self.assertRaisesRegex(
                LIVE.AppServerError, "pinned-session-source-missing"
            ):
                LIVE.calibration(
                    server,
                    root,
                    record_dir,
                    self.owner(),
                    run_nonce=str(uuid.uuid4()),
                    phase_nonce=str(uuid.uuid4()),
                    materialization_timeout_seconds=3.0,
                )
            self.assertTrue(removed)
            self.assertEqual(server.read_count, 1)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            server = EmptySessionCalibrationServer(
                root,
                read_faults={1: ("thread/read", -32603, 1.0)},
            )
            materialized = False
            original_guarded_read = server.read_thread_once_with_guard

            def materialize_before_dispatch(*args, **kwargs):
                nonlocal materialized
                if not materialized:
                    server._write(
                        [
                            {
                                "type": "session_meta",
                                "payload": {"id": server.thread_id},
                            },
                            {
                                "type": "event_msg",
                                "payload": {
                                    "type": "task_started",
                                    "turn_id": server.turn_id,
                                },
                            },
                            {
                                "type": "response_item",
                                "payload": {
                                    "type": "message",
                                    "role": "user",
                                },
                            },
                        ]
                    )
                    materialized = True
                return original_guarded_read(*args, **kwargs)

            record_dir = root / "records"
            record_dir.mkdir()
            with mock.patch.object(
                server,
                "read_thread_once_with_guard",
                side_effect=materialize_before_dispatch,
            ), self.assertRaisesRegex(
                LIVE.AppServerError,
                "operative-activity-observed-before-dispatch",
            ):
                LIVE.calibration(
                    server,
                    root,
                    record_dir,
                    self.owner(),
                    run_nonce=str(uuid.uuid4()),
                    phase_nonce=str(uuid.uuid4()),
                    materialization_timeout_seconds=3.0,
                )
            self.assertTrue(materialized)
            self.assertEqual(server.read_count, 1)

    def test_plain_three_record_boundary_cannot_authorize_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            server = FakeCalibrationServer(
                root,
                read_faults={1: ("thread/read", -32603, 1.0)},
            )
            record_dir = root / "records"
            record_dir.mkdir()
            with self.assertRaisesRegex(
                LIVE.AppServerError,
                "read-recovery-operative-activity-observed-at-fault",
            ):
                LIVE.calibration(
                    server,
                    root,
                    record_dir,
                    self.owner(),
                    run_nonce=str(uuid.uuid4()),
                    phase_nonce=str(uuid.uuid4()),
                    materialization_timeout_seconds=3.0,
                )
            self.assertEqual(server.read_count, 1)
            boundary, records = LIVE.capture_boundary(
                server.path,
                server.thread_id,
            )
            self.assertEqual(boundary["record_count"], 3)
            self.assertEqual(len(records), 3)

    def test_normal_observe_accepts_same_pinned_zero_precursor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            server = EmptySessionCalibrationServer(root)
            receipt, evidence = self.run_calibration(server, root)
            self.assertEqual(receipt["validation_outcome"], "accepted")
            self.assertEqual(
                evidence["thread_read_recovery"]["outcome"], "not-needed"
            )
            first = evidence["materialization_evidence"][
                "control_observations"
            ][0]
            self.assertEqual(first["boundary"]["record_count"], 0)
            self.assertRegex(
                first["source_identity_sha256"], r"^[0-9a-f]{64}$"
            )

    def test_fault_boundary_still_rejects_partial_bytes_and_activity(self) -> None:
        for kind, expected in (
            ("partial", "trailing partial record"),
            ("activity", "operative-activity-observed-at-fault"),
        ):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                if kind == "activity":
                    server = OperativeActivityAtFaultServer(
                        root,
                        read_faults={1: ("thread/read", -32603, 1.0)},
                    )
                else:
                    server = EmptySessionCalibrationServer(
                        root,
                        read_faults={1: ("thread/read", -32603, 1.0)},
                    )
                    original_start = server.start_turn

                    def start_partial(
                        thread_id: str, prompt: str
                    ) -> tuple[dict, float]:
                        result = original_start(thread_id, prompt)
                        server.path.write_bytes(b"{")
                        return result

                    server.start_turn = start_partial  # type: ignore[method-assign]
                record_dir = root / "records"
                record_dir.mkdir()
                with self.assertRaisesRegex(LIVE.AppServerError, expected):
                    LIVE.calibration(
                        server,
                        root,
                        record_dir,
                        self.owner(),
                        run_nonce=str(uuid.uuid4()),
                        phase_nonce=str(uuid.uuid4()),
                        materialization_timeout_seconds=3.0,
                    )

    def test_exceptional_calibration_exit_closes_pinned_descriptor(self) -> None:
        class RecordingTracker(LIVE.PreAttestationSessionBoundaryTracker):
            instances: list["RecordingTracker"] = []

            def __init__(self, codex_home: Path, session_id: str) -> None:
                super().__init__(codex_home, session_id)
                self.close_count = 0
                self.instances.append(self)

            def close(self) -> None:
                self.close_count += 1
                super().close()

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            record_dir = root / "records"
            record_dir.mkdir()
            server = EmptySessionCalibrationServer(
                root,
                read_faults={1: ("thread/read", -32603, 1.0)},
            )
            original_start = server.start_turn

            def start_partial(
                thread_id: str, prompt: str
            ) -> tuple[dict, float]:
                result = original_start(thread_id, prompt)
                server.path.write_bytes(b"{")
                return result

            server.start_turn = start_partial  # type: ignore[method-assign]
            with mock.patch.object(
                LIVE,
                "PreAttestationSessionBoundaryTracker",
                RecordingTracker,
            ), self.assertRaisesRegex(
                LIVE.AppServerError, "trailing partial record"
            ):
                LIVE.calibration(
                    server,
                    root,
                    record_dir,
                    self.owner(),
                    run_nonce=str(uuid.uuid4()),
                    phase_nonce=str(uuid.uuid4()),
                    materialization_timeout_seconds=3.0,
                )
            self.assertEqual(len(RecordingTracker.instances), 1)
            tracker = RecordingTracker.instances[0]
            self.assertEqual(tracker.close_count, 1)
            self.assertIsNone(tracker._fd)

    def test_interrupt_alias_and_archive_substitution_fail_closed(self) -> None:
        for server_type, expected in (
            (AliasOnInterruptServer, "interrupt-boundary-invalid.*aliases"),
            (SubstituteOnArchiveServer, "terminal-boundary-invalid.*unlinked"),
        ):
            with self.subTest(server=server_type.__name__), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                server = server_type(root)
                record_dir = root / "records"
                record_dir.mkdir()
                with self.assertRaisesRegex(LIVE.AppServerError, expected):
                    LIVE.calibration(
                        server,
                        root,
                        record_dir,
                        self.owner(),
                        run_nonce=str(uuid.uuid4()),
                        phase_nonce=str(uuid.uuid4()),
                        materialization_timeout_seconds=3.0,
                    )


if __name__ == "__main__":
    unittest.main()
