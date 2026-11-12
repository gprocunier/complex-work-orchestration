"""Offline supervision allocation order; fake admission is fixture-only."""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

from tests import test_supervise_native_worker as fixtures
from tests.test_policy_current_effects import current_policy
from tests.private_workspace_fixtures import copy_context_files


supervisor = fixtures.supervisor
NONCE = uuid.UUID("01234567-89ab-4cde-8fab-0123456789ab")


class SupervisionIdentityAllocationTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="cwo-identity-order-")
        self.addCleanup(temporary.cleanup)
        self.temporary = Path(temporary.name)
        self.workspace = copy_context_files(
            fixtures.ROOT, self.temporary / "workspace",
            ["scripts/supervise_native_worker.py"],
        )
        self.enterContext(mock.patch.dict(os.environ, {
            "CWO_TEMP_ROOT": str(self.temporary / "artifacts"),
            "CWO_SESSION_ID": "supervision-identity-order",
            "CWO_PRECOMMIT_REGISTRY_ROOT": str(self.temporary / "registry"),
        }))
        self.root = fixtures.cwo_temp_dir()
        self.enterContext(current_policy())
        # Historical construction only; start uses the current policy below.
        with fixtures.historical_v2_policy(), mock.patch.object(
            fixtures, "_FIXTURE_ROOT", self.root
        ), mock.patch.object(fixtures, "ROOT", self.workspace):
            self.packet = fixtures.planned_packet(packet_id="identity-order")
        self.packet_file = self.root / "packet.json"
        self.packet_file.write_text(json.dumps(self.packet), encoding="utf-8")
        self.session_file = self.root / "session.jsonl"
        fixtures.write_records(self.session_file, [fixtures.session_meta("identity-session")])
        self.args = argparse.Namespace(
            packet=str(self.packet_file), session_id="identity-session",
            session_file=str(self.session_file), agent_id="offline-fixture-agent",
            state_file=str(self.root / "state.json"),
            audit_file=str(self.root / "audit.jsonl"), retry_authorization=None,
            now="2026-10-24T16:00:00Z",
        )
        # Same qualified admission seams as run_cli; no production authority.
        self.enterContext(mock.patch.object(
            supervisor, "require_native_operative_dispatch", return_value=None
        ))
        self.enterContext(mock.patch.object(
            supervisor, "validate_native_worker_packet", return_value=[]
        ))

    def _snapshot(self) -> dict:
        return {
            path.relative_to(self.temporary).as_posix(): (
                path.stat().st_mode,
                None if path.is_dir() else path.read_bytes(),
            )
            for path in self.temporary.rglob("*")
        }

    @contextlib.contextmanager
    def _observe(self, trace: list[str], *, require_entropy: bool = False):
        with contextlib.ExitStack() as stack:
            for name in (
                "_persist_workspace_baseline", "capture_workspace_baseline",
                "cwo_temp_path", "atomic_write_text", "_write_state",
                "acquire_audit_lock", "_audit_event", "record_audit_event",
            ):
                original = getattr(supervisor, name)

                def observed(*args, _name=name, _original=original, **kwargs):
                    if _name == "cwo_temp_path" and kwargs.get("create_parent") is False:
                        trace.append("state-path-read")
                    else:
                        if require_entropy:
                            self.assertIn("entropy", trace, _name)
                        trace.append(_name)
                    return _original(*args, **kwargs)

                stack.enter_context(mock.patch.object(
                    supervisor, name, side_effect=observed
                ))
            yield

    def _nonce(self, trace: list[str]) -> uuid.UUID:
        trace.append("entropy")
        return NONCE

    def _positive(self) -> dict:
        # Real start, baseline capture/persistence, state lock/write and audit.
        with mock.patch.object(uuid, "uuid4", return_value=NONCE) as nonce:
            state = supervisor.start(self.args)
        nonce.assert_called_once_with()
        self.assertIsInstance(state["state_id"], str)
        self.assertIn(str(NONCE), state["state_id"])
        baseline = state["observed"]["workspace_baseline"]
        self.assertTrue(Path(baseline["path"]).is_file())
        self.assertTrue(baseline["baseline_complete"])
        written = json.loads(Path(state["state_file"]).read_text(encoding="utf-8"))
        self.assertEqual(written["state_id"], state["state_id"])
        events = [
            json.loads(line)
            for line in Path(self.args.audit_file).read_text(encoding="utf-8").splitlines()
        ]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "native_supervision_started")
        self.assertEqual(events[0]["native_supervision_state_id"], state["state_id"])
        return state

    def test_entropy_failure_preserves_all_temp_artifacts_after_real_positive(self):
        self._positive()
        # A fresh session makes any old-order baseline write a new artifact.
        self.args.session_id = "entropy-failure-session"
        self.args.state_file = str(self.root / "failed-state.json")
        fixtures.write_records(
            self.session_file, [fixtures.session_meta(self.args.session_id)]
        )
        before = self._snapshot()
        trace: list[str] = []
        failure = OSError("entropy unavailable")
        with self._observe(trace), mock.patch.object(
            supervisor, "_consume_retry_recovery_action",
            wraps=supervisor._consume_retry_recovery_action,
        ) as consume, mock.patch.object(uuid, "uuid4", side_effect=failure) as nonce:
            with self.assertRaises(OSError) as raised:
                supervisor.start(self.args)
        self.assertIs(raised.exception, failure)
        nonce.assert_called_once_with()
        # On e83 this fails because the real baseline was already persisted.
        self.assertEqual(self._snapshot(), before)
        self.assertEqual(trace, [])
        consume.assert_not_called()
        self.assertFalse(Path(self.args.state_file).exists())

    def test_synchronous_mutation_observers_see_allocation_first(self):
        self.args.state_file = None
        trace: list[str] = []
        with self._observe(trace, require_entropy=True), mock.patch.object(
            uuid, "uuid4", side_effect=lambda: self._nonce(trace)
        ) as nonce:
            state = supervisor.start(self.args)
        nonce.assert_called_once_with()
        self.assertEqual(trace[0], "state-path-read")
        self.assertEqual(trace[1], "entropy")
        for boundary in (
            "_persist_workspace_baseline", "capture_workspace_baseline",
            "cwo_temp_path", "atomic_write_text", "_write_state",
            "acquire_audit_lock", "_audit_event", "record_audit_event",
        ):
            self.assertIn(boundary, trace)
        self.assertTrue(Path(state["state_file"]).is_file())
        self.assertIn(str(NONCE), state["state_id"])

    def _synthetic_retry(self) -> dict:
        # Only explicit start bindings are real here; receipt validation below
        # is a synthetic seam, not a usable receipt or accepted retry.
        authorization = {
            "retry_packet_id": self.packet["packet_id"],
            "bead_id": self.packet["bead_id"],
            "requested_model": self.packet["requested_model"],
            "attested_model": self.packet["requested_model"],
            "retry_session_id": self.args.session_id,
            "attempt_from": 0, "attempt_to": 1,
            "work_sha256": supervisor.canonical_work_sha256(self.packet),
            "evidence_bindings": {
                "retry_packet_sha256": supervisor.canonical_retry_artifact_sha256(
                    self.packet
                ),
                "recovery_policy_sha256": supervisor.canonical_retry_artifact_sha256(
                    supervisor.load_policy("native-worker-execution")["bounded_native_retry"]
                ),
            },
        }
        path = self.root / "synthetic-retry.json"
        path.write_text(json.dumps(authorization), encoding="utf-8")
        self.args.retry_authorization = str(path)
        return authorization

    def test_synthetic_retry_seam_retains_real_refusal_and_blocks_consumption(self):
        self._synthetic_retry()
        store = supervisor.RecoveryActionStore()
        hooks = {"verified_recovery_action": object(), "recovery_action_store": store}
        before = self._snapshot()
        with mock.patch.object(
            supervisor, "validate_retry_authorization", return_value=[]
        ), mock.patch.object(
            supervisor.RecoveryActionStore, "consume",
            side_effect=AssertionError("synthetic action must never be consumed"),
        ) as consume:
            # Do not replace the real helper's refusal with retry success.
            with mock.patch.object(
                supervisor, "_consume_retry_recovery_action",
                wraps=supervisor._consume_retry_recovery_action,
            ) as bridge, mock.patch.object(uuid, "uuid4", return_value=NONCE) as nonce:
                with self.assertRaisesRegex(
                    SystemExit, "requires an exact verified recovery action object"
                ):
                    supervisor.start(self.args, **hooks)
            nonce.assert_called_once_with()
            bridge.assert_called_once()
            consume.assert_not_called()
            self.assertEqual(self._snapshot(), before)
            failure = OSError("entropy unavailable")
            with mock.patch.object(
                supervisor, "_consume_retry_recovery_action",
                wraps=supervisor._consume_retry_recovery_action,
            ) as bridge, mock.patch.object(uuid, "uuid4", side_effect=failure) as nonce:
                with self.assertRaises(OSError) as raised:
                    supervisor.start(self.args, **hooks)
            self.assertIs(raised.exception, failure)
            nonce.assert_called_once_with()
            bridge.assert_not_called()
            consume.assert_not_called()
            self.assertEqual(self._snapshot(), before)

    def test_recovery_handles_without_authorization_refuse_before_packet_io(self):
        before = self._snapshot()
        for hooks in (
            {"verified_recovery_action": object()},
            {"recovery_action_store": object()},
            {"verified_recovery_action": False},
        ):
            with self.subTest(hooks=sorted(hooks)), mock.patch.object(
                supervisor, "_load_json", side_effect=AssertionError("packet read before input refusal")
            ) as load, mock.patch.object(uuid, "uuid4", side_effect=OSError("entropy unavailable")) as nonce:
                with self.assertRaisesRegex(SystemExit, "recovery action hooks require --retry-authorization"):
                    supervisor.start(self.args, **hooks)
            load.assert_not_called()
            nonce.assert_not_called()
            self.assertEqual(self._snapshot(), before)

    def test_synthetic_retry_without_handles_still_refuses_before_entropy(self):
        self._synthetic_retry()
        before = self._snapshot()
        with mock.patch.object(
            supervisor, "validate_retry_authorization", return_value=[]
        ), mock.patch.object(uuid, "uuid4", side_effect=OSError("entropy unavailable")) as nonce:
            with self.assertRaisesRegex(
                SystemExit, "serialized retry authorization is audit-only"
            ):
                supervisor.start(self.args)
        nonce.assert_not_called()
        self.assertEqual(self._snapshot(), before)


if __name__ == "__main__":
    unittest.main()
