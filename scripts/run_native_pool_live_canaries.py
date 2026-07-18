#!/usr/bin/env python3
"""Run disposable exact-Spark app-server canaries for supervisor concurrency.

This ignored work-packet harness persists only sanitized, hash-bound evidence.
Raw model messages and reasoning remain in Codex-owned session telemetry and are
never copied into the result artifact.
"""

from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import hashlib
import json
import math
import os
import pwd
import re
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Callable, Mapping
import uuid


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.native_control import build_control_turn_contract  # noqa: E402
from cwo_core.native_live_campaign_contracts import (  # noqa: E402
    HistoricalV4V1ProofInputs,
    JsonArtifactSnapshot,
    VALIDATOR_CONTRACT_PATHS,  # noqa: F401
    Version5PredecessorProofInputs,
    Version6PredecessorProofInputs,
    Version7QuarantinePredecessorProofInputs,
    Version8ProtectedFaultPredecessorProofInputs,
    Version9PreallocationFaultPredecessorProofInputs,
    Version10InterruptedEmptyBoundaryPredecessorProofInputs,
    active_outer_authority_scope_key,
    validate_campaign_manifest,
    validate_full_auto_authorization as validate_full_auto_authorization_contract,
    validate_release_patch_result,
    validator_contract_sha256,  # noqa: F401
    validator_contract_sha256_v3,
    validator_contract_sha256_v4,
    validator_contract_sha256_v5,
    validator_contract_sha256_v6,
    validate_operative_version_tuple,
)
from cwo_core.native_canary_contracts import (  # noqa: E402
    CanaryAuthorizationStore,
    CONTROL_OBSERVATION_MAX,
    MATERIALIZATION_EVIDENCE_SCHEMA,
    MATERIALIZATION_EVIDENCE_TYPE,
    NativeCanaryContractError,
    canonical_sha256 as domain_sha256,
    consume_steering_receipt,
    materialization_execution_correlation,
    new_authorization_state,
    seal_materialization_evidence,
    validate_capability_rendered_command,
    validate_materialization_evidence,
)
from cwo_core.native_pool import NativePoolCoordinator  # noqa: E402
from cwo_core.native_live_allocation_ledger import (  # noqa: E402
    EXPECTED_ROLES,
    NativeLiveAllocationLedgerStore,
)
from cwo_core.native_pool_config import (  # noqa: E402
    build_live_canary_pool_contract,
    seal_bound_manifest_validation,
    validate_live_canary_manifest_gate,
)
from cwo_core.native_pool_contracts import (  # noqa: E402
    CAPABILITY_CERTIFICATION_ENVELOPE,
    CAPABILITY_CERTIFICATION_VERSION,
    CAPABILITY_OBSERVATION_AUTHORITY,
    CAPABILITY_RESPONSE_TIME_EQUATION,
    CAPABILITY_SCHEDULER_MODEL,
    CAPABILITY_RECEIPT_SCHEMA,
    CAPABILITY_RECEIPT_TYPE,
    CERTIFIED_CALLBACK_MAX_MS,
    CERTIFIED_SCHEDULER_OVERHEAD_MS,
    POOL_POLL_LAG_TOLERANCE_MS,
    canonical_sha256,
    callback_certification_policy_sha256,
    seal_artifact,
    validate_capability_receipt,
    validate_pool_receipt,
    write_private_artifact,
    zero_token_usage,
)
from cwo_core.native_pool_leases import PoolLeaseRegistry, capture_owner_identity  # noqa: E402
from cwo_core.native_pool_scheduler import select_earliest_deadline  # noqa: E402
from cwo_core.native_pool_workspace import PoolWorkspaceMonitor  # noqa: E402
from cwo_core.native_session import _record_token_snapshot  # noqa: E402
from cwo_core.native_session_boundary import (  # noqa: E402
    LocatedSession,
    NativeSessionBoundaryError,
    capture_boundary,  # noqa: F401
    capture_unique_boundary,
    locate_unique_session,
    session_source_identity,
    telemetry_markers,
    trusted_terminal_event,
    trusted_turn_context,
)
from cwo_core.workspace import status_path  # noqa: E402


EXACT_MODEL = "gpt-5.3-codex-spark"
CONTROL_TURN_ID = "complex-work-orchestration-18w.6-live-canary-control-turn"
POST_SUBMISSION_MATERIALIZATION_GRACE_MS = POOL_POLL_LAG_TOLERANCE_MS
PROVISIONAL_TERMINAL_GRACE_SECONDS = 5.0
THREAD_READ_TIMEOUT_SECONDS = 15.0
CALIBRATION_POLL_INTERVAL_SECONDS = 0.20
CALIBRATION_POLL_GAP_MAX_SECONDS = 0.250
CALIBRATION_READ_RECOVERY_TELEMETRY_TYPE = (
    "cwo-calibration-thread-read-recovery-telemetry:v2"
)
CALIBRATION_READ_RECOVERY_POLICY = (
    "single-application-retry-for-pinned-pre-attestation-startup-scaffold"
)
CALIBRATION_READ_RECOVERY_TELEMETRY_FIELDS = {
    "telemetry_type",
    "version",
    "policy",
    "method",
    "code",
    "replacement_attempt_max",
    "token_consumed",
    "replacement_attempt_count",
    "phase",
    "failed_callback_latency_ms",
    "remaining_deadline_ms_before_scheduling",
    "remaining_deadline_ms_before_attempt",
    "attestation_observed_at_fault",
    "connection_epoch_sha256",
    "prior_source_identity_sha256",
    "prior_boundary_sha256",
    "fault_boundary_record_count",
    "fault_boundary_byte_offset",
    "pre_attempt_source_identity_sha256",
    "pre_attempt_boundary_sha256",
    "pre_attempt_boundary_record_count",
    "pre_attempt_boundary_byte_offset",
    "fault_boundary_classification",
    "pre_dispatch_source_identity_sha256",
    "pre_dispatch_boundary_sha256",
    "pre_dispatch_boundary_record_count",
    "pre_dispatch_boundary_byte_offset",
    "pre_dispatch_boundary_classification",
    "wire_dispatch_count",
    "wire_request_id",
    "wire_request_sha256",
    "wire_response_correlation_sha256",
    "post_read_boundary_sha256",
    "post_read_boundary_record_count",
    "post_read_boundary_byte_offset",
    "workspace_monitoring_status",
    "workspace_baseline_sha256",
    "fault_workspace_sha256",
    "pre_dispatch_workspace_sha256",
    "post_read_workspace_sha256",
    "workspace_mutation_observed",
    "transport_outcome",
    "outcome",
    "telemetry_sha256",
}
STARTUP_SCAFFOLD_RECORD_TYPES = ("session_meta", "event_msg:task_started")
STARTUP_SCAFFOLD_TOP_LEVEL_FIELDS = {"type", "payload"}
STARTUP_SCAFFOLD_SESSION_META_FIELDS = {
    "cwd",
    "id",
    "session_id",
}
STARTUP_SCAFFOLD_TASK_STARTED_FIELDS = {
    "turn_id",
    "type",
}
OPERATIVE_ITEM_TYPES = {
    "commandExecution",
    "fileChange",
    "mcpToolCall",
    "dynamicToolCall",
    "collabAgentToolCall",
    "webSearch",
    "imageView",
    "sleep",
    "imageGeneration",
}
INDEPENDENT_VALIDATION_RECORD_TYPES = {
    "session_meta",
    "event_msg",
    "response_item",
    "world_state",
    "turn_context",
}
INDEPENDENT_VALIDATION_EVENT_TYPES = {
    "task_started",
    "user_message",
    "agent_message",
    "token_count",
    "task_complete",
}
INDEPENDENT_VALIDATION_RESPONSE_TYPES = {"message", "reasoning"}
INDEPENDENT_VALIDATION_MESSAGE_ROLES = {"developer", "user", "assistant"}


class CampaignLaunchInputs:
    """One read-once snapshot set for a live-campaign launch decision."""

    __slots__ = (
        "authorization",
        "manifest",
        "outer_authority",
        "release_patch_bytes",
        "pre_mutation_receipt",
        "pre_mutation_adjudication",
        "pre_live_receipt",
        "pre_live_adjudication",
        "opus_review_evidence",
        "opus_adjudication",
        "spark_validation_receipt",
        "spark_validation_session_path",
        "spark_validation_session_bytes",
        "legacy_predecessor",
        "predecessor_proof",
        "recovery_cause_evidence",
        "recovery_cause_source_analysis_bytes",
        "source_identities",
    )

    def __init__(
        self,
        *,
        authorization: JsonArtifactSnapshot,
        manifest: JsonArtifactSnapshot,
        outer_authority: JsonArtifactSnapshot,
        release_patch_bytes: bytes,
        pre_mutation_receipt: JsonArtifactSnapshot,
        pre_mutation_adjudication: JsonArtifactSnapshot,
        pre_live_receipt: JsonArtifactSnapshot,
        pre_live_adjudication: JsonArtifactSnapshot,
        opus_review_evidence: JsonArtifactSnapshot,
        opus_adjudication: JsonArtifactSnapshot,
        spark_validation_receipt: JsonArtifactSnapshot,
        spark_validation_session_path: Path,
        spark_validation_session_bytes: bytes,
        legacy_predecessor: HistoricalV4V1ProofInputs | None = None,
        predecessor_proof: (
            Version5PredecessorProofInputs
            | Version6PredecessorProofInputs
            | Version7QuarantinePredecessorProofInputs
            | Version8ProtectedFaultPredecessorProofInputs
            | Version9PreallocationFaultPredecessorProofInputs
            | Version10InterruptedEmptyBoundaryPredecessorProofInputs
            | None
        ) = None,
        recovery_cause_evidence: JsonArtifactSnapshot | None = None,
        recovery_cause_source_analysis_bytes: bytes | None = None,
        source_identities: Mapping[str, tuple[int, int, int, int]] | None = None,
    ) -> None:
        self.authorization = authorization
        self.manifest = manifest
        self.outer_authority = outer_authority
        self.release_patch_bytes = release_patch_bytes
        self.pre_mutation_receipt = pre_mutation_receipt
        self.pre_mutation_adjudication = pre_mutation_adjudication
        self.pre_live_receipt = pre_live_receipt
        self.pre_live_adjudication = pre_live_adjudication
        self.opus_review_evidence = opus_review_evidence
        self.opus_adjudication = opus_adjudication
        self.spark_validation_receipt = spark_validation_receipt
        self.spark_validation_session_path = spark_validation_session_path
        self.spark_validation_session_bytes = spark_validation_session_bytes
        self.legacy_predecessor = legacy_predecessor
        self.predecessor_proof = predecessor_proof
        self.recovery_cause_evidence = recovery_cause_evidence
        self.recovery_cause_source_analysis_bytes = (
            recovery_cause_source_analysis_bytes
        )
        self.source_identities = dict(source_identities or {})


class GlobalCampaignReservation:
    """Durable scope reservation held across one live campaign lifecycle."""

    def __init__(
        self,
        *,
        state_path: Path,
        lock_path: Path,
        scope_key: str,
        outer_authority_id: str,
        authorization_id: str,
        campaign_nonce: str,
        launch_claim_sha256: str,
        state_sha256: str,
    ) -> None:
        self.state_path = state_path
        self.lock_path = lock_path
        self.scope_key = scope_key
        self.outer_authority_id = outer_authority_id
        self.authorization_id = authorization_id
        self.campaign_nonce = campaign_nonce
        self.launch_claim_sha256 = launch_claim_sha256
        self.state_sha256 = state_sha256


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso(value: dt.datetime | None = None) -> str:
    return (value or utc_now()).isoformat().replace("+00:00", "Z")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_text(value: str) -> str:
    return sha256_bytes(value.encode("utf-8"))


def _strict_json_object_pairs(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    """Reject duplicate JSON names at every nesting level."""

    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise NativeSessionBoundaryError("session record has duplicate object keys")
        value[key] = item
    return value


def _strict_session_json_record(line: bytes, number: int) -> dict[str, Any]:
    try:
        value = json.loads(
            line.decode("utf-8"),
            object_pairs_hook=_strict_json_object_pairs,
        )
    except NativeSessionBoundaryError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NativeSessionBoundaryError(
            f"session record {number} is invalid: {exc}"
        ) from exc
    if not isinstance(value, dict):
        raise NativeSessionBoundaryError(
            f"session record {number} is not an object"
        )
    return value


def validate_startup_scaffold_records(
    records: list[Mapping[str, Any]],
    *,
    session_id: str,
    turn_id: str,
    expected_cwd: Path,
) -> dict[str, Any]:
    """Validate the only nonempty pre-attestation read-recovery grammar."""

    if len(records) != 2:
        raise NativeSessionBoundaryError(
            "startup scaffold record count is not exact"
        )
    session_record, started_record = records
    if (
        not STARTUP_SCAFFOLD_TOP_LEVEL_FIELDS.issubset(session_record)
        or session_record.get("type") != "session_meta"
        or not isinstance(session_record.get("payload"), Mapping)
    ):
        raise NativeSessionBoundaryError("startup scaffold session_meta invalid")
    session_timestamp = session_record.get("timestamp")
    if session_timestamp is not None and (
        not isinstance(session_timestamp, str) or not session_timestamp
    ):
        raise NativeSessionBoundaryError(
            "startup scaffold session_meta timestamp invalid"
        )
    session_payload = session_record["payload"]
    if not STARTUP_SCAFFOLD_SESSION_META_FIELDS.issubset(session_payload):
        raise NativeSessionBoundaryError(
            "startup scaffold session_meta identity fields missing"
        )
    if (
        session_payload.get("id") != session_id
        or session_payload.get("session_id") != session_id
        or session_payload.get("cwd") != str(expected_cwd.resolve())
    ):
        raise NativeSessionBoundaryError(
            "startup scaffold session_meta semantics invalid"
        )
    if (
        not STARTUP_SCAFFOLD_TOP_LEVEL_FIELDS.issubset(started_record)
        or started_record.get("type") != "event_msg"
        or not isinstance(started_record.get("payload"), Mapping)
    ):
        raise NativeSessionBoundaryError("startup scaffold task_started invalid")
    started_timestamp = started_record.get("timestamp")
    if started_timestamp is not None and (
        not isinstance(started_timestamp, str) or not started_timestamp
    ):
        raise NativeSessionBoundaryError(
            "startup scaffold task_started timestamp invalid"
        )
    started_payload = started_record["payload"]
    if not STARTUP_SCAFFOLD_TASK_STARTED_FIELDS.issubset(started_payload):
        raise NativeSessionBoundaryError(
            "startup scaffold task_started identity fields missing"
        )
    if (
        started_payload.get("type") != "task_started"
        or started_payload.get("turn_id") != turn_id
    ):
        raise NativeSessionBoundaryError(
            "startup scaffold task_started semantics invalid"
        )
    for record in records:
        payload = record.get("payload")
        assert isinstance(payload, Mapping)
        for container in (record, payload):
            for field in ("session_id", "thread_id"):
                identity = container.get(field)
                if identity is not None and identity != session_id:
                    raise NativeSessionBoundaryError(
                        "startup scaffold session identity changed"
                    )
            explicit_turn = container.get("turn_id")
            if explicit_turn is not None and explicit_turn != turn_id:
                raise NativeSessionBoundaryError(
                    "startup scaffold turn identity changed"
                )
            explicit_cwd = container.get("cwd")
            if (
                explicit_cwd is not None
                and explicit_cwd != str(expected_cwd.resolve())
            ):
                raise NativeSessionBoundaryError(
                    "startup scaffold workspace identity changed"
                )
    if _record_token_snapshot(dict(session_record)) is not None or _record_token_snapshot(
        dict(started_record)
    ) is not None:
        raise NativeSessionBoundaryError("startup scaffold token telemetry invalid")
    return {
        "classification": "canonical-session-meta-task-started",
        "record_types": list(STARTUP_SCAFFOLD_RECORD_TYPES),
        "session_id": session_id,
        "turn_id": turn_id,
        "attestation_count": 0,
        "assistant_output_count": 0,
        "tool_activity_count": 0,
        "terminal_event_count": 0,
    }


class PreAttestationSessionBoundaryTracker:
    """Pin one session object while accepting only a provably empty precursor.

    Native app-server may create its JSONL before the first complete record is
    durable.  That exact zero-byte state is non-attesting, but it must not turn
    the pre-attestation recovery edge into a path-based TOCTOU exception.  Keep
    the source open, bind every later lookup to that same object, and remember
    filesystem change metadata so same-inode rewrites or truncations cannot be
    hidden by returning to an earlier length.
    """

    def __init__(self, codex_home: Path, session_id: str) -> None:
        self.codex_home = Path(codex_home)
        self.session_id = session_id
        self._fd: int | None = None
        self._source_identity_sha256: str | None = None
        self._last_stat_signature: tuple[int, int, int] | None = None
        self._last_store: str | None = None

    @staticmethod
    def _stat_signature(current: os.stat_result) -> tuple[int, int, int]:
        return (current.st_size, current.st_mtime_ns, current.st_ctime_ns)

    @staticmethod
    def _require_owner_regular_unaliased(current: os.stat_result) -> None:
        if not stat.S_ISREG(current.st_mode):
            raise NativeSessionBoundaryError(
                "trusted session source is not a regular file"
            )
        if current.st_uid != os.geteuid():
            raise NativeSessionBoundaryError(
                "trusted session source owner does not match controller"
            )
        if current.st_nlink == 0:
            raise NativeSessionBoundaryError(
                "trusted session source is unlinked"
            )
        if current.st_nlink != 1:
            raise NativeSessionBoundaryError(
                "trusted session source has filesystem aliases"
            )

    @staticmethod
    def _require_private(current: os.stat_result) -> None:
        if stat.S_IMODE(current.st_mode) & 0o077:
            raise NativeSessionBoundaryError(
                "trusted session source is not private"
            )

    def _pin_or_verify(self, located: LocatedSession) -> os.stat_result:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(
            os, "O_NOFOLLOW", 0
        )
        if self._fd is None:
            try:
                candidate_fd = os.open(located.path, flags)
            except OSError as exc:
                raise NativeSessionBoundaryError(
                    "trusted session file is unavailable"
                ) from exc
            try:
                handle_stat = os.fstat(candidate_fd)
                path_stat = located.path.stat(follow_symlinks=False)
                self._require_owner_regular_unaliased(handle_stat)
                self._require_owner_regular_unaliased(path_stat)
                if (handle_stat.st_dev, handle_stat.st_ino) != (
                    path_stat.st_dev,
                    path_stat.st_ino,
                ):
                    raise NativeSessionBoundaryError(
                        "trusted session source changed while pinning"
                    )
                self._require_private(handle_stat)
                self._require_private(path_stat)
                identity = session_source_identity(
                    located.path, self.session_id
                )
                if identity != located.source_identity_sha256:
                    raise NativeSessionBoundaryError(
                        "trusted session source identity changed while pinning"
                    )
            except BaseException:
                os.close(candidate_fd)
                raise
            self._fd = candidate_fd
            self._source_identity_sha256 = identity
            return handle_stat

        handle_stat = os.fstat(self._fd)
        try:
            path_stat = located.path.stat(follow_symlinks=False)
        except OSError as exc:
            raise NativeSessionBoundaryError(
                "trusted session file is unavailable"
            ) from exc
        self._require_owner_regular_unaliased(handle_stat)
        self._require_owner_regular_unaliased(path_stat)
        if (handle_stat.st_dev, handle_stat.st_ino) != (
            path_stat.st_dev,
            path_stat.st_ino,
        ):
            raise NativeSessionBoundaryError(
                "trusted session source changed after pinning"
            )
        identity = session_source_identity(located.path, self.session_id)
        if (
            identity != self._source_identity_sha256
            or located.source_identity_sha256 != self._source_identity_sha256
        ):
            raise NativeSessionBoundaryError(
                "trusted session source identity changed after pinning"
            )
        self._require_private(handle_stat)
        self._require_private(path_stat)
        return handle_stat

    def _require_change_history_valid(
        self,
        current: os.stat_result,
        *,
        allow_archive_metadata_change: bool,
    ) -> None:
        previous = self._last_stat_signature
        if previous is None:
            return
        current_signature = self._stat_signature(current)
        if current_signature[0] < previous[0]:
            raise NativeSessionBoundaryError(
                "trusted session source was truncated after observation"
            )
        if (
            current_signature[0] == previous[0]
            and current_signature != previous
            and not allow_archive_metadata_change
        ):
            raise NativeSessionBoundaryError(
                "trusted session source was rewritten after observation"
            )

    def _require_no_ignored_candidate_types(self) -> None:
        """Reject matching filesystem objects the canonical locator skips."""

        for store in ("sessions", "archived_sessions"):
            directory = self.codex_home / store
            if not directory.is_dir():
                continue
            for candidate in directory.rglob(f"*{self.session_id}.jsonl"):
                try:
                    current = candidate.lstat()
                except OSError as exc:
                    raise NativeSessionBoundaryError(
                        "trusted session candidate is unavailable"
                    ) from exc
                if stat.S_ISLNK(current.st_mode):
                    raise NativeSessionBoundaryError(
                        "trusted session file is a symlink"
                    )
                if not stat.S_ISREG(current.st_mode):
                    raise NativeSessionBoundaryError(
                        "trusted session source is not a regular file"
                    )

    def _locate_current(self) -> LocatedSession:
        self._require_no_ignored_candidate_types()
        try:
            return locate_unique_session(self.codex_home, self.session_id)
        except NativeSessionBoundaryError as exc:
            if (
                str(exc) == "trusted session file is missing"
                and self._fd is not None
            ):
                raise NativeSessionBoundaryError(
                    "pinned trusted session source is missing"
                ) from exc
            raise

    def _parse_pinned_boundary(
        self,
        raw: bytes,
        *,
        baseline: Mapping[str, Any],
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        """Parse and hash only bytes read from the pinned descriptor."""

        offset = baseline.get("byte_offset")
        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
            raise NativeSessionBoundaryError("baseline byte offset is invalid")
        if len(raw) < offset:
            raise NativeSessionBoundaryError(
                "session JSONL was truncated below the baseline byte offset"
            )
        if hashlib.sha256(raw[:offset]).hexdigest() != baseline.get(
            "boundary_sha256"
        ):
            raise NativeSessionBoundaryError(
                "session JSONL prefix was rewritten after baseline capture"
            )
        if not raw:
            raise NativeSessionBoundaryError(
                "session file has no complete records"
            )
        if not raw.endswith(b"\n"):
            raise NativeSessionBoundaryError(
                "session file has a trailing partial record"
            )

        records: list[dict[str, Any]] = []
        for number, line in enumerate(raw.splitlines(keepends=True), 1):
            if not line.strip():
                raise NativeSessionBoundaryError(
                    f"session record {number} is blank"
                )
            value = _strict_session_json_record(line, number)
            explicit = value.get("session_id")
            if (
                isinstance(explicit, str)
                and explicit
                and explicit != self.session_id
            ):
                raise NativeSessionBoundaryError(
                    "session identity changed inside JSONL boundary"
                )
            if value.get("type") == "session_meta":
                payload = value.get("payload")
                if isinstance(payload, Mapping):
                    for field in ("id", "session_id"):
                        current = payload.get(field)
                        if (
                            isinstance(current, str)
                            and current
                            and current != self.session_id
                        ):
                            raise NativeSessionBoundaryError(
                                "session_meta identity does not match requested session"
                            )
            records.append(value)
        if not records:
            raise NativeSessionBoundaryError(
                "session file has no complete object records"
            )
        identities = {
            str(payload[field])
            for record in records
            if record.get("type") == "session_meta"
            and isinstance((payload := record.get("payload")), Mapping)
            for field in ("id", "session_id")
            if isinstance(payload.get(field), str) and payload.get(field)
        }
        identities.update(
            str(record["session_id"])
            for record in records
            if isinstance(record.get("session_id"), str)
            and record.get("session_id")
        )
        if identities != {self.session_id}:
            raise NativeSessionBoundaryError(
                "trusted session identity is missing from JSONL boundary"
            )
        token_snapshot: dict[str, int] | None = None
        for record in records:
            snapshot = _record_token_snapshot(record)
            if snapshot is not None:
                token_snapshot = {
                    key: int(value) for key, value in snapshot.items()
                }
        return (
            {
                "record_count": len(records),
                "byte_offset": len(raw),
                "boundary_sha256": hashlib.sha256(raw).hexdigest(),
                "token_snapshot": token_snapshot,
            },
            records,
        )

    def _pread_stable(self, expected: os.stat_result) -> bytes:
        if self._fd is None:
            raise NativeSessionBoundaryError(
                "trusted session source is not pinned"
            )
        raw = bytearray()
        while len(raw) < expected.st_size:
            chunk = os.pread(
                self._fd,
                min(1024 * 1024, expected.st_size - len(raw)),
                len(raw),
            )
            if not chunk:
                raise NativeSessionBoundaryError(
                    "trusted session source changed during descriptor read"
                )
            raw.extend(chunk)
        after = os.fstat(self._fd)
        if self._stat_signature(after) != self._stat_signature(expected):
            raise NativeSessionBoundaryError(
                "trusted session source changed during descriptor read"
            )
        return bytes(raw)

    def capture(
        self,
        *,
        baseline: Mapping[str, Any],
        allow_archive_transition: bool = False,
    ) -> tuple[
        LocatedSession | None,
        dict[str, Any],
        list[dict[str, Any]],
        bool,
    ]:
        """Return a strict boundary, or one pinned exact-empty precursor."""

        empty_boundary = {
            "record_count": 0,
            "byte_offset": 0,
            "boundary_sha256": sha256_bytes(b""),
            "token_snapshot": None,
        }
        try:
            located = self._locate_current()
        except NativeSessionBoundaryError as exc:
            if str(exc) != "trusted session file is missing":
                raise
            self._require_no_ignored_candidate_types()
            return None, empty_boundary, [], False

        archive_transition = (
            allow_archive_transition
            and self._last_store == "sessions"
            and located.store == "archived_sessions"
        )
        if self._last_store is not None and (
            located.store != self._last_store and not archive_transition
        ):
            raise NativeSessionBoundaryError(
                "trusted session store changed outside authorized archive transition"
            )
        before = self._pin_or_verify(located)
        self._require_change_history_valid(
            before,
            allow_archive_metadata_change=archive_transition,
        )
        raw = self._pread_stable(before)
        try:
            boundary, records = self._parse_pinned_boundary(
                raw,
                baseline=baseline,
            )
        except NativeSessionBoundaryError as exc:
            if str(exc) != "session file has no complete records":
                raise
            if self._fd is None:
                raise NativeSessionBoundaryError(
                    "trusted empty session source is not pinned"
                ) from exc
            boundary = empty_boundary
            records = []

        refreshed = self._locate_current()
        if refreshed.store != located.store:
            raise NativeSessionBoundaryError(
                "trusted session store changed during descriptor capture"
            )
        after = self._pin_or_verify(refreshed)
        if self._stat_signature(after) != self._stat_signature(before):
            raise NativeSessionBoundaryError(
                "trusted session source changed during descriptor capture"
            )
        # Parsing is deliberately inside the identity bracket: an ancestor or
        # leaf substitution during JSON decoding must be observed before the
        # boundary can become accepting.
        final_location = self._locate_current()
        if final_location.store != refreshed.store:
            raise NativeSessionBoundaryError(
                "trusted session store changed during descriptor capture"
            )
        final_stat = self._pin_or_verify(final_location)
        if self._stat_signature(final_stat) != self._stat_signature(before):
            raise NativeSessionBoundaryError(
                "trusted session source changed during descriptor capture"
            )
        self._last_stat_signature = self._stat_signature(final_stat)
        self._last_store = final_location.store
        return final_location, boundary, records, bool(records)

    def close(self) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None

    def __del__(self) -> None:
        try:
            self.close()
        except OSError:
            pass


def run_git(cwd: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def porcelain_mutation_paths(output: str) -> list[str]:
    """Parse porcelain-v1 records without destroying the status columns."""

    if output and not output.endswith("\n"):
        raise AppServerError("workspace-status-trailing-partial")
    values: list[str] = []
    for line in output.splitlines():
        if not line.strip():
            continue
        if len(line) < 4 or line[2] != " ":
            raise AppServerError("workspace-status-record-invalid")
        path = status_path(line)
        if not path:
            raise AppServerError("workspace-status-path-empty")
        values.append(path)
    return sorted(set(values))


def require_repository_checkpoint(repo_root: Path, expected_head: str) -> None:
    if run_git(repo_root, "rev-parse", "HEAD") != expected_head:
        raise AppServerError("full-auto-repository-head-changed")
    if run_git(repo_root, "status", "--porcelain=v1", "--untracked-files=no"):
        raise AppServerError("full-auto-repository-not-clean")


def percentile(values: list[float], ratio: float) -> float:
    ordered = sorted(values)
    if not ordered:
        raise ValueError("capability-stat-samples-missing")
    index = max(0, min(len(ordered) - 1, math.ceil(len(ordered) * ratio) - 1))
    return ordered[index]


def stats(values: list[float]) -> dict[str, float]:
    return {
        "p50_ms": round(percentile(values, 0.50), 3),
        "p90_ms": round(percentile(values, 0.90), 3),
        "p99_ms": round(percentile(values, 0.99), 3),
        "max_ms": round(max(values), 3),
    }


def callback_certification_policy() -> dict[str, Any]:
    try:
        document = json.loads(
            (ROOT / "policy" / "native-worker-execution.yaml").read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise AppServerError("callback-certification-policy-unreadable") from exc
    pool = document.get("native_supervision_pool") if isinstance(document, Mapping) else None
    certification = pool.get("callback_certification") if isinstance(pool, Mapping) else None
    expected = {
        "version": CAPABILITY_CERTIFICATION_VERSION,
        "envelope": CAPABILITY_CERTIFICATION_ENVELOPE,
        "scheduler_model": CAPABILITY_SCHEDULER_MODEL,
        "response_time_equation": CAPABILITY_RESPONSE_TIME_EQUATION,
        "observation_authority": CAPABILITY_OBSERVATION_AUTHORITY,
        "certified_callback_max_ms": CERTIFIED_CALLBACK_MAX_MS,
        "certified_scheduler_overhead_ms": CERTIFIED_SCHEDULER_OVERHEAD_MS,
    }
    if not isinstance(certification, Mapping) or dict(certification) != expected:
        raise AppServerError("callback-certification-policy-invalid")
    return dict(certification)


def capability_certification() -> dict[str, Any]:
    policy = callback_certification_policy()
    return {
        **policy,
        "policy_sha256": callback_certification_policy_sha256(policy),
        "adapter_implementation_sha256": sha256_bytes(Path(__file__).read_bytes()),
    }


def validate_full_auto_authorization(
    authorization: Mapping[str, Any],
    campaign_nonce: str,
    *,
    predecessor_authorization: Mapping[str, Any] | None = None,
    predecessor_authorization_raw_sha256: str | None = None,
    predecessor_manifest: Mapping[str, Any] | None = None,
    predecessor_manifest_raw_sha256: str | None = None,
    predecessor_authorization_state: Mapping[str, Any] | None = None,
    predecessor_authorization_state_raw_sha256: str | None = None,
    predecessor_failure_evidence: Mapping[str, Any] | None = None,
    predecessor_failure_evidence_raw_sha256: str | None = None,
    predecessor_original_containment: Mapping[str, Any] | None = None,
    predecessor_original_containment_raw_sha256: str | None = None,
    predecessor_containment: Mapping[str, Any] | None = None,
    predecessor_containment_raw_sha256: str | None = None,
    predecessor_allocation_ledger: Mapping[str, Any] | None = None,
    predecessor_allocation_ledger_raw_sha256: str | None = None,
    predecessor_allocation_audit_path: Path | None = None,
    predecessor_allocation_audit_raw_sha256: str | None = None,
    predecessor_allocation_audit_bytes: bytes | None = None,
    cause_evidence: bytes | None = None,
    predecessor_proof: (
        Version5PredecessorProofInputs
        | Version6PredecessorProofInputs
        | Version7QuarantinePredecessorProofInputs
        | Version8ProtectedFaultPredecessorProofInputs
        | Version9PreallocationFaultPredecessorProofInputs
        | Version10InterruptedEmptyBoundaryPredecessorProofInputs
        | None
    ) = None,
    recovery_cause_evidence: JsonArtifactSnapshot | None = None,
    recovery_cause_source_analysis: bytes | None = None,
    expected_validator_contract_sha256: str | None = None,
    repo_root: Path,
) -> tuple[str, str]:
    if authorization.get("version") in {6, 7, 8, 9, 10, 11}:
        errors = validate_full_auto_authorization_contract(
            authorization,
            expected_campaign_nonce=campaign_nonce,
            predecessor_proof=predecessor_proof,
            recovery_cause_evidence=recovery_cause_evidence,
            recovery_cause_source_analysis=recovery_cause_source_analysis,
            expected_validator_contract_sha256=expected_validator_contract_sha256,
            repo_root=repo_root,
        )
    else:
        errors = validate_full_auto_authorization_contract(
            authorization,
            expected_campaign_nonce=campaign_nonce,
            predecessor_authorization=predecessor_authorization,
            predecessor_authorization_raw_sha256=predecessor_authorization_raw_sha256,
            predecessor_manifest=predecessor_manifest,
            predecessor_manifest_raw_sha256=predecessor_manifest_raw_sha256,
            predecessor_authorization_state=predecessor_authorization_state,
            predecessor_authorization_state_raw_sha256=predecessor_authorization_state_raw_sha256,
            predecessor_failure_evidence=predecessor_failure_evidence,
            predecessor_failure_evidence_raw_sha256=predecessor_failure_evidence_raw_sha256,
            predecessor_original_containment=predecessor_original_containment,
            predecessor_original_containment_raw_sha256=predecessor_original_containment_raw_sha256,
            predecessor_containment=predecessor_containment,
            predecessor_containment_raw_sha256=predecessor_containment_raw_sha256,
            predecessor_allocation_ledger=predecessor_allocation_ledger,
            predecessor_allocation_ledger_raw_sha256=predecessor_allocation_ledger_raw_sha256,
            predecessor_allocation_audit_path=predecessor_allocation_audit_path,
            predecessor_allocation_audit_raw_sha256=predecessor_allocation_audit_raw_sha256,
            predecessor_allocation_audit_bytes=predecessor_allocation_audit_bytes,
            cause_evidence=cause_evidence,
            repo_root=repo_root,
        )
    if errors:
        raise AppServerError("full-auto-authorization-invalid:" + ";".join(errors))
    return str(authorization["authorization_id"]), run_git(repo_root, "rev-parse", "HEAD")


def validate_steering_launch_bindings(
    authorization_id: str,
    authorization_sha256: str,
    *,
    pre_mutation_receipt: Mapping[str, Any],
    pre_mutation_adjudication: Mapping[str, Any],
    pre_mutation_adjudication_sha256: str,
    pre_live_receipt: Mapping[str, Any],
    pre_live_adjudication: Mapping[str, Any],
    pre_live_adjudication_sha256: str,
) -> None:
    """Purely bind both steering bundles to the current inner authority."""

    if not _valid_uuid_text(authorization_id) or not re.fullmatch(
        r"[0-9a-f]{64}", authorization_sha256
    ):
        raise AppServerError("steering-authorization-identity-invalid")
    bundles = (
        (
            "pre-mutation",
            pre_mutation_receipt,
            pre_mutation_adjudication,
            pre_mutation_adjudication_sha256,
        ),
        (
            "pre-live",
            pre_live_receipt,
            pre_live_adjudication,
            pre_live_adjudication_sha256,
        ),
    )
    for label, receipt, adjudication, adjudication_sha256 in bundles:
        if (
            receipt.get("gate") != label
            or receipt.get("authorization_id") != authorization_id
            or receipt.get("authorization_sha256") != authorization_sha256
            or not re.fullmatch(r"[0-9a-f]{64}", adjudication_sha256)
        ):
            raise AppServerError(f"{label}-steering-binding-invalid")
        if adjudication.get("main_architect_decision") != "go":
            raise AppServerError(f"{label}-adjudication-decision-invalid")


def quarantined_predecessor_ledger_prefix_bindings(
    authorization: Mapping[str, Any],
    failed_predecessor: Version8ProtectedFaultPredecessorProofInputs | None,
) -> dict[str, Any]:
    """Use the v8 failed authority that originally bound the ledger prefix."""

    binding_authorization = (
        failed_predecessor.authorization.value
        if failed_predecessor is not None
        else authorization
    )
    source = (
        binding_authorization.get("bindings")
        if isinstance(binding_authorization.get("bindings"), Mapping)
        else {}
    )
    return {
        f"quarantined_predecessor_{field}": source.get(f"predecessor_{field}")
        for field in (
            "failure_ledger_prefix_file_sha256",
            "failure_ledger_prefix_state_sha256",
            "failure_ledger_prefix_head_entry_sha256",
        )
    }


def plan_steering_receipt_consumptions(
    campaign_nonce: str,
    authorization_id: str,
    authorization_sha256: str,
    *,
    registry_file: Path,
    repo_head: str,
    pre_mutation_receipt: Mapping[str, Any],
    pre_mutation_adjudication: Mapping[str, Any],
    pre_mutation_adjudication_sha256: str,
    pre_live_receipt: Mapping[str, Any],
    pre_live_adjudication: Mapping[str, Any],
    pre_live_adjudication_sha256: str,
) -> dict[str, tuple[str, dict[str, Any]]]:
    if not _valid_uuid_text(campaign_nonce):
        raise AppServerError("steering-control-identity-invalid")
    validate_steering_launch_bindings(
        authorization_id,
        authorization_sha256,
        pre_mutation_receipt=pre_mutation_receipt,
        pre_mutation_adjudication=pre_mutation_adjudication,
        pre_mutation_adjudication_sha256=pre_mutation_adjudication_sha256,
        pre_live_receipt=pre_live_receipt,
        pre_live_adjudication=pre_live_adjudication,
        pre_live_adjudication_sha256=pre_live_adjudication_sha256,
    )
    bundles = (
        (
            "pre-mutation",
            pre_mutation_receipt,
            pre_mutation_adjudication,
            pre_mutation_adjudication_sha256,
        ),
        (
            "pre-live",
            pre_live_receipt,
            pre_live_adjudication,
            pre_live_adjudication_sha256,
        ),
    )

    steering_prepared: dict[str, tuple[str, dict[str, Any]]] = {}
    for label, receipt, adjudication, adjudication_sha256 in bundles:
        phase_nonce = str(
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                f"{campaign_nonce}:{label}:{receipt.get('canonical_receipt_sha256')}",
            )
        )
        kwargs: dict[str, Any] = {
            "phase_nonce": phase_nonce,
            "architect_adjudication_sha256": adjudication_sha256,
            "architect_decision": "go",
        }
        if label == "pre-mutation" and receipt.get("opinion", {}).get("recommendation") == "stop":
            kwargs.update(
                {
                    "allow_resolved_stop": True,
                    "resolved_stop_adjudication": adjudication.get("resolved_stop"),
                    "resolved_stop_post_resolution_commit": repo_head,
                }
            )
        try:
            consume_steering_receipt(
                receipt,
                registry_file,
                dry_run=True,
                **kwargs,
            )
        except NativeCanaryContractError as exc:
            raise AppServerError(f"{label}-steering-not-accepting") from exc
        steering_prepared[label] = (receipt["canonical_receipt_sha256"], kwargs)
    return steering_prepared


class AppServerError(RuntimeError):
    pass


class AppServerRpcError(AppServerError):
    """One request-correlated JSON-RPC error with trusted local method context."""

    def __init__(
        self,
        *,
        method: str,
        code: int,
        request_id: int,
        latency_ms: float,
    ) -> None:
        if not isinstance(method, str) or not method:
            raise ValueError("app-server-rpc-error-method-invalid")
        if type(code) is not int:
            raise ValueError("app-server-rpc-error-code-invalid")
        if type(request_id) is not int or request_id < 0:
            raise ValueError("app-server-rpc-error-request-id-invalid")
        if (
            isinstance(latency_ms, bool)
            or not isinstance(latency_ms, (int, float))
            or not math.isfinite(float(latency_ms))
            or float(latency_ms) < 0
        ):
            raise ValueError("app-server-rpc-error-latency-invalid")
        self.method = method
        self.code = code
        self.request_id = request_id
        self.latency_ms = float(latency_ms)
        super().__init__(f"app-server-request-failed:{method}:{code}")


def validate_calibration_read_recovery_telemetry(
    value: Mapping[str, Any],
) -> list[str]:
    """Validate the closed, privacy-safe calibration read-recovery record."""

    errors: list[str] = []
    if not isinstance(value, Mapping):
        return ["read-recovery-telemetry-not-object"]
    telemetry = dict(value)
    if set(telemetry) != CALIBRATION_READ_RECOVERY_TELEMETRY_FIELDS:
        errors.append("read-recovery-telemetry-fields-invalid")
    if telemetry.get("telemetry_type") != CALIBRATION_READ_RECOVERY_TELEMETRY_TYPE:
        errors.append("read-recovery-telemetry-type-invalid")
    if type(telemetry.get("version")) is not int or telemetry.get("version") != 2:
        errors.append("read-recovery-telemetry-version-invalid")
    if telemetry.get("policy") != CALIBRATION_READ_RECOVERY_POLICY:
        errors.append("read-recovery-telemetry-policy-invalid")
    if (
        type(telemetry.get("replacement_attempt_max")) is not int
        or telemetry.get("replacement_attempt_max") != 1
    ):
        errors.append("read-recovery-replacement-max-invalid")
    if not isinstance(telemetry.get("token_consumed"), bool):
        errors.append("read-recovery-token-consumed-invalid")
    attempt_count = telemetry.get("replacement_attempt_count")
    if (
        type(attempt_count) is not int
        or attempt_count not in {0, 1}
    ):
        errors.append("read-recovery-attempt-count-invalid")
    for field in (
        "failed_callback_latency_ms",
        "remaining_deadline_ms_before_scheduling",
        "remaining_deadline_ms_before_attempt",
    ):
        current = telemetry.get(field)
        if current is not None and (
            isinstance(current, bool)
            or not isinstance(current, (int, float))
            or not math.isfinite(float(current))
            or float(current) < 0
        ):
            errors.append(f"read-recovery-{field.replace('_', '-')}-invalid")
    for field in ("connection_epoch_sha256", "prior_boundary_sha256"):
        current = telemetry.get(field)
        if not isinstance(current, str) or re.fullmatch(r"[0-9a-f]{64}", current) is None:
            errors.append(f"read-recovery-{field.replace('_', '-')}-invalid")
    for field in (
        "prior_source_identity_sha256",
        "pre_attempt_source_identity_sha256",
        "pre_dispatch_source_identity_sha256",
    ):
        current = telemetry.get(field)
        if current is not None and (
            not isinstance(current, str)
            or re.fullmatch(r"[0-9a-f]{64}", current) is None
        ):
            errors.append(f"read-recovery-{field.replace('_', '-')}-invalid")
    for field in (
        "pre_attempt_boundary_sha256",
        "pre_dispatch_boundary_sha256",
        "wire_request_sha256",
        "wire_response_correlation_sha256",
        "post_read_boundary_sha256",
        "workspace_baseline_sha256",
        "fault_workspace_sha256",
        "pre_dispatch_workspace_sha256",
        "post_read_workspace_sha256",
    ):
        current = telemetry.get(field)
        if current is not None and (
            not isinstance(current, str)
            or re.fullmatch(r"[0-9a-f]{64}", current) is None
        ):
            errors.append(f"read-recovery-{field.replace('_', '-')}-invalid")
    for field in (
        "fault_boundary_record_count",
        "fault_boundary_byte_offset",
        "pre_attempt_boundary_record_count",
        "pre_attempt_boundary_byte_offset",
        "pre_dispatch_boundary_record_count",
        "pre_dispatch_boundary_byte_offset",
        "post_read_boundary_record_count",
        "post_read_boundary_byte_offset",
    ):
        current = telemetry.get(field)
        if current is not None and (
            type(current) is not int or current < 0
        ):
            errors.append(f"read-recovery-{field.replace('_', '-')}-invalid")
    outcome = telemetry.get("outcome")
    if outcome not in {"not-needed", "recovered"}:
        errors.append("read-recovery-outcome-invalid")
    if telemetry.get("fault_boundary_classification") not in {
        None,
        "exact-empty-pinned-source",
        "canonical-session-meta-task-started",
    }:
        errors.append("read-recovery-fault-classification-invalid")
    if telemetry.get("pre_dispatch_boundary_classification") not in {
        None,
        "exact-empty-pinned-source",
        "canonical-session-meta-task-started",
    }:
        errors.append("read-recovery-predispatch-classification-invalid")
    wire_dispatch_count = telemetry.get("wire_dispatch_count")
    if type(wire_dispatch_count) is not int or wire_dispatch_count not in {0, 1}:
        errors.append("read-recovery-wire-dispatch-count-invalid")
    wire_request_id = telemetry.get("wire_request_id")
    if wire_request_id is not None and (
        type(wire_request_id) is not int or wire_request_id < 1
    ):
        errors.append("read-recovery-wire-request-id-invalid")
    if telemetry.get("transport_outcome") not in {
        "not-needed",
        "dispatch-attempted",
        "response-correlated",
    }:
        errors.append("read-recovery-transport-outcome-invalid")
    workspace_status = telemetry.get("workspace_monitoring_status")
    if workspace_status not in {"available", "unavailable-not-git"}:
        errors.append("read-recovery-workspace-monitoring-status-invalid")
    if not isinstance(telemetry.get("workspace_mutation_observed"), bool):
        errors.append("read-recovery-workspace-mutation-state-invalid")
    if workspace_status == "available":
        if telemetry.get("workspace_baseline_sha256") is None:
            errors.append("read-recovery-workspace-baseline-missing")
    elif telemetry.get("workspace_baseline_sha256") is not None:
        errors.append("read-recovery-workspace-baseline-unexpected")
    if outcome == "not-needed":
        if any(
            telemetry.get(field) is not None
            for field in (
                "method",
                "code",
                "phase",
                "failed_callback_latency_ms",
                "remaining_deadline_ms_before_scheduling",
                "remaining_deadline_ms_before_attempt",
                "attestation_observed_at_fault",
                "prior_source_identity_sha256",
                "fault_boundary_record_count",
                "fault_boundary_byte_offset",
                "pre_attempt_source_identity_sha256",
                "pre_attempt_boundary_sha256",
                "pre_attempt_boundary_record_count",
                "pre_attempt_boundary_byte_offset",
                "fault_boundary_classification",
                "pre_dispatch_source_identity_sha256",
                "pre_dispatch_boundary_sha256",
                "pre_dispatch_boundary_record_count",
                "pre_dispatch_boundary_byte_offset",
                "pre_dispatch_boundary_classification",
                "wire_request_id",
                "wire_request_sha256",
                "wire_response_correlation_sha256",
                "post_read_boundary_sha256",
                "post_read_boundary_record_count",
                "post_read_boundary_byte_offset",
                "fault_workspace_sha256",
                "pre_dispatch_workspace_sha256",
                "post_read_workspace_sha256",
            )
        ):
            errors.append("read-recovery-unused-fields-invalid")
        if (
            telemetry.get("token_consumed") is not False
            or attempt_count != 0
            or wire_dispatch_count != 0
            or telemetry.get("transport_outcome") != "not-needed"
            or telemetry.get("workspace_mutation_observed") is not False
        ):
            errors.append("read-recovery-unused-budget-invalid")
    elif outcome == "recovered":
        if telemetry.get("method") != "thread/read":
            errors.append("read-recovery-method-invalid")
        code = telemetry.get("code")
        if type(code) is not int or code != -32603:
            errors.append("read-recovery-code-invalid")
        if telemetry.get("phase") != "materialization":
            errors.append("read-recovery-phase-invalid")
        if telemetry.get("attestation_observed_at_fault") is not False:
            errors.append("read-recovery-attestation-state-invalid")
        if telemetry.get("token_consumed") is not True or attempt_count != 1:
            errors.append("read-recovery-consumption-invalid")
        if telemetry.get("workspace_mutation_observed") is not False:
            errors.append("read-recovery-workspace-mutation-observed")
        workspace_hashes = [
            telemetry.get("fault_workspace_sha256"),
            telemetry.get("pre_dispatch_workspace_sha256"),
            telemetry.get("post_read_workspace_sha256"),
        ]
        if workspace_status == "available":
            if any(
                current != telemetry.get("workspace_baseline_sha256")
                for current in workspace_hashes
            ):
                errors.append("read-recovery-workspace-boundary-changed")
        elif any(current is not None for current in workspace_hashes):
            errors.append("read-recovery-workspace-boundary-unexpected")
        if any(
            telemetry.get(field) is None
            for field in (
                "failed_callback_latency_ms",
                "remaining_deadline_ms_before_scheduling",
                "remaining_deadline_ms_before_attempt",
                "fault_boundary_record_count",
                "fault_boundary_byte_offset",
                "pre_attempt_boundary_sha256",
                "pre_attempt_boundary_record_count",
                "pre_attempt_boundary_byte_offset",
                "fault_boundary_classification",
                "pre_dispatch_source_identity_sha256",
                "pre_dispatch_boundary_sha256",
                "pre_dispatch_boundary_record_count",
                "pre_dispatch_boundary_byte_offset",
                "pre_dispatch_boundary_classification",
                "wire_request_id",
                "wire_request_sha256",
                "wire_response_correlation_sha256",
                "post_read_boundary_sha256",
                "post_read_boundary_record_count",
                "post_read_boundary_byte_offset",
            )
        ):
            errors.append("read-recovery-timing-missing")
        prior_source = telemetry.get("prior_source_identity_sha256")
        record_count = telemetry.get("fault_boundary_record_count")
        byte_offset = telemetry.get("fault_boundary_byte_offset")
        fault_classification = telemetry.get("fault_boundary_classification")
        if record_count == 0:
            if (
                byte_offset != 0
                or prior_source is None
                or telemetry.get("prior_boundary_sha256") != sha256_bytes(b"")
                or fault_classification != "exact-empty-pinned-source"
            ):
                errors.append("read-recovery-empty-fault-boundary-invalid")
        elif (
            type(record_count) is int
            and (
                record_count != 2
                or type(byte_offset) is not int
                or byte_offset <= 0
                or prior_source is None
                or fault_classification
                != "canonical-session-meta-task-started"
            )
        ):
            errors.append("read-recovery-materialized-fault-boundary-invalid")
        pre_attempt_source = telemetry.get("pre_attempt_source_identity_sha256")
        pre_attempt_count = telemetry.get("pre_attempt_boundary_record_count")
        pre_attempt_offset = telemetry.get("pre_attempt_boundary_byte_offset")
        if pre_attempt_count == 0:
            if (
                pre_attempt_offset != 0
                or pre_attempt_source is None
                or telemetry.get("pre_attempt_boundary_sha256")
                != sha256_bytes(b"")
            ):
                errors.append("read-recovery-empty-pre-attempt-boundary-invalid")
        elif (
            type(pre_attempt_count) is int
            and pre_attempt_count > 0
            and (
                type(pre_attempt_offset) is not int
                or pre_attempt_offset <= 0
                or pre_attempt_source is None
            )
        ):
            errors.append(
                "read-recovery-materialized-pre-attempt-boundary-invalid"
            )
        if (
            pre_attempt_count != record_count
            or pre_attempt_offset != byte_offset
            or telemetry.get("pre_attempt_boundary_sha256")
            != telemetry.get("prior_boundary_sha256")
        ):
            errors.append("read-recovery-pre-attempt-boundary-changed")
        if prior_source is not None and pre_attempt_source != prior_source:
            errors.append("read-recovery-pre-attempt-source-changed")
        if (
            telemetry.get("pre_dispatch_source_identity_sha256") != prior_source
            or telemetry.get("pre_dispatch_boundary_sha256")
            != telemetry.get("prior_boundary_sha256")
            or telemetry.get("pre_dispatch_boundary_record_count")
            != record_count
            or telemetry.get("pre_dispatch_boundary_byte_offset") != byte_offset
            or telemetry.get("pre_dispatch_boundary_classification")
            != fault_classification
        ):
            errors.append("read-recovery-predispatch-boundary-changed")
        if (
            wire_dispatch_count != 1
            or wire_request_id is None
            or telemetry.get("wire_request_sha256") is None
            or telemetry.get("wire_response_correlation_sha256") is None
            or telemetry.get("transport_outcome") != "response-correlated"
        ):
            errors.append("read-recovery-wire-proof-invalid")
        post_count = telemetry.get("post_read_boundary_record_count")
        post_offset = telemetry.get("post_read_boundary_byte_offset")
        if (
            type(post_count) is not int
            or type(post_offset) is not int
            or type(record_count) is not int
            or type(byte_offset) is not int
            or post_count < record_count
            or post_offset < byte_offset
            or telemetry.get("post_read_boundary_sha256") is None
        ):
            errors.append("read-recovery-post-read-boundary-invalid")
    expected_sha256 = canonical_sha256(
        {key: item for key, item in telemetry.items() if key != "telemetry_sha256"}
    )
    if telemetry.get("telemetry_sha256") != expected_sha256:
        errors.append("read-recovery-telemetry-sha256-invalid")
    return errors


def seal_calibration_read_recovery_telemetry(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    sealed = seal_artifact(value, "telemetry_sha256")
    errors = validate_calibration_read_recovery_telemetry(sealed)
    if errors:
        raise AppServerError("capability-read-recovery-telemetry-invalid:" + ";".join(errors))
    return sealed


class LivePoolProtectedFault(AppServerError):
    def __init__(self, first_protected_fault: Mapping[str, Any] | None) -> None:
        self.first_protected_fault = (
            dict(first_protected_fault)
            if isinstance(first_protected_fault, Mapping)
            else {
                "code": "unknown",
                "operation": None,
                "observed_callback_latency_ms": None,
                "certified_callback_max_ms": None,
                "latched_state_sequence": 0,
            }
        )
        super().__init__(f"live-pool-protected-fault:{self.first_protected_fault['code']}")


class AppServer:
    """Minimal stdlib JSON-RPC client for one trusted Codex app-server."""

    def __init__(self) -> None:
        self.process = subprocess.Popen(
            ["codex", "app-server", "--stdio"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            umask=0o077,
        )
        if self.process.stdin is None or self.process.stdout is None or self.process.stderr is None:
            raise AppServerError("app-server-pipes-unavailable")
        self._condition = threading.Condition()
        self._responses: dict[int, dict[str, Any]] = {}
        self._notifications: list[tuple[int, dict[str, Any]]] = []
        self._request_id = 0
        self._reader_error: str | None = None
        self._stderr_line_count = 0
        self.connection_epoch_sha256 = domain_sha256(
            {"epoch": str(uuid.uuid4())}, domain="app-server-stdio-connection-epoch"
        )
        self.rpc_latencies: dict[str, list[float]] = {}
        self.started_threads: dict[str, str | None] = {}
        self.allocation_ledger: NativeLiveAllocationLedgerStore | None = None
        threading.Thread(target=self._read_stdout, daemon=True).start()
        threading.Thread(target=self._drain_stderr, daemon=True).start()
        result, _ = self.request(
            "initialize",
            {
                "clientInfo": {
                    "name": "cwo-supervisor-concurrency-canary",
                    "title": "CWO supervisor concurrency canary",
                    "version": "1.0.0",
                },
                "capabilities": {"experimentalApi": True},
            },
            timeout=10,
        )
        if not isinstance(result, Mapping) or not result.get("codexHome"):
            raise AppServerError("app-server-initialize-invalid")
        self.codex_home = Path(str(result["codexHome"])).resolve()
        self.notify("initialized", {})

    def attach_allocation_ledger(self, ledger: NativeLiveAllocationLedgerStore) -> None:
        if self.started_threads or self.allocation_ledger is not None:
            raise AppServerError("allocation-ledger-attach-state-invalid")
        ledger.load()
        self.allocation_ledger = ledger

    def _read_stdout(self) -> None:
        assert self.process.stdout is not None
        try:
            for raw in self.process.stdout:
                try:
                    message = json.loads(raw)
                except json.JSONDecodeError:
                    with self._condition:
                        self._reader_error = "app-server-non-json-output"
                        self._condition.notify_all()
                    continue
                with self._condition:
                    if type(message.get("id")) is int and (
                        "result" in message or "error" in message
                    ):
                        self._responses[int(message["id"])] = message
                    elif isinstance(message.get("method"), str):
                        self._notifications.append((time.monotonic_ns(), message))
                    self._condition.notify_all()
        finally:
            with self._condition:
                if self.process.poll() is None:
                    self._reader_error = "app-server-output-closed"
                self._condition.notify_all()

    def _drain_stderr(self) -> None:
        assert self.process.stderr is not None
        for _line in self.process.stderr:
            self._stderr_line_count += 1

    def notify(self, method: str, params: Mapping[str, Any]) -> None:
        payload = {"method": method, "params": dict(params)}
        assert self.process.stdin is not None
        with self._condition:
            self.process.stdin.write(json.dumps(payload, separators=(",", ":")) + "\n")
            self.process.stdin.flush()

    def request(
        self,
        method: str,
        params: Mapping[str, Any],
        *,
        timeout: float = 30,
    ) -> tuple[dict[str, Any], float]:
        assert self.process.stdin is not None
        with self._condition:
            self._request_id += 1
            request_id = self._request_id
            payload = {"id": request_id, "method": method, "params": dict(params)}
            started = time.monotonic_ns()
            self.process.stdin.write(json.dumps(payload, separators=(",", ":")) + "\n")
            self.process.stdin.flush()
            deadline = time.monotonic() + timeout
            while request_id not in self._responses:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise AppServerError(f"app-server-request-timeout:{method}")
                if self.process.poll() is not None:
                    raise AppServerError(f"app-server-exited:{method}:{self.process.returncode}")
                if self._reader_error:
                    raise AppServerError(self._reader_error)
                self._condition.wait(timeout=remaining)
            message = self._responses.pop(request_id)
        latency_ms = (time.monotonic_ns() - started) / 1_000_000
        self.rpc_latencies.setdefault(method, []).append(latency_ms)
        if type(message.get("id")) is not int or message.get("id") != request_id:
            raise AppServerError(f"app-server-response-id-invalid:{method}")
        if "error" in message:
            if "result" in message or not isinstance(message.get("error"), Mapping):
                raise AppServerError(f"app-server-error-response-invalid:{method}")
            error = message["error"]
            code = error.get("code")
            if (
                type(code) is not int
                or not isinstance(error.get("message"), str)
            ):
                raise AppServerError(f"app-server-error-response-invalid:{method}")
            raise AppServerRpcError(
                method=method,
                code=code,
                request_id=request_id,
                latency_ms=latency_ms,
            )
        result = message.get("result")
        if not isinstance(result, dict):
            raise AppServerError(f"app-server-result-invalid:{method}")
        return result, latency_ms

    def request_once_with_guard(
        self,
        method: str,
        params: Mapping[str, Any],
        *,
        timeout: float,
        pre_dispatch_guard: Callable[[], Mapping[str, Any]],
    ) -> tuple[dict[str, Any], float, dict[str, Any], int, str]:
        """Issue one non-replayable wire request after an in-lock guard."""

        assert self.process.stdin is not None
        with self._condition:
            if self.process.poll() is not None:
                raise AppServerError(
                    f"app-server-exited-before-guarded-request:{method}:"
                    f"{self.process.returncode}"
                )
            if self._reader_error:
                raise AppServerError(self._reader_error)
            guarded = dict(pre_dispatch_guard())
            self._request_id += 1
            request_id = self._request_id
            payload = {"id": request_id, "method": method, "params": dict(params)}
            payload_sha256 = domain_sha256(
                payload, domain="app-server-single-wire-request"
            )
            started = time.monotonic_ns()
            # There is deliberately one write and one flush.  This client has
            # no reconnect, redirect, timeout retry, or implicit replay path.
            try:
                self.process.stdin.write(
                    json.dumps(payload, separators=(",", ":")) + "\n"
                )
                self.process.stdin.flush()
            except OSError as exc:
                raise AppServerError(
                    f"app-server-guarded-request-dispatch-ambiguous:{method}"
                ) from exc
            deadline = time.monotonic() + timeout
            while request_id not in self._responses:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise AppServerError(
                        f"app-server-guarded-request-response-ambiguous:{method}"
                    )
                if self.process.poll() is not None:
                    raise AppServerError(
                        f"app-server-guarded-request-response-ambiguous:{method}"
                    )
                if self._reader_error:
                    raise AppServerError(self._reader_error)
                self._condition.wait(timeout=remaining)
            message = self._responses.pop(request_id)
        latency_ms = (time.monotonic_ns() - started) / 1_000_000
        self.rpc_latencies.setdefault(method, []).append(latency_ms)
        if type(message.get("id")) is not int or message.get("id") != request_id:
            raise AppServerError(f"app-server-response-id-invalid:{method}")
        if "error" in message:
            if "result" in message or not isinstance(message.get("error"), Mapping):
                raise AppServerError(f"app-server-error-response-invalid:{method}")
            error = message["error"]
            code = error.get("code")
            if type(code) is not int or not isinstance(error.get("message"), str):
                raise AppServerError(f"app-server-error-response-invalid:{method}")
            raise AppServerRpcError(
                method=method,
                code=code,
                request_id=request_id,
                latency_ms=latency_ms,
            )
        result = message.get("result")
        if not isinstance(result, dict):
            raise AppServerError(f"app-server-result-invalid:{method}")
        return result, latency_ms, guarded, request_id, payload_sha256

    def model_discovery(self) -> dict[str, Any]:
        result, latency = self.request("model/list", {"includeHidden": True})
        models = result.get("data")
        if not isinstance(models, list):
            raise AppServerError("model-list-data-invalid")
        matches = [item for item in models if isinstance(item, Mapping) and item.get("id") == EXACT_MODEL]
        if len(matches) != 1 or matches[0].get("model") != EXACT_MODEL:
            raise AppServerError("exact-spark-model-unavailable")
        return {
            "id": matches[0]["id"],
            "model": matches[0]["model"],
            "display_name": matches[0].get("displayName"),
            "latency_ms": round(latency, 3),
        }

    def start_thread(
        self,
        cwd: Path,
        *,
        mutable: bool,
        role: str | None = None,
    ) -> tuple[dict[str, Any], float]:
        allocation_intent_id: str | None = None
        if self.allocation_ledger is not None:
            if role not in EXPECTED_ROLES:
                raise AppServerError("allocation-ledger-role-required")
            allocation_intent_id = self.allocation_ledger.allocation_intent(str(role))
        result, latency = self.request(
            "thread/start",
            {
                "model": EXACT_MODEL,
                "allowProviderModelFallback": False,
                "cwd": str(cwd.resolve()),
                "runtimeWorkspaceRoots": [str(cwd.resolve())],
                "approvalPolicy": "never",
                "sandbox": "workspace-write" if mutable else "read-only",
                "ephemeral": False,
                "historyMode": "legacy",
                "developerInstructions": (
                    "This is a bounded CWO live canary. Do not spawn subagents, use network access, "
                    "or access paths outside the supplied workspace. Follow the user task exactly."
                ),
            },
            timeout=30,
        )
        thread = result.get("thread")
        if not isinstance(thread, Mapping) or not thread.get("id"):
            raise AppServerError("thread-start-response-invalid")
        thread_id = str(thread["id"])
        self.started_threads[thread_id] = None
        if self.allocation_ledger is not None and allocation_intent_id is not None:
            self.allocation_ledger.bind_thread(allocation_intent_id, thread_id)
        if result.get("model") != EXACT_MODEL:
            raise AppServerError("thread-start-model-mismatch")
        return dict(result), latency

    def read_thread(
        self,
        thread_id: str,
        *,
        timeout: float = THREAD_READ_TIMEOUT_SECONDS,
    ) -> tuple[dict[str, Any], float]:
        result, latency = self.request(
            "thread/read",
            {"threadId": thread_id, "includeTurns": True},
            timeout=timeout,
        )
        thread = result.get("thread")
        if not isinstance(thread, Mapping) or thread.get("id") != thread_id:
            raise AppServerError("thread-read-response-invalid")
        return dict(thread), latency

    def read_thread_once_with_guard(
        self,
        thread_id: str,
        *,
        timeout: float,
        pre_dispatch_guard: Callable[[], Mapping[str, Any]],
    ) -> tuple[dict[str, Any], float, dict[str, Any], int, str]:
        result, latency, guarded, request_id, payload_sha256 = (
            self.request_once_with_guard(
                "thread/read",
                {"threadId": thread_id, "includeTurns": True},
                timeout=timeout,
                pre_dispatch_guard=pre_dispatch_guard,
            )
        )
        thread = result.get("thread")
        if not isinstance(thread, Mapping) or thread.get("id") != thread_id:
            raise AppServerError("thread-read-response-invalid")
        return dict(thread), latency, guarded, request_id, payload_sha256

    def start_turn(self, thread_id: str, prompt: str) -> tuple[dict[str, Any], float]:
        turn_intent_id: str | None = None
        if self.allocation_ledger is not None:
            turn_intent_id = self.allocation_ledger.turn_intent(thread_id)
        result, latency = self.request(
            "turn/start",
            {
                "threadId": thread_id,
                "input": [{"type": "text", "text": prompt, "text_elements": []}],
                "model": EXACT_MODEL,
                "effort": "low",
                "clientUserMessageId": str(uuid.uuid4()),
                "responsesapiClientMetadata": {
                    "cwo_bead": "complex-work-orchestration-18w.6",
                    "cwo_control_turn": CONTROL_TURN_ID,
                },
            },
            timeout=30,
        )
        turn = result.get("turn")
        if not isinstance(turn, Mapping) or not turn.get("id"):
            raise AppServerError("turn-start-response-invalid")
        turn_id = str(turn["id"])
        self.started_threads[thread_id] = turn_id
        if self.allocation_ledger is not None and turn_intent_id is not None:
            self.allocation_ledger.bind_turn(thread_id, turn_intent_id, turn_id)
        return dict(turn), latency

    def interrupt_turn(self, thread_id: str, turn_id: str) -> float:
        _result, latency = self.request(
            "turn/interrupt", {"threadId": thread_id, "turnId": turn_id}, timeout=15
        )
        if self.allocation_ledger is not None:
            self.allocation_ledger.record_lifecycle(
                thread_id, "interrupt-observed", "interrupt-request-accepted"
            )
        return latency

    def archive_thread(self, thread_id: str) -> float:
        _result, latency = self.request("thread/archive", {"threadId": thread_id}, timeout=15)
        if self.allocation_ledger is not None:
            self.allocation_ledger.record_lifecycle(
                thread_id, "archive-observed", "archive-request-accepted"
            )
        return latency

    def notifications(self, thread_id: str, method: str | None = None) -> list[dict[str, Any]]:
        with self._condition:
            values = []
            for _timestamp, message in self._notifications:
                params = message.get("params") if isinstance(message.get("params"), Mapping) else {}
                if params.get("threadId") != thread_id:
                    continue
                if method is not None and message.get("method") != method:
                    continue
                values.append(message)
            return values

    def notification_cursor(self) -> int:
        """Return the current connection-local receive sequence."""

        with self._condition:
            return len(self._notifications)

    def notification_events(
        self,
        thread_id: str,
        turn_id: str,
        *,
        after_sequence: int,
    ) -> list[dict[str, Any]]:
        """Snapshot trusted stdio notifications with connection-local provenance."""

        with self._condition:
            values: list[dict[str, Any]] = []
            for sequence, (received_ns, message) in enumerate(self._notifications, 1):
                if sequence <= after_sequence:
                    continue
                params = message.get("params") if isinstance(message.get("params"), Mapping) else {}
                if params.get("threadId") != thread_id or params.get("turnId") != turn_id:
                    continue
                values.append(
                    {
                        "connection_epoch_sha256": self.connection_epoch_sha256,
                        "sequence": sequence,
                        "received_monotonic_ns": received_ns,
                        "method": message.get("method"),
                        "params": dict(params),
                    }
                )
            return values

    def close(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)


def turn_from_thread(thread: Mapping[str, Any], turn_id: str | None) -> Mapping[str, Any] | None:
    turns = thread.get("turns")
    if not isinstance(turns, list):
        return None
    for item in turns:
        if isinstance(item, Mapping) and item.get("id") == turn_id:
            return item
    return None


def turn_status(thread: Mapping[str, Any], turn_id: str | None) -> str | None:
    turn = turn_from_thread(thread, turn_id)
    return str(turn.get("status")) if isinstance(turn, Mapping) and turn.get("status") else None


def turn_items(thread: Mapping[str, Any], turn_id: str | None) -> list[Mapping[str, Any]]:
    turn = turn_from_thread(thread, turn_id)
    items = turn.get("items") if isinstance(turn, Mapping) else None
    return [item for item in items if isinstance(item, Mapping)] if isinstance(items, list) else []


def final_message_hash_and_match(
    thread: Mapping[str, Any], turn_id: str | None, expected_token: str
) -> tuple[str | None, bool]:
    messages = [
        str(item.get("text", ""))
        for item in turn_items(thread, turn_id)
        if item.get("type") == "agentMessage" and item.get("phase") in {"finalAnswer", "final_answer", None}
    ]
    if not messages:
        return None, False
    final = messages[-1]
    return sha256_text(final), final.strip() == expected_token


def session_boundary_summary(
    codex_home: Path,
    thread_id: str,
    _reported: str | None,
    *,
    turn_id: str | None = None,
    baseline: Mapping[str, Any] | None = None,
    allow_unmaterialized: bool = False,
    expected_source_identity_sha256: str | None = None,
) -> dict[str, Any]:
    try:
        located, boundary, records = capture_unique_boundary(
            codex_home,
            thread_id,
            baseline=baseline,
        )
        if (
            expected_source_identity_sha256 is not None
            and located.source_identity_sha256 != expected_source_identity_sha256
        ):
            raise NativeSessionBoundaryError(
                "trusted session source identity changed after materialization"
            )
    except NativeSessionBoundaryError as exc:
        boundary_error = str(exc)
        if not allow_unmaterialized or boundary_error not in {
            "trusted session file is missing",
            "session file has no complete records",
        }:
            raise AppServerError(f"session-boundary-invalid:{exc}") from exc
        return {
            "available": False,
            "record_count": 0,
            "byte_offset": 0,
            "boundary_sha256": None,
            "token_snapshot": None,
            "source_identity_sha256": None,
            "trailing_partial": False,
            "attested_models": [],
            "attested_efforts": [],
            "compactions": 0,
            "reroutes": 0,
            "observation_type": "unmaterialized-nonattesting",
            "terminal_event": None,
        }
    models: list[str] = []
    efforts: list[str] = []
    compactions = 0
    reroutes = 0
    terminal_event = None
    if turn_id is not None:
        try:
            terminal_event = trusted_terminal_event(records, turn_id=turn_id)
        except NativeSessionBoundaryError as exc:
            raise AppServerError(f"session-terminal-grammar-invalid:{exc}") from exc
    for record in records:
        record_type = record.get("type")
        payload = record.get("payload") if isinstance(record.get("payload"), Mapping) else {}
        if record_type == "turn_context":
            if isinstance(payload.get("model"), str):
                models.append(str(payload["model"]))
            effort = payload.get("effort") or payload.get("reasoning_effort")
            if isinstance(effort, str):
                efforts.append(effort)
        payload_type = str(payload.get("type", ""))
        marker = f"{record_type}:{payload_type}".lower()
        if "compact" in marker:
            compactions += 1
        if "rerout" in marker:
            reroutes += 1
    return {
        "available": True,
        "record_count": boundary["record_count"],
        "byte_offset": boundary["byte_offset"],
        "boundary_sha256": boundary["boundary_sha256"],
        "token_snapshot": boundary.get("token_snapshot"),
        "source_identity_sha256": located.source_identity_sha256,
        "trailing_partial": False,
        "attested_models": sorted(set(models)),
        "attested_efforts": sorted(set(efforts)),
        "compactions": compactions,
        "reroutes": reroutes,
        "observation_type": "trusted-complete-boundary",
        "terminal_event": terminal_event,
    }


def captured_session_boundary_summary(
    located: LocatedSession,
    boundary: Mapping[str, Any],
    records: list[dict[str, Any]],
    *,
    turn_id: str | None,
) -> dict[str, Any]:
    """Summarize an already descriptor-bound session boundary."""

    models: list[str] = []
    efforts: list[str] = []
    compactions = 0
    reroutes = 0
    terminal_event = None
    if turn_id is not None:
        try:
            terminal_event = trusted_terminal_event(records, turn_id=turn_id)
        except NativeSessionBoundaryError as exc:
            raise AppServerError(
                f"session-terminal-grammar-invalid:{exc}"
            ) from exc
    for record in records:
        record_type = record.get("type")
        payload = (
            record.get("payload")
            if isinstance(record.get("payload"), Mapping)
            else {}
        )
        if record_type == "turn_context":
            if isinstance(payload.get("model"), str):
                models.append(str(payload["model"]))
            effort = payload.get("effort") or payload.get("reasoning_effort")
            if isinstance(effort, str):
                efforts.append(effort)
        marker = f"{record_type}:{payload.get('type', '')}".lower()
        if "compact" in marker:
            compactions += 1
        if "rerout" in marker:
            reroutes += 1
    return {
        "available": True,
        "record_count": boundary["record_count"],
        "byte_offset": boundary["byte_offset"],
        "boundary_sha256": boundary["boundary_sha256"],
        "token_snapshot": boundary.get("token_snapshot"),
        "source_identity_sha256": located.source_identity_sha256,
        "trailing_partial": False,
        "attested_models": sorted(set(models)),
        "attested_efforts": sorted(set(efforts)),
        "compactions": compactions,
        "reroutes": reroutes,
        "observation_type": "trusted-complete-boundary",
        "terminal_event": terminal_event,
    }


class LiveThreadAdapter:
    def __init__(
        self,
        server: AppServer,
        thread_response: Mapping[str, Any],
        *,
        prompt: str,
        expected_token: str,
        worktree: Path,
        mutable: bool,
        expected_mutation: str | None,
        force_interrupt_after_checks: int | None = None,
        record_dir: Path,
        monotonic_ns: Callable[[], int] = time.monotonic_ns,
    ) -> None:
        self.server = server
        self.thread_response = dict(thread_response)
        self.thread = dict(thread_response["thread"])
        self.thread_id = str(self.thread["id"])
        self.reported_session_path = self.thread.get("path")
        self.prompt = prompt
        self.expected_token = expected_token
        self.worktree = worktree
        self.mutable = mutable
        self.expected_mutation = expected_mutation
        self.force_interrupt_after_checks = force_interrupt_after_checks
        self.record_dir = record_dir
        self.turn_id: str | None = None
        self.send_started_ns: int | None = None
        self.last_thread: dict[str, Any] = dict(self.thread)
        self.check_count = 0
        self.interrupted = False
        self.archived = False
        self._boundary_phase = "pre-dispatch"
        self._boundary_lock = threading.RLock()
        self._monotonic_ns = monotonic_ns
        self._materialization_deadline_ns: int | None = None
        self._projection_started_ns: int | None = None
        self._session_boundary_baseline: dict[str, Any] | None = None
        self._session_source_identity_sha256: str | None = None
        self.callback_latencies: dict[str, list[float]] = {}
        self._evidence_sequence = 0

    def _timed(self, name: str, action: Callable[[], Any]) -> Any:
        started = time.monotonic_ns()
        try:
            return action()
        finally:
            elapsed = (time.monotonic_ns() - started) / 1_000_000
            self.callback_latencies.setdefault(name, []).append(elapsed)

    def arm(self, **_kwargs: Any) -> dict[str, str]:
        def action() -> dict[str, str]:
            if self.thread_response.get("model") != EXACT_MODEL:
                raise AppServerError("prearmed-thread-model-mismatch")
            if self.thread.get("id") != self.thread_id or self.thread.get("turns"):
                raise AppServerError("prearmed-thread-is-not-fresh")
            return {"ack": "armed"}

        return self._timed("arm", action)

    def send_input(self, *, message: str, **_kwargs: Any) -> dict[str, str]:
        def action() -> dict[str, str]:
            if message != self.prompt:
                raise AppServerError("turn-prompt-binding-mismatch")
            with self._boundary_lock:
                # Revoke the pre-dispatch allowance before the RPC. Failed or
                # ambiguous submission can never recover it from a missing id.
                self._boundary_phase = "dispatch-attempted"
                turn, _latency = self.server.start_turn(self.thread_id, message)
                returned_ns = self._monotonic_ns()
                turn_id = turn.get("id") if isinstance(turn, Mapping) else None
                if not isinstance(turn_id, str) or not turn_id:
                    raise AppServerError("turn-start-response-invalid")
                if self.server.started_threads.get(self.thread_id) != turn_id:
                    raise AppServerError("trusted-turn-start-binding-mismatch")
                self.turn_id = turn_id
                self.send_started_ns = returned_ns
                self._materialization_deadline_ns = returned_ns + (
                    POST_SUBMISSION_MATERIALIZATION_GRACE_MS * 1_000_000
                )
                self._boundary_phase = "submission-acknowledged-awaiting-materialization"
                return {"submission_id": self.turn_id}

        return self._timed("send_input", action)

    def mark_dispatched(self, *, submission_id: str, **_kwargs: Any) -> dict[str, str]:
        def action() -> dict[str, str]:
            if submission_id != self.turn_id:
                raise AppServerError("submission-id-binding-mismatch")
            write_private_artifact(
                self.record_dir / f"{self.thread_id}-dispatch.json",
                {
                    "thread_id": self.thread_id,
                    "turn_id": self.turn_id,
                    "prompt_sha256": sha256_text(self.prompt),
                    "control_turn_id": CONTROL_TURN_ID,
                },
            )
            return {"ack": "dispatched"}

        return self._timed("mark_dispatched", action)

    def check(self, **_kwargs: Any) -> dict[str, str]:
        def action() -> dict[str, str]:
            self.check_count += 1
            thread, _latency = self.server.read_thread(self.thread_id)
            self.last_thread = thread
            self.reported_session_path = thread.get("path") or self.reported_session_path
            boundary = self._capture_trusted_boundary(allow_pending=True)
            status = turn_status(self.last_thread, self.turn_id)
            terminal_event = boundary.get("terminal_event")
            durable_status = (
                terminal_event.get("status")
                if isinstance(terminal_event, Mapping)
                else None
            )
            if durable_status == "completed":
                _message_hash, matches = final_message_hash_and_match(
                    self.last_thread, self.turn_id, self.expected_token
                )
                return {"decision": "complete" if matches else "control-lost"}
            if durable_status == "interrupted":
                return {"decision": "interrupt"}
            if durable_status == "failed":
                return {"decision": "control-lost"}
            now_ns = self._monotonic_ns()
            if status in {"completed", "failed", "interrupted"}:
                if self._projection_started_ns is None:
                    self._projection_started_ns = now_ns
                elif (
                    now_ns - self._projection_started_ns
                    > int(PROVISIONAL_TERMINAL_GRACE_SECONDS * 1_000_000_000)
                ):
                    return {"decision": "control-lost"}
            elif status in {"inProgress", "in_progress", "running"}:
                if boundary.get("available") is True:
                    self._projection_started_ns = None
            if (
                self.force_interrupt_after_checks is not None
                and self.check_count >= self.force_interrupt_after_checks
            ):
                return {"decision": "interrupt"}
            if status in {
                "inProgress",
                "in_progress",
                "running",
                "completed",
                "failed",
                "interrupted",
                None,
            }:
                return {"decision": "continue"}
            return {"decision": "control-lost"}

        return self._timed("check", action)

    def interrupt(self, **_kwargs: Any) -> dict[str, str]:
        def action() -> dict[str, str]:
            with self._boundary_lock:
                if self.turn_id is None:
                    raise AppServerError("interrupt-turn-id-missing")
                # Interrupt wins locally before the control RPC is attempted;
                # unavailable telemetry can never be accepted after this point.
                self._boundary_phase = "interrupt-requested"
                self.server.interrupt_turn(self.thread_id, self.turn_id)
                self.interrupted = True
                return {"ack": "interrupt-requested"}

        return self._timed("interrupt", action)

    def finalize(self, *, control_action: str, **_kwargs: Any) -> dict[str, str]:
        def action() -> dict[str, str]:
            write_private_artifact(
                self.record_dir / f"{self.thread_id}-finalize-{control_action}.json",
                {
                    "thread_id": self.thread_id,
                    "turn_id": self.turn_id,
                    "control_action": control_action,
                    "control_turn_id": CONTROL_TURN_ID,
                },
            )
            return {"ack": control_action}

        return self._timed("finalize", action)

    def close(self, **_kwargs: Any) -> dict[str, str]:
        def action() -> dict[str, str]:
            with self._boundary_lock:
                self._boundary_phase = "closing"
                thread, _latency = self.server.read_thread(self.thread_id)
                self.last_thread = thread
                self.reported_session_path = thread.get("path") or self.reported_session_path
                boundary = self._capture_trusted_boundary(allow_pending=True)
                terminal_event = boundary.get("terminal_event")
                durable_status = (
                    terminal_event.get("status")
                    if isinstance(terminal_event, Mapping)
                    else None
                )
                if boundary.get("available") is True and durable_status not in {
                    "completed",
                    "interrupted",
                    "failed",
                }:
                    raise AppServerError(
                        f"close-before-durable-terminal:{durable_status}"
                    )
                if boundary.get("available") is not True and not self.interrupted:
                    raise AppServerError("close-before-durable-terminal:unavailable")
                self.server.archive_thread(self.thread_id)
                self.archived = True
                return {"ack": "closed"}

        return self._timed("close", action)

    @staticmethod
    def sleep(*, seconds: float) -> None:
        time.sleep(seconds)

    def callbacks(self) -> dict[str, Callable[..., Any]]:
        return {
            "arm": self.arm,
            "send_input": self.send_input,
            "mark_dispatched": self.mark_dispatched,
            "check": self.check,
            "interrupt": self.interrupt,
            "close": self.close,
            "finalize": self.finalize,
            "sleep": self.sleep,
        }

    def _workspace_mutations(self) -> list[str]:
        completed = subprocess.run(
            [
                "git",
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
            ],
            cwd=self.worktree,
            check=True,
            capture_output=True,
            text=True,
        )
        return porcelain_mutation_paths(completed.stdout)

    def _pending_window_is_open_locked(self) -> None:
        if self._boundary_phase != "submission-acknowledged-awaiting-materialization":
            raise AppServerError("post-submission-materialization-phase-invalid")
        if not self.turn_id or self.server.started_threads.get(self.thread_id) != self.turn_id:
            raise AppServerError("trusted-turn-start-binding-mismatch")
        if self._materialization_deadline_ns is None:
            raise AppServerError("post-submission-materialization-deadline-missing")
        if self._monotonic_ns() >= self._materialization_deadline_ns:
            raise AppServerError("post-submission-materialization-deadline-exceeded")

    def _record_complete_boundary_locked(self, boundary: Mapping[str, Any]) -> dict[str, Any]:
        if self._boundary_phase == "submission-acknowledged-awaiting-materialization":
            self._pending_window_is_open_locked()
            self._boundary_phase = "materialized"
        self._session_boundary_baseline = {
            "record_count": boundary.get("record_count"),
            "byte_offset": boundary.get("byte_offset"),
            "boundary_sha256": boundary.get("boundary_sha256"),
            "token_snapshot": boundary.get("token_snapshot"),
        }
        source_identity = boundary.get("source_identity_sha256")
        if not isinstance(source_identity, str) or not source_identity:
            raise AppServerError("trusted-session-source-identity-missing")
        if (
            self._session_source_identity_sha256 is not None
            and source_identity != self._session_source_identity_sha256
        ):
            raise AppServerError("trusted-session-source-identity-changed")
        self._session_source_identity_sha256 = source_identity
        return dict(boundary)

    def _fresh_nonterminal_thread_locked(self) -> None:
        self._pending_window_is_open_locked()
        thread, _latency = self.server.read_thread(self.thread_id)
        if thread.get("id") != self.thread_id:
            raise AppServerError("post-submission-thread-read-identity-mismatch")
        self.last_thread = thread
        self.reported_session_path = thread.get("path") or self.reported_session_path
        self._pending_window_is_open_locked()

    def _capture_trusted_boundary(self, *, allow_pending: bool) -> dict[str, Any]:
        with self._boundary_lock:
            pending_phase = self._boundary_phase in {
                "pre-dispatch",
                "submission-acknowledged-awaiting-materialization",
            }
            containment_phase = self._boundary_phase in {
                "interrupt-requested",
                "closing",
            }
            allow_unmaterialized = (
                (allow_pending and pending_phase or containment_phase)
                and self._session_boundary_baseline is None
            )
            boundary = session_boundary_summary(
                self.server.codex_home,
                self.thread_id,
                None,
                turn_id=self.turn_id,
                baseline=self._session_boundary_baseline,
                allow_unmaterialized=allow_unmaterialized,
                expected_source_identity_sha256=self._session_source_identity_sha256,
            )
            if boundary["available"]:
                return self._record_complete_boundary_locked(boundary)
            if self._boundary_phase == "pre-dispatch":
                boundary["observation_type"] = (
                    "pre-dispatch-unmaterialized-nonattesting-nonaccepting"
                )
                return boundary
            if containment_phase:
                boundary["observation_type"] = (
                    "containment-unmaterialized-nonattesting-rejected"
                )
                return boundary

            # The trusted file was absent or exactly zero bytes. Re-read the
            # control plane after that observation, retry the boundary once,
            # then re-read status immediately before emitting a pending marker.
            self._fresh_nonterminal_thread_locked()
            boundary = session_boundary_summary(
                self.server.codex_home,
                self.thread_id,
                None,
                turn_id=self.turn_id,
                baseline=None,
                allow_unmaterialized=True,
                expected_source_identity_sha256=None,
            )
            if boundary["available"]:
                return self._record_complete_boundary_locked(boundary)
            self._fresh_nonterminal_thread_locked()
            boundary["observation_type"] = (
                "post-submission-unmaterialized-nonattesting-nonaccepting"
            )
            return boundary

    def _trusted_summary(self, *, allow_pending: bool = True) -> dict[str, Any]:
        boundary = self._capture_trusted_boundary(allow_pending=allow_pending)
        items = turn_items(self.last_thread, self.turn_id)
        item_types = [str(item.get("type")) for item in items if item.get("type")]
        tool_calls = sum(item_type in OPERATIVE_ITEM_TYPES for item_type in item_types)
        compactions = item_types.count("contextCompaction") + len(
            self.server.notifications(self.thread_id, "thread/compacted")
        )
        final_hash, final_matches = final_message_hash_and_match(
            self.last_thread, self.turn_id, self.expected_token
        )
        reroutes = self.server.notifications(self.thread_id, "model/rerouted")
        token_events = self.server.notifications(self.thread_id, "thread/tokenUsage/updated")
        token_total = None
        if token_events:
            params = token_events[-1].get("params", {})
            token_usage = params.get("tokenUsage", {}) if isinstance(params, Mapping) else {}
            total = token_usage.get("total", {}) if isinstance(token_usage, Mapping) else {}
            if isinstance(total, Mapping):
                token_total = {
                    "input": total.get("inputTokens"),
                    "cached_input": total.get("cachedInputTokens"),
                    "output": total.get("outputTokens"),
                    "reasoning": total.get("reasoningOutputTokens"),
                    "total": total.get("totalTokens"),
                }
        models = boundary.get("attested_models", [])
        efforts = boundary.get("attested_efforts", [])
        model_exact = (
            boundary.get("available") is True
            and models == [EXACT_MODEL]
            and efforts == ["low"]
        )
        projected_status = turn_status(self.last_thread, self.turn_id)
        terminal_event = boundary.get("terminal_event")
        durable_status = (
            terminal_event.get("status")
            if isinstance(terminal_event, Mapping)
            else None
        )
        return {
            "thread_id": self.thread_id,
            "turn_id": self.turn_id,
            "thread_start_model": self.thread_response.get("model"),
            "thread_start_model_provider": self.thread_response.get("modelProvider"),
            "turn_status": durable_status or projected_status,
            "projected_turn_status": projected_status,
            "durable_terminal_event": terminal_event,
            "session_boundary": boundary,
            "model_exact": model_exact,
            "reroute_count": len(reroutes),
            "compactions": compactions,
            "tool_calls": tool_calls,
            "item_types": sorted(set(item_types)),
            "token_telemetry": {
                "availability": "available" if token_total is not None else "unavailable",
                "total": token_total,
            },
            "final_response_sha256": final_hash,
            "expected_final_token_observed": final_matches,
            "workspace_mutations": self._workspace_mutations(),
            "interrupted": self.interrupted,
            "archived": self.archived,
        }

    def evidence(self) -> dict[str, Any]:
        self._evidence_sequence += 1
        summary = self._trusted_summary()
        status = summary["turn_status"]
        terminal = status in {"completed", "interrupted", "failed"}
        reasons: list[str] = []
        if terminal and not summary["model_exact"]:
            reasons.append("trusted-model-attestation-mismatch")
        if (
            summary["session_boundary"].get("observation_type")
            == "containment-unmaterialized-nonattesting-rejected"
        ):
            reasons.append("containment-unmaterialized-nonattesting-rejected")
        if summary["reroute_count"]:
            reasons.append("model-reroute-observed")
        if summary["compactions"]:
            reasons.append("compaction-observed")
        if terminal and summary["session_boundary"].get("trailing_partial"):
            reasons.append("terminal-session-boundary-partial")
        if status == "completed" and not summary["expected_final_token_observed"]:
            reasons.append("invalid-final-response")
        mutations = summary["workspace_mutations"]
        if self.mutable:
            if any(path != self.expected_mutation for path in mutations):
                reasons.append("mutable-workspace-attribution-mismatch")
        elif mutations:
            reasons.append("read-only-workspace-mutation")
        runtime = 0
        if self.send_started_ns is not None:
            runtime = int(max(0, time.monotonic_ns() - self.send_started_ns) / 1_000_000_000)
        usage = {
            "tool_calls": int(summary["tool_calls"]),
            "runtime_seconds": runtime,
            "compactions": int(summary["compactions"]),
            "full_suite_runs": 0,
            "mutations": len(mutations),
            "tokens": zero_token_usage("pool-v1-token-ingest-not-bound"),
        }
        state_payload = {
            "thread_id": self.thread_id,
            "turn_id": self.turn_id,
            "status": status,
            "boundary_sha256": summary["session_boundary"].get("boundary_sha256"),
            "boundary_observation": summary["session_boundary"].get("observation_type"),
            "tool_calls": usage["tool_calls"],
            "runtime_seconds": usage["runtime_seconds"],
            "mutations": usage["mutations"],
            "compactions": usage["compactions"],
            "evidence_sequence": self._evidence_sequence,
        }
        if (
            summary["session_boundary"].get("observation_type")
            == "containment-unmaterialized-nonattesting-rejected"
        ):
            session_disposition = "quarantined"
            artifact_disposition = "rejected"
        elif summary["session_boundary"].get("available") is not True:
            session_disposition = "accepted-with-warning"
            artifact_disposition = "independent-validation-required"
        elif self.interrupted:
            session_disposition = "accepted-with-warning" if not reasons else "quarantined"
            artifact_disposition = "rejected"
        elif status == "completed" and not reasons:
            session_disposition = "accepted"
            artifact_disposition = "accepted"
        elif terminal:
            session_disposition = "quarantined"
            artifact_disposition = "rejected"
        else:
            session_disposition = "accepted"
            artifact_disposition = "accepted"
        return {
            "state_sha256": canonical_sha256(state_payload),
            "usage": usage,
            "protected_fault": bool(reasons),
            "control_loss": status == "failed" or "trusted-model-attestation-mismatch" in reasons,
            "reasons": reasons,
            "session_disposition": session_disposition,
            "artifact_disposition": artifact_disposition,
        }

    def final_summary(self) -> dict[str, Any]:
        summary = self._trusted_summary(allow_pending=False)
        summary["callback_stats"] = {
            name: stats(values) for name, values in sorted(self.callback_latencies.items())
        }
        summary["prompt_sha256"] = sha256_text(self.prompt)
        return summary


def guarded_measure(
    samples: dict[str, list[float]],
    name: str,
    action: Callable[[], Any],
    *,
    guard_seconds: float = 0.20,
) -> Any:
    started = time.monotonic_ns()
    result = action()
    time.sleep(guard_seconds)
    samples.setdefault(name, []).append((time.monotonic_ns() - started) / 1_000_000)
    return result


def pool_sleep(*, seconds: float) -> None:
    """Adapt the coordinator's keyword callback to positional-only time.sleep."""

    time.sleep(seconds)


def _run_calibration(
    server: AppServer,
    cwd: Path,
    record_dir: Path,
    owner: Mapping[str, Any],
    *,
    run_nonce: str,
    phase_nonce: str,
    boundary_trackers: list[PreAttestationSessionBoundaryTracker],
    materialization_timeout_seconds: float = 10.0,
    pre_allocation_check: Callable[[], None] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    samples: dict[str, list[float]] = {}

    def workspace_snapshot() -> tuple[str, str | None]:
        completed = subprocess.run(
            ["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"],
            cwd=cwd,
            check=False,
            capture_output=True,
        )
        if completed.returncode == 0:
            return "available", sha256_bytes(completed.stdout)
        if completed.returncode == 128:
            return "unavailable-not-git", None
        raise AppServerError("capability-workspace-comparison-failed")

    workspace_monitoring_status, workspace_baseline_sha256 = workspace_snapshot()
    if pre_allocation_check is not None:
        pre_allocation_check()
    result, preallocation_latency = server.start_thread(
        cwd, mutable=False, role="capability-calibration"
    )
    thread_id = str(result["thread"]["id"])
    guarded_measure(
        samples,
        "arm",
        lambda: (
            result.get("model") == EXACT_MODEL
            and result.get("thread", {}).get("id") == thread_id
            and not result.get("thread", {}).get("turns")
        )
        or (_ for _ in ()).throw(AppServerError("prearmed-thread-binding-invalid")),
        guard_seconds=0.0,
    )
    prompt = (
        "Use the exec_command tool exactly once to run `sleep 20`. After it finishes, return "
        "exactly CAPABILITY_LONG_DONE. Do not use any other tool."
    )
    notification_floor = server.notification_cursor()
    turn = guarded_measure(
        samples,
        "send_input",
        lambda: server.start_turn(thread_id, prompt),
        guard_seconds=0.0,
    )[0]
    turn_id = str(turn["id"])
    attempt_nonce = str(uuid.uuid4())
    guarded_measure(
        samples,
        "mark_dispatched",
        lambda: write_private_artifact(
            record_dir / "calibration-mark.json",
            {
                "thread_id": thread_id,
                "turn_id": turn_id,
                "control_turn_id": CONTROL_TURN_ID,
                "attempt_nonce": attempt_nonce,
                "phase_nonce": phase_nonce,
            },
        ),
        guard_seconds=0.0,
    )

    strict_baseline = {
        "record_count": 0,
        "byte_offset": 0,
        "boundary_sha256": sha256_bytes(b""),
        "token_snapshot": None,
    }
    preattestation_boundary = PreAttestationSessionBoundaryTracker(
        server.codex_home,
        thread_id,
    )
    boundary_trackers.append(preattestation_boundary)
    trusted_source_identity: str | None = None
    observed_prefix: dict[str, Any] = dict(strict_baseline)
    control_started_ns = time.monotonic_ns()
    control_observations: list[dict[str, Any]] = []
    projection_started_ns: int | None = None
    attestation_observed = False
    read_recovery_pending = False
    read_recovery: dict[str, Any] = {
        "telemetry_type": CALIBRATION_READ_RECOVERY_TELEMETRY_TYPE,
        "version": 2,
        "policy": CALIBRATION_READ_RECOVERY_POLICY,
        "method": None,
        "code": None,
        "replacement_attempt_max": 1,
        "token_consumed": False,
        "replacement_attempt_count": 0,
        "phase": None,
        "failed_callback_latency_ms": None,
        "remaining_deadline_ms_before_scheduling": None,
        "remaining_deadline_ms_before_attempt": None,
        "attestation_observed_at_fault": None,
        "connection_epoch_sha256": server.connection_epoch_sha256,
        "prior_source_identity_sha256": None,
        "prior_boundary_sha256": strict_baseline["boundary_sha256"],
        "fault_boundary_record_count": None,
        "fault_boundary_byte_offset": None,
        "pre_attempt_source_identity_sha256": None,
        "pre_attempt_boundary_sha256": None,
        "pre_attempt_boundary_record_count": None,
        "pre_attempt_boundary_byte_offset": None,
        "fault_boundary_classification": None,
        "pre_dispatch_source_identity_sha256": None,
        "pre_dispatch_boundary_sha256": None,
        "pre_dispatch_boundary_record_count": None,
        "pre_dispatch_boundary_byte_offset": None,
        "pre_dispatch_boundary_classification": None,
        "wire_dispatch_count": 0,
        "wire_request_id": None,
        "wire_request_sha256": None,
        "wire_response_correlation_sha256": None,
        "post_read_boundary_sha256": None,
        "post_read_boundary_record_count": None,
        "post_read_boundary_byte_offset": None,
        "workspace_monitoring_status": workspace_monitoring_status,
        "workspace_baseline_sha256": workspace_baseline_sha256,
        "fault_workspace_sha256": None,
        "pre_dispatch_workspace_sha256": None,
        "post_read_workspace_sha256": None,
        "workspace_mutation_observed": False,
        "transport_outcome": "not-needed",
        "outcome": "not-needed",
    }

    def capture_recovery_workspace(stage: str) -> str | None:
        status, current = workspace_snapshot()
        if status != workspace_monitoring_status:
            read_recovery["workspace_mutation_observed"] = True
            raise AppServerError(
                f"capability-read-recovery-workspace-monitor-changed-{stage}"
            )
        field = {
            "at-fault": "fault_workspace_sha256",
            "before-dispatch": "pre_dispatch_workspace_sha256",
            "post-read": "post_read_workspace_sha256",
        }[stage]
        read_recovery[field] = current
        if current != workspace_baseline_sha256:
            read_recovery["workspace_mutation_observed"] = True
            raise AppServerError(
                f"capability-read-recovery-workspace-mutated-{stage}"
            )
        return current

    def attach_recovery_fault(exc: BaseException) -> BaseException:
        """Attach privacy-safe bounded-retry state to every terminal fault."""

        if getattr(exc, "first_protected_fault", None) is not None:
            return exc
        snapshot = dict(read_recovery)
        snapshot.pop("telemetry_sha256", None)
        fault = {
            "fault_type": "calibration-thread-read-recovery",
            "failure_code": str(exc),
            "thread_id_sha256": sha256_text(thread_id),
            "turn_id_sha256": sha256_text(turn_id),
            "recovery_telemetry": snapshot,
            "recovery_telemetry_sha256": canonical_sha256(snapshot),
        }
        setattr(exc, "first_protected_fault", fault)
        return exc

    def public_boundary(value: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "record_count": int(value["record_count"]),
            "byte_offset": int(value["byte_offset"]),
            "boundary_sha256": str(value["boundary_sha256"]),
            "invalid_record_count": 0,
            "trailing_partial": False,
        }

    def normalize_projected_status(value: str | None) -> str:
        if value in {"inProgress", "in_progress", "running"}:
            return "active"
        if value in {"completed", "failed", "interrupted"}:
            return str(value)
        if value is None:
            return "missing"
        return "unknown"

    def append_control_observation(
        *,
        phase: str,
        projected_status: str,
        durable_status: str | None,
        source_identity_sha256: str | None,
        previous_boundary: Mapping[str, Any],
        boundary: Mapping[str, Any],
        decision: str,
    ) -> None:
        if len(control_observations) >= CONTROL_OBSERVATION_MAX:
            raise AppServerError("capability-control-observation-limit-exceeded")
        control_observations.append(
            {
                "ordinal": len(control_observations),
                "elapsed_monotonic_ms": round(
                    (time.monotonic_ns() - control_started_ns) / 1_000_000, 3
                ),
                "phase": phase,
                "projected_status": projected_status,
                "durable_status": durable_status,
                "source_identity_sha256": source_identity_sha256,
                "previous_boundary_sha256": str(
                    previous_boundary["boundary_sha256"]
                ),
                "boundary": public_boundary(boundary),
                "decision": decision,
            }
        )

    def record_nonterminal_projection(
        *,
        phase: str,
        projected_status: str,
        boundary_available: bool,
        ready: bool,
        source_identity_sha256: str | None,
        previous_boundary: Mapping[str, Any],
        boundary: Mapping[str, Any],
    ) -> bool:
        nonlocal projection_started_ns
        now_ns = time.monotonic_ns()
        if projected_status in {"completed", "failed", "interrupted"}:
            if projection_started_ns is None:
                projection_started_ns = now_ns
            append_control_observation(
                phase=phase,
                projected_status=projected_status,
                durable_status=None,
                source_identity_sha256=source_identity_sha256,
                previous_boundary=previous_boundary,
                boundary=boundary,
                decision="continue-provisional",
            )
            if (
                now_ns - projection_started_ns
                > int(PROVISIONAL_TERMINAL_GRACE_SECONDS * 1_000_000_000)
            ):
                raise AppServerError(
                    f"capability-uncorroborated-terminal-projection:{projected_status}"
                )
            return False
        if boundary_available and projected_status == "active":
            projection_started_ns = None
        elif (
            projection_started_ns is not None
            and now_ns - projection_started_ns
            > int(PROVISIONAL_TERMINAL_GRACE_SECONDS * 1_000_000_000)
        ):
            raise AppServerError("capability-uncorroborated-terminal-projection:unresolved")
        decision = (
            "ready"
            if ready and projected_status == "active"
            else "continue-active"
            if projected_status == "active"
            else "continue-pending"
        )
        append_control_observation(
            phase=phase,
            projected_status=projected_status,
            durable_status=None,
            source_identity_sha256=source_identity_sha256,
            previous_boundary=previous_boundary,
            boundary=boundary,
            decision=decision,
        )
        return ready and projected_status == "active"

    def observe(
        phase: str = "materialization",
        *,
        read_timeout_seconds: float = THREAD_READ_TIMEOUT_SECONDS,
        guarded_recovery_read: bool = False,
    ) -> tuple[dict[str, Any], dict[str, Any] | None]:
        nonlocal attestation_observed, trusted_source_identity, observed_prefix
        if guarded_recovery_read:
            def pre_dispatch_guard() -> Mapping[str, Any]:
                if (
                    read_recovery.get("token_consumed") is not True
                    or read_recovery.get("replacement_attempt_count") != 1
                    or read_recovery.get("wire_dispatch_count") != 0
                    or attestation_observed
                    or server.connection_epoch_sha256
                    != read_recovery.get("connection_epoch_sha256")
                ):
                    raise AppServerError(
                        "capability-read-recovery-predispatch-state-invalid"
                    )
                capture_recovery_workspace("before-dispatch")
                dispatch_boundary, classification = capture_recovery_boundary(
                    "before-dispatch"
                )
                if (
                    dispatch_boundary.get("record_count")
                    != read_recovery.get("fault_boundary_record_count")
                    or dispatch_boundary.get("byte_offset")
                    != read_recovery.get("fault_boundary_byte_offset")
                    or dispatch_boundary.get("boundary_sha256")
                    != read_recovery.get("prior_boundary_sha256")
                    or trusted_source_identity
                    != read_recovery.get("prior_source_identity_sha256")
                    or classification
                    != read_recovery.get("fault_boundary_classification")
                ):
                    raise AppServerError(
                        "capability-read-recovery-boundary-changed-before-dispatch"
                    )
                read_recovery.update(
                    {
                        "pre_dispatch_source_identity_sha256": (
                            trusted_source_identity
                        ),
                        "pre_dispatch_boundary_sha256": dispatch_boundary[
                            "boundary_sha256"
                        ],
                        "pre_dispatch_boundary_record_count": int(
                            dispatch_boundary["record_count"]
                        ),
                        "pre_dispatch_boundary_byte_offset": int(
                            dispatch_boundary["byte_offset"]
                        ),
                        "pre_dispatch_boundary_classification": classification,
                        # Consumed before the one write.  Any write or response
                        # ambiguity remains a terminal consumed attempt.
                        "wire_dispatch_count": 1,
                        "transport_outcome": "dispatch-attempted",
                    }
                )
                return {
                    "boundary_sha256": dispatch_boundary["boundary_sha256"],
                    "byte_offset": dispatch_boundary["byte_offset"],
                    "record_count": dispatch_boundary["record_count"],
                    "source_identity_sha256": trusted_source_identity,
                    "classification": classification,
                    "connection_epoch_sha256": server.connection_epoch_sha256,
                }

            (
                thread,
                _latency,
                guarded_boundary,
                wire_request_id,
                wire_request_sha256,
            ) = server.read_thread_once_with_guard(
                thread_id,
                timeout=read_timeout_seconds,
                pre_dispatch_guard=pre_dispatch_guard,
            )
            if (
                guarded_boundary.get("boundary_sha256")
                != read_recovery.get("pre_dispatch_boundary_sha256")
                or guarded_boundary.get("connection_epoch_sha256")
                != server.connection_epoch_sha256
            ):
                raise AppServerError(
                    "capability-read-recovery-guard-return-invalid"
                )
            read_recovery.update(
                {
                    "wire_request_id": wire_request_id,
                    "wire_request_sha256": wire_request_sha256,
                    "wire_response_correlation_sha256": domain_sha256(
                        {
                            "connection_epoch_sha256": (
                                server.connection_epoch_sha256
                            ),
                            "thread_id": thread_id,
                            "turn_id": turn_id,
                            "request_id": wire_request_id,
                            "request_sha256": wire_request_sha256,
                        },
                        domain="calibration-thread-read-recovery-response",
                    ),
                    "transport_outcome": "response-correlated",
                }
            )
        else:
            thread, _latency = server.read_thread(
                thread_id,
                timeout=read_timeout_seconds,
            )
        projected_status = normalize_projected_status(turn_status(thread, turn_id))
        previous_boundary = dict(observed_prefix)
        try:
            located, boundary, records, materialized = (
                preattestation_boundary.capture(
                    baseline=observed_prefix,
                )
            )
        except NativeSessionBoundaryError as exc:
            error = str(exc)
            if error == "pinned trusted session source is missing":
                raise AppServerError(
                    "capability-pinned-session-source-missing"
                ) from exc
            if error in {
                "trusted session source changed after pinning",
                "trusted session source identity changed after pinning",
                "trusted session source is unlinked",
            }:
                raise AppServerError(
                    "capability-session-source-identity-changed"
                ) from exc
            raise AppServerError(
                f"capability-session-boundary-invalid:{exc}"
            ) from exc
        if located is not None and trusted_source_identity is None:
            trusted_source_identity = located.source_identity_sha256
        elif (
            located is not None
            and trusted_source_identity != located.source_identity_sha256
        ):
            raise AppServerError("capability-session-source-identity-changed")
        observed_prefix = dict(boundary)
        if guarded_recovery_read:
            capture_recovery_workspace("post-read")
            read_recovery.update(
                {
                    "post_read_boundary_sha256": boundary["boundary_sha256"],
                    "post_read_boundary_record_count": int(
                        boundary["record_count"]
                    ),
                    "post_read_boundary_byte_offset": int(boundary["byte_offset"]),
                }
            )
        if not materialized:
            record_nonterminal_projection(
                phase=phase,
                projected_status=projected_status,
                boundary_available=False,
                ready=False,
                source_identity_sha256=(
                    located.source_identity_sha256
                    if located is not None
                    else None
                ),
                previous_boundary=previous_boundary,
                boundary=boundary,
            )
            return thread, None
        assert located is not None
        try:
            terminal_event = trusted_terminal_event(records, turn_id=turn_id)
        except NativeSessionBoundaryError as exc:
            raise AppServerError(f"capability-terminal-grammar-invalid:{exc}") from exc
        contexts = [
            (index, record["payload"])
            for index, record in enumerate(records)
            if record.get("type") == "turn_context"
            and isinstance(record.get("payload"), Mapping)
            and (record["payload"].get("turn_id") or record["payload"].get("turnId")) == turn_id
        ]
        if contexts and any(
            context.get("model") != EXACT_MODEL
            or (context.get("effort") or context.get("reasoning_effort")) != "low"
            for _index, context in contexts
        ):
            raise AppServerError("capability-trusted-model-effort-mismatch")
        if len(contexts) > 1:
            raise AppServerError("capability-current-turn-context-not-singular")
        if len(contexts) == 1:
            attestation_observed = True
        markers = telemetry_markers(records, turn_id=turn_id)
        if markers["compaction_indices"] or markers["reroute_indices"]:
            raise AppServerError("capability-session-containment-failed")
        if terminal_event is not None:
            raise AppServerError(
                "capability-terminal-event-before-deliberate-interrupt:"
                + str(terminal_event["status"])
            )

        def finish(
            observation: dict[str, Any] | None,
        ) -> tuple[dict[str, Any], dict[str, Any] | None]:
            usable = record_nonterminal_projection(
                phase=phase,
                projected_status=projected_status,
                boundary_available=True,
                ready=observation is not None,
                source_identity_sha256=located.source_identity_sha256,
                previous_boundary=previous_boundary,
                boundary=boundary,
            )
            return thread, observation if usable else None
        events = server.notification_events(
            thread_id,
            turn_id,
            after_sequence=notification_floor,
        )
        started_commands = []
        completed_commands = []
        for event in events:
            params = event["params"]
            item = params.get("item") if isinstance(params.get("item"), Mapping) else {}
            if item.get("type") != "commandExecution":
                continue
            if event.get("method") == "item/started":
                started_commands.append((event, item))
            elif event.get("method") == "item/completed":
                completed_commands.append((event, item))
        if len(started_commands) > 1:
            raise AppServerError("capability-command-start-not-singular")
        if completed_commands:
            raise AppServerError("capability-command-completed-before-interrupt")
        if not contexts or not started_commands:
            return finish(None)
        context_index, _context = trusted_turn_context(
            records,
            turn_id=turn_id,
            model=EXACT_MODEL,
            effort="low",
        )
        start_event, command = started_commands[0]
        if start_event.get("connection_epoch_sha256") != server.connection_epoch_sha256:
            raise AppServerError("capability-notification-connection-epoch-mismatch")
        started_at_ms = start_event["params"].get("startedAtMs")
        if (
            isinstance(started_at_ms, bool)
            or not isinstance(started_at_ms, int)
            or started_at_ms < 0
        ):
            raise AppServerError("capability-command-start-time-invalid")
        item_id = command.get("id")
        if not isinstance(item_id, str) or not item_id:
            raise AppServerError("capability-command-item-identity-invalid")
        if "source" not in command:
            raise AppServerError("capability-command-source-missing")
        if command.get("source") != "unifiedExecStartup":
            raise AppServerError("capability-command-source-invalid")
        if command.get("status") in {"completed", "failed", "declined"}:
            raise AppServerError(
                f"capability-command-terminal-before-interrupt:{command.get('status')}"
            )
        if command.get("status") != "inProgress":
            return finish(None)
        function_calls: list[tuple[int, Mapping[str, Any]]] = []
        function_outputs: list[tuple[int, Mapping[str, Any]]] = []
        competing_calls: list[int] = []
        for index, record in enumerate(records[context_index + 1 :], context_index + 1):
            if record.get("type") != "response_item" or not isinstance(
                record.get("payload"), Mapping
            ):
                continue
            payload = record["payload"]
            if payload.get("type") in {"function_call", "functionCall"}:
                if payload.get("name") == "exec_command":
                    function_calls.append((index, payload))
                else:
                    competing_calls.append(index)
            elif payload.get("type") in {"function_call_output", "functionCallOutput"}:
                function_outputs.append((index, payload))
        if competing_calls or len(function_calls) > 1:
            raise AppServerError("capability-function-call-not-singular")
        if function_outputs:
            raise AppServerError("capability-function-output-before-interrupt")
        if not function_calls:
            return finish(None)
        function_call_index, function_call = function_calls[0]
        call_id = function_call.get("call_id") or function_call.get("callId")
        if not isinstance(call_id, str) or not call_id:
            raise AppServerError("capability-function-call-identity-invalid")
        arguments = function_call.get("arguments")
        if not isinstance(arguments, str):
            raise AppServerError("capability-function-call-arguments-invalid")
        try:
            parsed_arguments = json.loads(arguments)
        except json.JSONDecodeError as exc:
            raise AppServerError("capability-function-call-arguments-invalid") from exc
        if not isinstance(parsed_arguments, Mapping) or not isinstance(
            parsed_arguments.get("cmd"), str
        ):
            raise AppServerError("capability-function-call-command-missing")
        if sha256_text(str(parsed_arguments["cmd"])) != sha256_text("sleep 20"):
            raise AppServerError("capability-function-call-command-digest-mismatch")
        try:
            rendered_command_sha256 = validate_capability_rendered_command(
                command.get("command"), raw_command=str(parsed_arguments["cmd"])
            )
        except NativeCanaryContractError as exc:
            raise AppServerError(f"capability-{exc}") from exc
        command_cwd = command.get("cwd")
        if not isinstance(command_cwd, str) or not command_cwd:
            raise AppServerError("capability-notification-workspace-missing")
        try:
            notification_workspace = Path(command_cwd).resolve(strict=True)
            expected_workspace = cwd.resolve(strict=True)
        except OSError as exc:
            raise AppServerError("capability-notification-workspace-unresolvable") from exc
        if notification_workspace != expected_workspace:
            raise AppServerError("capability-notification-workspace-mismatch")
        command_item_id_sha256 = domain_sha256(
            {"item_id": item_id}, domain="app-server-command-item-id"
        )
        function_call_id_sha256 = domain_sha256(
            {"call_id": call_id}, domain="session-exec-command-call-id"
        )
        raw_command_sha256 = sha256_text(str(parsed_arguments["cmd"]))
        execution_correlation_sha256 = materialization_execution_correlation(
            connection_epoch_sha256=str(start_event["connection_epoch_sha256"]),
            session_id=thread_id,
            thread_id=thread_id,
            turn_id=turn_id,
            command_item_id_sha256=command_item_id_sha256,
            function_call_id_sha256=function_call_id_sha256,
            notification_sequence=int(start_event["sequence"]),
            notification_received_monotonic_ns=int(
                start_event["received_monotonic_ns"]
            ),
            notification_started_at_ms=started_at_ms,
            turn_context_record_index=context_index,
            function_call_record_index=function_call_index,
            rendered_command_sha256=rendered_command_sha256,
            raw_command_sha256=raw_command_sha256,
        )
        return finish({
            "observed_at": iso(),
            "boundary": public_boundary(boundary),
            "session_source_identity_sha256": located.source_identity_sha256,
            "connection_epoch_sha256": str(start_event["connection_epoch_sha256"]),
            "notification_sequence": int(start_event["sequence"]),
            "notification_received_monotonic_ns": int(
                start_event["received_monotonic_ns"]
            ),
            "notification_started_at_ms": started_at_ms,
            "turn_context_record_index": context_index,
            "function_call_record_index": function_call_index,
            "command_item_id_sha256": command_item_id_sha256,
            "function_call_id_sha256": function_call_id_sha256,
            "rendered_command_sha256": rendered_command_sha256,
            "execution_correlation_sha256": execution_correlation_sha256,
            "notification_command_semantic_match": True,
            "notification_workspace_match": True,
            "command_source": "unifiedExecStartup",
            "command_status": "inProgress",
            "started_event_count": 1,
            "function_call_count": 1,
            "completed_event_count": 0,
            "paired_result_count": 0,
            "competing_call_count": 0,
            "terminal_event_count": 0,
            "failed_event_count": 0,
            "declined_event_count": 0,
            "ambiguous_event_count": 0,
        })

    def capture_recovery_boundary(stage: str) -> tuple[dict[str, Any], str]:
        """Pin exact-empty or canonical startup truth at every recovery edge."""

        if stage not in {"at-fault", "before-replacement", "before-dispatch"}:
            raise AppServerError("capability-read-recovery-stage-invalid")

        nonlocal attestation_observed, trusted_source_identity, observed_prefix
        previous_boundary = dict(observed_prefix)
        try:
            located, boundary, records, materialized = (
                preattestation_boundary.capture(
                    baseline=previous_boundary,
                )
            )
        except NativeSessionBoundaryError as exc:
            error = str(exc)
            if error == "pinned trusted session source is missing":
                raise AppServerError(
                    "capability-pinned-session-source-missing"
                ) from exc
            if error in {
                "trusted session source changed after pinning",
                "trusted session source identity changed after pinning",
                "trusted session source is unlinked",
            }:
                raise AppServerError(
                    "capability-session-source-identity-changed"
                ) from exc
            raise AppServerError(
                f"capability-read-recovery-fault-boundary-invalid:{exc}"
            ) from exc
        if located is not None and trusted_source_identity is None:
            trusted_source_identity = located.source_identity_sha256
        elif (
            located is not None
            and trusted_source_identity != located.source_identity_sha256
        ):
            raise AppServerError("capability-session-source-identity-changed")
        observed_prefix = dict(boundary)
        if not materialized:
            if located is None:
                raise AppServerError(
                    f"capability-read-recovery-session-source-missing-{stage}"
                )
            if (
                records
                or boundary.get("record_count") != 0
                or boundary.get("byte_offset") != 0
                or boundary.get("boundary_sha256") != sha256_bytes(b"")
                or boundary.get("token_snapshot") is not None
                or trusted_source_identity is None
                or located.source_identity_sha256 != trusted_source_identity
            ):
                raise AppServerError(
                    f"capability-read-recovery-boundary-not-exact-zero-{stage}"
                )
            append_control_observation(
                phase="materialization",
                projected_status="unknown",
                durable_status=None,
                source_identity_sha256=located.source_identity_sha256,
                previous_boundary=previous_boundary,
                boundary=boundary,
                decision="continue-pending",
            )
            return dict(boundary), "exact-empty-pinned-source"
        assert located is not None
        if any(
            record.get("type") == "turn_context"
            and isinstance(record.get("payload"), Mapping)
            and (
                record["payload"].get("turn_id")
                or record["payload"].get("turnId")
            )
            == turn_id
            for record in records
        ):
            attestation_observed = True
            raise AppServerError(
                f"capability-read-recovery-attestation-observed-{stage}"
            )
        markers = telemetry_markers(records, turn_id=turn_id)
        if markers["compaction_indices"] or markers["reroute_indices"]:
            raise AppServerError(
                f"capability-read-recovery-control-activity-observed-{stage}"
            )
        try:
            terminal = trusted_terminal_event(records, turn_id=turn_id)
        except NativeSessionBoundaryError as exc:
            raise AppServerError(
                f"capability-read-recovery-terminal-grammar-invalid-{stage}:{exc}"
            ) from exc
        if terminal is not None:
            raise AppServerError(
                f"capability-read-recovery-terminal-event-observed-{stage}"
            )
        if any(
            record.get("type") == "response_item"
            for record in records
        ):
            raise AppServerError(
                f"capability-read-recovery-operative-activity-observed-{stage}"
            )
        try:
            scaffold = validate_startup_scaffold_records(
                records,
                session_id=thread_id,
                turn_id=turn_id,
                expected_cwd=cwd,
            )
        except NativeSessionBoundaryError as exc:
            raise AppServerError(
                f"capability-read-recovery-startup-scaffold-invalid-{stage}:{exc}"
            ) from exc
        if boundary.get("token_snapshot") is not None:
            raise AppServerError(
                f"capability-read-recovery-startup-scaffold-token-invalid-{stage}"
            )
        append_control_observation(
            phase="materialization",
            projected_status="unknown",
            durable_status=None,
            source_identity_sha256=located.source_identity_sha256,
            previous_boundary=previous_boundary,
            boundary=boundary,
            decision="continue-pending",
        )
        return dict(boundary), str(scaffold["classification"])

    observations: list[dict[str, Any]] = []
    last_threads: dict[str, dict[str, Any]] = {}
    poll_started: list[float] = []
    if materialization_timeout_seconds < 1.0:
        raise AppServerError("capability-materialization-timeout-invalid")
    deadline = time.monotonic() + materialization_timeout_seconds

    def remaining_materialization_seconds() -> float:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AppServerError("capability-materialization-deadline-exceeded")
        return remaining

    def require_poll_start_within_bounds() -> None:
        remaining_materialization_seconds()
        if (
            len(poll_started) > 1
            and poll_started[-1] - poll_started[-2]
            > CALIBRATION_POLL_GAP_MAX_SECONDS
        ):
            raise AppServerError("capability-poll-interval-exceeded")

    def require_recovery_edge_within_bounds(poll_start: float) -> float:
        observed = time.monotonic()
        remaining = deadline - observed
        if remaining <= 0:
            raise AppServerError("capability-materialization-deadline-exceeded")
        if observed - poll_start > CALIBRATION_POLL_GAP_MAX_SECONDS:
            raise AppServerError("capability-poll-interval-exceeded")
        return remaining

    while time.monotonic() < deadline and len(observations) < 2:
        poll_start = time.monotonic()
        poll_started.append(poll_start)
        require_poll_start_within_bounds()
        replacement_attempt = read_recovery_pending
        remaining_before_attempt = remaining_materialization_seconds()
        if replacement_attempt:
            if (
                attestation_observed
                or server.connection_epoch_sha256
                != read_recovery["connection_epoch_sha256"]
            ):
                raise attach_recovery_fault(
                    AppServerError("capability-read-recovery-identity-invalid")
                )
            try:
                pre_attempt_boundary, pre_attempt_classification = (
                    capture_recovery_boundary("before-replacement")
                )
            except AppServerError as exc:
                raise attach_recovery_fault(exc) from exc
            if (
                pre_attempt_boundary["record_count"]
                != read_recovery["fault_boundary_record_count"]
                or pre_attempt_boundary["byte_offset"]
                != read_recovery["fault_boundary_byte_offset"]
                or pre_attempt_boundary["boundary_sha256"]
                != read_recovery["prior_boundary_sha256"]
                or trusted_source_identity
                != read_recovery["prior_source_identity_sha256"]
                or pre_attempt_classification
                != read_recovery["fault_boundary_classification"]
            ):
                raise attach_recovery_fault(
                    AppServerError(
                        "capability-read-recovery-boundary-changed-before-replacement"
                    )
                )
            if attestation_observed:
                raise attach_recovery_fault(
                    AppServerError(
                        "capability-read-recovery-attestation-observed-before-replacement"
                    )
                )
            try:
                remaining_before_attempt = require_recovery_edge_within_bounds(
                    poll_start
                )
            except AppServerError as exc:
                raise attach_recovery_fault(exc)
            read_recovery_pending = False
            read_recovery["replacement_attempt_count"] = 1
            read_recovery["remaining_deadline_ms_before_attempt"] = round(
                remaining_before_attempt * 1000,
                3,
            )
            read_recovery["pre_attempt_source_identity_sha256"] = (
                trusted_source_identity
            )
            read_recovery["pre_attempt_boundary_sha256"] = (
                pre_attempt_boundary["boundary_sha256"]
            )
            read_recovery["pre_attempt_boundary_record_count"] = int(
                pre_attempt_boundary["record_count"]
            )
            read_recovery["pre_attempt_boundary_byte_offset"] = int(
                pre_attempt_boundary["byte_offset"]
            )
        try:
            thread, observation = guarded_measure(
                samples,
                "check",
                lambda: observe(
                    read_timeout_seconds=min(
                        THREAD_READ_TIMEOUT_SECONDS,
                        remaining_before_attempt,
                    ),
                    guarded_recovery_read=replacement_attempt,
                ),
                guard_seconds=0.0,
            )
        except AppServerRpcError as exc:
            samples.setdefault("check", []).append(exc.latency_ms)
            if replacement_attempt:
                raise attach_recovery_fault(exc)
            eligible = (
                exc.method == "thread/read"
                and type(exc.code) is int
                and exc.code == -32603
                and not attestation_observed
                and read_recovery["token_consumed"] is False
                and server.connection_epoch_sha256
                == read_recovery["connection_epoch_sha256"]
            )
            if not eligible:
                raise
            remaining_before_scheduling = require_recovery_edge_within_bounds(
                poll_start
            )
            read_recovery.update(
                {
                    "method": exc.method,
                    "code": exc.code,
                    "phase": "materialization",
                    "failed_callback_latency_ms": round(exc.latency_ms, 3),
                    "remaining_deadline_ms_before_scheduling": round(
                        remaining_before_scheduling * 1000,
                        3,
                    ),
                    "attestation_observed_at_fault": bool(attestation_observed),
                }
            )
            try:
                capture_recovery_workspace("at-fault")
                fault_boundary, fault_classification = capture_recovery_boundary(
                    "at-fault"
                )
            except AppServerError as boundary_exc:
                raise attach_recovery_fault(boundary_exc) from boundary_exc
            if attestation_observed:
                raise attach_recovery_fault(
                    AppServerError(
                        "capability-read-recovery-attestation-observed-at-fault"
                    )
                )
            read_recovery.update(
                {
                    "token_consumed": True,
                    "attestation_observed_at_fault": False,
                    "prior_source_identity_sha256": trusted_source_identity,
                    "prior_boundary_sha256": fault_boundary["boundary_sha256"],
                    "fault_boundary_record_count": int(
                        fault_boundary["record_count"]
                    ),
                    "fault_boundary_byte_offset": int(
                        fault_boundary["byte_offset"]
                    ),
                    "fault_boundary_classification": fault_classification,
                }
            )
            read_recovery_pending = True
            continue
        except AppServerError as exc:
            if read_recovery.get("token_consumed") is True:
                raise attach_recovery_fault(exc)
            raise
        if replacement_attempt:
            try:
                require_recovery_edge_within_bounds(poll_start)
            except AppServerError as exc:
                raise attach_recovery_fault(exc)
            if (
                server.connection_epoch_sha256
                != read_recovery["connection_epoch_sha256"]
            ):
                raise attach_recovery_fault(
                    AppServerError("capability-read-recovery-identity-invalid")
                )
            read_recovery["outcome"] = "recovered"
        last_threads[thread_id] = thread
        if observation is not None:
            if not observations:
                observations.append(observation)
            else:
                first_time = dt.datetime.fromisoformat(
                    observations[0]["observed_at"].replace("Z", "+00:00")
                )
                current_time = dt.datetime.fromisoformat(
                    observation["observed_at"].replace("Z", "+00:00")
                )
                if (current_time - first_time).total_seconds() >= 1.0:
                    if any(
                        observations[0][field] != observation[field]
                        for field in (
                            "session_source_identity_sha256",
                            "connection_epoch_sha256",
                            "notification_sequence",
                            "notification_received_monotonic_ns",
                            "notification_started_at_ms",
                            "turn_context_record_index",
                            "function_call_record_index",
                            "command_item_id_sha256",
                            "function_call_id_sha256",
                            "rendered_command_sha256",
                            "execution_correlation_sha256",
                        )
                    ):
                        raise AppServerError("capability-observation-identity-changed")
                    observations.append(observation)
        elapsed = time.monotonic() - poll_start
        if len(observations) < 2:
            time.sleep(
                max(0.0, CALIBRATION_POLL_INTERVAL_SECONDS - elapsed)
            )
    if len(observations) != 2:
        raise AppServerError("capability-materialization-deadline-exceeded")
    pre_interrupt: dict[str, Any] | None = None
    pre_thread: dict[str, Any] | None = None
    while time.monotonic() < deadline and pre_interrupt is None:
        poll_start = time.monotonic()
        poll_started.append(poll_start)
        require_poll_start_within_bounds()
        remaining_before_attempt = remaining_materialization_seconds()
        pre_thread, pre_interrupt = guarded_measure(
            samples,
            "check",
            lambda: observe(
                "pre-interrupt",
                read_timeout_seconds=min(
                    THREAD_READ_TIMEOUT_SECONDS,
                    remaining_before_attempt,
                ),
            ),
            guard_seconds=0.0,
        )
        last_threads[thread_id] = pre_thread
        if pre_interrupt is None:
            time.sleep(
                max(
                    0.0,
                    CALIBRATION_POLL_INTERVAL_SECONDS
                    - (time.monotonic() - poll_start),
                )
            )
    if any(
        later - earlier > CALIBRATION_POLL_GAP_MAX_SECONDS
        for earlier, later in zip(poll_started, poll_started[1:])
    ):
        raise AppServerError("capability-poll-interval-exceeded")
    if pre_interrupt is None or any(
        pre_interrupt[field] != observations[-1][field]
        for field in (
            "session_source_identity_sha256",
            "connection_epoch_sha256",
            "notification_sequence",
            "notification_received_monotonic_ns",
            "notification_started_at_ms",
            "turn_context_record_index",
            "function_call_record_index",
            "command_item_id_sha256",
            "function_call_id_sha256",
            "rendered_command_sha256",
            "execution_correlation_sha256",
        )
    ):
        raise AppServerError("capability-immediate-revalidation-failed")
    interrupt_requested_at = iso()
    guarded_measure(
        samples,
        "interrupt",
        lambda: server.interrupt_turn(thread_id, turn_id),
        guard_seconds=0.0,
    )
    interrupt_request_accepted_at = iso()
    interrupt_deadline = time.monotonic() + 5.0
    interrupt_confirmed_at: str | None = None
    confirmed_terminal_event: dict[str, Any] | None = None
    while time.monotonic() < interrupt_deadline:
        thread, _latency = server.read_thread(thread_id)
        last_threads[thread_id] = thread
        previous_boundary = dict(observed_prefix)
        try:
            (
                interrupt_location,
                interrupt_boundary,
                interrupt_records,
                interrupt_materialized,
            ) = preattestation_boundary.capture(
                    baseline=observed_prefix,
            )
            if not interrupt_materialized or interrupt_location is None:
                raise NativeSessionBoundaryError(
                    "interrupt session boundary is not materialized"
                )
            interrupt_terminal_event = trusted_terminal_event(
                interrupt_records, turn_id=turn_id
            )
        except NativeSessionBoundaryError as exc:
            raise AppServerError(
                f"capability-interrupt-boundary-invalid:{exc}"
            ) from exc
        if interrupt_location.source_identity_sha256 != trusted_source_identity:
            raise AppServerError("capability-interrupt-session-source-identity-changed")
        interrupt_markers = telemetry_markers(interrupt_records, turn_id=turn_id)
        if (
            interrupt_markers["compaction_indices"]
            or interrupt_markers["reroute_indices"]
        ):
            raise AppServerError("capability-interrupt-containment-failed")
        observed_prefix = dict(interrupt_boundary)
        durable_status = (
            str(interrupt_terminal_event["status"])
            if interrupt_terminal_event is not None
            else None
        )
        if durable_status in {"completed", "failed"}:
            raise AppServerError(
                f"capability-interrupt-race-lost:{durable_status}"
            )
        if durable_status == "interrupted":
            append_control_observation(
                phase="interrupt-confirmation",
                projected_status=normalize_projected_status(
                    turn_status(thread, turn_id)
                ),
                durable_status="interrupted",
                source_identity_sha256=interrupt_location.source_identity_sha256,
                previous_boundary=previous_boundary,
                boundary=interrupt_boundary,
                decision="interrupt-confirmed",
            )
            confirmed_terminal_event = dict(interrupt_terminal_event)
            interrupt_confirmed_at = iso()
            break
        append_control_observation(
            phase="interrupt-confirmation",
            projected_status=normalize_projected_status(turn_status(thread, turn_id)),
            durable_status=None,
            source_identity_sha256=interrupt_location.source_identity_sha256,
            previous_boundary=previous_boundary,
            boundary=interrupt_boundary,
            decision="interrupt-pending",
        )
        time.sleep(0.05)
    if interrupt_confirmed_at is None or confirmed_terminal_event is None:
        raise AppServerError("capability-interrupt-not-confirmed")

    guarded_measure(
        samples,
        "finalize",
        lambda: write_private_artifact(
            record_dir / "calibration-finalize.json",
            {"thread_id": thread_id, "turn_id": turn_id, "control_turn_id": CONTROL_TURN_ID},
        ),
        guard_seconds=0.0,
    )
    guarded_measure(
        samples,
        "close",
        lambda: server.archive_thread(thread_id),
        guard_seconds=0.0,
    )
    previous_boundary = dict(observed_prefix)
    try:
        (
            terminal_location,
            terminal_boundary,
            terminal_records,
            terminal_materialized,
        ) = preattestation_boundary.capture(
            baseline=observed_prefix,
            allow_archive_transition=True,
        )
        if not terminal_materialized or terminal_location is None:
            raise NativeSessionBoundaryError(
                "terminal session boundary is not materialized"
            )
        terminal_event = trusted_terminal_event(terminal_records, turn_id=turn_id)
    except NativeSessionBoundaryError as exc:
        raise AppServerError(f"capability-terminal-boundary-invalid:{exc}") from exc
    terminal_markers = telemetry_markers(terminal_records, turn_id=turn_id)
    if terminal_location.source_identity_sha256 != trusted_source_identity:
        raise AppServerError("capability-terminal-session-source-identity-changed")
    if terminal_markers["compaction_indices"] or terminal_markers["reroute_indices"]:
        raise AppServerError("capability-terminal-containment-failed")
    if terminal_event != confirmed_terminal_event or terminal_event is None:
        raise AppServerError("capability-terminal-interrupt-proof-changed")
    if terminal_event.get("status") != "interrupted":
        raise AppServerError("capability-terminal-interrupt-proof-invalid")
    observed_prefix = dict(terminal_boundary)
    append_control_observation(
        phase="terminal",
        projected_status=normalize_projected_status(
            turn_status(last_threads[thread_id], turn_id)
        ),
        durable_status="interrupted",
        source_identity_sha256=terminal_location.source_identity_sha256,
        previous_boundary=previous_boundary,
        boundary=terminal_boundary,
        decision="terminal-accepted",
    )
    if trusted_source_identity is None:
        raise AppServerError("capability-session-source-identity-not-pinned")
    read_recovery_telemetry = seal_calibration_read_recovery_telemetry(
        read_recovery
    )
    materialization = seal_materialization_evidence(
        {
            "evidence_type": MATERIALIZATION_EVIDENCE_TYPE,
            "version": 4,
            "schema": MATERIALIZATION_EVIDENCE_SCHEMA,
            "evidence_id": f"materialization-{uuid.uuid4()}",
            "run_nonce": run_nonce,
            "attempt_nonce": attempt_nonce,
            "phase_nonce": phase_nonce,
            "session_id": thread_id,
            "thread_id": thread_id,
            "turn_id": turn_id,
            "requested_model": EXACT_MODEL,
            "attested_model": EXACT_MODEL,
            "attested_effort": "low",
            "attestation_source": (
                "initialized-codex-home-session-jsonl-and-local-app-server-stdio-notifications"
            ),
            "connection_epoch_sha256": server.connection_epoch_sha256,
            "command_sha256": sha256_text("sleep 20"),
            "session_source_identity_sha256": trusted_source_identity,
            "baseline": public_boundary(strict_baseline),
            "control_observations": control_observations,
            "liveness_observations": observations,
            "pre_interrupt_observation": pre_interrupt,
            "interrupt": {
                "requested_at": interrupt_requested_at,
                "request_accepted_at": interrupt_request_accepted_at,
                "confirmed_at": interrupt_confirmed_at,
                "session_id": thread_id,
                "thread_id": thread_id,
                "turn_id": turn_id,
                "request_outcome": "accepted",
                "outcome": "interrupt-confirmed",
            },
            "terminal": public_boundary(terminal_boundary),
            "terminal_event": terminal_event,
            "status": "interrupt-confirmed",
            "disposition": "accepted",
        }
    )
    materialization_errors = validate_materialization_evidence(
        materialization, require_accepting=True
    )
    if materialization_errors:
        raise AppServerError(
            "capability-materialization-evidence-invalid:" + ";".join(materialization_errors)
        )

    scheduler_samples: list[float] = []
    children = [
        {"child_id": "a", "next_deadline_ns": 1_000_000_000},
        {"child_id": "b", "next_deadline_ns": 1_000_000_000},
    ]
    cursor = 0
    for _index in range(4):
        started = time.monotonic_ns()
        selected = select_earliest_deadline(children, cursor=cursor)
        if selected is None:
            raise AppServerError("scheduler-calibration-selection-missing")
        cursor = selected.next_cursor
        time.sleep(0.05)
        scheduler_samples.append((time.monotonic_ns() - started) / 1_000_000)

    measured_at = utc_now()
    receipt = seal_artifact(
        {
            "receipt_type": CAPABILITY_RECEIPT_TYPE,
            "version": 1,
            "schema": CAPABILITY_RECEIPT_SCHEMA,
            "adapter_id": "native-multi-agent-v1",
            "adapter_version": "codex-app-server-0.144.5",
            "execution_surface": "connected-codex",
            "host_identity": dict(owner),
            "control_turn_id": CONTROL_TURN_ID,
            "measured_at": iso(measured_at),
            "expires_at": iso(measured_at + dt.timedelta(minutes=55)),
            "sample_count": min(len(values) for values in samples.values()),
            "requested_cap": 2,
            "clock": "monotonic_ns",
            "callbacks": {name: stats(samples[name]) for name in sorted(samples)},
            "scheduler_overhead": stats(scheduler_samples),
            "certification": capability_certification(),
            "capabilities": {
                "interrupt": True,
                "close": True,
                "wait": True,
                "trusted_telemetry": True,
            },
            "attestation_source": "trusted-control-plane-session-metadata",
            "validation_outcome": "accepted",
        },
        "receipt_sha256",
    )
    errors = validate_capability_receipt(receipt, now=utc_now())
    if errors:
        raise AppServerError("capability-receipt-invalid:" + ";".join(errors))
    ceilings = receipt["certification"]["certified_callback_max_ms"]
    check_max = ceilings["check"]
    lifecycle_max = max(ceilings.values())
    overhead_max = receipt["certification"]["certified_scheduler_overhead_ms"]
    if lifecycle_max + 2 * check_max + overhead_max > 1000:
        raise AppServerError("capability-response-time-bound-failed")

    thread = last_threads[thread_id]
    try:
        (
            summary_location,
            summary_boundary,
            summary_records,
            summary_materialized,
        ) = preattestation_boundary.capture(baseline=terminal_boundary)
        if not summary_materialized or summary_location is None:
            raise NativeSessionBoundaryError(
                "final session summary boundary is not materialized"
            )
        boundary = captured_session_boundary_summary(
            summary_location,
            summary_boundary,
            summary_records,
            turn_id=turn_id,
        )
    except NativeSessionBoundaryError as exc:
        raise AppServerError(
            f"capability-final-session-boundary-invalid:{exc}"
        ) from exc
    summary = {
        "thread_id": thread_id,
        "turn_id": turn_id,
        "thread_start_model": result.get("model"),
        "thread_start_model_provider": result.get("modelProvider"),
        "turn_status": turn_status(thread, turn_id),
        "session_boundary": boundary,
        "final_response_sha256": None,
        "expected_final_token_observed": False,
        "reroute_count": len(server.notifications(thread_id, "model/rerouted")),
        "compactions": len(server.notifications(thread_id, "thread/compacted"))
        + int(boundary.get("compactions", 0)),
    }
    if summary["thread_start_model"] != EXACT_MODEL:
        raise AppServerError("capability-thread-start-model-mismatch")
    if summary["session_boundary"].get("attested_models") != [EXACT_MODEL]:
        raise AppServerError("capability-session-model-mismatch")
    if summary["session_boundary"].get("attested_efforts") != ["low"]:
        raise AppServerError("capability-session-effort-mismatch")
    if summary["compactions"] or summary["reroute_count"]:
        raise AppServerError("capability-session-containment-failed")

    evidence = {
        "thread_preallocation_stats": stats([preallocation_latency]),
        "guard_band_ms": {"callbacks": 0, "scheduler_overhead": 50},
        "sessions": [summary],
        "materialization_evidence": materialization,
        "materialization_evidence_sha256": materialization["evidence_sha256"],
        "thread_read_recovery": read_recovery_telemetry,
        "thread_read_recovery_sha256": read_recovery_telemetry[
            "telemetry_sha256"
        ],
        "poll_interval_max_ms": round(
            max(
                (later - earlier) * 1000
                for earlier, later in zip(poll_started, poll_started[1:])
            ),
            3,
        ) if len(poll_started) > 1 else 0.0,
        "interrupt_confirmed": True,
        "peer_completion_deferred_to_coordinator_interrupt_canary": True,
        "scheduler_inequality_lhs_ms": round(
            lifecycle_max + 2 * check_max + overhead_max, 3
        ),
        "scheduler_inequality_rhs_ms": 1000,
    }
    return receipt, evidence


def calibration(
    server: AppServer,
    cwd: Path,
    record_dir: Path,
    owner: Mapping[str, Any],
    *,
    run_nonce: str,
    phase_nonce: str,
    materialization_timeout_seconds: float = 10.0,
    pre_allocation_check: Callable[[], None] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Run one calibration and deterministically release every pinned source."""

    boundary_trackers: list[PreAttestationSessionBoundaryTracker] = []
    try:
        return _run_calibration(
            server,
            cwd,
            record_dir,
            owner,
            run_nonce=run_nonce,
            phase_nonce=phase_nonce,
            boundary_trackers=boundary_trackers,
            materialization_timeout_seconds=materialization_timeout_seconds,
            pre_allocation_check=pre_allocation_check,
        )
    finally:
        for tracker in reversed(boundary_trackers):
            tracker.close()


def make_git_layout(root: Path) -> dict[str, Path]:
    integration = root / "integration"
    integration.mkdir()
    run_git(integration, "init", "-q")
    run_git(integration, "config", "user.name", "CWO Live Canary")
    run_git(integration, "config", "user.email", "cwo-canary@example.invalid")
    (integration / "data").mkdir()
    (integration / "targets").mkdir()
    (integration / "data" / "shared.txt").write_text("trusted-read-only-baseline\n", encoding="utf-8")
    (integration / "targets" / "child_0.txt").write_text("baseline-0\n", encoding="utf-8")
    (integration / "targets" / "child_1.txt").write_text("baseline-1\n", encoding="utf-8")
    run_git(integration, "add", ".")
    run_git(integration, "commit", "-qm", "canary baseline")
    paths: dict[str, Path] = {"integration": integration}
    for name in ("read-shared", "mutable-0", "mutable-1", "interrupt-shared"):
        target = root / name
        run_git(
            integration,
            "worktree",
            "add",
            "-q",
            "-b",
            f"cwo-18w6-{name}",
            str(target),
            "HEAD",
        )
        paths[name] = target
    return paths


def build_pool_inputs(
    server: AppServer,
    capability_receipt: Mapping[str, Any],
    campaign_manifest: Mapping[str, Any],
    *,
    root: Path,
    integration: Path,
    pool_name: str,
    worktrees: list[Path],
    mutable: bool,
    prompts: list[str],
    expected_tokens: list[str],
    pre_thread_start_check: Callable[[], Mapping[str, Any] | None],
    pre_allocation_check: Callable[[], None] | None = None,
    expected_bound_manifest_validation: Mapping[str, Any] | None = None,
    interrupt_after: list[int | None] | None = None,
) -> tuple[
    dict[str, Any],
    dict[str, dict[str, Any]],
    dict[str, LiveThreadAdapter],
    PoolWorkspaceMonitor,
]:
    record_dir = root / f"{pool_name}-records"
    thread_results = []
    bound_manifest_validation: Mapping[str, Any] | None = None
    for index, worktree in enumerate(worktrees):
        # The receipt is validation evidence, not authority.  Re-run the full
        # bound source check immediately before every allocation; the durable
        # claim acquired by main remains the one-shot launch authority.
        bound_manifest_validation = pre_thread_start_check()
        manifest_gate_errors = validate_live_canary_manifest_gate(
            campaign_manifest,
            bound_manifest_validation,
            expected_bound_manifest_validation,
        )
        if manifest_gate_errors:
            raise AppServerError(
                "campaign-manifest-invalid-before-thread-start:"
                + ";".join(manifest_gate_errors)
            )
        if campaign_manifest.get("control_turn_id") != CONTROL_TURN_ID:
            raise AppServerError("campaign-control-turn-invalid-before-thread-start")
        role = f"{pool_name}-{index}"
        if pre_allocation_check is not None:
            pre_allocation_check()
        result, _latency = server.start_thread(worktree, mutable=mutable, role=role)
        thread_results.append(result)
    record_dir.mkdir(mode=0o700)
    children = []
    child_contracts: dict[str, dict[str, Any]] = {}
    adapters: dict[str, LiveThreadAdapter] = {}
    for index, (result, worktree, prompt, expected_token) in enumerate(
        zip(thread_results, worktrees, prompts, expected_tokens)
    ):
        child_id = f"{pool_name}-child-{index}"
        thread_id = str(result["thread"]["id"])
        state_file = record_dir / f"{child_id}-worker-state.json"
        control_file = record_dir / f"{child_id}-control-contract.json"
        control_turn_id = f"{CONTROL_TURN_ID}:{pool_name}:{index}"
        packet_sha256 = sha256_text(
            json.dumps(
                {
                    "pool": pool_name,
                    "child": index,
                    "prompt_sha256": sha256_text(prompt),
                    "thread_id": thread_id,
                },
                sort_keys=True,
            )
        )
        control = build_control_turn_contract(
            state_file=str(state_file),
            agent_id=thread_id,
            control_turn_id=control_turn_id,
            task_sha256=sha256_text(prompt),
            poll_interval_ms=1000,
        )
        state = {
            "result_type": "cwo-native-supervision-state",
            "version": 1,
            "schema": "schemas/native-supervision-state.schema.json",
            "packet_id": f"{pool_name}-packet-{uuid.uuid4()}",
            "packet_sha256": packet_sha256,
            "agent_id": thread_id,
            "session_id": thread_id,
            "status": "created",
            "control_turn_id": None,
            "poll_interval_ms": 1000,
            "control_adapter": "native-multi-agent-v1",
            "required_capabilities": ["interrupt", "close", "wait"],
        }
        write_private_artifact(control_file, control)
        write_private_artifact(state_file, state)
        target = f"targets/child_{index}.txt" if mutable else None
        child = {
            "child_id": child_id,
            "packet_id": state["packet_id"],
            "attempt_nonce": f"{pool_name}-attempt-{uuid.uuid4()}",
            "session_id": thread_id,
            "agent_id": thread_id,
            "control_turn_id": control_turn_id,
            "packet_sha256": packet_sha256,
            "control_contract_file": str(control_file),
            "state_file": str(state_file),
            "worktree": str(worktree),
            "isolation_class": "mutable-isolated" if mutable else "read-only-shared",
            "declared_write_paths": [target] if target else [],
            "integration_target_paths": [target] if target else [],
            "lease_id": f"{pool_name}-lease-{uuid.uuid4()}",
        }
        children.append(child)
        child_contracts[child_id] = control
        adapters[child_id] = LiveThreadAdapter(
            server,
            result,
            prompt=prompt,
            expected_token=expected_token,
            worktree=worktree,
            mutable=mutable,
            expected_mutation=target,
            force_interrupt_after_checks=(interrupt_after or [None, None])[index],
            record_dir=record_dir,
        )
    request = {
        "request_type": "cwo-native-supervision-pool-render-request",
        "version": 1,
        "schema": "schemas/native-supervision-pool-render-request.schema.json",
        "pool_id": f"18w6-{pool_name}-{uuid.uuid4()}",
        "pool_epoch": f"18w6-{pool_name}-epoch-{uuid.uuid4()}",
        "control_turn_id": CONTROL_TURN_ID,
        "created_at": iso(),
        "max_active_workers": 2,
        "aggregate_hard_budget": {
            "tool_calls": 20,
            "runtime_seconds": 300,
            "compactions": 0,
            "full_suite_runs": 0,
            "mutations": 2 if mutable else 0,
        },
        "integration_root": str(integration),
        "children": children,
    }
    contract = build_live_canary_pool_contract(
        request,
        campaign_manifest=campaign_manifest,
        capability_receipt=capability_receipt,
        bound_manifest_validation=bound_manifest_validation,
        expected_bound_manifest_validation=expected_bound_manifest_validation,
        owner_pid=os.getpid(),
        now=utc_now(),
    )
    monitor = PoolWorkspaceMonitor(
        contract,
        integration_root=integration,
        child_worktrees={child_id: adapter.worktree for child_id, adapter in adapters.items()},
    )
    return contract, child_contracts, adapters, monitor


def run_pool_canary(
    server: AppServer,
    capability_receipt: Mapping[str, Any],
    campaign_manifest: Mapping[str, Any],
    *,
    root: Path,
    integration: Path,
    pool_name: str,
    worktrees: list[Path],
    mutable: bool,
    prompts: list[str],
    expected_tokens: list[str],
    pre_thread_start_check: Callable[[], Mapping[str, Any] | None],
    pre_allocation_check: Callable[[], None] | None = None,
    expected_bound_manifest_validation: Mapping[str, Any] | None = None,
    interrupt_after: list[int | None] | None = None,
) -> dict[str, Any]:
    contract, child_contracts, adapters, monitor = build_pool_inputs(
        server,
        capability_receipt,
        campaign_manifest,
        root=root,
        integration=integration,
        pool_name=pool_name,
        worktrees=worktrees,
        mutable=mutable,
        prompts=prompts,
        expected_tokens=expected_tokens,
        pre_thread_start_check=pre_thread_start_check,
        pre_allocation_check=pre_allocation_check,
        expected_bound_manifest_validation=expected_bound_manifest_validation,
        interrupt_after=interrupt_after,
    )
    child_ids = list(adapters)

    def read_child_evidence(*, child_id: str, state_file: str) -> dict[str, Any]:
        if state_file != next(
            child["state_file"] for child in contract["children"] if child["child_id"] == child_id
        ):
            raise AppServerError("child-evidence-state-file-mismatch")
        return adapters[child_id].evidence()

    coordinator = NativePoolCoordinator(
        contract,
        child_contracts,
        {child_id: adapters[child_id].prompt for child_id in child_ids},
        {child_id: adapters[child_id].callbacks() for child_id in child_ids},
        pool_callbacks={
            "monotonic_ns": time.monotonic_ns,
            "sleep": pool_sleep,
            "now_utc": iso,
            "read_child_evidence": read_child_evidence,
            "compare_workspaces": monitor.compare,
        },
        lease_registry=PoolLeaseRegistry(root / f"{pool_name}-leases.json"),
        capability_receipt=capability_receipt,
        state_file=root / f"{pool_name}-pool-state.json",
        decision_file=root / f"{pool_name}-pool-decision.json",
    )
    started = time.monotonic_ns()
    receipt = coordinator.run()
    elapsed = (time.monotonic_ns() - started) / 1_000_000_000
    terminal_state = coordinator.progress()["state"]
    receipt_errors = validate_pool_receipt(
        receipt, contract=contract, terminal_state=terminal_state
    )
    if receipt_errors:
        raise AppServerError("live-pool-receipt-invalid:" + ";".join(receipt_errors))
    if interrupt_after is None and receipt.get("accepting") is not True:
        first_fault = receipt.get("first_protected_fault")
        raise LivePoolProtectedFault(first_fault)
    summaries = [adapters[child_id].final_summary() for child_id in child_ids]
    worker_seconds = float(receipt["worker_seconds"])
    improvement = (
        (worker_seconds - float(receipt["pool_wall_seconds"])) / worker_seconds
        if worker_seconds > 0
        else 0.0
    )
    return {
        "pool_name": pool_name,
        "pool_id": contract["pool_id"],
        "pool_epoch": contract["pool_epoch"],
        "contract_sha256": contract["contract_sha256"],
        "receipt": receipt,
        "receipt_validation_errors": receipt_errors,
        "terminal_state_sha256": terminal_state["state_sha256"],
        "elapsed_seconds": round(elapsed, 3),
        "elapsed_improvement_ratio": round(improvement, 6),
        "sessions": summaries,
        "workspace": {
            "evidence": monitor.last_report["evidence"] if monitor.last_report else None,
            "phase": monitor.last_report["phase"] if monitor.last_report else None,
        },
    }


def validate_campaign(
    capability: Mapping[str, Any],
    calibration_evidence: Mapping[str, Any],
    canaries: list[Mapping[str, Any]],
) -> list[str]:
    errors: list[str] = []
    capability_errors = validate_capability_receipt(capability, now=utc_now())
    errors.extend(f"capability:{item}" for item in capability_errors)
    recovery = calibration_evidence.get("thread_read_recovery")
    recovery_errors = validate_calibration_read_recovery_telemetry(recovery)
    errors.extend(f"capability-read-recovery:{item}" for item in recovery_errors)
    if (
        isinstance(recovery, Mapping)
        and calibration_evidence.get("thread_read_recovery_sha256")
        != recovery.get("telemetry_sha256")
    ):
        errors.append("capability-read-recovery-sha256-mismatch")
    certification = capability["certification"]
    ceilings = certification["certified_callback_max_ms"]
    check_max = ceilings["check"]
    overhead = certification["certified_scheduler_overhead_ms"]
    lifecycle_max = max(ceilings.values())
    if check_max > 200:
        errors.append("capability-check-max-exceeded")
    if lifecycle_max + 2 * check_max + overhead > 1000:
        errors.append("capability-response-time-bound-failed")
    all_sessions = list(calibration_evidence.get("sessions", []))
    for canary in canaries:
        all_sessions.extend(canary.get("sessions", []))
    thread_ids = [session.get("thread_id") for session in all_sessions]
    if len(thread_ids) != 7 or len(thread_ids) != len(set(thread_ids)):
        errors.append("fresh-session-cardinality-or-uniqueness-failed")
    for session in all_sessions:
        boundary = session.get("session_boundary", {})
        if session.get("thread_start_model") != EXACT_MODEL:
            errors.append("session-thread-start-model-mismatch")
        if boundary.get("attested_models") != [EXACT_MODEL]:
            errors.append("session-trusted-model-mismatch")
        if boundary.get("attested_efforts") != ["low"]:
            errors.append("session-trusted-effort-mismatch")
        if boundary.get("trailing_partial"):
            errors.append("session-terminal-boundary-partial")
        if session.get("compactions"):
            errors.append("session-compaction-observed")
        if session.get("reroute_count"):
            errors.append("session-model-reroute-observed")
    by_name = {str(item.get("pool_name")): item for item in canaries}
    for name in ("read-only", "mutable"):
        canary = by_name.get(name, {})
        receipt = canary.get("receipt", {})
        if receipt.get("accepting") is not True or receipt.get("pool_disposition") != "accepted":
            errors.append(f"{name}-pool-not-accepting")
        if receipt.get("reasons"):
            errors.append(f"{name}-protected-reasons-observed")
        if canary.get("elapsed_improvement_ratio", 0) <= 0:
            errors.append(f"{name}-elapsed-improvement-not-positive")
        for session in canary.get("sessions", []):
            if not session.get("expected_final_token_observed"):
                errors.append(f"{name}-invalid-final-response")
    mutable = by_name.get("mutable", {})
    expected_mutations = [["targets/child_0.txt"], ["targets/child_1.txt"]]
    if [session.get("workspace_mutations") for session in mutable.get("sessions", [])] != expected_mutations:
        errors.append("mutable-workspace-attribution-failed")
    read_only = by_name.get("read-only", {})
    if any(session.get("workspace_mutations") for session in read_only.get("sessions", [])):
        errors.append("read-only-workspace-mutation-observed")
    interrupted = by_name.get("interrupt", {})
    receipt = interrupted.get("receipt", {})
    if receipt.get("accepting") is not False or receipt.get("pool_disposition") != "partial":
        errors.append("interrupt-pool-disposition-invalid")
    if receipt.get("reasons"):
        errors.append("interrupt-protected-reasons-observed")
    sessions = interrupted.get("sessions", [])
    if len(sessions) != 2:
        errors.append("interrupt-session-count-invalid")
    else:
        if sessions[0].get("turn_status") != "interrupted" or not sessions[0].get("interrupted"):
            errors.append("independent-interrupt-not-confirmed")
        if sessions[1].get("turn_status") != "completed" or not sessions[1].get(
            "expected_final_token_observed"
        ):
            errors.append("interrupt-peer-did-not-complete")
    if interrupted.get("elapsed_improvement_ratio", 0) <= 0:
        errors.append("interrupt-elapsed-improvement-not-positive")
    for canary in canaries:
        evidence = canary.get("workspace", {}).get("evidence")
        if evidence != {
            "integration_root_clean": True,
            "shared_read_only_clean": True,
            "child_worktrees_clean": True,
        }:
            errors.append(f"{canary.get('pool_name')}-workspace-evidence-not-clean")
        if canary.get("receipt_validation_errors"):
            errors.append(f"{canary.get('pool_name')}-receipt-validation-failed")
    return sorted(set(errors))


def contain_started_threads(server: AppServer) -> dict[str, Any]:
    """Idempotently interrupt, archive, and audit every allocated thread."""

    interrupted: list[str] = []
    archived: list[str] = []
    already_contained: list[str] = []
    ambiguous: list[str] = []
    ledger_errors: list[str] = []
    ledger = getattr(server, "allocation_ledger", None)

    def audit_containment(thread_id: str, outcome: str, status: str | None) -> None:
        if ledger is None:
            return
        try:
            ledger.record_containment_audit(
                thread_id,
                outcome=outcome,
                evidence={
                    "thread_id_sha256": sha256_text(thread_id),
                    "turn_status": status,
                    "outcome": outcome,
                },
            )
        except Exception as exc:
            ledger_errors.append(sha256_text(f"{type(exc).__name__}:{exc}"))

    for thread_id, turn_id in list(server.started_threads.items()):
        try:
            thread, _latency = server.read_thread(thread_id)
            status = turn_status(thread, turn_id) if turn_id else None
            if turn_id and status == "inProgress":
                server.interrupt_turn(thread_id, turn_id)
                interrupted.append(thread_id)
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    thread, _latency = server.read_thread(thread_id)
                    status = turn_status(thread, turn_id)
                    if status in {"interrupted", "completed", "failed"}:
                        break
                    time.sleep(0.05)
            if turn_id is None or status in {"interrupted", "completed", "failed"}:
                server.archive_thread(thread_id)
                archived.append(thread_id)
                audit_containment(thread_id, "contained", status)
            else:
                ambiguous.append(thread_id)
        except Exception:
            try:
                archived_in_ledger = bool(
                    ledger is not None
                    and ledger.has_lifecycle(thread_id, "archive-observed")
                )
            except Exception as exc:
                archived_in_ledger = False
                ledger_errors.append(sha256_text(f"{type(exc).__name__}:{exc}"))
            if archived_in_ledger:
                already_contained.append(thread_id)
                audit_containment(thread_id, "already-contained", None)
            else:
                ambiguous.append(thread_id)
    unresolved_allocations = 0
    unresolved_turns = 0
    ledger_allocation_count = len(server.started_threads)
    if ledger is not None:
        try:
            ledger_summary = ledger.summary()
            unresolved_allocations = int(
                ledger_summary["unresolved_allocation_intent_count"]
            )
            unresolved_turns = int(ledger_summary["unresolved_turn_intent_count"])
            ledger_allocation_count = int(ledger_summary["allocation_intent_count"])
        except Exception as exc:
            ledger_errors.append(sha256_text(f"{type(exc).__name__}:{exc}"))
    ambiguous_count = len(set(ambiguous)) + unresolved_allocations
    return {
        "allocated_count": ledger_allocation_count,
        "identified_thread_count": len(server.started_threads),
        "interrupted_count": len(set(interrupted)),
        "archived_count": len(set(archived)),
        "already_contained_count": len(set(already_contained)),
        "unresolved_allocation_intent_count": unresolved_allocations,
        "unresolved_turn_intent_count": unresolved_turns,
        "ambiguous_count": ambiguous_count,
        "all_contained": ambiguous_count == 0,
        "ledger_consistent": not ledger_errors and not unresolved_allocations and not unresolved_turns,
        "ledger_error_sha256": sorted(set(ledger_errors)),
    }


def _load_owned_regular_bytes(
    path: Path,
    label: str,
    *,
    require_private: bool,
    expected_identity: tuple[int, int, int, int] | None = None,
) -> bytes:
    """Capture one owner-bound file exactly once through a stable descriptor."""

    supplied = Path(path)
    lexical = supplied.absolute()
    try:
        resolved = supplied.resolve(strict=True)
    except OSError as exc:
        raise AppServerError(f"{label}-file-invalid") from exc
    if lexical != resolved:
        raise AppServerError(f"{label}-path-invalid")
    try:
        descriptor = os.open(
            resolved,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise AppServerError(f"{label}-file-invalid") from exc
    try:
        before = os.fstat(descriptor)
        descriptor_identity = (
            before.st_dev,
            before.st_ino,
            before.st_uid,
            before.st_mode,
        )
        if (
            expected_identity is not None
            and descriptor_identity != tuple(expected_identity)
        ):
            raise AppServerError(f"{label}-source-identity-changed")
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or (
                before.st_mode & 0o077
                if require_private
                else before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            )
        ):
            raise AppServerError(f"{label}-permissions-invalid")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        value = b"".join(chunks)
        after = os.fstat(descriptor)
    except OSError as exc:
        raise AppServerError(f"{label}-file-unreadable") from exc
    finally:
        os.close(descriptor)
    stable_fields = ("st_dev", "st_ino", "st_uid", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, field) != getattr(after, field) for field in stable_fields) or len(
        value
    ) != before.st_size:
        raise AppServerError(f"{label}-source-changed")
    if not value:
        raise AppServerError(f"{label}-file-empty")
    return value


def load_private_bytes(
    path: Path,
    label: str,
    *,
    expected_identity: tuple[int, int, int, int] | None = None,
) -> bytes:
    """Read one private regular file through a no-follow descriptor snapshot."""

    return _load_owned_regular_bytes(
        path,
        label,
        require_private=True,
        expected_identity=expected_identity,
    )


def load_trusted_session_bytes(
    path: Path,
    label: str,
    *,
    expected_identity: tuple[int, int, int, int] | None = None,
) -> bytes:
    """Snapshot owner-bound session telemetry that may be world-readable."""

    return _load_owned_regular_bytes(
        path,
        label,
        require_private=False,
        expected_identity=expected_identity,
    )


def load_private_json_snapshot(
    path: Path,
    label: str,
    *,
    expected_identity: tuple[int, int, int, int] | None = None,
) -> JsonArtifactSnapshot:
    raw = load_private_bytes(
        path,
        label,
        expected_identity=expected_identity,
    )
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AppServerError(f"{label}-file-unreadable") from exc
    if not isinstance(value, dict):
        raise AppServerError(f"{label}-not-object")
    return JsonArtifactSnapshot(raw=raw, value=value)


def load_private_json(path: Path, label: str) -> dict[str, Any]:
    return dict(load_private_json_snapshot(path, label).value)


def _private_control_directory(path: Path, label: str) -> Path:
    supplied = Path(path).absolute()
    try:
        if supplied.is_symlink():
            raise AppServerError(f"{label}-directory-permissions-invalid")
        missing: list[Path] = []
        cursor = supplied
        while not cursor.exists():
            if cursor.is_symlink():
                raise AppServerError(
                    f"{label}-directory-permissions-invalid"
                )
            missing.append(cursor)
            if cursor.parent == cursor:
                raise AppServerError(f"{label}-directory-unavailable")
            cursor = cursor.parent
        ancestor = cursor.lstat()
        if (
            stat.S_ISLNK(ancestor.st_mode)
            or not stat.S_ISDIR(ancestor.st_mode)
            or ancestor.st_uid != os.geteuid()
            or stat.S_IMODE(ancestor.st_mode) & 0o022
        ):
            raise AppServerError(f"{label}-directory-permissions-invalid")
        for directory in reversed(missing):
            directory.mkdir(mode=0o700)
            _fsync_private_control_directory(directory, label)
            _fsync_owned_control_directory(
                directory.parent,
                f"{label}-parent",
                require_private=False,
            )
        directory = supplied.resolve(strict=True)
    except OSError as exc:
        raise AppServerError(f"{label}-directory-unavailable") from exc
    if directory != supplied:
        raise AppServerError(f"{label}-directory-permissions-invalid")
    try:
        info = directory.lstat()
    except OSError as exc:
        raise AppServerError(f"{label}-directory-unavailable") from exc
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise AppServerError(f"{label}-directory-permissions-invalid")
    _fsync_private_control_directory(directory, label)
    _fsync_owned_control_directory(
        directory.parent,
        f"{label}-parent",
        require_private=False,
    )
    return directory


def _stable_codex_control_root() -> Path:
    """Resolve the control root from the effective account, never mutable HOME."""

    try:
        account_home = Path(pwd.getpwuid(os.geteuid()).pw_dir).absolute()
        root = (account_home / ".codex").resolve(strict=True)
        info = root.lstat()
    except (KeyError, OSError) as exc:
        raise AppServerError("stable-codex-control-root-unavailable") from exc
    if (
        root != account_home / ".codex"
        or stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise AppServerError("stable-codex-control-root-invalid")
    return root


def _open_private_control_lock(path: Path, label: str) -> int:
    """Open one owner-private regular lock file without following aliases."""

    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        info = os.fstat(descriptor)
    except OSError as exc:
        if descriptor is not None:
            os.close(descriptor)
        raise AppServerError(f"{label}-lock-invalid") from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        os.close(descriptor)
        raise AppServerError(f"{label}-lock-invalid")
    return descriptor


def _write_exclusive_private_bytes(path: Path, raw: bytes, label: str) -> None:
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
    except FileExistsError as exc:
        raise AppServerError(f"{label}-already-exists") from exc
    except OSError as exc:
        raise AppServerError(f"{label}-create-failed") from exc
    try:
        offset = 0
        while offset < len(raw):
            offset += os.write(descriptor, raw[offset:])
        os.fsync(descriptor)
    except OSError as exc:
        raise AppServerError(f"{label}-write-failed") from exc
    finally:
        os.close(descriptor)


def _fsync_private_control_directory(path: Path, label: str) -> None:
    """Durably persist a newly created private control-plane directory entry."""

    _fsync_owned_control_directory(path, label, require_private=True)


def _fsync_owned_control_directory(
    path: Path,
    label: str,
    *,
    require_private: bool,
) -> None:
    """Fsync an owner-controlled directory without following an alias."""

    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        info = os.fstat(descriptor)
        mode = stat.S_IMODE(info.st_mode)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or (mode != 0o700 if require_private else bool(mode & 0o022))
        ):
            raise AppServerError(f"{label}-directory-permissions-invalid")
        os.fsync(descriptor)
    except OSError as exc:
        raise AppServerError(f"{label}-directory-fsync-failed") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _active_authority_registry_root(override: Path | None = None) -> Path:
    return _private_control_directory(
        override
        if override is not None
        else _stable_codex_control_root() / "cwo-native-live-authorities-v1",
        "active-outer-authority-registry",
    )


def _active_authority_registry_path(
    outer_authority: Mapping[str, Any], registry_root: Path | None = None
) -> tuple[Path, Path, str]:
    scope = outer_authority.get("scope")
    if not isinstance(scope, Mapping):
        raise AppServerError("active-outer-authority-scope-invalid")
    try:
        scope_key = active_outer_authority_scope_key(
            scope.get("epic_id"), scope.get("parent_work_unit_id")
        )
    except ValueError as exc:
        raise AppServerError("active-outer-authority-scope-invalid") from exc
    declared = outer_authority.get("active_registry")
    if declared != {
        "contract": "cwo-active-outer-authority-registry:v1",
        "scope_key": scope_key,
    }:
        raise AppServerError("active-outer-authority-registry-declaration-invalid")
    root = _active_authority_registry_root(registry_root)
    return root / f"{scope_key}.json", root / f"{scope_key}.lock", scope_key


def _scope_campaign_paths(
    outer_authority: Mapping[str, Any], registry_root: Path | None = None
) -> tuple[Path, Path, str]:
    active_path, _active_lock, scope_key = _active_authority_registry_path(
        outer_authority, registry_root
    )
    return (
        active_path.with_name(f"{scope_key}.campaign-state.json"),
        active_path.with_name(f"{scope_key}.campaign-state.lock"),
        scope_key,
    )


def _valid_uuid_text(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        return False
    return str(parsed) == value


def _load_scope_campaign_state(path: Path, scope_key: str) -> dict[str, Any]:
    state = load_private_json(path, "scope-campaign-state")
    fields = {
        "state_type",
        "version",
        "scope_key",
        "phase",
        "outer_authority_id",
        "authorization_id",
        "campaign_nonce",
        "launch_claim_sha256",
        "candidate_commit",
        "candidate_tree",
        "previous_state_sha256",
        "reserved_at",
        "updated_at",
        "terminal_evidence_sha256",
        "canonical_state_sha256",
    }
    unsigned = dict(state)
    recorded = unsigned.pop("canonical_state_sha256", None)
    previous = state.get("previous_state_sha256")
    terminal = state.get("terminal_evidence_sha256")
    phase = state.get("phase")
    if (
        set(state) != fields
        or state.get("state_type") != "cwo-native-live-scope-campaign-state"
        or state.get("version") != 1
        or state.get("scope_key") != scope_key
        or phase not in {"reserved", "active", "terminal", "contained"}
        or not _valid_uuid_text(state.get("outer_authority_id"))
        or not _valid_uuid_text(state.get("authorization_id"))
        or not _valid_uuid_text(state.get("campaign_nonce"))
        or not re.fullmatch(r"[0-9a-f]{64}", str(state.get("launch_claim_sha256")))
        or not re.fullmatch(r"[0-9a-f]{40}", str(state.get("candidate_commit")))
        or not re.fullmatch(r"[0-9a-f]{40}", str(state.get("candidate_tree")))
        or (
            previous is not None
            and not re.fullmatch(r"[0-9a-f]{64}", str(previous))
        )
        or not isinstance(state.get("reserved_at"), str)
        or not isinstance(state.get("updated_at"), str)
        or (
            phase in {"reserved", "active"}
            and terminal is not None
        )
        or (
            phase in {"terminal", "contained"}
            and not re.fullmatch(r"[0-9a-f]{64}", str(terminal))
        )
        or recorded
        != sha256_bytes(
            json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
        )
    ):
        raise AppServerError("scope-campaign-state-invalid")
    return state


def _write_scope_campaign_state(path: Path, value: Mapping[str, Any]) -> None:
    state = dict(value)
    state.pop("canonical_state_sha256", None)
    state["canonical_state_sha256"] = sha256_bytes(
        json.dumps(state, sort_keys=True, separators=(",", ":")).encode()
    )
    raw = (json.dumps(state, indent=2, sort_keys=True) + "\n").encode()
    temporary = path.with_name(f".{path.name}.{uuid.uuid4()}.tmp")
    _write_exclusive_private_bytes(
        temporary, raw, "scope-campaign-state-temporary"
    )
    os.replace(temporary, path)
    _fsync_private_control_directory(path.parent, "scope-campaign-state")


def _authority_history_path(root: Path, scope_key: str, authority_id: str) -> Path:
    if not _valid_uuid_text(authority_id):
        raise AppServerError("active-outer-authority-id-invalid")
    identity_sha256 = domain_sha256(
        {"scope_key": scope_key, "authority_id": authority_id},
        domain="native-live-authority-history-identity",
    )
    return root / f"{scope_key}.authority-{identity_sha256}.json"


def _authority_history_record(
    active: Mapping[str, Any], *, predecessor_authority_id: str | None
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "record_type": "cwo-native-live-authority-history",
        "version": 1,
        "scope_key": active["scope_key"],
        "authority_id": active["authority_id"],
        "authority_file_sha256": active["authority_file_sha256"],
        "authority_canonical_sha256": active["authority_canonical_sha256"],
        "candidate_commit": active["candidate_commit"],
        "candidate_tree": active["candidate_tree"],
        "predecessor_authority_id": predecessor_authority_id,
        "recorded_at": iso(),
    }
    record["canonical_history_sha256"] = sha256_bytes(
        json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
    )
    return record


def _validate_authority_history_record(
    value: Mapping[str, Any],
    active: Mapping[str, Any],
    *,
    expected_predecessor_authority_id: str | None | object = ...,
) -> None:
    fields = {
        "record_type",
        "version",
        "scope_key",
        "authority_id",
        "authority_file_sha256",
        "authority_canonical_sha256",
        "candidate_commit",
        "candidate_tree",
        "predecessor_authority_id",
        "recorded_at",
        "canonical_history_sha256",
    }
    unsigned = dict(value)
    recorded = unsigned.pop("canonical_history_sha256", None)
    if (
        set(value) != fields
        or value.get("record_type") != "cwo-native-live-authority-history"
        or value.get("version") != 1
        or not _valid_uuid_text(value.get("authority_id"))
        or any(
            value.get(field) != active.get(field)
            for field in (
                "scope_key",
                "authority_id",
                "authority_file_sha256",
                "authority_canonical_sha256",
                "candidate_commit",
                "candidate_tree",
            )
        )
        or (
            expected_predecessor_authority_id is not ...
            and value.get("predecessor_authority_id")
            != expected_predecessor_authority_id
        )
        or (
            value.get("predecessor_authority_id") is not None
            and not _valid_uuid_text(value.get("predecessor_authority_id"))
        )
        or not isinstance(value.get("recorded_at"), str)
        or recorded
        != sha256_bytes(
            json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
        )
    ):
        raise AppServerError("active-outer-authority-history-invalid")


def _ensure_authority_history_record(
    root: Path,
    active: Mapping[str, Any],
    *,
    predecessor_authority_id: str | None,
    allow_existing: bool,
) -> None:
    path = _authority_history_path(
        root, str(active["scope_key"]), str(active["authority_id"])
    )
    if path.exists():
        value = load_private_json(path, "active-outer-authority-history")
        if allow_existing:
            _validate_authority_history_record(
                value,
                active,
                expected_predecessor_authority_id=predecessor_authority_id,
            )
        else:
            _validate_authority_history_record(value, value)
            raise AppServerError("active-outer-authority-id-reused")
        return
    value = _authority_history_record(
        active, predecessor_authority_id=predecessor_authority_id
    )
    _write_exclusive_private_bytes(
        path,
        (json.dumps(value, indent=2, sort_keys=True) + "\n").encode(),
        "active-outer-authority-history",
    )
    _fsync_private_control_directory(root, "active-outer-authority-history")


def _migrate_authority_history_seed(
    root: Path,
    scope_key: str,
    current: Mapping[str, Any],
    proposed_outer: Mapping[str, Any],
) -> None:
    """Seed immutable pre-registry lineage before the first supersession."""

    seed = proposed_outer.get("authority_history_seed")
    if not isinstance(seed, Mapping) or set(seed) != {
        "contract",
        "complete",
        "entries",
        "canonical_seed_sha256",
    }:
        raise AppServerError("active-outer-authority-history-seed-missing")
    unsigned_seed = dict(seed)
    recorded_seed = unsigned_seed.pop("canonical_seed_sha256", None)
    entries = seed.get("entries")
    if (
        seed.get("contract")
        != "cwo-native-live-authority-history-seed:v1"
        or seed.get("complete") is not True
        or not isinstance(entries, list)
        or not entries
        or recorded_seed
        != sha256_bytes(
            json.dumps(
                unsigned_seed, sort_keys=True, separators=(",", ":")
            ).encode()
        )
    ):
        raise AppServerError("active-outer-authority-history-seed-invalid")
    expected_fields = {
        "authority_id",
        "authority_file_sha256",
        "authority_canonical_sha256",
        "candidate_commit",
        "candidate_tree",
        "predecessor_authority_id",
    }
    seen: set[str] = set()
    prior_id: str | None = None
    normalized: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, Mapping) or set(entry) != expected_fields:
            raise AppServerError("active-outer-authority-history-seed-invalid")
        authority_id = entry.get("authority_id")
        if (
            not _valid_uuid_text(authority_id)
            or authority_id in seen
            or entry.get("predecessor_authority_id") != prior_id
            or not re.fullmatch(
                r"[0-9a-f]{64}", str(entry.get("authority_file_sha256"))
            )
            or not re.fullmatch(
                r"[0-9a-f]{64}",
                str(entry.get("authority_canonical_sha256")),
            )
            or not re.fullmatch(
                r"[0-9a-f]{40}", str(entry.get("candidate_commit"))
            )
            or not re.fullmatch(
                r"[0-9a-f]{40}", str(entry.get("candidate_tree"))
            )
        ):
            raise AppServerError("active-outer-authority-history-seed-invalid")
        seen.add(str(authority_id))
        prior_id = str(authority_id)
        normalized.append(dict(entry))
    last = normalized[-1]
    if any(
        last.get(field) != current.get(field)
        for field in (
            "authority_id",
            "authority_file_sha256",
            "authority_canonical_sha256",
            "candidate_commit",
            "candidate_tree",
        )
    ):
        raise AppServerError("active-outer-authority-history-seed-current-mismatch")
    for entry in normalized:
        active = {
            "scope_key": scope_key,
            "authority_id": entry["authority_id"],
            "authority_file_sha256": entry["authority_file_sha256"],
            "authority_canonical_sha256": entry[
                "authority_canonical_sha256"
            ],
            "candidate_commit": entry["candidate_commit"],
            "candidate_tree": entry["candidate_tree"],
        }
        _ensure_authority_history_record(
            root,
            active,
            predecessor_authority_id=entry["predecessor_authority_id"],
            allow_existing=True,
        )


def register_active_outer_authority(
    outer_authority: JsonArtifactSnapshot,
    *,
    candidate_commit: str,
    candidate_tree: str,
    registry_root: Path | None = None,
) -> JsonArtifactSnapshot:
    """Atomically supersede the active outer authority for one work-graph scope."""

    value = dict(outer_authority.value)
    outer_bindings = value.get("bindings")
    if (
        json.loads(outer_authority.raw) != value
        or value.get("status") != "active"
        or not _valid_uuid_text(value.get("authority_id"))
        or not isinstance(outer_bindings, Mapping)
        or outer_bindings.get("candidate_commit") != candidate_commit
        or outer_bindings.get("candidate_tree") != candidate_tree
        or not re.fullmatch(r"[0-9a-f]{40}", candidate_commit)
        or not re.fullmatch(r"[0-9a-f]{40}", candidate_tree)
        or value.get("canonical_outer_authority_sha256")
        != sha256_bytes(
            json.dumps(
                {
                    key: item
                    for key, item in value.items()
                    if key != "canonical_outer_authority_sha256"
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        )
    ):
        raise AppServerError("active-outer-authority-artifact-invalid")
    path, lock_path, scope_key = _active_authority_registry_path(
        value, registry_root
    )
    scope = value["scope"]
    record: dict[str, Any] = {
        "registry_type": "cwo-active-outer-authority-registry",
        "version": 1,
        "scope_key": scope_key,
        "epic_id": scope["epic_id"],
        "parent_work_unit_id": scope["parent_work_unit_id"],
        "authority_id": value["authority_id"],
        "authority_file_sha256": outer_authority.raw_sha256,
        "authority_canonical_sha256": value[
            "canonical_outer_authority_sha256"
        ],
        "candidate_commit": candidate_commit,
        "candidate_tree": candidate_tree,
        "status": "active",
        "updated_at": iso(),
    }
    record["canonical_registry_sha256"] = sha256_bytes(
        json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
    )
    raw = (json.dumps(record, indent=2, sort_keys=True) + "\n").encode()
    campaign_state_path, campaign_lock_path, campaign_scope_key = (
        _scope_campaign_paths(value, registry_root)
    )
    if campaign_scope_key != scope_key:
        raise AppServerError("active-outer-authority-scope-invalid")
    campaign_lock_descriptor = _open_private_control_lock(
        campaign_lock_path, "scope-campaign-state"
    )
    lock_descriptor: int | None = None
    try:
        fcntl.flock(campaign_lock_descriptor, fcntl.LOCK_EX)
        if campaign_state_path.exists():
            campaign_state = _load_scope_campaign_state(
                campaign_state_path, scope_key
            )
            if campaign_state["phase"] not in {"terminal", "contained"}:
                raise AppServerError("active-scope-campaign-nonterminal")
        lock_descriptor = _open_private_control_lock(
            lock_path, "active-outer-authority"
        )
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
        current_snapshot: JsonArtifactSnapshot | None = None
        if path.exists():
            current_snapshot = load_private_json_snapshot(
                path, "active-outer-authority-registry"
            )
            current = dict(current_snapshot.value)
            current_unsigned = dict(current)
            current_canonical = current_unsigned.pop(
                "canonical_registry_sha256", None
            )
            if (
                set(current) != set(record)
                or current.get("registry_type")
                != "cwo-active-outer-authority-registry"
                or current.get("version") != 1
                or current.get("scope_key") != scope_key
                or current_canonical
                != sha256_bytes(
                    json.dumps(
                        current_unsigned,
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode()
                )
            ):
                raise AppServerError("active-outer-authority-registry-invalid")
            current_history_path = _authority_history_path(
                path.parent, scope_key, str(current["authority_id"])
            )
            if current_history_path.exists():
                _validate_authority_history_record(
                    load_private_json(
                        current_history_path,
                        "active-outer-authority-history",
                    ),
                    current,
                )
            else:
                _migrate_authority_history_seed(
                    path.parent,
                    scope_key,
                    current,
                    value,
                )
            if current.get("authority_id") == value["authority_id"]:
                identity_fields = {
                    "scope_key",
                    "epic_id",
                    "parent_work_unit_id",
                    "authority_id",
                    "authority_file_sha256",
                    "authority_canonical_sha256",
                    "candidate_commit",
                    "candidate_tree",
                    "status",
                }
                if all(current.get(field) == record.get(field) for field in identity_fields):
                    return current_snapshot
                raise AppServerError("active-outer-authority-id-reused")
            supersession = value.get("supersession")
            if (
                not isinstance(supersession, Mapping)
                or supersession.get("prior_outer_authority_id")
                != current.get("authority_id")
                or supersession.get("prior_outer_authority_file_sha256")
                != current.get("authority_file_sha256")
                or supersession.get("prior_outer_authority_canonical_sha256")
                != current.get("authority_canonical_sha256")
            ):
                raise AppServerError(
                    "active-outer-authority-supersession-invalid"
                )
        _ensure_authority_history_record(
            path.parent,
            record,
            predecessor_authority_id=(
                str(current_snapshot.value["authority_id"])
                if current_snapshot is not None
                else None
            ),
            allow_existing=False,
        )
        temporary = path.with_name(f".{path.name}.{uuid.uuid4()}.tmp")
        _write_exclusive_private_bytes(
            temporary, raw, "active-outer-authority-registry-temporary"
        )
        os.replace(temporary, path)
        _fsync_private_control_directory(
            path.parent, "active-outer-authority-registry"
        )
    finally:
        if lock_descriptor is not None:
            os.close(lock_descriptor)
        os.close(campaign_lock_descriptor)
    return JsonArtifactSnapshot(raw=raw, value=record)


def _validate_active_outer_authority_unlocked(
    outer_authority: JsonArtifactSnapshot,
    *,
    candidate_commit: str,
    candidate_tree: str,
    path: Path,
    scope_key: str,
) -> str:
    registry = load_private_json(path, "active-outer-authority-registry")
    expected_fields = {
        "registry_type",
        "version",
        "scope_key",
        "epic_id",
        "parent_work_unit_id",
        "authority_id",
        "authority_file_sha256",
        "authority_canonical_sha256",
        "candidate_commit",
        "candidate_tree",
        "status",
        "updated_at",
        "canonical_registry_sha256",
    }
    unsigned = dict(registry)
    recorded = unsigned.pop("canonical_registry_sha256", None)
    scope = outer_authority.value.get("scope", {})
    if (
        set(registry) != expected_fields
        or registry.get("registry_type")
        != "cwo-active-outer-authority-registry"
        or registry.get("version") != 1
        or registry.get("scope_key") != scope_key
        or registry.get("epic_id") != scope.get("epic_id")
        or registry.get("parent_work_unit_id")
        != scope.get("parent_work_unit_id")
        or registry.get("authority_id")
        != outer_authority.value.get("authority_id")
        or registry.get("authority_file_sha256") != outer_authority.raw_sha256
        or registry.get("authority_canonical_sha256")
        != outer_authority.value.get("canonical_outer_authority_sha256")
        or registry.get("candidate_commit") != candidate_commit
        or registry.get("candidate_tree") != candidate_tree
        or registry.get("status") != "active"
        or recorded
        != sha256_bytes(
            json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
        )
    ):
        raise AppServerError("active-outer-authority-registry-mismatch")
    history_path = _authority_history_path(
        path.parent, scope_key, str(registry["authority_id"])
    )
    if not history_path.is_file() or history_path.is_symlink():
        raise AppServerError("active-outer-authority-history-missing")
    _validate_authority_history_record(
        load_private_json(history_path, "active-outer-authority-history"),
        registry,
    )
    return str(recorded)


def validate_active_outer_authority(
    outer_authority: JsonArtifactSnapshot,
    *,
    candidate_commit: str,
    candidate_tree: str,
    registry_root: Path | None = None,
) -> str:
    """Require the supplied outer artifact to remain the canonical active one."""

    path, lock_path, scope_key = _active_authority_registry_path(
        outer_authority.value, registry_root
    )
    lock_descriptor = _open_private_control_lock(
        lock_path, "active-outer-authority"
    )
    try:
        fcntl.flock(lock_descriptor, fcntl.LOCK_SH)
        return _validate_active_outer_authority_unlocked(
            outer_authority,
            candidate_commit=candidate_commit,
            candidate_tree=candidate_tree,
            path=path,
            scope_key=scope_key,
        )
    finally:
        os.close(lock_descriptor)


def _claim_identifier_marker_path(root: Path, kind: str, identifier: str) -> Path:
    if kind not in {"authorization", "nonce"} or not _valid_uuid_text(
        identifier
    ):
        raise AppServerError("campaign-global-claim-marker-identity-invalid")
    digest = domain_sha256(
        {"kind": kind, "identifier": identifier},
        domain="native-live-global-claim-identifier",
    )
    return root / f"{kind}-{digest}.json"


def _validate_claim_identifier_marker(
    value: Mapping[str, Any], *, kind: str, identifier: str
) -> None:
    fields = {
        "marker_type",
        "version",
        "kind",
        "identifier",
        "identifier_sha256",
        "claim_canonical_sha256",
        "created_at",
        "canonical_marker_sha256",
    }
    unsigned = dict(value)
    recorded = unsigned.pop("canonical_marker_sha256", None)
    if (
        set(value) != fields
        or value.get("marker_type")
        != "cwo-native-live-global-claim-identifier"
        or value.get("version") != 1
        or value.get("kind") != kind
        or value.get("identifier") != identifier
        or value.get("identifier_sha256")
        != domain_sha256(
            {"kind": kind, "identifier": identifier},
            domain="native-live-global-claim-identifier",
        )
        or not re.fullmatch(
            r"[0-9a-f]{64}", str(value.get("claim_canonical_sha256"))
        )
        or not isinstance(value.get("created_at"), str)
        or recorded
        != sha256_bytes(
            json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
        )
    ):
        raise AppServerError("campaign-global-claim-marker-invalid")


def _ensure_claim_identifier_marker(
    root: Path,
    *,
    kind: str,
    identifier: str,
    claim_canonical_sha256: str,
    allow_existing: bool,
) -> None:
    path = _claim_identifier_marker_path(root, kind, identifier)
    if path.exists():
        existing = load_private_json(path, "campaign-global-claim-marker")
        _validate_claim_identifier_marker(
            existing,
            kind=kind,
            identifier=identifier,
        )
        if not allow_existing:
            raise AppServerError(f"campaign-global-{kind}-reused")
        if existing.get("claim_canonical_sha256") != claim_canonical_sha256:
            raise AppServerError("campaign-global-claim-marker-conflict")
        return
    value: dict[str, Any] = {
        "marker_type": "cwo-native-live-global-claim-identifier",
        "version": 1,
        "kind": kind,
        "identifier": identifier,
        "identifier_sha256": domain_sha256(
            {"kind": kind, "identifier": identifier},
            domain="native-live-global-claim-identifier",
        ),
        "claim_canonical_sha256": claim_canonical_sha256,
        "created_at": iso(),
    }
    value["canonical_marker_sha256"] = sha256_bytes(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    )
    _write_exclusive_private_bytes(
        path,
        (json.dumps(value, indent=2, sort_keys=True) + "\n").encode(),
        "campaign-global-claim-marker",
    )
    _fsync_private_control_directory(root, "campaign-global-claim-marker")


def _reject_reused_claim_identifier(
    root: Path, *, kind: str, identifier: str
) -> None:
    path = _claim_identifier_marker_path(root, kind, identifier)
    if not path.exists():
        return
    _validate_claim_identifier_marker(
        load_private_json(path, "campaign-global-claim-marker"),
        kind=kind,
        identifier=identifier,
    )
    raise AppServerError(f"campaign-global-{kind}-reused")


def _migrate_global_claim_markers(root: Path) -> None:
    """Backfill separate ID and nonce tombstones from every legacy claim."""

    for path in sorted(root.glob("*.json")):
        value = load_private_json(path, "campaign-global-claim-registry-entry")
        if value.get("marker_type") == "cwo-native-live-global-claim-identifier":
            kind = value.get("kind")
            identifier = value.get("identifier")
            if kind not in {"authorization", "nonce"} or not _valid_uuid_text(
                identifier
            ):
                raise AppServerError("campaign-global-claim-marker-invalid")
            _validate_claim_identifier_marker(
                value, kind=str(kind), identifier=str(identifier)
            )
            continue
        if value.get("claim_type") != "cwo-native-live-campaign-global-claim":
            raise AppServerError("campaign-global-claim-registry-entry-invalid")
        unsigned = dict(value)
        recorded = unsigned.pop("canonical_claim_sha256", None)
        identity = value.get("identity")
        if (
            value.get("version") != 1
            or not isinstance(identity, Mapping)
            or not _valid_uuid_text(identity.get("authorization_id"))
            or not _valid_uuid_text(identity.get("campaign_nonce"))
            or recorded
            != domain_sha256(
                unsigned, domain="native-live-global-claim-artifact"
            )
        ):
            raise AppServerError("campaign-global-claim-registry-entry-invalid")
        for kind, identifier in (
            ("authorization", str(identity["authorization_id"])),
            ("nonce", str(identity["campaign_nonce"])),
        ):
            _ensure_claim_identifier_marker(
                root,
                kind=kind,
                identifier=identifier,
                claim_canonical_sha256=str(recorded),
                allow_existing=True,
            )


def acquire_global_campaign_claim(
    inputs: CampaignLaunchInputs,
    *,
    launch_claim_sha256: str,
    output: Path,
    authorization_state: Path,
    steering_registry: Path,
    allocation_ledger: Path,
    claim_root: Path | None = None,
    registry_root: Path | None = None,
) -> GlobalCampaignReservation:
    """Acquire the permanent machine-global claim for one inner authorization.

    A claim is an intentional one-shot tombstone, not a recoverable lock.  A
    contained or aborted campaign must mint a fresh authorization ID and nonce;
    deleting a prior claim would turn a forbidden resume into a replay path.
    """

    authorization = inputs.authorization.value
    manifest = inputs.manifest.value
    bindings = authorization.get("bindings")
    if not isinstance(bindings, Mapping):
        raise AppServerError("campaign-global-claim-authorization-invalid")
    authorization_id = authorization.get("authorization_id")
    campaign_nonce = bindings.get("campaign_nonce")
    if not _valid_uuid_text(authorization_id) or not _valid_uuid_text(
        campaign_nonce
    ):
        raise AppServerError("campaign-global-claim-identity-invalid")
    identity = {
        "authorization_id": authorization_id,
        "run_generation": authorization.get("run_generation"),
        "live_generation": authorization.get("live_generation"),
        "campaign_nonce": campaign_nonce,
    }
    identity_sha256 = domain_sha256(identity, domain="native-live-global-claim")
    root = _private_control_directory(
        claim_root
        if claim_root is not None
        else _stable_codex_control_root()
        / "cwo-native-live-campaign-claims-v1",
        "campaign-global-claim",
    )
    path = root / f"{identity_sha256}.json"
    claim: dict[str, Any] = {
        "claim_type": "cwo-native-live-campaign-global-claim",
        "version": 1,
        "identity": identity,
        "identity_sha256": identity_sha256,
        "launch_claim_sha256": launch_claim_sha256,
        "outer_authority_id": inputs.outer_authority.value.get("authority_id"),
        "candidate_commit": manifest.get("candidate", {}).get("commit"),
        "candidate_tree": manifest.get("candidate", {}).get("tree"),
        "output_paths": {
            "evidence": str(output.resolve(strict=False)),
            "authorization_state": str(authorization_state.resolve(strict=False)),
            "steering_registry": str(steering_registry.resolve(strict=False)),
            "allocation_ledger": str(allocation_ledger.resolve(strict=False)),
        },
        "claimed_at": iso(),
    }
    claim["canonical_claim_sha256"] = domain_sha256(
        claim, domain="native-live-global-claim-artifact"
    )
    authority_path, authority_lock_path, scope_key = (
        _active_authority_registry_path(
            inputs.outer_authority.value, registry_root
        )
    )
    state_path, state_lock_path, state_scope_key = _scope_campaign_paths(
        inputs.outer_authority.value, registry_root
    )
    if state_scope_key != scope_key:
        raise AppServerError("scope-campaign-state-scope-invalid")
    state_lock_descriptor = _open_private_control_lock(
        state_lock_path, "scope-campaign-state"
    )
    authority_lock_descriptor: int | None = None
    claim_lock_descriptor: int | None = None
    previous_state_sha256: str | None = None
    try:
        fcntl.flock(state_lock_descriptor, fcntl.LOCK_EX)
        if state_path.exists():
            prior_state = _load_scope_campaign_state(state_path, scope_key)
            if prior_state["phase"] not in {"terminal", "contained"}:
                raise AppServerError("scope-campaign-state-nonterminal")
            previous_state_sha256 = str(prior_state["canonical_state_sha256"])
        authority_lock_descriptor = _open_private_control_lock(
            authority_lock_path, "active-outer-authority"
        )
        fcntl.flock(authority_lock_descriptor, fcntl.LOCK_SH)
        _validate_active_outer_authority_unlocked(
            inputs.outer_authority,
            candidate_commit=str(manifest.get("candidate", {}).get("commit")),
            candidate_tree=str(manifest.get("candidate", {}).get("tree")),
            path=authority_path,
            scope_key=scope_key,
        )
        claim_lock_descriptor = _open_private_control_lock(
            root / ".registry.lock", "campaign-global-claim-registry"
        )
        fcntl.flock(claim_lock_descriptor, fcntl.LOCK_EX)
        _migrate_global_claim_markers(root)
        claim_canonical = str(claim["canonical_claim_sha256"])
        _reject_reused_claim_identifier(
            root,
            kind="authorization",
            identifier=str(authorization_id),
        )
        _reject_reused_claim_identifier(
            root,
            kind="nonce",
            identifier=str(campaign_nonce),
        )
        # Persist the pair-bearing intent first.  If the process dies while
        # deriving either identifier marker, migration can still reconstruct
        # both tombstones before any later claim is considered.
        _write_exclusive_private_bytes(
            path,
            (json.dumps(claim, indent=2, sort_keys=True) + "\n").encode(),
            "campaign-global-claim",
        )
        _fsync_private_control_directory(root, "campaign-global-claim")
        _ensure_claim_identifier_marker(
            root,
            kind="authorization",
            identifier=str(authorization_id),
            claim_canonical_sha256=claim_canonical,
            allow_existing=False,
        )
        _ensure_claim_identifier_marker(
            root,
            kind="nonce",
            identifier=str(campaign_nonce),
            claim_canonical_sha256=claim_canonical,
            allow_existing=False,
        )
        reserved_at = iso()
        state = {
            "state_type": "cwo-native-live-scope-campaign-state",
            "version": 1,
            "scope_key": scope_key,
            "phase": "reserved",
            "outer_authority_id": inputs.outer_authority.value.get("authority_id"),
            "authorization_id": authorization_id,
            "campaign_nonce": campaign_nonce,
            "launch_claim_sha256": launch_claim_sha256,
            "candidate_commit": manifest.get("candidate", {}).get("commit"),
            "candidate_tree": manifest.get("candidate", {}).get("tree"),
            "previous_state_sha256": previous_state_sha256,
            "reserved_at": reserved_at,
            "updated_at": reserved_at,
            "terminal_evidence_sha256": None,
        }
        _write_scope_campaign_state(state_path, state)
        persisted = _load_scope_campaign_state(state_path, scope_key)
        return GlobalCampaignReservation(
            state_path=state_path,
            lock_path=state_lock_path,
            scope_key=scope_key,
            outer_authority_id=str(inputs.outer_authority.value["authority_id"]),
            authorization_id=str(authorization_id),
            campaign_nonce=str(campaign_nonce),
            launch_claim_sha256=launch_claim_sha256,
            state_sha256=str(persisted["canonical_state_sha256"]),
        )
    finally:
        if claim_lock_descriptor is not None:
            os.close(claim_lock_descriptor)
        if authority_lock_descriptor is not None:
            os.close(authority_lock_descriptor)
        os.close(state_lock_descriptor)


def transition_global_campaign_state(
    reservation: GlobalCampaignReservation,
    phase: str,
    *,
    terminal_evidence_sha256: str | None = None,
    outer_authority: JsonArtifactSnapshot | None = None,
    candidate_commit: str | None = None,
    candidate_tree: str | None = None,
    registry_root: Path | None = None,
) -> dict[str, Any]:
    """Advance one durable scope reservation without permitting a replay."""

    lock_descriptor = _open_private_control_lock(
        reservation.lock_path, "scope-campaign-state"
    )
    try:
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
        current = _load_scope_campaign_state(
            reservation.state_path, reservation.scope_key
        )
        if (
            current["canonical_state_sha256"] != reservation.state_sha256
            or current["outer_authority_id"] != reservation.outer_authority_id
            or current["authorization_id"] != reservation.authorization_id
            or current["campaign_nonce"] != reservation.campaign_nonce
            or current["launch_claim_sha256"]
            != reservation.launch_claim_sha256
        ):
            raise AppServerError("scope-campaign-state-binding-invalid")
        allowed = {
            "reserved": {"active", "contained"},
            "active": {"terminal", "contained"},
        }
        if phase not in allowed.get(str(current["phase"]), set()):
            raise AppServerError("scope-campaign-state-transition-invalid")
        if phase == "active":
            if (
                outer_authority is None
                or candidate_commit is None
                or candidate_tree is None
            ):
                raise AppServerError("scope-campaign-active-authority-missing")
            validate_active_outer_authority(
                outer_authority,
                candidate_commit=candidate_commit,
                candidate_tree=candidate_tree,
                registry_root=registry_root,
            )
        elif not re.fullmatch(r"[0-9a-f]{64}", str(terminal_evidence_sha256)):
            raise AppServerError("scope-campaign-terminal-evidence-invalid")
        updated = dict(current)
        previous = str(updated.pop("canonical_state_sha256"))
        updated["phase"] = phase
        updated["previous_state_sha256"] = previous
        updated["updated_at"] = iso()
        updated["terminal_evidence_sha256"] = (
            terminal_evidence_sha256
            if phase in {"terminal", "contained"}
            else None
        )
        _write_scope_campaign_state(reservation.state_path, updated)
        persisted = _load_scope_campaign_state(
            reservation.state_path, reservation.scope_key
        )
        reservation.state_sha256 = str(persisted["canonical_state_sha256"])
        return persisted
    finally:
        os.close(lock_descriptor)


def require_unique_input_paths(paths: Mapping[str, Path]) -> dict[str, Path]:
    """Resolve a complete input set once and reject path or inode aliases."""

    resolved: dict[str, Path] = {}
    reverse: dict[Path, str] = {}
    identities: dict[tuple[int, int], str] = {}
    for label, supplied in paths.items():
        lexical = Path(supplied).absolute()
        try:
            current = Path(supplied).resolve(strict=True)
            info = current.stat()
        except OSError as exc:
            raise AppServerError(f"{label}-path-invalid") from exc
        identity = (info.st_dev, info.st_ino)
        if (
            lexical != current
            or current in reverse
            or identity in identities
            or not stat.S_ISREG(info.st_mode)
        ):
            raise AppServerError("campaign-input-path-alias")
        resolved[label] = current
        reverse[current] = label
        identities[identity] = label
    return resolved


def capture_input_source_identities(
    paths: Mapping[str, Path],
) -> dict[str, tuple[int, int, int, int]]:
    """Capture stable source identities after alias rejection."""

    identities: dict[str, tuple[int, int, int, int]] = {}
    owners: dict[tuple[int, int], str] = {}
    for label, path in paths.items():
        try:
            info = path.stat()
        except OSError as exc:
            raise AppServerError(f"{label}-source-identity-unavailable") from exc
        inode = (info.st_dev, info.st_ino)
        if inode in owners:
            raise AppServerError("campaign-input-path-alias")
        owners[inode] = label
        identities[label] = (info.st_dev, info.st_ino, info.st_uid, info.st_mode)
    return identities


def require_private_parent(path: Path, label: str) -> None:
    try:
        info = path.parent.lstat()
    except OSError as exc:
        raise AppServerError(f"{label}-directory-unavailable") from exc
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise AppServerError(f"{label}-directory-permissions-invalid")


def campaign_input_requires_private_parent(label: str) -> bool:
    """Session telemetry is owner-bound but may live below a shared directory."""

    return not (
        label.endswith("-session")
        or "-contained-session-" in label
        or label == "spark-validation-session"
    )


def require_generation8_launch_inputs(
    inputs: CampaignLaunchInputs,
) -> Version6PredecessorProofInputs:
    """Return the fixed v6 predecessor proof or reject a mixed generation."""

    if (
        inputs.authorization.value.get("version") != 7
        or inputs.manifest.value.get("version") != 4
        or not isinstance(inputs.predecessor_proof, Version6PredecessorProofInputs)
        or inputs.legacy_predecessor is not None
        or not isinstance(inputs.recovery_cause_evidence, JsonArtifactSnapshot)
        or not isinstance(inputs.recovery_cause_source_analysis_bytes, bytes)
    ):
        raise AppServerError("campaign-generation8-proof-input-invalid")
    return inputs.predecessor_proof


def generation8_private_source_snapshots(
    inputs: CampaignLaunchInputs,
) -> dict[str, bytes]:
    """Flatten every non-session Generation-8 source from the fixed proof DAG."""

    proof = require_generation8_launch_inputs(inputs)
    ancestor = proof.ancestor
    grandancestor = ancestor.ancestor
    return {
        "authorization": inputs.authorization.raw,
        "campaign-manifest": inputs.manifest.raw,
        "outer-authority": inputs.outer_authority.raw,
        "release-patch": inputs.release_patch_bytes,
        "pre-mutation-steering-receipt": inputs.pre_mutation_receipt.raw,
        "pre-mutation-adjudication": inputs.pre_mutation_adjudication.raw,
        "pre-live-steering-receipt": inputs.pre_live_receipt.raw,
        "pre-live-adjudication": inputs.pre_live_adjudication.raw,
        "opus-review-evidence": inputs.opus_review_evidence.raw,
        "opus-adjudication": inputs.opus_adjudication.raw,
        "spark-validation-receipt": inputs.spark_validation_receipt.raw,
        "predecessor-authorization": proof.authorization.raw,
        "predecessor-manifest": proof.manifest.raw,
        "predecessor-authorization-state": proof.authorization_state.raw,
        "predecessor-failure-evidence": proof.failure_evidence.raw,
        "predecessor-containment": proof.containment.raw,
        "predecessor-allocation-ledger": proof.allocation_ledger.raw,
        "predecessor-allocation-audit": proof.allocation_audit_bytes,
        "predecessor-recovery-cause-evidence": (
            proof.authorization_recovery_cause_evidence.raw
        ),
        "predecessor-recovery-cause-source-analysis": (
            proof.authorization_recovery_cause_source_analysis
        ),
        "predecessor-outer-authority": proof.outer_authority.raw,
        "predecessor-independent-validation-receipt": (
            proof.independent_validation_receipt.raw
        ),
        "ancestor-authorization": ancestor.authorization.raw,
        "ancestor-manifest": ancestor.manifest.raw,
        "ancestor-authorization-state": ancestor.authorization_state.raw,
        "ancestor-failure-evidence": ancestor.failure_evidence.raw,
        "ancestor-containment": ancestor.containment.raw,
        "ancestor-allocation-ledger": ancestor.allocation_ledger.raw,
        "ancestor-allocation-audit": ancestor.allocation_audit_bytes,
        "ancestor-authorization-cause-evidence": (
            ancestor.authorization_cause_evidence
        ),
        "ancestor-outer-authority": ancestor.outer_authority.raw,
        "ancestor-independent-validation-receipt": (
            ancestor.independent_validation_receipt.raw
        ),
        "grandancestor-authorization-cause-evidence": (
            grandancestor.cause_evidence
        ),
        "grandancestor-authorization": grandancestor.authorization.raw,
        "grandancestor-manifest": grandancestor.manifest.raw,
        "grandancestor-authorization-state": (
            grandancestor.authorization_state.raw
        ),
        "grandancestor-failure-evidence": grandancestor.failure_evidence.raw,
        "grandancestor-original-containment": (
            grandancestor.original_containment.raw
        ),
        "grandancestor-containment": grandancestor.containment.raw,
        "grandancestor-allocation-ledger": grandancestor.allocation_ledger.raw,
        "grandancestor-allocation-audit": grandancestor.allocation_audit_bytes,
        "cause-evidence": inputs.recovery_cause_evidence.raw,
        "cause-source-analysis": inputs.recovery_cause_source_analysis_bytes,
    }


def generation8_trusted_session_snapshots(
    inputs: CampaignLaunchInputs,
) -> dict[str, bytes]:
    """Flatten every JSONL boundary in the fixed Generation-8 proof DAG."""

    proof = require_generation8_launch_inputs(inputs)
    ancestor = proof.ancestor
    grandancestor = ancestor.ancestor
    snapshots = {
        "spark-validation-session": inputs.spark_validation_session_bytes,
        "predecessor-independent-validation-session": (
            proof.independent_validation_session_bytes
        ),
        "ancestor-independent-validation-session": (
            ancestor.independent_validation_session_bytes
        ),
    }
    snapshots.update(
        {
            f"predecessor-contained-session-{index}": raw
            for index, raw in enumerate(proof.contained_session_bytes)
        }
    )
    snapshots.update(
        {
            f"ancestor-contained-session-{index}": raw
            for index, raw in enumerate(ancestor.contained_session_bytes)
        }
    )
    snapshots.update(
        {
            f"grandancestor-contained-session-{index}": raw
            for index, raw in enumerate(grandancestor.contained_session_bytes)
        }
    )
    return snapshots


def generation8_source_file_sha256s(
    inputs: CampaignLaunchInputs,
) -> dict[str, str]:
    """Hash every read-once source bound by validation and launch claim v2."""

    return {
        label: sha256_bytes(raw)
        for label, raw in sorted(
            {
                **generation8_private_source_snapshots(inputs),
                **generation8_trusted_session_snapshots(inputs),
            }.items()
        )
    }


def require_generation9_launch_inputs(
    inputs: CampaignLaunchInputs,
) -> Version7QuarantinePredecessorProofInputs:
    """Return the fixed Gen8 quarantine proof or reject a mixed generation."""

    if (
        inputs.authorization.value.get("version") != 8
        or inputs.manifest.value.get("version") != 5
        or not isinstance(
            inputs.predecessor_proof,
            Version7QuarantinePredecessorProofInputs,
        )
        or inputs.legacy_predecessor is not None
        or not isinstance(inputs.recovery_cause_evidence, JsonArtifactSnapshot)
        or not isinstance(inputs.recovery_cause_source_analysis_bytes, bytes)
    ):
        raise AppServerError("campaign-generation9-proof-input-invalid")
    return inputs.predecessor_proof


def generation9_private_source_snapshots(
    inputs: CampaignLaunchInputs,
) -> dict[str, bytes]:
    """Flatten every non-session source in the fixed v8/v5 proof DAG."""

    quarantine = require_generation9_launch_inputs(inputs)
    predecessor = quarantine.ancestor
    ancestor = predecessor.ancestor
    grandancestor = ancestor.ancestor
    return {
        "authorization": inputs.authorization.raw,
        "campaign-manifest": inputs.manifest.raw,
        "outer-authority": inputs.outer_authority.raw,
        "release-patch": inputs.release_patch_bytes,
        "pre-mutation-steering-receipt": inputs.pre_mutation_receipt.raw,
        "pre-mutation-adjudication": inputs.pre_mutation_adjudication.raw,
        "pre-live-steering-receipt": inputs.pre_live_receipt.raw,
        "pre-live-adjudication": inputs.pre_live_adjudication.raw,
        "opus-review-evidence": inputs.opus_review_evidence.raw,
        "opus-adjudication": inputs.opus_adjudication.raw,
        "spark-validation-receipt": inputs.spark_validation_receipt.raw,
        "quarantined-predecessor-authorization": quarantine.authorization.raw,
        "quarantined-predecessor-manifest": quarantine.manifest.raw,
        "quarantined-predecessor-authorization-state": (
            quarantine.authorization_state.raw
        ),
        "quarantined-predecessor-failure-evidence": (
            quarantine.failure_evidence.raw
        ),
        "quarantined-predecessor-containment": quarantine.containment.raw,
        "quarantined-predecessor-allocation-ledger": (
            quarantine.allocation_ledger.raw
        ),
        "quarantined-predecessor-allocation-audit": (
            quarantine.allocation_audit_bytes
        ),
        "quarantined-predecessor-recovery-cause-evidence": (
            quarantine.authorization_recovery_cause_evidence.raw
        ),
        "quarantined-predecessor-recovery-cause-source-analysis": (
            quarantine.authorization_recovery_cause_source_analysis
        ),
        "quarantined-predecessor-outer-authority": quarantine.outer_authority.raw,
        "quarantined-predecessor-independent-validation-receipt": (
            quarantine.independent_validation_receipt.raw
        ),
        "predecessor-authorization": predecessor.authorization.raw,
        "predecessor-manifest": predecessor.manifest.raw,
        "predecessor-authorization-state": predecessor.authorization_state.raw,
        "predecessor-failure-evidence": predecessor.failure_evidence.raw,
        "predecessor-containment": predecessor.containment.raw,
        "predecessor-allocation-ledger": predecessor.allocation_ledger.raw,
        "predecessor-allocation-audit": predecessor.allocation_audit_bytes,
        "predecessor-recovery-cause-evidence": (
            predecessor.authorization_recovery_cause_evidence.raw
        ),
        "predecessor-recovery-cause-source-analysis": (
            predecessor.authorization_recovery_cause_source_analysis
        ),
        "predecessor-outer-authority": predecessor.outer_authority.raw,
        "predecessor-independent-validation-receipt": (
            predecessor.independent_validation_receipt.raw
        ),
        "ancestor-authorization": ancestor.authorization.raw,
        "ancestor-manifest": ancestor.manifest.raw,
        "ancestor-authorization-state": ancestor.authorization_state.raw,
        "ancestor-failure-evidence": ancestor.failure_evidence.raw,
        "ancestor-containment": ancestor.containment.raw,
        "ancestor-allocation-ledger": ancestor.allocation_ledger.raw,
        "ancestor-allocation-audit": ancestor.allocation_audit_bytes,
        "ancestor-authorization-cause-evidence": (
            ancestor.authorization_cause_evidence
        ),
        "ancestor-outer-authority": ancestor.outer_authority.raw,
        "ancestor-independent-validation-receipt": (
            ancestor.independent_validation_receipt.raw
        ),
        "grandancestor-authorization-cause-evidence": grandancestor.cause_evidence,
        "grandancestor-authorization": grandancestor.authorization.raw,
        "grandancestor-manifest": grandancestor.manifest.raw,
        "grandancestor-authorization-state": (
            grandancestor.authorization_state.raw
        ),
        "grandancestor-failure-evidence": grandancestor.failure_evidence.raw,
        "grandancestor-original-containment": (
            grandancestor.original_containment.raw
        ),
        "grandancestor-containment": grandancestor.containment.raw,
        "grandancestor-allocation-ledger": grandancestor.allocation_ledger.raw,
        "grandancestor-allocation-audit": grandancestor.allocation_audit_bytes,
        "cause-evidence": inputs.recovery_cause_evidence.raw,
        "cause-source-analysis": inputs.recovery_cause_source_analysis_bytes,
    }


def generation9_trusted_session_snapshots(
    inputs: CampaignLaunchInputs,
) -> dict[str, bytes]:
    """Flatten every JSONL boundary in the fixed Generation-9 proof DAG."""

    quarantine = require_generation9_launch_inputs(inputs)
    predecessor = quarantine.ancestor
    ancestor = predecessor.ancestor
    grandancestor = ancestor.ancestor
    snapshots = {
        "spark-validation-session": inputs.spark_validation_session_bytes,
        "quarantined-predecessor-independent-validation-session": (
            quarantine.independent_validation_session_bytes
        ),
        "quarantined-predecessor-session": quarantine.quarantined_session_bytes,
        "predecessor-independent-validation-session": (
            predecessor.independent_validation_session_bytes
        ),
        "ancestor-independent-validation-session": (
            ancestor.independent_validation_session_bytes
        ),
    }
    snapshots.update(
        {
            f"predecessor-contained-session-{index}": raw
            for index, raw in enumerate(predecessor.contained_session_bytes)
        }
    )
    snapshots.update(
        {
            f"ancestor-contained-session-{index}": raw
            for index, raw in enumerate(ancestor.contained_session_bytes)
        }
    )
    snapshots.update(
        {
            f"grandancestor-contained-session-{index}": raw
            for index, raw in enumerate(grandancestor.contained_session_bytes)
        }
    )
    return snapshots


def generation9_source_file_sha256s(
    inputs: CampaignLaunchInputs,
) -> dict[str, str]:
    """Hash every read-once source bound by validation and launch claim v3."""

    return {
        label: sha256_bytes(raw)
        for label, raw in sorted(
            {
                **generation9_private_source_snapshots(inputs),
                **generation9_trusted_session_snapshots(inputs),
            }.items()
        )
    }


def require_generation10_launch_inputs(
    inputs: CampaignLaunchInputs,
) -> Version8ProtectedFaultPredecessorProofInputs:
    """Return the fixed terminal Gen9 proof or reject a mixed generation."""

    if (
        inputs.authorization.value.get("version") != 9
        or inputs.manifest.value.get("version") != 6
        or not isinstance(
            inputs.predecessor_proof,
            Version8ProtectedFaultPredecessorProofInputs,
        )
        or inputs.legacy_predecessor is not None
        or not isinstance(inputs.recovery_cause_evidence, JsonArtifactSnapshot)
        or not isinstance(inputs.recovery_cause_source_analysis_bytes, bytes)
    ):
        raise AppServerError("campaign-generation10-proof-input-invalid")
    return inputs.predecessor_proof


def generation10_private_source_snapshots(
    inputs: CampaignLaunchInputs,
) -> dict[str, bytes]:
    """Flatten every non-session source in the fixed v9/v6 proof DAG."""

    failed = require_generation10_launch_inputs(inputs)
    quarantine = failed.ancestor
    predecessor = quarantine.ancestor
    ancestor = predecessor.ancestor
    grandancestor = ancestor.ancestor
    return {
        "authorization": inputs.authorization.raw,
        "campaign-manifest": inputs.manifest.raw,
        "outer-authority": inputs.outer_authority.raw,
        "release-patch": inputs.release_patch_bytes,
        "pre-mutation-steering-receipt": inputs.pre_mutation_receipt.raw,
        "pre-mutation-adjudication": inputs.pre_mutation_adjudication.raw,
        "pre-live-steering-receipt": inputs.pre_live_receipt.raw,
        "pre-live-adjudication": inputs.pre_live_adjudication.raw,
        "opus-review-evidence": inputs.opus_review_evidence.raw,
        "opus-adjudication": inputs.opus_adjudication.raw,
        "spark-validation-receipt": inputs.spark_validation_receipt.raw,
        "failed-predecessor-authorization": failed.authorization.raw,
        "failed-predecessor-manifest": failed.manifest.raw,
        "failed-predecessor-authorization-state": failed.authorization_state.raw,
        "failed-predecessor-failure-evidence": failed.failure_evidence.raw,
        "failed-predecessor-containment": failed.containment.raw,
        "failed-predecessor-allocation-ledger": failed.allocation_ledger.raw,
        "failed-predecessor-allocation-audit": failed.allocation_audit_bytes,
        "failed-predecessor-recovery-cause-evidence": (
            failed.authorization_recovery_cause_evidence.raw
        ),
        "failed-predecessor-recovery-cause-source-analysis": (
            failed.authorization_recovery_cause_source_analysis
        ),
        "failed-predecessor-outer-authority": failed.outer_authority.raw,
        "failed-predecessor-independent-validation-receipt": (
            failed.independent_validation_receipt.raw
        ),
        "quarantined-predecessor-authorization": quarantine.authorization.raw,
        "quarantined-predecessor-manifest": quarantine.manifest.raw,
        "quarantined-predecessor-authorization-state": (
            quarantine.authorization_state.raw
        ),
        "quarantined-predecessor-failure-evidence": quarantine.failure_evidence.raw,
        "quarantined-predecessor-containment": quarantine.containment.raw,
        "quarantined-predecessor-allocation-ledger": quarantine.allocation_ledger.raw,
        "quarantined-predecessor-allocation-audit": (
            quarantine.allocation_audit_bytes
        ),
        "quarantined-predecessor-recovery-cause-evidence": (
            quarantine.authorization_recovery_cause_evidence.raw
        ),
        "quarantined-predecessor-recovery-cause-source-analysis": (
            quarantine.authorization_recovery_cause_source_analysis
        ),
        "quarantined-predecessor-outer-authority": quarantine.outer_authority.raw,
        "quarantined-predecessor-independent-validation-receipt": (
            quarantine.independent_validation_receipt.raw
        ),
        "predecessor-authorization": predecessor.authorization.raw,
        "predecessor-manifest": predecessor.manifest.raw,
        "predecessor-authorization-state": predecessor.authorization_state.raw,
        "predecessor-failure-evidence": predecessor.failure_evidence.raw,
        "predecessor-containment": predecessor.containment.raw,
        "predecessor-allocation-ledger": predecessor.allocation_ledger.raw,
        "predecessor-allocation-audit": predecessor.allocation_audit_bytes,
        "predecessor-recovery-cause-evidence": (
            predecessor.authorization_recovery_cause_evidence.raw
        ),
        "predecessor-recovery-cause-source-analysis": (
            predecessor.authorization_recovery_cause_source_analysis
        ),
        "predecessor-outer-authority": predecessor.outer_authority.raw,
        "predecessor-independent-validation-receipt": (
            predecessor.independent_validation_receipt.raw
        ),
        "ancestor-authorization": ancestor.authorization.raw,
        "ancestor-manifest": ancestor.manifest.raw,
        "ancestor-authorization-state": ancestor.authorization_state.raw,
        "ancestor-failure-evidence": ancestor.failure_evidence.raw,
        "ancestor-containment": ancestor.containment.raw,
        "ancestor-allocation-ledger": ancestor.allocation_ledger.raw,
        "ancestor-allocation-audit": ancestor.allocation_audit_bytes,
        "ancestor-authorization-cause-evidence": ancestor.authorization_cause_evidence,
        "ancestor-outer-authority": ancestor.outer_authority.raw,
        "ancestor-independent-validation-receipt": (
            ancestor.independent_validation_receipt.raw
        ),
        "grandancestor-authorization-cause-evidence": grandancestor.cause_evidence,
        "grandancestor-authorization": grandancestor.authorization.raw,
        "grandancestor-manifest": grandancestor.manifest.raw,
        "grandancestor-authorization-state": grandancestor.authorization_state.raw,
        "grandancestor-failure-evidence": grandancestor.failure_evidence.raw,
        "grandancestor-original-containment": grandancestor.original_containment.raw,
        "grandancestor-containment": grandancestor.containment.raw,
        "grandancestor-allocation-ledger": grandancestor.allocation_ledger.raw,
        "grandancestor-allocation-audit": grandancestor.allocation_audit_bytes,
        "cause-evidence": inputs.recovery_cause_evidence.raw,
        "cause-source-analysis": inputs.recovery_cause_source_analysis_bytes,
    }


def generation10_trusted_session_snapshots(
    inputs: CampaignLaunchInputs,
) -> dict[str, bytes]:
    """Flatten every JSONL boundary in the fixed Generation-10 proof DAG."""

    failed = require_generation10_launch_inputs(inputs)
    quarantine = failed.ancestor
    predecessor = quarantine.ancestor
    ancestor = predecessor.ancestor
    grandancestor = ancestor.ancestor
    snapshots = {
        "spark-validation-session": inputs.spark_validation_session_bytes,
        "failed-predecessor-independent-validation-session": (
            failed.independent_validation_session_bytes
        ),
        "quarantined-predecessor-independent-validation-session": (
            quarantine.independent_validation_session_bytes
        ),
        "quarantined-predecessor-session": quarantine.quarantined_session_bytes,
        "predecessor-independent-validation-session": (
            predecessor.independent_validation_session_bytes
        ),
        "ancestor-independent-validation-session": (
            ancestor.independent_validation_session_bytes
        ),
    }
    snapshots.update(
        {
            f"failed-predecessor-contained-session-{index}": raw
            for index, raw in enumerate(failed.contained_session_bytes)
        }
    )
    snapshots.update(
        {
            f"predecessor-contained-session-{index}": raw
            for index, raw in enumerate(predecessor.contained_session_bytes)
        }
    )
    snapshots.update(
        {
            f"ancestor-contained-session-{index}": raw
            for index, raw in enumerate(ancestor.contained_session_bytes)
        }
    )
    snapshots.update(
        {
            f"grandancestor-contained-session-{index}": raw
            for index, raw in enumerate(grandancestor.contained_session_bytes)
        }
    )
    return snapshots


def generation10_source_file_sha256s(
    inputs: CampaignLaunchInputs,
) -> dict[str, str]:
    """Hash every read-once source bound by validation and launch claim v4."""

    return {
        label: sha256_bytes(raw)
        for label, raw in sorted(
            {
                **generation10_private_source_snapshots(inputs),
                **generation10_trusted_session_snapshots(inputs),
            }.items()
        )
    }


def require_generation11_launch_inputs(
    inputs: CampaignLaunchInputs,
) -> Version9PreallocationFaultPredecessorProofInputs:
    """Return the fixed terminal Gen10 proof or reject a mixed generation."""

    if (
        inputs.authorization.value.get("version") != 10
        or inputs.manifest.value.get("version") != 7
        or not isinstance(
            inputs.predecessor_proof,
            Version9PreallocationFaultPredecessorProofInputs,
        )
        or inputs.legacy_predecessor is not None
        or not isinstance(inputs.recovery_cause_evidence, JsonArtifactSnapshot)
        or not isinstance(inputs.recovery_cause_source_analysis_bytes, bytes)
    ):
        raise AppServerError("campaign-generation11-proof-input-invalid")
    return inputs.predecessor_proof


def generation11_private_source_snapshots(
    inputs: CampaignLaunchInputs,
) -> dict[str, bytes]:
    """Flatten every non-session source in the fixed v10/v7 proof DAG."""

    preallocation = require_generation11_launch_inputs(inputs)
    failed = preallocation.ancestor
    quarantine = failed.ancestor
    predecessor = quarantine.ancestor
    ancestor = predecessor.ancestor
    grandancestor = ancestor.ancestor
    return {
        "authorization": inputs.authorization.raw,
        "campaign-manifest": inputs.manifest.raw,
        "outer-authority": inputs.outer_authority.raw,
        "release-patch": inputs.release_patch_bytes,
        "pre-mutation-steering-receipt": inputs.pre_mutation_receipt.raw,
        "pre-mutation-adjudication": inputs.pre_mutation_adjudication.raw,
        "pre-live-steering-receipt": inputs.pre_live_receipt.raw,
        "pre-live-adjudication": inputs.pre_live_adjudication.raw,
        "opus-review-evidence": inputs.opus_review_evidence.raw,
        "opus-adjudication": inputs.opus_adjudication.raw,
        "spark-validation-receipt": inputs.spark_validation_receipt.raw,
        "preallocation-failed-predecessor-authorization": (
            preallocation.authorization.raw
        ),
        "preallocation-failed-predecessor-manifest": preallocation.manifest.raw,
        "preallocation-failed-predecessor-authorization-state": (
            preallocation.authorization_state.raw
        ),
        "preallocation-failed-predecessor-failure-evidence": (
            preallocation.failure_evidence.raw
        ),
        "preallocation-failed-predecessor-containment": (
            preallocation.containment.raw
        ),
        "preallocation-failed-predecessor-global-claim": (
            preallocation.global_claim.raw
        ),
        "preallocation-failed-predecessor-authorization-marker": (
            preallocation.authorization_marker.raw
        ),
        "preallocation-failed-predecessor-nonce-marker": (
            preallocation.nonce_marker.raw
        ),
        "preallocation-failed-predecessor-scope-state": (
            preallocation.scope_state.raw
        ),
        "preallocation-failed-predecessor-preflight": preallocation.preflight.raw,
        "preallocation-failed-predecessor-pre-mutation-receipt": (
            preallocation.pre_mutation_receipt.raw
        ),
        "preallocation-failed-predecessor-pre-live-receipt": (
            preallocation.pre_live_receipt.raw
        ),
        "preallocation-failed-predecessor-recovery-cause-evidence": (
            preallocation.authorization_recovery_cause_evidence.raw
        ),
        "preallocation-failed-predecessor-recovery-cause-source-analysis": (
            preallocation.authorization_recovery_cause_source_analysis
        ),
        "preallocation-failed-predecessor-outer-authority": (
            preallocation.outer_authority.raw
        ),
        "preallocation-failed-predecessor-independent-validation-receipt": (
            preallocation.independent_validation_receipt.raw
        ),
        "failed-predecessor-authorization": failed.authorization.raw,
        "failed-predecessor-manifest": failed.manifest.raw,
        "failed-predecessor-authorization-state": failed.authorization_state.raw,
        "failed-predecessor-failure-evidence": failed.failure_evidence.raw,
        "failed-predecessor-containment": failed.containment.raw,
        "failed-predecessor-allocation-ledger": failed.allocation_ledger.raw,
        "failed-predecessor-allocation-audit": failed.allocation_audit_bytes,
        "failed-predecessor-recovery-cause-evidence": (
            failed.authorization_recovery_cause_evidence.raw
        ),
        "failed-predecessor-recovery-cause-source-analysis": (
            failed.authorization_recovery_cause_source_analysis
        ),
        "failed-predecessor-outer-authority": failed.outer_authority.raw,
        "failed-predecessor-independent-validation-receipt": (
            failed.independent_validation_receipt.raw
        ),
        "quarantined-predecessor-authorization": quarantine.authorization.raw,
        "quarantined-predecessor-manifest": quarantine.manifest.raw,
        "quarantined-predecessor-authorization-state": (
            quarantine.authorization_state.raw
        ),
        "quarantined-predecessor-failure-evidence": quarantine.failure_evidence.raw,
        "quarantined-predecessor-containment": quarantine.containment.raw,
        "quarantined-predecessor-allocation-ledger": quarantine.allocation_ledger.raw,
        "quarantined-predecessor-allocation-audit": (
            quarantine.allocation_audit_bytes
        ),
        "quarantined-predecessor-recovery-cause-evidence": (
            quarantine.authorization_recovery_cause_evidence.raw
        ),
        "quarantined-predecessor-recovery-cause-source-analysis": (
            quarantine.authorization_recovery_cause_source_analysis
        ),
        "quarantined-predecessor-outer-authority": quarantine.outer_authority.raw,
        "quarantined-predecessor-independent-validation-receipt": (
            quarantine.independent_validation_receipt.raw
        ),
        "predecessor-authorization": predecessor.authorization.raw,
        "predecessor-manifest": predecessor.manifest.raw,
        "predecessor-authorization-state": predecessor.authorization_state.raw,
        "predecessor-failure-evidence": predecessor.failure_evidence.raw,
        "predecessor-containment": predecessor.containment.raw,
        "predecessor-allocation-ledger": predecessor.allocation_ledger.raw,
        "predecessor-allocation-audit": predecessor.allocation_audit_bytes,
        "predecessor-recovery-cause-evidence": (
            predecessor.authorization_recovery_cause_evidence.raw
        ),
        "predecessor-recovery-cause-source-analysis": (
            predecessor.authorization_recovery_cause_source_analysis
        ),
        "predecessor-outer-authority": predecessor.outer_authority.raw,
        "predecessor-independent-validation-receipt": (
            predecessor.independent_validation_receipt.raw
        ),
        "ancestor-authorization": ancestor.authorization.raw,
        "ancestor-manifest": ancestor.manifest.raw,
        "ancestor-authorization-state": ancestor.authorization_state.raw,
        "ancestor-failure-evidence": ancestor.failure_evidence.raw,
        "ancestor-containment": ancestor.containment.raw,
        "ancestor-allocation-ledger": ancestor.allocation_ledger.raw,
        "ancestor-allocation-audit": ancestor.allocation_audit_bytes,
        "ancestor-authorization-cause-evidence": ancestor.authorization_cause_evidence,
        "ancestor-outer-authority": ancestor.outer_authority.raw,
        "ancestor-independent-validation-receipt": (
            ancestor.independent_validation_receipt.raw
        ),
        "grandancestor-authorization-cause-evidence": grandancestor.cause_evidence,
        "grandancestor-authorization": grandancestor.authorization.raw,
        "grandancestor-manifest": grandancestor.manifest.raw,
        "grandancestor-authorization-state": grandancestor.authorization_state.raw,
        "grandancestor-failure-evidence": grandancestor.failure_evidence.raw,
        "grandancestor-original-containment": grandancestor.original_containment.raw,
        "grandancestor-containment": grandancestor.containment.raw,
        "grandancestor-allocation-ledger": grandancestor.allocation_ledger.raw,
        "grandancestor-allocation-audit": grandancestor.allocation_audit_bytes,
        "cause-evidence": inputs.recovery_cause_evidence.raw,
        "cause-source-analysis": inputs.recovery_cause_source_analysis_bytes,
    }


def generation11_trusted_session_snapshots(
    inputs: CampaignLaunchInputs,
) -> dict[str, bytes]:
    """Flatten every JSONL boundary in the fixed Generation-11 proof DAG."""

    preallocation = require_generation11_launch_inputs(inputs)
    failed = preallocation.ancestor
    quarantine = failed.ancestor
    predecessor = quarantine.ancestor
    ancestor = predecessor.ancestor
    grandancestor = ancestor.ancestor
    snapshots = {
        "spark-validation-session": inputs.spark_validation_session_bytes,
        "preallocation-failed-predecessor-independent-validation-session": (
            preallocation.independent_validation_session_bytes
        ),
        "failed-predecessor-independent-validation-session": (
            failed.independent_validation_session_bytes
        ),
        "quarantined-predecessor-independent-validation-session": (
            quarantine.independent_validation_session_bytes
        ),
        "quarantined-predecessor-session": quarantine.quarantined_session_bytes,
        "predecessor-independent-validation-session": (
            predecessor.independent_validation_session_bytes
        ),
        "ancestor-independent-validation-session": (
            ancestor.independent_validation_session_bytes
        ),
    }
    snapshots.update(
        {
            f"failed-predecessor-contained-session-{index}": raw
            for index, raw in enumerate(failed.contained_session_bytes)
        }
    )
    snapshots.update(
        {
            f"predecessor-contained-session-{index}": raw
            for index, raw in enumerate(predecessor.contained_session_bytes)
        }
    )
    snapshots.update(
        {
            f"ancestor-contained-session-{index}": raw
            for index, raw in enumerate(ancestor.contained_session_bytes)
        }
    )
    snapshots.update(
        {
            f"grandancestor-contained-session-{index}": raw
            for index, raw in enumerate(grandancestor.contained_session_bytes)
        }
    )
    return snapshots


def generation11_source_file_sha256s(
    inputs: CampaignLaunchInputs,
) -> dict[str, str]:
    """Hash every read-once source bound by validation and launch claim v5."""

    return {
        label: sha256_bytes(raw)
        for label, raw in sorted(
            {
                **generation11_private_source_snapshots(inputs),
                **generation11_trusted_session_snapshots(inputs),
            }.items()
        )
    }


def require_generation12_launch_inputs(
    inputs: CampaignLaunchInputs,
) -> Version10InterruptedEmptyBoundaryPredecessorProofInputs:
    """Return the exact terminal Gen11 leaf or reject a mixed generation."""

    if (
        inputs.authorization.value.get("version") != 11
        or inputs.manifest.value.get("version") != 8
        or not isinstance(
            inputs.predecessor_proof,
            Version10InterruptedEmptyBoundaryPredecessorProofInputs,
        )
        or inputs.legacy_predecessor is not None
        or not isinstance(inputs.recovery_cause_evidence, JsonArtifactSnapshot)
        or not isinstance(inputs.recovery_cause_source_analysis_bytes, bytes)
    ):
        raise AppServerError("campaign-generation12-proof-input-invalid")
    return inputs.predecessor_proof


_GENERATION11_TOP_LEVEL_PRIVATE_SOURCE_LABELS = {
    "authorization",
    "campaign-manifest",
    "outer-authority",
    "release-patch",
    "pre-mutation-steering-receipt",
    "pre-mutation-adjudication",
    "pre-live-steering-receipt",
    "pre-live-adjudication",
    "opus-review-evidence",
    "opus-adjudication",
    "spark-validation-receipt",
    "cause-evidence",
    "cause-source-analysis",
}


def _generation11_ancestor_launch_inputs(
    inputs: CampaignLaunchInputs,
    interrupted: Version10InterruptedEmptyBoundaryPredecessorProofInputs,
) -> CampaignLaunchInputs:
    """Project the fixed v10/v7 ancestor into the frozen Gen11 flattener.

    Only ancestor-prefixed sources survive the caller's filter.  Reusing the
    frozen flattener prevents the historical subtree from silently drifting as
    Generation 12 adds its immediate terminal leaf.
    """

    return CampaignLaunchInputs(
        authorization=interrupted.authorization,
        manifest=interrupted.manifest,
        outer_authority=interrupted.outer_authority,
        release_patch_bytes=inputs.release_patch_bytes,
        pre_mutation_receipt=interrupted.pre_mutation_receipt,
        pre_mutation_adjudication=inputs.pre_mutation_adjudication,
        pre_live_receipt=interrupted.pre_live_receipt,
        pre_live_adjudication=inputs.pre_live_adjudication,
        opus_review_evidence=inputs.opus_review_evidence,
        opus_adjudication=inputs.opus_adjudication,
        spark_validation_receipt=interrupted.independent_validation_receipt,
        spark_validation_session_path=inputs.spark_validation_session_path,
        spark_validation_session_bytes=(
            interrupted.independent_validation_session_bytes
        ),
        predecessor_proof=interrupted.ancestor,
        recovery_cause_evidence=(
            interrupted.authorization_recovery_cause_evidence
        ),
        recovery_cause_source_analysis_bytes=(
            interrupted.authorization_recovery_cause_source_analysis
        ),
    )


def generation12_private_source_snapshots(
    inputs: CampaignLaunchInputs,
) -> dict[str, bytes]:
    """Flatten every non-session source in the fixed v11/v8 proof DAG."""

    interrupted = require_generation12_launch_inputs(inputs)
    ancestor_inputs = _generation11_ancestor_launch_inputs(inputs, interrupted)
    ancestor_sources = {
        label: raw
        for label, raw in generation11_private_source_snapshots(
            ancestor_inputs
        ).items()
        if label not in _GENERATION11_TOP_LEVEL_PRIVATE_SOURCE_LABELS
    }
    return {
        "authorization": inputs.authorization.raw,
        "campaign-manifest": inputs.manifest.raw,
        "outer-authority": inputs.outer_authority.raw,
        "release-patch": inputs.release_patch_bytes,
        "pre-mutation-steering-receipt": inputs.pre_mutation_receipt.raw,
        "pre-mutation-adjudication": inputs.pre_mutation_adjudication.raw,
        "pre-live-steering-receipt": inputs.pre_live_receipt.raw,
        "pre-live-adjudication": inputs.pre_live_adjudication.raw,
        "opus-review-evidence": inputs.opus_review_evidence.raw,
        "opus-adjudication": inputs.opus_adjudication.raw,
        "spark-validation-receipt": inputs.spark_validation_receipt.raw,
        "interrupted-failed-predecessor-authorization": (
            interrupted.authorization.raw
        ),
        "interrupted-failed-predecessor-manifest": interrupted.manifest.raw,
        "interrupted-failed-predecessor-authorization-state": (
            interrupted.authorization_state.raw
        ),
        "interrupted-failed-predecessor-failure-evidence": (
            interrupted.failure_evidence.raw
        ),
        "interrupted-failed-predecessor-containment": interrupted.containment.raw,
        "interrupted-failed-predecessor-global-claim": interrupted.global_claim.raw,
        "interrupted-failed-predecessor-authorization-marker": (
            interrupted.authorization_marker.raw
        ),
        "interrupted-failed-predecessor-nonce-marker": (
            interrupted.nonce_marker.raw
        ),
        "interrupted-failed-predecessor-scope-state": interrupted.scope_state.raw,
        "interrupted-failed-predecessor-preflight": interrupted.preflight.raw,
        "interrupted-failed-predecessor-pre-mutation-receipt": (
            interrupted.pre_mutation_receipt.raw
        ),
        "interrupted-failed-predecessor-pre-mutation-adjudication": (
            interrupted.pre_mutation_adjudication.raw
        ),
        "interrupted-failed-predecessor-pre-live-receipt": (
            interrupted.pre_live_receipt.raw
        ),
        "interrupted-failed-predecessor-pre-live-adjudication": (
            interrupted.pre_live_adjudication.raw
        ),
        "interrupted-failed-predecessor-allocation-ledger": (
            interrupted.allocation_ledger.raw
        ),
        "interrupted-failed-predecessor-allocation-audit": (
            interrupted.allocation_audit_bytes
        ),
        "interrupted-failed-predecessor-steering-registry": (
            interrupted.steering_registry.raw
        ),
        "interrupted-failed-predecessor-terminal-facts": interrupted.terminal_facts.raw,
        "interrupted-failed-predecessor-generation11-runner-source": (
            interrupted.generation11_runner_source_bytes
        ),
        "interrupted-failed-predecessor-generation11-session-boundary-source": (
            interrupted.generation11_session_boundary_source_bytes
        ),
        "interrupted-failed-predecessor-recovery-cause-analysis": (
            interrupted.recovery_cause_analysis_bytes
        ),
        "interrupted-failed-predecessor-recovery-steering-receipt": (
            interrupted.recovery_steering_receipt.raw
        ),
        "interrupted-failed-predecessor-recovery-cause-evidence": (
            interrupted.authorization_recovery_cause_evidence.raw
        ),
        "interrupted-failed-predecessor-recovery-cause-source-analysis": (
            interrupted.authorization_recovery_cause_source_analysis
        ),
        "interrupted-failed-predecessor-outer-authority": (
            interrupted.outer_authority.raw
        ),
        "interrupted-failed-predecessor-independent-validation-receipt": (
            interrupted.independent_validation_receipt.raw
        ),
        **ancestor_sources,
        "cause-evidence": inputs.recovery_cause_evidence.raw,
        "cause-source-analysis": inputs.recovery_cause_source_analysis_bytes,
    }


def generation12_trusted_session_snapshots(
    inputs: CampaignLaunchInputs,
) -> dict[str, bytes]:
    """Flatten current validation plus the one terminal Gen11 session."""

    interrupted = require_generation12_launch_inputs(inputs)
    ancestor_inputs = _generation11_ancestor_launch_inputs(inputs, interrupted)
    ancestor_sessions = {
        label: raw
        for label, raw in generation11_trusted_session_snapshots(
            ancestor_inputs
        ).items()
        if label != "spark-validation-session"
    }
    return {
        "spark-validation-session": inputs.spark_validation_session_bytes,
        "interrupted-failed-predecessor-terminal-session": (
            interrupted.terminal_session_bytes
        ),
        "interrupted-failed-predecessor-independent-validation-session": (
            interrupted.independent_validation_session_bytes
        ),
        "interrupted-failed-predecessor-recovery-steering-session": (
            interrupted.recovery_steering_session_bytes
        ),
        **ancestor_sessions,
    }


def generation12_source_file_sha256s(
    inputs: CampaignLaunchInputs,
) -> dict[str, str]:
    """Hash every read-once source bound by validation and launch claim v6."""

    return {
        label: sha256_bytes(raw)
        for label, raw in sorted(
            {
                **generation12_private_source_snapshots(inputs),
                **generation12_trusted_session_snapshots(inputs),
            }.items()
        )
    }


def require_trusted_session_snapshots_unchanged(
    paths: Mapping[str, Path], inputs: CampaignLaunchInputs
) -> None:
    """Re-read every trusted JSONL immediately before the first allocation."""

    if inputs.authorization.value.get("version") == 11:
        expected = generation12_trusted_session_snapshots(inputs)
    elif inputs.authorization.value.get("version") == 10:
        expected = generation11_trusted_session_snapshots(inputs)
    elif inputs.authorization.value.get("version") == 9:
        expected = generation10_trusted_session_snapshots(inputs)
    elif inputs.authorization.value.get("version") == 8:
        expected = generation9_trusted_session_snapshots(inputs)
    elif inputs.authorization.value.get("version") == 7:
        expected = generation8_trusted_session_snapshots(inputs)
    else:
        proof = inputs.predecessor_proof
        if not isinstance(proof, Version5PredecessorProofInputs):
            raise AppServerError("campaign-historical-proof-input-invalid")
        expected = {
            "spark-validation-session": inputs.spark_validation_session_bytes,
            "predecessor-independent-validation-session": (
                proof.independent_validation_session_bytes
            ),
            **{
                f"predecessor-contained-session-{index}": raw
                for index, raw in enumerate(proof.contained_session_bytes)
            },
            **{
                f"ancestor-contained-session-{index}": raw
                for index, raw in enumerate(proof.ancestor.contained_session_bytes)
            },
        }
    for label, snapshot in expected.items():
        path = paths.get(label)
        if path is None:
            raise AppServerError(f"{label}-path-missing")
        expected_identity = inputs.source_identities.get(label)
        if expected_identity is None:
            raise AppServerError(f"{label}-source-identity-missing")
        if (
            load_trusted_session_bytes(
                path,
                label,
                expected_identity=tuple(expected_identity),
            )
            != snapshot
        ):
            raise AppServerError(f"{label}-changed-before-allocation")


def require_launch_source_snapshots_unchanged(
    paths: Mapping[str, Path], inputs: CampaignLaunchInputs
) -> None:
    """Recheck every mutable source against the read-once launch snapshots."""

    if inputs.authorization.value.get("version") == 11:
        expected = generation12_private_source_snapshots(inputs)
    elif inputs.authorization.value.get("version") == 10:
        expected = generation11_private_source_snapshots(inputs)
    elif inputs.authorization.value.get("version") == 9:
        expected = generation10_private_source_snapshots(inputs)
    elif inputs.authorization.value.get("version") == 8:
        expected = generation9_private_source_snapshots(inputs)
    elif inputs.authorization.value.get("version") == 7:
        expected = generation8_private_source_snapshots(inputs)
    else:
        proof = inputs.predecessor_proof
        if not isinstance(proof, Version5PredecessorProofInputs):
            raise AppServerError("campaign-historical-proof-input-invalid")
        expected = {
            "authorization": inputs.authorization.raw,
            "campaign-manifest": inputs.manifest.raw,
            "outer-authority": inputs.outer_authority.raw,
            "release-patch": inputs.release_patch_bytes,
            "pre-mutation-steering-receipt": inputs.pre_mutation_receipt.raw,
            "pre-mutation-adjudication": inputs.pre_mutation_adjudication.raw,
            "pre-live-steering-receipt": inputs.pre_live_receipt.raw,
            "pre-live-adjudication": inputs.pre_live_adjudication.raw,
            "opus-review-evidence": inputs.opus_review_evidence.raw,
            "opus-adjudication": inputs.opus_adjudication.raw,
            "spark-validation-receipt": inputs.spark_validation_receipt.raw,
            "predecessor-authorization": proof.authorization.raw,
            "predecessor-manifest": proof.manifest.raw,
            "predecessor-authorization-state": proof.authorization_state.raw,
            "predecessor-failure-evidence": proof.failure_evidence.raw,
            "predecessor-containment": proof.containment.raw,
            "predecessor-allocation-ledger": proof.allocation_ledger.raw,
            "predecessor-allocation-audit": proof.allocation_audit_bytes,
            "predecessor-outer-authority": proof.outer_authority.raw,
            "predecessor-independent-validation-receipt": (
                proof.independent_validation_receipt.raw
            ),
            "predecessor-authorization-cause-evidence": (
                proof.authorization_cause_evidence
            ),
            "ancestor-authorization": proof.ancestor.authorization.raw,
            "ancestor-manifest": proof.ancestor.manifest.raw,
            "ancestor-authorization-state": proof.ancestor.authorization_state.raw,
            "ancestor-failure-evidence": proof.ancestor.failure_evidence.raw,
            "ancestor-original-containment": (
                proof.ancestor.original_containment.raw
            ),
            "ancestor-containment": proof.ancestor.containment.raw,
            "ancestor-allocation-ledger": proof.ancestor.allocation_ledger.raw,
            "ancestor-allocation-audit": proof.ancestor.allocation_audit_bytes,
            "cause-evidence": inputs.recovery_cause_evidence.raw,
            "cause-source-analysis": inputs.recovery_cause_source_analysis_bytes,
        }
    for label, snapshot in expected.items():
        path = paths.get(label)
        expected_identity = inputs.source_identities.get(label)
        if path is None or expected_identity is None:
            raise AppServerError(f"{label}-source-identity-missing")
        if (
            load_private_bytes(
                path,
                label,
                expected_identity=tuple(expected_identity),
            )
            != snapshot
        ):
            raise AppServerError(f"{label}-changed-before-allocation")
    require_trusted_session_snapshots_unchanged(paths, inputs)
    for label, expected_identity in inputs.source_identities.items():
        path = paths.get(label)
        if path is None:
            raise AppServerError(f"{label}-path-missing")
        try:
            info = path.stat()
        except OSError as exc:
            raise AppServerError(f"{label}-source-identity-unavailable") from exc
        if (info.st_dev, info.st_ino, info.st_uid, info.st_mode) != tuple(
            expected_identity
        ):
            raise AppServerError(f"{label}-source-identity-changed")


def _capture_session_snapshot(
    raw: bytes,
    session_id: str,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if not raw or not raw.endswith(b"\n"):
        raise AppServerError("spark-validation-session-telemetry-invalid")
    records: list[dict[str, Any]] = []
    try:
        for line in raw.splitlines(keepends=True):
            if not line.strip():
                continue
            value = json.loads(line.decode("utf-8"))
            if not isinstance(value, dict):
                raise AppServerError("spark-validation-session-telemetry-invalid")
            explicit = value.get("session_id")
            if isinstance(explicit, str) and explicit and explicit != session_id:
                raise AppServerError("spark-validation-session-telemetry-invalid")
            records.append(value)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AppServerError("spark-validation-session-telemetry-invalid") from exc
    identities = {
        str(payload[field])
        for record in records
        if record.get("type") == "session_meta"
        and isinstance((payload := record.get("payload")), Mapping)
        for field in ("id", "session_id")
        if isinstance(payload.get(field), str) and payload.get(field)
    }
    identities.update(
        str(record["session_id"])
        for record in records
        if isinstance(record.get("session_id"), str) and record.get("session_id")
    )
    if not records or identities != {session_id}:
        raise AppServerError("spark-validation-session-telemetry-invalid")
    return (
        {
            "record_count": len(records),
            "byte_offset": len(raw),
            "boundary_sha256": sha256_bytes(raw),
        },
        records,
    )


def validate_independent_validation_session(
    receipt: Mapping[str, Any],
    session_path: Path,
    *,
    codex_home: Path | None = None,
) -> str:
    raw = load_trusted_session_bytes(
        Path(session_path), "spark-validation-session"
    )
    return validate_independent_validation_session_snapshot(
        receipt,
        session_path,
        raw,
        codex_home=codex_home,
    )


def validate_independent_validation_session_snapshot(
    receipt: Mapping[str, Any],
    session_path: Path,
    session_raw: bytes,
    *,
    codex_home: Path | None = None,
) -> str:
    session_id = receipt.get("session_id")
    turn_id = receipt.get("submission_id")
    if not _valid_uuid_text(session_id) or not _valid_uuid_text(turn_id):
        raise AppServerError("spark-validation-session-identity-invalid")
    supplied_path = Path(session_path)
    lexical_path = supplied_path.absolute()
    try:
        resolved_path = supplied_path.resolve(strict=True)
    except OSError as exc:
        raise AppServerError("spark-validation-session-path-invalid") from exc
    if supplied_path.is_symlink() or lexical_path != resolved_path:
        raise AppServerError("spark-validation-session-path-invalid")
    path = resolved_path
    trusted_home = (
        codex_home
        if codex_home is not None
        else Path(os.environ.get("CODEX_HOME", Path.home() / ".codex"))
    ).resolve()
    try:
        relative = path.relative_to(trusted_home)
    except ValueError as exc:
        raise AppServerError("spark-validation-session-path-invalid") from exc
    if (
        len(relative.parts) != 2
        or relative.parts[0] != "archived_sessions"
        or session_id not in relative.name
    ):
        raise AppServerError("spark-validation-session-path-invalid")
    if not session_raw:
        raise AppServerError("spark-validation-session-file-empty")
    boundary_value = receipt.get("boundary")
    expected_terminal = (
        boundary_value.get("terminal") if isinstance(boundary_value, Mapping) else None
    )
    if not isinstance(expected_terminal, Mapping):
        raise AppServerError("spark-validation-session-boundary-invalid")
    try:
        observed_boundary, records = _capture_session_snapshot(session_raw, session_id)
        context_index, _context = trusted_turn_context(
            records,
            turn_id=turn_id,
            model=EXACT_MODEL,
            effort="low",
        )
        markers = telemetry_markers(records, turn_id=turn_id)
        terminal = trusted_terminal_event(records, turn_id=turn_id)
    except (OSError, NativeSessionBoundaryError) as exc:
        raise AppServerError("spark-validation-session-telemetry-invalid") from exc
    if (
        sha256_text(str(path)) != expected_terminal.get("path_sha256")
        or any(
            observed_boundary.get(field) != expected_terminal.get(field)
            for field in ("record_count", "byte_offset", "boundary_sha256")
        )
        or expected_terminal.get("invalid_record_count") != 0
        or expected_terminal.get("trailing_partial") is not False
        or sha256_bytes(session_raw) != observed_boundary.get("boundary_sha256")
        or markers.get("compaction_indices")
        or markers.get("reroute_indices")
        or not isinstance(terminal, Mapping)
        or terminal.get("status") != "completed"
    ):
        raise AppServerError("spark-validation-session-boundary-mismatch")
    session_meta_indices: list[int] = []
    turn_context_indices: list[int] = []
    start_indices: list[int] = []
    terminal_indices: list[int] = []
    agent_messages: list[tuple[int, str]] = []
    assistant_messages: list[tuple[int, str]] = []
    for index, record in enumerate(records):
        record_type = record.get("type")
        payload = record.get("payload")
        if record_type not in INDEPENDENT_VALIDATION_RECORD_TYPES or not isinstance(
            payload, Mapping
        ):
            raise AppServerError("spark-validation-session-activity-invalid")
        payload_type = payload.get("type")
        if record_type in {"session_meta", "world_state", "turn_context"}:
            if payload_type is not None:
                raise AppServerError("spark-validation-session-activity-invalid")
            if record_type == "session_meta":
                session_meta_indices.append(index)
            elif record_type == "turn_context":
                turn_context_indices.append(index)
            continue
        if record_type == "event_msg":
            if payload_type not in INDEPENDENT_VALIDATION_EVENT_TYPES:
                raise AppServerError("spark-validation-session-activity-invalid")
            lifecycle_turn_id = payload.get("turn_id")
            if payload_type in {"task_started", "task_complete"}:
                if lifecycle_turn_id != turn_id:
                    raise AppServerError("spark-validation-session-activity-invalid")
                target = start_indices if payload_type == "task_started" else terminal_indices
                target.append(index)
            if payload_type == "agent_message":
                message = payload.get("message")
                if payload.get("phase") != "final_answer" or not isinstance(message, str):
                    raise AppServerError("spark-validation-session-activity-invalid")
                agent_messages.append((index, message))
            continue
        if payload_type not in INDEPENDENT_VALIDATION_RESPONSE_TYPES:
            raise AppServerError("spark-validation-session-activity-invalid")
        if payload_type == "reasoning":
            continue
        role = payload.get("role")
        if role not in INDEPENDENT_VALIDATION_MESSAGE_ROLES:
            raise AppServerError("spark-validation-session-activity-invalid")
        if role != "assistant":
            continue
        content = payload.get("content")
        if payload.get("phase") != "final_answer" or not isinstance(content, list):
            raise AppServerError("spark-validation-session-activity-invalid")
        output_texts = [
            str(item["text"])
            for item in content
            if isinstance(item, Mapping)
            and item.get("type") == "output_text"
            and isinstance(item.get("text"), str)
        ]
        if len(output_texts) != 1 or len(content) != 1:
            raise AppServerError("spark-validation-session-activity-invalid")
        assistant_messages.append((index, output_texts[0]))
    if (
        len(session_meta_indices) != 1
        or len(turn_context_indices) != 1
        or turn_context_indices[0] != context_index
        or len(start_indices) != 1
        or len(terminal_indices) != 1
        or len(agent_messages) != 1
        or len(assistant_messages) != 1
    ):
        raise AppServerError("spark-validation-session-activity-invalid")
    start_index = start_indices[0]
    terminal_index = terminal_indices[0]
    agent_index, agent_text = agent_messages[0]
    assistant_index, final_text = assistant_messages[0]
    if not (
        session_meta_indices[0] == 0
        and start_index == 1
        and terminal_index == len(records) - 1
        and start_index < context_index < agent_index < assistant_index < terminal_index
    ) or agent_text != final_text:
        raise AppServerError("spark-validation-session-activity-invalid")
    try:
        final_opinion = json.loads(final_text)
    except json.JSONDecodeError as exc:
        raise AppServerError("spark-validation-session-final-json-invalid") from exc
    if (
        sha256_text(final_text) != receipt.get("final_response_sha256")
        or final_opinion != receipt.get("opinion")
    ):
        raise AppServerError("spark-validation-session-final-binding-mismatch")
    return str(observed_boundary["boundary_sha256"])


def guarded_diff_sha256(repo_root: Path) -> str:
    try:
        completed = subprocess.run(
            ["git", "diff", "--binary"],
            cwd=repo_root,
            check=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError as exc:
        raise AppServerError("guarded-primary-diff-unavailable") from exc
    return sha256_bytes(completed.stdout)


def campaign_output_paths(
    output: Path,
    manifest: Mapping[str, Any],
    *,
    authorization_state: Path | None,
    steering_registry: Path | None,
) -> tuple[Path, Path, Path]:
    outputs = manifest.get("outputs")
    if not isinstance(outputs, Mapping):
        raise AppServerError("campaign-manifest-outputs-invalid")
    if output.name != outputs.get("evidence_basename"):
        raise AppServerError("campaign-output-basename-mismatch")
    state_path = (
        authorization_state.absolute()
        if authorization_state is not None
        else output.parent / str(outputs.get("authorization_state_basename"))
    )
    registry_path = (
        steering_registry.absolute()
        if steering_registry is not None
        else output.parent / str(outputs.get("steering_registry_basename"))
    )
    ledger_path = output.parent / str(outputs.get("allocation_ledger_basename"))
    expected = {
        state_path.name: outputs.get("authorization_state_basename"),
        registry_path.name: outputs.get("steering_registry_basename"),
        ledger_path.name: outputs.get("allocation_ledger_basename"),
    }
    if any(actual != declared for actual, declared in expected.items()):
        raise AppServerError("campaign-output-path-mismatch")
    if len({output, state_path, registry_path, ledger_path}) != 4:
        raise AppServerError("campaign-output-path-collision")
    return state_path, registry_path, ledger_path


def validate_campaign_launch_bindings(
    *,
    inputs: CampaignLaunchInputs,
    guarded_primary: Path,
) -> dict[str, Any]:
    authorization = dict(inputs.authorization.value)
    manifest = dict(inputs.manifest.value)
    outer_authority = dict(inputs.outer_authority.value)
    pre_mutation_receipt = dict(inputs.pre_mutation_receipt.value)
    pre_live_receipt = dict(inputs.pre_live_receipt.value)
    pre_mutation_adjudication = dict(inputs.pre_mutation_adjudication.value)
    pre_live_adjudication = dict(inputs.pre_live_adjudication.value)
    opus_review_evidence = dict(inputs.opus_review_evidence.value)
    opus_adjudication = dict(inputs.opus_adjudication.value)
    spark_validation_receipt = dict(inputs.spark_validation_receipt.value)
    spark_validation_session_file_sha256 = validate_independent_validation_session_snapshot(
        spark_validation_receipt,
        inputs.spark_validation_session_path,
        inputs.spark_validation_session_bytes,
    )
    primary_diff_sha256 = guarded_diff_sha256(guarded_primary)
    validate_steering_launch_bindings(
        str(authorization.get("authorization_id")),
        inputs.authorization.raw_sha256,
        pre_mutation_receipt=pre_mutation_receipt,
        pre_mutation_adjudication=pre_mutation_adjudication,
        pre_mutation_adjudication_sha256=(
            inputs.pre_mutation_adjudication.raw_sha256
        ),
        pre_live_receipt=pre_live_receipt,
        pre_live_adjudication=pre_live_adjudication,
        pre_live_adjudication_sha256=inputs.pre_live_adjudication.raw_sha256,
    )
    authorization_version = authorization.get("version")
    interrupted_failed: (
        Version10InterruptedEmptyBoundaryPredecessorProofInputs | None
    )
    preallocation_failed: Version9PreallocationFaultPredecessorProofInputs | None
    failed_predecessor: Version8ProtectedFaultPredecessorProofInputs | None
    if authorization_version == 11:
        interrupted_failed = require_generation12_launch_inputs(inputs)
        preallocation_failed = interrupted_failed.ancestor
        failed_predecessor = preallocation_failed.ancestor
        proof = failed_predecessor.ancestor
        validator_sha256 = validator_contract_sha256_v6(
            ROOT, manifest.get("candidate", {}).get("tree")
        )
        manifest_proof = interrupted_failed
    elif authorization_version == 10:
        interrupted_failed = None
        preallocation_failed = require_generation11_launch_inputs(inputs)
        failed_predecessor = preallocation_failed.ancestor
        proof = failed_predecessor.ancestor
        validator_sha256 = validator_contract_sha256_v5(
            ROOT, manifest.get("candidate", {}).get("tree")
        )
        manifest_proof = preallocation_failed
    elif authorization_version == 9:
        interrupted_failed = None
        preallocation_failed = None
        failed_predecessor = require_generation10_launch_inputs(inputs)
        proof = failed_predecessor.ancestor
        validator_sha256 = validator_contract_sha256_v4(
            ROOT, manifest.get("candidate", {}).get("tree")
        )
        manifest_proof = failed_predecessor
    else:
        interrupted_failed = None
        preallocation_failed = None
        failed_predecessor = None
        proof = require_generation9_launch_inputs(inputs)
        validator_sha256 = validator_contract_sha256_v3(
            ROOT, manifest.get("candidate", {}).get("tree")
        )
        manifest_proof = proof
    predecessor = proof.ancestor
    ancestor = predecessor.ancestor
    grandancestor = ancestor.ancestor
    common_manifest_kwargs = {
        "authorization": authorization,
        "authorization_raw_sha256": inputs.authorization.raw_sha256,
        "outer_authority": outer_authority,
        "outer_authority_raw_sha256": inputs.outer_authority.raw_sha256,
        "independent_validation_receipt": spark_validation_receipt,
        "independent_validation_receipt_raw_sha256": (
            inputs.spark_validation_receipt.raw_sha256
        ),
        "repo_root": ROOT,
        "expected_primary_diff_sha256": primary_diff_sha256,
    }
    errors = validate_campaign_manifest(
        manifest,
        predecessor_proof=manifest_proof,
        recovery_cause_evidence=inputs.recovery_cause_evidence,
        recovery_cause_source_analysis=inputs.recovery_cause_source_analysis_bytes,
        expected_validator_contract_sha256=validator_sha256,
        **common_manifest_kwargs,
    )
    predecessor_bindings = {
        **quarantined_predecessor_ledger_prefix_bindings(
            authorization, failed_predecessor
        ),
        "quarantined_predecessor_authorization_file_sha256": (
            proof.authorization.raw_sha256
        ),
        "quarantined_predecessor_manifest_file_sha256": (
            proof.manifest.raw_sha256
        ),
        "quarantined_predecessor_authorization_state_file_sha256": (
            proof.authorization_state.raw_sha256
        ),
        "quarantined_predecessor_failure_evidence_file_sha256": (
            proof.failure_evidence.raw_sha256
        ),
        "quarantined_predecessor_containment_file_sha256": (
            proof.containment.raw_sha256
        ),
        "quarantined_predecessor_allocation_ledger_file_sha256": (
            proof.allocation_ledger.raw_sha256
        ),
        "quarantined_predecessor_allocation_audit_file_sha256": sha256_bytes(
            proof.allocation_audit_bytes
        ),
        "quarantined_predecessor_recovery_cause_evidence_file_sha256": (
            proof.authorization_recovery_cause_evidence.raw_sha256
        ),
        "quarantined_predecessor_recovery_cause_source_analysis_file_sha256": (
            sha256_bytes(proof.authorization_recovery_cause_source_analysis)
        ),
        "quarantined_predecessor_outer_authority_file_sha256": (
            proof.outer_authority.raw_sha256
        ),
        "quarantined_predecessor_independent_validation_receipt_file_sha256": (
            proof.independent_validation_receipt.raw_sha256
        ),
        "quarantined_predecessor_independent_validation_session_file_sha256": sha256_bytes(
            proof.independent_validation_session_bytes
        ),
        "quarantined_predecessor_session_file_sha256": sha256_bytes(
            proof.quarantined_session_bytes
        ),
        "predecessor_authorization_file_sha256": (
            predecessor.authorization.raw_sha256
        ),
        "predecessor_manifest_file_sha256": predecessor.manifest.raw_sha256,
        "predecessor_authorization_state_file_sha256": (
            predecessor.authorization_state.raw_sha256
        ),
        "predecessor_failure_evidence_file_sha256": (
            predecessor.failure_evidence.raw_sha256
        ),
        "predecessor_containment_file_sha256": (
            predecessor.containment.raw_sha256
        ),
        "predecessor_allocation_ledger_file_sha256": (
            predecessor.allocation_ledger.raw_sha256
        ),
        "predecessor_allocation_audit_file_sha256": sha256_bytes(
            predecessor.allocation_audit_bytes
        ),
        "predecessor_recovery_cause_evidence_file_sha256": (
            predecessor.authorization_recovery_cause_evidence.raw_sha256
        ),
        "predecessor_recovery_cause_source_analysis_file_sha256": sha256_bytes(
            predecessor.authorization_recovery_cause_source_analysis
        ),
        "predecessor_outer_authority_file_sha256": (
            predecessor.outer_authority.raw_sha256
        ),
        "predecessor_independent_validation_receipt_file_sha256": (
            predecessor.independent_validation_receipt.raw_sha256
        ),
        "predecessor_independent_validation_session_file_sha256": sha256_bytes(
            predecessor.independent_validation_session_bytes
        ),
        "predecessor_contained_session_file_sha256s": [
            sha256_bytes(raw) for raw in predecessor.contained_session_bytes
        ],
        "ancestor_authorization_file_sha256": ancestor.authorization.raw_sha256,
        "ancestor_manifest_file_sha256": ancestor.manifest.raw_sha256,
        "ancestor_authorization_state_file_sha256": (
            ancestor.authorization_state.raw_sha256
        ),
        "ancestor_failure_evidence_file_sha256": (
            ancestor.failure_evidence.raw_sha256
        ),
        "ancestor_containment_file_sha256": ancestor.containment.raw_sha256,
        "ancestor_allocation_ledger_file_sha256": (
            ancestor.allocation_ledger.raw_sha256
        ),
        "ancestor_allocation_audit_file_sha256": sha256_bytes(
            ancestor.allocation_audit_bytes
        ),
        "ancestor_authorization_cause_evidence_file_sha256": sha256_bytes(
            ancestor.authorization_cause_evidence
        ),
        "ancestor_outer_authority_file_sha256": ancestor.outer_authority.raw_sha256,
        "ancestor_independent_validation_receipt_file_sha256": (
            ancestor.independent_validation_receipt.raw_sha256
        ),
        "ancestor_independent_validation_session_file_sha256": sha256_bytes(
            ancestor.independent_validation_session_bytes
        ),
        "ancestor_contained_session_file_sha256s": [
            sha256_bytes(raw) for raw in ancestor.contained_session_bytes
        ],
        "grandancestor_authorization_file_sha256": (
            grandancestor.authorization.raw_sha256
        ),
        "grandancestor_manifest_file_sha256": grandancestor.manifest.raw_sha256,
        "grandancestor_authorization_state_file_sha256": (
            grandancestor.authorization_state.raw_sha256
        ),
        "grandancestor_failure_evidence_file_sha256": (
            grandancestor.failure_evidence.raw_sha256
        ),
        "grandancestor_original_containment_file_sha256": (
            grandancestor.original_containment.raw_sha256
        ),
        "grandancestor_containment_file_sha256": (
            grandancestor.containment.raw_sha256
        ),
        "grandancestor_allocation_ledger_file_sha256": (
            grandancestor.allocation_ledger.raw_sha256
        ),
        "grandancestor_allocation_audit_file_sha256": sha256_bytes(
            grandancestor.allocation_audit_bytes
        ),
        "grandancestor_cause_evidence_file_sha256": sha256_bytes(
            grandancestor.cause_evidence
        ),
        "grandancestor_contained_session_file_sha256s": [
            sha256_bytes(raw) for raw in grandancestor.contained_session_bytes
        ],
        "recovery_cause_evidence_file_sha256": (
            inputs.recovery_cause_evidence.raw_sha256
        ),
        "recovery_cause_source_analysis_file_sha256": sha256_bytes(
            inputs.recovery_cause_source_analysis_bytes
        ),
        "validator_contract_sha256": validator_sha256,
    }
    if failed_predecessor is not None:
        predecessor_bindings.update(
            {
                "failed_predecessor_authorization_file_sha256": (
                    failed_predecessor.authorization.raw_sha256
                ),
                "failed_predecessor_manifest_file_sha256": (
                    failed_predecessor.manifest.raw_sha256
                ),
                "failed_predecessor_authorization_state_file_sha256": (
                    failed_predecessor.authorization_state.raw_sha256
                ),
                "failed_predecessor_failure_evidence_file_sha256": (
                    failed_predecessor.failure_evidence.raw_sha256
                ),
                "failed_predecessor_containment_file_sha256": (
                    failed_predecessor.containment.raw_sha256
                ),
                "failed_predecessor_allocation_ledger_file_sha256": (
                    failed_predecessor.allocation_ledger.raw_sha256
                ),
                "failed_predecessor_allocation_audit_file_sha256": sha256_bytes(
                    failed_predecessor.allocation_audit_bytes
                ),
                "failed_predecessor_recovery_cause_evidence_file_sha256": (
                    failed_predecessor.authorization_recovery_cause_evidence.raw_sha256
                ),
                "failed_predecessor_recovery_cause_source_analysis_file_sha256": (
                    sha256_bytes(
                        failed_predecessor.authorization_recovery_cause_source_analysis
                    )
                ),
                "failed_predecessor_outer_authority_file_sha256": (
                    failed_predecessor.outer_authority.raw_sha256
                ),
                "failed_predecessor_independent_validation_receipt_file_sha256": (
                    failed_predecessor.independent_validation_receipt.raw_sha256
                ),
                "failed_predecessor_independent_validation_session_file_sha256": (
                    sha256_bytes(
                        failed_predecessor.independent_validation_session_bytes
                    )
                ),
                "failed_predecessor_contained_session_file_sha256s": [
                    sha256_bytes(raw)
                    for raw in failed_predecessor.contained_session_bytes
                ],
                "failed_predecessor_contained_session_family_sha256": (
                    (
                        preallocation_failed.authorization.value
                        if preallocation_failed is not None
                        else authorization
                    ).get("bindings", {}).get(
                        "predecessor_contained_session_family_sha256"
                    )
                ),
            }
        )
    if preallocation_failed is not None:
        predecessor_bindings.update(
            {
                "preallocation_failed_predecessor_authorization_file_sha256": (
                    preallocation_failed.authorization.raw_sha256
                ),
                "preallocation_failed_predecessor_manifest_file_sha256": (
                    preallocation_failed.manifest.raw_sha256
                ),
                "preallocation_failed_predecessor_authorization_state_file_sha256": (
                    preallocation_failed.authorization_state.raw_sha256
                ),
                "preallocation_failed_predecessor_failure_evidence_file_sha256": (
                    preallocation_failed.failure_evidence.raw_sha256
                ),
                "preallocation_failed_predecessor_containment_file_sha256": (
                    preallocation_failed.containment.raw_sha256
                ),
                "preallocation_failed_predecessor_global_claim_file_sha256": (
                    preallocation_failed.global_claim.raw_sha256
                ),
                "preallocation_failed_predecessor_authorization_marker_file_sha256": (
                    preallocation_failed.authorization_marker.raw_sha256
                ),
                "preallocation_failed_predecessor_nonce_marker_file_sha256": (
                    preallocation_failed.nonce_marker.raw_sha256
                ),
                "preallocation_failed_predecessor_scope_state_file_sha256": (
                    preallocation_failed.scope_state.raw_sha256
                ),
                "preallocation_failed_predecessor_preflight_file_sha256": (
                    preallocation_failed.preflight.raw_sha256
                ),
                "preallocation_failed_predecessor_pre_mutation_receipt_file_sha256": (
                    preallocation_failed.pre_mutation_receipt.raw_sha256
                ),
                "preallocation_failed_predecessor_pre_live_receipt_file_sha256": (
                    preallocation_failed.pre_live_receipt.raw_sha256
                ),
                "preallocation_failed_predecessor_recovery_cause_evidence_file_sha256": (
                    preallocation_failed.authorization_recovery_cause_evidence.raw_sha256
                ),
                "preallocation_failed_predecessor_recovery_cause_source_analysis_file_sha256": (
                    sha256_bytes(
                        preallocation_failed.authorization_recovery_cause_source_analysis
                    )
                ),
                "preallocation_failed_predecessor_outer_authority_file_sha256": (
                    preallocation_failed.outer_authority.raw_sha256
                ),
                "preallocation_failed_predecessor_independent_validation_receipt_file_sha256": (
                    preallocation_failed.independent_validation_receipt.raw_sha256
                ),
                "preallocation_failed_predecessor_independent_validation_session_file_sha256": (
                    sha256_bytes(
                        preallocation_failed.independent_validation_session_bytes
                    )
                ),
            }
        )
    if interrupted_failed is not None:
        predecessor_bindings.update(
            {
                "interrupted_failed_predecessor_authorization_file_sha256": (
                    interrupted_failed.authorization.raw_sha256
                ),
                "interrupted_failed_predecessor_manifest_file_sha256": (
                    interrupted_failed.manifest.raw_sha256
                ),
                "interrupted_failed_predecessor_authorization_state_file_sha256": (
                    interrupted_failed.authorization_state.raw_sha256
                ),
                "interrupted_failed_predecessor_failure_evidence_file_sha256": (
                    interrupted_failed.failure_evidence.raw_sha256
                ),
                "interrupted_failed_predecessor_containment_file_sha256": (
                    interrupted_failed.containment.raw_sha256
                ),
                "interrupted_failed_predecessor_global_claim_file_sha256": (
                    interrupted_failed.global_claim.raw_sha256
                ),
                "interrupted_failed_predecessor_authorization_marker_file_sha256": (
                    interrupted_failed.authorization_marker.raw_sha256
                ),
                "interrupted_failed_predecessor_nonce_marker_file_sha256": (
                    interrupted_failed.nonce_marker.raw_sha256
                ),
                "interrupted_failed_predecessor_scope_state_file_sha256": (
                    interrupted_failed.scope_state.raw_sha256
                ),
                "interrupted_failed_predecessor_preflight_file_sha256": (
                    interrupted_failed.preflight.raw_sha256
                ),
                "interrupted_failed_predecessor_pre_mutation_receipt_file_sha256": (
                    interrupted_failed.pre_mutation_receipt.raw_sha256
                ),
                "interrupted_failed_predecessor_pre_mutation_adjudication_file_sha256": (
                    interrupted_failed.pre_mutation_adjudication.raw_sha256
                ),
                "interrupted_failed_predecessor_pre_live_receipt_file_sha256": (
                    interrupted_failed.pre_live_receipt.raw_sha256
                ),
                "interrupted_failed_predecessor_pre_live_adjudication_file_sha256": (
                    interrupted_failed.pre_live_adjudication.raw_sha256
                ),
                "interrupted_failed_predecessor_allocation_ledger_file_sha256": (
                    interrupted_failed.allocation_ledger.raw_sha256
                ),
                "interrupted_failed_predecessor_allocation_audit_file_sha256": (
                    sha256_bytes(interrupted_failed.allocation_audit_bytes)
                ),
                "interrupted_failed_predecessor_steering_registry_file_sha256": (
                    interrupted_failed.steering_registry.raw_sha256
                ),
                "interrupted_failed_predecessor_terminal_session_file_sha256": (
                    sha256_bytes(interrupted_failed.terminal_session_bytes)
                ),
                "interrupted_failed_predecessor_terminal_facts_file_sha256": (
                    interrupted_failed.terminal_facts.raw_sha256
                ),
                "interrupted_failed_predecessor_generation11_runner_source_sha256": (
                    sha256_bytes(interrupted_failed.generation11_runner_source_bytes)
                ),
                "interrupted_failed_predecessor_generation11_session_boundary_source_sha256": (
                    sha256_bytes(
                        interrupted_failed.generation11_session_boundary_source_bytes
                    )
                ),
                "interrupted_failed_predecessor_recovery_cause_analysis_sha256": (
                    sha256_bytes(interrupted_failed.recovery_cause_analysis_bytes)
                ),
                "interrupted_failed_predecessor_recovery_steering_receipt_file_sha256": (
                    interrupted_failed.recovery_steering_receipt.raw_sha256
                ),
                "interrupted_failed_predecessor_recovery_steering_session_file_sha256": (
                    sha256_bytes(interrupted_failed.recovery_steering_session_bytes)
                ),
                "interrupted_failed_predecessor_recovery_cause_evidence_file_sha256": (
                    interrupted_failed.authorization_recovery_cause_evidence.raw_sha256
                ),
                "interrupted_failed_predecessor_recovery_cause_source_analysis_file_sha256": (
                    sha256_bytes(
                        interrupted_failed.authorization_recovery_cause_source_analysis
                    )
                ),
                "interrupted_failed_predecessor_outer_authority_file_sha256": (
                    interrupted_failed.outer_authority.raw_sha256
                ),
                "interrupted_failed_predecessor_independent_validation_receipt_file_sha256": (
                    interrupted_failed.independent_validation_receipt.raw_sha256
                ),
                "interrupted_failed_predecessor_independent_validation_session_file_sha256": (
                    sha256_bytes(
                        interrupted_failed.independent_validation_session_bytes
                    )
                ),
            }
        )
    if errors:
        raise AppServerError("campaign-manifest-invalid:" + ";".join(errors))
    if manifest.get("control_turn_id") != CONTROL_TURN_ID:
        raise AppServerError("campaign-manifest-control-turn-mismatch")
    reviews = manifest["reviews"]
    observed_reviews = {
        "pre_mutation_receipt_canonical_sha256": pre_mutation_receipt.get(
            "canonical_receipt_sha256"
        ),
        "pre_mutation_receipt_file_sha256": inputs.pre_mutation_receipt.raw_sha256,
        "pre_mutation_adjudication_file_sha256": (
            inputs.pre_mutation_adjudication.raw_sha256
        ),
        "opus_evidence_file_sha256": inputs.opus_review_evidence.raw_sha256,
        "opus_adjudication_file_sha256": inputs.opus_adjudication.raw_sha256,
        "spark_validation_receipt_canonical_sha256": spark_validation_receipt.get(
            "canonical_receipt_sha256"
        ),
        "spark_validation_receipt_file_sha256": (
            inputs.spark_validation_receipt.raw_sha256
        ),
        "pre_live_receipt_canonical_sha256": pre_live_receipt.get(
            "canonical_receipt_sha256"
        ),
        "pre_live_receipt_file_sha256": inputs.pre_live_receipt.raw_sha256,
        "pre_live_adjudication_file_sha256": inputs.pre_live_adjudication.raw_sha256,
    }
    if dict(reviews) != observed_reviews:
        raise AppServerError("campaign-manifest-review-binding-mismatch")
    candidate = manifest["candidate"]
    if (
        opus_review_evidence.get("exact_model") != "claude-opus-4-6"
        or opus_review_evidence.get("candidate_commit") != candidate["commit"]
        or opus_review_evidence.get("glm_5_2_used") is not False
        or opus_review_evidence.get("model_synthesis_used") is not False
        or opus_adjudication.get("main_architect_decision") != "go"
        or opus_adjudication.get("candidate_commit") != candidate["commit"]
        or opus_adjudication.get("opus_evidence_file_sha256")
        != observed_reviews["opus_evidence_file_sha256"]
    ):
        raise AppServerError("campaign-opus-review-binding-invalid")
    release_errors = validate_release_patch_result(
        ROOT,
        None,
        manifest,
        patch_bytes=inputs.release_patch_bytes,
    )
    if release_errors:
        raise AppServerError("campaign-release-patch-invalid:" + ";".join(release_errors))
    try:
        policy_document = json.loads(
            (ROOT / "policy" / "native-worker-execution.yaml").read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise AppServerError("campaign-policy-unreadable") from exc
    pool_policy = (
        policy_document.get("native_supervision_pool")
        if isinstance(policy_document, Mapping)
        else None
    )
    current_policy = {
        "status": pool_policy.get("status") if isinstance(pool_policy, Mapping) else None,
        "cap_two_operative_release": (
            pool_policy.get("cap_two_operative_release")
            if isinstance(pool_policy, Mapping)
            else None
        ),
    }
    if current_policy != manifest["release"]["policy_before"]:
        raise AppServerError("campaign-policy-before-mismatch")
    all_source_file_sha256s = (
        generation12_source_file_sha256s(inputs)
        if authorization_version == 11
        else (
            generation11_source_file_sha256s(inputs)
            if authorization_version == 10
            else (
                generation10_source_file_sha256s(inputs)
                if authorization_version == 9
                else generation9_source_file_sha256s(inputs)
            )
        )
    )
    return {
        "authorization_raw_sha256": inputs.authorization.raw_sha256,
        "manifest_file_sha256": inputs.manifest.raw_sha256,
        "manifest_sha256": manifest["manifest_sha256"],
        "candidate_commit": candidate["commit"],
        "candidate_tree": candidate["tree"],
        "origin_main_commit": candidate["origin_main_commit"],
        "guarded_primary_diff_sha256": primary_diff_sha256,
        "release_patch_sha256": manifest["release"]["patch_file_sha256"],
        "release_prospective_tree": manifest["release"]["prospective_tree"],
        "outer_authority_file_sha256": inputs.outer_authority.raw_sha256,
        **predecessor_bindings,
        "spark_validation_session_file_sha256": spark_validation_session_file_sha256,
        "spark_validation_receipt_file_sha256": observed_reviews[
            "spark_validation_receipt_file_sha256"
        ],
        "opus_evidence_file_sha256": observed_reviews["opus_evidence_file_sha256"],
        "opus_adjudication_file_sha256": observed_reviews[
            "opus_adjudication_file_sha256"
        ],
        "source_file_sha256s": all_source_file_sha256s,
    }


def campaign_launch_claim_payload(
    inputs: CampaignLaunchInputs,
    *,
    output: Path,
    authorization_state: Path,
    steering_registry: Path,
    allocation_ledger: Path,
) -> dict[str, Any]:
    """Bind every read-once Generation-8 source to the v2 launch claim."""

    proof = require_generation8_launch_inputs(inputs)
    ancestor = proof.ancestor
    grandancestor = ancestor.ancestor
    authorization = inputs.authorization.value
    manifest = inputs.manifest.value
    outer = inputs.outer_authority.value
    spark = inputs.spark_validation_receipt.value
    declared_outputs = manifest.get("outputs")
    if not isinstance(declared_outputs, Mapping):
        raise AppServerError("campaign-launch-claim-outputs-invalid")
    output_basenames = {
        "evidence_basename": output.name,
        "authorization_state_basename": authorization_state.name,
        "steering_registry_basename": steering_registry.name,
        "allocation_ledger_basename": allocation_ledger.name,
    }
    if output_basenames != dict(declared_outputs):
        raise AppServerError("campaign-launch-claim-outputs-mismatch")
    bindings = authorization.get("bindings")
    if not isinstance(bindings, Mapping):
        raise AppServerError("campaign-launch-claim-authorization-invalid")
    source_file_sha256s = generation8_source_file_sha256s(inputs)
    claim = {
        "claim_type": "cwo-native-live-campaign-launch-claim",
        "version": 2,
        "authority_semantics": {
            "durable_one_shot_claim_is_launch_authority": True,
            "authorization_and_nonce_tombstones_are_permanent": True,
            "bound_manifest_validation_is_evidence_only": True,
            "resume_retry_replay_salvage_forbidden": True,
        },
        "authorization": {
            "authorization_id": authorization.get("authorization_id"),
            "raw_sha256": inputs.authorization.raw_sha256,
            "canonical_sha256": authorization.get(
                "canonical_authorization_sha256"
            ),
            "run_generation": authorization.get("run_generation"),
            "live_generation": authorization.get("live_generation"),
            "predecessor_live_generation": authorization.get(
                "predecessor_live_generation"
            ),
            "campaign_nonce": bindings.get("campaign_nonce"),
        },
        "manifest": {
            "manifest_id": manifest.get("manifest_id"),
            "raw_sha256": inputs.manifest.raw_sha256,
            "canonical_sha256": manifest.get("manifest_sha256"),
        },
        "outer_authority": {
            "authority_id": outer.get("authority_id"),
            "raw_sha256": inputs.outer_authority.raw_sha256,
            "canonical_sha256": outer.get("canonical_outer_authority_sha256"),
        },
        "spark_validation": {
            "receipt_raw_sha256": inputs.spark_validation_receipt.raw_sha256,
            "receipt_canonical_sha256": spark.get("canonical_receipt_sha256"),
            "session_id": spark.get("session_id"),
            "session_file_sha256": sha256_bytes(
                inputs.spark_validation_session_bytes
            ),
        },
        "successor_proof": {
            "proof_dag": ["v7/v4", "v6/v3", "v5/v2", "v4/v1"],
            "recovery_cause_evidence_raw_sha256": (
                inputs.recovery_cause_evidence.raw_sha256
            ),
            "recovery_cause_source_analysis_sha256": sha256_bytes(
                inputs.recovery_cause_source_analysis_bytes
            ),
            "predecessor_recovery_cause_evidence_raw_sha256": (
                proof.authorization_recovery_cause_evidence.raw_sha256
            ),
            "predecessor_recovery_cause_source_analysis_sha256": sha256_bytes(
                proof.authorization_recovery_cause_source_analysis
            ),
            "ancestor_authorization_cause_evidence_sha256": sha256_bytes(
                ancestor.authorization_cause_evidence
            ),
            "grandancestor_cause_evidence_sha256": sha256_bytes(
                grandancestor.cause_evidence
            ),
            "predecessor_contained_session_sha256s": [
                sha256_bytes(raw) for raw in proof.contained_session_bytes
            ],
            "ancestor_contained_session_sha256s": [
                sha256_bytes(raw) for raw in ancestor.contained_session_bytes
            ],
            "grandancestor_contained_session_sha256s": [
                sha256_bytes(raw)
                for raw in grandancestor.contained_session_bytes
            ],
        },
        "steering": {
            "pre_mutation_receipt_raw_sha256": (
                inputs.pre_mutation_receipt.raw_sha256
            ),
            "pre_mutation_receipt_canonical_sha256": (
                inputs.pre_mutation_receipt.value.get("canonical_receipt_sha256")
            ),
            "pre_live_receipt_raw_sha256": inputs.pre_live_receipt.raw_sha256,
            "pre_live_receipt_canonical_sha256": inputs.pre_live_receipt.value.get(
                "canonical_receipt_sha256"
            ),
            "pre_mutation_adjudication_raw_sha256": (
                inputs.pre_mutation_adjudication.raw_sha256
            ),
            "pre_live_adjudication_raw_sha256": (
                inputs.pre_live_adjudication.raw_sha256
            ),
        },
        "outside_review": {
            "opus_evidence_raw_sha256": inputs.opus_review_evidence.raw_sha256,
            "opus_adjudication_raw_sha256": inputs.opus_adjudication.raw_sha256,
            "exact_model": inputs.opus_review_evidence.value.get("exact_model"),
            "glm_5_2_used": inputs.opus_review_evidence.value.get("glm_5_2_used"),
            "model_synthesis_used": inputs.opus_review_evidence.value.get(
                "model_synthesis_used"
            ),
            "main_architect_decision": inputs.opus_adjudication.value.get(
                "main_architect_decision"
            ),
        },
        "source_file_sha256s": source_file_sha256s,
        "output_basenames": output_basenames,
        "output_paths": {
            "evidence": str(output.resolve(strict=False)),
            "authorization_state": str(authorization_state.resolve(strict=False)),
            "steering_registry": str(steering_registry.resolve(strict=False)),
            "allocation_ledger": str(allocation_ledger.resolve(strict=False)),
        },
        "validator_contract_sha256": bindings.get("validator_contract_sha256"),
    }
    return claim


def campaign_launch_claim_payload_v3(
    inputs: CampaignLaunchInputs,
    *,
    output: Path,
    authorization_state: Path,
    steering_registry: Path,
    allocation_ledger: Path,
) -> dict[str, Any]:
    """Bind every read-once Generation-9 source and quarantine proof."""

    quarantine = require_generation9_launch_inputs(inputs)
    predecessor = quarantine.ancestor
    ancestor = predecessor.ancestor
    grandancestor = ancestor.ancestor
    authorization = inputs.authorization.value
    manifest = inputs.manifest.value
    outer = inputs.outer_authority.value
    spark = inputs.spark_validation_receipt.value
    declared_outputs = manifest.get("outputs")
    if not isinstance(declared_outputs, Mapping):
        raise AppServerError("campaign-launch-claim-outputs-invalid")
    output_basenames = {
        "evidence_basename": output.name,
        "authorization_state_basename": authorization_state.name,
        "steering_registry_basename": steering_registry.name,
        "allocation_ledger_basename": allocation_ledger.name,
    }
    if output_basenames != dict(declared_outputs):
        raise AppServerError("campaign-launch-claim-outputs-mismatch")
    bindings = authorization.get("bindings")
    if not isinstance(bindings, Mapping):
        raise AppServerError("campaign-launch-claim-authorization-invalid")
    claim = {
        "claim_type": "cwo-native-live-campaign-launch-claim",
        "version": 3,
        "authority_semantics": {
            "durable_one_shot_claim_is_launch_authority": True,
            "authorization_and_nonce_tombstones_are_permanent": True,
            "bound_manifest_validation_is_evidence_only": True,
            "resume_retry_replay_salvage_forbidden": True,
            "quarantined_predecessor_is_never_attestation": True,
        },
        "authorization": {
            "authorization_id": authorization.get("authorization_id"),
            "raw_sha256": inputs.authorization.raw_sha256,
            "canonical_sha256": authorization.get(
                "canonical_authorization_sha256"
            ),
            "run_generation": authorization.get("run_generation"),
            "live_generation": authorization.get("live_generation"),
            "predecessor_live_generation": authorization.get(
                "predecessor_live_generation"
            ),
            "campaign_nonce": bindings.get("campaign_nonce"),
        },
        "manifest": {
            "manifest_id": manifest.get("manifest_id"),
            "raw_sha256": inputs.manifest.raw_sha256,
            "canonical_sha256": manifest.get("manifest_sha256"),
        },
        "outer_authority": {
            "authority_id": outer.get("authority_id"),
            "raw_sha256": inputs.outer_authority.raw_sha256,
            "canonical_sha256": outer.get("canonical_outer_authority_sha256"),
        },
        "spark_validation": {
            "receipt_raw_sha256": inputs.spark_validation_receipt.raw_sha256,
            "receipt_canonical_sha256": spark.get("canonical_receipt_sha256"),
            "session_id": spark.get("session_id"),
            "session_file_sha256": sha256_bytes(
                inputs.spark_validation_session_bytes
            ),
        },
        "successor_proof": {
            "proof_dag": ["v8/v5", "v7/v4", "v6/v3", "v5/v2", "v4/v1"],
            "recovery_cause_evidence_raw_sha256": (
                inputs.recovery_cause_evidence.raw_sha256
            ),
            "recovery_cause_source_analysis_sha256": sha256_bytes(
                inputs.recovery_cause_source_analysis_bytes
            ),
            "quarantined_predecessor": {
                "authorization_raw_sha256": quarantine.authorization.raw_sha256,
                "manifest_raw_sha256": quarantine.manifest.raw_sha256,
                "authorization_state_raw_sha256": (
                    quarantine.authorization_state.raw_sha256
                ),
                "failure_evidence_raw_sha256": (
                    quarantine.failure_evidence.raw_sha256
                ),
                "containment_raw_sha256": quarantine.containment.raw_sha256,
                "allocation_ledger_raw_sha256": (
                    quarantine.allocation_ledger.raw_sha256
                ),
                "allocation_audit_sha256": sha256_bytes(
                    quarantine.allocation_audit_bytes
                ),
                "recovery_cause_evidence_raw_sha256": (
                    quarantine.authorization_recovery_cause_evidence.raw_sha256
                ),
                "recovery_cause_source_analysis_sha256": sha256_bytes(
                    quarantine.authorization_recovery_cause_source_analysis
                ),
                "outer_authority_raw_sha256": (
                    quarantine.outer_authority.raw_sha256
                ),
                "independent_validation_receipt_raw_sha256": (
                    quarantine.independent_validation_receipt.raw_sha256
                ),
                "independent_validation_session_sha256": sha256_bytes(
                    quarantine.independent_validation_session_bytes
                ),
                "quarantined_session_sha256": sha256_bytes(
                    quarantine.quarantined_session_bytes
                ),
                "failure_ledger_prefix_file_sha256": bindings.get(
                    "predecessor_failure_ledger_prefix_file_sha256"
                ),
                "failure_ledger_prefix_state_sha256": bindings.get(
                    "predecessor_failure_ledger_prefix_state_sha256"
                ),
                "failure_ledger_prefix_head_entry_sha256": bindings.get(
                    "predecessor_failure_ledger_prefix_head_entry_sha256"
                ),
                "attestation_disposition": "unavailable-quarantined-nonaccepting",
                "accepting_model_evidence": False,
            },
            "predecessor_recovery_cause_evidence_raw_sha256": (
                predecessor.authorization_recovery_cause_evidence.raw_sha256
            ),
            "predecessor_recovery_cause_source_analysis_sha256": sha256_bytes(
                predecessor.authorization_recovery_cause_source_analysis
            ),
            "ancestor_authorization_cause_evidence_sha256": sha256_bytes(
                ancestor.authorization_cause_evidence
            ),
            "grandancestor_cause_evidence_sha256": sha256_bytes(
                grandancestor.cause_evidence
            ),
            "predecessor_contained_session_sha256s": [
                sha256_bytes(raw) for raw in predecessor.contained_session_bytes
            ],
            "ancestor_contained_session_sha256s": [
                sha256_bytes(raw) for raw in ancestor.contained_session_bytes
            ],
            "grandancestor_contained_session_sha256s": [
                sha256_bytes(raw)
                for raw in grandancestor.contained_session_bytes
            ],
        },
        "steering": {
            "pre_mutation_receipt_raw_sha256": (
                inputs.pre_mutation_receipt.raw_sha256
            ),
            "pre_mutation_receipt_canonical_sha256": (
                inputs.pre_mutation_receipt.value.get("canonical_receipt_sha256")
            ),
            "pre_live_receipt_raw_sha256": inputs.pre_live_receipt.raw_sha256,
            "pre_live_receipt_canonical_sha256": inputs.pre_live_receipt.value.get(
                "canonical_receipt_sha256"
            ),
            "pre_mutation_adjudication_raw_sha256": (
                inputs.pre_mutation_adjudication.raw_sha256
            ),
            "pre_live_adjudication_raw_sha256": (
                inputs.pre_live_adjudication.raw_sha256
            ),
        },
        "outside_review": {
            "opus_evidence_raw_sha256": inputs.opus_review_evidence.raw_sha256,
            "opus_adjudication_raw_sha256": inputs.opus_adjudication.raw_sha256,
            "exact_model": inputs.opus_review_evidence.value.get("exact_model"),
            "glm_5_2_used": inputs.opus_review_evidence.value.get("glm_5_2_used"),
            "model_synthesis_used": inputs.opus_review_evidence.value.get(
                "model_synthesis_used"
            ),
            "main_architect_decision": inputs.opus_adjudication.value.get(
                "main_architect_decision"
            ),
        },
        "source_file_sha256s": generation9_source_file_sha256s(inputs),
        "output_basenames": output_basenames,
        "output_paths": {
            "evidence": str(output.resolve(strict=False)),
            "authorization_state": str(authorization_state.resolve(strict=False)),
            "steering_registry": str(steering_registry.resolve(strict=False)),
            "allocation_ledger": str(allocation_ledger.resolve(strict=False)),
        },
        "validator_contract_sha256": bindings.get("validator_contract_sha256"),
    }
    return claim


def campaign_launch_claim_payload_v4(
    inputs: CampaignLaunchInputs,
    *,
    output: Path,
    authorization_state: Path,
    steering_registry: Path,
    allocation_ledger: Path,
) -> dict[str, Any]:
    """Bind every read-once Generation-10 source and protected-fault proof."""

    failed = require_generation10_launch_inputs(inputs)
    quarantine = failed.ancestor
    predecessor = quarantine.ancestor
    ancestor = predecessor.ancestor
    grandancestor = ancestor.ancestor
    authorization = inputs.authorization.value
    manifest = inputs.manifest.value
    outer = inputs.outer_authority.value
    spark = inputs.spark_validation_receipt.value
    declared_outputs = manifest.get("outputs")
    if not isinstance(declared_outputs, Mapping):
        raise AppServerError("campaign-launch-claim-outputs-invalid")
    output_basenames = {
        "evidence_basename": output.name,
        "authorization_state_basename": authorization_state.name,
        "steering_registry_basename": steering_registry.name,
        "allocation_ledger_basename": allocation_ledger.name,
    }


    if output_basenames != dict(declared_outputs):
        raise AppServerError("campaign-launch-claim-outputs-mismatch")
    bindings = authorization.get("bindings")
    if not isinstance(bindings, Mapping):
        raise AppServerError("campaign-launch-claim-authorization-invalid")
    return {
        "claim_type": "cwo-native-live-campaign-launch-claim",
        "version": 4,
        "authority_semantics": {
            "durable_one_shot_claim_is_launch_authority": True,
            "authorization_and_nonce_tombstones_are_permanent": True,
            "bound_manifest_validation_is_evidence_only": True,
            "resume_retry_replay_salvage_forbidden": True,
            "terminal_predecessor_is_attested_containment_evidence_only": True,
            "terminal_predecessor_is_never_operative_authority": True,
        },
        "authorization": {
            "authorization_id": authorization.get("authorization_id"),
            "raw_sha256": inputs.authorization.raw_sha256,
            "canonical_sha256": authorization.get(
                "canonical_authorization_sha256"
            ),
            "run_generation": authorization.get("run_generation"),
            "live_generation": authorization.get("live_generation"),
            "predecessor_live_generation": authorization.get(
                "predecessor_live_generation"
            ),
            "campaign_nonce": bindings.get("campaign_nonce"),
        },
        "manifest": {
            "manifest_id": manifest.get("manifest_id"),
            "raw_sha256": inputs.manifest.raw_sha256,
            "canonical_sha256": manifest.get("manifest_sha256"),
        },
        "outer_authority": {
            "authority_id": outer.get("authority_id"),
            "raw_sha256": inputs.outer_authority.raw_sha256,
            "canonical_sha256": outer.get("canonical_outer_authority_sha256"),
        },
        "spark_validation": {
            "receipt_raw_sha256": inputs.spark_validation_receipt.raw_sha256,
            "receipt_canonical_sha256": spark.get("canonical_receipt_sha256"),
            "session_id": spark.get("session_id"),
            "session_file_sha256": sha256_bytes(
                inputs.spark_validation_session_bytes
            ),
        },
        "successor_proof": {
            "proof_dag": [
                "v9/v6",
                "v8/v5",
                "v7/v4",
                "v6/v3",
                "v5/v2",
                "v4/v1",
            ],
            "recovery_cause_evidence_raw_sha256": (
                inputs.recovery_cause_evidence.raw_sha256
            ),
            "recovery_cause_source_analysis_sha256": sha256_bytes(
                inputs.recovery_cause_source_analysis_bytes
            ),
            "failed_predecessor": {
                "authorization_raw_sha256": failed.authorization.raw_sha256,
                "manifest_raw_sha256": failed.manifest.raw_sha256,
                "authorization_state_raw_sha256": (
                    failed.authorization_state.raw_sha256
                ),
                "failure_evidence_raw_sha256": (
                    failed.failure_evidence.raw_sha256
                ),
                "containment_raw_sha256": failed.containment.raw_sha256,
                "allocation_ledger_raw_sha256": (
                    failed.allocation_ledger.raw_sha256
                ),
                "allocation_audit_sha256": sha256_bytes(
                    failed.allocation_audit_bytes
                ),
                "authorization_recovery_cause_evidence_raw_sha256": (
                    failed.authorization_recovery_cause_evidence.raw_sha256
                ),
                "authorization_recovery_cause_source_analysis_sha256": (
                    sha256_bytes(
                        failed.authorization_recovery_cause_source_analysis
                    )
                ),
                "outer_authority_raw_sha256": failed.outer_authority.raw_sha256,
                "independent_validation_receipt_raw_sha256": (
                    failed.independent_validation_receipt.raw_sha256
                ),
                "independent_validation_session_sha256": sha256_bytes(
                    failed.independent_validation_session_bytes
                ),
                "contained_session_sha256s": [
                    sha256_bytes(raw) for raw in failed.contained_session_bytes
                ],
                "contained_session_family_sha256": bindings.get(
                    "predecessor_contained_session_family_sha256"
                ),
                "contained_session_count": bindings.get(
                    "predecessor_contained_session_count"
                ),
                "attestation_disposition": (
                    "trusted-attested-contained-nonaccepting"
                ),
                "accepting_model_evidence": False,
                "operative_authority": False,
            },
            "quarantined_ancestor": {
                "authorization_raw_sha256": quarantine.authorization.raw_sha256,
                "manifest_raw_sha256": quarantine.manifest.raw_sha256,
                "containment_raw_sha256": quarantine.containment.raw_sha256,
                "quarantined_session_sha256": sha256_bytes(
                    quarantine.quarantined_session_bytes
                ),
                "attestation_disposition": (
                    "unavailable-quarantined-nonaccepting"
                ),
                "accepting_model_evidence": False,
            },
            "predecessor_recovery_cause_evidence_raw_sha256": (
                predecessor.authorization_recovery_cause_evidence.raw_sha256
            ),
            "predecessor_recovery_cause_source_analysis_sha256": sha256_bytes(
                predecessor.authorization_recovery_cause_source_analysis
            ),
            "ancestor_authorization_cause_evidence_sha256": sha256_bytes(
                ancestor.authorization_cause_evidence
            ),
            "grandancestor_cause_evidence_sha256": sha256_bytes(
                grandancestor.cause_evidence
            ),
            "predecessor_contained_session_sha256s": [
                sha256_bytes(raw) for raw in predecessor.contained_session_bytes
            ],
            "ancestor_contained_session_sha256s": [
                sha256_bytes(raw) for raw in ancestor.contained_session_bytes
            ],
            "grandancestor_contained_session_sha256s": [
                sha256_bytes(raw) for raw in grandancestor.contained_session_bytes
            ],
        },
        "steering": {
            "pre_mutation_receipt_raw_sha256": (
                inputs.pre_mutation_receipt.raw_sha256
            ),
            "pre_mutation_receipt_canonical_sha256": (
                inputs.pre_mutation_receipt.value.get("canonical_receipt_sha256")
            ),
            "pre_live_receipt_raw_sha256": inputs.pre_live_receipt.raw_sha256,
            "pre_live_receipt_canonical_sha256": (
                inputs.pre_live_receipt.value.get("canonical_receipt_sha256")
            ),
            "pre_mutation_adjudication_raw_sha256": (
                inputs.pre_mutation_adjudication.raw_sha256
            ),
            "pre_live_adjudication_raw_sha256": (
                inputs.pre_live_adjudication.raw_sha256
            ),
        },
        "outside_review": {
            "opus_evidence_raw_sha256": inputs.opus_review_evidence.raw_sha256,
            "opus_adjudication_raw_sha256": inputs.opus_adjudication.raw_sha256,
            "exact_model": inputs.opus_review_evidence.value.get("exact_model"),
            "glm_5_2_used": inputs.opus_review_evidence.value.get("glm_5_2_used"),
            "model_synthesis_used": inputs.opus_review_evidence.value.get(
                "model_synthesis_used"
            ),
            "main_architect_decision": inputs.opus_adjudication.value.get(
                "main_architect_decision"
            ),
        },
        "source_file_sha256s": generation10_source_file_sha256s(inputs),
        "output_basenames": output_basenames,
        "output_paths": {
            "evidence": str(output.resolve(strict=False)),
            "authorization_state": str(authorization_state.resolve(strict=False)),
            "steering_registry": str(steering_registry.resolve(strict=False)),
            "allocation_ledger": str(allocation_ledger.resolve(strict=False)),
        },
        "validator_contract_sha256": bindings.get("validator_contract_sha256"),
    }



def campaign_launch_claim_payload_v6(
    inputs: CampaignLaunchInputs,
    *,
    output: Path,
    authorization_state: Path,
    steering_registry: Path,
    allocation_ledger: Path,
) -> dict[str, Any]:
    """Bind every Generation-12 source and the terminal Gen11 leaf."""

    interrupted = require_generation12_launch_inputs(inputs)
    authorization = inputs.authorization.value
    manifest = inputs.manifest.value
    outer = inputs.outer_authority.value
    spark = inputs.spark_validation_receipt.value
    version_errors = validate_operative_version_tuple(
        authorization.get("version"), manifest.get("version"), 6, 6
    )
    if version_errors:
        raise AppServerError(
            "campaign-launch-claim-version-tuple-invalid:"
            + ";".join(version_errors)
        )
    declared_outputs = manifest.get("outputs")
    if not isinstance(declared_outputs, Mapping):
        raise AppServerError("campaign-launch-claim-outputs-invalid")
    output_basenames = {
        "evidence_basename": output.name,
        "authorization_state_basename": authorization_state.name,
        "steering_registry_basename": steering_registry.name,
        "allocation_ledger_basename": allocation_ledger.name,
    }
    if output_basenames != dict(declared_outputs):
        raise AppServerError("campaign-launch-claim-outputs-mismatch")
    bindings = authorization.get("bindings")
    if not isinstance(bindings, Mapping):
        raise AppServerError("campaign-launch-claim-authorization-invalid")
    return {
        "claim_type": "cwo-native-live-campaign-launch-claim",
        "version": 6,
        "operative_version_tuple": {
            "authorization_version": 11,
            "manifest_version": 8,
            "launch_claim_version": 6,
            "validator_contract_version": 6,
        },
        "authority_semantics": {
            "durable_one_shot_claim_is_launch_authority": True,
            "authorization_and_nonce_tombstones_are_permanent": True,
            "bound_manifest_validation_is_evidence_only": True,
            "resume_retry_replay_salvage_forbidden": True,
            "terminal_predecessor_is_containment_evidence_only": True,
            "interrupted_terminal_is_never_accepting_completion": True,
            "consumed_predecessor_steering_is_evidence_only": True,
        },
        "authorization": {
            "authorization_id": authorization.get("authorization_id"),
            "raw_sha256": inputs.authorization.raw_sha256,
            "canonical_sha256": authorization.get(
                "canonical_authorization_sha256"
            ),
            "run_generation": authorization.get("run_generation"),
            "live_generation": authorization.get("live_generation"),
            "predecessor_live_generation": authorization.get(
                "predecessor_live_generation"
            ),
            "campaign_nonce": bindings.get("campaign_nonce"),
        },
        "manifest": {
            "manifest_id": manifest.get("manifest_id"),
            "raw_sha256": inputs.manifest.raw_sha256,
            "canonical_sha256": manifest.get("manifest_sha256"),
        },
        "outer_authority": {
            "authority_id": outer.get("authority_id"),
            "raw_sha256": inputs.outer_authority.raw_sha256,
            "canonical_sha256": outer.get("canonical_outer_authority_sha256"),
        },
        "spark_validation": {
            "receipt_raw_sha256": inputs.spark_validation_receipt.raw_sha256,
            "receipt_canonical_sha256": spark.get("canonical_receipt_sha256"),
            "session_id": spark.get("session_id"),
            "session_file_sha256": sha256_bytes(
                inputs.spark_validation_session_bytes
            ),
        },
        "successor_proof": {
            "proof_dag": [
                "v11/v8",
                "v10/v7",
                "v9/v6",
                "v8/v5",
                "v7/v4",
                "v6/v3",
                "v5/v2",
                "v4/v1",
            ],
            "recovery_cause_evidence_raw_sha256": (
                inputs.recovery_cause_evidence.raw_sha256
            ),
            "recovery_cause_source_analysis_sha256": sha256_bytes(
                inputs.recovery_cause_source_analysis_bytes
            ),
            "interrupted_failed_predecessor": {
                "authorization_raw_sha256": interrupted.authorization.raw_sha256,
                "manifest_raw_sha256": interrupted.manifest.raw_sha256,
                "authorization_state_raw_sha256": (
                    interrupted.authorization_state.raw_sha256
                ),
                "failure_evidence_raw_sha256": (
                    interrupted.failure_evidence.raw_sha256
                ),
                "containment_raw_sha256": interrupted.containment.raw_sha256,
                "global_claim_raw_sha256": interrupted.global_claim.raw_sha256,
                "authorization_marker_raw_sha256": (
                    interrupted.authorization_marker.raw_sha256
                ),
                "nonce_marker_raw_sha256": interrupted.nonce_marker.raw_sha256,
                "scope_state_raw_sha256": interrupted.scope_state.raw_sha256,
                "preflight_raw_sha256": interrupted.preflight.raw_sha256,
                "pre_mutation_receipt_raw_sha256": (
                    interrupted.pre_mutation_receipt.raw_sha256
                ),
                "pre_mutation_adjudication_raw_sha256": (
                    interrupted.pre_mutation_adjudication.raw_sha256
                ),
                "pre_live_receipt_raw_sha256": (
                    interrupted.pre_live_receipt.raw_sha256
                ),
                "pre_live_adjudication_raw_sha256": (
                    interrupted.pre_live_adjudication.raw_sha256
                ),
                "allocation_ledger_raw_sha256": (
                    interrupted.allocation_ledger.raw_sha256
                ),
                "allocation_audit_sha256": sha256_bytes(
                    interrupted.allocation_audit_bytes
                ),
                "steering_registry_raw_sha256": (
                    interrupted.steering_registry.raw_sha256
                ),
                "terminal_session_count": 1,
                "terminal_session_sha256": sha256_bytes(
                    interrupted.terminal_session_bytes
                ),
                "terminal_facts_raw_sha256": interrupted.terminal_facts.raw_sha256,
                "terminal_facts_canonical_sha256": interrupted.terminal_facts.value.get(
                    "canonical_terminal_facts_sha256"
                ),
                "generation11_runner_source_sha256": sha256_bytes(
                    interrupted.generation11_runner_source_bytes
                ),
                "generation11_session_boundary_source_sha256": sha256_bytes(
                    interrupted.generation11_session_boundary_source_bytes
                ),
                "recovery_cause_analysis_sha256": sha256_bytes(
                    interrupted.recovery_cause_analysis_bytes
                ),
                "recovery_steering_receipt_raw_sha256": (
                    interrupted.recovery_steering_receipt.raw_sha256
                ),
                "recovery_steering_receipt_canonical_sha256": (
                    interrupted.recovery_steering_receipt.value.get(
                        "canonical_receipt_sha256"
                    )
                ),
                "recovery_steering_session_sha256": sha256_bytes(
                    interrupted.recovery_steering_session_bytes
                ),
                "outer_authority_raw_sha256": (
                    interrupted.outer_authority.raw_sha256
                ),
                "independent_validation_receipt_raw_sha256": (
                    interrupted.independent_validation_receipt.raw_sha256
                ),
                "independent_validation_session_sha256": sha256_bytes(
                    interrupted.independent_validation_session_bytes
                ),
                "authorization_recovery_cause_evidence_raw_sha256": (
                    interrupted.authorization_recovery_cause_evidence.raw_sha256
                ),
                "authorization_recovery_cause_source_analysis_sha256": (
                    sha256_bytes(
                        interrupted.authorization_recovery_cause_source_analysis
                    )
                ),
                "initial_empty_boundary_sha256": bindings.get(
                    "predecessor_initial_empty_boundary_sha256"
                ),
                "recovery_entry_sha256": bindings.get(
                    "predecessor_recovery_entry_sha256"
                ),
                "interrupted_terminal_event_sha256": bindings.get(
                    "predecessor_interrupted_terminal_event_sha256"
                ),
                "no_replacement_read_sha256": bindings.get(
                    "predecessor_no_replacement_read_sha256"
                ),
                "accepting_completion": False,
                "operative_authority": False,
            },
            "ancestor_launch_claim_sha256": interrupted.global_claim.value.get(
                "launch_claim_sha256"
            ),
            "ancestor_proof_root_authorization_sha256": (
                interrupted.ancestor.authorization.raw_sha256
            ),
        },
        "steering": {
            "pre_mutation_receipt_raw_sha256": (
                inputs.pre_mutation_receipt.raw_sha256
            ),
            "pre_mutation_receipt_canonical_sha256": (
                inputs.pre_mutation_receipt.value.get("canonical_receipt_sha256")
            ),
            "pre_live_receipt_raw_sha256": inputs.pre_live_receipt.raw_sha256,
            "pre_live_receipt_canonical_sha256": (
                inputs.pre_live_receipt.value.get("canonical_receipt_sha256")
            ),
            "pre_mutation_adjudication_raw_sha256": (
                inputs.pre_mutation_adjudication.raw_sha256
            ),
            "pre_live_adjudication_raw_sha256": (
                inputs.pre_live_adjudication.raw_sha256
            ),
        },
        "outside_review": {
            "opus_evidence_raw_sha256": inputs.opus_review_evidence.raw_sha256,
            "opus_adjudication_raw_sha256": inputs.opus_adjudication.raw_sha256,
            "exact_model": inputs.opus_review_evidence.value.get("exact_model"),
            "glm_5_2_used": inputs.opus_review_evidence.value.get("glm_5_2_used"),
            "model_synthesis_used": inputs.opus_review_evidence.value.get(
                "model_synthesis_used"
            ),
            "main_architect_decision": inputs.opus_adjudication.value.get(
                "main_architect_decision"
            ),
        },
        "source_file_sha256s": generation12_source_file_sha256s(inputs),
        "output_basenames": output_basenames,
        "output_paths": {
            "evidence": str(output.resolve(strict=False)),
            "authorization_state": str(authorization_state.resolve(strict=False)),
            "steering_registry": str(steering_registry.resolve(strict=False)),
            "allocation_ledger": str(allocation_ledger.resolve(strict=False)),
        },
        "validator_contract_sha256": bindings.get("validator_contract_sha256"),
    }


def campaign_launch_claim_payload_v5(
    inputs: CampaignLaunchInputs,
    *,
    output: Path,
    authorization_state: Path,
    steering_registry: Path,
    allocation_ledger: Path,
) -> dict[str, Any]:
    """Bind every Generation-11 source and the zero-allocation fault leaf."""

    preallocation = require_generation11_launch_inputs(inputs)
    authorization = inputs.authorization.value
    manifest = inputs.manifest.value
    outer = inputs.outer_authority.value
    spark = inputs.spark_validation_receipt.value
    declared_outputs = manifest.get("outputs")
    if not isinstance(declared_outputs, Mapping):
        raise AppServerError("campaign-launch-claim-outputs-invalid")
    output_basenames = {
        "evidence_basename": output.name,
        "authorization_state_basename": authorization_state.name,
        "steering_registry_basename": steering_registry.name,
        "allocation_ledger_basename": allocation_ledger.name,
    }
    if output_basenames != dict(declared_outputs):
        raise AppServerError("campaign-launch-claim-outputs-mismatch")
    bindings = authorization.get("bindings")
    if not isinstance(bindings, Mapping):
        raise AppServerError("campaign-launch-claim-authorization-invalid")
    return {
        "claim_type": "cwo-native-live-campaign-launch-claim",
        "version": 5,
        "authority_semantics": {
            "durable_one_shot_claim_is_launch_authority": True,
            "authorization_and_nonce_tombstones_are_permanent": True,
            "bound_manifest_validation_is_evidence_only": True,
            "resume_retry_replay_salvage_forbidden": True,
            "terminal_predecessor_is_containment_evidence_only": True,
            "preclaim_steering_binding_is_required": True,
        },
        "authorization": {
            "authorization_id": authorization.get("authorization_id"),
            "raw_sha256": inputs.authorization.raw_sha256,
            "canonical_sha256": authorization.get(
                "canonical_authorization_sha256"
            ),
            "run_generation": authorization.get("run_generation"),
            "live_generation": authorization.get("live_generation"),
            "predecessor_live_generation": authorization.get(
                "predecessor_live_generation"
            ),
            "campaign_nonce": bindings.get("campaign_nonce"),
        },
        "manifest": {
            "manifest_id": manifest.get("manifest_id"),
            "raw_sha256": inputs.manifest.raw_sha256,
            "canonical_sha256": manifest.get("manifest_sha256"),
        },
        "outer_authority": {
            "authority_id": outer.get("authority_id"),
            "raw_sha256": inputs.outer_authority.raw_sha256,
            "canonical_sha256": outer.get("canonical_outer_authority_sha256"),
        },
        "spark_validation": {
            "receipt_raw_sha256": inputs.spark_validation_receipt.raw_sha256,
            "receipt_canonical_sha256": spark.get("canonical_receipt_sha256"),
            "session_id": spark.get("session_id"),
            "session_file_sha256": sha256_bytes(
                inputs.spark_validation_session_bytes
            ),
        },
        "successor_proof": {
            "proof_dag": [
                "v10/v7",
                "v9/v6",
                "v8/v5",
                "v7/v4",
                "v6/v3",
                "v5/v2",
                "v4/v1",
            ],
            "recovery_cause_evidence_raw_sha256": (
                inputs.recovery_cause_evidence.raw_sha256
            ),
            "recovery_cause_source_analysis_sha256": sha256_bytes(
                inputs.recovery_cause_source_analysis_bytes
            ),
            "preallocation_failed_predecessor": {
                "authorization_raw_sha256": preallocation.authorization.raw_sha256,
                "manifest_raw_sha256": preallocation.manifest.raw_sha256,
                "authorization_state_raw_sha256": (
                    preallocation.authorization_state.raw_sha256
                ),
                "failure_evidence_raw_sha256": (
                    preallocation.failure_evidence.raw_sha256
                ),
                "containment_raw_sha256": preallocation.containment.raw_sha256,
                "global_claim_raw_sha256": preallocation.global_claim.raw_sha256,
                "authorization_marker_raw_sha256": (
                    preallocation.authorization_marker.raw_sha256
                ),
                "nonce_marker_raw_sha256": preallocation.nonce_marker.raw_sha256,
                "scope_state_raw_sha256": preallocation.scope_state.raw_sha256,
                "preflight_raw_sha256": preallocation.preflight.raw_sha256,
                "pre_mutation_receipt_raw_sha256": (
                    preallocation.pre_mutation_receipt.raw_sha256
                ),
                "pre_live_receipt_raw_sha256": (
                    preallocation.pre_live_receipt.raw_sha256
                ),
                "allocation_intent_count": 0,
                "session_count": 0,
                "operative_authority": False,
            },
            "ancestor_launch_claim_sha256": preallocation.global_claim.value.get(
                "launch_claim_sha256"
            ),
            "ancestor_proof_root_authorization_sha256": (
                preallocation.ancestor.authorization.raw_sha256
            ),
        },
        "steering": {
            "pre_mutation_receipt_raw_sha256": (
                inputs.pre_mutation_receipt.raw_sha256
            ),
            "pre_mutation_receipt_canonical_sha256": (
                inputs.pre_mutation_receipt.value.get("canonical_receipt_sha256")
            ),
            "pre_live_receipt_raw_sha256": inputs.pre_live_receipt.raw_sha256,
            "pre_live_receipt_canonical_sha256": (
                inputs.pre_live_receipt.value.get("canonical_receipt_sha256")
            ),
            "pre_mutation_adjudication_raw_sha256": (
                inputs.pre_mutation_adjudication.raw_sha256
            ),
            "pre_live_adjudication_raw_sha256": (
                inputs.pre_live_adjudication.raw_sha256
            ),
        },
        "outside_review": {
            "opus_evidence_raw_sha256": inputs.opus_review_evidence.raw_sha256,
            "opus_adjudication_raw_sha256": inputs.opus_adjudication.raw_sha256,
            "exact_model": inputs.opus_review_evidence.value.get("exact_model"),
            "glm_5_2_used": inputs.opus_review_evidence.value.get("glm_5_2_used"),
            "model_synthesis_used": inputs.opus_review_evidence.value.get(
                "model_synthesis_used"
            ),
            "main_architect_decision": inputs.opus_adjudication.value.get(
                "main_architect_decision"
            ),
        },
        "source_file_sha256s": generation11_source_file_sha256s(inputs),
        "output_basenames": output_basenames,
        "output_paths": {
            "evidence": str(output.resolve(strict=False)),
            "authorization_state": str(authorization_state.resolve(strict=False)),
            "steering_registry": str(steering_registry.resolve(strict=False)),
            "allocation_ledger": str(allocation_ledger.resolve(strict=False)),
        },
        "validator_contract_sha256": bindings.get("validator_contract_sha256"),
    }


def campaign_launch_claim_sha256(
    inputs: CampaignLaunchInputs,
    *,
    output: Path,
    authorization_state: Path,
    steering_registry: Path,
    allocation_ledger: Path,
) -> str:
    """Seal one immutable versioned launch claim under its exact domain."""

    authorization_version = inputs.authorization.value.get("version")
    if authorization_version == 11:
        claim = campaign_launch_claim_payload_v6(
            inputs,
            output=output,
            authorization_state=authorization_state,
            steering_registry=steering_registry,
            allocation_ledger=allocation_ledger,
        )
        return domain_sha256(
            claim, domain="native-live-campaign-launch-claim-v6"
        )
    if authorization_version == 10:
        claim = campaign_launch_claim_payload_v5(
            inputs,
            output=output,
            authorization_state=authorization_state,
            steering_registry=steering_registry,
            allocation_ledger=allocation_ledger,
        )
        return domain_sha256(
            claim, domain="native-live-campaign-launch-claim-v5"
        )
    if authorization_version == 9:
        claim = campaign_launch_claim_payload_v4(
            inputs,
            output=output,
            authorization_state=authorization_state,
            steering_registry=steering_registry,
            allocation_ledger=allocation_ledger,
        )
        return domain_sha256(
            claim, domain="native-live-campaign-launch-claim-v4"
        )
    if authorization_version == 8:
        claim = campaign_launch_claim_payload_v3(
            inputs,
            output=output,
            authorization_state=authorization_state,
            steering_registry=steering_registry,
            allocation_ledger=allocation_ledger,
        )
        return domain_sha256(
            claim, domain="native-live-campaign-launch-claim-v3"
        )
    if authorization_version != 7:
        proof = inputs.predecessor_proof
        if not isinstance(proof, Version5PredecessorProofInputs):
            raise AppServerError("campaign-historical-proof-input-invalid")
        historical_claim = {
            "claim_type": "cwo-native-live-campaign-launch-claim",
            "version": 1,
            "authorization_raw_sha256": inputs.authorization.raw_sha256,
            "manifest_raw_sha256": inputs.manifest.raw_sha256,
            "outer_authority_raw_sha256": inputs.outer_authority.raw_sha256,
            "release_patch_sha256": sha256_bytes(inputs.release_patch_bytes),
            "pre_mutation_receipt_raw_sha256": (
                inputs.pre_mutation_receipt.raw_sha256
            ),
            "pre_live_receipt_raw_sha256": inputs.pre_live_receipt.raw_sha256,
            "opus_evidence_raw_sha256": inputs.opus_review_evidence.raw_sha256,
            "spark_receipt_raw_sha256": (
                inputs.spark_validation_receipt.raw_sha256
            ),
            "spark_session_sha256": sha256_bytes(
                inputs.spark_validation_session_bytes
            ),
            "predecessor_authorization_raw_sha256": proof.authorization.raw_sha256,
            "predecessor_manifest_raw_sha256": proof.manifest.raw_sha256,
            "predecessor_contained_session_sha256s": [
                sha256_bytes(raw) for raw in proof.contained_session_bytes
            ],
            "ancestor_contained_session_sha256s": [
                sha256_bytes(raw) for raw in proof.ancestor.contained_session_bytes
            ],
            "recovery_cause_evidence_raw_sha256": (
                inputs.recovery_cause_evidence.raw_sha256
                if inputs.recovery_cause_evidence is not None
                else None
            ),
            "recovery_cause_source_analysis_sha256": (
                sha256_bytes(inputs.recovery_cause_source_analysis_bytes)
                if inputs.recovery_cause_source_analysis_bytes is not None
                else None
            ),
            "output_paths": {
                "evidence": str(output.resolve(strict=False)),
                "authorization_state": str(
                    authorization_state.resolve(strict=False)
                ),
                "steering_registry": str(steering_registry.resolve(strict=False)),
                "allocation_ledger": str(allocation_ledger.resolve(strict=False)),
            },
        }
        return domain_sha256(
            historical_claim, domain="native-live-campaign-launch-claim"
        )
    claim = campaign_launch_claim_payload(
        inputs,
        output=output,
        authorization_state=authorization_state,
        steering_registry=steering_registry,
        allocation_ledger=allocation_ledger,
    )
    return domain_sha256(claim, domain="native-live-campaign-launch-claim-v2")


def validate_and_acquire_global_campaign_claim(
    inputs: CampaignLaunchInputs,
    *,
    campaign_nonce: str,
    authorization_id: str,
    authorization_sha256: str,
    repo_head: str,
    guarded_primary: Path,
    output: Path,
    authorization_state: Path,
    steering_registry: Path,
    allocation_ledger: Path,
) -> tuple[
    dict[str, Any],
    str,
    dict[str, Any],
    dict[str, tuple[str, dict[str, Any]]],
    GlobalCampaignReservation,
]:
    """Complete every preclaim check before creating durable authority state."""

    artifact_bindings = validate_campaign_launch_bindings(
        inputs=inputs,
        guarded_primary=guarded_primary,
    )
    prepared = plan_steering_receipt_consumptions(
        campaign_nonce,
        authorization_id,
        authorization_sha256,
        registry_file=steering_registry,
        repo_head=repo_head,
        pre_mutation_receipt=inputs.pre_mutation_receipt.value,
        pre_mutation_adjudication=inputs.pre_mutation_adjudication.value,
        pre_mutation_adjudication_sha256=(
            inputs.pre_mutation_adjudication.raw_sha256
        ),
        pre_live_receipt=inputs.pre_live_receipt.value,
        pre_live_adjudication=inputs.pre_live_adjudication.value,
        pre_live_adjudication_sha256=inputs.pre_live_adjudication.raw_sha256,
    )
    launch_claim_sha256 = campaign_launch_claim_sha256(
        inputs,
        output=output,
        authorization_state=authorization_state,
        steering_registry=steering_registry,
        allocation_ledger=allocation_ledger,
    )
    artifact_bindings["launch_claim_sha256"] = launch_claim_sha256
    expected_bound_manifest_validation = seal_bound_manifest_validation(
        inputs.manifest.value,
        artifact_bindings,
    )
    reservation = acquire_global_campaign_claim(
        inputs,
        launch_claim_sha256=launch_claim_sha256,
        output=output,
        authorization_state=authorization_state,
        steering_registry=steering_registry,
        allocation_ledger=allocation_ledger,
    )
    return (
        artifact_bindings,
        launch_claim_sha256,
        expected_bound_manifest_validation,
        prepared,
        reservation,
    )


def safe_allocation_ledger_summary(
    ledger: NativeLiveAllocationLedgerStore | None,
) -> dict[str, Any] | None:
    if ledger is None:
        return None
    try:
        return {"available": True, **ledger.summary()}
    except Exception as exc:
        return {
            "available": False,
            "summary_error_sha256": sha256_text(f"{type(exc).__name__}:{exc}"),
        }


def require_operative_campaign_contract(
    authorization_version: Any,
    manifest_version: Any,
    launch_claim_version: Any = 6,
    validator_contract_version: Any = 6,
) -> None:
    """Keep historical contracts inspectable but outside the live launcher."""

    errors = validate_operative_version_tuple(
        authorization_version,
        manifest_version,
        launch_claim_version,
        validator_contract_version,
    )
    if not errors:
        return
    if authorization_version != 11:
        raise AppServerError("campaign-authorization-version-historical-only")
    raise AppServerError(
        "campaign-contract-version-mismatch:" + ";".join(errors)
    )


GENERATION8_REQUIRED_PROOF_PATHS = {
    "predecessor-authorization",
    "predecessor-manifest",
    "predecessor-authorization-state",
    "predecessor-failure-evidence",
    "predecessor-containment",
    "predecessor-allocation-ledger",
    "predecessor-allocation-audit",
    "predecessor-outer-authority",
    "predecessor-independent-validation-receipt",
    "predecessor-independent-validation-session",
    "predecessor-recovery-cause-evidence",
    "predecessor-recovery-cause-source-analysis",
    "ancestor-authorization",
    "ancestor-manifest",
    "ancestor-authorization-state",
    "ancestor-failure-evidence",
    "ancestor-containment",
    "ancestor-allocation-ledger",
    "ancestor-allocation-audit",
    "ancestor-outer-authority",
    "ancestor-independent-validation-receipt",
    "ancestor-independent-validation-session",
    "ancestor-authorization-cause-evidence",
    "grandancestor-authorization-cause-evidence",
    "grandancestor-authorization",
    "grandancestor-manifest",
    "grandancestor-authorization-state",
    "grandancestor-failure-evidence",
    "grandancestor-original-containment",
    "grandancestor-containment",
    "grandancestor-allocation-ledger",
    "grandancestor-allocation-audit",
    "cause-evidence",
    "cause-source-analysis",
}
GENERATION8_FORBIDDEN_MIXED_PROOF_PATHS = {
    "predecessor-original-containment",
    "predecessor-authorization-cause-evidence",
    "ancestor-original-containment",
}


def require_generation8_proof_path_set(
    paths: Mapping[str, Path],
    *,
    predecessor_contained_sessions: int,
    ancestor_contained_sessions: int,
    grandancestor_contained_sessions: int,
) -> None:
    """Reject an incomplete, historical, or mixed proof before allocation."""

    if (
        not GENERATION8_REQUIRED_PROOF_PATHS.issubset(paths)
        or GENERATION8_FORBIDDEN_MIXED_PROOF_PATHS.intersection(paths)
        or predecessor_contained_sessions < 1
        or ancestor_contained_sessions < 1
        or grandancestor_contained_sessions < 1
    ):
        raise AppServerError("campaign-generation8-proof-path-set-invalid")


GENERATION9_QUARANTINE_PROOF_PATHS = {
    "quarantined-predecessor-authorization",
    "quarantined-predecessor-manifest",
    "quarantined-predecessor-authorization-state",
    "quarantined-predecessor-failure-evidence",
    "quarantined-predecessor-containment",
    "quarantined-predecessor-allocation-ledger",
    "quarantined-predecessor-allocation-audit",
    "quarantined-predecessor-outer-authority",
    "quarantined-predecessor-independent-validation-receipt",
    "quarantined-predecessor-independent-validation-session",
    "quarantined-predecessor-recovery-cause-evidence",
    "quarantined-predecessor-recovery-cause-source-analysis",
    "quarantined-predecessor-session",
}
GENERATION9_REQUIRED_PROOF_PATHS = (
    GENERATION8_REQUIRED_PROOF_PATHS | GENERATION9_QUARANTINE_PROOF_PATHS
)


def require_generation9_proof_path_set(
    paths: Mapping[str, Path],
    *,
    predecessor_contained_sessions: int,
    ancestor_contained_sessions: int,
    grandancestor_contained_sessions: int,
) -> None:
    """Reject an incomplete, downgraded, mixed, or aliased v8/v5 proof."""

    if (
        not GENERATION9_REQUIRED_PROOF_PATHS.issubset(paths)
        or GENERATION8_FORBIDDEN_MIXED_PROOF_PATHS.intersection(paths)
        or predecessor_contained_sessions < 1
        or ancestor_contained_sessions < 1
        or grandancestor_contained_sessions < 1
    ):
        raise AppServerError("campaign-generation9-proof-path-set-invalid")


GENERATION10_FAILED_PROOF_PATHS = {
    "failed-predecessor-authorization",
    "failed-predecessor-manifest",
    "failed-predecessor-authorization-state",
    "failed-predecessor-failure-evidence",
    "failed-predecessor-containment",
    "failed-predecessor-allocation-ledger",
    "failed-predecessor-allocation-audit",
    "failed-predecessor-outer-authority",
    "failed-predecessor-independent-validation-receipt",
    "failed-predecessor-independent-validation-session",
    "failed-predecessor-recovery-cause-evidence",
    "failed-predecessor-recovery-cause-source-analysis",
}
GENERATION10_REQUIRED_PROOF_PATHS = (
    GENERATION9_REQUIRED_PROOF_PATHS | GENERATION10_FAILED_PROOF_PATHS
)


def require_generation10_proof_path_set(
    paths: Mapping[str, Path],
    *,
    failed_predecessor_contained_sessions: int,
    predecessor_contained_sessions: int,
    ancestor_contained_sessions: int,
    grandancestor_contained_sessions: int,
) -> None:
    """Reject an incomplete, downgraded, or mixed v9/v6 proof before allocation."""

    failed_session_labels = {
        label
        for label in paths
        if label.startswith("failed-predecessor-contained-session-")
    }
    expected_failed_session_labels = {
        f"failed-predecessor-contained-session-{index}" for index in range(5)
    }
    if (
        not GENERATION10_REQUIRED_PROOF_PATHS.issubset(paths)
        or GENERATION8_FORBIDDEN_MIXED_PROOF_PATHS.intersection(paths)
        or failed_predecessor_contained_sessions != 5
        or failed_session_labels != expected_failed_session_labels
        or predecessor_contained_sessions < 1
        or ancestor_contained_sessions < 1
        or grandancestor_contained_sessions < 1
    ):
        raise AppServerError("campaign-generation10-proof-path-set-invalid")


GENERATION11_PREALLOCATION_PROOF_PATHS = {
    "preallocation-failed-predecessor-authorization",
    "preallocation-failed-predecessor-manifest",
    "preallocation-failed-predecessor-authorization-state",
    "preallocation-failed-predecessor-failure-evidence",
    "preallocation-failed-predecessor-containment",
    "preallocation-failed-predecessor-global-claim",
    "preallocation-failed-predecessor-authorization-marker",
    "preallocation-failed-predecessor-nonce-marker",
    "preallocation-failed-predecessor-scope-state",
    "preallocation-failed-predecessor-preflight",
    "preallocation-failed-predecessor-pre-mutation-receipt",
    "preallocation-failed-predecessor-pre-live-receipt",
    "preallocation-failed-predecessor-outer-authority",
    "preallocation-failed-predecessor-independent-validation-receipt",
    "preallocation-failed-predecessor-independent-validation-session",
    "preallocation-failed-predecessor-recovery-cause-evidence",
    "preallocation-failed-predecessor-recovery-cause-source-analysis",
}
GENERATION11_REQUIRED_PROOF_PATHS = (
    GENERATION10_REQUIRED_PROOF_PATHS | GENERATION11_PREALLOCATION_PROOF_PATHS
)


def require_generation11_proof_path_set(
    paths: Mapping[str, Path],
    *,
    failed_predecessor_contained_sessions: int,
    predecessor_contained_sessions: int,
    ancestor_contained_sessions: int,
    grandancestor_contained_sessions: int,
) -> None:
    """Reject an incomplete, downgraded, mixed, or session-bearing v10 leaf."""

    immediate_session_labels = {
        label
        for label in paths
        if label.startswith("preallocation-failed-predecessor-contained-session-")
    }
    if (
        not GENERATION11_REQUIRED_PROOF_PATHS.issubset(paths)
        or immediate_session_labels
    ):
        raise AppServerError("campaign-generation11-proof-path-set-invalid")
    require_generation10_proof_path_set(
        paths,
        failed_predecessor_contained_sessions=(
            failed_predecessor_contained_sessions
        ),
        predecessor_contained_sessions=predecessor_contained_sessions,
        ancestor_contained_sessions=ancestor_contained_sessions,
        grandancestor_contained_sessions=grandancestor_contained_sessions,
    )


GENERATION12_INTERRUPTED_PROOF_PATHS = {
    "interrupted-failed-predecessor-authorization",
    "interrupted-failed-predecessor-manifest",
    "interrupted-failed-predecessor-authorization-state",
    "interrupted-failed-predecessor-failure-evidence",
    "interrupted-failed-predecessor-containment",
    "interrupted-failed-predecessor-global-claim",
    "interrupted-failed-predecessor-authorization-marker",
    "interrupted-failed-predecessor-nonce-marker",
    "interrupted-failed-predecessor-scope-state",
    "interrupted-failed-predecessor-preflight",
    "interrupted-failed-predecessor-pre-mutation-receipt",
    "interrupted-failed-predecessor-pre-mutation-adjudication",
    "interrupted-failed-predecessor-pre-live-receipt",
    "interrupted-failed-predecessor-pre-live-adjudication",
    "interrupted-failed-predecessor-allocation-ledger",
    "interrupted-failed-predecessor-allocation-audit",
    "interrupted-failed-predecessor-steering-registry",
    "interrupted-failed-predecessor-terminal-session",
    "interrupted-failed-predecessor-terminal-facts",
    "interrupted-failed-predecessor-generation11-runner-source",
    "interrupted-failed-predecessor-generation11-session-boundary-source",
    "interrupted-failed-predecessor-recovery-cause-analysis",
    "interrupted-failed-predecessor-recovery-steering-receipt",
    "interrupted-failed-predecessor-recovery-steering-session",
    "interrupted-failed-predecessor-outer-authority",
    "interrupted-failed-predecessor-independent-validation-receipt",
    "interrupted-failed-predecessor-independent-validation-session",
    "interrupted-failed-predecessor-recovery-cause-evidence",
    "interrupted-failed-predecessor-recovery-cause-source-analysis",
}
GENERATION12_REQUIRED_PROOF_PATHS = (
    GENERATION11_REQUIRED_PROOF_PATHS | GENERATION12_INTERRUPTED_PROOF_PATHS
)


def require_generation12_proof_path_set(
    paths: Mapping[str, Path],
    *,
    failed_predecessor_contained_sessions: int,
    predecessor_contained_sessions: int,
    ancestor_contained_sessions: int,
    grandancestor_contained_sessions: int,
) -> None:
    """Reject incomplete, mixed, or multi-session terminal Gen11 leaves."""

    terminal_session_labels = {
        label
        for label in paths
        if label.startswith("interrupted-failed-predecessor-terminal-session")
    }
    forbidden_immediate_sessions = {
        label
        for label in paths
        if label.startswith("interrupted-failed-predecessor-contained-session-")
    }
    if (
        not GENERATION12_REQUIRED_PROOF_PATHS.issubset(paths)
        or terminal_session_labels
        != {"interrupted-failed-predecessor-terminal-session"}
        or forbidden_immediate_sessions
    ):
        raise AppServerError("campaign-generation12-proof-path-set-invalid")
    require_generation11_proof_path_set(
        paths,
        failed_predecessor_contained_sessions=(
            failed_predecessor_contained_sessions
        ),
        predecessor_contained_sessions=predecessor_contained_sessions,
        ancestor_contained_sessions=ancestor_contained_sessions,
        grandancestor_contained_sessions=grandancestor_contained_sessions,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--authorization", type=Path, required=True)
    parser.add_argument("--campaign-manifest", type=Path, required=True)
    parser.add_argument("--outer-authority", type=Path, required=True)
    for suffix in (
        "authorization",
        "manifest",
        "authorization-state",
        "failure-evidence",
        "containment",
        "global-claim",
        "authorization-marker",
        "nonce-marker",
        "scope-state",
        "preflight",
        "pre-mutation-receipt",
        "pre-mutation-adjudication",
        "pre-live-receipt",
        "pre-live-adjudication",
        "allocation-ledger",
        "allocation-audit",
        "steering-registry",
        "terminal-session",
        "terminal-facts",
        "generation11-runner-source",
        "generation11-session-boundary-source",
        "recovery-cause-analysis",
        "recovery-steering-receipt",
        "recovery-steering-session",
        "outer-authority",
        "independent-validation-receipt",
        "independent-validation-session",
        "recovery-cause-evidence",
        "recovery-cause-source-analysis",
    ):
        parser.add_argument(
            f"--interrupted-failed-predecessor-{suffix}",
            type=Path,
            required=True,
        )
    parser.add_argument(
        "--preallocation-failed-predecessor-authorization",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--preallocation-failed-predecessor-manifest", type=Path, required=True
    )
    parser.add_argument(
        "--preallocation-failed-predecessor-authorization-state",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--preallocation-failed-predecessor-failure-evidence",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--preallocation-failed-predecessor-containment",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--preallocation-failed-predecessor-global-claim",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--preallocation-failed-predecessor-authorization-marker",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--preallocation-failed-predecessor-nonce-marker",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--preallocation-failed-predecessor-scope-state",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--preallocation-failed-predecessor-preflight", type=Path, required=True
    )
    parser.add_argument(
        "--preallocation-failed-predecessor-pre-mutation-receipt",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--preallocation-failed-predecessor-pre-live-receipt",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--preallocation-failed-predecessor-outer-authority",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--preallocation-failed-predecessor-independent-validation-receipt",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--preallocation-failed-predecessor-independent-validation-session",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--preallocation-failed-predecessor-recovery-cause-evidence",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--preallocation-failed-predecessor-recovery-cause-source-analysis",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--failed-predecessor-authorization", type=Path, required=True
    )
    parser.add_argument("--failed-predecessor-manifest", type=Path, required=True)
    parser.add_argument(
        "--failed-predecessor-authorization-state", type=Path, required=True
    )
    parser.add_argument(
        "--failed-predecessor-failure-evidence", type=Path, required=True
    )
    parser.add_argument(
        "--failed-predecessor-containment", type=Path, required=True
    )
    parser.add_argument(
        "--failed-predecessor-allocation-ledger", type=Path, required=True
    )
    parser.add_argument(
        "--failed-predecessor-allocation-audit", type=Path, required=True
    )
    parser.add_argument(
        "--failed-predecessor-outer-authority", type=Path, required=True
    )
    parser.add_argument(
        "--failed-predecessor-independent-validation-receipt",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--failed-predecessor-independent-validation-session",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--failed-predecessor-recovery-cause-evidence",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--failed-predecessor-recovery-cause-source-analysis",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--failed-predecessor-contained-session", type=Path, action="append"
    )
    parser.add_argument(
        "--quarantined-predecessor-authorization", type=Path, required=True
    )
    parser.add_argument(
        "--quarantined-predecessor-manifest", type=Path, required=True
    )
    parser.add_argument(
        "--quarantined-predecessor-authorization-state", type=Path, required=True
    )
    parser.add_argument(
        "--quarantined-predecessor-failure-evidence", type=Path, required=True
    )
    parser.add_argument(
        "--quarantined-predecessor-containment", type=Path, required=True
    )
    parser.add_argument(
        "--quarantined-predecessor-allocation-ledger", type=Path, required=True
    )
    parser.add_argument(
        "--quarantined-predecessor-allocation-audit", type=Path, required=True
    )
    parser.add_argument(
        "--quarantined-predecessor-outer-authority", type=Path, required=True
    )
    parser.add_argument(
        "--quarantined-predecessor-independent-validation-receipt",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--quarantined-predecessor-independent-validation-session",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--quarantined-predecessor-recovery-cause-evidence",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--quarantined-predecessor-recovery-cause-source-analysis",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--quarantined-predecessor-session", type=Path, required=True
    )
    parser.add_argument("--predecessor-authorization", type=Path, required=True)
    parser.add_argument("--predecessor-manifest", type=Path, required=True)
    parser.add_argument("--predecessor-authorization-state", type=Path, required=True)
    parser.add_argument("--predecessor-failure-evidence", type=Path, required=True)
    parser.add_argument("--predecessor-original-containment", type=Path)
    parser.add_argument("--predecessor-containment", type=Path, required=True)
    parser.add_argument("--predecessor-allocation-ledger", type=Path, required=True)
    parser.add_argument("--predecessor-allocation-audit", type=Path, required=True)
    parser.add_argument("--predecessor-outer-authority", type=Path)
    parser.add_argument("--predecessor-independent-validation-receipt", type=Path)
    parser.add_argument("--predecessor-independent-validation-session", type=Path)
    parser.add_argument("--predecessor-recovery-cause-evidence", type=Path)
    parser.add_argument("--predecessor-recovery-cause-source-analysis", type=Path)
    parser.add_argument("--predecessor-authorization-cause-evidence", type=Path)
    parser.add_argument(
        "--predecessor-contained-session", type=Path, action="append"
    )
    parser.add_argument("--ancestor-authorization", type=Path)
    parser.add_argument("--ancestor-manifest", type=Path)
    parser.add_argument("--ancestor-authorization-state", type=Path)
    parser.add_argument("--ancestor-failure-evidence", type=Path)
    parser.add_argument("--ancestor-original-containment", type=Path)
    parser.add_argument("--ancestor-containment", type=Path)
    parser.add_argument("--ancestor-allocation-ledger", type=Path)
    parser.add_argument("--ancestor-allocation-audit", type=Path)
    parser.add_argument("--ancestor-outer-authority", type=Path)
    parser.add_argument("--ancestor-independent-validation-receipt", type=Path)
    parser.add_argument("--ancestor-independent-validation-session", type=Path)
    parser.add_argument("--ancestor-authorization-cause-evidence", type=Path)
    parser.add_argument("--ancestor-contained-session", type=Path, action="append")
    parser.add_argument("--grandancestor-authorization-cause-evidence", type=Path)
    parser.add_argument("--grandancestor-authorization", type=Path)
    parser.add_argument("--grandancestor-manifest", type=Path)
    parser.add_argument("--grandancestor-authorization-state", type=Path)
    parser.add_argument("--grandancestor-failure-evidence", type=Path)
    parser.add_argument("--grandancestor-original-containment", type=Path)
    parser.add_argument("--grandancestor-containment", type=Path)
    parser.add_argument("--grandancestor-allocation-ledger", type=Path)
    parser.add_argument("--grandancestor-allocation-audit", type=Path)
    parser.add_argument(
        "--grandancestor-contained-session", type=Path, action="append"
    )
    parser.add_argument("--cause-evidence", type=Path, required=True)
    parser.add_argument("--cause-source-analysis", type=Path)
    parser.add_argument("--guarded-primary", type=Path, required=True)
    parser.add_argument("--release-patch", type=Path, required=True)
    parser.add_argument("--pre-mutation-steering-receipt", type=Path, required=True)
    parser.add_argument("--pre-mutation-adjudication", type=Path, required=True)
    parser.add_argument("--opus-review-evidence", type=Path, required=True)
    parser.add_argument("--opus-adjudication", type=Path, required=True)
    parser.add_argument("--spark-validation-receipt", type=Path, required=True)
    parser.add_argument("--spark-validation-session", type=Path, required=True)
    parser.add_argument("--pre-live-steering-receipt", type=Path, required=True)
    parser.add_argument("--pre-live-adjudication", type=Path, required=True)
    parser.add_argument("--campaign-nonce", required=True)
    parser.add_argument("--authorization-state", type=Path)
    parser.add_argument("--steering-registry", type=Path)
    args = parser.parse_args()
    output = Path(args.output).absolute()
    started_at = utc_now()
    server: AppServer | None = None
    authorization_store: CanaryAuthorizationStore | None = None
    authorization_state: dict[str, Any] | None = None
    steering_consumptions: dict[str, str] = {}
    allocation_ledger: NativeLiveAllocationLedgerStore | None = None
    artifact_bindings: dict[str, Any] = {}
    manifest: dict[str, Any] | None = None
    campaign_reservation: GlobalCampaignReservation | None = None
    campaign_committed = False
    try:
        if not _valid_uuid_text(args.campaign_nonce):
            raise AppServerError("campaign-nonce-invalid")
        path_arguments: dict[str, Path] = {
            "authorization": args.authorization,
            "campaign-manifest": args.campaign_manifest,
            "outer-authority": args.outer_authority,
            "interrupted-failed-predecessor-authorization": (
                args.interrupted_failed_predecessor_authorization
            ),
            "interrupted-failed-predecessor-manifest": (
                args.interrupted_failed_predecessor_manifest
            ),
            "interrupted-failed-predecessor-authorization-state": (
                args.interrupted_failed_predecessor_authorization_state
            ),
            "interrupted-failed-predecessor-failure-evidence": (
                args.interrupted_failed_predecessor_failure_evidence
            ),
            "interrupted-failed-predecessor-containment": (
                args.interrupted_failed_predecessor_containment
            ),
            "interrupted-failed-predecessor-global-claim": (
                args.interrupted_failed_predecessor_global_claim
            ),
            "interrupted-failed-predecessor-authorization-marker": (
                args.interrupted_failed_predecessor_authorization_marker
            ),
            "interrupted-failed-predecessor-nonce-marker": (
                args.interrupted_failed_predecessor_nonce_marker
            ),
            "interrupted-failed-predecessor-scope-state": (
                args.interrupted_failed_predecessor_scope_state
            ),
            "interrupted-failed-predecessor-preflight": (
                args.interrupted_failed_predecessor_preflight
            ),
            "interrupted-failed-predecessor-pre-mutation-receipt": (
                args.interrupted_failed_predecessor_pre_mutation_receipt
            ),
            "interrupted-failed-predecessor-pre-mutation-adjudication": (
                args.interrupted_failed_predecessor_pre_mutation_adjudication
            ),
            "interrupted-failed-predecessor-pre-live-receipt": (
                args.interrupted_failed_predecessor_pre_live_receipt
            ),
            "interrupted-failed-predecessor-pre-live-adjudication": (
                args.interrupted_failed_predecessor_pre_live_adjudication
            ),
            "interrupted-failed-predecessor-allocation-ledger": (
                args.interrupted_failed_predecessor_allocation_ledger
            ),
            "interrupted-failed-predecessor-allocation-audit": (
                args.interrupted_failed_predecessor_allocation_audit
            ),
            "interrupted-failed-predecessor-steering-registry": (
                args.interrupted_failed_predecessor_steering_registry
            ),
            "interrupted-failed-predecessor-terminal-session": (
                args.interrupted_failed_predecessor_terminal_session
            ),
            "interrupted-failed-predecessor-terminal-facts": (
                args.interrupted_failed_predecessor_terminal_facts
            ),
            "interrupted-failed-predecessor-generation11-runner-source": (
                args.interrupted_failed_predecessor_generation11_runner_source
            ),
            "interrupted-failed-predecessor-generation11-session-boundary-source": (
                args.interrupted_failed_predecessor_generation11_session_boundary_source
            ),
            "interrupted-failed-predecessor-recovery-cause-analysis": (
                args.interrupted_failed_predecessor_recovery_cause_analysis
            ),
            "interrupted-failed-predecessor-recovery-steering-receipt": (
                args.interrupted_failed_predecessor_recovery_steering_receipt
            ),
            "interrupted-failed-predecessor-recovery-steering-session": (
                args.interrupted_failed_predecessor_recovery_steering_session
            ),
            "interrupted-failed-predecessor-outer-authority": (
                args.interrupted_failed_predecessor_outer_authority
            ),
            "interrupted-failed-predecessor-independent-validation-receipt": (
                args.interrupted_failed_predecessor_independent_validation_receipt
            ),
            "interrupted-failed-predecessor-independent-validation-session": (
                args.interrupted_failed_predecessor_independent_validation_session
            ),
            "interrupted-failed-predecessor-recovery-cause-evidence": (
                args.interrupted_failed_predecessor_recovery_cause_evidence
            ),
            "interrupted-failed-predecessor-recovery-cause-source-analysis": (
                args.interrupted_failed_predecessor_recovery_cause_source_analysis
            ),
            "preallocation-failed-predecessor-authorization": (
                args.preallocation_failed_predecessor_authorization
            ),
            "preallocation-failed-predecessor-manifest": (
                args.preallocation_failed_predecessor_manifest
            ),
            "preallocation-failed-predecessor-authorization-state": (
                args.preallocation_failed_predecessor_authorization_state
            ),
            "preallocation-failed-predecessor-failure-evidence": (
                args.preallocation_failed_predecessor_failure_evidence
            ),
            "preallocation-failed-predecessor-containment": (
                args.preallocation_failed_predecessor_containment
            ),
            "preallocation-failed-predecessor-global-claim": (
                args.preallocation_failed_predecessor_global_claim
            ),
            "preallocation-failed-predecessor-authorization-marker": (
                args.preallocation_failed_predecessor_authorization_marker
            ),
            "preallocation-failed-predecessor-nonce-marker": (
                args.preallocation_failed_predecessor_nonce_marker
            ),
            "preallocation-failed-predecessor-scope-state": (
                args.preallocation_failed_predecessor_scope_state
            ),
            "preallocation-failed-predecessor-preflight": (
                args.preallocation_failed_predecessor_preflight
            ),
            "preallocation-failed-predecessor-pre-mutation-receipt": (
                args.preallocation_failed_predecessor_pre_mutation_receipt
            ),
            "preallocation-failed-predecessor-pre-live-receipt": (
                args.preallocation_failed_predecessor_pre_live_receipt
            ),
            "preallocation-failed-predecessor-outer-authority": (
                args.preallocation_failed_predecessor_outer_authority
            ),
            "preallocation-failed-predecessor-independent-validation-receipt": (
                args.preallocation_failed_predecessor_independent_validation_receipt
            ),
            "preallocation-failed-predecessor-independent-validation-session": (
                args.preallocation_failed_predecessor_independent_validation_session
            ),
            "preallocation-failed-predecessor-recovery-cause-evidence": (
                args.preallocation_failed_predecessor_recovery_cause_evidence
            ),
            "preallocation-failed-predecessor-recovery-cause-source-analysis": (
                args.preallocation_failed_predecessor_recovery_cause_source_analysis
            ),
            "failed-predecessor-authorization": (
                args.failed_predecessor_authorization
            ),
            "failed-predecessor-manifest": args.failed_predecessor_manifest,
            "failed-predecessor-authorization-state": (
                args.failed_predecessor_authorization_state
            ),
            "failed-predecessor-failure-evidence": (
                args.failed_predecessor_failure_evidence
            ),
            "failed-predecessor-containment": args.failed_predecessor_containment,
            "failed-predecessor-allocation-ledger": (
                args.failed_predecessor_allocation_ledger
            ),
            "failed-predecessor-allocation-audit": (
                args.failed_predecessor_allocation_audit
            ),
            "failed-predecessor-outer-authority": (
                args.failed_predecessor_outer_authority
            ),
            "failed-predecessor-independent-validation-receipt": (
                args.failed_predecessor_independent_validation_receipt
            ),
            "failed-predecessor-independent-validation-session": (
                args.failed_predecessor_independent_validation_session
            ),
            "failed-predecessor-recovery-cause-evidence": (
                args.failed_predecessor_recovery_cause_evidence
            ),
            "failed-predecessor-recovery-cause-source-analysis": (
                args.failed_predecessor_recovery_cause_source_analysis
            ),
            "quarantined-predecessor-authorization": (
                args.quarantined_predecessor_authorization
            ),
            "quarantined-predecessor-manifest": (
                args.quarantined_predecessor_manifest
            ),
            "quarantined-predecessor-authorization-state": (
                args.quarantined_predecessor_authorization_state
            ),
            "quarantined-predecessor-failure-evidence": (
                args.quarantined_predecessor_failure_evidence
            ),
            "quarantined-predecessor-containment": (
                args.quarantined_predecessor_containment
            ),
            "quarantined-predecessor-allocation-ledger": (
                args.quarantined_predecessor_allocation_ledger
            ),
            "quarantined-predecessor-allocation-audit": (
                args.quarantined_predecessor_allocation_audit
            ),
            "quarantined-predecessor-outer-authority": (
                args.quarantined_predecessor_outer_authority
            ),
            "quarantined-predecessor-independent-validation-receipt": (
                args.quarantined_predecessor_independent_validation_receipt
            ),
            "quarantined-predecessor-independent-validation-session": (
                args.quarantined_predecessor_independent_validation_session
            ),
            "quarantined-predecessor-recovery-cause-evidence": (
                args.quarantined_predecessor_recovery_cause_evidence
            ),
            "quarantined-predecessor-recovery-cause-source-analysis": (
                args.quarantined_predecessor_recovery_cause_source_analysis
            ),
            "quarantined-predecessor-session": (
                args.quarantined_predecessor_session
            ),
            "predecessor-authorization": args.predecessor_authorization,
            "predecessor-manifest": args.predecessor_manifest,
            "predecessor-authorization-state": args.predecessor_authorization_state,
            "predecessor-failure-evidence": args.predecessor_failure_evidence,
            "predecessor-containment": args.predecessor_containment,
            "predecessor-allocation-ledger": args.predecessor_allocation_ledger,
            "predecessor-allocation-audit": args.predecessor_allocation_audit,
            "cause-evidence": args.cause_evidence,
            "release-patch": args.release_patch,
            "pre-mutation-steering-receipt": args.pre_mutation_steering_receipt,
            "pre-mutation-adjudication": args.pre_mutation_adjudication,
            "opus-review-evidence": args.opus_review_evidence,
            "opus-adjudication": args.opus_adjudication,
            "spark-validation-receipt": args.spark_validation_receipt,
            "spark-validation-session": args.spark_validation_session,
            "pre-live-steering-receipt": args.pre_live_steering_receipt,
            "pre-live-adjudication": args.pre_live_adjudication,
        }
        optional_arguments = {
            "predecessor-original-containment": args.predecessor_original_containment,
            "predecessor-outer-authority": args.predecessor_outer_authority,
            "predecessor-independent-validation-receipt": (
                args.predecessor_independent_validation_receipt
            ),
            "predecessor-independent-validation-session": (
                args.predecessor_independent_validation_session
            ),
            "predecessor-recovery-cause-evidence": (
                args.predecessor_recovery_cause_evidence
            ),
            "predecessor-recovery-cause-source-analysis": (
                args.predecessor_recovery_cause_source_analysis
            ),
            "predecessor-authorization-cause-evidence": (
                args.predecessor_authorization_cause_evidence
            ),
            "ancestor-authorization": args.ancestor_authorization,
            "ancestor-manifest": args.ancestor_manifest,
            "ancestor-authorization-state": args.ancestor_authorization_state,
            "ancestor-failure-evidence": args.ancestor_failure_evidence,
            "ancestor-original-containment": args.ancestor_original_containment,
            "ancestor-containment": args.ancestor_containment,
            "ancestor-allocation-ledger": args.ancestor_allocation_ledger,
            "ancestor-allocation-audit": args.ancestor_allocation_audit,
            "ancestor-outer-authority": args.ancestor_outer_authority,
            "ancestor-independent-validation-receipt": (
                args.ancestor_independent_validation_receipt
            ),
            "ancestor-independent-validation-session": (
                args.ancestor_independent_validation_session
            ),
            "ancestor-authorization-cause-evidence": (
                args.ancestor_authorization_cause_evidence
            ),
            "grandancestor-authorization-cause-evidence": (
                args.grandancestor_authorization_cause_evidence
            ),
            "grandancestor-authorization": args.grandancestor_authorization,
            "grandancestor-manifest": args.grandancestor_manifest,
            "grandancestor-authorization-state": (
                args.grandancestor_authorization_state
            ),
            "grandancestor-failure-evidence": (
                args.grandancestor_failure_evidence
            ),
            "grandancestor-original-containment": (
                args.grandancestor_original_containment
            ),
            "grandancestor-containment": args.grandancestor_containment,
            "grandancestor-allocation-ledger": (
                args.grandancestor_allocation_ledger
            ),
            "grandancestor-allocation-audit": (
                args.grandancestor_allocation_audit
            ),
            "cause-source-analysis": args.cause_source_analysis,
        }
        path_arguments.update(
            {
                label: path
                for label, path in optional_arguments.items()
                if path is not None
            }
        )
        path_arguments.update(
            {
                f"failed-predecessor-contained-session-{index}": path
                for index, path in enumerate(
                    args.failed_predecessor_contained_session or []
                )
            }
        )
        path_arguments.update(
            {
                f"predecessor-contained-session-{index}": path
                for index, path in enumerate(
                    args.predecessor_contained_session or []
                )
            }
        )
        path_arguments.update(
            {
                f"ancestor-contained-session-{index}": path
                for index, path in enumerate(args.ancestor_contained_session or [])
            }
        )
        path_arguments.update(
            {
                f"grandancestor-contained-session-{index}": path
                for index, path in enumerate(
                    args.grandancestor_contained_session or []
                )
            }
        )
        paths = require_unique_input_paths(path_arguments)
        source_identities = capture_input_source_identities(paths)
        for label, path in paths.items():
            if campaign_input_requires_private_parent(label):
                require_private_parent(path, label)

        def private_bytes_snapshot(label: str) -> bytes:
            return load_private_bytes(
                paths[label],
                label,
                expected_identity=source_identities[label],
            )

        def trusted_session_snapshot(label: str) -> bytes:
            return load_trusted_session_bytes(
                paths[label],
                label,
                expected_identity=source_identities[label],
            )

        def private_json_snapshot(label: str) -> JsonArtifactSnapshot:
            return load_private_json_snapshot(
                paths[label],
                label,
                expected_identity=source_identities[label],
            )

        authorization_snapshot = private_json_snapshot("authorization")
        manifest_snapshot = private_json_snapshot("campaign-manifest")
        authorization = dict(authorization_snapshot.value)
        manifest = dict(manifest_snapshot.value)
        version = authorization.get("version")
        require_operative_campaign_contract(
            version, manifest.get("version"), 6, 6
        )
        require_generation12_proof_path_set(
            paths,
            failed_predecessor_contained_sessions=len(
                args.failed_predecessor_contained_session or []
            ),
            predecessor_contained_sessions=len(
                args.predecessor_contained_session or []
            ),
            ancestor_contained_sessions=len(args.ancestor_contained_session or []),
            grandancestor_contained_sessions=len(
                args.grandancestor_contained_session or []
            ),
        )

        predecessor_common = {
            label: private_json_snapshot(label)
            for label in (
                "predecessor-authorization",
                "predecessor-manifest",
                "predecessor-authorization-state",
                "predecessor-failure-evidence",
                "predecessor-containment",
                "predecessor-allocation-ledger",
            )
        }
        ancestor_authorization_cause = private_bytes_snapshot(
            "ancestor-authorization-cause-evidence"
        )
        grandancestor_authorization_cause = private_bytes_snapshot(
            "grandancestor-authorization-cause-evidence"
        )
        grandancestor = HistoricalV4V1ProofInputs(
            authorization=private_json_snapshot("grandancestor-authorization"),
            manifest=private_json_snapshot("grandancestor-manifest"),
            authorization_state=private_json_snapshot(
                "grandancestor-authorization-state"
            ),
            failure_evidence=private_json_snapshot(
                "grandancestor-failure-evidence"
            ),
            original_containment=private_json_snapshot(
                "grandancestor-original-containment"
            ),
            containment=private_json_snapshot("grandancestor-containment"),
            allocation_ledger=private_json_snapshot(
                "grandancestor-allocation-ledger"
            ),
            allocation_audit_bytes=private_bytes_snapshot(
                "grandancestor-allocation-audit"
            ),
            cause_evidence=grandancestor_authorization_cause,
            contained_session_bytes=tuple(
                trusted_session_snapshot(
                    f"grandancestor-contained-session-{index}"
                )
                for index in range(
                    len(args.grandancestor_contained_session or [])
                )
            ),
        )
        ancestor = Version5PredecessorProofInputs(
            authorization=private_json_snapshot("ancestor-authorization"),
            manifest=private_json_snapshot("ancestor-manifest"),
            authorization_state=private_json_snapshot(
                "ancestor-authorization-state"
            ),
            failure_evidence=private_json_snapshot("ancestor-failure-evidence"),
            containment=private_json_snapshot("ancestor-containment"),
            allocation_ledger=private_json_snapshot(
                "ancestor-allocation-ledger"
            ),
            allocation_audit_bytes=private_bytes_snapshot(
                "ancestor-allocation-audit"
            ),
            authorization_cause_evidence=ancestor_authorization_cause,
            outer_authority=private_json_snapshot("ancestor-outer-authority"),
            independent_validation_receipt=private_json_snapshot(
                "ancestor-independent-validation-receipt"
            ),
            independent_validation_session_bytes=trusted_session_snapshot(
                "ancestor-independent-validation-session"
            ),
            ancestor=grandancestor,
            contained_session_bytes=tuple(
                trusted_session_snapshot(f"ancestor-contained-session-{index}")
                for index in range(len(args.ancestor_contained_session or []))
            ),
        )
        generation7_proof = Version6PredecessorProofInputs(
            authorization=predecessor_common["predecessor-authorization"],
            manifest=predecessor_common["predecessor-manifest"],
            authorization_state=predecessor_common[
                "predecessor-authorization-state"
            ],
            failure_evidence=predecessor_common["predecessor-failure-evidence"],
            containment=predecessor_common["predecessor-containment"],
            allocation_ledger=predecessor_common[
                "predecessor-allocation-ledger"
            ],
            allocation_audit_bytes=private_bytes_snapshot(
                "predecessor-allocation-audit"
            ),
            authorization_recovery_cause_evidence=private_json_snapshot(
                "predecessor-recovery-cause-evidence"
            ),
            authorization_recovery_cause_source_analysis=private_bytes_snapshot(
                "predecessor-recovery-cause-source-analysis"
            ),
            outer_authority=private_json_snapshot("predecessor-outer-authority"),
            independent_validation_receipt=private_json_snapshot(
                "predecessor-independent-validation-receipt"
            ),
            independent_validation_session_bytes=trusted_session_snapshot(
                "predecessor-independent-validation-session"
            ),
            ancestor=ancestor,
            contained_session_bytes=tuple(
                trusted_session_snapshot(
                    f"predecessor-contained-session-{index}"
                )
                for index in range(
                    len(args.predecessor_contained_session or [])
                )
            ),
        )
        generation9_proof = Version7QuarantinePredecessorProofInputs(
            authorization=private_json_snapshot(
                "quarantined-predecessor-authorization"
            ),
            manifest=private_json_snapshot(
                "quarantined-predecessor-manifest"
            ),
            authorization_state=private_json_snapshot(
                "quarantined-predecessor-authorization-state"
            ),
            failure_evidence=private_json_snapshot(
                "quarantined-predecessor-failure-evidence"
            ),
            containment=private_json_snapshot(
                "quarantined-predecessor-containment"
            ),
            allocation_ledger=private_json_snapshot(
                "quarantined-predecessor-allocation-ledger"
            ),
            allocation_audit_bytes=private_bytes_snapshot(
                "quarantined-predecessor-allocation-audit"
            ),
            authorization_recovery_cause_evidence=private_json_snapshot(
                "quarantined-predecessor-recovery-cause-evidence"
            ),
            authorization_recovery_cause_source_analysis=private_bytes_snapshot(
                "quarantined-predecessor-recovery-cause-source-analysis"
            ),
            outer_authority=private_json_snapshot(
                "quarantined-predecessor-outer-authority"
            ),
            independent_validation_receipt=private_json_snapshot(
                "quarantined-predecessor-independent-validation-receipt"
            ),
            independent_validation_session_bytes=trusted_session_snapshot(
                "quarantined-predecessor-independent-validation-session"
            ),
            ancestor=generation7_proof,
            quarantined_session_bytes=trusted_session_snapshot(
                "quarantined-predecessor-session"
            ),
        )
        predecessor_proof = Version8ProtectedFaultPredecessorProofInputs(
            authorization=private_json_snapshot(
                "failed-predecessor-authorization"
            ),
            manifest=private_json_snapshot("failed-predecessor-manifest"),
            authorization_state=private_json_snapshot(
                "failed-predecessor-authorization-state"
            ),
            failure_evidence=private_json_snapshot(
                "failed-predecessor-failure-evidence"
            ),
            containment=private_json_snapshot("failed-predecessor-containment"),
            allocation_ledger=private_json_snapshot(
                "failed-predecessor-allocation-ledger"
            ),
            allocation_audit_bytes=private_bytes_snapshot(
                "failed-predecessor-allocation-audit"
            ),
            authorization_recovery_cause_evidence=private_json_snapshot(
                "failed-predecessor-recovery-cause-evidence"
            ),
            authorization_recovery_cause_source_analysis=private_bytes_snapshot(
                "failed-predecessor-recovery-cause-source-analysis"
            ),
            outer_authority=private_json_snapshot(
                "failed-predecessor-outer-authority"
            ),
            independent_validation_receipt=private_json_snapshot(
                "failed-predecessor-independent-validation-receipt"
            ),
            independent_validation_session_bytes=trusted_session_snapshot(
                "failed-predecessor-independent-validation-session"
            ),
            ancestor=generation9_proof,
            contained_session_bytes=tuple(
                trusted_session_snapshot(
                    f"failed-predecessor-contained-session-{index}"
                )
                for index in range(
                    len(args.failed_predecessor_contained_session or [])
                )
            ),
        )
        preallocation_proof = Version9PreallocationFaultPredecessorProofInputs(
            authorization=private_json_snapshot(
                "preallocation-failed-predecessor-authorization"
            ),
            manifest=private_json_snapshot(
                "preallocation-failed-predecessor-manifest"
            ),
            authorization_state=private_json_snapshot(
                "preallocation-failed-predecessor-authorization-state"
            ),
            failure_evidence=private_json_snapshot(
                "preallocation-failed-predecessor-failure-evidence"
            ),
            containment=private_json_snapshot(
                "preallocation-failed-predecessor-containment"
            ),
            global_claim=private_json_snapshot(
                "preallocation-failed-predecessor-global-claim"
            ),
            authorization_marker=private_json_snapshot(
                "preallocation-failed-predecessor-authorization-marker"
            ),
            nonce_marker=private_json_snapshot(
                "preallocation-failed-predecessor-nonce-marker"
            ),
            scope_state=private_json_snapshot(
                "preallocation-failed-predecessor-scope-state"
            ),
            preflight=private_json_snapshot(
                "preallocation-failed-predecessor-preflight"
            ),
            pre_mutation_receipt=private_json_snapshot(
                "preallocation-failed-predecessor-pre-mutation-receipt"
            ),
            pre_live_receipt=private_json_snapshot(
                "preallocation-failed-predecessor-pre-live-receipt"
            ),
            authorization_recovery_cause_evidence=private_json_snapshot(
                "preallocation-failed-predecessor-recovery-cause-evidence"
            ),
            authorization_recovery_cause_source_analysis=private_bytes_snapshot(
                "preallocation-failed-predecessor-recovery-cause-source-analysis"
            ),
            outer_authority=private_json_snapshot(
                "preallocation-failed-predecessor-outer-authority"
            ),
            independent_validation_receipt=private_json_snapshot(
                "preallocation-failed-predecessor-independent-validation-receipt"
            ),
            independent_validation_session_bytes=trusted_session_snapshot(
                "preallocation-failed-predecessor-independent-validation-session"
            ),
            ancestor=predecessor_proof,
        )
        interrupted_proof = Version10InterruptedEmptyBoundaryPredecessorProofInputs(
            authorization=private_json_snapshot(
                "interrupted-failed-predecessor-authorization"
            ),
            manifest=private_json_snapshot(
                "interrupted-failed-predecessor-manifest"
            ),
            authorization_state=private_json_snapshot(
                "interrupted-failed-predecessor-authorization-state"
            ),
            failure_evidence=private_json_snapshot(
                "interrupted-failed-predecessor-failure-evidence"
            ),
            global_claim=private_json_snapshot(
                "interrupted-failed-predecessor-global-claim"
            ),
            authorization_marker=private_json_snapshot(
                "interrupted-failed-predecessor-authorization-marker"
            ),
            nonce_marker=private_json_snapshot(
                "interrupted-failed-predecessor-nonce-marker"
            ),
            scope_state=private_json_snapshot(
                "interrupted-failed-predecessor-scope-state"
            ),
            preflight=private_json_snapshot(
                "interrupted-failed-predecessor-preflight"
            ),
            pre_mutation_receipt=private_json_snapshot(
                "interrupted-failed-predecessor-pre-mutation-receipt"
            ),
            pre_mutation_adjudication=private_json_snapshot(
                "interrupted-failed-predecessor-pre-mutation-adjudication"
            ),
            pre_live_receipt=private_json_snapshot(
                "interrupted-failed-predecessor-pre-live-receipt"
            ),
            pre_live_adjudication=private_json_snapshot(
                "interrupted-failed-predecessor-pre-live-adjudication"
            ),
            allocation_ledger=private_json_snapshot(
                "interrupted-failed-predecessor-allocation-ledger"
            ),
            allocation_audit_bytes=private_bytes_snapshot(
                "interrupted-failed-predecessor-allocation-audit"
            ),
            steering_registry=private_json_snapshot(
                "interrupted-failed-predecessor-steering-registry"
            ),
            terminal_session_bytes=trusted_session_snapshot(
                "interrupted-failed-predecessor-terminal-session"
            ),
            containment=private_json_snapshot(
                "interrupted-failed-predecessor-containment"
            ),
            terminal_facts=private_json_snapshot(
                "interrupted-failed-predecessor-terminal-facts"
            ),
            generation11_runner_source_bytes=private_bytes_snapshot(
                "interrupted-failed-predecessor-generation11-runner-source"
            ),
            generation11_session_boundary_source_bytes=private_bytes_snapshot(
                "interrupted-failed-predecessor-generation11-session-boundary-source"
            ),
            recovery_cause_analysis_bytes=private_bytes_snapshot(
                "interrupted-failed-predecessor-recovery-cause-analysis"
            ),
            recovery_steering_receipt=private_json_snapshot(
                "interrupted-failed-predecessor-recovery-steering-receipt"
            ),
            recovery_steering_session_bytes=trusted_session_snapshot(
                "interrupted-failed-predecessor-recovery-steering-session"
            ),
            authorization_recovery_cause_evidence=private_json_snapshot(
                "interrupted-failed-predecessor-recovery-cause-evidence"
            ),
            authorization_recovery_cause_source_analysis=private_bytes_snapshot(
                "interrupted-failed-predecessor-recovery-cause-source-analysis"
            ),
            outer_authority=private_json_snapshot(
                "interrupted-failed-predecessor-outer-authority"
            ),
            independent_validation_receipt=private_json_snapshot(
                "interrupted-failed-predecessor-independent-validation-receipt"
            ),
            independent_validation_session_bytes=trusted_session_snapshot(
                "interrupted-failed-predecessor-independent-validation-session"
            ),
            ancestor=preallocation_proof,
        )
        recovery_cause_evidence = private_json_snapshot("cause-evidence")
        recovery_cause_source_analysis_bytes = private_bytes_snapshot(
            "cause-source-analysis"
        )

        launch_inputs = CampaignLaunchInputs(
            authorization=authorization_snapshot,
            manifest=manifest_snapshot,
            outer_authority=private_json_snapshot("outer-authority"),
            release_patch_bytes=private_bytes_snapshot("release-patch"),
            pre_mutation_receipt=private_json_snapshot(
                "pre-mutation-steering-receipt"
            ),
            pre_mutation_adjudication=private_json_snapshot(
                "pre-mutation-adjudication"
            ),
            pre_live_receipt=private_json_snapshot(
                "pre-live-steering-receipt"
            ),
            pre_live_adjudication=private_json_snapshot(
                "pre-live-adjudication"
            ),
            opus_review_evidence=private_json_snapshot("opus-review-evidence"),
            opus_adjudication=private_json_snapshot("opus-adjudication"),
            spark_validation_receipt=private_json_snapshot(
                "spark-validation-receipt"
            ),
            spark_validation_session_path=paths["spark-validation-session"],
            spark_validation_session_bytes=trusted_session_snapshot(
                "spark-validation-session"
            ),
            predecessor_proof=interrupted_proof,
            recovery_cause_evidence=recovery_cause_evidence,
            recovery_cause_source_analysis_bytes=(
                recovery_cause_source_analysis_bytes
            ),
            source_identities=source_identities,
        )
        authorization_sha256 = launch_inputs.authorization.raw_sha256
        authorization_id, repo_head = validate_full_auto_authorization(
            authorization,
            args.campaign_nonce,
            predecessor_proof=interrupted_proof,
            recovery_cause_evidence=recovery_cause_evidence,
            recovery_cause_source_analysis=recovery_cause_source_analysis_bytes,
            expected_validator_contract_sha256=validator_contract_sha256_v6(
                ROOT, authorization.get("bindings", {}).get("checkpoint_tree")
            ),
            repo_root=ROOT,
        )

        pre_mutation_receipt = dict(launch_inputs.pre_mutation_receipt.value)
        pre_live_receipt = dict(launch_inputs.pre_live_receipt.value)
        spark_validation_receipt = dict(
            launch_inputs.spark_validation_receipt.value
        )
        state_path, registry_path, ledger_path = campaign_output_paths(
            output,
            manifest,
            authorization_state=args.authorization_state,
            steering_registry=args.steering_registry,
        )
        if any(path.exists() or path.is_symlink() for path in (output, state_path, registry_path, ledger_path)):
            raise AppServerError("campaign-output-already-exists")
        for label, path in (
            ("campaign-output", output),
            ("authorization-state", state_path),
            ("steering-registry", registry_path),
            ("allocation-ledger", ledger_path),
        ):
            require_private_parent(path, label)
            if path in set(paths.values()):
                raise AppServerError("campaign-output-input-path-collision")
        (
            artifact_bindings,
            launch_claim_sha256,
            expected_bound_manifest_validation,
            prepared,
            campaign_reservation,
        ) = validate_and_acquire_global_campaign_claim(
            launch_inputs,
            campaign_nonce=args.campaign_nonce,
            authorization_id=authorization_id,
            authorization_sha256=authorization_sha256,
            repo_head=repo_head,
            guarded_primary=args.guarded_primary.absolute(),
            output=output,
            authorization_state=state_path,
            steering_registry=registry_path,
            allocation_ledger=ledger_path,
        )
        campaign_committed = True
        authorization_store = CanaryAuthorizationStore(state_path)
        authorization_state = authorization_store.initialize(
            new_authorization_state(
                authorization_id=authorization_id,
                run_nonce=args.campaign_nonce,
                now=iso(),
                launch_claim_sha256=launch_claim_sha256,
            )
        )
        require_repository_checkpoint(ROOT, repo_head)
        for label in ("pre-mutation", "pre-live"):
            _, params = prepared[label]
            if label == "pre-mutation":
                receipt = pre_mutation_receipt
            else:
                receipt = pre_live_receipt
            steering_consumptions[label] = consume_steering_receipt(receipt, registry_path, **params)
        require_repository_checkpoint(ROOT, repo_head)
        active_state = authorization_store.require_action("tracked-mutation")
        if (
            launch_claim_sha256 is not None
            and active_state.get("launch_claim_sha256") != launch_claim_sha256
        ):
            raise AppServerError("campaign-launch-claim-state-mismatch")

        def require_allocation_watermark_unchanged() -> None:
            """Perform the final complete recheck adjacent to an allocation RPC."""

            candidate = manifest.get("candidate")
            if not isinstance(candidate, Mapping):
                raise AppServerError("campaign-candidate-watermark-invalid")
            require_repository_checkpoint(ROOT, str(candidate.get("commit")))
            if (
                run_git(ROOT, "rev-parse", "HEAD^{tree}")
                != candidate.get("tree")
                or run_git(ROOT, "rev-parse", "origin/main")
                != candidate.get("origin_main_commit")
                or guarded_diff_sha256(args.guarded_primary.absolute())
                != artifact_bindings["guarded_primary_diff_sha256"]
                or validator_contract_sha256_v6(ROOT, str(candidate.get("tree")))
                != artifact_bindings["validator_contract_sha256"]
            ):
                raise AppServerError("campaign-allocation-watermark-changed")
            # This content-and-identity pass is deliberately last.  The caller
            # invokes it again after receipt validation and immediately before
            # `thread/start`, closing the validation-time rewrite window.
            require_launch_source_snapshots_unchanged(paths, launch_inputs)

        def require_bound_campaign_inputs_before_thread_start() -> dict[str, Any] | None:
            require_launch_source_snapshots_unchanged(paths, launch_inputs)
            refreshed_bindings = validate_campaign_launch_bindings(
                inputs=launch_inputs,
                guarded_primary=args.guarded_primary.absolute(),
            )
            if launch_claim_sha256 is not None:
                refreshed_bindings["launch_claim_sha256"] = (
                    campaign_launch_claim_sha256(
                        launch_inputs,
                        output=output,
                        authorization_state=state_path,
                        steering_registry=registry_path,
                        allocation_ledger=ledger_path,
                    )
                )
            if refreshed_bindings != artifact_bindings:
                raise AppServerError(
                    "campaign-artifact-binding-changed-before-thread-start"
                )
            refreshed_receipt = seal_bound_manifest_validation(
                manifest, refreshed_bindings
            )
            if refreshed_receipt != expected_bound_manifest_validation:
                raise AppServerError(
                    "campaign-bound-validation-changed-before-thread-start"
                )
            require_allocation_watermark_unchanged()
            return refreshed_receipt

        with tempfile.TemporaryDirectory(prefix="cwo-18w6-live-") as temporary:
            temp_root = Path(temporary)
            temp_root.chmod(0o700)
            layout = make_git_layout(temp_root)
            record_dir = temp_root / "capability-records"
            record_dir.mkdir(mode=0o700)
            server = AppServer()
            if (
                server.codex_home.resolve()
                != launch_inputs.spark_validation_session_path.parents[1].resolve()
                or validate_independent_validation_session_snapshot(
                    spark_validation_receipt,
                    launch_inputs.spark_validation_session_path,
                    launch_inputs.spark_validation_session_bytes,
                    codex_home=server.codex_home,
                )
                != artifact_bindings["spark_validation_session_file_sha256"]
            ):
                raise AppServerError(
                    "spark-validation-session-changed-before-allocation"
                )
            discovery = server.model_discovery()
            owner = capture_owner_identity(os.getpid())
            authorization_bindings = authorization.get("bindings")
            if not isinstance(authorization_bindings, Mapping):
                raise AppServerError("allocation-ledger-authorization-bindings-invalid")
            if (
                run_git(ROOT, "rev-parse", "HEAD") != manifest["candidate"]["commit"]
                or run_git(ROOT, "rev-parse", "HEAD^{tree}")
                != manifest["candidate"]["tree"]
                or guarded_diff_sha256(args.guarded_primary.absolute())
                != artifact_bindings["guarded_primary_diff_sha256"]
                or validator_contract_sha256_v6(
                    ROOT, manifest["candidate"]["tree"]
                )
                != artifact_bindings["validator_contract_sha256"]
            ):
                raise AppServerError("campaign-watermark-changed-before-allocation")
            require_repository_checkpoint(ROOT, manifest["candidate"]["commit"])
            certification_policy = callback_certification_policy()
            work_units = manifest["work_units"]
            allocation_ledger = NativeLiveAllocationLedgerStore(ledger_path)
            allocation_ledger.initialize(
                {
                    "bead_id": work_units["epic_id"],
                    "work_unit_id": work_units["live_work_unit_id"],
                    "authorization_id": authorization_id,
                    "authorization_raw_sha256": authorization_sha256,
                    "authorization_canonical_sha256": authorization[
                        "canonical_authorization_sha256"
                    ],
                    "campaign_manifest_sha256": manifest["manifest_sha256"],
                    "campaign_nonce": args.campaign_nonce,
                    "live_generation": manifest["live_generation"],
                    "predecessor_generation": manifest["predecessor_live_generation"],
                    "candidate_commit": manifest["candidate"]["commit"],
                    "candidate_tree": manifest["candidate"]["tree"],
                    "origin_main_commit": manifest["candidate"]["origin_main_commit"],
                    "guarded_primary_diff_sha256": authorization_bindings[
                        "guarded_primary_diff_sha256"
                    ],
                    "predecessor_containment_sha256": authorization_bindings[
                        "predecessor_containment_canonical_sha256"
                    ],
                    "frozen_release_patch_sha256": artifact_bindings[
                        "release_patch_sha256"
                    ],
                    "pre_mutation_steering_receipt_sha256": pre_mutation_receipt[
                        "canonical_receipt_sha256"
                    ],
                    "pre_live_steering_receipt_sha256": pre_live_receipt[
                        "canonical_receipt_sha256"
                    ],
                    "opus_review_sha256": artifact_bindings[
                        "opus_evidence_file_sha256"
                    ],
                    "certification_policy_sha256": callback_certification_policy_sha256(
                        certification_policy
                    ),
                    "controller_identity": owner,
                    "connection_epoch_sha256": server.connection_epoch_sha256,
                    "retention_class": "private-local-until-bead-closure",
                    "expected_roles": list(EXPECTED_ROLES),
                },
                version=2,
            )
            server.attach_allocation_ledger(allocation_ledger)
            require_launch_source_snapshots_unchanged(paths, launch_inputs)
            if campaign_reservation is None:
                raise AppServerError("scope-campaign-reservation-missing")
            transition_global_campaign_state(
                campaign_reservation,
                "active",
                outer_authority=launch_inputs.outer_authority,
                candidate_commit=manifest["candidate"]["commit"],
                candidate_tree=manifest["candidate"]["tree"],
            )
            require_bound_campaign_inputs_before_thread_start()
            capability, calibration_evidence = calibration(
                server,
                layout["read-shared"],
                record_dir,
                owner,
                run_nonce=authorization_id,
                phase_nonce=args.campaign_nonce,
                pre_allocation_check=require_allocation_watermark_unchanged,
            )
            allocation_ledger.bind_certification(capability["receipt_sha256"])

            read_prompts = [
                (
                    f"Use exec_command to run `sleep 2`, then use exec_command to run "
                    f"`sha256sum data/shared.txt`. Do not mutate any file. Return exactly "
                    f"READ_ONLY_CHILD_{index}_OK."
                )
                for index in range(2)
            ]
            read_canary = run_pool_canary(
                server,
                capability,
                manifest,
                root=temp_root,
                integration=layout["integration"],
                pool_name="read-only",
                worktrees=[layout["read-shared"], layout["read-shared"]],
                mutable=False,
                prompts=read_prompts,
                expected_tokens=["READ_ONLY_CHILD_0_OK", "READ_ONLY_CHILD_1_OK"],
                pre_thread_start_check=(
                    require_bound_campaign_inputs_before_thread_start
                ),
                pre_allocation_check=require_allocation_watermark_unchanged,
                expected_bound_manifest_validation=(
                    expected_bound_manifest_validation
                ),
            )

            mutable_prompts = [
                (
                    f"Use apply_patch to append the exact line `spark-canary-{index}` to "
                    f"targets/child_{index}.txt and do not modify any other file. Then use "
                    f"exec_command to run `sleep 2`. Return exactly MUTABLE_CHILD_{index}_OK."
                )
                for index in range(2)
            ]
            mutable_canary = run_pool_canary(
                server,
                capability,
                manifest,
                root=temp_root,
                integration=layout["integration"],
                pool_name="mutable",
                worktrees=[layout["mutable-0"], layout["mutable-1"]],
                mutable=True,
                prompts=mutable_prompts,
                expected_tokens=["MUTABLE_CHILD_0_OK", "MUTABLE_CHILD_1_OK"],
                pre_thread_start_check=(
                    require_bound_campaign_inputs_before_thread_start
                ),
                pre_allocation_check=require_allocation_watermark_unchanged,
                expected_bound_manifest_validation=(
                    expected_bound_manifest_validation
                ),
            )

            interrupt_prompts = [
                (
                    "Use exec_command to run `sleep 20`. After it finishes, return exactly "
                    "INTERRUPT_LONG_UNEXPECTED_COMPLETION. Do not use any other tool."
                ),
                (
                    "Use exec_command to run `sleep 3`. After it finishes, return exactly "
                    "INTERRUPT_PEER_OK. Do not use any other tool."
                ),
            ]
            interrupt_canary = run_pool_canary(
                server,
                capability,
                manifest,
                root=temp_root,
                integration=layout["integration"],
                pool_name="interrupt",
                worktrees=[layout["interrupt-shared"], layout["interrupt-shared"]],
                mutable=False,
                prompts=interrupt_prompts,
                expected_tokens=["INTERRUPT_LONG_UNEXPECTED_COMPLETION", "INTERRUPT_PEER_OK"],
                pre_thread_start_check=(
                    require_bound_campaign_inputs_before_thread_start
                ),
                pre_allocation_check=require_allocation_watermark_unchanged,
                expected_bound_manifest_validation=(
                    expected_bound_manifest_validation
                ),
                interrupt_after=[2, None],
            )
            canaries = [read_canary, mutable_canary, interrupt_canary]
            campaign_errors = validate_campaign(capability, calibration_evidence, canaries)
            if campaign_errors:
                raise AppServerError("campaign-validation-failed:" + ";".join(campaign_errors))
            authorization_state = authorization_store.transition(
                "complete", reason="seven-turn-campaign-accepted", now=iso()
            )
            value = seal_artifact(
                {
                    "result_type": "cwo-native-supervision-pool-live-canary-evidence",
                    "version": 1,
                    "bead_id": manifest["work_units"]["epic_id"],
                    "work_unit_id": manifest["work_units"]["live_work_unit_id"],
                    "control_turn_id": manifest["control_turn_id"],
                    "exact_model": EXACT_MODEL,
                    "attestation_source": "trusted-control-plane-session-metadata",
                    "execution_surface": "connected-codex",
                    "app_server_transport": "stdio",
                    "model_discovery": discovery,
                    "started_at": iso(started_at),
                    "completed_at": iso(),
                    "capability_receipt": capability,
                    "capability_calibration": calibration_evidence,
                    "materialization_evidence_sha256": calibration_evidence[
                        "materialization_evidence_sha256"
                    ],
                    "authorization_sha256": authorization_sha256,
                    "authorization_id": authorization_id,
                    "authorization_canonical_sha256": authorization[
                        "canonical_authorization_sha256"
                    ],
                    "campaign_manifest_sha256": manifest["manifest_sha256"],
                    "campaign_bindings": artifact_bindings,
                    "run_generation": manifest["run_generation"],
                    "live_generation": manifest["live_generation"],
                    "predecessor_live_generation": manifest[
                        "predecessor_live_generation"
                    ],
                    "authorization_state_sha256": authorization_state["state_sha256"],
                    "steering_consumptions": steering_consumptions,
                    "allocation_ledger": allocation_ledger.summary(),
                    "canaries": canaries,
                    "fresh_session_count": 7,
                    "no_resume_or_salvage": True,
                    "campaign_errors": campaign_errors,
                    "validation_outcome": "accepted",
                    "release_gate_passed": True,
                    "temporary_workspace_disposition": "deleted-after-evidence-capture",
                    "glm_5_2_used": False,
                    "model_synthesis_used": False,
                },
                "evidence_sha256",
            )
            write_private_artifact(output, value)
            if campaign_reservation is not None:
                transition_global_campaign_state(
                    campaign_reservation,
                    "terminal",
                    terminal_evidence_sha256=value["evidence_sha256"],
                )
                campaign_reservation = None
            print(
                json.dumps(
                    {
                        "release_gate_passed": value["release_gate_passed"],
                        "evidence_sha256": value["evidence_sha256"],
                        "fresh_session_count": value["fresh_session_count"],
                        "campaign_errors": value["campaign_errors"],
                        "observed_check_max_ms": capability["callbacks"]["check"]["max_ms"],
                        "certified_check_max_ms": capability["certification"][
                            "certified_callback_max_ms"
                        ]["check"],
                        "scheduler_inequality_lhs_ms": calibration_evidence[
                            "scheduler_inequality_lhs_ms"
                        ],
                        "canaries": [
                            {
                                "name": item["pool_name"],
                                "accepting": item["receipt"]["accepting"],
                                "disposition": item["receipt"]["pool_disposition"],
                                "elapsed_improvement_ratio": item[
                                    "elapsed_improvement_ratio"
                                ],
                            }
                            for item in canaries
                        ],
                    },
                    sort_keys=True,
                )
            )
            return 0
    except Exception as exc:
        manifest_work_units = (
            manifest.get("work_units")
            if isinstance(manifest, Mapping)
            and isinstance(manifest.get("work_units"), Mapping)
            else {}
        )
        containment = (
            contain_started_threads(server)
            if server is not None
            else {
                "allocated_count": 0,
                "identified_thread_count": 0,
                "interrupted_count": 0,
                "archived_count": 0,
                "already_contained_count": 0,
                "unresolved_allocation_intent_count": 0,
                "unresolved_turn_intent_count": 0,
                "ambiguous_count": 0,
                "all_contained": True,
                "ledger_consistent": True,
                "ledger_error_sha256": [],
            }
        )
        if authorization_store is not None and authorization_state is not None:
            try:
                current = authorization_store.load()
                if current["state"] == "active":
                    authorization_state = authorization_store.transition(
                        "containment-only", reason="evidence-bearing-protected-fault", now=iso()
                    )
                else:
                    authorization_state = current
            except Exception:
                containment["authorization_transition_failed"] = True
        raw_failure = str(exc)
        safe_failure_code = (
            raw_failure
            if raw_failure
            and len(raw_failure) <= 240
            and all(character.isalnum() or character in "-_:;." for character in raw_failure)
            else type(exc).__name__
        )
        failure = seal_artifact(
            {
                "result_type": "cwo-native-supervision-pool-live-canary-failure",
                "version": 1,
                "bead_id": (
                    manifest_work_units.get("epic_id")
                ),
                "work_unit_id": (
                    manifest_work_units.get("live_work_unit_id")
                ),
                "control_turn_id": (
                    manifest.get("control_turn_id")
                    if isinstance(manifest, Mapping)
                    else CONTROL_TURN_ID
                ),
                "exact_model": EXACT_MODEL,
                "started_at": iso(started_at),
                "failed_at": iso(),
                "failure_class": type(exc).__name__,
                "failure_code": safe_failure_code,
                "failure_message_sha256": sha256_text(str(exc)),
                "validation_outcome": "rejected",
                "release_gate_passed": False,
                "no_resume_or_salvage": True,
                "containment": containment,
                "authorization_state_sha256": (
                    authorization_state.get("state_sha256")
                    if isinstance(authorization_state, Mapping)
                    else None
                ),
                "steering_consumptions": steering_consumptions,
                "campaign_bindings": artifact_bindings,
                "first_protected_fault": getattr(exc, "first_protected_fault", None),
                "allocation_ledger": safe_allocation_ledger_summary(allocation_ledger),
                "glm_5_2_used": False,
                "model_synthesis_used": False,
            },
            "evidence_sha256",
        )
        failure_persisted = (
            campaign_committed
            and not output.exists()
            and not output.is_symlink()
        )
        if failure_persisted:
            write_private_artifact(output, failure)
        if (
            campaign_reservation is not None
            and failure_persisted
            and containment.get("all_contained") is True
            and containment.get("ledger_consistent") is True
            and containment.get("ambiguous_count") == 0
            and containment.get("authorization_transition_failed") is not True
        ):
            try:
                transition_global_campaign_state(
                    campaign_reservation,
                    "contained",
                    terminal_evidence_sha256=failure["evidence_sha256"],
                )
                campaign_reservation = None
            except Exception:
                containment["scope_campaign_transition_failed"] = True
        print(
            json.dumps(
                {
                    "release_gate_passed": False,
                    "failure_class": type(exc).__name__,
                    "failure_code": safe_failure_code,
                    "failure_message_sha256": failure["failure_message_sha256"],
                    "evidence_sha256": failure["evidence_sha256"],
                    "failure_evidence_persisted": failure_persisted,
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1
    finally:
        if server is not None:
            server.close()


if __name__ == "__main__":
    raise SystemExit(main())
