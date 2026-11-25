#!/usr/bin/env python3
"""Shared native adapter, calibration and containment, with a retired campaign CLI."""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import hashlib
import json
import math
import os
import re
import shlex
from pathlib import Path
import stat
import sys
import threading
import time
from typing import Any, Callable, Iterable, Mapping, NoReturn
import uuid


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core import native_live_availability as live_availability  # noqa: E402
from cwo_core.native_canary_contracts import (  # noqa: E402
    CONTROL_OBSERVATION_MAX,
    MATERIALIZATION_EVIDENCE_SCHEMA,
    MATERIALIZATION_EVIDENCE_TYPE,
    NativeCanaryContractError,
    canonical_sha256 as domain_sha256,
    materialization_execution_correlation,
    materialization_liveness_correlation,
    seal_materialization_evidence,
    validate_capability_rendered_command,
    validate_materialization_evidence,
)
from cwo_core.native_pool import LegacyNativePoolExecutionRetired  # noqa: E402
from cwo_core.native_pool_capacity import load_pool_capacity  # noqa: E402
from cwo_core.native_pool_capacity_compat import (  # noqa: E402
    LEGACY_CONCURRENT_CAPACITY,
)
from cwo_core.native_live_allocation_ledger import (  # noqa: E402
    _IdentityCapabilityRegistry as _IdentityCapabilityRegistry,
    _TurnNegativeResponseObserverBinding as _TurnNegativeResponseObserverBinding,
)
from cwo_core.native_turn_dispatch import (  # noqa: E402
    TURN_ABSENCE_PROOF_ARTIFACT_TYPE as TURN_ABSENCE_PROOF_ARTIFACT_TYPE,
    TurnDispatchReservation as TurnDispatchReservation,
    evolve_turn_dispatch_record as evolve_turn_dispatch_record,
    seal_turn_absence_proof as seal_turn_absence_proof,
    validate_turn_dispatch_record,
)
from cwo_core.native_pool_contracts import (  # noqa: E402
    CAPABILITY_CERTIFICATION_ENVELOPE,
    CAPABILITY_CERTIFICATION_VERSION,
    CAPABILITY_OBSERVATION_AUTHORITY,
    CAPABILITY_RESPONSE_TIME_EQUATION,
    CAPABILITY_SCHEDULER_MODEL,
    CAPABILITY_SLACK_WARNING_FRACTION,
    CAPABILITY_RECEIPT_SCHEMA,
    CAPABILITY_RECEIPT_TYPE,
    CERTIFIED_CALLBACK_MAX_MS,
    CERTIFIED_SCHEDULER_OVERHEAD_MS,
    POOL_POLL_INTERVAL_MS,
    POOL_POLL_LAG_TOLERANCE_MS,
    canonical_sha256,
    callback_certification_policy_sha256,
    default_completion_evidence_policy,
    seal_artifact,
    validate_capability_receipt,
    validate_completion_evidence_policy,
    write_private_artifact,
    zero_token_usage,
)
from cwo_core.native_pool_scheduler import select_earliest_deadline  # noqa: E402
from cwo_core.native_pool_schedulability import (  # noqa: E402
    PoolSchedulabilityError,
    scheduling_budget_proof,
)
from cwo_core.workspace import (  # noqa: E402
    capture_workspace_baseline,
    compare_workspace_baseline,
)
from codex_tool_surface import (  # noqa: E402
    ALLOWLIST_PARAMETER as _CONFIG_TOOL_ALLOWLIST_PARAMETER,
    CodexToolSurfaceError as CodexToolSurfaceError,
    DIRECT_TOOL_TRANSPORT,
    NAMESPACED_EXEC_TOOL_TRANSPORT,
    require_surface_proof as require_surface_proof,
    thread_start_enforcement_params as thread_start_enforcement_params,
    prepare_capture_binding as prepare_capture_binding,
    require_capture_binding as require_capture_binding,
    _codex_binary as _codex_binary,
    tool_transport_instructions as tool_transport_instructions,
    tool_profile_is_mutable as tool_profile_is_mutable,
    require_zero_endpoint_inventory as require_zero_endpoint_inventory,
)
from cwo_core.native_tool_isolation import (  # noqa: E402
    NativeToolIsolationError,
    build_tool_surface_snapshot,
    default_tool_policy,
    forbidden_tool_activity,
    normalize_tool_policy,
    require_prompt_preflight,
    require_unchanged_tool_surface,
    validate_tool_surface_snapshot,
)
from cwo_core.native_worker_contracts import (  # noqa: E402
    _argument_value,
    _event_items,
    _output_text,
    _paired_namespaced_exec_result,
    canonical_argument_hash,
    decode_namespaced_exec_source,
    is_tool_call_item,
    is_tool_output_item,
    normalize_action_receipts,
    trusted_tool_name,
)
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
from cwo_core.workspace import (  # noqa: E402
    WorkspaceInspectionError,
    capture_tracked_workspace_state,
    cleanliness_established,
    status_path,
    worktree_state_digest,
)


from cwo_core.supervision.transport.errors import (  # noqa: E402
    AmbiguousTurnStartError as AmbiguousTurnStartError,
    AppServerError as AppServerError,
    AppServerRpcError as AppServerRpcError,
)
from cwo_core.supervision.transport.private_io import (  # noqa: E402
    _fsync_owned_control_directory as _fsync_owned_control_directory,
    _fsync_private_control_directory as _fsync_private_control_directory,
    _load_owned_regular_bytes as _load_owned_regular_bytes,
    _open_private_control_lock as _open_private_control_lock,
    _private_control_directory as _private_control_directory,
    load_private_bytes as load_private_bytes,
    load_private_json as load_private_json,
    load_private_json_snapshot as load_private_json_snapshot,
)
from cwo_core.supervision.transport.app_server import (  # noqa: E402
    AMBIGUOUS_TURN_DISCOVERY_POLL_SECONDS as AMBIGUOUS_TURN_DISCOVERY_POLL_SECONDS,
    AMBIGUOUS_TURN_DISCOVERY_TIMEOUT_SECONDS as AMBIGUOUS_TURN_DISCOVERY_TIMEOUT_SECONDS,
    CONTROL_TURN_ID as CONTROL_TURN_ID,
    EXACT_MODEL as EXACT_MODEL,
    THREAD_PHASE_LIVE_CANARY as THREAD_PHASE_LIVE_CANARY,
    THREAD_PHASE_PRECOMMIT_FIT as THREAD_PHASE_PRECOMMIT_FIT,
    THREAD_READ_TIMEOUT_SECONDS as THREAD_READ_TIMEOUT_SECONDS,
    THREAD_START_PHASES as THREAD_START_PHASES,
    AppServer as AppServer,
    _canonical_controller_workdir as _canonical_controller_workdir,
    _seal_same_process_proof as _seal_same_process_proof,
    _validated_same_process_proof as _validated_same_process_proof,
    sha256_bytes as sha256_bytes,
    sha256_text as sha256_text,
)

CONFIG_TOOL_ALLOWLIST_PARAMETER = _CONFIG_TOOL_ALLOWLIST_PARAMETER

POST_SUBMISSION_MATERIALIZATION_GRACE_MS = POOL_POLL_LAG_TOLERANCE_MS
PROVISIONAL_TERMINAL_GRACE_SECONDS = 5.0
CALIBRATION_STARTUP_TIMEOUT_SECONDS = 30.0
CALIBRATION_MATERIALIZATION_TIMEOUT_SECONDS = 10.0
CALIBRATION_POLL_INTERVAL_SECONDS = 0.20
CALIBRATION_POLL_GAP_MAX_SECONDS = 0.250
STAGED_ARCHIVE_CLOSE_SETTLE_SECONDS = 0.05
STAGED_ARCHIVE_TERMINAL_TIMEOUT_SECONDS = 5.0
STAGED_ARCHIVE_TERMINAL_POLL_SECONDS = 0.05
CALIBRATION_CERTIFICATION_SAMPLING_PHASE = (
    "after-first-exact-operative-observation"
)
DESCRIPTOR_CAPTURE_ATTEMPT_MAX = 8
DESCRIPTOR_CAPTURE_RETRY_GAP_SECONDS = 0.01
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


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso(value: dt.datetime | None = None) -> str:
    return (value or utc_now()).isoformat().replace("+00:00", "Z")


def privacy_safe_notification_shape(
    events: list[Mapping[str, Any]],
    *,
    connection_epoch_sha256: str,
    thread_id: str,
    turn_id: str,
) -> dict[str, Any]:
    """Project app-server notification structure without raw user/tool payloads."""

    projected: list[dict[str, Any]] = []
    for event in events[:16]:
        params = event.get("params") if isinstance(event.get("params"), Mapping) else {}
        item = params.get("item") if isinstance(params.get("item"), Mapping) else {}
        item_id = item.get("id")
        payload = item.get("arguments")
        if payload is None:
            payload = item.get("command")
        projected.append(
            {
                "sequence": int(event.get("sequence", 0)),
                "received_monotonic_ns": int(event.get("received_monotonic_ns", 0)),
                "method": str(event.get("method") or "missing"),
                "params_keys": sorted(str(key) for key in params),
                "item_keys": sorted(str(key) for key in item),
                "thread_id_matches": params.get("threadId") == thread_id,
                "turn_id_matches": params.get("turnId") == turn_id,
                "item_type": str(item.get("type") or "missing"),
                "item_status": str(item.get("status") or "missing"),
                "item_namespace": (
                    str(item["namespace"]) if isinstance(item.get("namespace"), str) else None
                ),
                "item_tool": str(item["tool"]) if isinstance(item.get("tool"), str) else None,
                "item_id_sha256": sha256_text(str(item_id)),
                "payload_digest_sha256": sha256_text(str(payload)),
                "started_at_ms_type": (
                    "integer"
                    if isinstance(params.get("startedAtMs"), int)
                    and not isinstance(params.get("startedAtMs"), bool)
                    else "missing"
                ),
            }
        )
    body = {
        "evidence_type": "cwo-app-server-notification-shape:v1",
        "version": 1,
        "connection_epoch_sha256": connection_epoch_sha256,
        "thread_id_sha256": sha256_text(thread_id),
        "turn_id_sha256": sha256_text(turn_id),
        "event_count": len(projected),
        "events": projected,
    }
    body["evidence_sha256"] = domain_sha256(
        body, domain="native-app-server-notification-shape"
    )
    return body


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

    @classmethod
    def _require_append_only_transition(
        cls,
        previous: os.stat_result,
        current: os.stat_result,
    ) -> None:
        if current.st_size < previous.st_size or (
            current.st_size == previous.st_size
            and cls._stat_signature(current) != cls._stat_signature(previous)
        ):
            raise NativeSessionBoundaryError(
                "trusted session source changed during descriptor capture"
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

    def _pread_snapshot(
        self,
        expected: os.stat_result,
    ) -> tuple[bytes, os.stat_result]:
        """Read one exact stat-sized prefix and report concurrent growth."""

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
        self._require_owner_regular_unaliased(after)
        self._require_private(after)
        if after.st_size < expected.st_size or (
            after.st_size == expected.st_size
            and self._stat_signature(after) != self._stat_signature(expected)
        ):
            raise NativeSessionBoundaryError(
                "trusted session source changed during descriptor read"
            )
        return bytes(raw), after

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
        retained_prefix: bytes | None = None
        retry_anchor: os.stat_result | None = None
        for attempt in range(DESCRIPTOR_CAPTURE_ATTEMPT_MAX):
            before = self._pin_or_verify(located)
            if retry_anchor is not None:
                self._require_append_only_transition(retry_anchor, before)
            self._require_change_history_valid(
                before,
                allow_archive_metadata_change=archive_transition,
            )
            raw, read_after = self._pread_snapshot(before)
            if retained_prefix is not None and not raw.startswith(retained_prefix):
                raise NativeSessionBoundaryError(
                    "session JSONL prefix was rewritten during append retry"
                )
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
            # Parsing is deliberately inside the identity bracket: an ancestor
            # or leaf substitution during JSON decoding must be observed before
            # the boundary can become accepting.
            final_location = self._locate_current()
            if final_location.store != refreshed.store:
                raise NativeSessionBoundaryError(
                    "trusted session store changed during descriptor capture"
                )
            final_stat = self._pin_or_verify(final_location)

            before_signature = self._stat_signature(before)
            observed = (read_after, after, final_stat)
            if all(
                self._stat_signature(current) == before_signature
                for current in observed
            ):
                self._last_stat_signature = before_signature
                self._last_store = final_location.store
                return final_location, boundary, records, bool(records)

            previous = before
            for current in observed:
                self._require_append_only_transition(previous, current)
                previous = current
            retained_prefix = raw
            retry_anchor = final_stat
            located = final_location
            if attempt + 1 >= DESCRIPTOR_CAPTURE_ATTEMPT_MAX:
                raise NativeSessionBoundaryError(
                    "trusted session source did not stabilize after append retries"
                )
            time.sleep(DESCRIPTOR_CAPTURE_RETRY_GAP_SECONDS)

        raise AssertionError("descriptor capture retry bound was not enforced")

    def close(self) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None

    def __del__(self) -> None:
        try:
            self.close()
        except OSError:
            pass


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
        "slack_warning_fraction": CAPABILITY_SLACK_WARNING_FRACTION,
    }
    if not isinstance(certification, Mapping) or dict(certification) != expected:
        raise AppServerError("callback-certification-policy-invalid")
    limits = load_pool_capacity(document)
    try:
        proof = scheduling_budget_proof(
            requested_workers=limits.hard_max_active_workers,
            certified_callback_max_ms=CERTIFIED_CALLBACK_MAX_MS,
            certified_scheduler_overhead_ms=(
                CERTIFIED_SCHEDULER_OVERHEAD_MS
            ),
            poll_interval_ms=pool.get("scheduler", {}).get(
                "poll_interval_ms"
            ),
        )
    except PoolSchedulabilityError as error:
        raise AppServerError(
            "callback-certification-schedulability-input-invalid"
        ) from error
    if not proof.accepted:
        raise AppServerError("callback-certification-hard-cap-unschedulable")
    return dict(certification)


# The adapter implementation is this runner plus the transport moved out of it.
ADAPTER_IMPLEMENTATION_PATHS = (
    "scripts/run_native_pool_live_canaries.py",
    "scripts/cwo_core/native_live_availability.py",
    "scripts/cwo_core/supervision/transport/app_server.py",
    "scripts/cwo_core/supervision/transport/errors.py",
    "scripts/cwo_core/supervision/transport/private_io.py",
)


def adapter_implementation_sha256() -> str:
    """Digest every adapter source so moved transport code stays covered."""

    return domain_sha256(
        {
            relative: sha256_bytes((ROOT / relative).read_bytes())
            for relative in ADAPTER_IMPLEMENTATION_PATHS
        },
        domain="native-adapter-implementation-sources",
    )


def capability_certification() -> dict[str, Any]:
    policy = callback_certification_policy()
    return {
        **policy,
        "policy_sha256": callback_certification_policy_sha256(policy),
        "adapter_implementation_sha256": adapter_implementation_sha256(),
    }


def capture_server_tool_surface(
    server: Any,
    tool_policy: Mapping[str, Any],
) -> dict[str, Any]:
    """Capture one strict, truthful tool-surface snapshot from a server."""

    policy = normalize_tool_policy(tool_policy)
    reader = getattr(server, "tool_surface_capability", None)
    if reader is None:
        capability: Mapping[str, Any] = {
            "source": "legacy-app-server-interface-no-allowlist",
            "server_allowlist_supported": False,
            "allowlist_parameter": None,
            "effective_allowlist": None,
        }
    else:
        raw = reader(permitted_tools=list(policy["permitted_tools"]))
        if not isinstance(raw, Mapping):
            raise AppServerError("tool-surface-capability-invalid")
        expected = {
            "source",
            "server_allowlist_supported",
            "allowlist_parameter",
            "effective_allowlist",
        }
        if set(raw) != expected:
            raise AppServerError("tool-surface-capability-fields-invalid")
        capability = raw
    try:
        return build_tool_surface_snapshot(
            policy,
            source=capability.get("source"),
            server_allowlist_supported=capability.get(
                "server_allowlist_supported"
            ),
            allowlist_parameter=capability.get("allowlist_parameter"),
            effective_allowlist=capability.get("effective_allowlist"),
        )
    except NativeToolIsolationError as exc:
        raise AppServerError(str(exc)) from exc


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


EXACT_TOOL_TRACE_STEP_FIELDS = frozenset(
    {
        "sequence",
        "tool",
        "canonical_argument_hashes",
        "action_class",
        "determinable_target_paths",
        "pairing_status",
        "result_kind",
        "exit_code",
    }
)

READ_ONLY_COMMAND_AUTHORITY_STEP_FIELDS = frozenset(
    {
        "sequence",
        "tool",
        "argument_alternatives",
        "continuation_of",
    }
)
PENDING_EXEC_SESSION = "__CWO_PENDING_EXEC_SESSION__"
_DIRECT_PENDING_EXEC_RESULT = re.compile(
    r"Chunk ID: [0-9A-Za-z_-]+\n"
    r"Wall time: [0-9]+(?:\.[0-9]+)? seconds\n"
    r"Process running with session ID (?P<session_id>[1-9][0-9]*)\n"
    r"Original token count: [0-9]+\n"
    r"Output:\n[\s\S]*\Z"
)
_READ_ONLY_SHELL_META = frozenset({";", "&", "|", ">", "<"})


def _read_only_command_tokens(command: Any) -> list[str]:
    """Parse one deliberately narrow command without authorizing shell syntax."""

    if (
        not isinstance(command, str)
        or not command
        or "\x00" in command
        or "\n" in command
        or "\r" in command
        or "`" in command
        or "$(" in command
        or "${" in command
    ):
        raise AppServerError("read-only-command-authority-command-invalid")
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|<>")
        lexer.whitespace_split = True
        lexer.commenters = ""
        tokens = list(lexer)
    except ValueError as exc:
        raise AppServerError(
            "read-only-command-authority-command-invalid"
        ) from exc
    if not tokens or any(
        token and set(token) <= _READ_ONLY_SHELL_META for token in tokens
    ):
        raise AppServerError("read-only-command-authority-shell-syntax-forbidden")
    return tokens


def _require_positive_read_only_command(command: Any) -> None:
    """Accept only reviewed read/test command families, never a generic shell."""

    tokens = _read_only_command_tokens(command)
    executable = tokens[0]
    arguments = tokens[1:]
    if executable == "git":
        if not arguments or arguments[0] not in {
            "diff",
            "status",
            "rev-parse",
            "show",
            "ls-files",
        }:
            raise AppServerError("read-only-command-authority-git-command-forbidden")
        if any(
            token
            in {
                "--output",
                "--exec",
                "--ext-diff",
                "--textconv",
                "-c",
                "--config-env",
            }
            or token.startswith(("--output=", "--ext", "--textc"))
            for token in arguments[1:]
        ):
            raise AppServerError("read-only-command-authority-git-option-forbidden")
        return
    if executable in {"sha256sum", "cat", "head", "tail", "wc"}:
        if any(token.startswith("--files0-from") for token in arguments):
            raise AppServerError("read-only-command-authority-option-forbidden")
        return
    if executable in {"rg", "grep"}:
        if any(
            token in {"--pre", "--pre-glob"}
            or token.startswith("--pre=")
            or token.startswith("--pre-glob=")
            for token in arguments
        ):
            raise AppServerError("read-only-command-authority-option-forbidden")
        return
    if executable == "find":
        if any(
            token
            in {
                "-delete",
                "-exec",
                "-execdir",
                "-fls",
                "-fprint",
                "-ok",
                "-okdir",
            }
            or token.startswith(("-fls", "-fprint"))
            for token in arguments
        ):
            raise AppServerError("read-only-command-authority-option-forbidden")
        return
    if executable in {"python", "python3"}:
        if not arguments or arguments[0] != "-B":
            raise AppServerError("read-only-command-authority-python-no-bytecode-required")
        python_arguments = arguments[1:]
        allowed = False
        if python_arguments[:2] == ["-m", "unittest"]:
            allowed = True
        elif python_arguments and python_arguments[0] in {
            "scripts/validate_repository.py",
            "scripts/run_parallel_unittest.py",
        }:
            allowed = True
        if not allowed or any(token in {"-c", "-i"} for token in python_arguments):
            raise AppServerError("read-only-command-authority-python-command-forbidden")
        return
    if executable == "./scripts/install.sh":
        if "--dry-run" not in arguments:
            raise AppServerError("read-only-command-authority-install-not-dry-run")
        return
    raise AppServerError("read-only-command-authority-executable-forbidden")


def _normalize_read_only_command_authority(
    value: list[Mapping[str, Any]] | None,
    *,
    worktree: Path,
    tool_transport: str,
) -> list[dict[str, Any]] | None:
    if value is None:
        return None
    if type(value) is not list or not value:
        raise AppServerError("read-only-command-authority-invalid")
    normalized: list[dict[str, Any]] = []
    for sequence, raw_step in enumerate(value):
        if (
            type(raw_step) is not dict
            or set(raw_step) != READ_ONLY_COMMAND_AUTHORITY_STEP_FIELDS
        ):
            raise AppServerError("read-only-command-authority-step-fields-invalid")
        tool = raw_step.get("tool")
        alternatives = raw_step.get("argument_alternatives")
        continuation = raw_step.get("continuation_of")
        if (
            raw_step.get("sequence") != sequence
            or tool not in {"exec_command", "write_stdin"}
            or type(alternatives) is not list
            or not alternatives
            or any(type(item) is not dict for item in alternatives)
        ):
            raise AppServerError("read-only-command-authority-step-invalid")
        canonical_alternatives: list[dict[str, Any]] = []
        hashes: list[str] = []
        for raw_arguments in alternatives:
            arguments = copy.deepcopy(dict(raw_arguments))
            if tool == "exec_command":
                if (
                    continuation is not None
                    or set(arguments)
                    - {"cmd", "workdir", "login", "yield_time_ms", "max_output_tokens"}
                    or arguments.get("workdir") != str(worktree)
                    or not isinstance(arguments.get("cmd"), str)
                    or (
                        tool_transport == DIRECT_TOOL_TRANSPORT
                        and arguments.get("login") is not False
                    )
                    or (
                        tool_transport == NAMESPACED_EXEC_TOOL_TRANSPORT
                        and "login" in arguments
                    )
                ):
                    raise AppServerError(
                        "read-only-command-authority-exec-arguments-invalid"
                    )
                for field in ("yield_time_ms", "max_output_tokens"):
                    if field in arguments and (
                        isinstance(arguments[field], bool)
                        or not isinstance(arguments[field], int)
                        or arguments[field] <= 0
                    ):
                        raise AppServerError(
                            "read-only-command-authority-exec-arguments-invalid"
                        )
                _require_positive_read_only_command(arguments["cmd"])
            else:
                if (
                    isinstance(continuation, bool)
                    or not isinstance(continuation, int)
                    or continuation < 0
                    or continuation >= sequence
                    or normalized[continuation]["tool"] != "exec_command"
                    or set(arguments)
                    - {"session_id", "chars", "yield_time_ms", "max_output_tokens"}
                    or arguments.get("session_id") != PENDING_EXEC_SESSION
                    or arguments.get("chars") != ""
                ):
                    raise AppServerError(
                        "read-only-command-authority-continuation-invalid"
                    )
                for field in ("yield_time_ms", "max_output_tokens"):
                    if field in arguments and (
                        isinstance(arguments[field], bool)
                        or not isinstance(arguments[field], int)
                        or arguments[field] <= 0
                    ):
                        raise AppServerError(
                            "read-only-command-authority-continuation-invalid"
                        )
            canonical_alternatives.append(arguments)
            hashes.append(canonical_argument_hash(arguments))
        if hashes != sorted(set(hashes)):
            raise AppServerError(
                "read-only-command-authority-alternatives-not-canonical"
            )
        normalized.append(
            {
                "sequence": sequence,
                "tool": tool,
                "argument_alternatives": canonical_alternatives,
                "continuation_of": continuation,
            }
        )
    return normalized


def _direct_pending_operation_session_id(output_item: Mapping[str, Any]) -> int | None:
    match = _DIRECT_PENDING_EXEC_RESULT.fullmatch(_output_text(output_item))
    return int(match.group("session_id")) if match is not None else None


def _trusted_tool_authority_receipts(
    records: list[Mapping[str, Any]],
    receipts: list[dict[str, Any]],
    *,
    tool_transport: str,
) -> list[dict[str, Any]]:
    """Bind raw calls to normalized receipts without exposing raw commands."""

    events: list[tuple[int, str, Mapping[str, Any]]] = []
    for record_index, record in enumerate(records):
        for item_index, item in enumerate(_event_items(record)):
            order = record_index * 1000 + item_index
            if is_tool_call_item(item):
                events.append((order, "call", item))
            elif is_tool_output_item(item):
                events.append((order, "output", item))
    outputs: dict[str, list[tuple[int, Mapping[str, Any]]]] = {}
    for order, kind, item in events:
        if kind != "output":
            continue
        call_id = str(item.get("call_id") or item.get("callId") or "").strip()
        outputs.setdefault(call_id, []).append((order, item))
    calls: list[dict[str, Any]] = []
    call_ids: dict[str, int] = {}
    for order, kind, item in events:
        if kind != "call":
            continue
        call_id = str(
            item.get("call_id") or item.get("callId") or item.get("id") or ""
        ).strip()
        call_ids[call_id] = call_ids.get(call_id, 0) + 1
        tool = trusted_tool_name(item)
        arguments = _argument_value(item)
        namespaced = False
        if (
            tool_transport == NAMESPACED_EXEC_TOOL_TRANSPORT
            and str(item.get("type") or item.get("kind") or "").lower()
            in {"custom_tool_call", "customtoolcall"}
            and tool == "exec"
        ):
            try:
                decoded = decode_namespaced_exec_source(item.get("input"))
            except ValueError:
                pass
            else:
                tool = str(decoded["tool"])
                arguments = decoded["arguments"]
                namespaced = True
        paired_outputs = outputs.get(call_id, []) if call_id else []
        output_item = paired_outputs[0][1] if len(paired_outputs) == 1 else None
        output_order = paired_outputs[0][0] if len(paired_outputs) == 1 else None
        operation_session_id: int | None = None
        if isinstance(output_item, Mapping):
            if namespaced:
                _kind, _exit, conflict, operation_session_id = (
                    _paired_namespaced_exec_result(
                        tool=str(tool),
                        output_item=output_item,
                    )
                )
                if conflict:
                    operation_session_id = None
            elif tool in {"exec_command", "write_stdin"}:
                operation_session_id = _direct_pending_operation_session_id(
                    output_item
                )
        if tool == "write_stdin" and isinstance(arguments, Mapping):
            argument_session_id = arguments.get("session_id")
            if (
                isinstance(argument_session_id, int)
                and not isinstance(argument_session_id, bool)
                and argument_session_id > 0
            ):
                if (
                    operation_session_id is not None
                    and operation_session_id != argument_session_id
                ):
                    operation_session_id = None
                else:
                    operation_session_id = argument_session_id
        call_status = "exact"
        if (
            not call_id
            or call_ids[call_id] != 1
            or len(paired_outputs) > 1
            or (
                len(paired_outputs) == 1
                and paired_outputs[0][0] <= order
            )
        ):
            call_status = "invalid"
        if tool == "write_stdin":
            chronological_parents = [
                prior
                for prior in calls
                if prior["tool"] == "exec_command"
                and prior["_operation_session_id"] == operation_session_id
                and prior["_paired_output_order"] is not None
                and prior["_paired_output_order"] < order
            ]
            if len(chronological_parents) != 1:
                call_status = "invalid"
        calls.append(
            {
                "_order": order,
                "_paired_output_order": output_order,
                "_call_id": call_id,
                "_arguments": arguments,
                "_operation_session_id": operation_session_id,
                "sequence": len(calls),
                "tool": tool,
                "canonical_argument_hash": canonical_argument_hash(arguments),
                "continuation_argument_hash": (
                    canonical_argument_hash(
                        {
                            **dict(arguments),
                            "session_id": PENDING_EXEC_SESSION,
                        }
                    )
                    if tool == "write_stdin" and isinstance(arguments, Mapping)
                    else None
                ),
                "call_id_sha256": (
                    sha256_text(call_id) if call_id else None
                ),
                "operation_session_id_sha256": (
                    sha256_text(str(operation_session_id))
                    if operation_session_id is not None
                    else None
                ),
                "raw_pairing_status": call_status,
            }
        )
    projected: list[dict[str, Any]] = []
    for sequence, call in enumerate(calls):
        receipt = receipts[sequence] if sequence < len(receipts) else None
        aligned = bool(
            isinstance(receipt, Mapping)
            and receipt.get("sequence") == sequence
            and receipt.get("call_id") == call["_call_id"]
            and receipt.get("tool") == call["tool"]
            and receipt.get("canonical_argument_hash")
            == call["canonical_argument_hash"]
        )
        projected.append(
            {
                key: value
                for key, value in call.items()
                if not key.startswith("_")
            }
            | {
                "raw_receipt_alignment": "exact" if aligned else "invalid",
                "pairing_status": (
                    receipt.get("pairing_status")
                    if isinstance(receipt, Mapping)
                    else None
                ),
                "result_kind": (
                    receipt.get("typed_result", {}).get("kind")
                    if isinstance(receipt, Mapping)
                    and isinstance(receipt.get("typed_result"), Mapping)
                    else None
                ),
                "exit_code": (
                    receipt.get("exit_code")
                    if isinstance(receipt, Mapping)
                    else None
                ),
            }
        )
    if len(calls) != len(receipts):
        projected.append(
            {
                "sequence": len(projected),
                "tool": "telemetry_anomaly.raw_receipt_cardinality",
                "canonical_argument_hash": None,
                "continuation_argument_hash": None,
                "call_id_sha256": None,
                "operation_session_id_sha256": None,
                "raw_pairing_status": "invalid",
                "raw_receipt_alignment": "invalid",
                "pairing_status": None,
                "result_kind": None,
                "exit_code": None,
            }
        )
    return projected


def _tool_receipt_projection(receipt: Mapping[str, Any]) -> dict[str, Any]:
    typed_result = receipt.get("typed_result")
    return {
        "sequence": receipt.get("sequence"),
        "tool": receipt.get("tool"),
        "canonical_argument_hash": receipt.get("canonical_argument_hash"),
        "action_class": receipt.get("action_class"),
        "determinable_target_paths": list(
            receipt.get("determinable_target_paths", [])
        ),
        "pairing_status": receipt.get("pairing_status"),
        "result_kind": (
            typed_result.get("kind")
            if isinstance(typed_result, Mapping)
            else None
        ),
        "exit_code": receipt.get("exit_code"),
    }


def _trusted_session_workdir_binding(
    records: list[Mapping[str, Any]],
    expected_workdir: Path,
) -> None:
    session_records = [
        record for record in records if record.get("type") == "session_meta"
    ]
    if len(session_records) != 1:
        raise AppServerError("session-controller-workdir-binding-invalid")
    payload = session_records[0].get("payload")
    if (
        not isinstance(payload, Mapping)
        or payload.get("cwd") != str(expected_workdir)
    ):
        raise AppServerError("session-controller-workdir-mismatch")


def _nonexistent_canonical_nonsymlink_path(value: str) -> bool:
    """Prove a lexical absolute path is absent without trusting symlink aliases."""

    candidate = Path(value)
    if (
        not candidate.is_absolute()
        or "\x00" in value
        or str(candidate) != value
    ):
        return False
    cursor = Path(candidate.anchor)
    for part in candidate.parts[1:]:
        cursor = cursor / part
        try:
            metadata = cursor.lstat()
        except FileNotFoundError:
            return True
        except OSError:
            return False
        if stat.S_ISLNK(metadata.st_mode):
            return False
    return False


def _exec_workdir_binding(
    receipt: Mapping[str, Any],
    expected_workdir: Path | None,
) -> dict[str, Any] | None:
    if expected_workdir is None or receipt.get("tool") != "exec_command":
        return None
    expected_sha256 = sha256_text(str(expected_workdir))
    present = receipt.get("_invocation_workdir_present") is True
    supplied = receipt.get("_invocation_workdir")
    supplied_sha256 = (
        sha256_text(supplied)
        if isinstance(supplied, str)
        else canonical_sha256(
            {
                "present": present,
                "type": type(supplied).__name__,
            }
        )
    )
    base = {
        "expected_workdir_sha256": expected_sha256,
        "supplied_workdir_sha256": supplied_sha256,
        "supplied": present,
    }
    if not present:
        return {**base, "disposition": "controller-default"}
    if type(supplied) is not str or not supplied or "\x00" in supplied:
        return {**base, "disposition": "security-violation-malformed-workdir"}
    if supplied == str(expected_workdir):
        return {**base, "disposition": "controller-exact"}
    result = receipt.get("typed_result")
    result_kind = result.get("kind") if isinstance(result, Mapping) else None
    if (
        result_kind == "paired-input-error"
        and _nonexistent_canonical_nonsymlink_path(supplied)
    ):
        return {**base, "disposition": "recoverable-nonexistent-workdir"}
    return {**base, "disposition": "security-violation-workdir-mismatch"}


def _normalize_expected_tool_trace(
    value: list[Mapping[str, Any]] | None,
) -> list[dict[str, Any]] | None:
    if value is None:
        return None
    if type(value) is not list or not value:
        raise AppServerError("expected-tool-trace-invalid")
    normalized: list[dict[str, Any]] = []
    for sequence, raw_step in enumerate(value):
        if type(raw_step) is not dict or set(raw_step) != EXACT_TOOL_TRACE_STEP_FIELDS:
            raise AppServerError("expected-tool-trace-step-fields-invalid")
        step = dict(raw_step)
        targets = step.get("determinable_target_paths")
        if (
            step.get("sequence") != sequence
            or not isinstance(step.get("tool"), str)
            or re.fullmatch(
                r"[a-z][a-z0-9_.:-]{0,127}", step["tool"]
            )
            is None
            or type(step.get("canonical_argument_hashes")) is not list
            or not step["canonical_argument_hashes"]
            or step["canonical_argument_hashes"]
            != sorted(set(step["canonical_argument_hashes"]))
            or any(
                not isinstance(item, str)
                or re.fullmatch(r"[0-9a-f]{64}", item) is None
                for item in step["canonical_argument_hashes"]
            )
            or step.get("action_class")
            not in {
                "control",
                "network",
                "publish",
                "read",
                "test",
                "write",
            }
            or type(targets) is not list
            or targets != sorted(set(targets))
            or any(not isinstance(item, str) or not item for item in targets)
            or step.get("pairing_status") != "paired"
            or step.get("result_kind") != "paired-success"
            or step.get("exit_code") != 0
        ):
            raise AppServerError("expected-tool-trace-step-invalid")
        normalized.append(
            {
                **step,
                "determinable_target_paths": list(targets),
            }
        )
    return normalized


def _bind_receipt_workdirs(receipts, workdir):
    for receipt in receipts:
        binding = _exec_workdir_binding(receipt, workdir)
        receipt["_workdir_binding"] = binding
        typed_result = receipt.get("typed_result")
        if (
            isinstance(typed_result, dict)
            and typed_result.get("kind") == "paired-input-error"
            and isinstance(binding, Mapping)
            and binding.get("disposition") == "recoverable-nonexistent-workdir"
        ):
            typed_result["kind"] = "paired-recoverable-workdir-input-error"


def trusted_tool_evidence_summary(
    records: list[Mapping[str, Any]],
    *,
    turn_id: str | None,
    terminal_event: Mapping[str, Any] | None = None,
    tool_transport: str = DIRECT_TOOL_TRANSPORT,
    expected_workdir: Path | str | None = None,
    registered_tool_projector: Callable[..., None] | None = None,
) -> dict[str, Any]:
    """Summarize tool activity only from the descriptor-bound session boundary."""

    empty = {
        "trusted_tool_calls": 0,
        "trusted_completed_tool_calls": 0,
        "trusted_tool_evidence_sha256": [],
        "trusted_tool_names": [],
        "trusted_tool_activity": [],
        "trusted_tool_receipts": [],
        "trusted_tool_trace_sha256": canonical_sha256([]),
        "trusted_tool_authority_receipts": [],
        "trusted_tool_authority_receipts_sha256": canonical_sha256([]),
    }
    if turn_id is None:
        return empty
    context_indices = [
        index
        for index, record in enumerate(records)
        if record.get("type") == "turn_context"
        and isinstance(record.get("payload"), Mapping)
        and (
            record["payload"].get("turn_id")
            or record["payload"].get("turnId")
        )
        == turn_id
    ]
    if not context_indices:
        return empty
    if len(context_indices) != 1:
        raise AppServerError(
            "session-tool-evidence-grammar-invalid:exact-turn-context-not-singular"
        )
    start_index = context_indices[0]
    end_index = len(records)
    if terminal_event is not None:
        terminal_index = terminal_event.get("record_index")
        if (
            isinstance(terminal_index, bool)
            or not isinstance(terminal_index, int)
            or terminal_index <= start_index
        ):
            raise AppServerError(
                "session-tool-evidence-grammar-invalid:terminal-order-invalid"
            )
        end_index = terminal_index + 1
    controller_workdir = (
        _canonical_controller_workdir(expected_workdir)
        if expected_workdir is not None
        else None
    )
    tool_records = records[start_index + 1 : end_index]
    receipts = normalize_action_receipts(
        tool_records,
        segment_id=turn_id,
        tool_transport=tool_transport,
        include_private_transport_evidence=controller_workdir is not None,
    )
    calls = list(receipts)
    if registered_tool_projector is not None:
        registered_tool_projector(turn_id, tool_records, calls, terminal_event is not None)
    authority_receipts = _trusted_tool_authority_receipts(
        tool_records,
        calls,
        tool_transport=tool_transport,
    )
    if tool_transport == DIRECT_TOOL_TRANSPORT:
        for receipt, authority_receipt in zip(calls, authority_receipts):
            typed_result = receipt.get("typed_result")
            if (
                isinstance(typed_result, dict)
                and typed_result.get("kind") == "paired-unknown"
                and receipt.get("pairing_status") == "paired"
                and receipt.get("tool") in {"exec_command", "write_stdin"}
                and authority_receipt.get("raw_pairing_status") == "exact"
                and authority_receipt.get("raw_receipt_alignment") == "exact"
                and authority_receipt.get("operation_session_id_sha256")
                is not None
            ):
                typed_result["kind"] = "paired-pending"
        for index, receipt in enumerate(calls):
            typed_result = receipt.get("typed_result")
            if (
                not isinstance(typed_result, dict)
                or typed_result.get("kind") != "paired-pending"
            ):
                continue
            session_sha256 = authority_receipts[index].get(
                "operation_session_id_sha256"
            )
            resolved = any(
                later_receipt.get("tool") == "write_stdin"
                and authority_receipts[later_index].get(
                    "operation_session_id_sha256"
                )
                == session_sha256
                and later_receipt.get("typed_result", {}).get("kind")
                in {"paired-success", "paired-failure"}
                for later_index, later_receipt in enumerate(
                    calls[index + 1 :], start=index + 1
                )
            )
            if resolved:
                typed_result["kind"] = "paired-deferred"
        authority_receipts = _trusted_tool_authority_receipts(
            records[start_index + 1 : end_index],
            calls,
            tool_transport=tool_transport,
        )
    _bind_receipt_workdirs(calls, controller_workdir)
    completed = [
        receipt
        for receipt in calls
        if receipt.get("pairing_status") == "paired"
        and (
            receipt.get("typed_result", {}).get("kind")
            not in {"paired-interrupted", "paired-pending"}
        )
        and (not receipt.get("_registered_finite")
             or receipt["typed_result"]["kind"] == "paired-success")
    ]
    trusted_receipts = [
        _tool_receipt_projection(receipt) for receipt in calls
    ]
    trusted_activity = []
    for receipt in calls:
        raw_tool = str(receipt.get("tool") or "").strip().lower()
        normalized_tool = (
            raw_tool
            if re.fullmatch(r"[a-z][a-z0-9_.:-]{0,127}", raw_tool)
            else "unknown"
        )
        typed_result = receipt.get("typed_result")
        result_kind = (
            typed_result.get("kind")
            if isinstance(typed_result, Mapping)
            else None
        )
        workdir_binding = receipt.get("_workdir_binding")
        workdir_violation = bool(
            isinstance(workdir_binding, Mapping)
            and str(workdir_binding.get("disposition", "")).startswith(
                "security-violation-"
            )
        )
        telemetry_anomaly = (
            receipt.get("pairing_status") == "ambiguous"
            or result_kind
            in {
                "paired-input-error",
                "paired-interrupted",
                "paired-unknown",
                "unpaired-output",
            }
            or (result_kind == "paired-pending" and terminal_event is not None)
            or normalized_tool == "unknown"
        )
        tool = (
            "security_violation.exec_command_workdir"
            if workdir_violation
            else f"telemetry_anomaly.{normalized_tool[:96]}"
            if telemetry_anomaly
            else normalized_tool
        )
        activity_payload = {
            "tool": tool,
            "reported_tool": normalized_tool,
            "call_id_sha256": (
                hashlib.sha256(str(receipt["call_id"]).encode("utf-8")).hexdigest()
                if receipt.get("call_id")
                else None
            ),
            "canonical_argument_hash": receipt.get("canonical_argument_hash"),
            "action_class": receipt.get("action_class"),
            "determinable_target_paths": receipt.get("determinable_target_paths"),
            "pairing_status": receipt.get("pairing_status"),
            "workdir_binding": workdir_binding,
        }
        activity = {
            "tool": tool,
            "evidence_sha256": canonical_sha256(activity_payload),
            "pairing_status": receipt.get("pairing_status"),
            "result_kind": result_kind,
        }
        if receipt.get("_registered_finite") is True:
            activity["registered_finite"] = True
        trusted_activity.append(activity)
    evidence_sha256 = sorted(
        canonical_sha256(
            {
                "tool": receipt.get("tool"),
                "canonical_argument_hash": receipt.get("canonical_argument_hash"),
                "action_class": receipt.get("action_class"),
                "determinable_target_paths": receipt.get("determinable_target_paths"),
                "typed_result": receipt.get("typed_result"),
                "exit_code": receipt.get("exit_code"),
                "pairing_status": receipt.get("pairing_status"),
            }
        )
        for receipt in completed
    )
    return {
        "trusted_tool_calls": len(calls),
        "trusted_completed_tool_calls": len(completed),
        "trusted_tool_evidence_sha256": evidence_sha256,
        "trusted_tool_names": sorted({item["tool"] for item in trusted_activity}),
        "trusted_tool_activity": trusted_activity,
        "trusted_tool_receipts": trusted_receipts,
        "trusted_tool_trace_sha256": canonical_sha256(trusted_receipts),
        "trusted_tool_authority_receipts": authority_receipts,
        "trusted_tool_authority_receipts_sha256": canonical_sha256(
            authority_receipts
        ),
    }


def session_boundary_summary(
    codex_home: Path,
    thread_id: str,
    _reported: str | None,
    *,
    turn_id: str | None = None,
    baseline: Mapping[str, Any] | None = None,
    allow_unmaterialized: bool = False,
    expected_source_identity_sha256: str | None = None,
    tool_transport: str = DIRECT_TOOL_TRANSPORT,
    expected_workdir: Path | str | None = None,
    registered_tool_projector: Callable[..., None] | None = None,
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
            "trusted_tool_calls": 0,
            "trusted_completed_tool_calls": 0,
            "trusted_tool_evidence_sha256": [],
            "trusted_tool_names": [],
            "trusted_tool_activity": [],
            "trusted_tool_receipts": [],
            "trusted_tool_trace_sha256": canonical_sha256([]),
            "trusted_tool_authority_receipts": [],
            "trusted_tool_authority_receipts_sha256": canonical_sha256([]),
        }
    controller_workdir = (
        _canonical_controller_workdir(expected_workdir)
        if expected_workdir is not None
        else None
    )
    if controller_workdir is not None:
        _trusted_session_workdir_binding(records, controller_workdir)
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
    tool_evidence = trusted_tool_evidence_summary(
        records,
        turn_id=turn_id,
        terminal_event=terminal_event,
        tool_transport=tool_transport,
        expected_workdir=controller_workdir,
        registered_tool_projector=registered_tool_projector,
    )
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
        **tool_evidence,
    }


def captured_session_boundary_summary(
    located: LocatedSession,
    boundary: Mapping[str, Any],
    records: list[dict[str, Any]],
    *,
    turn_id: str | None,
    tool_transport: str = DIRECT_TOOL_TRANSPORT,
    expected_workdir: Path | str | None = None,
) -> dict[str, Any]:
    """Summarize an already descriptor-bound session boundary."""

    controller_workdir = (
        _canonical_controller_workdir(expected_workdir)
        if expected_workdir is not None
        else None
    )
    if controller_workdir is not None:
        _trusted_session_workdir_binding(records, controller_workdir)
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
    tool_evidence = trusted_tool_evidence_summary(
        records,
        turn_id=turn_id,
        terminal_event=terminal_event,
        tool_transport=tool_transport,
        expected_workdir=controller_workdir,
    )
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
        **tool_evidence,
    }


class StagedThreadArchive:
    """Issue one archive RPC off-callback and expose a bounded close check."""

    def __init__(
        self,
        server: AppServer,
        thread_id: str,
        *,
        prepare: Callable[[], None] | None = None,
        after_archive: Callable[[float], None] | None = None,
    ) -> None:
        self.server = server
        self.thread_id = thread_id
        self.prepare = prepare
        self.after_archive = after_archive
        self._lock = threading.Lock()
        self._done = threading.Event()
        self._started = False
        self._error: BaseException | None = None
        self._rpc_latency_ms: float | None = None

    def _run(self) -> None:
        try:
            if self.prepare is not None:
                self.prepare()
            latency = self.server.archive_thread(self.thread_id)
            if (
                not isinstance(latency, (int, float))
                or isinstance(latency, bool)
                or not math.isfinite(float(latency))
                or float(latency) < 0
            ):
                raise AppServerError("staged-archive-latency-invalid")
            proof_reader = getattr(self.server, "archive_acceptance_proof", None)
            if callable(proof_reader) and proof_reader(self.thread_id) is None:
                raise AppServerError("staged-archive-acceptance-proof-missing")
            self._rpc_latency_ms = float(latency)
            if self.after_archive is not None:
                self.after_archive(self._rpc_latency_ms)
        except BaseException as exc:
            self._error = exc
        finally:
            self._done.set()

    def start(self) -> None:
        with self._lock:
            if self._started:
                raise AppServerError("staged-archive-already-started")
            register = getattr(self.server, "register_staged_archive", None)
            if callable(register):
                register(self.thread_id, self)
            self._started = True
            threading.Thread(
                target=self._run,
                name=f"cwo-archive-{sha256_text(self.thread_id)[:12]}",
                daemon=True,
            ).start()

    def require_complete(
        self,
        *,
        timeout_seconds: float = STAGED_ARCHIVE_CLOSE_SETTLE_SECONDS,
    ) -> float:
        if not self._started:
            raise AppServerError("staged-archive-not-started")
        if not self._done.wait(timeout=max(0.0, timeout_seconds)):
            raise AppServerError("staged-archive-not-complete-after-cooperative-wait")
        if self._error is not None:
            if isinstance(self._error, Exception):
                raise self._error
            raise AppServerError(
                f"staged-archive-failed:{type(self._error).__name__}"
            )
        if self._rpc_latency_ms is None:
            raise AppServerError("staged-archive-latency-missing")
        return self._rpc_latency_ms

    def completion_ready(self) -> bool:
        """Return whether the single staged request has reached a terminal result."""

        if not self._started:
            raise AppServerError("staged-archive-not-started")
        return self._done.is_set()

    def telemetry(self) -> dict[str, Any]:
        return {
            "mode": "cooperative-staged-single-request",
            "started": self._started,
            "completed": self._done.is_set() and self._error is None,
            "rpc_latency_ms": (
                round(self._rpc_latency_ms, 3)
                if self._rpc_latency_ms is not None
                else None
            ),
            "error_type": (
                type(self._error).__name__ if self._error is not None else None
            ),
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
        expected_tool_trace: list[Mapping[str, Any]] | None = None,
        read_only_command_authority: list[Mapping[str, Any]] | None = None,
        completion_evidence_policy: Mapping[str, Any] | None = None,
        tool_policy: Mapping[str, Any] | None = None,
        prompt_preflight_receipt: Mapping[str, Any] | None = None,
        preflight_tool_surface: Mapping[str, Any] | None = None,
        tool_surface_reader: Callable[[], Mapping[str, Any]] | None = None,
        force_interrupt_after_checks: int | None = None,
        record_dir: Path,
        monotonic_ns: Callable[[], int] = time.monotonic_ns,
        campaign_live_route: bool = True,
    ) -> None:
        self.campaign_live_route = campaign_live_route
        self.server = server
        self.thread_response = copy.deepcopy(dict(thread_response))
        self.thread = copy.deepcopy(dict(thread_response["thread"]))
        self.thread_id = str(self.thread["id"])
        self.reported_session_path = self.thread.get("path")
        self.prompt = prompt
        self.expected_token = expected_token
        self.worktree = _canonical_controller_workdir(worktree)
        self.mutable = mutable
        self.expected_mutation = expected_mutation
        transport_reader = getattr(server, "operative_tool_transport", None)
        self.tool_transport = (
            str(transport_reader())
            if callable(transport_reader)
            else DIRECT_TOOL_TRANSPORT
        )
        if self.tool_transport not in {
            DIRECT_TOOL_TRANSPORT,
            NAMESPACED_EXEC_TOOL_TRANSPORT,
        }:
            raise AppServerError("operative-tool-transport-invalid")
        if expected_tool_trace is not None and read_only_command_authority is not None:
            raise AppServerError("tool-authority-contract-ambiguous")
        self.expected_tool_trace = _normalize_expected_tool_trace(
            expected_tool_trace
        )
        self.expected_tool_trace_sha256 = (
            canonical_sha256(self.expected_tool_trace)
            if self.expected_tool_trace is not None
            else None
        )
        self.read_only_command_authority = (
            _normalize_read_only_command_authority(
                read_only_command_authority,
                worktree=self.worktree,
                tool_transport=self.tool_transport,
            )
        )
        if self.mutable and self.read_only_command_authority is not None:
            raise AppServerError("read-only-command-authority-mutable-forbidden")
        self.read_only_command_authority_sha256 = (
            canonical_sha256(self.read_only_command_authority)
            if self.read_only_command_authority is not None
            else None
        )
        isolation_class = "mutable-isolated" if mutable else "read-only-shared"
        raw_policy = (
            default_completion_evidence_policy(isolation_class)
            if completion_evidence_policy is None
            else completion_evidence_policy
        )
        policy_errors = validate_completion_evidence_policy(
            raw_policy,
            isolation_class=isolation_class,
        )
        if policy_errors:
            raise AppServerError(
                "completion-evidence-policy-invalid:" + ";".join(policy_errors)
            )
        required = raw_policy["required_evidence"]
        self.completion_evidence_policy = {
            "minimum_tool_calls": int(raw_policy["minimum_tool_calls"]),
            "required_evidence": {
                "predicates": list(required["predicates"]),
                "sha256": list(required["sha256"]),
            },
            "allow_zero_tool_completion": bool(
                raw_policy["allow_zero_tool_completion"]
            ),
            "expected_mutation_mode": str(raw_policy["expected_mutation_mode"]),
        }
        self.completion_evidence_policy_sha256 = canonical_sha256(
            self.completion_evidence_policy
        )
        raw_tool_policy = (
            default_tool_policy(
                mutable=mutable,
                workload_class="safety-canary",
            )
            if tool_policy is None
            else tool_policy
        )
        try:
            self.tool_policy = normalize_tool_policy(raw_tool_policy)
            observed_prompt_preflight = require_prompt_preflight(
                prompt, self.tool_policy
            )
        except NativeToolIsolationError as exc:
            raise AppServerError(str(exc)) from exc
        if (
            prompt_preflight_receipt is not None
            and dict(prompt_preflight_receipt) != observed_prompt_preflight
        ):
            raise AppServerError("prompt-preflight-receipt-mismatch")
        self.prompt_preflight = observed_prompt_preflight
        self.tool_policy_sha256 = canonical_sha256(self.tool_policy)
        self._tool_surface_reader = tool_surface_reader or (
            lambda: capture_server_tool_surface(self.server, self.tool_policy)
        )
        initial_surface = (
            dict(preflight_tool_surface)
            if preflight_tool_surface is not None
            else dict(self._tool_surface_reader())
        )
        surface_errors = validate_tool_surface_snapshot(
            initial_surface, self.tool_policy
        )
        if surface_errors:
            raise AppServerError(
                "preflight-tool-surface-invalid:" + ";".join(surface_errors)
            )
        self.preflight_tool_surface = initial_surface
        self.pre_dispatch_tool_surface: dict[str, Any] | None = None
        self._forbidden_tool_activity: list[dict[str, str]] = []
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
        self._durable_terminal_status: str | None = None
        self._session_boundary_baseline: dict[str, Any] | None = None
        self._session_source_identity_sha256: str | None = None
        self.callback_latencies: dict[str, list[float]] = {}
        self.callback_subphase_latencies: dict[str, list[float]] = {}
        self._evidence_sequence = 0
        self._staged_archive: StagedThreadArchive | None = None
        self._archive_terminal_evidence_sha256: str | None = None
        self._archive_observation_deadline_ns: int | None = None
        self._effective_boundary_sources: dict[str, Any] | None = None
        self._effective_boundary: dict[str, Any] | None = None
        self._effective_boundary_sha256: str | None = None
        self._effective_boundary_arm_in_progress = False
        self._effective_boundary_armed = False
        self._effective_boundary_send_reserved = False
        self._workspace_baseline: dict[str, Any] | None = None
        self._workspace_baseline_sha256: str | None = None

    @staticmethod
    def _sealed_mapping_matches(value: Mapping[str, Any], field: str) -> bool:
        observed = value.get(field)
        if not isinstance(observed, str):
            return False
        body = dict(value)
        body.pop(field, None)
        return observed == canonical_sha256(body)

    def _current_effective_boundary(self) -> dict[str, Any]:
        sources = self._effective_boundary_sources
        if not isinstance(sources, Mapping):
            raise AppServerError("effective-boundary-unbound")
        evidence_by_thread = getattr(
            self.server, "_effective_thread_start_evidence", None
        )
        evidence = (
            evidence_by_thread.get(self.thread_id)
            if isinstance(evidence_by_thread, Mapping)
            else None
        )
        if not isinstance(evidence, Mapping):
            raise AppServerError("effective-boundary-thread-start-missing")
        return {
            "thread_start": copy.deepcopy(dict(evidence)),
            "thread_response": copy.deepcopy(self.thread_response),
            "thread": copy.deepcopy(self.thread),
            "planned_child": copy.deepcopy(dict(sources["planned_child"])),
            "runtime_child": copy.deepcopy(dict(sources["runtime_child"])),
            "pool_contract": copy.deepcopy(dict(sources["pool_contract"])),
            "control_contract": copy.deepcopy(dict(sources["control_contract"])),
            "predispatch_proof": copy.deepcopy(dict(sources["predispatch_proof"])),
            "adapter": {
                "requested_model": getattr(
                    self.server, "requested_model", EXACT_MODEL
                ),
                "prompt": self.prompt,
                "worktree": str(self.worktree),
                "mutable": self.mutable,
                "return_contract": {
                    "expected_token": self.expected_token,
                    "expected_mutation": self.expected_mutation,
                    "expected_tool_trace": copy.deepcopy(
                        self.expected_tool_trace
                    ),
                    "read_only_command_authority": copy.deepcopy(
                        self.read_only_command_authority
                    ),
                    "completion_evidence_policy": copy.deepcopy(
                        self.completion_evidence_policy
                    ),
                },
                "prompt_preflight": copy.deepcopy(self.prompt_preflight),
                "tool_policy": copy.deepcopy(self.tool_policy),
                "tool_surface": copy.deepcopy(self.preflight_tool_surface),
                "workspace_baseline_sha256": (
                    canonical_sha256(self._workspace_baseline)
                    if self._workspace_baseline is not None
                    else None
                ),
                "writable_roots": list(sources["writable_roots"]),
            },
        }

    def _validate_effective_boundary(self, boundary: Mapping[str, Any]) -> None:
        expected_fields = {
            "thread_start",
            "thread_response",
            "thread",
            "planned_child",
            "runtime_child",
            "pool_contract",
            "control_contract",
            "predispatch_proof",
            "adapter",
        }
        if set(boundary) != expected_fields:
            raise AppServerError("effective-boundary-malformed")
        start = boundary.get("thread_start")
        response = boundary.get("thread_response")
        thread = boundary.get("thread")
        planned = boundary.get("planned_child")
        child = boundary.get("runtime_child")
        pool = boundary.get("pool_contract")
        control = boundary.get("control_contract")
        proof = boundary.get("predispatch_proof")
        adapter = boundary.get("adapter")
        if any(
            not isinstance(value, Mapping)
            for value in (
                start,
                response,
                thread,
                planned,
                child,
                pool,
                control,
                proof,
                adapter,
            )
        ):
            raise AppServerError("effective-boundary-malformed")
        request = start.get("request")
        trusted_response = start.get("response")
        if not isinstance(request, Mapping) or not isinstance(
            trusted_response, Mapping
        ):
            raise AppServerError("effective-boundary-thread-start-malformed")
        if trusted_response != response or trusted_response.get("thread") != thread:
            raise AppServerError("effective-boundary-thread-start-response-mismatch")
        worktree = str(self.worktree)
        requested_model = getattr(self.server, "requested_model", EXACT_MODEL)
        provider = trusted_response.get("modelProvider")
        request_provider = request.get("modelProvider")
        expected_sandbox_type = "workspaceWrite" if self.mutable else "readOnly"
        expected_sandbox_request = "workspace-write" if self.mutable else "read-only"
        sandbox = trusted_response.get("sandbox")
        if (
            request.get("model") != requested_model
            or request.get("allowProviderModelFallback") is not False
            or request.get("sandbox") != expected_sandbox_request
            or request.get("approvalPolicy") != "never"
            or request.get("cwd") != worktree
            or request.get("runtimeWorkspaceRoots") != [worktree]
            or trusted_response.get("model") != requested_model
            or not isinstance(provider, str)
            or not provider.strip()
            or request_provider not in (None, provider)
            or trusted_response.get("approvalPolicy") != "never"
            or trusted_response.get("cwd") != worktree
            or trusted_response.get("runtimeWorkspaceRoots") != [worktree]
            or not isinstance(sandbox, Mapping)
            or sandbox.get("type") != expected_sandbox_type
            or sandbox.get("networkAccess", False) is not False
            or thread.get("id") != self.thread_id
            or type(thread.get("turns")) is not list
            or thread.get("turns") != []
        ):
            raise AppServerError("effective-boundary-thread-start-mismatch")
        sandbox_roots = sandbox.get("writableRoots", [])
        if type(sandbox_roots) is not list or any(
            not isinstance(root, str) for root in sandbox_roots
        ):
            raise AppServerError("effective-boundary-writable-roots-malformed")
        try:
            explicit_roots = [
                str(_canonical_controller_workdir(root)) for root in sandbox_roots
            ]
        except AppServerError as exc:
            raise AppServerError("effective-boundary-writable-root-invalid") from exc
        effective_roots = sorted(
            set(([worktree] if self.mutable else []) + explicit_roots)
        )
        if (
            explicit_roots != sorted(set(explicit_roots))
            or effective_roots != adapter.get("writable_roots")
            or (not self.mutable and explicit_roots)
        ):
            raise AppServerError("effective-boundary-writable-root-mismatch")
        if (
            adapter.get("requested_model") != requested_model
            or adapter.get("prompt") != self.prompt
            or adapter.get("worktree") != worktree
            or adapter.get("mutable") is not self.mutable
            or adapter.get("return_contract")
            != {
                "expected_token": self.expected_token,
                "expected_mutation": self.expected_mutation,
                "expected_tool_trace": self.expected_tool_trace,
                "read_only_command_authority": self.read_only_command_authority,
                "completion_evidence_policy": self.completion_evidence_policy,
            }
            or adapter.get("prompt_preflight") != self.prompt_preflight
            or adapter.get("tool_policy") != self.tool_policy
            or adapter.get("tool_surface") != self.preflight_tool_surface
            or adapter.get("workspace_baseline_sha256")
            != self._workspace_baseline_sha256
        ):
            raise AppServerError("effective-boundary-adapter-mismatch")
        common_fields = (
            "child_id",
            "packet_id",
            "attempt_nonce",
            "session_id",
            "agent_id",
            "packet_sha256",
            "lease_id",
            "isolation_class",
            "completion_evidence_policy",
            "tool_policy",
            "declared_write_paths",
            "integration_target_paths",
        )
        if any(planned.get(field) != child.get(field) for field in common_fields):
            raise AppServerError("effective-boundary-planned-child-mismatch")
        if (
            planned.get("session_id") != self.thread_id
            or planned.get("agent_id") != self.thread_id
            or planned.get("worktree") != worktree
            or planned.get("prompt") != self.prompt
            or planned.get("prompt_preflight") != self.prompt_preflight
            or planned.get("tool_surface") != self.preflight_tool_surface
            or planned.get("completion_evidence_policy")
            != self.completion_evidence_policy
            or planned.get("tool_policy") != self.tool_policy
            or child.get("worktree") != worktree
            or child.get("session_id") != self.thread_id
            or child.get("agent_id") != self.thread_id
        ):
            raise AppServerError("effective-boundary-child-identity-mismatch")
        expected_paths = [self.expected_mutation] if self.expected_mutation else []
        hard_budget = planned.get("hard_budget")
        if (
            planned.get("declared_write_paths") != expected_paths
            or planned.get("integration_target_paths") != expected_paths
            or child.get("declared_write_paths") != expected_paths
            or child.get("integration_target_paths") != expected_paths
            or child.get("isolation_class")
            != ("mutable-isolated" if self.mutable else "read-only-shared")
            or not isinstance(hard_budget, Mapping)
            or set(hard_budget)
            != {
                "tool_calls",
                "runtime_seconds",
                "compactions",
                "full_suite_runs",
                "mutations",
            }
            or any(
                type(value) is not int or value < 0
                for value in hard_budget.values()
            )
        ):
            raise AppServerError("effective-boundary-scope-mismatch")
        if (
            not self._sealed_mapping_matches(control, "contract_sha256")
            or control.get("agent_id") != self.thread_id
            or control.get("state_file") != child.get("state_file")
            or control.get("control_turn_id") != child.get("control_turn_id")
            or control.get("task_sha256") != sha256_text(self.prompt)
            or control.get("poll_interval_ms") != POOL_POLL_INTERVAL_MS
        ):
            raise AppServerError("effective-boundary-control-contract-mismatch")
        if not self._sealed_mapping_matches(pool, "contract_sha256"):
            raise AppServerError("effective-boundary-pool-contract-invalid")
        pool_children = pool.get("children")
        matches = (
            [item for item in pool_children if item.get("child_id") == child.get("child_id")]
            if isinstance(pool_children, list)
            and all(isinstance(item, Mapping) for item in pool_children)
            else []
        )
        if len(matches) != 1:
            raise AppServerError("effective-boundary-pool-child-missing")
        pool_child = matches[0]
        pool_fields = (
            "child_id",
            "packet_id",
            "attempt_nonce",
            "session_id",
            "agent_id",
            "control_turn_id",
            "packet_sha256",
            "state_file",
            "isolation_class",
            "completion_evidence_policy",
            "tool_policy",
            "declared_write_paths",
            "integration_target_paths",
            "lease_id",
        )
        worktree_identity = pool_child.get("worktree_identity")
        if (
            any(pool_child.get(field) != child.get(field) for field in pool_fields)
            or pool_child.get("control_contract_sha256")
            != control.get("contract_sha256")
            or not isinstance(worktree_identity, Mapping)
            or worktree_identity.get("canonical_path_sha256")
            != sha256_text(worktree)
        ):
            raise AppServerError("effective-boundary-pool-child-mismatch")
        if (
            proof.get("accepted") is not True
            or proof.get("decision") != "accept"
            or proof.get("stage") != "pre-dispatch"
            or proof.get("contract_sha256") != pool.get("contract_sha256")
            or not self._sealed_mapping_matches(proof, "result_sha256")
        ):
            raise AppServerError("effective-boundary-predispatch-proof-mismatch")

    def bind_effective_boundary(
        self,
        *,
        planned_child: Mapping[str, Any],
        runtime_child: Mapping[str, Any],
        pool_contract: Mapping[str, Any],
        control_contract: Mapping[str, Any],
        predispatch_proof: Mapping[str, Any],
        writable_roots: Iterable[Path | str],
    ) -> None:
        """Bind all controller-owned pre-turn evidence exactly once."""

        with self._boundary_lock:
            if self._effective_boundary_sources is not None:
                raise AppServerError("effective-boundary-already-bound")
            roots = sorted(
                {str(_canonical_controller_workdir(root)) for root in writable_roots}
            )
            self._effective_boundary_sources = {
                "planned_child": planned_child,
                "runtime_child": runtime_child,
                "pool_contract": pool_contract,
                "control_contract": control_contract,
                "predispatch_proof": predispatch_proof,
                "writable_roots": roots,
            }
            try:
                boundary = self._current_effective_boundary()
                self._validate_effective_boundary(boundary)
            except BaseException:
                self._effective_boundary_sources = None
                raise
            self._effective_boundary = copy.deepcopy(boundary)
            self._effective_boundary_sha256 = canonical_sha256(boundary)

    def bind_workspace_baseline(self, baseline: Mapping[str, Any]) -> None:
        """Bind one complete controller-owned pre-dispatch workspace baseline."""

        with self._boundary_lock:
            if self._workspace_baseline is not None:
                raise AppServerError("workspace-baseline-already-bound")
            if (
                self._effective_boundary_sources is not None
                or self._boundary_phase != "pre-dispatch"
                or self._effective_boundary_arm_in_progress
                or self._effective_boundary_armed
                or self._effective_boundary_send_reserved
            ):
                raise AppServerError("workspace-baseline-binding-too-late")
            value = copy.deepcopy(dict(baseline))
            caps = value.get("caps")
            if (
                value.get("workspace_evidence_type")
                != "content-aware-baseline"
                or value.get("version") != 2
                or value.get("baseline_complete") is not True
                or value.get("incomplete") is not False
                or value.get("include_untracked") is not True
                or value.get("tracked_paths_complete") is not True
                or not isinstance(value.get("tracked_status"), list)
                or not isinstance(value.get("tracked_paths"), list)
                or not isinstance(value.get("preexisting_dirty_paths"), list)
                or not isinstance(value.get("content_fingerprints"), Mapping)
                or not isinstance(value.get("allowed_paths"), list)
                or not isinstance(caps, Mapping)
                or type(caps.get("max_files")) is not int
                or caps["max_files"] < 1
                or type(caps.get("max_bytes")) is not int
                or caps["max_bytes"] < 0
                or type(caps.get("max_seconds")) not in {int, float}
                or caps["max_seconds"] <= 0
            ):
                raise AppServerError("workspace-baseline-invalid")
            try:
                baseline_root = Path(str(value.get("cwd", ""))).resolve()
            except (OSError, RuntimeError, ValueError) as exc:
                raise AppServerError("workspace-baseline-root-invalid") from exc
            if baseline_root != self.worktree:
                raise AppServerError("workspace-baseline-root-mismatch")
            self._workspace_baseline = value
            self._workspace_baseline_sha256 = canonical_sha256(value)

    def _require_effective_boundary(
        self,
        *,
        current_tool_surface: Mapping[str, Any] | None = None,
    ) -> None:
        if self._effective_boundary is None or self._effective_boundary_sha256 is None:
            raise AppServerError("effective-boundary-unbound")
        if canonical_sha256(self._effective_boundary) != self._effective_boundary_sha256:
            raise AppServerError("effective-boundary-receipt-mutated")
        current = self._current_effective_boundary()
        self._validate_effective_boundary(current)
        if current != self._effective_boundary:
            raise AppServerError("effective-boundary-source-mutated")
        if current_tool_surface is not None:
            surface = dict(current_tool_surface)
            surface_errors = validate_tool_surface_snapshot(
                surface, self.tool_policy
            )
            if surface_errors:
                raise AppServerError(
                    "effective-boundary-tool-surface-invalid:"
                    + ";".join(surface_errors)
                )
            try:
                require_unchanged_tool_surface(
                    self.preflight_tool_surface, surface
                )
            except NativeToolIsolationError as exc:
                raise AppServerError(str(exc)) from exc

    def _timed(self, name: str, action: Callable[[], Any]) -> Any:
        started = time.monotonic_ns()
        try:
            return action()
        finally:
            elapsed = (time.monotonic_ns() - started) / 1_000_000
            self.callback_latencies.setdefault(name, []).append(elapsed)

    def _record_callback_subphase(self, name: str, started_ns: int) -> None:
        elapsed = max(0, self._monotonic_ns() - started_ns) / 1_000_000
        self.callback_subphase_latencies.setdefault(name, []).append(elapsed)

    def arm(self, **_kwargs: Any) -> dict[str, str]:
        def action() -> dict[str, str]:
            with self._boundary_lock:
                if (
                    self._effective_boundary_arm_in_progress
                    or self._effective_boundary_armed
                ):
                    raise AppServerError("effective-boundary-already-armed")
                self._effective_boundary_arm_in_progress = True
                try:
                    current_surface = dict(self._tool_surface_reader())
                    self._require_effective_boundary(
                        current_tool_surface=current_surface
                    )
                    if self.thread_response.get("model") != getattr(
                        self.server, "requested_model", EXACT_MODEL
                    ):
                        raise AppServerError("prearmed-thread-model-mismatch")
                    if (
                        self.thread.get("id") != self.thread_id
                        or self.thread.get("turns")
                    ):
                        raise AppServerError("prearmed-thread-is-not-fresh")
                except BaseException:
                    self._effective_boundary_arm_in_progress = False
                    raise
                self._effective_boundary_arm_in_progress = False
                self._effective_boundary_armed = True
            return {"ack": "armed"}

        return self._timed("arm", action)

    def send_input(self, *, message: str, **_kwargs: Any) -> dict[str, str]:
        def action() -> dict[str, str]:
            self._require_campaign_live_route()
            with self._boundary_lock:
                if self._effective_boundary_arm_in_progress:
                    raise AppServerError("effective-boundary-arm-in-progress")
                if not self._effective_boundary_armed:
                    raise AppServerError("effective-boundary-not-armed")
                if self._effective_boundary_send_reserved:
                    raise AppServerError("effective-boundary-send-not-one-shot")
                self._effective_boundary_send_reserved = True
                self._require_effective_boundary()
                if message != self.prompt:
                    raise AppServerError("turn-prompt-binding-mismatch")
                subphase_started = self._monotonic_ns()
                try:
                    current_prompt_preflight = require_prompt_preflight(
                        message, self.tool_policy
                    )
                except NativeToolIsolationError as exc:
                    raise AppServerError(str(exc)) from exc
                finally:
                    self._record_callback_subphase(
                        "send_input.prompt_preflight", subphase_started
                    )
                if current_prompt_preflight != self.prompt_preflight:
                    raise AppServerError("prompt-preflight-changed-before-dispatch")
                subphase_started = self._monotonic_ns()
                try:
                    current_surface = dict(self._tool_surface_reader())
                finally:
                    self._record_callback_subphase(
                        "send_input.tool_surface_capture", subphase_started
                    )
                subphase_started = self._monotonic_ns()
                try:
                    surface_errors = validate_tool_surface_snapshot(
                        current_surface, self.tool_policy
                    )
                    if surface_errors:
                        raise AppServerError(
                            "pre-dispatch-tool-surface-invalid:"
                            + ";".join(surface_errors)
                        )
                    try:
                        require_unchanged_tool_surface(
                            self.preflight_tool_surface, current_surface
                        )
                    except NativeToolIsolationError as exc:
                        raise AppServerError(str(exc)) from exc
                finally:
                    self._record_callback_subphase(
                        "send_input.tool_surface_validation", subphase_started
                    )
                self.pre_dispatch_tool_surface = current_surface
                # The surface reader is a reentrant callback. Rebind all
                # controller-owned identity and scope inputs after it returns,
                # immediately before irrevocably attempting the RPC.
                self._require_effective_boundary(
                    current_tool_surface=current_surface
                )
                lock_started = self._monotonic_ns()
                self._record_callback_subphase(
                    "send_input.boundary_lock_wait", lock_started
                )
                # Revoke the pre-dispatch allowance before the RPC. Failed or
                # ambiguous submission can never recover it from a missing id.
                self._boundary_phase = "dispatch-attempted"
                subphase_started = self._monotonic_ns()
                try:
                    self._require_campaign_live_route()
                    turn, _latency = self.server.start_turn(self.thread_id, message)
                finally:
                    self._record_callback_subphase(
                        "send_input.turn_start_rpc", subphase_started
                    )
                subphase_started = self._monotonic_ns()
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
                self._record_callback_subphase(
                    "send_input.acknowledgement_binding", subphase_started
                )
                return {"submission_id": self.turn_id}

        return self._timed("send_input", action)

    def _require_campaign_live_route(self) -> None:
        # Omission keeps the campaign contract; noncampaign constructors select
        # False explicitly and retain their own N1/preview admission contract.
        if self.campaign_live_route:
            live_availability.require_campaign_live()
            live_availability.require_pool_live()
            live_availability.require_n1_live()

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
                    "control_turn_id": self.control_turn_identity(),
                },
            )
            return {"ack": "dispatched"}

        return self._timed("mark_dispatched", action)

    def check(self, **_kwargs: Any) -> dict[str, str]:
        def action() -> dict[str, str]:
            self.check_count += 1
            boundary = self._capture_trusted_boundary(allow_pending=True)
            if boundary.get("available") is True:
                thread, _latency = self.server.read_thread(self.thread_id)
                self.last_thread = thread
                self.reported_session_path = (
                    thread.get("path") or self.reported_session_path
                )
            status = turn_status(self.last_thread, self.turn_id)
            terminal_event = boundary.get("terminal_event")
            durable_status = (
                terminal_event.get("status")
                if isinstance(terminal_event, Mapping)
                else None
            )
            if durable_status in {"completed", "failed", "interrupted"}:
                self._durable_terminal_status = str(durable_status)
            terminal = durable_status in {
                "completed",
            }
            trace_observation = self._exact_tool_trace_observation(
                boundary.get("trusted_tool_receipts", []),
                terminal=terminal,
            )
            if (
                trace_observation["required"]
                and trace_observation["mismatch"]
            ):
                return {"decision": "interrupt"}
            if self._observe_forbidden_tool_activity(boundary):
                return {"decision": "interrupt"}
            if durable_status == "completed":
                _message_hash, matches = self.final_message_observation()
                if not matches:
                    return {"decision": "control-lost"}
                if self._known_completion_evidence_missing(boundary):
                    return {"decision": "interrupt"}
                return {"decision": "complete"}
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

    def _observe_forbidden_tool_activity(
        self, boundary: Mapping[str, Any]
    ) -> list[dict[str, str]]:
        trusted_activity = list(boundary.get("trusted_tool_activity", []))
        authority_observation = self._read_only_command_authority_observation(
            boundary.get("trusted_tool_authority_receipts", []),
            terminal=(
                isinstance(boundary.get("terminal_event"), Mapping)
                and boundary["terminal_event"].get("status")
                in {"completed", "failed", "interrupted"}
            ),
        )
        if authority_observation["required"] and authority_observation["mismatch"]:
            trusted_activity.append(
                {
                    "tool": "security_violation.read_only_command_authority",
                    "evidence_sha256": canonical_sha256(
                        {
                            "expected_sha256": authority_observation[
                                "expected_sha256"
                            ],
                            "observed_sha256": authority_observation[
                                "observed_sha256"
                            ],
                            "reason": authority_observation["reason"],
                        }
                    ),
                }
            )
        if (
            self.tool_policy["workload_class"] == "operative"
            and self.tool_policy["enforcement_mode"]
            == "trusted-detect-and-contain"
        ):
            item_types = [
                str(item.get("type"))
                for item in turn_items(self.last_thread, self.turn_id)
                if item.get("type")
            ]
            projected_tool_calls = sum(
                item_type in OPERATIVE_ITEM_TYPES for item_type in item_types
            )
            terminal_event = boundary.get("terminal_event")
            durable_status = (
                terminal_event.get("status")
                if isinstance(terminal_event, Mapping)
                else None
            )
            trusted_tool_calls = int(boundary.get("trusted_tool_calls", 0))
            terminal = durable_status in {
                "completed",
                "failed",
                "interrupted",
            }
            for item in list(trusted_activity):
                if (
                    terminal
                    and isinstance(item, Mapping)
                    and item.get("pairing_status") == "unpaired"
                    and item.get("result_kind") == "unpaired-call"
                ):
                    reported_tool = str(item.get("tool") or "unknown")
                    trusted_activity.append(
                        {
                            "tool": (
                                "telemetry_anomaly."
                                + (
                                    reported_tool
                                    if re.fullmatch(
                                        r"[a-z][a-z0-9_.:-]{0,96}",
                                        reported_tool,
                                    )
                                    else "unknown"
                                )
                            ),
                            "evidence_sha256": canonical_sha256(
                                {
                                    "reported_activity": dict(item),
                                    "reason": "terminal-unpaired-call",
                                }
                            ),
                        }
                    )
            if (
                terminal
                and projected_tool_calls > trusted_tool_calls
            ):
                trusted_activity.append(
                    {
                        "tool": "telemetry_anomaly.missing_call_receipt",
                        "evidence_sha256": canonical_sha256(
                            {
                                "thread_id": self.thread_id,
                                "turn_id": self.turn_id,
                                "projected_tool_calls": projected_tool_calls,
                                "trusted_tool_calls": trusted_tool_calls,
                            }
                        ),
                    }
                )
        try:
            observed = forbidden_tool_activity(
                trusted_activity, self.tool_policy
            )
        except NativeToolIsolationError as exc:
            raise AppServerError(str(exc)) from exc
        combined = {
            (item["tool"], item["evidence_sha256"]): item
            for item in [*self._forbidden_tool_activity, *observed]
        }
        self._forbidden_tool_activity = [
            combined[key] for key in sorted(combined)
        ]
        return list(self._forbidden_tool_activity)

    def _read_only_command_authority_observation(
        self,
        observed_value: Any,
        *,
        terminal: bool,
    ) -> dict[str, Any]:
        expected = self.read_only_command_authority
        observed = (
            [dict(item) for item in observed_value]
            if isinstance(observed_value, list)
            and all(isinstance(item, Mapping) for item in observed_value)
            else []
        )
        observed_sha256 = canonical_sha256(observed)
        if expected is None:
            return {
                "required": False,
                "status": "not-required",
                "mismatch": False,
                "satisfied": True,
                "reason": None,
                "expected_sha256": None,
                "observed_sha256": observed_sha256,
            }
        reason: str | None = None
        pending_sessions: dict[int, str] = {}
        for sequence, observed_step in enumerate(observed):
            if sequence >= len(expected):
                reason = "extra-call"
                break
            expected_step = expected[sequence]
            if observed_step.get("sequence") != sequence:
                reason = f"step-{sequence}-sequence-mismatch"
                break
            if observed_step.get("tool") != expected_step["tool"]:
                reason = f"step-{sequence}-tool-mismatch"
                break
            if (
                observed_step.get("raw_pairing_status") != "exact"
                or observed_step.get("raw_receipt_alignment") != "exact"
                or observed_step.get("call_id_sha256") is None
            ):
                reason = f"step-{sequence}-raw-receipt-binding-invalid"
                break
            if expected_step["tool"] == "exec_command":
                allowed_hashes = {
                    canonical_argument_hash(item)
                    for item in expected_step["argument_alternatives"]
                }
                if observed_step.get("canonical_argument_hash") not in allowed_hashes:
                    reason = f"step-{sequence}-canonical-argument-mismatch"
                    break
            else:
                allowed_hashes = {
                    canonical_argument_hash(item)
                    for item in expected_step["argument_alternatives"]
                }
                if observed_step.get("continuation_argument_hash") not in allowed_hashes:
                    reason = f"step-{sequence}-continuation-argument-mismatch"
                    break
                parent = expected_step["continuation_of"]
                if (
                    not isinstance(parent, int)
                    or pending_sessions.get(parent) is None
                    or observed_step.get("operation_session_id_sha256")
                    != pending_sessions[parent]
                ):
                    reason = f"step-{sequence}-pending-parent-mismatch"
                    break
            pairing_status = observed_step.get("pairing_status")
            result_kind = observed_step.get("result_kind")
            if pairing_status == "unpaired":
                if terminal or sequence != len(observed) - 1:
                    reason = f"step-{sequence}-unpaired"
                    break
                continue
            if pairing_status != "paired":
                reason = f"step-{sequence}-pairing-mismatch"
                break
            if result_kind in {"paired-pending", "paired-deferred"}:
                session_sha256 = observed_step.get("operation_session_id_sha256")
                if session_sha256 is None:
                    reason = f"step-{sequence}-pending-session-missing"
                    break
                if expected_step["tool"] == "exec_command":
                    pending_sessions[sequence] = session_sha256
            elif result_kind not in {"paired-success", "paired-failure"}:
                reason = f"step-{sequence}-result-invalid"
                break
        complete = reason is None and len(observed) == len(expected)
        successful = complete and all(
            item.get("pairing_status") == "paired"
            and item.get("result_kind") in {"paired-success", "paired-deferred"}
            and (
                item.get("exit_code") == 0
                or item.get("result_kind") == "paired-deferred"
            )
            for item in observed
        )
        if reason is None and terminal and not complete:
            reason = "terminal-cardinality-mismatch"
        mismatch = reason is not None
        return {
            "required": True,
            "status": (
                "mismatch"
                if mismatch
                else "satisfied"
                if successful and terminal
                else "authorized-failure"
                if complete and terminal
                else "pending"
            ),
            "mismatch": mismatch,
            "satisfied": successful and terminal,
            "reason": reason,
            "expected_sha256": self.read_only_command_authority_sha256,
            "observed_sha256": observed_sha256,
        }

    def control_turn_identity(self) -> str:
        """Identity fixed by the controller before any dispatch evidence write."""
        return CONTROL_TURN_ID

    def final_message_observation(self) -> tuple[str | None, bool]:
        """Controller-selected final contract; token canaries retain exact equality.

        Product adapters may override this with strict native-return validation
        bound before arming. Both supervision and evidence use this one method;
        no post-turn replacement of expected_token is permitted.
        """
        return final_message_hash_and_match(
            self.last_thread, self.turn_id, self.expected_token)

    def _exact_tool_trace_observation(
        self,
        observed_value: Any,
        *,
        terminal: bool,
    ) -> dict[str, Any]:
        expected = self.expected_tool_trace
        observed = (
            [dict(item) for item in observed_value]
            if isinstance(observed_value, list)
            and all(isinstance(item, Mapping) for item in observed_value)
            else []
        )
        observed_sha256 = canonical_sha256(observed)
        if expected is None:
            return {
                "required": False,
                "status": "not-required",
                "mismatch": False,
                "satisfied": True,
                "reason": None,
                "expected_sha256": None,
                "observed_sha256": observed_sha256,
            }
        reason: str | None = None
        for sequence, observed_step in enumerate(observed):
            if sequence >= len(expected):
                reason = "extra-call"
                break
            expected_step = expected[sequence]
            for field in (
                "sequence",
                "tool",
                "action_class",
                "determinable_target_paths",
            ):
                if observed_step.get(field) != expected_step[field]:
                    reason = f"step-{sequence}-{field}-mismatch"
                    break
            if reason is not None:
                break
            if (
                observed_step.get("canonical_argument_hash")
                not in expected_step["canonical_argument_hashes"]
            ):
                reason = f"step-{sequence}-canonical-argument-mismatch"
                break
            pairing_status = observed_step.get("pairing_status")
            if pairing_status == "unpaired":
                if terminal or sequence != len(observed) - 1:
                    reason = f"step-{sequence}-unpaired"
                continue
            if pairing_status != expected_step["pairing_status"]:
                reason = f"step-{sequence}-pairing-mismatch"
                break
            if (
                observed_step.get("result_kind")
                != expected_step["result_kind"]
                or observed_step.get("exit_code")
                != expected_step["exit_code"]
            ):
                reason = f"step-{sequence}-result-mismatch"
                break
        trace_complete = (
            reason is None
            and len(observed) == len(expected)
            and all(
                observed_step.get("pairing_status") == "paired"
                and observed_step.get("result_kind") == "paired-success"
                and observed_step.get("exit_code") == 0
                for observed_step in observed
            )
        )
        if reason is None and terminal and not trace_complete:
            reason = "terminal-cardinality-mismatch"
        mismatch = reason is not None
        satisfied = trace_complete and terminal
        return {
            "required": True,
            "status": (
                "mismatch"
                if mismatch
                else "satisfied"
                if satisfied
                else "pending"
            ),
            "mismatch": mismatch,
            "satisfied": satisfied,
            "reason": reason,
            "expected_sha256": self.expected_tool_trace_sha256,
            "observed_sha256": observed_sha256,
        }

    def _known_completion_evidence_missing(
        self,
        boundary: Mapping[str, Any],
    ) -> bool:
        """Detect terminal evidence deficits knowable without another callback."""

        policy = self.completion_evidence_policy
        completed_calls = int(boundary.get("trusted_completed_tool_calls", 0))
        if completed_calls < policy["minimum_tool_calls"]:
            return True
        required = policy["required_evidence"]
        if "trusted-tool-call" in required["predicates"] and completed_calls < 1:
            return True
        observed_hashes = set(boundary.get("trusted_tool_evidence_sha256", []))
        if not set(required["sha256"]).issubset(observed_hashes):
            return True
        trace_observation = self._exact_tool_trace_observation(
            boundary.get("trusted_tool_receipts", []),
            terminal=True,
        )
        return (
            trace_observation["required"]
            and not trace_observation["satisfied"]
        )

    def interrupt(self, **_kwargs: Any) -> dict[str, str]:
        def action() -> dict[str, str]:
            with self._boundary_lock:
                if self.turn_id is None:
                    raise AppServerError("interrupt-turn-id-missing")
                if self._durable_terminal_status in {
                    "completed",
                    "failed",
                    "interrupted",
                }:
                    return {"ack": "already-terminal"}
                # Interrupt wins locally before the control RPC is attempted;
                # unavailable telemetry can never be accepted after this point.
                self._boundary_phase = "interrupt-requested"
                try:
                    self.server.interrupt_turn(self.thread_id, self.turn_id)
                except AppServerRpcError:
                    # A terminal transition may win the race after the last
                    # check but before turn/interrupt. Adjudicate the trusted
                    # boundary once; never retry the interrupt request.
                    boundary = self._capture_trusted_boundary(
                        allow_pending=True
                    )
                    terminal_event = boundary.get("terminal_event")
                    durable_status = (
                        terminal_event.get("status")
                        if isinstance(terminal_event, Mapping)
                        else None
                    )
                    if durable_status in {
                        "completed",
                        "failed",
                        "interrupted",
                    }:
                        self._durable_terminal_status = str(durable_status)
                        return {"ack": "already-terminal"}
                    raise
                self.interrupted = True
                return {"ack": "interrupt-requested"}

        return self._timed("interrupt", action)

    def _prepare_staged_archive(self) -> None:
        deadline = time.monotonic() + STAGED_ARCHIVE_TERMINAL_TIMEOUT_SECONDS
        while True:
            with self._boundary_lock:
                if self._durable_terminal_status in {
                    "completed",
                    "failed",
                    "interrupted",
                }:
                    self._bind_archive_terminal_evidence_locked()
                    return
                thread, _latency = self.server.read_thread(self.thread_id)
                self.last_thread = thread
                self.reported_session_path = (
                    thread.get("path") or self.reported_session_path
                )
                boundary = self._capture_trusted_boundary(allow_pending=True)
                terminal_event = boundary.get("terminal_event")
                durable_status = (
                    terminal_event.get("status")
                    if isinstance(terminal_event, Mapping)
                    else None
                )
                if durable_status in {"completed", "failed", "interrupted"}:
                    self._durable_terminal_status = str(durable_status)
                    self._bind_archive_terminal_evidence_locked()
                    return
                if boundary.get("available") is not True and self.interrupted:
                    # Preserve the fail-closed containment path when an accepted
                    # interrupt cannot be materialized in session telemetry.
                    return
            if time.monotonic() >= deadline:
                raise AppServerError(
                    f"archive-before-durable-terminal:{durable_status}"
                )
            time.sleep(STAGED_ARCHIVE_TERMINAL_POLL_SECONDS)

    def _bind_archive_terminal_evidence_locked(self) -> None:
        if (
            self._durable_terminal_status
            not in {"completed", "failed", "interrupted"}
            or self.turn_id is None
            or self._session_source_identity_sha256 is None
            or self._session_boundary_baseline is None
        ):
            raise AppServerError("archive-terminal-evidence-incomplete")
        self._archive_terminal_evidence_sha256 = canonical_sha256(
            {
                "thread_id": self.thread_id,
                "turn_id": self.turn_id,
                "durable_terminal_status": self._durable_terminal_status,
                "session_source_identity_sha256": (
                    self._session_source_identity_sha256
                ),
                "terminal_boundary": dict(self._session_boundary_baseline),
            }
        )

    def _record_staged_archive_containment(self, _latency_ms: float) -> None:
        evidence_sha256 = self._archive_terminal_evidence_sha256
        recorder = getattr(
            self.server,
            "record_terminal_archive_containment",
            None,
        )
        if evidence_sha256 is None or not callable(recorder):
            return
        if self.turn_id is None:
            raise AppServerError("archive-terminal-turn-id-missing")
        recorder(
            self.thread_id,
            self.turn_id,
            terminal_evidence_sha256=evidence_sha256,
        )

    def finalize(self, *, control_action: str, **_kwargs: Any) -> dict[str, Any]:
        def action() -> dict[str, Any]:
            write_private_artifact(
                self.record_dir / f"{self.thread_id}-finalize-{control_action}.json",
                {
                    "thread_id": self.thread_id,
                    "turn_id": self.turn_id,
                    "control_action": control_action,
                    "control_turn_id": self.control_turn_identity(),
                },
            )
            if control_action not in {
                "worker-completed",
                "interrupt-confirmed",
            }:
                return {"ack": control_action}
            with self._boundary_lock:
                if self._staged_archive is not None:
                    raise AppServerError("staged-archive-already-bound")
                self._boundary_phase = "closing"
                staged_archive = StagedThreadArchive(
                    self.server,
                    self.thread_id,
                    prepare=self._prepare_staged_archive,
                    after_archive=self._record_staged_archive_containment,
                )
                self._staged_archive = staged_archive
            staged_archive.start()
            self._archive_observation_deadline_ns = self._monotonic_ns() + int(
                STAGED_ARCHIVE_TERMINAL_TIMEOUT_SECONDS * 1_000_000_000
            )
            return {
                "ack": control_action,
                "close_wait_required": True,
            }

        return self._timed("finalize", action)

    def close(self, **_kwargs: Any) -> dict[str, Any]:
        def action() -> dict[str, Any]:
            if self._staged_archive is None:
                raise AppServerError("close-before-staged-archive")
            if not self._staged_archive.completion_ready():
                return {
                    "ack": "close-pending",
                    "close_wait_required": True,
                }
            self._staged_archive.require_complete(timeout_seconds=0.0)
            if (
                self._session_source_identity_sha256 is None
                and self._session_boundary_baseline is None
            ):
                # An interrupted, never-materialized boundary has no file to
                # relocate. The accepted archive RPC and same-process
                # containment proof remain its only truthful closure evidence.
                self.archived = True
                return {"ack": "closed"}
            try:
                located = locate_unique_session(
                    self.server.codex_home,
                    self.thread_id,
                )
            except NativeSessionBoundaryError as exc:
                if (
                    str(exc) == "trusted session file is missing"
                    and self._archive_observation_deadline_ns is not None
                    and self._monotonic_ns()
                    < self._archive_observation_deadline_ns
                ):
                    return {
                        "ack": "close-pending",
                        "close_wait_required": True,
                    }
                raise AppServerError(
                    f"staged-archive-observation-invalid:{exc}"
                ) from exc
            if located.store != "archived_sessions":
                if (
                    self._archive_observation_deadline_ns is not None
                    and self._monotonic_ns()
                    < self._archive_observation_deadline_ns
                ):
                    return {
                        "ack": "close-pending",
                        "close_wait_required": True,
                    }
                raise AppServerError("staged-archive-relocation-not-observed")
            if (
                self._session_source_identity_sha256 is not None
                and located.source_identity_sha256
                != self._session_source_identity_sha256
            ):
                raise AppServerError("staged-archive-source-identity-changed")
            self.reported_session_path = str(located.path)
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
        if self._workspace_baseline is not None:
            if (
                canonical_sha256(self._workspace_baseline)
                != self._workspace_baseline_sha256
            ):
                raise AppServerError("workspace-baseline-mutated")
            baseline = copy.deepcopy(self._workspace_baseline)
            caps = baseline["caps"]
            current = capture_workspace_baseline(
                self.worktree,
                allowed_paths=list(baseline["allowed_paths"]),
                include_untracked=True,
                max_files=int(caps["max_files"]),
                max_bytes=int(caps["max_bytes"]),
                max_seconds=float(caps["max_seconds"]),
            )
            report = compare_workspace_baseline(
                baseline,
                current,
                allowed_paths=list(baseline["allowed_paths"]),
            )
            if report.get("incomplete") or report.get("attribution_ambiguous"):
                raise AppServerError("workspace-baseline-comparison-incomplete")
            mutations = report.get("mutations")
            if not isinstance(mutations, list) or any(
                not isinstance(item, Mapping)
                or not isinstance(item.get("path"), str)
                or not item["path"]
                for item in mutations
            ):
                raise AppServerError("workspace-baseline-comparison-invalid")
            return sorted({str(item["path"]) for item in mutations})
        # No bound baseline: report dirty paths from an inert capture, never
        # from git status, which would run the worktree's own config.
        state = capture_tracked_workspace_state(
            self.worktree, include_untracked=True, include_content_fingerprints=False
        )
        if state.get("error") or state.get("incomplete"):
            raise AppServerError("workspace-status-incomplete")
        if not cleanliness_established(state):
            # Empty raw status is not a clean worktree when Git conversions
            # could apply; without a bound baseline that cannot be settled.
            raise AppServerError("workspace-cleanliness-unknown")
        return sorted({status_path(line) for line in state["tracked_status"]})

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

    def _turn_started_notification_observed_locked(self) -> bool:
        self._pending_window_is_open_locked()
        for message in self.server.notifications(self.thread_id, "turn/started"):
            params = (
                message.get("params")
                if isinstance(message.get("params"), Mapping)
                else {}
            )
            turn = params.get("turn") if isinstance(params.get("turn"), Mapping) else {}
            if turn.get("id") == self.turn_id:
                return True
        self._pending_window_is_open_locked()
        return False

    def _fresh_nonterminal_thread_locked(self) -> bool:
        self._pending_window_is_open_locked()
        # turn/start acknowledges the submission before the app-server is
        # necessarily ready to project that turn through thread/read.  The
        # exact turn/started notification is the trusted readiness witness.
        # Until it arrives, retain a nonattesting pending boundary and do not
        # race thread/read against the still-initializing turn.
        if not self._turn_started_notification_observed_locked():
            return False
        try:
            thread, _latency = self.server.read_thread(self.thread_id)
        except AppServerRpcError as exc:
            if exc.method != "thread/read" or exc.code != -32603:
                raise
            # turn/started can precede readable thread projection.  While the
            # bounded materialization window remains open, keep this state
            # nonattesting instead of turning the expected startup race into
            # control loss.
            self._pending_window_is_open_locked()
            return False
        if thread.get("id") != self.thread_id:
            raise AppServerError("post-submission-thread-read-identity-mismatch")
        self.last_thread = thread
        self.reported_session_path = thread.get("path") or self.reported_session_path
        self._pending_window_is_open_locked()
        return True

    def _registered_tool_projector(self):
        return None

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
                tool_transport=self.tool_transport,
                expected_workdir=self.worktree,
                registered_tool_projector=self._registered_tool_projector(),
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
            if not self._fresh_nonterminal_thread_locked():
                boundary["observation_type"] = (
                    "post-submission-turn-start-pending-nonattesting"
                )
                return boundary
            boundary = session_boundary_summary(
                self.server.codex_home,
                self.thread_id,
                None,
                turn_id=self.turn_id,
                baseline=None,
                allow_unmaterialized=True,
                expected_source_identity_sha256=None,
                tool_transport=self.tool_transport,
                expected_workdir=self.worktree,
                registered_tool_projector=self._registered_tool_projector(),
            )
            if boundary["available"]:
                return self._record_complete_boundary_locked(boundary)
            if not self._fresh_nonterminal_thread_locked():
                boundary["observation_type"] = (
                    "post-submission-turn-start-pending-nonattesting"
                )
                return boundary
            boundary["observation_type"] = (
                "post-submission-unmaterialized-nonattesting-nonaccepting"
            )
            return boundary

    def _trusted_summary(self, *, allow_pending: bool = True) -> dict[str, Any]:
        boundary = self._capture_trusted_boundary(allow_pending=allow_pending)
        items = turn_items(self.last_thread, self.turn_id)
        item_types = [str(item.get("type")) for item in items if item.get("type")]
        projected_tool_calls = sum(
            item_type in OPERATIVE_ITEM_TYPES for item_type in item_types
        )
        violations = self._observe_forbidden_tool_activity(boundary)
        compactions = item_types.count("contextCompaction") + len(
            self.server.notifications(self.thread_id, "thread/compacted")
        )
        final_hash, final_matches = self.final_message_observation()
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
        requested_model = getattr(self.server, "requested_model", EXACT_MODEL)
        requested_effort = getattr(self.server, "reasoning_effort", "low")
        model_exact = (
            boundary.get("available") is True
            and models == [requested_model]
            and efforts == [requested_effort]
        )
        projected_status = turn_status(self.last_thread, self.turn_id)
        terminal_event = boundary.get("terminal_event")
        durable_status = (
            terminal_event.get("status")
            if isinstance(terminal_event, Mapping)
            else None
        )
        if durable_status in {"completed", "failed", "interrupted"}:
            self._durable_terminal_status = str(durable_status)
        trusted_tool_calls = int(boundary.get("trusted_tool_calls", 0))
        return {
            "thread_id": self.thread_id,
            "turn_id": self.turn_id,
            "thread_start_model": self.thread_response.get("model"),
            "thread_start_model_provider": self.thread_response.get("modelProvider"),
            "turn_status": durable_status,
            "projected_turn_status": projected_status,
            "durable_terminal_event": terminal_event,
            "session_boundary": boundary,
            "model_exact": model_exact,
            "reroute_count": len(reroutes),
            "compactions": compactions,
            "tool_calls": trusted_tool_calls,
            "completed_tool_calls": int(
                boundary.get("trusted_completed_tool_calls", 0)
            ),
            "projected_tool_calls": projected_tool_calls,
            "trusted_tool_evidence_sha256": list(
                boundary.get("trusted_tool_evidence_sha256", [])
            ),
            "trusted_tool_names": list(boundary.get("trusted_tool_names", [])),
            "trusted_tool_activity": list(
                boundary.get("trusted_tool_activity", [])
            ),
            "trusted_tool_receipts": list(
                boundary.get("trusted_tool_receipts", [])
            ),
            "trusted_tool_trace_sha256": boundary.get(
                "trusted_tool_trace_sha256"
            ),
            "trusted_tool_authority_receipts": list(
                boundary.get("trusted_tool_authority_receipts", [])
            ),
            "trusted_tool_authority_receipts_sha256": boundary.get(
                "trusted_tool_authority_receipts_sha256"
            ),
            "forbidden_tool_activity": violations,
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

    def _completion_evidence_observation(
        self,
        summary: Mapping[str, Any],
    ) -> dict[str, Any]:
        policy = self.completion_evidence_policy
        required = policy["required_evidence"]
        mutations = list(summary["workspace_mutations"])
        completed_calls = int(summary["completed_tool_calls"])
        observed_hashes = set(summary["trusted_tool_evidence_sha256"])
        observed_predicates: set[str] = set()
        terminal_event = summary.get("durable_terminal_event")
        if (
            summary["session_boundary"].get("available") is True
            and isinstance(terminal_event, Mapping)
            and terminal_event.get("status") == "completed"
        ):
            observed_predicates.add("trusted-terminal-boundary")
        if completed_calls:
            observed_predicates.add("trusted-tool-call")
        if policy["expected_mutation_mode"] == "read-only" and not mutations:
            observed_predicates.add("read-only-workspace-clean")
        if (
            policy["expected_mutation_mode"] == "mutable-isolated"
            and self.expected_mutation is not None
            and mutations == [self.expected_mutation]
        ):
            observed_predicates.add("expected-workspace-mutation")
        missing_predicates = sorted(
            set(required["predicates"]) - observed_predicates
        )
        missing_hashes = sorted(set(required["sha256"]) - observed_hashes)
        minimum_met = completed_calls >= policy["minimum_tool_calls"]
        durable_terminal_event = summary.get("durable_terminal_event")
        trace_observation = self._exact_tool_trace_observation(
            summary["trusted_tool_receipts"],
            terminal=(
                isinstance(durable_terminal_event, Mapping)
                and durable_terminal_event.get("status") == "completed"
            ),
        )
        authority_observation = self._read_only_command_authority_observation(
            summary.get("trusted_tool_authority_receipts", []),
            terminal=(
                isinstance(durable_terminal_event, Mapping)
                and durable_terminal_event.get("status") == "completed"
            ),
        )
        observable_action_required = bool(
            policy["minimum_tool_calls"]
            or set(required["predicates"])
            & {"expected-workspace-mutation", "trusted-tool-call"}
            or required["sha256"]
        )
        return {
            "minimum_tool_calls_met": minimum_met,
            "observed_predicates": sorted(observed_predicates),
            "missing_predicates": missing_predicates,
            "missing_evidence_sha256": missing_hashes,
            "observable_action_required": observable_action_required,
            "exact_tool_trace_observation": trace_observation,
            "read_only_command_authority_observation": authority_observation,
            "satisfied": (
                minimum_met
                and not missing_predicates
                and not missing_hashes
                and trace_observation["satisfied"]
                and authority_observation["satisfied"]
            ),
        }

    def _completion_evidence_reasons(
        self,
        summary: Mapping[str, Any],
        observation: Mapping[str, Any],
    ) -> list[str]:
        if (
            summary["turn_status"] != "completed"
            or not summary["expected_final_token_observed"]
        ):
            return []
        policy = self.completion_evidence_policy
        mutations = summary["workspace_mutations"]
        completed_calls = int(summary["completed_tool_calls"])
        reasons: list[str] = []
        if (
            completed_calls == 0
            and not policy["allow_zero_tool_completion"]
            and (
                policy["minimum_tool_calls"] > 0
                or "trusted-tool-call"
                in policy["required_evidence"]["predicates"]
            )
        ):
            reasons.append("zero-tool-completion")
        if (
            observation["observable_action_required"]
            and completed_calls == 0
            and not mutations
        ):
            reasons.append("premature-completion")
        if not observation["satisfied"]:
            reasons.append("required-evidence-missing")
        return reasons

    def evidence(self) -> dict[str, Any]:
        self._evidence_sequence += 1
        summary = self._trusted_summary()
        status = summary["turn_status"]
        terminal = status in {"completed", "interrupted", "failed"}
        reasons: list[str] = []
        completion_observation = self._completion_evidence_observation(
            summary
        )
        trace_observation = completion_observation[
            "exact_tool_trace_observation"
        ]
        authority_observation = completion_observation[
            "read_only_command_authority_observation"
        ]
        if status == "failed":
            reasons.append("trusted-turn-failed")
        if trace_observation["required"] and trace_observation["mismatch"]:
            reasons.append("exact-tool-trace-mismatch")
        if (
            authority_observation["required"]
            and authority_observation["mismatch"]
        ):
            reasons.append("read-only-command-authority-mismatch")
        if summary["forbidden_tool_activity"]:
            reasons.append("forbidden-tool-activity")
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
        reasons.extend(
            self._completion_evidence_reasons(summary, completion_observation)
        )
        if self.mutable:
            expected_mutations = [self.expected_mutation]
            if (
                mutations
                and (
                    self.turn_id is None
                    or mutations != expected_mutations
                )
            ) or (
                status == "completed"
                and mutations != expected_mutations
            ):
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
            "completion_evidence_policy_sha256": self.completion_evidence_policy_sha256,
            "tool_policy_sha256": self.tool_policy_sha256,
            "preflight_tool_surface_sha256": self.preflight_tool_surface[
                "surface_sha256"
            ],
            "pre_dispatch_tool_surface_sha256": (
                self.pre_dispatch_tool_surface.get("surface_sha256")
                if self.pre_dispatch_tool_surface is not None
                else None
            ),
            "trusted_completed_tool_calls": summary["completed_tool_calls"],
            "trusted_tool_evidence_sha256": summary["trusted_tool_evidence_sha256"],
            "expected_tool_trace_sha256": (
                trace_observation["expected_sha256"]
            ),
            "observed_tool_trace_sha256": (
                trace_observation["observed_sha256"]
            ),
            "exact_tool_trace_status": trace_observation["status"],
            "expected_read_only_command_authority_sha256": (
                authority_observation["expected_sha256"]
            ),
            "observed_read_only_command_authority_sha256": (
                authority_observation["observed_sha256"]
            ),
            "read_only_command_authority_status": authority_observation[
                "status"
            ],
            "forbidden_tool_activity": summary["forbidden_tool_activity"],
            "completion_evidence_satisfied": completion_observation["satisfied"],
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
        state_sha256 = canonical_sha256(state_payload)
        control_loss = (
            status == "failed"
            or "trusted-model-attestation-mismatch" in reasons
        )
        pool_wide_reason_codes = {
            "authority-violation",
            "forbidden-tool-activity",
            "mutation-attribution-ambiguous",
            "read-only-workspace-mutation",
            "security-violation",
            "trusted-model-attestation-mismatch",
        }
        failure_class = (
            "control-security-failure"
            if control_loss or any(reason in pool_wide_reason_codes for reason in reasons)
            else "individual-child-failure"
            if reasons
            else None
        )
        return {
            "state_sha256": state_sha256,
            "usage": usage,
            "protected_fault": bool(reasons),
            "control_loss": control_loss,
            "failure_class": failure_class,
            "recovery_evidence_sha256": state_sha256 if reasons else None,
            "reasons": reasons,
            "session_disposition": session_disposition,
            "artifact_disposition": artifact_disposition,
        }

    def final_summary(self) -> dict[str, Any]:
        summary = self._trusted_summary(allow_pending=False)
        completion_observation = self._completion_evidence_observation(summary)
        summary["completion_evidence_policy"] = self.completion_evidence_policy
        summary[
            "completion_evidence_policy_sha256"
        ] = self.completion_evidence_policy_sha256
        summary["completion_evidence_observation"] = completion_observation
        summary["completion_evidence_satisfied"] = completion_observation["satisfied"]
        trace_observation = completion_observation[
            "exact_tool_trace_observation"
        ]
        summary["expected_tool_trace_sha256"] = (
            trace_observation["expected_sha256"]
        )
        summary["exact_tool_trace_observation"] = trace_observation
        summary["exact_tool_trace_satisfied"] = trace_observation["satisfied"]
        authority_observation = completion_observation[
            "read_only_command_authority_observation"
        ]
        summary["expected_read_only_command_authority_sha256"] = (
            authority_observation["expected_sha256"]
        )
        summary["read_only_command_authority_observation"] = (
            authority_observation
        )
        summary["read_only_command_authority_satisfied"] = (
            authority_observation["satisfied"]
        )
        summary["tool_policy"] = self.tool_policy
        summary["tool_policy_sha256"] = self.tool_policy_sha256
        summary["prompt_preflight"] = self.prompt_preflight
        summary["preflight_tool_surface"] = self.preflight_tool_surface
        summary["pre_dispatch_tool_surface"] = self.pre_dispatch_tool_surface
        summary["override_provenance"] = self.tool_policy["override_provenance"]
        summary["callback_stats"] = {
            name: stats(values) for name, values in sorted(self.callback_latencies.items())
        }
        summary["callback_subphase_stats"] = {
            name: stats(values)
            for name, values in sorted(self.callback_subphase_latencies.items())
        }
        summary["archive_staging"] = (
            self._staged_archive.telemetry()
            if self._staged_archive is not None
            else None
        )
        summary["prompt_sha256"] = sha256_text(self.prompt)
        return summary


def _measure_action_ms(
    action: Callable[[], Any],
    *,
    guard_seconds: float = 0.0,
) -> tuple[Any, float]:
    started = time.monotonic_ns()
    result = action()
    if guard_seconds != 0.0:
        time.sleep(guard_seconds)
    elapsed_ms = (time.monotonic_ns() - started) / 1_000_000
    return result, elapsed_ms


def guarded_measure(
    samples: dict[str, list[float]],
    name: str,
    action: Callable[[], Any],
    *,
    guard_seconds: float = 0.20,
) -> Any:
    result, elapsed_ms = _measure_action_ms(
        action,
        guard_seconds=guard_seconds,
    )
    samples.setdefault(name, []).append(elapsed_ms)
    return result


def pool_sleep(*, seconds: float) -> None:
    """Adapt the coordinator's keyword callback to positional-only time.sleep."""

    time.sleep(seconds)


def matches_exact_namespaced_wire_source(source: Any, expected: str) -> bool:
    """Accept the exact wrapper or the app-server's one-LF wire projection."""

    return isinstance(source, str) and source in {expected, expected + "\n"}


def _run_calibration(
    server: AppServer,
    cwd: Path,
    record_dir: Path,
    owner: Mapping[str, Any],
    *,
    run_nonce: str,
    phase_nonce: str,
    boundary_trackers: list[PreAttestationSessionBoundaryTracker],
    control_turn_id: str = CONTROL_TURN_ID,
    requested_cap: int = LEGACY_CONCURRENT_CAPACITY,
    startup_timeout_seconds: float = CALIBRATION_STARTUP_TIMEOUT_SECONDS,
    materialization_timeout_seconds: float = (
        CALIBRATION_MATERIALIZATION_TIMEOUT_SECONDS
    ),
    pre_allocation_check: Callable[[], None] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    live_availability.require_n1_live()
    if (
        not isinstance(control_turn_id, str)
        or not control_turn_id
        or control_turn_id != control_turn_id.strip()
    ):
        raise AppServerError("capability-control-turn-id-invalid")
    capacity_limits = load_pool_capacity()
    if (
        not capacity_limits.is_released(requested_cap)
        or requested_cap < 2
    ):
        raise AppServerError("capability-requested-cap-invalid")
    expected_model = getattr(server, "requested_model", EXACT_MODEL)
    if not isinstance(expected_model, str) or not expected_model.strip():
        raise AppServerError("capability-requested-model-invalid")
    expected_model = expected_model.strip()
    transport_reader = getattr(server, "operative_tool_transport", None)
    tool_transport = (
        str(transport_reader())
        if callable(transport_reader)
        else DIRECT_TOOL_TRANSPORT
    )
    if tool_transport not in {
        DIRECT_TOOL_TRANSPORT,
        NAMESPACED_EXEC_TOOL_TRANSPORT,
    }:
        raise AppServerError("capability-tool-transport-invalid")
    samples: dict[str, list[float]] = {}
    calibration_arguments = {
        "cmd": "sleep 20",
        "workdir": str(cwd.resolve()),
        "yield_time_ms": 30000,
        "max_output_tokens": 1000,
    }
    calibration_wrapper_source = (
        "const result = await tools.exec_command("
        + json.dumps(
            calibration_arguments,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "); text(JSON.stringify(result));"
    )
    prompt = (
        (
            "Use functions.exec exactly once with this exact source and no other tool: `"
            + calibration_wrapper_source
            + "`. After it finishes, return exactly CAPABILITY_LONG_DONE."
        )
        if tool_transport == NAMESPACED_EXEC_TOOL_TRANSPORT
        else (
            "Use the exec_command tool exactly once to run `sleep 20`. After it finishes, return "
            "exactly CAPABILITY_LONG_DONE. Do not use any other tool."
        )
    )
    calibration_tool_policy = default_tool_policy(
        mutable=False,
        workload_class="safety-canary",
        # The connected-Codex config proof establishes one exact three-tool
        # operative surface. Calibration remains read-only at the sandbox and
        # prompt layers, while using that same proved server surface.
        permitted_tools=["apply_patch", "exec_command", "write_stdin"],
    )
    try:
        calibration_prompt_preflight = require_prompt_preflight(
            prompt, calibration_tool_policy
        )
    except NativeToolIsolationError as exc:
        raise AppServerError(str(exc)) from exc
    calibration_preflight_surface = capture_server_tool_surface(
        server, calibration_tool_policy
    )

    def workspace_snapshot() -> tuple[str, str | None]:
        # Inert digest of the worktree's status and raw inventory.
        try:
            return worktree_state_digest(cwd)
        except WorkspaceInspectionError as exc:
            raise AppServerError("capability-workspace-comparison-failed") from exc

    workspace_monitoring_status, workspace_baseline_sha256 = workspace_snapshot()
    if pre_allocation_check is not None:
        pre_allocation_check()
    allocation_surface = capture_server_tool_surface(
        server, calibration_tool_policy
    )
    try:
        require_unchanged_tool_surface(
            calibration_preflight_surface, allocation_surface
        )
    except NativeToolIsolationError as exc:
        raise AppServerError(str(exc)) from exc
    start_kwargs: dict[str, Any] = {
        "mutable": False,
        "role": "capability-calibration",
    }
    if allocation_surface["server_allowlist_supported"]:
        start_kwargs.update(
            {
                "permitted_tools": list(
                    calibration_tool_policy["permitted_tools"]
                ),
                "allowlist_parameter": allocation_surface[
                    "allowlist_parameter"
                ],
            }
        )
    live_availability.require_n1_live()
    result, preallocation_latency = server.start_thread(cwd, **start_kwargs)
    thread_id = str(result["thread"]["id"])
    guarded_measure(
        samples,
        "arm",
        lambda: (
            result.get("model") == expected_model
            and result.get("thread", {}).get("id") == thread_id
            and not result.get("thread", {}).get("turns")
        )
        or (_ for _ in ()).throw(AppServerError("prearmed-thread-binding-invalid")),
        guard_seconds=0.0,
    )
    calibration_pre_dispatch_surface = capture_server_tool_surface(
        server, calibration_tool_policy
    )
    try:
        require_unchanged_tool_surface(
            calibration_preflight_surface, calibration_pre_dispatch_surface
        )
    except NativeToolIsolationError as exc:
        raise AppServerError(str(exc)) from exc
    notification_floor = server.notification_cursor()
    turn = guarded_measure(
        samples,
        "send_input",
        lambda: server.start_turn(thread_id, prompt),
        guard_seconds=0.0,
    )[0]
    turn_id = str(turn["id"])
    acknowledged_thread = {
        "id": thread_id,
        "turns": [dict(turn)],
    }
    attempt_nonce = str(uuid.uuid4())
    guarded_measure(
        samples,
        "mark_dispatched",
        lambda: write_private_artifact(
            record_dir / "calibration-mark.json",
            {
                "thread_id": thread_id,
                "turn_id": turn_id,
                "control_turn_id": control_turn_id,
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
    notification_shape_evidence: dict[str, Any] | None = None
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
        nonlocal attestation_observed, trusted_source_identity
        nonlocal observed_prefix, notification_shape_evidence
        events = server.notification_events(
            thread_id,
            turn_id,
            after_sequence=notification_floor,
        )
        if events:
            notification_shape_evidence = privacy_safe_notification_shape(
                events,
                connection_epoch_sha256=server.connection_epoch_sha256,
                thread_id=thread_id,
                turn_id=turn_id,
            )
            write_private_artifact(
                record_dir / "calibration-notification-shape.json",
                notification_shape_evidence,
            )
        if guarded_recovery_read:
            if tool_transport == NAMESPACED_EXEC_TOOL_TRANSPORT:
                raise AppServerError(
                    "capability-namespaced-read-recovery-unexpected"
                )
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
        elif tool_transport == NAMESPACED_EXEC_TOOL_TRANSPORT:
            # The app-server can serialize thread/read behind an active
            # namespaced dynamic tool call.  That would hide the in-progress
            # window until the nested tool completes.  Use the already trusted
            # turn/start acknowledgement while the pinned session JSONL and
            # connection-local item/started notification independently prove
            # exact live activity below.  No RPC is issued on this path before
            # the deliberate interrupt.
            thread = dict(acknowledged_thread)
        else:
            thread, _latency = server.read_thread(
                thread_id,
                timeout=read_timeout_seconds,
            )
        if not events:
            events = server.notification_events(
                thread_id,
                turn_id,
                after_sequence=notification_floor,
            )
            if events:
                notification_shape_evidence = privacy_safe_notification_shape(
                    events,
                    connection_epoch_sha256=server.connection_epoch_sha256,
                    thread_id=thread_id,
                    turn_id=turn_id,
                )
                write_private_artifact(
                    record_dir / "calibration-notification-shape.json",
                    notification_shape_evidence,
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
        if not materialized and tool_transport != NAMESPACED_EXEC_TOOL_TRANSPORT:
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
        if located is None:
            record_nonterminal_projection(
                phase=phase,
                projected_status=projected_status,
                boundary_available=False,
                ready=False,
                source_identity_sha256=None,
                previous_boundary=previous_boundary,
                boundary=boundary,
            )
            return thread, None
        contexts: list[tuple[int, Mapping[str, Any]]] = []
        if materialized:
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
                context.get("model") != expected_model
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
            effective_projected_status = (
                "active"
                if (
                    tool_transport == NAMESPACED_EXEC_TOOL_TRANSPORT
                    and observation is not None
                )
                else projected_status
            )
            usable = record_nonterminal_projection(
                phase=phase,
                projected_status=effective_projected_status,
                boundary_available=True,
                ready=observation is not None,
                source_identity_sha256=located.source_identity_sha256,
                previous_boundary=previous_boundary,
                boundary=boundary,
            )
            return thread, observation if usable else None
        started_commands = []
        completed_commands = []
        expected_item_types = (
            {"dynamicToolCall", "commandExecution"}
            if tool_transport == NAMESPACED_EXEC_TOOL_TRANSPORT
            else {"commandExecution"}
        )
        for event in events:
            params = event["params"]
            item = params.get("item") if isinstance(params.get("item"), Mapping) else {}
            if item.get("type") not in expected_item_types:
                continue
            if event.get("method") == "item/started":
                started_commands.append((event, item))
            elif event.get("method") == "item/completed":
                completed_commands.append((event, item))
        if len(started_commands) > 1:
            raise AppServerError("capability-command-start-not-singular")
        if completed_commands:
            raise AppServerError("capability-command-completed-before-interrupt")
        if not started_commands or (
            tool_transport == DIRECT_TOOL_TRANSPORT and not contexts
        ):
            return finish(None)
        context_index: int | None = None
        if contexts:
            context_index, _context = trusted_turn_context(
                records,
                turn_id=turn_id,
                model=expected_model,
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
        command_projection_type = command.get("type")
        if command_projection_type == "commandExecution":
            if "source" not in command:
                raise AppServerError("capability-command-source-missing")
            if command.get("source") != "unifiedExecStartup":
                raise AppServerError("capability-command-source-invalid")
            command_source = "unifiedExecStartup"
        elif command_projection_type == "dynamicToolCall":
            if (
                command.get("namespace") != "functions"
                or command.get("tool") != "exec"
            ):
                raise AppServerError("capability-namespaced-command-identity-invalid")
            command_source = "namespacedExecStartup"
        else:
            raise AppServerError("capability-command-projection-invalid")
        if command.get("status") in {"completed", "failed", "declined"}:
            raise AppServerError(
                f"capability-command-terminal-before-interrupt:{command.get('status')}"
            )
        if command.get("status") != "inProgress":
            return finish(None)
        function_calls: list[tuple[int, Mapping[str, Any]]] = []
        function_outputs: list[tuple[int, Mapping[str, Any]]] = []
        competing_calls: list[int] = []
        record_floor = context_index + 1 if context_index is not None else 0
        for index, record in enumerate(records[record_floor:], record_floor):
            if record.get("type") != "response_item" or not isinstance(
                record.get("payload"), Mapping
            ):
                continue
            payload = record["payload"]
            payload_type = payload.get("type")
            if tool_transport == DIRECT_TOOL_TRANSPORT:
                if payload_type in {"function_call", "functionCall"}:
                    if payload.get("name") == "exec_command":
                        function_calls.append((index, payload))
                    else:
                        competing_calls.append(index)
                elif payload_type in {"function_call_output", "functionCallOutput"}:
                    function_outputs.append((index, payload))
                elif payload_type in {"custom_tool_call", "customToolCall"}:
                    competing_calls.append(index)
            else:
                if payload_type in {"custom_tool_call", "customToolCall"}:
                    if payload.get("name") == "exec":
                        function_calls.append((index, payload))
                    else:
                        competing_calls.append(index)
                elif payload_type in {
                    "custom_tool_call_output",
                    "customToolCallOutput",
                }:
                    function_outputs.append((index, payload))
                elif payload_type in {"function_call", "functionCall"}:
                    competing_calls.append(index)
        if competing_calls or len(function_calls) > 1:
            raise AppServerError("capability-function-call-not-singular")
        if function_outputs:
            raise AppServerError("capability-function-output-before-interrupt")
        notification_first = (
            tool_transport == NAMESPACED_EXEC_TOOL_TRANSPORT
            and not function_calls
        )
        if not function_calls and not notification_first:
            return finish(None)
        function_call_index: int | None = None
        function_call: Mapping[str, Any] | None = None
        call_id: str | None = None
        if function_calls:
            function_call_index, function_call = function_calls[0]
            call_id = function_call.get("call_id") or function_call.get("callId")
            if not isinstance(call_id, str) or not call_id:
                raise AppServerError("capability-function-call-identity-invalid")
        if tool_transport == DIRECT_TOOL_TRANSPORT:
            assert function_call is not None
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
            rendered_command = command.get("command")
        else:
            if command_projection_type == "dynamicToolCall":
                source = (
                    command.get("arguments")
                    if notification_first
                    else function_call.get("input")
                    if function_call is not None
                    else None
                )
                try:
                    decoded = decode_namespaced_exec_source(source)
                except ValueError as exc:
                    raise AppServerError(
                        f"capability-namespaced-function-call-invalid:{exc}"
                    ) from exc
                if decoded.get("tool") != "exec_command":
                    raise AppServerError("capability-function-call-command-missing")
                parsed_arguments = decoded["arguments"]
                if not matches_exact_namespaced_wire_source(
                    source, calibration_wrapper_source
                ):
                    raise AppServerError("capability-namespaced-source-digest-mismatch")
                if command.get("arguments") != source:
                    raise AppServerError(
                        "capability-namespaced-notification-source-mismatch"
                    )
                rendered_command_sha256 = domain_sha256(
                    {"wrapper_source_sha256": decoded["source_sha256"]},
                    domain="native-capability-namespaced-wrapper",
                )
            else:
                parsed_arguments = dict(calibration_arguments)
                if function_call is not None:
                    try:
                        decoded = decode_namespaced_exec_source(
                            function_call.get("input")
                        )
                    except ValueError as exc:
                        raise AppServerError(
                            f"capability-namespaced-function-call-invalid:{exc}"
                        ) from exc
                    if (
                        decoded.get("tool") != "exec_command"
                        or decoded.get("arguments") != calibration_arguments
                        or not matches_exact_namespaced_wire_source(
                            function_call.get("input"), calibration_wrapper_source
                        )
                    ):
                        raise AppServerError(
                            "capability-namespaced-source-digest-mismatch"
                        )
                try:
                    rendered_command_sha256 = validate_capability_rendered_command(
                        command.get("command"), raw_command="sleep 20"
                    )
                except NativeCanaryContractError as exc:
                    raise AppServerError(f"capability-{exc}") from exc
        if sha256_text(str(parsed_arguments["cmd"])) != sha256_text("sleep 20"):
            raise AppServerError("capability-function-call-command-digest-mismatch")
        if tool_transport == DIRECT_TOOL_TRANSPORT:
            try:
                rendered_command_sha256 = validate_capability_rendered_command(
                    rendered_command, raw_command=str(parsed_arguments["cmd"])
                )
            except NativeCanaryContractError as exc:
                raise AppServerError(f"capability-{exc}") from exc
        command_cwd = (
            command.get("cwd")
            if command_projection_type == "commandExecution"
            else parsed_arguments.get("workdir")
        )
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
        function_call_id_sha256 = (
            domain_sha256(
                {"call_id": call_id}, domain="session-exec-command-call-id"
            )
            if call_id is not None
            else None
        )
        raw_command_sha256 = sha256_text(str(parsed_arguments["cmd"]))
        execution_correlation_sha256 = materialization_liveness_correlation(
            connection_epoch_sha256=str(start_event["connection_epoch_sha256"]),
            session_id=thread_id,
            thread_id=thread_id,
            turn_id=turn_id,
            command_item_id_sha256=command_item_id_sha256,
            notification_sequence=int(start_event["sequence"]),
            notification_received_monotonic_ns=int(
                start_event["received_monotonic_ns"]
            ),
            notification_started_at_ms=started_at_ms,
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
            "correlation_mode": (
                "notification-first"
                if notification_first
                else "session-and-notification"
            ),
            "notification_command_semantic_match": True,
            "notification_workspace_match": True,
            "command_source": command_source,
            "command_status": "inProgress",
            "started_event_count": 1,
            "function_call_count": 0 if notification_first else 1,
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
    startup_samples: dict[str, list[float]] = {}
    poll_started: list[float] = []
    if startup_timeout_seconds < 1.0:
        raise AppServerError("capability-startup-timeout-invalid")
    if materialization_timeout_seconds < 1.0:
        raise AppServerError("capability-materialization-timeout-invalid")
    deadline = time.monotonic() + startup_timeout_seconds
    materialization_deadline_armed = False

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

    def remaining_recovery_seconds() -> float:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AppServerError("capability-materialization-deadline-exceeded")
        return remaining

    while time.monotonic() < deadline and len(observations) < 2:
        poll_start = time.monotonic()
        certification_armed = bool(observations)
        if certification_armed:
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
                remaining_before_attempt = remaining_recovery_seconds()
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
        sample_sink = samples if certification_armed else startup_samples
        try:
            thread, observation = guarded_measure(
                sample_sink,
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
            sample_sink.setdefault("check", []).append(exc.latency_ms)
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
            remaining_before_scheduling = remaining_recovery_seconds()
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
        observed_after_read = time.monotonic()
        if observed_after_read >= deadline:
            exc = AppServerError(
                "capability-materialization-deadline-exceeded"
            )
            if read_recovery.get("token_consumed") is True:
                raise attach_recovery_fault(exc)
            raise exc
        if not certification_armed and observation is not None:
            # The establishing read belongs to startup. Arm operative cadence
            # only after its exact observation is complete.
            poll_started.append(observed_after_read)
        if replacement_attempt:
            try:
                remaining_recovery_seconds()
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
                deadline = (
                    observed_after_read + materialization_timeout_seconds
                )
                materialization_deadline_armed = True
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
    if len(observations) != 2 or not materialization_deadline_armed:
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
        if time.monotonic() >= deadline:
            exc = AppServerError(
                "capability-materialization-deadline-exceeded"
            )
            if read_recovery.get("token_consumed") is True:
                raise attach_recovery_fault(exc)
            raise exc
        last_threads[thread_id] = pre_thread
        if pre_interrupt is None:
            time.sleep(
                max(
                    0.0,
                    CALIBRATION_POLL_INTERVAL_SECONDS
                    - (time.monotonic() - poll_start),
                )
            )
    observed_poll_gaps = [
        later - earlier
        for earlier, later in zip(poll_started, poll_started[1:])
    ]
    if any(
        gap > CALIBRATION_POLL_GAP_MAX_SECONDS
        for gap in observed_poll_gaps
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

    previous_boundary = dict(observed_prefix)
    append_control_observation(
        phase="terminal",
        projected_status=normalize_projected_status(
            turn_status(last_threads[thread_id], turn_id)
        ),
        durable_status="interrupted",
        source_identity_sha256=trusted_source_identity,
        previous_boundary=previous_boundary,
        boundary=observed_prefix,
        decision="terminal-accepted",
    )

    staged_archive = StagedThreadArchive(server, thread_id)

    def persist_and_stage_archive() -> None:
        write_private_artifact(
            record_dir / "calibration-finalize.json",
            {
                "thread_id": thread_id,
                "turn_id": turn_id,
                "control_turn_id": control_turn_id,
            },
        )
        staged_archive.start()

    guarded_measure(
        samples,
        "finalize",
        persist_and_stage_archive,
        guard_seconds=0.0,
    )
    time.sleep(POOL_POLL_INTERVAL_MS / 1000)
    guarded_measure(
        samples,
        "close",
        lambda: staged_archive.require_complete(),
        guard_seconds=0.0,
    )
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
    if trusted_source_identity is None:
        raise AppServerError("capability-session-source-identity-not-pinned")
    if pre_interrupt is None:
        raise AppServerError("capability-terminal-correlation-liveness-missing")
    terminal_context_index, _terminal_context = trusted_turn_context(
        terminal_records,
        turn_id=turn_id,
        model=expected_model,
        effort="low",
    )
    terminal_calls: list[tuple[int, Mapping[str, Any]]] = []
    terminal_competing_calls: list[int] = []
    for index, record in enumerate(
        terminal_records[terminal_context_index + 1 :],
        terminal_context_index + 1,
    ):
        if record.get("type") != "response_item" or not isinstance(
            record.get("payload"), Mapping
        ):
            continue
        payload = record["payload"]
        payload_type = payload.get("type")
        if tool_transport == DIRECT_TOOL_TRANSPORT:
            if payload_type in {"function_call", "functionCall"}:
                if payload.get("name") == "exec_command":
                    terminal_calls.append((index, payload))
                else:
                    terminal_competing_calls.append(index)
            elif payload_type in {"custom_tool_call", "customToolCall"}:
                terminal_competing_calls.append(index)
        else:
            if payload_type in {"custom_tool_call", "customToolCall"}:
                if payload.get("name") == "exec":
                    terminal_calls.append((index, payload))
                else:
                    terminal_competing_calls.append(index)
            elif payload_type in {"function_call", "functionCall"}:
                terminal_competing_calls.append(index)
    if terminal_competing_calls or len(terminal_calls) != 1:
        raise AppServerError("capability-terminal-function-call-not-singular")
    terminal_function_index, terminal_function = terminal_calls[0]
    terminal_call_id = terminal_function.get("call_id") or terminal_function.get("callId")
    if not isinstance(terminal_call_id, str) or not terminal_call_id:
        raise AppServerError("capability-terminal-function-call-identity-invalid")
    if tool_transport == DIRECT_TOOL_TRANSPORT:
        terminal_arguments_text = terminal_function.get("arguments")
        try:
            terminal_arguments = json.loads(terminal_arguments_text)
        except (TypeError, json.JSONDecodeError) as exc:
            raise AppServerError(
                "capability-terminal-function-call-arguments-invalid"
            ) from exc
        if terminal_arguments != {"cmd": "sleep 20"}:
            raise AppServerError("capability-terminal-function-call-command-mismatch")
    else:
        terminal_source = terminal_function.get("input")
        try:
            terminal_decoded = decode_namespaced_exec_source(terminal_source)
        except ValueError as exc:
            raise AppServerError(
                f"capability-terminal-namespaced-function-call-invalid:{exc}"
            ) from exc
        if (
            not matches_exact_namespaced_wire_source(
                terminal_source, calibration_wrapper_source
            )
            or terminal_decoded.get("tool") != "exec_command"
            or terminal_decoded.get("arguments") != calibration_arguments
        ):
            raise AppServerError("capability-terminal-namespaced-source-mismatch")
    terminal_function_call_id_sha256 = domain_sha256(
        {"call_id": terminal_call_id}, domain="session-exec-command-call-id"
    )
    terminal_execution_correlation_sha256 = materialization_execution_correlation(
        connection_epoch_sha256=server.connection_epoch_sha256,
        session_id=thread_id,
        thread_id=thread_id,
        turn_id=turn_id,
        command_item_id_sha256=pre_interrupt["command_item_id_sha256"],
        function_call_id_sha256=terminal_function_call_id_sha256,
        notification_sequence=pre_interrupt["notification_sequence"],
        notification_received_monotonic_ns=pre_interrupt[
            "notification_received_monotonic_ns"
        ],
        notification_started_at_ms=pre_interrupt["notification_started_at_ms"],
        turn_context_record_index=terminal_context_index,
        function_call_record_index=terminal_function_index,
        rendered_command_sha256=pre_interrupt["rendered_command_sha256"],
        raw_command_sha256=sha256_text("sleep 20"),
    )
    terminal_execution_correlation = {
        "turn_context_record_index": terminal_context_index,
        "function_call_record_index": terminal_function_index,
        "function_call_id_sha256": terminal_function_call_id_sha256,
        "command_item_id_sha256": pre_interrupt["command_item_id_sha256"],
        "notification_sequence": pre_interrupt["notification_sequence"],
        "notification_received_monotonic_ns": pre_interrupt[
            "notification_received_monotonic_ns"
        ],
        "notification_started_at_ms": pre_interrupt["notification_started_at_ms"],
        "rendered_command_sha256": pre_interrupt["rendered_command_sha256"],
        "execution_correlation_sha256": terminal_execution_correlation_sha256,
    }
    if notification_shape_evidence is None:
        raise AppServerError("capability-notification-shape-evidence-missing")
    read_recovery_telemetry = seal_calibration_read_recovery_telemetry(
        read_recovery
    )
    materialization = seal_materialization_evidence(
        {
            "evidence_type": MATERIALIZATION_EVIDENCE_TYPE,
            "version": 5,
            "schema": MATERIALIZATION_EVIDENCE_SCHEMA,
            "evidence_id": f"materialization-{uuid.uuid4()}",
            "run_nonce": run_nonce,
            "attempt_nonce": attempt_nonce,
            "phase_nonce": phase_nonce,
            "session_id": thread_id,
            "thread_id": thread_id,
            "turn_id": turn_id,
            "requested_model": expected_model,
            "attested_model": expected_model,
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
            "notification_shape": notification_shape_evidence,
            "terminal_execution_correlation": terminal_execution_correlation,
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
    record_terminal_containment = getattr(
        server,
        "record_terminal_archive_containment",
        None,
    )
    if callable(record_terminal_containment):
        record_terminal_containment(
            thread_id,
            turn_id,
            terminal_evidence_sha256=materialization["evidence_sha256"],
        )

    scheduler_samples: list[float] = []
    children = [
        {
            "child_id": f"calibration-{index}",
            "next_deadline_ns": 1_000_000_000,
        }
        for index in range(requested_cap)
    ]
    cursor = 0

    def measure_scheduler_selection() -> None:
        nonlocal cursor
        selected = select_earliest_deadline(children, cursor=cursor)
        if selected is None:
            raise AppServerError("scheduler-calibration-selection-missing")
        cursor = selected.next_cursor
        time.sleep(0.05)

    for _index in range(4):
        _result, elapsed_ms = _measure_action_ms(measure_scheduler_selection)
        scheduler_samples.append(elapsed_ms)

    measured_at = utc_now()
    receipt = seal_artifact(
        {
            "receipt_type": CAPABILITY_RECEIPT_TYPE,
            "version": 1,
            "schema": CAPABILITY_RECEIPT_SCHEMA,
            "adapter_id": "native-multi-agent-v1",
            "adapter_version": (
                server.capability_adapter_version()
                if hasattr(server, "capability_adapter_version")
                else "codex-app-server-0.144.5"
            ),
            "execution_surface": "connected-codex",
            "host_identity": dict(owner),
            "control_turn_id": control_turn_id,
            "measured_at": iso(measured_at),
            "expires_at": iso(measured_at + dt.timedelta(minutes=55)),
            "sample_count": min(len(values) for values in samples.values()),
            "requested_cap": requested_cap,
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
    overhead_max = receipt["certification"]["certified_scheduler_overhead_ms"]
    try:
        proof = scheduling_budget_proof(
            requested_workers=receipt["requested_cap"],
            certified_callback_max_ms=ceilings,
            certified_scheduler_overhead_ms=overhead_max,
            poll_interval_ms=POOL_POLL_INTERVAL_MS,
        )
    except PoolSchedulabilityError as error:
        raise AppServerError(
            "capability-schedulability-input-invalid"
        ) from error
    if not proof.accepted:
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
            tool_transport=tool_transport,
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
        "tool_policy": calibration_tool_policy,
        "tool_policy_sha256": canonical_sha256(calibration_tool_policy),
        "prompt_preflight": calibration_prompt_preflight,
        "preflight_tool_surface": calibration_preflight_surface,
        "pre_dispatch_tool_surface": calibration_pre_dispatch_surface,
        "override_provenance": calibration_tool_policy["override_provenance"],
    }
    if summary["thread_start_model"] != expected_model:
        raise AppServerError("capability-thread-start-model-mismatch")
    if summary["session_boundary"].get("attested_models") != [expected_model]:
        raise AppServerError("capability-session-model-mismatch")
    if summary["session_boundary"].get("attested_efforts") != ["low"]:
        raise AppServerError("capability-session-effort-mismatch")
    if summary["compactions"] or summary["reroute_count"]:
        raise AppServerError("capability-session-containment-failed")
    trusted_receipts = boundary.get("trusted_tool_receipts", [])
    trusted_activity = boundary.get("trusted_tool_activity", [])
    expected_arguments = (
        calibration_arguments
        if tool_transport == NAMESPACED_EXEC_TOOL_TRANSPORT
        else {"cmd": "sleep 20"}
    )
    permitted_interrupted_results = (
        {("unpaired", "unpaired-call"), ("paired", "paired-interrupted")}
        if tool_transport == NAMESPACED_EXEC_TOOL_TRANSPORT
        else {("paired", "paired-interrupted")}
    )
    observed_interrupted_result = (
        (
            trusted_receipts[0].get("pairing_status"),
            trusted_receipts[0].get("result_kind"),
        )
        if type(trusted_receipts) is list and len(trusted_receipts) == 1
        else (None, None)
    )
    expected_activity_tool = (
        "exec_command"
        if observed_interrupted_result == ("unpaired", "unpaired-call")
        else "telemetry_anomaly.exec_command"
    )
    expected_interrupted_result = (
        type(trusted_receipts) is list
        and len(trusted_receipts) == 1
        and trusted_receipts[0].get("sequence") == 0
        and trusted_receipts[0].get("tool") == "exec_command"
        and trusted_receipts[0].get("canonical_argument_hash")
        == canonical_argument_hash(expected_arguments)
        and trusted_receipts[0].get("determinable_target_paths") == []
        and observed_interrupted_result in permitted_interrupted_results
        and trusted_receipts[0].get("exit_code") is None
        and type(trusted_activity) is list
        and len(trusted_activity) == 1
        and trusted_activity[0].get("tool") == expected_activity_tool
        and (
            trusted_activity[0].get("pairing_status"),
            trusted_activity[0].get("result_kind"),
        )
        in permitted_interrupted_results
        and boundary.get("terminal_event") == confirmed_terminal_event
    )
    if not expected_interrupted_result:
        raise AppServerError("capability-interrupted-tool-result-invalid")
    calibration_violations = forbidden_tool_activity(
        trusted_activity, calibration_tool_policy
    )
    expected_interrupted_violation = (
        []
        if observed_interrupted_result == ("unpaired", "unpaired-call")
        else [
            {
                "tool": trusted_activity[0]["tool"],
                "evidence_sha256": trusted_activity[0]["evidence_sha256"],
            }
        ]
    )
    if calibration_violations != expected_interrupted_violation:
        raise AppServerError("capability-interrupted-tool-result-invalid")
    summary["forbidden_tool_activity"] = []

    evidence = {
        "thread_preallocation_stats": stats([preallocation_latency]),
        "guard_band_ms": {"callbacks": 0, "scheduler_overhead": 50},
        "startup_check_stats": stats(startup_samples["check"]),
        "startup_check_sample_count": len(startup_samples["check"]),
        "certification_check_sample_count": len(samples["check"]),
        "certification_sampling_phase": CALIBRATION_CERTIFICATION_SAMPLING_PHASE,
        "sessions": [summary],
        "materialization_evidence": materialization,
        "materialization_evidence_sha256": materialization["evidence_sha256"],
        "thread_read_recovery": read_recovery_telemetry,
        "thread_read_recovery_sha256": read_recovery_telemetry[
            "telemetry_sha256"
        ],
        "poll_interval_max_ms": round(
            max(observed_poll_gaps) * 1000,
            3,
        ) if observed_poll_gaps else 0.0,
        "interrupt_confirmed": True,
        "archive_staging": {
            **staged_archive.telemetry(),
            "cooperative_wait_ms": POOL_POLL_INTERVAL_MS,
            "close_settle_max_ms": round(
                STAGED_ARCHIVE_CLOSE_SETTLE_SECONDS * 1000,
                3,
            ),
        },
        "peer_completion_deferred_to_coordinator_interrupt_canary": True,
        "scheduler_inequality_lhs_ms": round(proof.total_demand_ms, 3),
        "scheduler_inequality_rhs_ms": proof.poll_interval_ms,
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
    control_turn_id: str = CONTROL_TURN_ID,
    requested_cap: int = LEGACY_CONCURRENT_CAPACITY,
    startup_timeout_seconds: float = CALIBRATION_STARTUP_TIMEOUT_SECONDS,
    materialization_timeout_seconds: float = (
        CALIBRATION_MATERIALIZATION_TIMEOUT_SECONDS
    ),
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
            control_turn_id=control_turn_id,
            requested_cap=requested_cap,
            boundary_trackers=boundary_trackers,
            startup_timeout_seconds=startup_timeout_seconds,
            materialization_timeout_seconds=materialization_timeout_seconds,
            pre_allocation_check=pre_allocation_check,
        )
    except Exception as exc:
        diagnostic = record_dir / "calibration-notification-shape.json"
        if diagnostic.is_file() and not diagnostic.is_symlink():
            try:
                shape = json.loads(diagnostic.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                shape = None
            if isinstance(shape, Mapping):
                setattr(exc, "calibration_notification_shape", dict(shape))
        raise
    finally:
        for tracker in reversed(boundary_trackers):
            tracker.close()


def contain_started_threads(
    server: AppServer,
    *,
    allow_same_process_proofs: bool = False,
    delete_proven_never_turned: bool = False,
    failure_diagnostics: list[dict[str, Any]] | None = None,
    containment_actions: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Idempotently prove terminal absence, then contain allocated threads."""

    interrupted: list[str] = []
    archived: list[str] = []
    already_contained: list[str] = []
    ambiguous: list[str] = []
    ledger_errors: list[str] = []
    ledger = getattr(server, "allocation_ledger", None)
    no_pending_turn_intent = allow_same_process_proofs and ledger is None
    if allow_same_process_proofs and ledger is not None:
        try:
            no_pending_turn_intent = (
                int(ledger.summary()["unresolved_turn_intent_count"]) == 0
            )
        except Exception as exc:
            ledger_errors.append(sha256_text(f"{type(exc).__name__}:{exc}"))

    def record_failure(
        thread_id: str,
        substep: str,
        exc: Exception,
    ) -> None:
        if failure_diagnostics is None:
            return
        diagnostic: dict[str, Any] = {
            "thread_id_sha256": sha256_text(thread_id),
            "substep": substep,
            "failure_class": type(exc).__name__,
            "failure_message_sha256": sha256_text(str(exc)),
        }
        if isinstance(exc, AppServerRpcError):
            diagnostic.update(
                {
                    "rpc_method": exc.method,
                    "rpc_code": exc.code,
                }
            )
        failure_diagnostics.append(diagnostic)

    for thread_id, record in list(
        getattr(server, "_turn_dispatch_records", {}).items()
    ):
        if not isinstance(record, Mapping):
            ambiguous.append(str(thread_id))
            continue
        errors = validate_turn_dispatch_record(record)
        if errors:
            ambiguous.append(str(thread_id))
            continue
        if record.get("status") in {"dispatching", "failed-ambiguous"}:
            try:
                record = server.contain_ambiguous_turn_dispatch(str(thread_id))
            except Exception:
                ambiguous.append(str(thread_id))
                continue
        if record.get("status") == "failed-ambiguous":
            ambiguous.append(str(thread_id))

    def audit_containment(
        thread_id: str,
        outcome: str,
        status: str | None,
        *,
        local_proof_sha256: str | None = None,
    ) -> bool:
        if ledger is None:
            return True
        try:
            evidence = {
                "thread_id_sha256": sha256_text(thread_id),
                "turn_status": status,
                "outcome": outcome,
            }
            if local_proof_sha256 is not None:
                evidence["same_process_proof_sha256"] = (
                    local_proof_sha256
                )
            ledger.record_containment_audit(
                thread_id,
                outcome=outcome,
                evidence=evidence,
            )
        except Exception as exc:
            ledger_errors.append(sha256_text(f"{type(exc).__name__}:{exc}"))
            return False
        return True

    for thread_id, turn_id in list(server.started_threads.items()):
        dispatch_record = (
            server.turn_dispatch_record(thread_id)
            if hasattr(server, "turn_dispatch_record")
            else None
        )
        if (
            isinstance(dispatch_record, Mapping)
            and dispatch_record.get("status") == "failed-ambiguous"
        ):
            ambiguous.append(thread_id)
            continue
        if (
            isinstance(dispatch_record, Mapping)
            and dispatch_record.get("status") == "failed-contained"
            and dispatch_record.get("archived") is True
        ):
            try:
                success_audited = bool(
                    ledger is None or ledger.has_successful_containment(thread_id)
                )
            except Exception as exc:
                success_audited = False
                ledger_errors.append(sha256_text(f"{type(exc).__name__}:{exc}"))
            if success_audited:
                already_contained.append(thread_id)
            else:
                ambiguous.append(thread_id)
            continue
        staged_archive = (
            server.staged_archive(thread_id)
            if hasattr(server, "staged_archive")
            else None
        )
        if staged_archive is not None:
            try:
                staged_archive.require_complete(timeout_seconds=15.0)
            except Exception as exc:
                record_failure(thread_id, "staged-archive-settlement", exc)
                ambiguous.append(thread_id)
                continue
        local_proof = (
            server.same_process_containment_proof(thread_id)
            if allow_same_process_proofs
            and hasattr(server, "same_process_containment_proof")
            else None
        )
        if local_proof is not None:
            try:
                success_audited = bool(
                    ledger is not None
                    and ledger.has_successful_containment(thread_id)
                )
            except Exception as exc:
                success_audited = False
                ledger_errors.append(
                    sha256_text(f"{type(exc).__name__}:{exc}")
                )
            if success_audited or audit_containment(
                thread_id,
                "already-contained",
                None,
                local_proof_sha256=local_proof["proof_sha256"],
            ):
                already_contained.append(thread_id)
            else:
                ambiguous.append(thread_id)
            continue
        if (
            staged_archive is not None
            and hasattr(server, "archive_acceptance_proof")
            and server.archive_acceptance_proof(thread_id) is not None
        ):
            # The exact archive request was accepted, but no terminal-bound
            # containment proof survived. Never issue a second archive RPC.
            ambiguous.append(thread_id)
            continue
        fresh_proof = (
            server.fresh_never_turned_thread_proof(thread_id)
            if allow_same_process_proofs
            and hasattr(server, "fresh_never_turned_thread_proof")
            else None
        )
        if (
            turn_id is None
            and dispatch_record is None
            and no_pending_turn_intent
            and fresh_proof is not None
        ):
            delete_fresh_thread = (
                delete_proven_never_turned and ledger is None
            )
            substep = (
                "never-turned-delete"
                if delete_fresh_thread
                else "never-turned-archive"
            )
            try:
                if delete_fresh_thread:
                    # Archive requires a materialized rollout. The activation
                    # delete opt-in is limited to a proven fresh, loaded,
                    # non-ephemeral thread that has never received a turn.
                    server.delete_thread(thread_id)
                    substep = "never-turned-delete-proof"
                    local_proof = (
                        server.record_never_turned_delete_containment(
                            thread_id
                        )
                    )
                else:
                    server.archive_thread(thread_id)
                    substep = "never-turned-archive-proof"
                    local_proof = (
                        server.record_never_turned_archive_containment(
                            thread_id
                        )
                    )
                substep = "never-turned-containment-audit"
                if not audit_containment(
                    thread_id,
                    "contained",
                    None,
                    local_proof_sha256=local_proof[
                        "proof_sha256"
                    ],
                ):
                    raise AppServerError(
                        "never-turned-containment-audit-failed"
                    )
                if delete_fresh_thread:
                    if containment_actions is not None:
                        containment_actions.append(
                            {
                                "action": "never-turned-delete",
                                "thread_id_sha256": sha256_text(
                                    thread_id
                                ),
                                "proof_sha256": local_proof[
                                    "proof_sha256"
                                ],
                            }
                        )
                else:
                    archived.append(thread_id)
            except Exception as exc:
                record_failure(thread_id, substep, exc)
                ambiguous.append(thread_id)
            continue
        try:
            thread, _latency = server.read_thread(thread_id)
            projected = AppServer._projected_turns(thread)
            expected_turns = {turn_id} if turn_id is not None else set()
            active = {
                candidate
                for candidate, status in projected.items()
                if AppServer._normalized_terminal_status(status) is None
            }
            interrupt_failed = False
            for candidate in sorted(active):
                try:
                    server.interrupt_turn(thread_id, candidate)
                    interrupted.append(thread_id)
                except Exception:
                    interrupt_failed = True
            deadline = time.monotonic() + AMBIGUOUS_TURN_DISCOVERY_TIMEOUT_SECONDS
            terminal: dict[str, str] = {
                candidate: normalized
                for candidate, status in projected.items()
                if (normalized := AppServer._normalized_terminal_status(status))
                is not None
            }
            while active and time.monotonic() < deadline and not interrupt_failed:
                try:
                    thread, _latency = server.read_thread(
                        thread_id,
                        timeout=max(0.001, deadline - time.monotonic()),
                    )
                except TypeError as exc:
                    if "timeout" not in str(exc):
                        raise
                    thread, _latency = server.read_thread(thread_id)
                projected = AppServer._projected_turns(thread)
                terminal.update(
                    {
                        candidate: normalized
                        for candidate, status in projected.items()
                        if (normalized := AppServer._normalized_terminal_status(status))
                        is not None
                    }
                )
                active = {
                    candidate
                    for candidate, status in projected.items()
                    if AppServer._normalized_terminal_status(status) is None
                }
                if active:
                    time.sleep(AMBIGUOUS_TURN_DISCOVERY_POLL_SECONDS)
            terminal_proven = expected_turns.issubset(terminal)
            absence_proven = not active
            if not interrupt_failed and terminal_proven and absence_proven:
                server.archive_thread(thread_id)
                archived.append(thread_id)
                audit_containment(
                    thread_id,
                    "contained",
                    terminal.get(turn_id) if turn_id is not None else None,
                )
            else:
                ambiguous.append(thread_id)
        except Exception:
            try:
                containment_audited = bool(
                    ledger is not None
                    and ledger.has_successful_containment(thread_id)
                )
            except Exception as exc:
                containment_audited = False
                ledger_errors.append(sha256_text(f"{type(exc).__name__}:{exc}"))
            record_proves_containment = bool(
                isinstance(dispatch_record, Mapping)
                and not validate_turn_dispatch_record(dispatch_record)
                and dispatch_record.get("status") == "failed-contained"
                and dispatch_record.get("absence_verified") is True
            )
            if containment_audited or (ledger is None and record_proves_containment):
                already_contained.append(thread_id)
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
    ambiguous_count = len(set(ambiguous)) + unresolved_allocations + unresolved_turns
    return {
        "allocated_count": ledger_allocation_count,
        "identified_thread_count": len(server.started_threads),
        "interrupted_count": len(set(interrupted)),
        "archived_count": len(set(archived)),
        "already_contained_count": len(set(already_contained)),
        "unresolved_allocation_intent_count": unresolved_allocations,
        "unresolved_turn_intent_count": unresolved_turns,
        "ambiguous_count": ambiguous_count,
        "all_contained": ambiguous_count == 0 and not ledger_errors,
        "ledger_consistent": not ledger_errors
        and not unresolved_allocations
        and not unresolved_turns,
        "ledger_error_sha256": sorted(set(ledger_errors)),
    }


def _refuse_retired_campaign() -> NoReturn:
    live_availability.require_campaign_live()
    live_availability.require_pool_live()
    live_availability.require_n1_live()
    raise LegacyNativePoolExecutionRetired()


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
    completion_evidence_policies: list[Mapping[str, Any]] | None = None,
    tool_policies: list[Mapping[str, Any]] | None = None,
    read_only_command_authorities: list[list[Mapping[str, Any]] | None] | None = None,
    pre_thread_start_check: Callable[[], Mapping[str, Any] | None],
    pre_allocation_check: Callable[[], None] | None = None,
    expected_bound_manifest_validation: Mapping[str, Any] | None = None,
    interrupt_after: list[int | None] | None = None,
) -> NoReturn:
    """Refuse retired campaign pool preparation."""
    _refuse_retired_campaign()


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
    completion_evidence_policies: list[Mapping[str, Any]] | None = None,
    tool_policies: list[Mapping[str, Any]] | None = None,
    read_only_command_authorities: list[list[Mapping[str, Any]] | None] | None = None,
    pre_thread_start_check: Callable[[], Mapping[str, Any] | None],
    pre_allocation_check: Callable[[], None] | None = None,
    expected_bound_manifest_validation: Mapping[str, Any] | None = None,
    interrupt_after: list[int | None] | None = None,
) -> dict[str, Any]:
    """Refuse the retired v1 pool canary before preparing a worker."""
    _refuse_retired_campaign()


def acquire_global_campaign_claim(
    inputs: Any,
    *,
    launch_claim_sha256: str,
    output: Path,
    authorization_state: Path,
    steering_registry: Path,
    allocation_ledger: Path,
    claim_root: Path | None = None,
    registry_root: Path | None = None,
) -> NoReturn:
    """Refuse retired machine-global campaign claims."""
    _refuse_retired_campaign()


def validate_and_acquire_global_campaign_claim(
    inputs: Any,
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
    pre_mutation_verified_operator_authorities: Iterable[Any] | None = None,
    pre_live_verified_operator_authorities: Iterable[Any] | None = None,
) -> NoReturn:
    """Refuse retired campaign validation and claims."""
    _refuse_retired_campaign()


def _start_campaign_server() -> AppServer:
    """Refuse retired campaign server construction."""
    _refuse_retired_campaign()


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
    parser.parse_args()
    started_at = utc_now()
    try:
        _refuse_retired_campaign()
    except Exception as exc:
        raw_failure = str(exc)
        failure_class = type(exc).__name__
        safe_failure_code = (
            raw_failure
            if raw_failure
            and len(raw_failure) <= 240
            and all(character.isalnum() or character in "-_:;." for character in raw_failure)
            else failure_class
        )
        failure = seal_artifact(
            {
                "result_type": "cwo-native-supervision-pool-live-canary-failure",
                "version": 1,
                "bead_id": None,
                "work_unit_id": None,
                "control_turn_id": CONTROL_TURN_ID,
                "exact_model": EXACT_MODEL,
                "started_at": iso(started_at),
                "failed_at": iso(),
                "failure_class": failure_class,
                "failure_code": safe_failure_code,
                "failure_message_sha256": sha256_text(raw_failure),
                "validation_outcome": "rejected",
                "release_gate_passed": False,
                "no_resume_or_salvage": True,
                "containment": {
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
                },
                "authorization_state_sha256": None,
                "steering_consumptions": {},
                "campaign_bindings": {},
                "first_protected_fault": getattr(exc, "first_protected_fault", None),
                "allocation_ledger": None,
                "glm_5_2_used": False,
                "model_synthesis_used": False,
            },
            "evidence_sha256",
        )
        print(
            json.dumps(
                {
                    "release_gate_passed": False,
                    "failure_class": failure_class,
                    "failure_code": safe_failure_code,
                    "failure_message_sha256": failure["failure_message_sha256"],
                    "evidence_sha256": failure["evidence_sha256"],
                    "failure_evidence_persisted": False,
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
