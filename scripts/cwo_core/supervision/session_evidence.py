"""Trusted session boundaries, tool evidence and turn observations."""

from __future__ import annotations

import copy
import hashlib
import json
import math
import os
import re
import shlex
import stat
import time
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

from cwo_core.codex_tool_surface import (
    DIRECT_TOOL_TRANSPORT,
    NAMESPACED_EXEC_TOOL_TRANSPORT,
)
from cwo_core.native_canary_contracts import canonical_sha256 as domain_sha256
from cwo_core.native_pool_contracts import (
    canonical_sha256,
    seal_artifact,
)
from cwo_core.native_session import session_record_token_snapshot
from cwo_core.native_session_boundary import (
    LocatedSession,
    NativeSessionBoundaryError,
    capture_unique_boundary,
    locate_unique_session,
    session_source_identity,
    trusted_terminal_event,
)
from cwo_core.native_tool_isolation import (
    NativeToolIsolationError,
    build_tool_surface_snapshot,
    normalize_tool_policy,
)
from cwo_core.native_worker_contracts import (
    tool_argument_value,
    session_event_items,
    tool_output_text,
    paired_namespaced_exec_result,
    canonical_argument_hash,
    decode_namespaced_exec_source,
    is_tool_call_item,
    is_tool_output_item,
    normalize_action_receipts,
    trusted_tool_name,
)
from cwo_core.supervision.transport.app_server import (
    canonical_controller_workdir as _canonical_controller_workdir,
    sha256_bytes,
    sha256_text,
)
from cwo_core.supervision.transport.errors import AppServerError


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


def strict_session_json_object_pairs(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    """Reject duplicate JSON names at every nesting level."""

    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise NativeSessionBoundaryError("session record has duplicate object keys")
        value[key] = item
    return value


def parse_strict_session_json_record(line: bytes, number: int) -> dict[str, Any]:
    try:
        value = json.loads(
            line.decode("utf-8"),
            object_pairs_hook=strict_session_json_object_pairs,
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
    if session_record_token_snapshot(dict(session_record)) is not None or session_record_token_snapshot(
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
            value = parse_strict_session_json_record(line, number)
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
            snapshot = session_record_token_snapshot(record)
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
DIRECT_PENDING_EXEC_RESULT_PATTERN = re.compile(
    r"Chunk ID: [0-9A-Za-z_-]+\n"
    r"Wall time: [0-9]+(?:\.[0-9]+)? seconds\n"
    r"Process running with session ID (?P<session_id>[1-9][0-9]*)\n"
    r"Original token count: [0-9]+\n"
    r"Output:\n[\s\S]*\Z"
)
READ_ONLY_SHELL_META = frozenset({";", "&", "|", ">", "<"})


def parse_read_only_command_tokens(command: Any) -> list[str]:
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
        token and set(token) <= READ_ONLY_SHELL_META for token in tokens
    ):
        raise AppServerError("read-only-command-authority-shell-syntax-forbidden")
    return tokens


def require_positive_read_only_command(command: Any) -> None:
    """Accept only reviewed read/test command families, never a generic shell."""

    tokens = parse_read_only_command_tokens(command)
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


def normalize_read_only_command_authority(
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
                require_positive_read_only_command(arguments["cmd"])
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


def direct_pending_operation_session_id(output_item: Mapping[str, Any]) -> int | None:
    match = DIRECT_PENDING_EXEC_RESULT_PATTERN.fullmatch(tool_output_text(output_item))
    return int(match.group("session_id")) if match is not None else None


def trusted_tool_authority_receipts(
    records: list[Mapping[str, Any]],
    receipts: list[dict[str, Any]],
    *,
    tool_transport: str,
) -> list[dict[str, Any]]:
    """Bind raw calls to normalized receipts without exposing raw commands."""

    events: list[tuple[int, str, Mapping[str, Any]]] = []
    for record_index, record in enumerate(records):
        for item_index, item in enumerate(session_event_items(record)):
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
        arguments = tool_argument_value(item)
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
                    paired_namespaced_exec_result(
                        tool=str(tool),
                        output_item=output_item,
                    )
                )
                if conflict:
                    operation_session_id = None
            elif tool in {"exec_command", "write_stdin"}:
                operation_session_id = direct_pending_operation_session_id(
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


def project_tool_receipt(receipt: Mapping[str, Any]) -> dict[str, Any]:
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


def require_trusted_session_workdir(
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


def is_nonexistent_canonical_nonsymlink_path(value: str) -> bool:
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


def exec_workdir_binding(
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
        and is_nonexistent_canonical_nonsymlink_path(supplied)
    ):
        return {**base, "disposition": "recoverable-nonexistent-workdir"}
    return {**base, "disposition": "security-violation-workdir-mismatch"}


def normalize_expected_tool_trace(
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


def bind_tool_receipt_workdirs(
    receipts: Iterable[dict[str, Any]], workdir: Path | None
) -> None:
    for receipt in receipts:
        binding = exec_workdir_binding(receipt, workdir)
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
    authority_receipts = trusted_tool_authority_receipts(
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
        authority_receipts = trusted_tool_authority_receipts(
            records[start_index + 1 : end_index],
            calls,
            tool_transport=tool_transport,
        )
    bind_tool_receipt_workdirs(calls, controller_workdir)
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
        project_tool_receipt(receipt) for receipt in calls
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
        require_trusted_session_workdir(records, controller_workdir)
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
        require_trusted_session_workdir(records, controller_workdir)
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
