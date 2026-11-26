"""Bounded activation-preview calibration and startup recovery."""

from __future__ import annotations

import datetime as dt
import json
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Mapping

from cwo_core import native_live_availability as live_availability
from cwo_core.codex_tool_surface import (
    DIRECT_TOOL_TRANSPORT,
    NAMESPACED_EXEC_TOOL_TRANSPORT,
)
from cwo_core.native_canary_contracts import (
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
from cwo_core.native_pool_capacity import load_pool_capacity
from cwo_core.native_pool_capacity_compat import LEGACY_CONCURRENT_CAPACITY
from cwo_core.native_pool_contracts import (
    CAPABILITY_RECEIPT_SCHEMA,
    CAPABILITY_RECEIPT_TYPE,
    POOL_POLL_INTERVAL_MS,
    canonical_sha256,
    seal_artifact,
    validate_capability_receipt,
    write_private_artifact,
)
from cwo_core.native_pool_schedulability import (
    PoolSchedulabilityError,
    scheduling_budget_proof,
)
from cwo_core.native_pool_scheduler import select_earliest_deadline
from cwo_core.native_session_boundary import (
    NativeSessionBoundaryError,
    telemetry_markers,
    trusted_terminal_event,
    trusted_turn_context,
)
from cwo_core.native_tool_isolation import (
    NativeToolIsolationError,
    default_tool_policy,
    forbidden_tool_activity,
    require_prompt_preflight,
    require_unchanged_tool_surface,
)
from cwo_core.native_worker_contracts import (
    canonical_argument_hash,
    decode_namespaced_exec_source,
)
from cwo_core.supervision.callback_timing import (
    PROVISIONAL_TERMINAL_GRACE_SECONDS,
    _measure_action_ms,
    capability_certification,
    guarded_measure,
    iso,
    stats,
    utc_now,
)
from cwo_core.supervision.containment import (
    STAGED_ARCHIVE_CLOSE_SETTLE_SECONDS,
    StagedThreadArchive,
)
from cwo_core.supervision.session_evidence import (
    CALIBRATION_READ_RECOVERY_POLICY,
    CALIBRATION_READ_RECOVERY_TELEMETRY_TYPE,
    PreAttestationSessionBoundaryTracker,
    capture_server_tool_surface,
    captured_session_boundary_summary,
    privacy_safe_notification_shape,
    seal_calibration_read_recovery_telemetry,
    turn_status,
    validate_startup_scaffold_records,
)
from cwo_core.supervision.transport.app_server import (
    AppServer,
    CONTROL_TURN_ID,
    EXACT_MODEL,
    THREAD_READ_TIMEOUT_SECONDS,
    sha256_bytes,
    sha256_text,
)
from cwo_core.supervision.transport.errors import (
    AppServerError,
    AppServerRpcError,
)
from cwo_core.workspace import (
    WorkspaceInspectionError,
    worktree_state_digest,
)


CALIBRATION_STARTUP_TIMEOUT_SECONDS = 30.0
CALIBRATION_MATERIALIZATION_TIMEOUT_SECONDS = 10.0
CALIBRATION_POLL_INTERVAL_SECONDS = 0.20
CALIBRATION_POLL_GAP_MAX_SECONDS = 0.250


CALIBRATION_CERTIFICATION_SAMPLING_PHASE = (
    "after-first-exact-operative-observation"
)


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
