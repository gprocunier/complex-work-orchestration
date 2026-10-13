"""Installed N=1 maintenance binding for the EXISTING transaction launcher.

This module assembles ``AdmittedPoolLaunch``; it never dispatches a pool itself.
The only operative dispatch remains native_pool_transaction ->
run_admitted_native_pool.  Qualification and release are supplied by the trusted
parent's existing producers, not synthesized here.  Unsupported tool isolation,
missing release evidence, wider scope and unproved cleanup all fail closed.

Controller context classes live in a separate installed module so loading this
adapter's verified source bytes under a fresh module name preserves their type
identity.  No .orchestration-audit import or caller-selected plugin is required.
"""

from __future__ import annotations

from copy import deepcopy
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import time
import uuid
from typing import Any, Mapping, Sequence

from cwo_core.maintenance_runtime_support import (
    MaintenanceControllerContext, MaintenanceRelease, MaintenanceRuntimeError, MaintenanceSessionLedger, MaintenanceTask,
    private_path, require,
)
from cwo_core.maintenance_qualification import require_maintenance_qualification
from cwo_core.maintenance_image import require_control_image
from cwo_core.native_control import build_control_turn_contract
from cwo_core.native_pool_admission import (
    AdmissionCandidate, BeadsClaimAdapter, reserve_pool_cohort,
    validate_dispatch_receipt,
)
from cwo_core.native_pool_config import ADMITTED_RENDER_REQUEST_SCHEMA, build_pool_contract
from cwo_core.native_pool_contracts import (
    POOL_POLL_INTERVAL_MS, canonical_sha256, default_completion_evidence_policy,
    validate_pool_receipt, validate_pool_state, write_private_artifact,
)
from cwo_core.native_pool_leases import PoolLeaseRegistry
from cwo_core.native_pool_preflight import (
    ADMITTED_PREFLIGHT_REQUEST_SCHEMA, default_callback_certification, effective_child_packet_sha256, run_pool_preflight,
)
from cwo_core.native_pool_transaction import (
    AdmittedPoolLaunch, MAINTENANCE_PLAN_VERSION, TransactionRuntime, validate_transaction_plan,
)
from cwo_core.native_pool_workspace import PoolWorkspaceMonitor, capture_workspace_snapshot
from cwo_core.native_precommit import (
    TRUSTED_ATTESTATION_SOURCE, arm_precommit, check_precommit, create_precommit_state,
    finalize_precommit, issue_precommit_receipt, mark_fit_dispatched, validate_precommit_receipt,
)
from cwo_core.native_stop_scope import build_stop_metadata, policy_scope_authority
from cwo_core.native_tool_isolation import (
    default_tool_policy, require_prompt_preflight, require_unchanged_tool_surface,
)
from cwo_core.paths import is_cwo_temp_path
from cwo_core.policy import load_policy
from cwo_core.workspace import capture_workspace_baseline, compare_workspace_baseline
from prepare_native_worker import (
    _render_prompt, validate_native_worker_packet, validate_native_worker_return,
)
from run_native_pool_live_canaries import (
    AppServer, AppServerError, LiveThreadAdapter, THREAD_PHASE_PRECOMMIT_FIT,
    capture_server_tool_surface, contain_started_threads, pool_sleep, turn_items,
)


def _iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _sha(value: bytes | str) -> str:
    return hashlib.sha256(value.encode() if isinstance(value, str) else value).hexdigest()


def _strict_json(text: str) -> Any:
    def pairs(entries):
        result = {}
        for key, value in entries:
            require(key not in result, "duplicate-json-key")
            result[key] = value
        return result
    def constant(_value):
        raise MaintenanceRuntimeError("maintenance-runtime-nonfinite-json")
    return json.loads(text, object_pairs_hook=pairs, parse_constant=constant)


def read_pool_terminal_state(path: Path, *, contract: Mapping[str, Any]) -> dict[str, Any]:
    """Consume coordinator-owned state bytes, not a receipt's success claim."""
    private_path(path, exists=True)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as handle:
        info = os.fstat(handle.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                and not info.st_mode & 0o077, "pool-state-private-file-required")
        data = handle.read(16 * 1024 * 1024 + 1)
    require(len(data) <= 16 * 1024 * 1024, "pool-state-too-large")
    value = _strict_json(data.decode("utf-8"))
    require(type(value) is dict and type(value.get("status")) is str,
            "pool-state-status-type-invalid")
    children = value.get("children")
    require(type(children) is list and all(type(child) is dict
            and type(child.get("status")) is str for child in children),
            "pool-child-status-type-invalid")
    errors = validate_pool_state(value, contract=contract)
    require(not errors, "pool-state-invalid:" + ";".join(errors))
    return value


class OperationalThreadAdapter(LiveThreadAdapter):
    """Strict native-return observation without changing the sealed token.

    A valid realignment return is transport completion, NOT product acceptance.
    A malformed/missing/reentrant return can never become a positive match.
    Trusted identity may be the exact value or the explicit controller sentinel;
    model/identity are bound to observed startup and subsequently checked JSONL.
    """

    def __init__(self, *args, packet: Mapping[str, Any], segment_id: str, authority_guard, **kwargs):
        self.packet = deepcopy(dict(packet))
        self.packet_hash = canonical_sha256(self.packet)
        self.segment_id = segment_id
        self.authority_guard = authority_guard
        self.native_return: dict[str, Any] | None = None
        self.return_errors: list[str] = []
        self._observing_return = False
        self._return_invalidated = False
        super().__init__(*args, expected_token="maintenance-native-return-v1:" + self.packet_hash, **kwargs)

    def final_message_observation(self) -> tuple[str | None, bool]:
        if self._return_invalidated or self._observing_return:
            self._return_invalidated = True
            self.native_return = None
            self.return_errors = ["worker-return-reentrant-observation"]
            return None, False
        self._observing_return = True
        self.native_return, self.return_errors = None, []
        digest = None
        try:
            require(canonical_sha256(self.packet) == self.packet_hash, "return-packet-drift")
            messages = [item.get("text") for item in turn_items(self.last_thread, self.turn_id)
                        if item.get("type") == "agentMessage"
                        and item.get("phase") in {"finalAnswer", "final_answer", None}]
            if not messages or type(messages[-1]) is not str:
                self.return_errors = ["worker-return-missing"]
                return None, False
            raw = messages[-1]
            digest = _sha(raw)
            value = _strict_json(raw)
            require(type(value) is dict and type(value.get("version")) is int and value["version"] == 1,
                    "worker-return-json-types-invalid")
            trusted = {"session_id": self.thread_id, "segment_id": self.segment_id,
                       "actual_model": self.thread_response["model"],
                       "attestation_source": TRUSTED_ATTESTATION_SOURCE, "attestation_status": "trusted"}
            require(trusted["actual_model"] == self.packet["requested_model"], "return-model-mismatch")
            for key, expected in trusted.items():
                require(type(value.get(key)) is str and value[key] in {expected, "__CWO_CONTROLLER_BOUND__"},
                        "return-identity-mismatch:" + key)
            value.update(trusted)
            errors = validate_native_worker_return(self.packet, value)
            require(not errors, "worker-return-invalid:" + ";".join(errors))
            if value["status"] == "completed":
                require(value.get("remaining_scope") == {}, "completed-return-remaining-scope")
            self.native_return = value
        except (ValueError, TypeError, KeyError, AttributeError, OverflowError) as exc:
            self.return_errors = [str(exc)]
        finally:
            if self._return_invalidated:
                self.native_return = None
                self.return_errors = ["worker-return-reentrant-observation"]
            self._observing_return = False
        return digest, self.native_return is not None and not self.return_errors

    def arm(self, **kwargs):
        self.authority_guard()
        return super().arm(**kwargs)

    def control_turn_identity(self) -> str:
        boundary = self._effective_boundary
        require(isinstance(boundary, Mapping), "control-identity-before-boundary")
        identity = boundary.get("control_contract", {}).get("control_turn_id")
        require(type(identity) is str and bool(identity), "control-identity-missing")
        return identity

    def send_input(self, **kwargs):
        self.authority_guard()
        return super().send_input(**kwargs)

    def final_summary(self):
        summary = super().final_summary()
        self.final_message_observation()
        return {**summary, "native_worker_return": deepcopy(self.native_return),
                "native_worker_return_errors": list(self.return_errors)}


class _GuardedTransport:
    def __init__(self, server: AppServer, guard):
        self._server, self._guard = server, guard

    def __getattr__(self, name):
        return getattr(self._server, name)

    def start_turn(self, *args, **kwargs):
        # Last parent-authority check, immediately before the actual RPC.  The
        # adapter already published its dispatch-attempted state before here.
        self._guard()
        return self._server.start_turn(*args, **kwargs)

    def start_thread(self, *_args, **_kwargs):
        raise MaintenanceRuntimeError("maintenance-runtime-unaccounted-thread-start-forbidden")


class _SessionProjection:
    """Append-only normalization of REAL startup/session records for precommit.

    The bootstrap record says it is an AppServer startup observation.  Subsequent
    records come from the actual session file; no assistant result/tool evidence
    is generated.  Both source identity and its already-read byte prefix are
    rechecked before each append, including after archive relocation.
    """

    def __init__(self, *, server, response, target: Path, worktree: Path):
        self.server, self.response, self.target = server, deepcopy(response), target
        self.worktree = worktree
        self.session_id = response["thread"]["id"]
        self.source = Path(response["thread"]["path"])
        self.prefix = b""
        self.identity = None
        self.target_prefix = b""
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        self._append({"timestamp": _iso(), "type": "session_meta",
                      "payload": {"id": self.session_id, "cwd": str(worktree)},
                      "turn_context": {"model": server.requested_model,
                                       "attestation_source": TRUSTED_ATTESTATION_SOURCE},
                      "controller_observation": {"source": "trusted-app-server-thread-start",
                           "response_sha256": canonical_sha256(response),
                           "connection_epoch_sha256": server.connection_epoch_sha256}})

    def _append(self, record):
        line = (json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()
        require(not self.target.is_symlink() and self.target.read_bytes() == self.target_prefix,
                "precommit-projection-drift")
        fd = os.open(self.target, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
        with os.fdopen(fd, "ab") as handle:
            handle.write(line)
            handle.flush()
            os.fsync(handle.fileno())
        self.target_prefix += line

    def sync(self, *, require_complete=False):
        if not self.source.exists():
            require(not require_complete, "precommit-session-not-materialized")
            return
        private_path(self.source, exists=True)
        details = self.source.stat()
        identity = (details.st_dev, details.st_ino)
        require(self.identity in (None, identity), "precommit-session-source-replaced")
        self.identity = identity
        data = self.source.read_bytes()
        require(data.startswith(self.prefix), "precommit-session-prefix-drift")
        boundary = data.rfind(b"\n") + 1
        require(not require_complete or boundary == len(data), "precommit-session-partial")
        for line in data[len(self.prefix):boundary].splitlines():
            if not line.strip():
                continue
            record = _strict_json(line.decode())
            require(type(record) is dict, "precommit-session-record-invalid")
            payload = record.get("payload")
            if record.get("type") == "session_meta" and isinstance(payload, Mapping):
                require(payload.get("id", self.session_id) == self.session_id
                        and payload.get("session_id", self.session_id) == self.session_id,
                        "precommit-session-identity-mismatch")
                require(payload.get("cwd", str(self.worktree)) == str(self.worktree), "precommit-session-cwd-mismatch")
            context = payload if record.get("type") == "turn_context" else record.get("turn_context")
            if isinstance(context, dict) and context.get("model") is not None:
                require(context["model"] == self.server.requested_model
                        and context.get("effort", context.get("reasoning_effort")) in (None, self.server.reasoning_effort),
                        "precommit-session-model-mismatch")
                context["attestation_source"] = TRUSTED_ATTESTATION_SOURCE
            self._append(record)
        self.prefix = data[:boundary]


def run_app_server_precommit(*, server, thread_response, task, run_dir: Path,
                            current_authority, authority_guard, timeout_seconds: int,
                            maintenance_operation=None, maintenance_verifier=None) -> Mapping[str, Any]:
    """Actual bounded fit turn using the existing native_precommit state machine."""
    control_id = "maintenance-precommit:" + task.attempt_nonce
    state_file, receipt_file = run_dir / "precommit-state.json", run_dir / "precommit-receipt.json"
    projection = _SessionProjection(server=server, response=thread_response,
                                    target=run_dir / "precommit-session.jsonl", worktree=task.worktree)
    projection.sync()
    state = create_precommit_state(packet_id=task.packet_id, work_plan=task.work_plan,
        session_id=thread_response["thread"]["id"], session_file=projection.target,
        agent_id=thread_response["thread"]["id"], workdir=task.worktree,
        operative_routing=task.operative_routing, current_authority=current_authority,
        state_file=state_file, attempt_nonce=task.attempt_nonce, owner_pid=os.getpid(),
        control_execution_handle=control_id, requested_model=server.requested_model,
        maintenance_operation=maintenance_operation, maintenance_verifier=maintenance_verifier,
        audit_file=run_dir / "precommit-audit.jsonl")
    closed = False
    try:
        authority_guard()
        arm_precommit(state_file, control_id)
        turn, _ = server.start_turn(thread_response["thread"]["id"], state["fit_prompt"])
        turn_id = turn["id"]
        _, code = mark_fit_dispatched(state_file, control_id, turn_id)
        require(code == 0, "precommit-dispatch-rejected")
        deadline = time.monotonic() + timeout_seconds
        while True:
            authority_guard()
            require(time.monotonic() < deadline, "precommit-timeout")
            require(server._reader_error is None and server.process.poll() is None, "precommit-transport-failed")
            projection.sync()
            terminal, code = check_precommit(state_file, control_id)
            require(code == 0, "precommit-observation-rejected")
            if terminal["status"] == "completed":
                require(terminal.get("fit_result", {}).get("decision") == "accept", "precommit-fit-rejected")
                break
            time.sleep(0.2)
        # Observe the owned terminal while its live endpoint inventory remains
        # queryable. Archiving unloads the thread; a post-archive MCP query is
        # not valid host evidence and must not be used as its first final guard.
        observed_thread, _ = server.read_thread(thread_response["thread"]["id"])
        observed_turns = observed_thread.get("turns")
        require(type(observed_turns) is list and len(observed_turns) == 1
                and type(observed_turns[0]) is dict
                and observed_turns[0].get("id") == turn_id
                and observed_turns[0].get("status") == "completed"
                and observed_turns[0].get("error") is None,
                "precommit-live-terminal-before-archive-required")
        authority_guard()
        finalize_precommit(state_file, control_id, "worker-completed")
        server.archive_thread(thread_response["thread"]["id"])
        server.record_terminal_archive_containment(thread_response["thread"]["id"], turn_id,
                                                   terminal_evidence_sha256=terminal["terminal"]["boundary_sha256"])
        thread, _ = server.read_thread(thread_response["thread"]["id"])
        projection.source = Path(thread["path"])
        projection.sync(require_complete=True)
        terminal, code = check_precommit(state_file, control_id)
        require(code == 0 and terminal["status"] == "completed", "precommit-closure-observation-rejected")
        finalize_precommit(state_file, control_id, "close-confirmed")
        closed = True
        issue_precommit_receipt(state_file, receipt_file=receipt_file, current_authority=current_authority)
        # The producer's Python return also includes a convenience receipt_file
        # key; the persisted JSON is the exact closed receipt schema.
        return _strict_json(receipt_file.read_text(encoding="utf-8"))
    except BaseException as exc:
        if not closed:
            try:
                finalize_precommit(state_file, control_id, "control-failed")
            except BaseException as secondary:
                exc.add_note("precommit control-failure persistence: " + str(secondary))
        raise


class _Runtime:
    def __init__(self, plan, context):
        self.plan, self.context = deepcopy(dict(plan)), context
        self.task = context.task
        self.blueprint_hash = canonical_sha256(self.task.blueprint())
        self.authority_hash = canonical_sha256(context.current_authority)
        self._qualification_ready = False
        self.policy = load_policy("native-worker-execution")
        self.tool_policy = default_tool_policy(mutable=self.task.role == "product", workload_class="operative",
            permitted_tools=context.tool_surface_proof.get("requested_tools"),
            **({"tool_profile": context.tool_surface_proof["tool_profile"]}
                if isinstance(context.tool_surface_proof.get("tool_profile"), str)
                and context.tool_surface_proof["tool_profile"].endswith("-v2") else {}))
        self.server = self.transport = None
        self.construction_attempted = False
        self.construction_cleanup = None
        self.surface = self.precommit = self.release = self.reserved = self.monitor = self.launch = None
        self.responses: dict[str, Mapping[str, Any]] = {}
        self.adapters: dict[str, OperationalThreadAdapter] = {}
        self.started = False
        self.prepared = False
        self.allocations = 0
        self.started_at = None
        self.cleanup = None
        self.validation = None
        self.effective = None
        self.operation = context.operation.evidence()["operation"]
        self.ids = {label: str(uuid.uuid5(uuid.NAMESPACE_URL, "cwo-maintenance:" + self.plan["plan_sha256"] + ":" + label))
                    for label in ("packet", "attempt", "lease", "pool", "epoch", "launch", "campaign")}
        self.initial_workspace = capture_workspace_snapshot(self.task.worktree, allowed_paths=list(self.task.write_paths))
        self._guard()

    def _guard(self):
        self.context.require_authority(self.plan)
        require(canonical_sha256(self.task.blueprint()) == self.blueprint_hash, "task-blueprint-drift")
        require(canonical_sha256(self.context.current_authority) == self.authority_hash, "routing-authority-drift")
        if self._qualification_ready:
            self._qualified_guard()
        if self.started_at is not None:
            require(time.monotonic() - self.started_at < self.operation["reservation"]["runtime_seconds"],
                    "operation-runtime-reservation-exhausted")

    def _qualified_guard(self):
        qualification = require_maintenance_qualification(self.context.qualification,
            operation=self.context.operation, verifier=self.context.verifier)
        record = qualification.record
        require(type(self.context.control_image) is dict, "control-image-required")
        image = require_control_image(self.context.control_image)
        require(image["image_sha256"] == record["control_image_sha256"]
                == self.plan["controller_overlay_sha256"], "qualified-image-mismatch")
        selected = self.context.current_authority.get("qualifications", {}).get(self.plan["selected_model"])
        require(selected == record, "qualified-current-authority-mismatch")
        require(record["tool_profile_sha256"] == canonical_sha256(self.tool_policy["permitted_tools"]),
                "qualified-tool-profile-mismatch")
        return record

    def _surface(self):
        surface = capture_server_tool_surface(self.server, self.tool_policy)
        self._guard()
        require(surface["server_allowlist_supported"] is True, "tool-enforcement-unavailable")
        if self.surface is not None:
            require_unchanged_tool_surface(self.surface, surface)
        return surface

    def prepare(self, plan):
        require(not self.prepared and plan == self.plan, "prepare-reused-or-plan-mismatch")
        self._guard()
        self._qualified_guard()
        self._qualification_ready = True
        require(self.context.session_ledger.count() == plan["budget"]["cumulative_before"], "session-baseline-mismatch")
        private_path(self.context.run_dir, exists=False)
        self.context.run_dir.mkdir(mode=0o700)
        self.prepared = True
        self.started_at = time.monotonic()
        # AppServer itself validates the pinned installed proof/binary/config
        # before launching a process.  model/list is not counted as a session.
        self.construction_attempted = True
        try:
            self.server = AppServer(requested_model=plan["selected_model"],
                                   reasoning_effort=self.context.reasoning_effort,
                                   tool_surface_proof=self.context.tool_surface_proof,
                                   operation_metadata={"cwo_bead": self.plan["children"][0]["bead_id"],
                                       "cwo_control_turn": "maintenance:" + self.operation["operation_id"],
                                       "cwo_mission": self.operation["mission_id"]})
        except BaseException as exc:
            self.construction_cleanup = deepcopy(getattr(exc, "app_server_cleanup", None))
            raise
        self.transport = _GuardedTransport(self.server, self._guard)
        discovery = self.server.model_discovery()
        self.surface = self._surface()
        write_private_artifact(self.context.run_dir / "transport-discovery.json",
                               {"model_discovery": discovery, "tool_surface": self.surface})
        self._guard()
        return {field: self.plan[field] for field in (
            "candidate_manifest_sha256", "controller_overlay_sha256", "authority_sha256", "runtime_adapter_sha256")}

    def _start(self, call_context, *, prelude):
        require(self.prepared and self.cleanup is None, "allocation-before-prepare-or-after-cleanup")
        intent = call_context.get("transaction_allocation")
        require(type(intent) is dict and intent.get("ordinal") == self.allocations
                and intent.get("allocation_class") == ("prelude" if prelude else "worker")
                and intent.get("child_id") == (None if prelude else self.task.child_id), "allocation-intent-mismatch")
        require(intent.get("allocation_id") == canonical_sha256({
            "transaction_id": self.plan["transaction_id"], "allocation_class": intent["allocation_class"],
            "ordinal": intent["ordinal"], "child_id": intent["child_id"]}), "allocation-id-mismatch")
        require(self.allocations < self.plan["budget"]["reserved_sessions"], "session-reservation-exhausted")
        surface = self._surface()
        self._guard()
        self._qualified_guard()
        # This fsync and the coordinator's intent both precede the actual RPC.
        self.context.session_ledger.record_intent(self.operation["operation_id"], intent)
        self.allocations += 1
        kwargs = {"mutable": False if prelude else self.task.role == "product", "role": self.task.role,
                  "permitted_tools": list(self.tool_policy["permitted_tools"]),
                  "allowlist_parameter": surface["allowlist_parameter"]}
        if prelude:
            kwargs["thread_phase"] = THREAD_PHASE_PRECOMMIT_FIT
        self._guard()
        response, _ = self.server.start_thread(self.task.worktree, **kwargs)
        thread = response.get("thread", {})
        require(type(thread.get("id")) is str and thread.get("turns") == []
                and response.get("model") == self.plan["selected_model"], "startup-identity-mismatch")
        self.responses[intent["allocation_class"]] = deepcopy(response)
        observed = self.server._effective_thread_start_evidence.get(thread["id"])
        require(isinstance(observed, Mapping) and observed.get("response") == response, "startup-evidence-missing")
        sandbox = response.get("sandbox", {})
        mutable = kwargs["mutable"]
        require(response.get("cwd") == str(self.task.worktree)
                and response.get("runtimeWorkspaceRoots") == [str(self.task.worktree)]
                and response.get("approvalPolicy") == "never"
                and sandbox.get("type") == ("workspaceWrite" if mutable else "readOnly")
                and sandbox.get("networkAccess", False) is False
                and sandbox.get("writableRoots", []) in ([], [str(self.task.worktree)])
                and (mutable or sandbox.get("writableRoots", []) == []), "startup-sandbox-mismatch")
        write_private_artifact(self.context.run_dir / (intent["allocation_class"] + "-startup.json"), observed)
        return {"allocation_id": intent["allocation_id"], "allocation_class": intent["allocation_class"],
                "child_id": intent["child_id"], "session_id": thread["id"],
                "requested_model": self.plan["selected_model"], "actual_model": response["model"],
                "attestation_source": "trusted-app-server-thread-start",
                "interrupt_supported": callable(self.server.interrupt_turn),
                "close_supported": callable(self.server.archive_thread), "wait_supported": callable(self.server.read_thread),
                "workspace_identity_sha256": None if prelude else self.plan["children"][0]["worktree_identity_sha256"]}

    def start_prelude_session(self, ordinal, call_context):
        require(type(ordinal) is int and ordinal == 0 and self.precommit is None, "prelude-shape-invalid")
        allocation = self._start(call_context, prelude=True)
        runner = self.context.precommit_runner or run_app_server_precommit
        known_threads = set(self.server.started_threads)
        receipt = runner(server=self.transport, thread_response=self.responses["prelude"], task=self.task,
            run_dir=self.context.run_dir, current_authority=self.context.current_authority,
            authority_guard=self._guard, timeout_seconds=self.precommit_seconds,
            maintenance_operation=self.context.operation, maintenance_verifier=self.context.verifier)
        require(set(self.server.started_threads) == known_threads, "precommit-unaccounted-allocation")
        errors = validate_precommit_receipt(receipt, self.task.work_plan,
            operative_routing=self.task.operative_routing, current_authority=self.context.current_authority,
            expected_packet_id=self.task.packet_id, live=True, require_accepting=True)
        require(not errors, "precommit-receipt-invalid:" + ";".join(errors))
        require(receipt.get("session_id") == allocation["session_id"], "precommit-session-mismatch")
        self.precommit = deepcopy(dict(receipt))
        self._guard()
        return {**allocation, "attestation_source": "trusted-session-jsonl"}

    def release_artifacts(self, plan, _context, _readiness, *, refresh=False):
        self._guard()
        qualification = self._qualified_guard()
        require(plan == self.plan and self.precommit is not None, "release-before-precommit")
        release = self.context.release_packet(plan=deepcopy(self.plan), task=self.task,
            precommit_receipt=deepcopy(self.precommit), current_authority=self.context.current_authority, refresh=refresh,
            maintenance_operation=self.context.operation, maintenance_verifier=self.context.verifier)
        self._guard()
        require(type(release) is MaintenanceRelease, "checked-release-producer-required")
        packet = deepcopy(dict(release.packet))
        require(type(packet.get("release_evidence", {}).get("version")) is int
                and packet["release_evidence"]["version"] == 2, "maintenance-release-v2-required")
        errors = validate_native_worker_packet(packet, dispatchable=True, current_authority=self.context.current_authority,
            maintenance_operation=self.context.operation, maintenance_verifier=self.context.verifier)
        require(not errors, "operative-packet-invalid:" + ";".join(errors))
        require(packet.get("packet_id") == self.task.packet_id
                and packet.get("bead_id") == self.plan["children"][0]["bead_id"]
                and packet.get("requested_model") == self.plan["selected_model"]
                and canonical_sha256(packet.get("work_plan")) == canonical_sha256(self.task.work_plan)
                and packet.get("precommit_receipt_sha256") == self.precommit["receipt_sha256"]
                and canonical_sha256(packet.get("tool_policy")) == canonical_sha256(self.tool_policy)
                and packet.get("scope", {}).get("workdir") == str(self.task.worktree), "release-packet-binding-mismatch")
        if self.task.role == "review":
            require("source-mutation" in packet["scope"]["prohibited_actions"], "readonly-packet-mutation-not-forbidden")
        else:
            require(packet["scope"]["allowed_paths"] == list(self.task.write_paths), "release-write-scope-mismatch")
        dependencies = deepcopy(list(release.dependencies))
        evidence = packet["release_evidence"]
        require(evidence.get("canary_receipt_sha256") == qualification["canary_sha256"],
                "release-qualification-canary-mismatch")
        require(dt.datetime.fromisoformat(qualification["origin_issued_at"])
                <= dt.datetime.fromisoformat(evidence["issued_at"])
                < dt.datetime.fromisoformat(evidence["expires_at"])
                <= dt.datetime.fromisoformat(qualification["origin_expires_at"]),
                "release-qualification-lifetime-mismatch")
        self._qualified_guard()  # Hook/render observers must not change qualification.
        operative = [dep for dep in dependencies if dep.get("kind") == "operative-release"]
        require(len(operative) == 1 and operative[0] == {"child_id": self.task.child_id,
            "kind": "operative-release", "evidence_sha256": evidence["evidence_sha256"],
            "issued_at": evidence["issued_at"], "expires_at": evidence["expires_at"]}, "release-dependency-not-issuer-evidence")
        self.release = MaintenanceRelease(packet, tuple(dependencies))
        scope_instructions = ("\n\nController operation instructions:\n" + self.task.instruction
            + "\nReturn only the packet's native-worker-return JSON. Controller-owned identity fields "
            "session_id, segment_id, actual_model, attestation_source and attestation_status must be "
            "the exact string __CWO_CONTROLLER_BOUND__; this sentinel is replaced only from observed controller evidence.")
        prompt = _render_prompt(dict(packet)) + scope_instructions
        isolation = "mutable-isolated" if self.task.role == "product" else "read-only-shared"
        self.effective = {"child_id": self.task.child_id, "packet_id": self.ids["packet"],
            "attempt_nonce": self.ids["attempt"], "lease_id": self.ids["lease"], "worktree": str(self.task.worktree),
            "isolation_class": isolation, "completion_evidence_policy": default_completion_evidence_policy(isolation),
            "tool_policy": self.tool_policy, "prompt": prompt,
            "prompt_preflight": require_prompt_preflight(prompt, self.tool_policy), "tool_surface": self._surface(),
            "hard_budget": dict(self.task.hard_budget), "declared_write_paths": list(self.task.write_paths),
            "integration_target_paths": list(self.task.write_paths)}
        self.effective["packet_sha256"] = effective_child_packet_sha256(self.effective)
        write_private_artifact(self.context.run_dir / "operative-packet.json", packet)
        return {"packet_bindings": [{"child_id": self.task.child_id, "packet_sha256": canonical_sha256(packet),
                "precommit_receipt_sha256": self.precommit["receipt_sha256"],
                "work_plan_sha256": self.plan["children"][0]["work_plan_sha256"]}], "release_dependencies": dependencies}

    def start_worker_session(self, child, call_context):
        require(child == self.plan["children"][0] and self.release is not None and "worker" not in self.responses,
                "worker-before-release-or-reused")
        return self._start(call_context, prelude=False)

    def _live_revalidate(self, binding):
        self._guard()
        expected = self.reserved.receipt["child_bindings"][0] if self.reserved else self.candidate.child_bindings[
            self.plan["children"][0]["bead_id"]]
        require(binding == expected, "admission-binding-drift")
        observed = capture_workspace_snapshot(self.task.worktree, allowed_paths=list(self.task.write_paths))
        require(observed["identity"] == self.initial_workspace["identity"], "predispatch-workspace-drift")
        require(binding["packet_sha256"] == self.effective["packet_sha256"]
                and binding["packet_id"] == self.effective["packet_id"]
                and binding["worktree_identity_sha256"] == self.plan["children"][0]["worktree_identity_sha256"],
                "admission-packet-workspace-drift")
        self._guard()
        return deepcopy(dict(binding))

    def bind_admitted_launch(self, plan, allocations, _context):
        self._guard()
        require(plan == self.plan and self.launch is None and len(allocations) == 1, "launch-reused-or-shape-invalid")
        packet = self.release.packet
        candidate = self.context.admission_candidate(plan=deepcopy(self.plan), task=self.task,
            packet=deepcopy(packet), effective_child=deepcopy(self.effective), claim_adapter=self.context.claim_adapter)
        self._guard()
        require(type(candidate) is AdmissionCandidate and set(candidate.child_bindings) == {plan["children"][0]["bead_id"]},
                "admission-candidate-invalid")
        self.candidate = candidate
        self.reserved = reserve_pool_cohort(candidate, claim_adapter=self.context.claim_adapter,
            admission_nonce=self.operation["operation_id"], live_revalidate=self._live_revalidate,
            rebuild=None, policy_document=self.policy, productive=True)
        require(self.reserved.admitted, "cohort-not-admitted")
        reservation = self.reserved.receipt
        binding, claim = reservation["child_bindings"][0], reservation["claims"][0]
        response = self.responses["worker"]
        thread_id = response["thread"]["id"]
        require(allocations[0]["session_id"] == thread_id and allocations[0]["child_id"] == self.task.child_id,
                "launch-allocation-mismatch")
        prompt = self.effective["prompt"]
        prompt_receipt = self.effective["prompt_preflight"]
        surface = self._surface()
        state_file = self.context.run_dir / "worker-state.json"
        control_file = self.context.run_dir / "control-contract.json"
        control_id = "maintenance-control:" + self.operation["operation_id"]
        control = build_control_turn_contract(state_file=str(state_file), agent_id=thread_id,
            control_turn_id=control_id, task_sha256=_sha(prompt), poll_interval_ms=POOL_POLL_INTERVAL_MS)
        write_private_artifact(control_file, control)
        write_private_artifact(state_file, {"result_type": "cwo-native-supervision-state", "version": 1,
            "schema": "schemas/native-supervision-state.schema.json", "packet_id": self.effective["packet_id"],
            "packet_sha256": self.effective["packet_sha256"], "agent_id": thread_id, "session_id": thread_id,
            "status": "created", "control_turn_id": None, "poll_interval_ms": POOL_POLL_INTERVAL_MS,
            "control_adapter": "native-multi-agent-v1", "required_capabilities": ["interrupt", "close", "wait"],
            **build_stop_metadata("child", authority=policy_scope_authority("maintenance-child-state-v1", authorized_scope="child"))})
        isolation = "mutable-isolated" if self.task.role == "product" else "read-only-shared"
        fields = {key: deepcopy(binding[key]) for key in ("bead_id", "work_unit_id", "candidate_sha256",
            "work_estimate_sha256", "worker_commitment_sha256", "lease_scope_sha256", "worktree_identity_sha256",
            "requested_model", "admitted_child_sha256")}
        child = {"child_id": self.task.child_id, "packet_id": self.effective["packet_id"],
            "attempt_nonce": self.effective["attempt_nonce"], "session_id": thread_id, "agent_id": thread_id,
            "control_turn_id": control_id, "packet_sha256": self.effective["packet_sha256"],
            "control_contract_file": str(control_file), "state_file": str(state_file), "worktree": str(self.task.worktree),
            "isolation_class": isolation, "completion_evidence_policy": default_completion_evidence_policy(isolation),
            "tool_policy": self.tool_policy, "declared_write_paths": list(self.task.write_paths),
            "integration_target_paths": list(self.task.write_paths), "lease_id": self.effective["lease_id"],
            "claim_sha256": claim["claim_sha256"], "hard_budget": dict(self.task.hard_budget), **fields}
        render = {"request_type": "cwo-native-supervision-pool-render-request", "version": 2,
            "schema": ADMITTED_RENDER_REQUEST_SCHEMA, "pool_id": self.ids["pool"], "pool_epoch": self.ids["epoch"],
            "control_turn_id": control_id, "created_at": _iso(), "max_active_workers": 1,
            "aggregate_hard_budget": dict(self.task.hard_budget), "integration_root": str(self.context.integration_root),
            "children": [child], "completion_policy": "all-or-nothing", "admission_reservation": reservation}
        contract = build_pool_contract(render, capability_receipt=None, enable_concurrency=True,
                                       owner_pid=os.getpid(), policy_document=self.policy)
        planned = {key: value for key, value in child.items() if key not in {"state_file", "control_contract_file", "control_turn_id"}}
        planned.update(prompt=prompt, prompt_preflight=prompt_receipt, tool_surface=surface)
        request = {"preflight_type": "cwo-native-supervision-pool-preflight-request", "version": 2,
            "schema": ADMITTED_PREFLIGHT_REQUEST_SCHEMA, "stage": "pre-dispatch",
            "launch_id": self.ids["launch"], "campaign_nonce": self.ids["campaign"],
            "pool_id": contract["pool_id"], "pool_epoch": contract["pool_epoch"],
            "integration_root": str(self.context.integration_root), "artifact_directories": [str(self.context.run_dir)],
            "requested_workers": 1, "released_capacity": self.policy["native_supervision_pool"]["capacity"]["released_max_active_workers"],
            "aggregate_hard_budget": dict(self.task.hard_budget), "children": [planned],
            "fallback": {"main_thread": "maintenance-controller", "recovery": "fresh-authorized-operation"},
            "productive_dogfood_delivery_prerequisite": False, "callback_certification": default_callback_certification(),
            "poll_interval_ms": POOL_POLL_INTERVAL_MS, "pool_contract": contract, "overrides": [], "admission_reservation": reservation}
        proof = run_pool_preflight(request, policy_document=self.policy)
        require(proof.get("accepted") is True and proof.get("decision") == "accept", "predispatch-preflight-rejected")
        write_private_artifact(self.context.run_dir / "predispatch-preflight.json", proof)
        self.monitor = PoolWorkspaceMonitor(contract, integration_root=self.context.integration_root,
            child_worktrees={self.task.child_id: self.task.worktree}, policy_document=self.policy)
        adapter = OperationalThreadAdapter(self.transport, response, packet=packet,
            segment_id=plan["children"][0]["segment_id"], authority_guard=self._guard,
            prompt=prompt, worktree=self.task.worktree, mutable=self.task.role == "product",
            expected_mutation=self.task.write_paths[0] if self.task.write_paths else None,
            read_only_command_authority=self.task.read_only_command_authority,
            completion_evidence_policy=child["completion_evidence_policy"], tool_policy=self.tool_policy,
            prompt_preflight_receipt=prompt_receipt, preflight_tool_surface=surface,
            tool_surface_reader=self._surface, record_dir=self.context.run_dir)
        adapter.bind_workspace_baseline(self.monitor.child_baseline(self.task.child_id))
        adapter.bind_effective_boundary(planned_child=planned, runtime_child=child, pool_contract=contract,
            control_contract=control, predispatch_proof=proof,
            writable_roots=[self.task.worktree] if self.task.role == "product" else [])
        self.adapters[self.task.child_id] = adapter
        def read_child_evidence(*, child_id, state_file):
            require(child_id == self.task.child_id and state_file == child["state_file"], "child-evidence-binding-mismatch")
            self._guard()
            return adapter.evidence()
        self.launch = AdmittedPoolLaunch(reservation, self.reserved.capability, contract, request, proof,
            {self.task.child_id: control}, {self.task.child_id: prompt}, {self.task.child_id: adapter.callbacks()},
            {"claim_adapter": self.reserved.claim_adapter, "live_revalidate": self._live_revalidate,
             "pool_callbacks": {"monotonic_ns": time.monotonic_ns, "sleep": pool_sleep, "now_utc": _iso,
                                "read_child_evidence": read_child_evidence, "compare_workspaces": self.monitor.compare},
             "lease_registry": PoolLeaseRegistry(self.context.run_dir / "leases"), "capability_receipt": None,
             "state_file": self.context.run_dir / "pool-state.json", "decision_file": self.context.run_dir / "pool-decision.json",
             "policy_document": self.policy})
        # Retain the actual contract before the admitted launcher can trigger a
        # productive turn. Later independent consumption must not reconstruct
        # it from a newer environment or a success-only summary.
        write_private_artifact(self.context.run_dir / "admission-reservation.json", reservation)
        write_private_artifact(self.context.run_dir / "pool-contract.json", contract)
        self._guard()
        return self.launch

    def contain(self, _started, reason, _context):
        if self.cleanup is not None:
            return deepcopy(self.cleanup)
        cleanup_started = time.monotonic()
        thread_result, server_result, errors = None, None, []
        if self.server is not None:
            try:
                thread_result = contain_started_threads(self.server, allow_same_process_proofs=True,
                                                        delete_proven_never_turned=True)
            except BaseException as exc:
                errors.append("threads:" + type(exc).__name__ + ":" + str(exc))
            try:
                server_result = self.server.close()
            except BaseException as exc:
                server_result = getattr(exc, "app_server_cleanup", None)
                errors.append("server:" + type(exc).__name__ + ":" + str(exc))
        unidentified_allocations = self.allocations - len(self.server.started_threads) if self.server is not None else 0
        if unidentified_allocations:
            errors.append("allocation-acknowledgement-unknown")
        construction_contained = not self.construction_attempted or (
            isinstance(self.construction_cleanup, Mapping)
            and self.construction_cleanup.get("all_contained") is True
            and self.construction_cleanup.get("resources_closed") is True
            and not self.construction_cleanup.get("errors"))
        cleanup_budget_exceeded = time.monotonic() - cleanup_started > self.operation["reservation"]["cleanup_seconds"]
        all_contained = (self.server is None and construction_contained and not errors) or (isinstance(thread_result, Mapping)
            and thread_result.get("all_contained") is True and isinstance(server_result, Mapping)
            and server_result.get("all_contained") is True and server_result.get("resources_closed") is True and not errors)
        self.cleanup = {"all_contained": all_contained, "reason": reason, "threads": thread_result,
                        "server": server_result, "errors": errors, "claims_retained": self.reserved is not None,
                        "unidentified_allocations": unidentified_allocations,
                        "construction_cleanup": self.construction_cleanup,
                        "cleanup_budget_exceeded": cleanup_budget_exceeded}
        if self.context.run_dir.exists():
            write_private_artifact(self.context.run_dir / "containment.json", self.cleanup)
        return deepcopy(self.cleanup)

    def validate(self, launched, context):
        require(self.validation is None and self.launch is not None, "validation-reused-or-unlaunched")
        self._guard()
        errors = validate_dispatch_receipt(launched.get("dispatch_receipt"), reservation_receipt=self.reserved.receipt)
        terminal_state = None
        terminal_path = self.context.run_dir / "pool-state.json"
        try:
            terminal_state = read_pool_terminal_state(terminal_path, contract=self.launch.contract)
        except (OSError, ValueError) as exc:
            errors.append("pool-terminal-state-unobserved:" + str(exc))
        errors += validate_pool_receipt(launched.get("pool_receipt"), contract=self.launch.contract,
            terminal_state=terminal_state, admission_reservation=self.reserved.receipt,
            dispatch_receipt=launched.get("dispatch_receipt"))
        receipt = launched.get("pool_receipt", {})
        if receipt.get("pool_disposition") != "accepted":
            errors.append("pool-not-accepted")
        summary = self.adapters[self.task.child_id].final_summary()
        value = summary.get("native_worker_return")
        if not (isinstance(value, Mapping) and not summary.get("native_worker_return_errors")
                and value.get("status") == "completed" and value.get("remaining_scope") == {}
                and value.get("decision_required") == [] and value.get("artifact_disposition") == "accepted"
                and value.get("session_disposition") in {"accepted", "accepted-with-warning"}):
            errors.append("native-return-not-accepted")
        if isinstance(value, Mapping) and sorted(value.get("files_touched", [])) != sorted(summary.get("workspace_mutations", [])):
            errors.append("native-return-mutation-list-mismatch")
        cleanup = self.contain([], "pool-finished", context)
        if cleanup["all_contained"] is not True:
            errors.append("containment-unproven")
        if cleanup["cleanup_budget_exceeded"]:
            errors.append("cleanup-reservation-overrun")
        checks = []
        if not errors:
            before = capture_workspace_baseline(self.task.worktree, allowed_paths=[], include_untracked=True)
            for command in self.task.validation_commands:
                self._guard()
                completed = subprocess.run(command.argv, cwd=self.task.worktree, capture_output=True,
                    timeout=command.timeout_seconds, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}, check=False)
                result = {"command_sha256": canonical_sha256(command.document()), "returncode": completed.returncode,
                          "stdout_sha256": _sha(completed.stdout), "stderr_sha256": _sha(completed.stderr)}
                result["accepted"] = completed.returncode == 0 and (command.stdout_sha256 is None
                    or result["stdout_sha256"] == command.stdout_sha256)
                checks.append(result)
                if not result["accepted"]:
                    errors.append("independent-validation-failed")
            after = capture_workspace_baseline(self.task.worktree, allowed_paths=[], include_untracked=True)
            check_delta = compare_workspace_baseline(before, after, allowed_paths=[])
            if check_delta.get("mutation_detected") or check_delta.get("incomplete") or check_delta.get("attribution_ambiguous"):
                errors.append("validation-mutated-workspace")
            for path, digest in self.task.expected_artifacts.items():
                target = self.task.worktree / path
                if target.is_symlink() or not target.is_file() or _sha(target.read_bytes()) != digest:
                    errors.append("product-artifact-mismatch:" + path)
        workspace = self.monitor.compare(contract=self.launch.contract, phase="maintenance-final-observation")
        if any(workspace.get(field) is not True for field in ("integration_root_clean", "shared_read_only_clean", "child_worktrees_clean")):
            errors.append("workspace-final-observation-rejected")
        self._guard()
        # Independent command/workspace observers run before this final read.
        # A receipt cannot outlive drift in the state it claims to close.
        if terminal_state is not None:
            try:
                final_state = read_pool_terminal_state(terminal_path, contract=self.launch.contract)
                if canonical_sha256(final_state) != canonical_sha256(terminal_state):
                    errors.append("pool-terminal-state-drift")
            except (OSError, ValueError) as exc:
                errors.append("pool-terminal-state-unobserved:" + str(exc))
        self.validation = {"accepted": not errors, "healthy_evidence_retained": cleanup["all_contained"] is True,
            "errors": sorted(set(errors)), "pool_receipt_sha256": canonical_sha256(receipt),
            "native_return": value, "native_return_errors": summary.get("native_worker_return_errors"),
            "independent_checks": checks, "workspace": workspace, "containment": cleanup,
            "pool_terminal_state_sha256": terminal_state.get("state_sha256") if terminal_state else None,
            "bead_disposition": "owned-pending-controller-finalization", "bead_closed": False}
        write_private_artifact(self.context.run_dir / "validation.json", self.validation)
        return deepcopy(self.validation)


def build_transaction_runtime(plan: Mapping[str, Any], controller_context: object) -> TransactionRuntime:
    """Build, but do not launch, the exact shared runtime from parent authority.

    The loader claims/binds operation authority before importing this adapter.
    Missing hooks, unsupported scope and wrong budgets are rejected before
    process creation.  No providerless mode is an acceptance route.
    """
    require(type(controller_context) is MaintenanceControllerContext, "trusted-context-required")
    context = controller_context
    errors = validate_transaction_plan(plan)
    require(not errors and plan.get("version") == MAINTENANCE_PLAN_VERSION, "v8-plan-required:" + ";".join(errors))
    context.require_authority(plan)
    require(context.runtime_state is None, "context-runtime-reused")
    require(type(context.task) is MaintenanceTask, "task-type-invalid")
    require(type(context.session_ledger) is MaintenanceSessionLedger, "session-ledger-type-invalid")
    require(len(plan["children"]) == 1 and plan["prelude_session_count"] == 1 and plan["required_session_count"] == 2,
            "one-precommit-one-worker-required")
    child = plan["children"][0]
    blueprint = context.task.blueprint()
    require(child["child_id"] == context.task.child_id and child["packet_blueprint_sha256"] == canonical_sha256(blueprint)
            and child["work_plan_sha256"] == canonical_sha256(context.task.work_plan)
            and child["write_paths"] == list(context.task.write_paths), "task-plan-binding-mismatch")
    require(type(context.claim_adapter) is BeadsClaimAdapter, "explicit-beads-adapter-required")
    require(callable(context.release_packet) and callable(context.admission_candidate), "checked-producers-required")
    require(context.precommit_runner is None or callable(context.precommit_runner), "precommit-producer-invalid")
    require(context.reasoning_effort in {"low", "medium", "high", "xhigh", "max", "ultra"}, "effort-invalid")
    private_path(context.integration_root, exists=True)
    private_path(context.run_dir, exists=False)
    require(is_cwo_temp_path(context.run_dir), "precommit-requires-cwo-owned-temp-path")
    require(context.integration_root.is_dir() and context.integration_root != context.task.worktree,
            "integration-worktree-isolation-required")
    for root in (context.integration_root, context.task.worktree):
        require(not context.run_dir.is_relative_to(root) and not context.session_ledger.path.is_relative_to(root),
                "controller-state-in-worker-workspace")
    operation = context.operation.evidence()["operation"]
    require(context.session_ledger.mission_id == operation["mission_id"], "session-ledger-mission-mismatch")
    reservation = operation["reservation"]
    require(context.task.hard_budget["tool_calls"] <= reservation["tool_calls"], "tool-reservation-insufficient")
    precommit_seconds = reservation["runtime_seconds"] - context.task.hard_budget["runtime_seconds"] - sum(
        command.timeout_seconds for command in context.task.validation_commands)
    require(precommit_seconds > 0, "runtime-reservation-insufficient")
    state = _Runtime(plan, context)
    state.precommit_seconds = precommit_seconds
    require(canonical_sha256(state.initial_workspace["identity"]) == child["worktree_identity_sha256"],
            "worktree-identity-mismatch")
    context.runtime_state = state
    return TransactionRuntime(trusted_session_count=context.session_ledger.count,
        read_bead=context.claim_adapter.show_exact, prepare=state.prepare,
        start_prelude_session=state.start_prelude_session, release_artifacts=state.release_artifacts,
        refresh_release_artifacts=lambda plan, ctx, readiness: state.release_artifacts(plan, ctx, readiness, refresh=True),
        start_worker_session=state.start_worker_session, bind_admitted_launch=state.bind_admitted_launch,
        contain=state.contain, validate=state.validate,
        maintenance_operation=context.operation, maintenance_verifier=context.verifier)
