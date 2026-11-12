"""Stdlib JSON-RPC client for one trusted Codex app-server over stdio.

Moved from ``scripts/run_native_pool_live_canaries.py``, which still re-exports
``AppServer``, its constants and helpers. The current client enforces the default-off native launch
hold; the recorded historical source remains unchanged.

Raw launch requires explicit absolute executable/home paths or a verified
capture binding. The child receives that home and the executable's directory
as PATH; construction never falls back to the user's default Codex home.
"""

from __future__ import annotations

import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import threading
import time
from typing import Any, Callable, Mapping
import uuid
from cwo_core import native_live_availability as live_availability

from cwo_core.codex_tool_surface import (
    ALLOWLIST_PARAMETER as CONFIG_TOOL_ALLOWLIST_PARAMETER,
    CodexToolSurfaceError,
    DIRECT_TOOL_TRANSPORT,
    NAMESPACED_EXEC_TOOL_TRANSPORT,
    require_surface_proof,
    thread_start_enforcement_params,
    prepare_capture_binding,
    require_capture_binding,
    _codex_binary as _codex_binary,
    tool_transport_instructions,
    tool_profile_is_mutable,
    require_zero_endpoint_inventory,
)
from cwo_core.native_canary_contracts import canonical_sha256 as domain_sha256
from cwo_core.native_live_allocation_ledger import (
    EXPECTED_ROLES,
    NativeLiveAllocationLedgerStore,
    _IdentityCapabilityRegistry,
    _TurnNegativeResponseObserverBinding,
)
from cwo_core.native_pool_contracts import write_private_artifact
from cwo_core.native_turn_dispatch import (
    TURN_ABSENCE_PROOF_ARTIFACT_TYPE,
    TurnDispatchReservation,
    evolve_turn_dispatch_record,
    seal_turn_absence_proof,
    validate_turn_dispatch_record,
)
from cwo_core.supervision.transport.errors import (
    AmbiguousTurnStartError,
    AppServerError,
    AppServerRpcError,
)
from cwo_core.supervision.transport.private_io import (
    _open_private_control_lock,
    _private_control_directory,
    load_private_json,
)


EXACT_MODEL = "gpt-5.3-codex-spark"
THREAD_PHASE_LIVE_CANARY = "live-canary"
THREAD_PHASE_PRECOMMIT_FIT = "precommit-fit"
THREAD_START_PHASES = frozenset(
    {
        THREAD_PHASE_LIVE_CANARY,
        THREAD_PHASE_PRECOMMIT_FIT,
    }
)
CONTROL_TURN_ID = "complex-work-orchestration-18w.6-live-canary-control-turn"
THREAD_READ_TIMEOUT_SECONDS = 15.0
AMBIGUOUS_TURN_DISCOVERY_TIMEOUT_SECONDS = 5.0
AMBIGUOUS_TURN_DISCOVERY_POLL_SECONDS = 0.05


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_text(value: str) -> str:
    return sha256_bytes(value.encode("utf-8"))


def _seal_same_process_proof(
    payload: Mapping[str, Any],
    *,
    domain: str,
) -> dict[str, Any]:
    proof = dict(payload)
    proof["proof_sha256"] = domain_sha256(proof, domain=domain)
    return proof


def _validated_same_process_proof(
    value: Any,
    *,
    domain: str,
    expected_fields: set[str],
) -> dict[str, Any] | None:
    if not isinstance(value, Mapping) or set(value) != {
        *expected_fields,
        "proof_sha256",
    }:
        return None
    proof = dict(value)
    supplied = proof.pop("proof_sha256")
    if (
        not isinstance(supplied, str)
        or re.fullmatch(r"[0-9a-f]{64}", supplied) is None
        or domain_sha256(proof, domain=domain) != supplied
    ):
        return None
    return dict(value)


def _explicit_launch_home(executable, codex_home) -> Path:
    """Raw transports never choose an executable or home from ambient state."""
    if not isinstance(executable, (str, Path)) or not isinstance(codex_home, (str, Path)):
        raise AppServerError("app-server-explicit-launch-required")
    if not Path(executable).is_absolute() or not Path(codex_home).is_absolute():
        raise AppServerError("app-server-explicit-launch-required")
    return Path(codex_home).resolve()


def _require_native_rpc(method: str) -> None:
    """Keep only the reviewed containment RPCs usable under the closed hold."""
    if method not in {"initialize", "initialized", "thread/read", "turn/interrupt", "thread/archive",
                      "thread/delete", "model/list", "mcpServerStatus/list"}:
        live_availability.require_n1_live()


def _explicit_probe_binding(executable, codex_home, requested_model, catalog):
    home = _explicit_launch_home(executable, codex_home)
    try:
        binding = prepare_capture_binding(home, requested_model=requested_model,
            permitted_tools=["exec_command", "write_stdin"], catalog_projection=catalog,
            expected_binary=executable)
    except CodexToolSurfaceError as exc:
        if str(exc) == "codex-capture-binding-drift:codex_binary":
            raise AppServerError("app-server-explicit-executable-mismatch") from exc
        raise
    if binding["codex_binary"] != str(Path(executable).resolve()):
        raise AppServerError("app-server-explicit-executable-mismatch")
    return binding


class AppServer:
    """Minimal stdlib JSON-RPC client for one trusted Codex app-server."""

    def __init__(
        self,
        *,
        requested_model: str = EXACT_MODEL,
        reasoning_effort: str = "low",
        tool_surface_proof: Mapping[str, Any] | None = None,
        tool_surface_probe_catalog: Path | None = None,
        tool_surface_probe_binding: Mapping[str, Any] | None = None,
        operation_metadata: Mapping[str, str] | None = None,
        executable: Path | str | None = None,
        codex_home: Path | str | None = None,
    ) -> None:
        self.process = None
        self._reader_threads: list[threading.Thread] = []
        self._close_lock = threading.RLock()
        self._closing = False
        self._cleanup_result: dict[str, Any] | None = None
        try:
            live_availability.require_n1_live()
            if not isinstance(requested_model, str) or not requested_model.strip():
                raise AppServerError("app-server-requested-model-invalid")
            if not isinstance(reasoning_effort, str) or reasoning_effort not in {"low", "medium", "high", "xhigh", "max", "ultra"}:
                raise AppServerError("app-server-reasoning-effort-invalid")
            if operation_metadata is not None and (
                type(operation_metadata) is not dict or
                set(operation_metadata) != {"cwo_bead", "cwo_control_turn", "cwo_mission"} or
                any(type(v) is not str or not v.strip() for v in operation_metadata.values())
            ):
                raise AppServerError("app-server-operation-metadata-invalid")
            self.operation_metadata = dict(operation_metadata) if operation_metadata is not None else None
            self.requested_model = requested_model.strip()
            self.reasoning_effort = reasoning_effort
            self._tool_surface_proof = (
                dict(tool_surface_proof)
                if isinstance(tool_surface_proof, Mapping)
                else None
            )
            home = None
            binding = None
            startup_config: dict[str, Any] = {}
            if tool_surface_proof is not None:
                if tool_surface_probe_catalog is not None or tool_surface_probe_binding is not None:
                    raise AppServerError("tool-proof-and-probe-catalog-conflict")
                verified = require_surface_proof(tool_surface_proof,
                    requested_model=self.requested_model,
                    permitted_tools=tool_surface_proof.get("requested_tools") if isinstance(tool_surface_proof, Mapping) else None)
                binding = require_capture_binding(verified["capture_binding"])
            elif tool_surface_probe_binding is not None:
                binding = require_capture_binding(tool_surface_probe_binding)
                if (binding["requested_model"] != self.requested_model
                        or (tool_surface_probe_catalog is not None and
                            binding["startup_config"].get("model_catalog_json") != str(tool_surface_probe_catalog.absolute()))):
                    raise AppServerError("tool-probe-binding-mismatch")
            elif tool_surface_probe_catalog is not None:
                binding = _explicit_probe_binding(executable, codex_home,
                    self.requested_model, tool_surface_probe_catalog)
            if binding is not None:
                home = Path(binding["codex_home"])
                startup_config = binding["startup_config"]
            else:
                home = _explicit_launch_home(executable, codex_home)
            # Register invalidation state BEFORE stdout readers and thread/start.
            self._mcp_guard_required = binding is not None and "effect_policy" in binding
            self._mcp_endpoint_fault = None
            self._mcp_notification_generation = 0
            self._zero_mcp_observations = {}
            self._mcp_finalized_threads = set()
            self.launched_executable = binding["codex_binary"] if binding else str(executable)
            command = [self.launched_executable]
            for key, value in sorted(startup_config.items()):
                command.extend(["-c", key + "=" + json.dumps(value)])
            command.extend(["app-server", "--stdio"])
            # The requested home is process-local, never a global config mutation.
            environment = dict(os.environ, CODEX_HOME=str(home),
                               PATH=str(Path(self.launched_executable).parent))
            live_availability.require_n1_live()
            self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, bufsize=1, umask=0o077, env=environment)
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
            self._known_thread_turn_ids: dict[str, set[str]] = {}
            self._turn_dispatch_records: dict[str, dict[str, Any]] = {}
            self._fresh_never_turned_thread_proofs: dict[str, dict[str, Any]] = {}
            self._archive_acceptance_proofs: dict[str, dict[str, Any]] = {}
            self._staged_archives: dict[str, Any] = {}
            self._delete_acceptance_proofs: dict[str, dict[str, Any]] = {}
            self._same_process_containment_proofs: dict[str, dict[str, Any]] = {}
            self._pending_turn_start_response_observers: dict[int, dict[str, Any]] = {}
            self._observed_negative_turn_response_capabilities_by_request: dict[
                int, object
            ] = {}
            self._negative_turn_response_capabilities = _IdentityCapabilityRegistry()
            self.allocation_ledger: NativeLiveAllocationLedgerStore | None = None
            for target in (self._read_stdout, self._drain_stderr):
                reader = threading.Thread(target=target, daemon=True)
                self._reader_threads.append(reader)
                reader.start()
                self._ensure_startup_open()
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
            if (not isinstance(result, Mapping) or not isinstance(result.get("codexHome"), str)
                    or not result["codexHome"].strip()):
                raise AppServerError("app-server-initialize-invalid")
            self.codex_home = Path(result["codexHome"]).resolve()
            if self.codex_home != home:
                raise AppServerError("codex-tool-surface-home-drift")
            self._ensure_startup_open()
            if binding is not None:
                require_capture_binding(binding)
            self.notify("initialized", {})
            self._ensure_startup_open()

        except BaseException as exc:
            try:
                cleanup = self.close()
            except BaseException as cleanup_exc:
                cleanup = getattr(cleanup_exc, "app_server_cleanup", None) or {
                    "all_contained": False, "resources_closed": False,
                    "errors": [f"{type(cleanup_exc).__name__}:{cleanup_exc}"],
                }
            if type(cleanup) is not dict:
                cleanup = {"all_contained": False, "resources_closed": False,
                           "errors": ["cleanup-result-invalid"]}
            exc.app_server_cleanup = cleanup
            if cleanup.get("errors") or cleanup.get("all_contained") is not True:
                exc.add_note("app-server construction cleanup: " + json.dumps(cleanup, sort_keys=True, default=str))
            if isinstance(exc, CodexToolSurfaceError):
                wrapped = AppServerError(str(exc))
                wrapped.app_server_cleanup = cleanup
                raise wrapped from exc
            raise

    def _ensure_startup_open(self) -> None:
        if self._closing or self._cleanup_result is not None:
            raise AppServerError("app-server-closed-during-startup")

    def attach_allocation_ledger(self, ledger: NativeLiveAllocationLedgerStore) -> None:
        if self.started_threads or self.allocation_ledger is not None:
            raise AppServerError("allocation-ledger-attach-state-invalid")
        state = ledger.load()
        self.allocation_ledger = ledger
        try:
            self._load_durable_turn_dispatch_records(state)
        except BaseException:
            self._turn_dispatch_records = {}
            self.started_threads = {}
            self.allocation_ledger = None
            raise

    def _load_durable_turn_dispatch_records(
        self, ledger_state: Mapping[str, Any]
    ) -> None:
        """Recover private dispatch correlations before containment resumes."""

        ledger = self.allocation_ledger
        if ledger is None:
            raise AppServerError("turn-dispatch-recovery-ledger-missing")
        directory = ledger.directory / "turn-dispatch"
        if not directory.exists():
            self._turn_dispatch_records = {}
            return
        metadata = directory.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise AppServerError("turn-dispatch-recovery-directory-invalid")
        intent_entries = {
            str(entry["turn_intent_id"]): entry
            for entry in ledger_state.get("entries", [])
            if isinstance(entry, Mapping)
            and entry.get("event") == "turn-intent"
            and isinstance(entry.get("turn_intent_id"), str)
        }
        recovered: dict[str, dict[str, Any]] = {}
        recovered_threads: dict[str, str | None] = {}
        for path in sorted(directory.iterdir(), key=lambda item: item.name):
            if path.suffix != ".json":
                raise AppServerError("turn-dispatch-recovery-file-invalid")
            record = load_private_json(path, "turn-dispatch-recovery")
            errors = validate_turn_dispatch_record(record)
            intent_id = record.get("turn_intent_id")
            intent_entry = intent_entries.get(str(intent_id))
            if (
                errors
                or path.name != f"{intent_id}.json"
                or record.get("ledger_id") != ledger_state.get("ledger_id")
                or intent_entry is None
                or record.get("thread_id") != intent_entry.get("thread_id")
                or record.get("turn_intent_entry_sha256")
                != intent_entry.get("entry_sha256")
                or record.get("ledger_head_entry_sha256")
                != intent_entry.get("entry_sha256")
            ):
                raise AppServerError("turn-dispatch-recovery-link-invalid")
            thread_id = str(record["thread_id"])
            if thread_id in recovered:
                raise AppServerError("turn-dispatch-recovery-thread-duplicate")
            resolution = ledger.turn_intent_resolution(str(intent_id))
            durable_resolution = str(resolution["resolution"])
            record_resolution = str(record["ledger_resolution"])
            if record_resolution != "pending" and record_resolution != durable_resolution:
                raise AppServerError("turn-dispatch-recovery-resolution-mismatch")
            turn_id = resolution.get("turn_id")
            recovered[thread_id] = dict(record)
            recovered_threads[thread_id] = (
                str(turn_id) if isinstance(turn_id, str) and turn_id else None
            )
        self._turn_dispatch_records = recovered
        self.started_threads.update(recovered_threads)

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
                if not isinstance(message, Mapping):
                    with self._condition:
                        self._reader_error = "app-server-non-object-output"
                        self._condition.notify_all()
                    continue
                with self._condition:
                    if type(message.get("id")) is int and (
                        "result" in message or "error" in message
                    ):
                        response_id = int(message["id"])
                        pending = getattr(
                            self, "_pending_turn_start_response_observers", {}
                        ).pop(response_id, None)
                        observed_capability: object | None = None
                        error = message.get("error")
                        exact_negative = bool(
                            "result" not in message
                            and isinstance(error, Mapping)
                            and type(error.get("code")) is int
                            and isinstance(error.get("message"), str)
                        )
                        if isinstance(pending, Mapping):
                            pending_capability = pending.get("capability")
                            if (
                                exact_negative
                                and pending_capability is not None
                                and isinstance(pending.get("thread_id"), str)
                                and isinstance(
                                    pending.get("turn_intent_id"), str
                                )
                                and pending.get("request_id") == response_id
                                and pending.get("connection_epoch_sha256")
                                == self.connection_epoch_sha256
                                and isinstance(
                                    pending.get("wire_request_sha256"), str
                                )
                                and isinstance(
                                    pending.get("dispatch_record_sha256"), str
                                )
                            ):
                                witness = {
                                    "request_id": response_id,
                                    "connection_epoch_sha256": str(
                                        pending["connection_epoch_sha256"]
                                    ),
                                    "wire_request_sha256": str(
                                        pending["wire_request_sha256"]
                                    ),
                                    "code": int(error["code"]),
                                    "response_sha256": domain_sha256(
                                        dict(message),
                                        domain=(
                                            "app-server-turn-start-negative-response"
                                        ),
                                    ),
                                }
                                # Security boundary: keep the pending-to-observed
                                # transition in the sole raw-stdout parser. Do not
                                # extract this into a helper that accepts a caller-
                                # supplied response mapping.
                                observed_candidate = object()
                                ledger = self.allocation_ledger
                                ledger_observed = ledger is None
                                if ledger is not None:
                                    with ledger._instance_lock:
                                        try:
                                            pending_binding = ledger._pending_turn_negative_response_observer_capabilities.pop(
                                                pending_capability
                                            )
                                        except (KeyError, TypeError):
                                            pending_binding = None
                                        if (
                                            pending_binding is not None
                                            and pending_binding.thread_id
                                            == pending.get("thread_id")
                                            and pending_binding.turn_intent_id
                                            == pending.get("turn_intent_id")
                                            and pending_binding.request_id
                                            == response_id
                                            and pending_binding.connection_epoch_sha256
                                            == pending.get(
                                                "connection_epoch_sha256"
                                            )
                                            and pending_binding.wire_request_sha256
                                            == pending.get("wire_request_sha256")
                                            and pending_binding.dispatch_record_sha256
                                            == pending.get(
                                                "dispatch_record_sha256"
                                            )
                                        ):
                                            ledger._turn_negative_response_observer_capabilities.register(
                                                observed_candidate,
                                                _TurnNegativeResponseObserverBinding(
                                                    thread_id=str(
                                                        pending["thread_id"]
                                                    ),
                                                    turn_intent_id=str(
                                                        pending[
                                                            "turn_intent_id"
                                                        ]
                                                    ),
                                                    request_id=response_id,
                                                    connection_epoch_sha256=str(
                                                        pending[
                                                            "connection_epoch_sha256"
                                                        ]
                                                    ),
                                                    wire_request_sha256=str(
                                                        pending[
                                                            "wire_request_sha256"
                                                        ]
                                                    ),
                                                    response_sha256=str(
                                                        witness[
                                                            "response_sha256"
                                                        ]
                                                    ),
                                                    response_code=int(
                                                        witness["code"]
                                                    ),
                                                ),
                                            )
                                            ledger_observed = True
                                if ledger_observed:
                                    capabilities = getattr(
                                        self,
                                        "_negative_turn_response_capabilities",
                                        None,
                                    )
                                    if capabilities is None:
                                        capabilities = (
                                            _IdentityCapabilityRegistry()
                                        )
                                        self._negative_turn_response_capabilities = (
                                            capabilities
                                        )
                                    by_request = getattr(
                                        self,
                                        "_observed_negative_turn_response_capabilities_by_request",
                                        None,
                                    )
                                    if by_request is None:
                                        by_request = {}
                                        self._observed_negative_turn_response_capabilities_by_request = (
                                            by_request
                                        )
                                    capabilities.register(
                                        observed_candidate,
                                        witness,
                                    )
                                    by_request[response_id] = observed_candidate
                                    observed_capability = observed_candidate
                            if observed_capability is None:
                                ledger = self.allocation_ledger
                                if (
                                    ledger is not None
                                    and pending_capability is not None
                                ):
                                    ledger._discard_turn_negative_response_observer_capability(
                                        pending_capability
                                    )
                        if response_id in self._responses:
                            self._reader_error = "app-server-duplicate-response-id"
                            if observed_capability is not None:
                                getattr(
                                    self,
                                    "_negative_turn_response_capabilities",
                                    {},
                                ).pop(observed_capability, None)
                                getattr(
                                    self,
                                    "_observed_negative_turn_response_capabilities_by_request",
                                    {},
                                ).pop(response_id, None)
                                ledger = self.allocation_ledger
                                if ledger is not None:
                                    ledger._discard_turn_negative_response_observer_capability(
                                        observed_capability
                                    )
                        else:
                            self._responses[response_id] = dict(message)
                    elif isinstance(message.get("method"), str):
                        self._observe_mcp_notification(message)
                        self._notifications.append(
                            (time.monotonic_ns(), dict(message))
                        )
                    self._condition.notify_all()
        finally:
            with self._condition:
                if self.process.poll() is None:
                    self._reader_error = "app-server-output-closed"
                self._condition.notify_all()

    def _observe_mcp_notification(self, message: Mapping[str, Any]) -> None:
        if (getattr(self, "_mcp_guard_required", False)
                and message.get("method") in {"mcpServer/startupStatus/updated", "config/mcpServer/reload"}):
            self._mcp_notification_generation += 1
            self._mcp_endpoint_fault = "app-server-mcp-endpoint-appearance"

    def _require_mcp_guard(self, thread_id: str | None = None) -> None:
        if not getattr(self, "_mcp_guard_required", False):
            return
        if self._mcp_endpoint_fault is not None or self._mcp_notification_generation != 0:
            raise AppServerError(self._mcp_endpoint_fault or "app-server-mcp-inventory-invalidated")
        if thread_id is not None and thread_id not in self._zero_mcp_observations:
            raise AppServerError("app-server-mcp-inventory-before-turn-required")

    def require_zero_mcp_endpoints(self, thread_id: str) -> dict[str, Any]:
        """Read the actual owned thread's full inventory; empty is not assumed."""
        with self._condition:
            self._require_mcp_guard()
            if type(thread_id) is not str or thread_id not in self.started_threads:
                raise AppServerError("app-server-mcp-inventory-thread-not-owned")
            generation = getattr(self, "_mcp_notification_generation", 0)
        pages, cursor, seen = [], None, set()
        for _ in range(100):
            params = {"threadId": thread_id, "detail": "full", "limit": 100, "cursor": cursor}
            response, _latency = self.request("mcpServerStatus/list", params, timeout=15)
            pages.append({"request": params, "response": copy.deepcopy(response)})
            with self._condition:
                self._require_mcp_guard()
                if getattr(self, "_mcp_notification_generation", 0) != generation:
                    raise AppServerError("app-server-mcp-inventory-reentrant-invalidation")
            if (type(response) is not dict or set(response) not in ({"data"}, {"data", "nextCursor"})
                    or response.get("data") != []):
                self._mcp_endpoint_fault = "app-server-mcp-endpoints-not-empty"
                raise AppServerError(self._mcp_endpoint_fault)
            cursor = response.get("nextCursor")
            if cursor is None:
                break
            if type(cursor) is not str or not cursor or cursor in seen:
                raise AppServerError("app-server-mcp-inventory-cursor-invalid")
            seen.add(cursor)
        observation = {"source": "app-server-thread-mcp-inventory-v1", "version": 1,
            "thread_id": thread_id, "pid": self.process.pid,
            "connection_epoch_sha256": self.connection_epoch_sha256,
            "notification_generation": generation, "pages": pages}
        try:
            checked = require_zero_endpoint_inventory(observation, thread_id=thread_id,
                pid=self.process.pid, connection_epoch_sha256=self.connection_epoch_sha256)
        except CodexToolSurfaceError as exc:
            raise AppServerError(str(exc)) from exc
        with self._condition:
            self._require_mcp_guard()
            self._zero_mcp_observations.setdefault(thread_id, []).append(copy.deepcopy(checked))
        return checked

    def _guard_thread_observation(self, thread_id: str, thread: Mapping[str, Any]) -> None:
        if not getattr(self, "_mcp_guard_required", False):
            return
        with self._condition:
            self._require_mcp_guard()
        turns = thread.get("turns")
        if type(turns) is not list:
            raise AppServerError("app-server-mcp-final-thread-turns-invalid")
        terminal = any(type(turn) is dict and turn.get("status") in {"completed", "failed", "interrupted"}
                       for turn in turns)
        if terminal and thread_id not in self._mcp_finalized_threads:
            self.require_zero_mcp_endpoints(thread_id)
            with self._condition:
                self._require_mcp_guard()
                self._mcp_finalized_threads.add(thread_id)

    def _drain_stderr(self) -> None:
        assert self.process.stderr is not None
        for _line in self.process.stderr:
            self._stderr_line_count += 1

    def notify(self, method: str, params: Mapping[str, Any]) -> None:
        payload = {"method": method, "params": dict(params)}
        assert self.process.stdin is not None
        with self._condition:
            _require_native_rpc(method)
            self.process.stdin.write(json.dumps(payload, separators=(",", ":")) + "\n")
            self.process.stdin.flush()

    def request(
        self,
        method: str,
        params: Mapping[str, Any],
        *,
        timeout: float = 30,
    ) -> tuple[dict[str, Any], float]:
        _require_native_rpc(method)
        assert self.process.stdin is not None
        with self._condition:
            self._request_id += 1
            request_id = self._request_id
            payload = {"id": request_id, "method": method, "params": dict(params)}
            if method in {"turn/start", "thread/start", "thread/resume", "thread/fork", "config/mcpServer/reload"}:
                self._require_mcp_guard(params.get("threadId") if method == "turn/start" else None)
                if method == "config/mcpServer/reload" and getattr(self, "_mcp_guard_required", False):
                    self._mcp_endpoint_fault = "app-server-mcp-reload-forbidden"
                    raise AppServerError(self._mcp_endpoint_fault)
            started = time.monotonic_ns()
            _require_native_rpc(method)
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

        _require_native_rpc(method)
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
            if method in {"turn/start", "thread/start", "thread/resume", "thread/fork", "config/mcpServer/reload"}:
                self._require_mcp_guard(params.get("threadId") if method == "turn/start" else None)
                if method == "config/mcpServer/reload" and getattr(self, "_mcp_guard_required", False):
                    self._mcp_endpoint_fault = "app-server-mcp-reload-forbidden"
                    raise AppServerError(self._mcp_endpoint_fault)
            self._request_id += 1
            request_id = self._request_id
            payload = {"id": request_id, "method": method, "params": dict(params)}
            payload_sha256 = domain_sha256(
                payload, domain="app-server-single-wire-request"
            )
            started = time.monotonic_ns()
            # There is deliberately one write and one flush.  This client has
            # no reconnect, redirect, timeout retry, or implicit replay path.
            _require_native_rpc(method)
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
        requested_model = getattr(self, "requested_model", EXACT_MODEL)
        matches = [item for item in models if isinstance(item, Mapping) and item.get("id") == requested_model]
        if len(matches) != 1 or matches[0].get("model") != requested_model:
            raise AppServerError("requested-model-unavailable")
        return {
            "id": matches[0]["id"],
            "model": matches[0]["model"],
            "display_name": matches[0].get("displayName"),
            "latency_ms": round(latency, 3),
        }

    def tool_surface_capability(
        self, *, permitted_tools: list[str]
    ) -> dict[str, Any]:
        proof = getattr(self, "_tool_surface_proof", None)
        requested_model = getattr(self, "requested_model", EXACT_MODEL)
        if proof is not None:
            try:
                verified = require_surface_proof(
                    proof,
                    requested_model=requested_model,
                    permitted_tools=permitted_tools,
                )
            except CodexToolSurfaceError as exc:
                raise AppServerError(str(exc)) from exc
            return {
                "source": (
                    "codex-app-server-v2-thread-config-proof:"
                    + verified["proof_sha256"]
                ),
                "server_allowlist_supported": True,
                "allowlist_parameter": CONFIG_TOOL_ALLOWLIST_PARAMETER,
                "effective_allowlist": list(verified["observed_tools"]),
            }
        return {
            "source": "codex-app-server-v2-thread-start-schema",
            "server_allowlist_supported": False,
            "allowlist_parameter": None,
            "effective_allowlist": None,
        }

    def capability_adapter_version(self) -> str:
        """Return the app-server version bound by the exact surface proof."""

        proof = getattr(self, "_tool_surface_proof", None)
        if proof is None:
            return "codex-app-server-0.144.5"
        try:
            verified = require_surface_proof(
                proof,
                requested_model=getattr(self, "requested_model", EXACT_MODEL),
                permitted_tools=proof.get("requested_tools") if isinstance(proof, Mapping) else None,
            )
        except CodexToolSurfaceError as exc:
            raise AppServerError(str(exc)) from exc
        version = verified.get("codex_version")
        if not isinstance(version, str) or not version.strip():
            raise AppServerError("codex-tool-surface-version-invalid")
        return f"codex-app-server-{version.strip()}"

    def operative_tool_transport(self) -> str:
        """Return the proof-bound call transport used by this model."""

        proof = getattr(self, "_tool_surface_proof", None)
        if proof is None:
            return DIRECT_TOOL_TRANSPORT
        try:
            verified = require_surface_proof(
                proof,
                requested_model=getattr(self, "requested_model", EXACT_MODEL),
                permitted_tools=proof.get("requested_tools") if isinstance(proof, Mapping) else None,
            )
        except CodexToolSurfaceError as exc:
            raise AppServerError(str(exc)) from exc
        transport = verified.get("tool_transport")
        if not isinstance(transport, str) or transport not in {
            DIRECT_TOOL_TRANSPORT,
            NAMESPACED_EXEC_TOOL_TRANSPORT,
        }:
            raise AppServerError("codex-tool-surface-transport-invalid")
        return str(transport)

    def _thread_tool_allowlist_params(
        self,
        *,
        permitted_tools: list[str] | None,
        allowlist_parameter: str | None,
    ) -> dict[str, Any]:
        """Return only a capability-backed, exact server allowlist parameter."""

        if permitted_tools is None:
            if allowlist_parameter is not None:
                raise AppServerError("thread-start-tool-allowlist-without-tools")
            return {}
        if (
            not isinstance(allowlist_parameter, str)
            or re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,127}", allowlist_parameter)
            is None
        ):
            raise AppServerError("thread-start-tool-allowlist-parameter-missing")
        if (
            not isinstance(permitted_tools, list)
            or not permitted_tools
            or any(
                not isinstance(tool, str)
                or re.fullmatch(r"[a-z][a-z0-9_.:-]{0,127}", tool) is None
                for tool in permitted_tools
            )
            or permitted_tools != sorted(permitted_tools)
            or len(permitted_tools) != len(set(permitted_tools))
        ):
            raise AppServerError("thread-start-tool-allowlist-invalid")
        # This method is part of the trusted in-process controller. Worker
        # input cannot replace the capability reader or its result.
        capability = self.tool_surface_capability(
            permitted_tools=list(permitted_tools)
        )
        expected_fields = {
            "source",
            "server_allowlist_supported",
            "allowlist_parameter",
            "effective_allowlist",
        }
        if not isinstance(capability, Mapping) or set(capability) != expected_fields:
            raise AppServerError("thread-start-tool-surface-capability-invalid")
        if (
            not isinstance(capability.get("source"), str)
            or not capability["source"].strip()
            or type(capability.get("server_allowlist_supported")) is not bool
        ):
            raise AppServerError("thread-start-tool-surface-capability-invalid")
        if capability["server_allowlist_supported"] is not True:
            raise AppServerError("thread-start-tool-restriction-unsupported")
        if capability.get("allowlist_parameter") != allowlist_parameter:
            raise AppServerError("thread-start-tool-allowlist-parameter-mismatch")
        effective_allowlist = capability.get("effective_allowlist")
        if (
            not isinstance(effective_allowlist, list)
            or any(
                not isinstance(tool, str)
                or re.fullmatch(r"[a-z][a-z0-9_.:-]{0,127}", tool) is None
                for tool in effective_allowlist
            )
            or effective_allowlist != sorted(effective_allowlist)
            or len(effective_allowlist) != len(set(effective_allowlist))
        ):
            raise AppServerError("thread-start-tool-surface-capability-invalid")
        if effective_allowlist != permitted_tools:
            raise AppServerError("thread-start-tool-allowlist-effective-mismatch")
        if allowlist_parameter == CONFIG_TOOL_ALLOWLIST_PARAMETER:
            try:
                return thread_start_enforcement_params(
                    getattr(self, "_tool_surface_proof", None),
                    requested_model=getattr(self, "requested_model", EXACT_MODEL),
                    permitted_tools=permitted_tools,
                )
            except CodexToolSurfaceError as exc:
                raise AppServerError(str(exc)) from exc
        return {allowlist_parameter: list(permitted_tools)}

    def start_thread(
        self,
        cwd: Path,
        *,
        mutable: bool,
        role: str | None = None,
        thread_phase: str = THREAD_PHASE_LIVE_CANARY,
        permitted_tools: list[str] | None = None,
        allowlist_parameter: str | None = None,
    ) -> tuple[dict[str, Any], float]:
        if self.allocation_ledger is not None:
            if role not in EXPECTED_ROLES:
                raise AppServerError("allocation-ledger-role-required")
        if thread_phase not in THREAD_START_PHASES:
            raise AppServerError("thread-start-phase-invalid")
        sealed_cwd = _canonical_controller_workdir(cwd)
        transport = self.operative_tool_transport()
        tool_allowlist_params = self._thread_tool_allowlist_params(
            permitted_tools=permitted_tools,
            allowlist_parameter=allowlist_parameter,
        )
        if mutable and isinstance(getattr(self, "_tool_surface_proof", None), Mapping) and not tool_profile_is_mutable(self._tool_surface_proof.get("tool_profile")):
            raise AppServerError("read-only-tool-profile-mutable-thread-forbidden")
        if thread_phase == THREAD_PHASE_PRECOMMIT_FIT:
            developer_instructions = (
                "This is a trusted CWO no-tools precommit fit estimate, not the later "
                "implementation task. Do not inspect or modify the repository. Do not use "
                "tools, spawn subagents, or use network access. The primary outcome and "
                "acceptance checks describe work that a later operative worker may perform; "
                "your only task in this turn is to estimate that later worker's required tool "
                "calls and runtime. Return exactly one JSON object containing only these five "
                "fields: decision, tool_calls_p50, tool_calls_p90, runtime_seconds_p50, and "
                "runtime_seconds_p90. decision must be accept, pm-realignment, or architect-realignment. "
                "Do not add status, reason, primary_outcome, or commentary."
            )
        else:
            developer_instructions = (
                "This is a bounded CWO live canary. Do not spawn subagents, use network access, "
                "or access paths outside the supplied workspace. Follow the user task exactly."
            )
            try:
                developer_instructions += tool_transport_instructions(permitted_tools, transport)
            except CodexToolSurfaceError as exc:
                raise AppServerError(str(exc)) from exc
        params: dict[str, Any] = {
            "model": getattr(self, "requested_model", EXACT_MODEL),
            "allowProviderModelFallback": False,
            "cwd": str(sealed_cwd),
            "runtimeWorkspaceRoots": [str(sealed_cwd)],
            "approvalPolicy": "never",
            "sandbox": "workspace-write" if mutable else "read-only",
            "ephemeral": False,
            "historyMode": "legacy",
            "developerInstructions": developer_instructions,
        }
        if set(tool_allowlist_params).intersection(params):
            raise AppServerError("thread-start-tool-allowlist-parameter-collision")
        params.update(tool_allowlist_params)
        allocation_intent_id: str | None = None
        if self.allocation_ledger is not None:
            allocation_intent_id = self.allocation_ledger.allocation_intent(str(role))
        result, latency = self.request(
            "thread/start",
            params,
            timeout=30,
        )
        thread = result.get("thread")
        if not isinstance(thread, Mapping) or not thread.get("id"):
            raise AppServerError("thread-start-response-invalid")
        thread_id = str(thread["id"])
        self.started_threads[thread_id] = None
        getattr(self, "_fresh_never_turned_thread_proofs", {}).pop(
            thread_id,
            None,
        )
        getattr(self, "_archive_acceptance_proofs", {}).pop(
            thread_id,
            None,
        )
        getattr(self, "_delete_acceptance_proofs", {}).pop(
            thread_id,
            None,
        )
        getattr(self, "_same_process_containment_proofs", {}).pop(
            thread_id,
            None,
        )
        turns = thread.get("turns")
        if not hasattr(self, "_known_thread_turn_ids"):
            self._known_thread_turn_ids = {}
        self._known_thread_turn_ids[thread_id] = (
            {
                str(item["id"])
                for item in turns
                if isinstance(item, Mapping)
                and isinstance(item.get("id"), str)
                and item.get("id")
            }
            if isinstance(turns, list)
            else set()
        )
        if self.allocation_ledger is not None and allocation_intent_id is not None:
            self.allocation_ledger.bind_thread(allocation_intent_id, thread_id)
        if result.get("model") != getattr(self, "requested_model", EXACT_MODEL):
            raise AppServerError("thread-start-model-mismatch")
        if type(turns) is list and not turns:
            fresh_proofs = getattr(
                self,
                "_fresh_never_turned_thread_proofs",
                None,
            )
            if fresh_proofs is None:
                fresh_proofs = {}
                self._fresh_never_turned_thread_proofs = fresh_proofs
            fresh_proofs[thread_id] = _seal_same_process_proof(
                {
                    "proof_type": "app-server-connection-local-thread-proof",
                    "version": 1,
                    "kind": "fresh-never-turned",
                    "thread_id_sha256": sha256_text(thread_id),
                    "connection_epoch_sha256": self.connection_epoch_sha256,
                    "known_turn_ids_sha256": domain_sha256(
                        [],
                        domain="app-server-known-thread-turn-ids",
                    ),
                    "thread_start_response_sha256": domain_sha256(
                        dict(result),
                        domain="app-server-fresh-thread-start-response",
                    ),
                },
                domain="app-server-connection-local-thread-proof",
            )
        response = copy.deepcopy(dict(result))
        evidence = getattr(self, "_effective_thread_start_evidence", None)
        if evidence is None:
            evidence = {}
            self._effective_thread_start_evidence = evidence
        evidence[thread_id] = {
            "request": copy.deepcopy(params),
            "response": copy.deepcopy(response),
        }
        if getattr(self, "_mcp_guard_required", False):
            self.require_zero_mcp_endpoints(thread_id)
        return response, latency

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
        self._guard_thread_observation(thread_id, thread)
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
        self._guard_thread_observation(thread_id, thread)
        return dict(thread), latency, guarded, request_id, payload_sha256

    def _turn_dispatch_path(self, turn_intent_id: str) -> Path | None:
        ledger = self.allocation_ledger
        if ledger is None:
            return None
        return ledger.directory / "turn-dispatch" / f"{turn_intent_id}.json"

    def _consume_negative_turn_response_capability(
        self,
        capability: object,
        record: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Consume the exact object identity bound to this dispatch action."""

        capabilities = getattr(self, "_negative_turn_response_capabilities", {})
        try:
            witness = capabilities.pop(capability)
        except (KeyError, TypeError) as exc:
            raise AppServerError(
                "turn-negative-response-capability-invalid"
            ) from exc
        if (
            witness.get("request_id") != record.get("request_id")
            or witness.get("connection_epoch_sha256")
            != record.get("connection_epoch_sha256")
            or witness.get("wire_request_sha256")
            != record.get("wire_request_sha256")
        ):
            raise AppServerError("turn-negative-response-capability-mismatch")
        return dict(witness)

    def _discard_negative_turn_response_capability(
        self,
        capability: object,
    ) -> None:
        """Revoke an observed capability without creating replacement authority."""

        try:
            getattr(self, "_negative_turn_response_capabilities", {}).pop(
                capability, None
            )
        except TypeError:
            return
        by_request = getattr(
            self,
            "_observed_negative_turn_response_capabilities_by_request",
            {},
        )
        for request_id, candidate in tuple(by_request.items()):
            if candidate is capability:
                by_request.pop(request_id, None)
        ledger = self.allocation_ledger
        if ledger is not None:
            ledger._discard_turn_negative_response_observer_capability(capability)

    def _persist_turn_dispatch_record(
        self, record: Mapping[str, Any]
    ) -> dict[str, Any]:
        with self._condition:
            descriptor = self._open_turn_dispatch_lock(
                str(record["turn_intent_id"])
            )
            try:
                if descriptor is not None:
                    fcntl.flock(descriptor, fcntl.LOCK_EX)
                return self._persist_turn_dispatch_record_locked(record)
            finally:
                if descriptor is not None:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                    os.close(descriptor)

    def _persist_turn_dispatch_record_locked(
        self, record: Mapping[str, Any]
    ) -> dict[str, Any]:
        """Persist while the caller holds this turn's condition and file lock."""

        errors = validate_turn_dispatch_record(record)
        if errors:
            raise AppServerError("turn-dispatch-record-invalid:" + ";".join(errors))
        persisted = dict(record)
        records = getattr(self, "_turn_dispatch_records", None)
        if records is None:
            records = {}
            self._turn_dispatch_records = records
        records[str(record["thread_id"])] = persisted
        path = self._turn_dispatch_path(str(record["turn_intent_id"]))
        if path is not None:
            write_private_artifact(path, persisted)
        return persisted

    def _open_turn_dispatch_lock(self, turn_intent_id: str) -> int | None:
        """Open the cross-AppServer lock for one exact durable turn intent."""

        ledger = self.allocation_ledger
        if ledger is None:
            return None
        lock_directory = _private_control_directory(
            ledger.directory / "turn-dispatch-locks",
            "turn-dispatch",
        )
        return _open_private_control_lock(
            lock_directory / f"{turn_intent_id}.lock",
            "turn-dispatch",
        )

    def turn_dispatch_record(self, thread_id: str) -> dict[str, Any] | None:
        with self._condition:
            record = getattr(self, "_turn_dispatch_records", {}).get(thread_id)
            return dict(record) if isinstance(record, Mapping) else None

    def _turn_intent_ledger_link(
        self, turn_intent_id: str
    ) -> tuple[str | None, str | None, str | None]:
        ledger = self.allocation_ledger
        if ledger is None:
            return None, None, None
        state = ledger.load()
        entries = state.get("entries")
        if not isinstance(entries, list):
            raise AppServerError("turn-dispatch-ledger-intent-link-invalid")
        matches = [
            entry
            for entry in entries
            if isinstance(entry, Mapping)
            and entry.get("event") == "turn-intent"
            and entry.get("turn_intent_id") == turn_intent_id
        ]
        if len(matches) != 1:
            raise AppServerError("turn-dispatch-ledger-intent-link-invalid")
        return (
            str(state["ledger_id"]),
            str(state["head_entry_sha256"]),
            str(matches[0]["entry_sha256"]),
        )

    @staticmethod
    def _projected_turns(thread: Mapping[str, Any]) -> dict[str, str | None]:
        turns = thread.get("turns")
        if not isinstance(turns, list):
            raise AppServerError("ambiguous-turn-thread-projection-invalid")
        projected: dict[str, str | None] = {}
        for item in turns:
            if not isinstance(item, Mapping):
                raise AppServerError("ambiguous-turn-thread-projection-invalid")
            turn_id = item.get("id")
            if not isinstance(turn_id, str) or not turn_id or turn_id in projected:
                raise AppServerError("ambiguous-turn-thread-projection-invalid")
            raw_status = item.get("status")
            projected[turn_id] = str(raw_status) if raw_status else None
        return projected

    @staticmethod
    def _normalized_terminal_status(status: str | None) -> str | None:
        normalized = {
            "completed": "completed",
            "failed": "failed",
            "interrupted": "interrupted",
        }
        return normalized.get(status or "")

    def _late_turn_start_response(
        self,
        record: Mapping[str, Any],
    ) -> tuple[str | None, object | None]:
        """Consume only stdout-observed late evidence for the reserved request."""

        request_id = int(record["request_id"])
        with self._condition:
            message = self._responses.pop(request_id, None)
            if message is None:
                return None, None
            observed = getattr(
                self,
                "_observed_negative_turn_response_capabilities_by_request",
                {},
            ).pop(request_id, None)
        if not isinstance(message, Mapping):
            if observed is not None:
                self._discard_negative_turn_response_capability(observed)
            return None, None
        error = message.get("error")
        if "error" in message:
            witness = getattr(
                self, "_negative_turn_response_capabilities", {}
            ).get(observed)
            if (
                "result" not in message
                and isinstance(error, Mapping)
                and type(error.get("code")) is int
                and isinstance(error.get("message"), str)
                and observed is not None
                and isinstance(witness, Mapping)
                and message.get("id") == request_id
                and witness.get("request_id") == request_id
                and witness.get("connection_epoch_sha256")
                == record.get("connection_epoch_sha256")
                and witness.get("wire_request_sha256")
                == record.get("wire_request_sha256")
                and witness.get("code") == error.get("code")
                and witness.get("response_sha256")
                == domain_sha256(
                    dict(message),
                    domain="app-server-turn-start-negative-response",
                )
            ):
                return None, observed
            if observed is not None:
                self._discard_negative_turn_response_capability(observed)
            return None, None
        if observed is not None:
            self._discard_negative_turn_response_capability(observed)
        result = message.get("result")
        turn = result.get("turn") if isinstance(result, Mapping) else None
        turn_id = turn.get("id") if isinstance(turn, Mapping) else None
        return (
            str(turn_id) if isinstance(turn_id, str) and turn_id else None,
            None,
        )

    def _post_cursor_turn_starts(
        self,
        *,
        thread_id: str,
        after_sequence: int,
        preexisting_turn_ids: set[str],
    ) -> tuple[set[str], set[int], int]:
        turn_ids: set[str] = set()
        sequences: set[int] = set()
        with self._condition:
            notifications = list(self._notifications)
            observed_cursor = len(notifications)
        for sequence, (_received_ns, message) in enumerate(notifications, 1):
            if sequence <= after_sequence or message.get("method") != "turn/started":
                continue
            params = (
                message.get("params")
                if isinstance(message.get("params"), Mapping)
                else {}
            )
            if params.get("threadId") != thread_id:
                continue
            turn = params.get("turn") if isinstance(params.get("turn"), Mapping) else {}
            turn_id = turn.get("id") or params.get("turnId")
            if (
                isinstance(turn_id, str)
                and turn_id
                and turn_id not in preexisting_turn_ids
            ):
                turn_ids.add(turn_id)
                sequences.add(sequence)
        return turn_ids, sequences, observed_cursor

    def _bind_ambiguous_turn_candidate(
        self,
        record: Mapping[str, Any],
        candidate_turn_ids: set[str],
        *,
        exact_response_turn_id: str | None,
    ) -> str:
        canonical = (
            exact_response_turn_id
            if exact_response_turn_id in candidate_turn_ids
            else sorted(candidate_turn_ids)[0]
        )
        if record.get("ledger_resolution") == "pending":
            if self.allocation_ledger is not None:
                self.allocation_ledger.bind_turn(
                    str(record["thread_id"]),
                    str(record["turn_intent_id"]),
                    canonical,
                )
            self.started_threads[str(record["thread_id"])] = canonical
        return canonical

    def contain_ambiguous_turn_dispatch(
        self,
        thread_id: str,
        *,
        timeout: float = AMBIGUOUS_TURN_DISCOVERY_TIMEOUT_SECONDS,
        negative_response_capability: object | None = None,
    ) -> dict[str, Any]:
        """Discover and contain one uncertain ``turn/start`` without replaying it."""

        current = self.turn_dispatch_record(thread_id)
        if current is None:
            raise AppServerError("ambiguous-turn-dispatch-record-missing")
        ledger = self.allocation_ledger

        def exactly_verified_failed_contained(record: Mapping[str, Any]) -> bool:
            """Accept a final record only through the exact durable verifier."""

            if (
                ledger is None
                or record.get("status") != "failed-contained"
                or record.get("thread_id") != thread_id
            ):
                return False
            try:
                witness = ledger.verify_contained_turn_dispatch(
                    thread_id,
                    str(record["turn_intent_id"]),
                )
                verified = ledger.consume_verified_contained_turn_dispatch(
                    witness,
                    expected_thread_id=thread_id,
                    expected_turn_intent_id=str(record["turn_intent_id"]),
                )
                return bool(
                    verified.get("verification_grade") == "ledger-chain-only"
                    and verified.get("dispatch_authorized") is False
                    and verified.get("dispatch_record_sha256")
                    == record.get("record_sha256")
                )
            except Exception:
                return False

        def persist_exact_audited_success(
            precursor: Mapping[str, Any],
            *,
            allow_audit_create: bool,
        ) -> dict[str, Any]:
            """Audit an exact successor while the durable status stays ambiguous."""

            with self._condition:
                descriptor = self._open_turn_dispatch_lock(
                    str(precursor["turn_intent_id"])
                )
                try:
                    if descriptor is not None:
                        fcntl.flock(descriptor, fcntl.LOCK_EX)
                    path = self._turn_dispatch_path(
                        str(precursor["turn_intent_id"])
                    )
                    durable = (
                        load_private_json(path, "turn-dispatch-cas")
                        if path is not None
                        else self.turn_dispatch_record(thread_id)
                    )
                    if durable is None:
                        raise AppServerError("turn-dispatch-cas-record-missing")
                    errors = validate_turn_dispatch_record(durable)
                    if errors:
                        raise AppServerError(
                            "turn-dispatch-cas-record-invalid:" + ";".join(errors)
                        )
                    if durable != dict(precursor):
                        conflict = dict(durable)
                        if (
                            conflict["status"] == "failed-contained"
                            and not exactly_verified_failed_contained(conflict)
                        ):
                            conflict = evolve_turn_dispatch_record(
                                conflict,
                                status="failed-ambiguous",
                            )
                            return self._persist_turn_dispatch_record_locked(conflict)
                        self._turn_dispatch_records[thread_id] = conflict
                        return conflict
                    if ledger is None:
                        return dict(precursor)
                    candidate = evolve_turn_dispatch_record(
                        precursor,
                        status="failed-contained",
                    )
                    try:
                        if allow_audit_create:
                            ledger.record_containment_audit(
                                thread_id,
                                outcome="contained",
                                evidence={
                                    "dispatch_record_sha256": candidate[
                                        "record_sha256"
                                    ],
                                    "absence_proof_sha256": candidate[
                                        "absence_proof_sha256"
                                    ],
                                    "discovered_turn_ids": candidate[
                                        "discovered_turn_ids"
                                    ],
                                    "terminal_status_by_turn": candidate[
                                        "terminal_status_by_turn"
                                    ],
                                    "absence_verified": True,
                                    "archive_request_accepted": True,
                                },
                            )
                        elif not ledger.has_exact_containment_audit_for_dispatch(
                            candidate
                        ):
                            return dict(precursor)
                    except Exception:
                        return dict(precursor)
                    durable_after_audit = load_private_json(
                        path, "turn-dispatch-cas"
                    )
                    errors = validate_turn_dispatch_record(durable_after_audit)
                    if errors:
                        raise AppServerError(
                            "turn-dispatch-cas-record-invalid:" + ";".join(errors)
                        )
                    if durable_after_audit != dict(precursor):
                        conflict = dict(durable_after_audit)
                        if (
                            conflict["status"] == "failed-contained"
                            and not exactly_verified_failed_contained(conflict)
                        ):
                            conflict = evolve_turn_dispatch_record(
                                conflict,
                                status="failed-ambiguous",
                            )
                            return self._persist_turn_dispatch_record_locked(conflict)
                        self._turn_dispatch_records[thread_id] = conflict
                        return conflict
                    return self._persist_turn_dispatch_record_locked(candidate)
                finally:
                    if descriptor is not None:
                        fcntl.flock(descriptor, fcntl.LOCK_UN)
                        os.close(descriptor)

        if current["status"] == "failed-contained":
            if not exactly_verified_failed_contained(current):
                current = self._persist_turn_dispatch_record(
                    evolve_turn_dispatch_record(
                        current,
                        status="failed-ambiguous",
                    )
                )
            else:
                return current
        if current["status"] not in {"dispatching", "failed-ambiguous"}:
            raise AppServerError("ambiguous-turn-dispatch-state-invalid")
        ambiguity_reason = (
            str(current["ambiguity_reason"])
            if current["ambiguity_reason"] is not None
            else "dispatch-interrupted-before-response"
        )

        deadline = time.monotonic() + max(0.0, float(timeout))
        same_connection_epoch = (
            current["connection_epoch_sha256"] == self.connection_epoch_sha256
        )
        discovery_cursor = (
            int(current["notification_cursor"]) if same_connection_epoch else 0
        )
        preexisting = set(current["preexisting_turn_ids"])
        discovered = set(current["discovered_turn_ids"])
        attempted = set(current["interrupt_attempted_turn_ids"])
        interrupt_failed = set(current["interrupt_failed_turn_ids"])
        terminal_statuses = dict(current["terminal_status_by_turn"])
        notification_epoch = self.connection_epoch_sha256
        notification_sequences = (
            set(current["notification_sequences"])
            if current.get("notification_connection_epoch_sha256")
            == notification_epoch
            else set()
        )
        exact_response_turn_id = current.get("exact_response_turn_id")
        query_count = int(current["query_count"])
        final_active: set[str] = set(current["active_turn_ids_at_final_check"])
        absence_verified = False
        ledger_resolution = str(current["ledger_resolution"])
        durable_absence_authorized = False
        if ledger is not None:
            durable = ledger.turn_intent_resolution(str(current["turn_intent_id"]))
            durable_resolution = str(durable["resolution"])
            if ledger_resolution != "pending" and ledger_resolution != durable_resolution:
                raise AppServerError("ambiguous-turn-ledger-resolution-mismatch")
            if durable_resolution == "turn-bound":
                durable_turn_id = durable.get("turn_id")
                if not isinstance(durable_turn_id, str) or not durable_turn_id:
                    raise AppServerError("ambiguous-turn-ledger-binding-invalid")
                discovered.add(durable_turn_id)
                self.started_threads[thread_id] = durable_turn_id
                ledger_resolution = "turn-bound"
            elif durable_resolution == "verified-absent":
                evidence_sha256 = durable.get("evidence_sha256")
                if not isinstance(evidence_sha256, str):
                    raise AppServerError("ambiguous-turn-ledger-absence-invalid")
                if current.get("absence_proof_sha256") not in {
                    None,
                    evidence_sha256,
                }:
                    raise AppServerError("ambiguous-turn-ledger-absence-mismatch")
                ledger_resolution = "verified-absent"
                durable_absence_authorized = True
        audit_pending = bool(
            current.get("status") == "failed-ambiguous"
            and current.get("archived") is True
            and current.get("absence_verified") is True
            and not current.get("active_turn_ids_at_final_check")
            and not current.get("interrupt_failed_turn_ids")
            and set(current.get("discovered_turn_ids", []))
            == set(current.get("terminal_status_by_turn", {}))
            and current.get("ledger_resolution") in {"turn-bound", "verified-absent"}
            and current.get("ledger_resolution") == ledger_resolution
        )
        if audit_pending:
            return persist_exact_audited_success(
                current,
                allow_audit_create=False,
            )
        first_pass = True

        while first_pass or time.monotonic() < deadline:
            first_pass = False
            late_turn, late_negative = (
                self._late_turn_start_response(current)
                if same_connection_epoch
                else (None, None)
            )
            if late_turn is not None:
                exact_response_turn_id = late_turn
                if late_turn not in preexisting:
                    discovered.add(late_turn)
            if late_negative is not None:
                if negative_response_capability is None:
                    negative_response_capability = late_negative
                    ambiguity_reason = "rpc-error-response"
                elif late_negative is not negative_response_capability:
                    self._discard_negative_turn_response_capability(late_negative)
            notified, sequences, observed_cursor = self._post_cursor_turn_starts(
                thread_id=thread_id,
                after_sequence=discovery_cursor,
                preexisting_turn_ids=preexisting,
            )
            discovered.update(notified)
            notification_sequences.update(sequences)

            remaining = max(0.001, deadline - time.monotonic())
            query_succeeded = False
            try:
                thread, _latency = self.read_thread(
                    thread_id,
                    timeout=min(THREAD_READ_TIMEOUT_SECONDS, remaining),
                )
                query_count += 1
                query_succeeded = True
                projected = self._projected_turns(thread)
            except Exception:
                projected = {}
            # A turn/start notification can be delivered after the thread/read
            # snapshot but before the proof decision. Recheck the receive queue
            # after every successful or failed query and fold it into discovery.
            post_notified, post_sequences, observed_cursor = (
                self._post_cursor_turn_starts(
                    thread_id=thread_id,
                    after_sequence=discovery_cursor,
                    preexisting_turn_ids=preexisting,
                )
            )
            discovered.update(post_notified)
            notification_sequences.update(post_sequences)
            discovered.update(set(projected) - preexisting)

            final_active = {
                turn_id
                for turn_id, status in projected.items()
                if self._normalized_terminal_status(status) is None
            }
            for turn_id in discovered:
                terminal = self._normalized_terminal_status(projected.get(turn_id))
                if terminal is not None:
                    terminal_statuses[turn_id] = terminal
            interrupt_failed.difference_update(terminal_statuses)
            # Exact responses and post-cursor start notifications prove that a
            # candidate existed even when thread/read is unavailable. Treat
            # every discovered candidate as active until a trusted terminal
            # projection proves otherwise, so query failure cannot leave it
            # running merely because its current status is unknown.
            active_candidates = sorted(discovered - set(terminal_statuses))
            for turn_id in active_candidates:
                attempted.add(turn_id)
                try:
                    self.interrupt_turn(
                        thread_id,
                        turn_id,
                        timeout=min(
                            15.0,
                            max(0.001, deadline - time.monotonic()),
                        ),
                    )
                except Exception:
                    interrupt_failed.add(turn_id)
                else:
                    # The failure set describes the latest attempt, not a sticky
                    # historical veto. A later accepted interrupt is retryable.
                    interrupt_failed.discard(turn_id)

            all_discovered_terminal = set(terminal_statuses) == discovered
            terminal_snapshot = bool(
                query_succeeded
                and not final_active
                and all_discovered_terminal
                and not interrupt_failed
                and not active_candidates
            )
            if terminal_snapshot and (
                discovered
                or negative_response_capability is not None
                or durable_absence_authorized
            ):
                # A terminal projection proves discovered turns inactive. An
                # empty projection is never authoritative by itself: only the
                # exact negative-response capability or an already-bound
                # durable proof may authorize the no-turn branch.
                absence_verified = bool(discovered or durable_absence_authorized)
                break
            if time.monotonic() >= deadline:
                break
            time.sleep(
                min(
                    AMBIGUOUS_TURN_DISCOVERY_POLL_SECONDS,
                    max(0.0, deadline - time.monotonic()),
                )
            )

        containment_state_complete = bool(
            set(terminal_statuses) == discovered
            and not interrupt_failed
            and not final_active
        )
        contained = bool(
            containment_state_complete
            and (
                discovered
                or negative_response_capability is not None
                or durable_absence_authorized
            )
        )
        absence_proof_sha256 = current.get("absence_proof_sha256")
        archived = False
        if contained:
            try:
                if discovered and ledger_resolution == "verified-absent":
                    raise AppServerError("ambiguous-turn-after-absence-resolution")
                if discovered and ledger_resolution == "pending":
                    self._bind_ambiguous_turn_candidate(
                        current,
                        discovered,
                        exact_response_turn_id=exact_response_turn_id,
                    )
                    ledger_resolution = "turn-bound"
                elif not discovered and ledger_resolution == "pending":
                    if ledger is None:
                        raise AppServerError("turn-absence-proof-ledger-missing")
                    if negative_response_capability is None:
                        raise AppServerError(
                            "turn-absence-negative-response-capability-missing"
                        )
                    negative_response = (
                        self._consume_negative_turn_response_capability(
                            negative_response_capability,
                            current,
                        )
                    )
                    proof_dispatch = evolve_turn_dispatch_record(
                        current,
                        wire_write_attempt_count=1,
                        status="failed-ambiguous",
                        ambiguity_reason=ambiguity_reason,
                        exact_response_turn_id=None,
                        notification_connection_epoch_sha256=notification_epoch,
                        notification_sequences=sorted(notification_sequences),
                        discovered_turn_ids=[],
                        interrupt_attempted_turn_ids=[],
                        interrupt_failed_turn_ids=[],
                        terminal_status_by_turn={},
                        active_turn_ids_at_final_check=[],
                        query_count=query_count,
                        absence_verified=False,
                        absence_proof_sha256=None,
                        archived=False,
                        ledger_resolution="pending",
                    )
                    current = self._persist_turn_dispatch_record(proof_dispatch)
                    proof = seal_turn_absence_proof(
                        {
                            "artifact_type": TURN_ABSENCE_PROOF_ARTIFACT_TYPE,
                            "version": 1,
                            "thread_id": thread_id,
                            "turn_intent_id": current["turn_intent_id"],
                            "ledger_id": current["ledger_id"],
                            "turn_intent_entry_sha256": current[
                                "turn_intent_entry_sha256"
                            ],
                            "dispatch_record": current,
                            "negative_response": negative_response,
                            "proof_sha256": "",
                        }
                    )
                    verifier_capability = (
                        ledger._mint_turn_absence_verifier_capability(
                            proof,
                            negative_response_capability=(
                                negative_response_capability
                            ),
                        )
                    )
                    ledger.resolve_turn_intent_absent(
                        thread_id,
                        str(current["turn_intent_id"]),
                        proof=proof,
                        verifier_capability=verifier_capability,
                    )
                    absence_proof_sha256 = str(proof["proof_sha256"])
                    ledger_resolution = "verified-absent"
                    absence_verified = True
                elif not discovered and ledger_resolution == "verified-absent":
                    if ledger is None:
                        raise AppServerError("turn-absence-proof-ledger-missing")
                    durable = ledger.turn_intent_resolution(
                        str(current["turn_intent_id"])
                    )
                    absence_proof_sha256 = str(durable["evidence_sha256"])
                    absence_verified = True
            except Exception:
                contained = False
        if contained and discovered:
            absence_verified = True
        if negative_response_capability is not None:
            self._discard_negative_turn_response_capability(
                negative_response_capability
            )
        if contained:
            try:
                self.archive_thread(thread_id)
                archived = True
            except Exception:
                archived = False
                contained = False
        precursor = evolve_turn_dispatch_record(
            current,
            wire_write_attempt_count=1,
            status="failed-ambiguous",
            ambiguity_reason=ambiguity_reason,
            exact_response_turn_id=exact_response_turn_id,
            notification_connection_epoch_sha256=notification_epoch,
            notification_sequences=sorted(notification_sequences),
            discovered_turn_ids=sorted(discovered),
            interrupt_attempted_turn_ids=sorted(attempted),
            interrupt_failed_turn_ids=sorted(interrupt_failed),
            terminal_status_by_turn={
                key: terminal_statuses[key] for key in sorted(terminal_statuses)
            },
            active_turn_ids_at_final_check=sorted(final_active),
            query_count=query_count,
            absence_verified=absence_verified,
            absence_proof_sha256=absence_proof_sha256,
            archived=archived,
            ledger_resolution=ledger_resolution,
        )
        precursor = self._persist_turn_dispatch_record(precursor)
        if contained:
            return persist_exact_audited_success(
                precursor,
                allow_audit_create=True,
            )
        return precursor

    def start_turn(
        self,
        thread_id: str,
        prompt: str,
        *,
        timeout: float = 30,
        ambiguity_timeout: float = AMBIGUOUS_TURN_DISCOVERY_TIMEOUT_SECONDS,
    ) -> tuple[dict[str, Any], float]:
        """Write ``turn/start`` exactly once and contain uncertain outcomes."""

        live_availability.require_n1_live()
        if getattr(self, "_mcp_guard_required", False):
            self.require_zero_mcp_endpoints(thread_id)
            self._mcp_finalized_threads.discard(thread_id)

        getattr(self, "_fresh_never_turned_thread_proofs", {}).pop(
            thread_id,
            None,
        )
        getattr(self, "_same_process_containment_proofs", {}).pop(
            thread_id,
            None,
        )
        with self._condition:
            if self.process.poll() is not None:
                raise AppServerError(
                    f"app-server-exited-before-turn-intent:{self.process.returncode}"
                )
            if self._reader_error:
                raise AppServerError(self._reader_error)
        turn_intent_id = (
            self.allocation_ledger.turn_intent(thread_id)
            if self.allocation_ledger is not None
            else str(uuid.uuid4())
        )
        params = {
            "threadId": thread_id,
            "input": [{"type": "text", "text": prompt, "text_elements": []}],
            "model": getattr(self, "requested_model", EXACT_MODEL),
            "effort": getattr(self, "reasoning_effort", "low"),
            "clientUserMessageId": turn_intent_id,
            "responsesapiClientMetadata": dict(getattr(self, "operation_metadata", None) or {
                "cwo_bead": "complex-work-orchestration-18w.6",
                "cwo_control_turn": CONTROL_TURN_ID,
            }),
        }
        ledger_id, ledger_head, intent_entry = self._turn_intent_ledger_link(
            turn_intent_id
        )
        unobserved_response_observer: Mapping[str, Any] | None = None
        with self._condition:
            if self.process.poll() is not None:
                raise AppServerError(
                    f"app-server-exited-before-turn-start:{self.process.returncode}"
                )
            if self._reader_error:
                raise AppServerError(self._reader_error)
            self._request_id += 1
            request_id = self._request_id
            notification_cursor = len(self._notifications)
            payload = {
                "id": request_id,
                "method": "turn/start",
                "params": params,
            }
            wire_request_sha256 = domain_sha256(
                payload, domain="app-server-single-wire-request"
            )
            known = getattr(self, "_known_thread_turn_ids", {}).get(thread_id, set())
            reservation = TurnDispatchReservation(
                thread_id=thread_id,
                turn_intent_id=turn_intent_id,
                request_id=request_id,
                connection_epoch_sha256=self.connection_epoch_sha256,
                notification_cursor=notification_cursor,
                preexisting_turn_ids=tuple(sorted(known)),
                ledger_id=ledger_id,
                ledger_head_entry_sha256=ledger_head,
                turn_intent_entry_sha256=intent_entry,
                wire_request_sha256=wire_request_sha256,
            )
            record = self._persist_turn_dispatch_record(reservation.prepared_record())
            record = self._persist_turn_dispatch_record(
                evolve_turn_dispatch_record(
                    record,
                    status="dispatching",
                    wire_write_attempt_count=1,
                )
            )
            observer_capability = object()
            pending_observers = getattr(
                self, "_pending_turn_start_response_observers", None
            )
            if pending_observers is None:
                pending_observers = {}
                self._pending_turn_start_response_observers = pending_observers
            if request_id in pending_observers:
                raise AppServerError(
                    "turn-start-response-observer-request-duplicate"
                )
            pending_observers[request_id] = {
                "capability": observer_capability,
                "thread_id": thread_id,
                "turn_intent_id": turn_intent_id,
                "request_id": request_id,
                "connection_epoch_sha256": self.connection_epoch_sha256,
                "wire_request_sha256": wire_request_sha256,
                "dispatch_record_sha256": record["record_sha256"],
            }
            if self.allocation_ledger is not None:
                try:
                    self.allocation_ledger._register_pending_turn_negative_response_observer_capability(
                        observer_capability,
                        record,
                    )
                except BaseException:
                    pending_observers.pop(request_id, None)
                    raise
            self._require_mcp_guard(thread_id)
            started = time.monotonic_ns()
            live_availability.require_n1_live()
            try:
                assert self.process.stdin is not None
                self.process.stdin.write(
                    json.dumps(payload, separators=(",", ":")) + "\n"
                )
                self.process.stdin.flush()
            except OSError:
                ambiguity_reason = "wire-write-error"
            else:
                ambiguity_reason = None
                deadline = time.monotonic() + timeout
                while request_id not in self._responses:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        ambiguity_reason = "response-timeout"
                        break
                    if self.process.poll() is not None:
                        ambiguity_reason = "app-server-exited"
                        break
                    if self._reader_error:
                        ambiguity_reason = "reader-error"
                        break
                    self._condition.wait(timeout=remaining)
                message = (
                    self._responses.pop(request_id)
                    if ambiguity_reason is None
                    else None
                )
                if ambiguity_reason is None:
                    candidate = pending_observers.pop(request_id, None)
                    if isinstance(candidate, Mapping):
                        unobserved_response_observer = candidate

        if unobserved_response_observer is not None:
            unobserved_capability = unobserved_response_observer.get("capability")
            if unobserved_capability is not None:
                self._discard_negative_turn_response_capability(
                    unobserved_capability
                )

        if ambiguity_reason is not None:
            record = self._persist_turn_dispatch_record(
                evolve_turn_dispatch_record(
                    record,
                    status="failed-ambiguous",
                    ambiguity_reason=ambiguity_reason,
                )
            )
            contained = self.contain_ambiguous_turn_dispatch(
                thread_id, timeout=ambiguity_timeout
            )
            raise AmbiguousTurnStartError(contained)

        latency_ms = (time.monotonic_ns() - started) / 1_000_000
        self.rpc_latencies.setdefault("turn/start", []).append(latency_ms)
        rpc_error: AppServerRpcError | None = None
        negative_response_capability: object | None = None
        if not isinstance(message, Mapping) or message.get("id") != request_id:
            ambiguity_reason = "response-id-invalid"
        elif "error" in message:
            error = message.get("error")
            if (
                "result" in message
                or not isinstance(error, Mapping)
                or type(error.get("code")) is not int
                or not isinstance(error.get("message"), str)
            ):
                ambiguity_reason = "error-response-invalid"
            else:
                rpc_error = AppServerRpcError(
                    method="turn/start",
                    code=int(error["code"]),
                    request_id=request_id,
                    latency_ms=latency_ms,
                )
                observed_by_request = getattr(
                    self,
                    "_observed_negative_turn_response_capabilities_by_request",
                    {},
                )
                observed = observed_by_request.pop(request_id, None)
                witness = getattr(
                    self, "_negative_turn_response_capabilities", {}
                ).get(observed)
                if (
                    observed is not None
                    and isinstance(witness, Mapping)
                    and witness.get("request_id") == request_id
                    and witness.get("connection_epoch_sha256")
                    == record.get("connection_epoch_sha256")
                    and witness.get("wire_request_sha256")
                    == record.get("wire_request_sha256")
                    and witness.get("code") == error.get("code")
                    and witness.get("response_sha256")
                    == domain_sha256(
                        dict(message),
                        domain="app-server-turn-start-negative-response",
                    )
                ):
                    negative_response_capability = observed
                    ambiguity_reason = "rpc-error-response"
                else:
                    if observed is not None:
                        self._discard_negative_turn_response_capability(observed)
                    ambiguity_reason = "rpc-error-response-unobserved"
        else:
            result = message.get("result")
            turn = result.get("turn") if isinstance(result, Mapping) else None
            turn_id = turn.get("id") if isinstance(turn, Mapping) else None
            if not isinstance(turn_id, str) or not turn_id:
                ambiguity_reason = "response-turn-invalid"

        if ambiguity_reason is not None:
            record = self._persist_turn_dispatch_record(
                evolve_turn_dispatch_record(
                    record,
                    status="failed-ambiguous",
                    ambiguity_reason=ambiguity_reason,
                )
            )
            contained = self.contain_ambiguous_turn_dispatch(
                thread_id,
                timeout=ambiguity_timeout,
                negative_response_capability=negative_response_capability,
            )
            if (
                rpc_error is not None
                and contained["status"] == "failed-contained"
                and contained["ledger_resolution"] == "verified-absent"
            ):
                raise rpc_error
            raise AmbiguousTurnStartError(contained)

        assert isinstance(turn, Mapping) and isinstance(turn_id, str)
        self.started_threads[thread_id] = turn_id
        if self.allocation_ledger is not None:
            try:
                self.allocation_ledger.bind_turn(thread_id, turn_intent_id, turn_id)
            except Exception:
                record = self._persist_turn_dispatch_record(
                    evolve_turn_dispatch_record(
                        record,
                        status="failed-ambiguous",
                        ambiguity_reason="ledger-turn-bind-failed",
                        exact_response_turn_id=turn_id,
                        discovered_turn_ids=[turn_id],
                    )
                )
                contained = self.contain_ambiguous_turn_dispatch(
                    thread_id, timeout=ambiguity_timeout
                )
                raise AmbiguousTurnStartError(contained)
        record = evolve_turn_dispatch_record(
            record,
            status="acknowledged",
            exact_response_turn_id=turn_id,
            discovered_turn_ids=[turn_id],
            wire_write_attempt_count=1,
            ledger_resolution="turn-bound",
        )
        self._persist_turn_dispatch_record(record)
        return dict(turn), latency_ms

    def interrupt_turn(
        self,
        thread_id: str,
        turn_id: str,
        *,
        timeout: float = 15,
    ) -> float:
        _result, latency = self.request(
            "turn/interrupt",
            {"threadId": thread_id, "turnId": turn_id},
            timeout=timeout,
        )
        if self.allocation_ledger is not None:
            self.allocation_ledger.record_lifecycle(
                thread_id, "interrupt-observed", "interrupt-request-accepted"
            )
        return latency

    def archive_thread(self, thread_id: str) -> float:
        result, latency = self.request(
            "thread/archive",
            {"threadId": thread_id},
            timeout=15,
        )
        archive_proofs = getattr(self, "_archive_acceptance_proofs", None)
        if archive_proofs is None:
            archive_proofs = {}
            self._archive_acceptance_proofs = archive_proofs
        archive_proofs[thread_id] = _seal_same_process_proof(
            {
                "proof_type": "app-server-connection-local-thread-proof",
                "version": 1,
                "kind": "archive-accepted",
                "thread_id_sha256": sha256_text(thread_id),
                "connection_epoch_sha256": self.connection_epoch_sha256,
                "archive_response_sha256": domain_sha256(
                    result,
                    domain="app-server-thread-archive-response",
                ),
            },
            domain="app-server-connection-local-thread-proof",
        )
        if self.allocation_ledger is not None:
            self.allocation_ledger.record_lifecycle(
                thread_id, "archive-observed", "archive-request-accepted"
            )
        return latency

    def delete_thread(self, thread_id: str) -> float:
        result, latency = self.request(
            "thread/delete",
            {"threadId": thread_id},
            timeout=15,
        )
        delete_proofs = getattr(self, "_delete_acceptance_proofs", None)
        if delete_proofs is None:
            delete_proofs = {}
            self._delete_acceptance_proofs = delete_proofs
        delete_proofs[thread_id] = _seal_same_process_proof(
            {
                "proof_type": "app-server-connection-local-thread-proof",
                "version": 1,
                "kind": "delete-accepted",
                "thread_id_sha256": sha256_text(thread_id),
                "connection_epoch_sha256": self.connection_epoch_sha256,
                "delete_response_sha256": domain_sha256(
                    result,
                    domain="app-server-thread-delete-response",
                ),
            },
            domain="app-server-connection-local-thread-proof",
        )
        return latency

    def fresh_never_turned_thread_proof(
        self,
        thread_id: str,
    ) -> dict[str, Any] | None:
        proof = _validated_same_process_proof(
            getattr(
                self,
                "_fresh_never_turned_thread_proofs",
                {},
            ).get(thread_id),
            domain="app-server-connection-local-thread-proof",
            expected_fields={
                "proof_type",
                "version",
                "kind",
                "thread_id_sha256",
                "connection_epoch_sha256",
                "known_turn_ids_sha256",
                "thread_start_response_sha256",
            },
        )
        if (
            proof is None
            or proof.get("proof_type")
            != "app-server-connection-local-thread-proof"
            or proof.get("version") != 1
            or proof.get("kind") != "fresh-never-turned"
            or proof.get("thread_id_sha256") != sha256_text(thread_id)
            or proof.get("connection_epoch_sha256")
            != self.connection_epoch_sha256
            or proof.get("known_turn_ids_sha256")
            != domain_sha256(
                [],
                domain="app-server-known-thread-turn-ids",
            )
            or self.started_threads.get(thread_id) is not None
            or getattr(self, "_known_thread_turn_ids", {}).get(thread_id)
            != set()
            or getattr(self, "_turn_dispatch_records", {}).get(thread_id)
            is not None
        ):
            return None
        return proof

    def archive_acceptance_proof(
        self,
        thread_id: str,
    ) -> dict[str, Any] | None:
        proof = _validated_same_process_proof(
            getattr(
                self,
                "_archive_acceptance_proofs",
                {},
            ).get(thread_id),
            domain="app-server-connection-local-thread-proof",
            expected_fields={
                "proof_type",
                "version",
                "kind",
                "thread_id_sha256",
                "connection_epoch_sha256",
                "archive_response_sha256",
            },
        )
        if (
            proof is None
            or proof.get("proof_type")
            != "app-server-connection-local-thread-proof"
            or proof.get("version") != 1
            or proof.get("kind") != "archive-accepted"
            or proof.get("thread_id_sha256") != sha256_text(thread_id)
            or proof.get("connection_epoch_sha256")
            != self.connection_epoch_sha256
        ):
            return None
        return proof

    def register_staged_archive(self, thread_id: str, staged_archive: Any) -> None:
        """Bind one in-flight archive so containment never replays its RPC."""

        with self._condition:
            existing = getattr(self, "_staged_archives", {}).get(thread_id)
            if existing is not None and existing is not staged_archive:
                raise AppServerError("staged-archive-registration-conflict")
            if not hasattr(self, "_staged_archives"):
                self._staged_archives = {}
            self._staged_archives[thread_id] = staged_archive

    def staged_archive(self, thread_id: str) -> Any | None:
        with self._condition:
            return getattr(self, "_staged_archives", {}).get(thread_id)

    def delete_acceptance_proof(
        self,
        thread_id: str,
    ) -> dict[str, Any] | None:
        proof = _validated_same_process_proof(
            getattr(
                self,
                "_delete_acceptance_proofs",
                {},
            ).get(thread_id),
            domain="app-server-connection-local-thread-proof",
            expected_fields={
                "proof_type",
                "version",
                "kind",
                "thread_id_sha256",
                "connection_epoch_sha256",
                "delete_response_sha256",
            },
        )
        if (
            proof is None
            or proof.get("proof_type")
            != "app-server-connection-local-thread-proof"
            or proof.get("version") != 1
            or proof.get("kind") != "delete-accepted"
            or proof.get("thread_id_sha256") != sha256_text(thread_id)
            or proof.get("connection_epoch_sha256")
            != self.connection_epoch_sha256
        ):
            return None
        return proof

    def record_terminal_archive_containment(
        self,
        thread_id: str,
        turn_id: str,
        *,
        terminal_evidence_sha256: str,
    ) -> dict[str, Any]:
        """Bind trusted terminal evidence to this connection's accepted archive."""

        archive_proof = self.archive_acceptance_proof(thread_id)
        if (
            self.started_threads.get(thread_id) != turn_id
            or archive_proof is None
            or re.fullmatch(r"[0-9a-f]{64}", terminal_evidence_sha256)
            is None
        ):
            raise AppServerError("terminal-archive-containment-proof-invalid")
        proof = _seal_same_process_proof(
            {
                "proof_type": "app-server-same-process-containment",
                "version": 1,
                "kind": "terminal-turn-archived",
                "thread_id_sha256": sha256_text(thread_id),
                "turn_id_sha256": sha256_text(turn_id),
                "connection_epoch_sha256": self.connection_epoch_sha256,
                "fresh_thread_proof_sha256": None,
                "archive_acceptance_sha256": archive_proof[
                    "proof_sha256"
                ],
                "terminal_evidence_sha256": terminal_evidence_sha256,
            },
            domain="app-server-same-process-containment",
        )
        proofs = getattr(self, "_same_process_containment_proofs", None)
        if proofs is None:
            proofs = {}
            self._same_process_containment_proofs = proofs
        proofs[thread_id] = proof
        return dict(proof)

    def record_never_turned_archive_containment(
        self,
        thread_id: str,
    ) -> dict[str, Any]:
        """Bind a fresh no-turn allocation to this connection's accepted archive."""

        fresh_proof = self.fresh_never_turned_thread_proof(thread_id)
        archive_proof = self.archive_acceptance_proof(thread_id)
        dispatch_record = getattr(
            self,
            "_turn_dispatch_records",
            {},
        ).get(thread_id)
        if (
            self.started_threads.get(thread_id) is not None
            or dispatch_record is not None
            or fresh_proof is None
            or archive_proof is None
        ):
            raise AppServerError("never-turned-archive-containment-proof-invalid")
        proof = _seal_same_process_proof(
            {
                "proof_type": "app-server-same-process-containment",
                "version": 1,
                "kind": "never-turned-archived",
                "thread_id_sha256": sha256_text(thread_id),
                "turn_id_sha256": None,
                "connection_epoch_sha256": self.connection_epoch_sha256,
                "fresh_thread_proof_sha256": fresh_proof[
                    "proof_sha256"
                ],
                "archive_acceptance_sha256": archive_proof[
                    "proof_sha256"
                ],
                "terminal_evidence_sha256": None,
            },
            domain="app-server-same-process-containment",
        )
        proofs = getattr(self, "_same_process_containment_proofs", None)
        if proofs is None:
            proofs = {}
            self._same_process_containment_proofs = proofs
        proofs[thread_id] = proof
        getattr(self, "_fresh_never_turned_thread_proofs", {}).pop(
            thread_id,
            None,
        )
        return dict(proof)

    def record_never_turned_delete_containment(
        self,
        thread_id: str,
    ) -> dict[str, Any]:
        """Bind a fresh no-turn allocation to this connection's accepted delete."""

        fresh_proof = self.fresh_never_turned_thread_proof(thread_id)
        delete_proof = self.delete_acceptance_proof(thread_id)
        dispatch_record = getattr(
            self,
            "_turn_dispatch_records",
            {},
        ).get(thread_id)
        if (
            self.started_threads.get(thread_id) is not None
            or dispatch_record is not None
            or fresh_proof is None
            or delete_proof is None
        ):
            raise AppServerError("never-turned-delete-containment-proof-invalid")
        proof = _seal_same_process_proof(
            {
                "proof_type": "app-server-same-process-containment",
                "version": 2,
                "kind": "never-turned-deleted",
                "thread_id_sha256": sha256_text(thread_id),
                "turn_id_sha256": None,
                "connection_epoch_sha256": self.connection_epoch_sha256,
                "fresh_thread_proof_sha256": fresh_proof[
                    "proof_sha256"
                ],
                "delete_acceptance_sha256": delete_proof[
                    "proof_sha256"
                ],
                "terminal_evidence_sha256": None,
            },
            domain="app-server-same-process-containment",
        )
        proofs = getattr(self, "_same_process_containment_proofs", None)
        if proofs is None:
            proofs = {}
            self._same_process_containment_proofs = proofs
        proofs[thread_id] = proof
        getattr(self, "_fresh_never_turned_thread_proofs", {}).pop(
            thread_id,
            None,
        )
        return dict(proof)

    def same_process_containment_proof(
        self,
        thread_id: str,
    ) -> dict[str, Any] | None:
        raw_proof = getattr(
            self,
            "_same_process_containment_proofs",
            {},
        ).get(thread_id)
        if (
            isinstance(raw_proof, Mapping)
            and raw_proof.get("kind") == "never-turned-deleted"
        ):
            proof = _validated_same_process_proof(
                raw_proof,
                domain="app-server-same-process-containment",
                expected_fields={
                    "proof_type",
                    "version",
                    "kind",
                    "thread_id_sha256",
                    "turn_id_sha256",
                    "connection_epoch_sha256",
                    "fresh_thread_proof_sha256",
                    "delete_acceptance_sha256",
                    "terminal_evidence_sha256",
                },
            )
            delete_proof = self.delete_acceptance_proof(thread_id)
            if (
                proof is None
                or proof.get("proof_type")
                != "app-server-same-process-containment"
                or proof.get("version") != 2
                or proof.get("thread_id_sha256")
                != sha256_text(thread_id)
                or proof.get("connection_epoch_sha256")
                != self.connection_epoch_sha256
                or delete_proof is None
                or proof.get("delete_acceptance_sha256")
                != delete_proof.get("proof_sha256")
                or self.started_threads.get(thread_id) is not None
                or proof.get("turn_id_sha256") is not None
                or proof.get("terminal_evidence_sha256") is not None
                or re.fullmatch(
                    r"[0-9a-f]{64}",
                    str(proof.get("fresh_thread_proof_sha256")),
                )
                is None
            ):
                return None
            return proof
        archive_proof = self.archive_acceptance_proof(thread_id)
        proof = _validated_same_process_proof(
            raw_proof,
            domain="app-server-same-process-containment",
            expected_fields={
                "proof_type",
                "version",
                "kind",
                "thread_id_sha256",
                "turn_id_sha256",
                "connection_epoch_sha256",
                "fresh_thread_proof_sha256",
                "archive_acceptance_sha256",
                "terminal_evidence_sha256",
            },
        )
        if (
            proof is None
            or proof.get("proof_type")
            != "app-server-same-process-containment"
            or proof.get("version") != 1
            or proof.get("thread_id_sha256") != sha256_text(thread_id)
            or proof.get("connection_epoch_sha256")
            != self.connection_epoch_sha256
            or archive_proof is None
            or proof.get("archive_acceptance_sha256")
            != archive_proof.get("proof_sha256")
            or re.fullmatch(
                r"[0-9a-f]{64}",
                str(proof.get("archive_acceptance_sha256")),
            )
            is None
        ):
            return None
        if proof.get("kind") == "terminal-turn-archived":
            turn_id = self.started_threads.get(thread_id)
            if (
                not isinstance(turn_id, str)
                or proof.get("turn_id_sha256") != sha256_text(turn_id)
                or proof.get("fresh_thread_proof_sha256") is not None
                or re.fullmatch(
                    r"[0-9a-f]{64}",
                    str(proof.get("terminal_evidence_sha256")),
                )
                is None
            ):
                return None
        elif proof.get("kind") == "never-turned-archived":
            if (
                self.started_threads.get(thread_id) is not None
                or proof.get("turn_id_sha256") is not None
                or proof.get("terminal_evidence_sha256") is not None
                or re.fullmatch(
                    r"[0-9a-f]{64}",
                    str(proof.get("fresh_thread_proof_sha256")),
                )
                is None
            ):
                return None
        else:
            return None
        return proof

    def same_process_containment_proofs(self) -> list[dict[str, Any]]:
        proofs = [
            proof
            for thread_id in getattr(
                self,
                "_same_process_containment_proofs",
                {},
            )
            if (
                proof := self.same_process_containment_proof(
                    thread_id
                )
            )
            is not None
        ]
        return sorted(proofs, key=lambda proof: proof["proof_sha256"])

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

    def close(self) -> dict[str, Any]:
        """Reap only our child; failures are durable and never imply containment."""

        with self._close_lock:
            if self._closing:
                error = AppServerError("app-server-cleanup-reentrant")
                error.app_server_cleanup = {"all_contained": False, "resources_closed": False,
                                            "errors": ["cleanup-in-progress"]}
                raise error
            if self._cleanup_result is not None:
                result = copy.deepcopy(self._cleanup_result)
            else:
                self._closing = True
                result = {"all_contained": self.process is None, "resources_closed": False, "errors": []}
                errors = result["errors"]
                def attempt(label, function):
                    try:
                        return function()
                    except BaseException as exc:
                        errors.append(f"{label}:{type(exc).__name__}:{exc}")
                        return None
                try:
                    process = self.process
                    if process is not None:
                        if attempt("poll", process.poll) is None:
                            attempt("terminate", process.terminate)
                            attempt("wait", lambda: process.wait(timeout=5))
                        if attempt("poll-after-terminate", process.poll) is None:
                            attempt("kill", process.kill)
                            attempt("wait-after-kill", lambda: process.wait(timeout=5))
                        exited = attempt("final-poll", process.poll) is not None
                        reaped = attempt("reap", lambda: process.wait(timeout=0)) if exited else None
                        result["all_contained"] = exited and type(reaped) is int
                        result["pid"] = process.pid
                    # Do not close buffered pipes under a reader still blocked in I/O.
                    readers_closed = True
                    for reader in self._reader_threads:
                        if reader.ident is not None and reader is not threading.current_thread():
                            attempt("reader-join", lambda r=reader: r.join(timeout=1))
                        if reader.is_alive():
                            readers_closed = False
                            errors.append("reader-still-running")
                    if result["all_contained"] and readers_closed:
                        if process is not None:
                            for name in ("stdin", "stdout", "stderr"):
                                stream = getattr(process, name, None)
                                if stream is not None:
                                    attempt("close-" + name, stream.close)
                        result["resources_closed"] = not any(e.startswith("close-") for e in errors)
                    if not result["all_contained"]:
                        errors.append("owned-process-containment-unproved")
                finally:
                    self._cleanup_result = copy.deepcopy(result)
                    self._closing = False
            if result["errors"] or not result["all_contained"] or not result["resources_closed"]:
                error = AppServerError("app-server-cleanup-failed")
                error.app_server_cleanup = result
                raise error
            return result


def _canonical_controller_workdir(value: Path | str) -> Path:
    """Return one lexical, existing, nonsymlink controller workdir."""

    try:
        supplied = Path(value)
    except (TypeError, ValueError) as exc:
        raise AppServerError("controller-workdir-invalid") from exc
    if not supplied.is_absolute() or "\x00" in str(supplied):
        raise AppServerError("controller-workdir-invalid")
    try:
        resolved = supplied.resolve(strict=True)
        metadata = supplied.lstat()
    except OSError as exc:
        raise AppServerError("controller-workdir-invalid") from exc
    if (
        supplied != resolved
        or stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
    ):
        raise AppServerError("controller-workdir-invalid")
    return resolved
