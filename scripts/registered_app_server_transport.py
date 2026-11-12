"""Registered-only seam for the recorded app-server transport.

Bounded registered phases preserve the approved initialization and stdout-reader
transitions. Other RPC, lifecycle, and cleanup behavior is inherited unchanged.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import threading
import time
from typing import Any, Mapping
import uuid

from cwo_core.supervision.transport.app_server import (
    AppServer as RecordedAppServer,
    AppServerError,
    CodexToolSurfaceError,
    EXACT_MODEL,
    NativeLiveAllocationLedgerStore,
    _IdentityCapabilityRegistry,
    _TurnNegativeResponseObserverBinding,
    domain_sha256,
    prepare_capture_binding,
    require_capture_binding,
    require_surface_proof,
)


class RegisteredAppServer(RecordedAppServer):
    """Approved registered hooks over the original recorded transport."""

    def __init__(
        self,
        *,
        requested_model: str = EXACT_MODEL,
        reasoning_effort: str = "low",
        tool_surface_proof: Mapping[str, Any] | None = None,
        tool_surface_probe_catalog: Path | None = None,
        tool_surface_probe_binding: Mapping[str, Any] | None = None,
        operation_metadata: Mapping[str, str] | None = None,
    ) -> None:
        self.process = None
        self._reader_threads: list[threading.Thread] = []
        self._close_lock = threading.RLock()
        self._closing = False
        self._cleanup_result: dict[str, Any] | None = None
        try:
            if type(self) is RegisteredAppServer:
                raise AppServerError("registered-app-server-launcher-required")
            self._validate_settings(requested_model, reasoning_effort, operation_metadata,
                                    tool_surface_proof)
            home, binding, startup_config = self._prepare_tool_binding(
                tool_surface_proof, tool_surface_probe_catalog, tool_surface_probe_binding
            )
            self._launch_registered_transport(home, binding, startup_config)
            self._prepare_rpc_state()
            self._start_readers()
            self._initialize_protocol(home, binding)
        except BaseException as exc:
            cleanup = self._construction_cleanup(exc)
            if isinstance(exc, CodexToolSurfaceError):
                wrapped = AppServerError(str(exc))
                wrapped.app_server_cleanup = cleanup
                raise wrapped from exc
            raise

    def _validate_settings(self, requested_model, reasoning_effort,
                           operation_metadata, tool_surface_proof):
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

    def _prepare_tool_binding(self, tool_surface_proof, tool_surface_probe_catalog,
                              tool_surface_probe_binding):
        home = self._requested_home()
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
            binding = prepare_capture_binding(home, requested_model=self.requested_model,
                permitted_tools=["exec_command", "write_stdin"], catalog_projection=tool_surface_probe_catalog)
        if binding is not None:
            home = Path(binding["codex_home"])
            startup_config = binding["startup_config"]
        return home, binding, startup_config

    def _launch_registered_transport(self, home, binding, startup_config):
        # Register invalidation state BEFORE stdout readers and thread/start.
        self._mcp_guard_required = binding is not None and "effect_policy" in binding
        self._mcp_endpoint_fault = None
        self._mcp_notification_generation = 0
        self._zero_mcp_observations = {}
        self._mcp_finalized_threads = set()
        self.launched_executable = binding["codex_binary"] if binding else self._default_executable()
        command = [self.launched_executable]
        for key, value in sorted(startup_config.items()):
            command.extend(["-c", key + "=" + json.dumps(value)])
        command.extend(["app-server", "--stdio"])
        # The requested home is process-local, never a global config mutation.
        environment = dict(os.environ, CODEX_HOME=str(home))
        self.process = self._launch_process(command, environment)
        if self.process.stdin is None or self.process.stdout is None or self.process.stderr is None:
            raise AppServerError("app-server-pipes-unavailable")

    def _prepare_rpc_state(self):
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

    def _start_readers(self):
        for target in (self._read_stdout, self._drain_stderr):
            reader = threading.Thread(target=target, daemon=True)
            self._reader_threads.append(reader)
            reader.start()
            self._ensure_startup_open()

    def _initialize_protocol(self, home, binding):
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

    def _construction_cleanup(self, exc):
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
        return cleanup

    def _default_executable(self) -> str:
        """A PATH executable is not an admitted registered launcher."""
        raise AppServerError("registered-app-server-launcher-required")

    def _requested_home(self) -> Path:
        return Path(os.environ.get("CODEX_HOME", Path.home() / ".codex")).resolve()

    def _launch_process(self, command, environment):
        """Only a registered host may supply the admitted launch boundary."""
        raise AppServerError(
            "registered-app-server-launcher-required: "
            "a registered subclass must provide the launch boundary"
        )

    def _receive_method(self, message):
        self._observe_mcp_notification(message)
        self._notifications.append((time.monotonic_ns(), dict(message)))

    def _protocol_lines(self):
        return self.process.stdout

    def _read_stdout(self) -> None:
        assert self.process.stdout is not None
        try:
            for raw in self._protocol_lines():
                self._consume_raw_stdout_line(raw)
        finally:
            with self._condition:
                if self.process.poll() is None:
                    self._reader_error = "app-server-output-closed"
                self._condition.notify_all()

    def _reader_fault(self, reason):
        with self._condition:
            self._reader_error = reason
            self._condition.notify_all()

    def _consume_raw_stdout_line(self, raw):
        """Only raw stdout enters this parser and its observation transition."""
        try:
            message = json.loads(raw)
        except json.JSONDecodeError:
            self._reader_fault("app-server-non-json-output")
            return
        if not isinstance(message, Mapping):
            self._reader_fault("app-server-non-object-output")
            return
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
                exact_negative = (
                    "result" not in message
                    and isinstance(error, Mapping)
                    and type(error.get("code")) is int
                    and isinstance(error.get("message"), str)
                )
                if isinstance(pending, Mapping):
                    pending_capability = pending.get("capability")
                    if self._pending_negative_matches(
                        pending, response_id, exact_negative
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
                        ledger_observed = self._register_ledger_negative(
                            pending, pending_capability, response_id,
                            observed_candidate, witness
                        )
                        if ledger_observed:
                            self._register_local_negative(
                                observed_candidate, witness, response_id
                            )
                            observed_capability = observed_candidate
                    self._discard_pending_negative(
                        pending_capability, observed_capability
                    )
                if response_id in self._responses:
                    self._reader_error = "app-server-duplicate-response-id"
                    if observed_capability is not None:
                        self._discard_observed_negative(observed_capability, response_id)
                else:
                    self._responses[response_id] = dict(message)
            elif isinstance(message.get("method"), str):
                self._receive_method(message)
            self._condition.notify_all()

    def _pending_negative_matches(self, pending, response_id, exact_negative):
        return bool(
            exact_negative
            and pending.get("capability") is not None
            and isinstance(pending.get("thread_id"), str)
            and isinstance(pending.get("turn_intent_id"), str)
            and pending.get("request_id") == response_id
            and pending.get("connection_epoch_sha256") == self.connection_epoch_sha256
            and isinstance(pending.get("wire_request_sha256"), str)
            and isinstance(pending.get("dispatch_record_sha256"), str)
        )

    def _register_ledger_negative(self, pending, pending_capability, response_id,
                                  observed_candidate, witness):
        ledger = self.allocation_ledger
        if ledger is None:
            return True
        with ledger._instance_lock:
            try:
                pending_binding = ledger._pending_turn_negative_response_observer_capabilities.pop(
                    pending_capability
                )
            except (KeyError, TypeError):
                pending_binding = None
            if pending_binding is None or not self._ledger_binding_matches(
                pending_binding, pending, response_id
            ):
                return False
            ledger._turn_negative_response_observer_capabilities.register(
                observed_candidate,
                _TurnNegativeResponseObserverBinding(
                    thread_id=str(pending["thread_id"]),
                    turn_intent_id=str(pending["turn_intent_id"]),
                    request_id=response_id,
                    connection_epoch_sha256=str(pending["connection_epoch_sha256"]),
                    wire_request_sha256=str(pending["wire_request_sha256"]),
                    response_sha256=str(witness["response_sha256"]),
                    response_code=int(witness["code"]),
                ),
            )
            return True

    def _ledger_binding_matches(self, binding, pending, response_id):
        return (
            binding.thread_id == pending.get("thread_id")
            and binding.turn_intent_id == pending.get("turn_intent_id")
            and binding.request_id == response_id
            and binding.connection_epoch_sha256 == pending.get("connection_epoch_sha256")
            and binding.wire_request_sha256 == pending.get("wire_request_sha256")
            and binding.dispatch_record_sha256 == pending.get("dispatch_record_sha256")
        )

    def _register_local_negative(self, observed_candidate, witness, response_id):
        capabilities = getattr(self, "_negative_turn_response_capabilities", None)
        if capabilities is None:
            capabilities = _IdentityCapabilityRegistry()
            self._negative_turn_response_capabilities = capabilities
        by_request = getattr(
            self, "_observed_negative_turn_response_capabilities_by_request", None
        )
        if by_request is None:
            by_request = {}
            self._observed_negative_turn_response_capabilities_by_request = by_request
        capabilities.register(observed_candidate, witness)
        by_request[response_id] = observed_candidate

    def _discard_pending_negative(self, pending_capability, observed_capability):
        ledger = self.allocation_ledger
        if (observed_capability is None and ledger is not None
                and pending_capability is not None):
            ledger._discard_turn_negative_response_observer_capability(pending_capability)

    def _discard_observed_negative(self, observed_capability, response_id):
        getattr(self, "_negative_turn_response_capabilities", {}).pop(
            observed_capability, None
        )
        getattr(self, "_observed_negative_turn_response_capabilities_by_request", {}).pop(
            response_id, None
        )
        ledger = self.allocation_ledger
        if ledger is not None:
            ledger._discard_turn_negative_response_observer_capability(observed_capability)
