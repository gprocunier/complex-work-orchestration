"""Registered-only seam for the recorded app-server transport.

Bounded registered phases preserve the approved initialization and stdout-reader
transitions. Other RPC, lifecycle, and cleanup behavior is inherited unchanged.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import select
import subprocess
import threading
import time
from typing import Any, Mapping
import uuid

import linux_owned_children as owned
from offline_n1_host import OfflineHostError
from cwo_core.supervision.transport.app_server import (
    AppServer as RecordedAppServer,
    AppServerError,
    CodexToolSurfaceError,
    EXACT_MODEL,
    IdentityCapabilityRegistry as _IdentityCapabilityRegistry,
    NativeLiveAllocationLedgerStore,
    TurnNegativeResponseObserverBinding as _TurnNegativeResponseObserverBinding,
    domain_sha256,
    prepare_capture_binding,
    require_capture_binding,
    require_surface_proof,
)


def protocol_argument_file() -> int:
    """One Linux ABI on both interpreters; unsupported kernels/libcs refuse."""
    library = owned.ctypes.CDLL(None, use_errno=True)
    create = getattr(library, 'memfd_create', None)
    if create is None:
        raise OfflineHostError("The registered Linux argument-file mechanism is unavailable.")
    create.argtypes = (owned.ctypes.c_char_p, owned.ctypes.c_uint)
    create.restype = owned.ctypes.c_int
    descriptor = create(b'cwo-n1-arguments', 3)  # Linux MFD_CLOEXEC | MFD_ALLOW_SEALING.
    if descriptor < 0:
        raise OSError(owned.ctypes.get_errno(), 'The registered argument-file mechanism failed.')
    return descriptor


class DeadlineProtocolInput:
    """One bounded nonblocking protocol writer, including lock acquisition."""

    def __init__(self, stream, failure):
        self.stream, self.failure_callback = stream, failure
        self.descriptor = stream.fileno()
        self.failure = None
        self._lock = threading.Lock()
        self._poison = os.open(os.devnull, os.O_RDONLY | os.O_CLOEXEC)
        self._aborted = False
        self._closing = False
        os.set_blocking(self.descriptor, False)

    def write(self, value: str) -> int:
        deadline, acquired = time.monotonic() + 5, False
        try:
            if type(value) is not str or len(value) > 1048576:
                raise OfflineHostError("A bounded protocol write is required.")
            data = value.encode('utf-8')
            if len(data) > 1048576:
                raise OfflineHostError("The protocol write byte bound was exceeded.")
            acquired = self._lock.acquire(timeout=max(0, deadline - time.monotonic()))
            if not acquired:
                raise TimeoutError('registered-protocol-write-lock-timeout')
            self.flush()
            self._write_all(memoryview(data), deadline)
            return len(value)
        except BaseException as failure:
            if self.failure is None:
                self.failure = failure
            self.failure_callback(self.failure)
            raise
        finally:
            if acquired:
                self._lock.release()
                if self._closing:
                    self.close()

    def _write_all(self, data: memoryview, deadline: float) -> None:
        while data:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('registered-protocol-write-timeout')
            try:
                if not select.select([], [self.descriptor], [], remaining)[1]:
                    continue
                self.flush()
                count = os.write(self.descriptor, data)
                if count <= 0:
                    raise OfflineHostError("Protocol write made no progress.")
                data = data[count:]
            except (BlockingIOError, InterruptedError):
                continue

    def flush(self) -> None:
        if self.failure is not None or self.stream.closed or self._aborted or self._closing:
            raise AppServerError('registered-protocol-writer-unavailable') from self.failure
        # os.write has no Python-side pending buffer.

    def abort(self) -> None:
        """Fence a not-yet-entered write without waiting for its writer lock.

        The stable read-only descriptor prevents a paused writer from sending
        an old accepting frame after request authority has been revoked.
        """
        if not self._aborted and not self.stream.closed:
            os.dup2(self._poison, self.descriptor)
            self._aborted = True
        if self._poison is not None:
            os.close(self._poison)
            self._poison = None

    def close(self) -> None:
        self._closing = True
        if not self._lock.acquire(blocking=False):
            return
        try:
            if not self.stream.closed:
                self.stream.close()
            if self._poison is not None:
                os.close(self._poison)
                self._poison = None
        finally:
            self._lock.release()


class ProtocolPipeChild:
    """Protocol streams with status operations delegated to original custody."""

    def __init__(self, child, streams, argv):
        self._child = child
        self.stdin, self.stdout, self.stderr = streams
        self.args = argv

    def _get_pid(self):
        return self._child.pid

    def _set_pid(self, value):
        self._child.pid = value

    pid = property(_get_pid, _set_pid)

    def _get_returncode(self):
        return self._child.returncode

    def _set_returncode(self, value):
        self._child.returncode = value

    returncode = property(_get_returncode, _set_returncode)

    def poll(self) -> int | None:
        if self.returncode is not None:
            return self.returncode
        return self._handle_backend.status(self._handle_birth)

    def wait(self, timeout: float | None = None) -> int | None:
        if not (type(timeout) in (int, float) and 0 <= timeout <= 30):
            raise OfflineHostError("A finite retained-handle wait is required.")
        if self.returncode is not None:
            return self.returncode
        if not self._handle_backend.wait_exit(self._handle_birth.descriptor, timeout):
            raise subprocess.TimeoutExpired(self.args, timeout)
        return self.poll()

    def communicate(self, data: str, timeout: float) -> tuple[str, str]:
        return owned.atomic_spawn.communicate(self, data, timeout)


class ProtocolPipeBackend(owned._LinuxBackend):
    """Retain the exact direct-child handle, with private protocol pipes."""

    def __init__(self, pass_fds):
        super().__init__()
        self.pass_fds = pass_fds

    def _spawn_atomic(self, birth, argv, executable, workspace):
        def retain(child, streams):
            self._retain_atomic(birth, child)
            birth.child = ProtocolPipeChild(child, streams, argv)
            birth.child._handle_backend, birth.child._handle_birth = self, birth
        self._operation("Atomic protocol child creation", owned.atomic_spawn.spawn_piped,
                        executable, argv, workspace, tuple(self.pass_fds), retain)

    def spawn(self, birth, argv, executable, workspace) -> tuple[int, int]:
        result = super().spawn(birth, argv, executable, workspace)
        birth.child._handle_backend, birth.child._handle_birth = self, birth
        return result

    def status(self, birth) -> int | None:
        with self._lifecycle_lock:
            if birth.child.returncode is not None:
                return birth.child.returncode
            if birth.active_operation is not None or birth.releasing or birth.closed:
                return None
            self._start_operation(birth.descriptor, 'wait')
            primary = None
            try:
                result = self._operation('Protocol child status', os.waitid, os.P_PIDFD,
                                         birth.descriptor, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                return None if result is None else self._exit_code(birth, result)
            except BaseException as failure:
                primary = failure
                raise
            finally:
                self._finish_operation(birth, primary)


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
