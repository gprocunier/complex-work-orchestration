#!/usr/bin/env python3
"""Prove an exact connected-Codex worker tool surface using loopback capture."""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
from typing import Any
import uuid


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from codex_tool_surface import (  # noqa: E402
    CodexToolSurfaceError,
    EXACT_READ_ONLY_TOOLS,
    EXACT_CORE_RESOURCE_OPERATIVE_TOOLS,
    EXACT_CORE_RESOURCE_READ_ONLY_TOOLS,
    tools_are_mutable,
    normalized_tools,
    prepare_capture_binding,
    require_capture_binding,
    bind_capture_process,
    canonical_sha256,
    prepare_read_only_catalog,
    build_surface_proof,
    probe_thread_config,
    validate_surface_proof,
)
from run_native_pool_live_canaries import AppServer, AppServerError  # noqa: E402


DEFAULT_MODEL = "gpt-5.3-codex-spark"
EXACT_TOOLS = ["apply_patch", "exec_command", "write_stdin"]


def _write_private_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _process_cleanup_report(value: Any) -> dict[str, Any]:
    """Unknown or malformed cleanup is not evidence of containment."""

    if (type(value) is dict
            and type(value.get("all_contained")) is bool
            and type(value.get("resources_closed")) is bool
            and type(value.get("errors")) is list
            and all(type(item) is str for item in value["errors"])):
        report = {key: value[key] for key in ("all_contained", "resources_closed", "errors")}
    else:
        report = {"all_contained": None, "resources_closed": None,
                  "errors": ["process-cleanup-unproved"]}
    if type(value) is dict and type(value.get("pid")) is int:
        report["pid"] = value["pid"]
    return report


def capture_tool_request(
    *,
    codex_home: Path,
    requested_model: str,
    timeout_seconds: float,
    permitted_tools: list[str] | tuple[str, ...] = tuple(EXACT_TOOLS),
    catalog_projection: Path | None = None,
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    tools = normalized_tools(permitted_tools)
    binding = prepare_capture_binding(codex_home, requested_model=requested_model,
        permitted_tools=tools, catalog_projection=catalog_projection)
    captured: dict[str, Any] = {}
    received = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"data":[]}')

        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("content-length", "0"))
            try:
                value = json.loads(self.rfile.read(length))
                if isinstance(value, dict) and not captured:
                    captured.update(value)
            finally:
                received.set()
            self.send_response(503)
            self.send_header("content-type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error":{"message":"cwo-probe-complete"}}')

        def log_message(self, _format: str, *_values: object) -> None:
            return

    # A bounded request loop avoids shutdown() deadlocking before serve_forever.
    listener = None
    listener_thread = None
    listener_stop = threading.Event()
    listener_errors: list[str] = []
    server: AppServer | None = None
    server_construction_started = False
    primary_error: BaseException | None = None
    workspace: tempfile.TemporaryDirectory | None = None

    def serve() -> None:
        try:
            while not listener_stop.is_set():
                listener.handle_request()
        except BaseException as exc:
            listener_errors.append(f"listener-serve:{type(exc).__name__}:{exc}")
            received.set()

    try:
        listener = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        listener.daemon_threads = True
        listener.timeout = 0.1
        port = int(listener.server_address[1])
        listener_thread = threading.Thread(target=serve, daemon=True)
        listener_thread.start()
        config = probe_thread_config(
            codex_home,
            requested_model=requested_model,
            provider_name="cwo-loopback-probe",
            base_url=f"http://127.0.0.1:{port}/v1",
            permitted_tools=tools,
            catalog_projection=catalog_projection,
        )
        lockdown = {k: v for k, v in config.items() if k not in {"model_provider", "model_providers"}}
        if canonical_sha256(lockdown) != binding["lockdown_config_sha256"]:
            raise CodexToolSurfaceError("probe-configuration-binding-drift")
        server_construction_started = True
        server = AppServer(requested_model=requested_model,
                           tool_surface_probe_binding=binding)
        if str(server.codex_home) != binding["codex_home"] or server.launched_executable != binding["codex_binary"]:
            raise CodexToolSurfaceError("probe-process-home-or-binary-mismatch")
        workspace = tempfile.TemporaryDirectory(prefix="cwo-tool-surface-")
        directory = workspace.name
        started, _latency = server.request(
            "thread/start",
            {
                "model": requested_model,
                "modelProvider": "cwo-loopback-probe",
                "allowProviderModelFallback": False,
                "cwd": directory,
                "runtimeWorkspaceRoots": [directory],
                "approvalPolicy": "never",
                "sandbox": "read-only" if not tools_are_mutable(tools) else "workspace-write",
                "ephemeral": True,
                "historyMode": "legacy",
                "dynamicTools": [],
                "config": config,
                "developerInstructions": (
                    "This is a local tool-surface probe. Return PROBE and do not use tools."
                ),
            },
            timeout=30,
        )
        if evidence is not None:
            evidence["thread_start"] = started
            evidence["requested_tools"] = tools
            evidence["startup_catalog"] = str(catalog_projection) if catalog_projection else None
        thread = started.get("thread") if isinstance(started, dict) else None
        if (
            not isinstance(started, dict)
            or started.get("model") != requested_model
            or started.get("modelProvider") != "cwo-loopback-probe"
            or started.get("approvalPolicy") != "never"
            or not isinstance(started.get("sandbox"), dict)
            or started["sandbox"].get("type") != ("readOnly" if not tools_are_mutable(tools) else "workspaceWrite")
            or started["sandbox"].get("networkAccess") is not False
            or not isinstance(thread, dict)
            or not isinstance(thread.get("id"), str)
        ):
            raise CodexToolSurfaceError("probe-thread-start-invalid")
        # Raw thread/start above still belongs to this process. Register ownership
        # before asking the actual thread-scoped status API, never echo an allowlist.
        server.started_threads[thread["id"]] = None
        endpoint_before = server.require_zero_mcp_endpoints(thread["id"])
        if evidence is not None:
            evidence["endpoint_inventory_before"] = endpoint_before
        require_capture_binding(binding)
        server.request(
            "turn/start",
            {
                "threadId": thread["id"],
                "input": [
                    {
                        "type": "text",
                        "text": "Return exactly PROBE without using tools.",
                        "text_elements": [],
                    }
                ],
                "model": requested_model,
                "effort": "low",
            },
            timeout=30,
        )
        if not received.wait(timeout_seconds):
            raise CodexToolSurfaceError("probe-request-capture-timeout")
        require_capture_binding(binding)
        endpoint_after = server.require_zero_mcp_endpoints(thread["id"])
        if evidence is not None:
            evidence["endpoint_inventory_after"] = endpoint_after
            evidence["captured_request_sha256"] = canonical_sha256(captured)
        process_binding = bind_capture_process(binding, captured,
            executable=server.launched_executable, codex_home=str(server.codex_home),
            pid=server.process.pid, thread_id=thread["id"], effective_thread={
                "model": started["model"], "modelProvider": started["modelProvider"],
                "approvalPolicy": started["approvalPolicy"], "networkAccess": started["sandbox"]["networkAccess"],
                "sandbox": started["sandbox"]["type"], "allowProviderModelFallback": False,
                "dynamicTools": [], "lockdown_config_sha256": canonical_sha256(lockdown)},
            endpoint_inventory={"before": endpoint_before, "after": endpoint_after})
        if evidence is not None:
            evidence["capture_binding"] = binding
            evidence["process_binding"] = process_binding
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        cleanup_errors = []
        def cleanup(label, action):
            try:
                return action()
            except BaseException as exc:
                cleanup_errors.append(f"{label}:{type(exc).__name__}:{exc}")
                return getattr(exc, "app_server_cleanup", None)
        outcome = (getattr(primary_error, "app_server_cleanup", None)
                   if server_construction_started else
                   {"all_contained": True, "resources_closed": True, "errors": []})
        if server is not None:
            outcome = cleanup("server-close", server.close)
        outcome = _process_cleanup_report(outcome)
        if outcome["all_contained"] is not True or outcome["resources_closed"] is not True or outcome["errors"]:
            cleanup_errors.append("process-cleanup-not-complete")
        cleanup("listener-stop", listener_stop.set)
        if listener_thread is not None and listener_thread.ident is not None:
            if listener_thread is not threading.current_thread():
                cleanup("listener-join", lambda: listener_thread.join(timeout=5))
        serving_stopped = listener_thread is None or cleanup("listener-liveness", listener_thread.is_alive) is False
        if listener is not None:
            cleanup("listener-close", listener.server_close)
        listener_closed = listener is None or cleanup("listener-socket", listener.socket.fileno) == -1
        if not serving_stopped:
            cleanup_errors.append("listener-thread-containment-unproved")
        if not listener_closed:
            cleanup_errors.append("listener-socket-close-unproved")
        cleanup_errors.extend(listener_errors)
        if workspace is not None:
            if outcome["all_contained"] is True and serving_stopped and listener_closed:
                cleanup("workspace-remove", workspace.cleanup)
            else:
                # Retain potentially live cwd; suppress automatic finalizer removal.
                workspace._finalizer.detach()
                cleanup_errors.append("workspace-retained-containment-unproved:" + workspace.name)
        containment = (outcome["all_contained"] if serving_stopped and listener_closed else False)
        report = {"all_contained": containment, "serving_thread_stopped": serving_stopped,
                  "listener_closed": listener_closed, "errors": list(cleanup_errors)}
        if evidence is not None:
            evidence["process_cleanup"] = outcome
            evidence["probe_cleanup"] = report
        if primary_error is not None:
            primary_error.app_server_cleanup = outcome
            primary_error.probe_cleanup = report
        if cleanup_errors:
            if primary_error is not None:
                primary_error.probe_cleanup_errors = cleanup_errors
                primary_error.add_note("probe cleanup: " + ";".join(cleanup_errors))
            else:
                error = CodexToolSurfaceError("probe-cleanup-failed:" + ";".join(cleanup_errors))
                error.app_server_cleanup = outcome
                error.probe_cleanup = report
                error.probe_cleanup_errors = cleanup_errors
                raise error
    if not captured:
        raise CodexToolSurfaceError("probe-request-not-captured")
    return captured


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--capture", type=Path)
    parser.add_argument("--profile", choices=("mutating", "read-only", "mutating-core-resources-v2",
                                              "read-only-core-resources-v2"), default="mutating")
    parser.add_argument("--catalog-projection", type=Path)
    parser.add_argument("--host-evidence", type=Path)
    parser.add_argument(
        "--codex-home",
        type=Path,
        default=Path(os.environ.get("CODEX_HOME", Path.home() / ".codex")),
    )
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--timeout-seconds", type=float, default=15.0)
    args = parser.parse_args()
    if args.timeout_seconds <= 0 or args.timeout_seconds > 120:
        parser.error("--timeout-seconds must be in (0, 120]")
    tools = list({"mutating": EXACT_TOOLS, "read-only": EXACT_READ_ONLY_TOOLS,
                  "mutating-core-resources-v2": EXACT_CORE_RESOURCE_OPERATIVE_TOOLS,
                  "read-only-core-resources-v2": EXACT_CORE_RESOURCE_READ_ONLY_TOOLS}[args.profile])
    if (not tools_are_mutable(tools)) != (args.catalog_projection is not None):
        parser.error("read-only requires --catalog-projection; mutating forbids it")
    evidence: dict[str, Any] = {"qualification": False, "provider_model_calls": 0}
    try:
        if args.catalog_projection is not None:
            prepare_read_only_catalog(args.codex_home, requested_model=args.model, output=args.catalog_projection)
        captured = capture_tool_request(
            codex_home=args.codex_home.resolve(),
            requested_model=args.model,
            timeout_seconds=args.timeout_seconds,
            permitted_tools=tools, catalog_projection=args.catalog_projection, evidence=evidence,
        )
        if args.capture is not None:
            _write_private_json(args.capture.resolve(), captured)
        proof = build_surface_proof(
            captured,
            codex_home=args.codex_home.resolve(),
            requested_model=args.model,
            permitted_tools=tools, catalog_projection=args.catalog_projection,
            capture_binding=evidence["capture_binding"], process_binding=evidence["process_binding"],
        )
        errors = validate_surface_proof(
            proof,
            requested_model=args.model,
            permitted_tools=tools,
        )
        if errors:
            raise CodexToolSurfaceError(";".join(errors))
        if args.host_evidence is not None:
            # This is capture/cleanup evidence, not a success commit. The proof
            # write below may still fail, as may subsequent failure reporting.
            _write_private_json(args.host_evidence.resolve(), evidence)
        _write_private_json(args.output.resolve(), proof)
    except (Exception, KeyboardInterrupt) as exc:
        failure = {"accepted": False, "error": str(exc), "error_type": type(exc).__name__,
                   "app_server_cleanup": _process_cleanup_report(getattr(exc, "app_server_cleanup", evidence.get("process_cleanup"))),
                   "probe_cleanup": getattr(exc, "probe_cleanup", evidence.get("probe_cleanup")),
                   "probe_cleanup_errors": list(getattr(exc, "probe_cleanup_errors", [])),
                   "notes": list(getattr(exc, "__notes__", []))}
        evidence.update(failure)
        if args.host_evidence is not None:
            try:
                _write_private_json(args.host_evidence.resolve(), evidence)
            except Exception as write_error:
                failure["evidence_write_error"] = f"{type(write_error).__name__}:{write_error}"
        print(json.dumps(failure, sort_keys=True))
        return 130 if isinstance(exc, KeyboardInterrupt) else 1
    print(
        json.dumps(
            {
                "accepted": True,
                "model": proof["observed_model"],
                "tools": proof["observed_tools"],
                "proof_sha256": proof["proof_sha256"],
                "output": str(args.output.resolve()),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
