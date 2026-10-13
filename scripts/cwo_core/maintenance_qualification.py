"""Prospective maintenance qualification: observed provider + checked reader CLI.

Only the trusted parent mints process-local observation/execution capabilities.
The reader CLI validates evidence, not authority. No worker JSON, copied object,
self-selected runner, receipt or hash can create a live qualification. Failed
observations retain their original failure and cleanup evidence, never a grant.
This is not a replacement for any frozen historical qualification protocol.
"""
from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import threading
import time
from typing import Any, Mapping
import uuid

from . import checked_command
from .maintenance_authority import require_maintenance_operation
from .maintenance_image import capture_control_image, require_control_image
from .native_pool_contracts import canonical_sha256
from .native_authority import canonical_authority_sha256


class QualificationError(ValueError):
    pass


RAW_NAMES = frozenset({
    "intent.json", "prompt.txt", "tool-surface.json", "process-start.json",
    "allocation-intent.json", "thread-start.json", "thread-config.json",
    "turn-intent.json", "turn-start.json", "turn-dispatch.json", "terminal.json",
    "session-before-closure.jsonl", "session.jsonl", "session-source.json",
    "thread-closure.json", "archived-thread.json", "process-closure.json",
    "model-discovery.json", "observation-times.json", "control-image.json",
    "endpoint-inventory-before.json", "endpoint-inventory-after.json",
})
REPORT_FIELDS = frozenset({
    "kind", "version", "mission_id", "operation_sha256", "model",
    "origin_issued_at", "origin_expires_at", "tool_profile_sha256",
    "tool_surface_proof_sha256", "control_image_sha256", "host_provenance_sha256",
    "pins", "primary_error", "cleanup_errors", "qualified",
})
_LOCK = threading.RLock()
_ISSUED: dict[str, dict[str, Any]] = {}
_ATTEMPTS: dict[tuple[object, str], str] = {}
_TOKEN = object()


def need(value: Any, reason: str) -> None:
    if value is not True:
        raise QualificationError("maintenance-qualification-" + reason)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hash(value: Any, label: str) -> str:
    need(type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value), label)
    return value


def _text(value: Any, label: str) -> str:
    need(type(value) is str and bool(value.strip()), label)
    return value


def _shape(value: Any, fields: set[str] | frozenset[str], label: str) -> dict:
    need(type(value) is dict and set(value) == fields, label)
    return value


def parse_json(raw: bytes | str) -> Any:
    def pairs(entries):
        out = {}
        for key, value in entries:
            need(key not in out, "duplicate-key")
            out[key] = value
        return out
    def constant(_value):
        raise QualificationError("maintenance-qualification-nonfinite-json")
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, UnicodeError, TypeError) as exc:
        raise QualificationError("maintenance-qualification-invalid-json") from exc


def _path(path: Path) -> Path:
    need(isinstance(path, Path) and path.is_absolute() and ".." not in path.parts
         and not any(p.is_symlink() for p in (path, *path.parents)), "path-invalid")
    return path


def _directory_identity(path: Path) -> tuple[int, int]:
    _path(path)
    info = path.stat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
         and stat.S_IMODE(info.st_mode) == 0o700, "output-not-private")
    return info.st_dev, info.st_ino


def _owned_read(path: Path, *, private: bool = False) -> tuple[bytes, dict[str, int]]:
    _path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
             and before.st_nlink == 1 and (not private or stat.S_IMODE(before.st_mode) == 0o600), "file-owner-invalid")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read()
        after = os.fstat(fd)
        fields = ("st_dev", "st_ino", "st_uid", "st_mode", "st_nlink", "st_size", "st_mtime_ns")
        need(all(getattr(before, f) == getattr(after, f) for f in fields)
             and (path.stat(follow_symlinks=False).st_dev, path.stat(follow_symlinks=False).st_ino)
             == (after.st_dev, after.st_ino), "file-capture-drift")
        return raw, {name: getattr(after, field) for name, field in zip(
            ("device", "inode", "uid", "mode", "links", "size", "mtime_ns"), fields)}
    finally:
        os.close(fd)


def private_write(root: Path, name: str, value: Any) -> str:
    need(type(name) is str and Path(name).name == name, "evidence-name-invalid")
    data = value if type(value) is bytes else (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()
    fd = os.open(_path(root) / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    return digest(data)


def pinned_bytes(root: Path, name: str, pins: Mapping[str, str]) -> bytes:
    need(type(name) is str and Path(name).name == name, "evidence-name-invalid")
    raw, _ = _owned_read(root / name, private=True)
    need(digest(raw) == pins.get(name), "evidence-pin-drift")
    return raw


def _lifetime(report: Mapping[str, Any], now: dt.datetime | None = None) -> None:
    current = now or dt.datetime.now(dt.timezone.utc)
    issued = dt.datetime.fromisoformat(report["origin_issued_at"])
    expires = dt.datetime.fromisoformat(report["origin_expires_at"])
    need(current.tzinfo is not None and issued.tzinfo is not None and expires.tzinfo is not None
         and issued <= current < expires and dt.timedelta(0) < expires - issued <= dt.timedelta(hours=1), "not-current")


def _session_path(value: Any, home: str) -> Path:
    path = _path(Path(_text(value, "session-path-invalid")))
    need(any(path.is_relative_to(Path(home) / sub) for sub in ("sessions", "archived_sessions")), "session-home-mismatch")
    return path


def _same_json(left: Any, right: Any) -> bool:
    """JSON equality preserves nested types; false is not integer zero."""
    try:
        return type(left) is type(right) and canonical_sha256(left) == canonical_sha256(right)
    except (ValueError, TypeError):
        return False


def _validate_session_metadata(rows, *, model, tid, turn_id, workspace):
    """Known host metadata is evidence, never execution/permission authority.

    Locale, catalog digest and installed skill descriptions are informational.
    Model/workspace/turn contradictions are not. Unknown row/event families
    reject rather than disappearing through an execution-event denylist.
    """
    events = {"task_started", "task_complete", "user_message", "agent_message", "token_count"}
    counters = {"input_tokens", "cached_input_tokens", "cache_write_input_tokens", "output_tokens", "reasoning_output_tokens", "total_tokens"}
    for row in rows:
        payload = row['payload']; kind = row['type']
        for key, expected in (("thread_id", tid), ("session_id", tid), ("turn_id", turn_id), ("root_turn_id", turn_id)):
            if key in payload:
                need(type(payload[key]) is str and payload[key] == expected, "session-record-identity-mismatch")
        if kind == 'event_msg':
            need(type(payload.get('type')) is str and payload['type'] in events, 'session-event-forbidden')
        elif kind == 'world_state':
            _shape(payload, {'full','state'}, 'world-state-fields-invalid')
            need(type(payload['full']) is bool and type(payload['state']) is dict, 'world-state-types-invalid')
            state=payload['state']
            if payload['full']:
                need('model' in state and 'environments' in state, 'world-state-required-fields-missing')
            if 'model' in state:
                need(type(state['model']) is str and state['model']==model, 'world-state-model-mismatch')
            if 'collaboration_mode' in state:
                collaboration=state['collaboration_mode'];need(type(collaboration) is dict,'world-state-collaboration-invalid')
                if 'model' in collaboration:need(type(collaboration['model']) is str and collaboration['model']==model,'world-state-model-mismatch')
            if 'environments' in state:
                environment=state['environments'];need(type(environment) is dict,'world-state-environment-invalid')
                local=environment.get('environments',{}).get('local') if type(environment.get('environments')) is dict else None
                need(type(local) is dict and type(local.get('cwd')) is str and local['cwd']==workspace,'world-state-workspace-mismatch')
        elif kind == 'token_usage_record':
            _shape(payload, {'thread_id','turn_id','session_id','root_turn_id','response_id','usage','turn_token_usage','thread_token_usage'}, 'token-record-fields-invalid')
            _text(payload['response_id'],'token-response-id-invalid')
            for key in ('usage','turn_token_usage','thread_token_usage'):
                group=_shape(payload[key],counters,'token-counters-fields-invalid')
                need(all(type(v) is int and v>=0 for v in group.values()),'token-counters-types-invalid')
                need(group['total_tokens']==group['input_tokens']+group['output_tokens']
                     and group['cached_input_tokens']<=group['input_tokens']
                     and group['reasoning_output_tokens']<=group['output_tokens'],'token-counters-inconsistent')
        elif kind == 'turn_context':
            profile=payload.get('permission_profile')
            if profile is not None:
                need(type(profile) is dict and profile.get('type')=='managed' and profile.get('network')=='restricted','session-permission-profile-invalid')
                filesystem=profile.get('file_system')
                need(type(filesystem) is dict and filesystem.get('type')=='restricted' and type(filesystem.get('entries')) is list,'session-permission-profile-invalid')
                need(all(type(entry) is dict and entry.get('access') in ('read','none') and type(entry.get('path')) is dict for entry in filesystem['entries']),'session-write-permission-forbidden')
            collaboration=payload.get('collaboration_mode')
            if collaboration is not None:
                need(type(collaboration) is dict and type(collaboration.get('settings')) is dict,'session-collaboration-invalid')
                settings=collaboration['settings']
                need(settings.get('model')==model and settings.get('reasoning_effort')=='low','session-collaboration-model-mismatch')


def inspect_observation(*, root: Path, observation_sha256: str, now: dt.datetime | None = None) -> dict[str, Any]:
    """Pure reader: validates original evidence; its return NEVER grants authority."""
    try:
        _hash(observation_sha256, "observation-hash-invalid")
        report = parse_json(pinned_bytes(root, "observation.json", {"observation.json": observation_sha256}))
        _shape(report, REPORT_FIELDS, "report-fields-invalid")
        need(report["kind"] == "cwo-maintenance-qualification-observation" and type(report["version"]) is int
             and report["version"] == 3 and report["qualified"] is False, "report-header-invalid")
        need(report["primary_error"] is None and report["cleanup_errors"] == [], "capture-or-cleanup-failed")
        _lifetime(report, now)
        pins = _shape(report["pins"], RAW_NAMES, "required-raw-set-invalid")
        for name, value in pins.items():
            _hash(value, "pin-invalid")
        raw = {name: pinned_bytes(root, name, pins) for name in RAW_NAMES}
        get = lambda name: parse_json(raw[name])
        image = get("control-image.json")
        _shape(image, {"image_type", "version", "root", "files", "image_sha256"}, "control-image-shape-invalid")
        need(image["image_type"] == "cwo-maintenance-control-image" and type(image["version"]) is int
             and image["version"] == 1 and type(image["root"]) is str and type(image["files"]) is dict
             and bool(image["files"]) and image["image_sha256"] == report["control_image_sha256"], "control-image-join-invalid")
        for name, entry in image["files"].items():
            need(type(name) is str and bool(name), "control-image-path-invalid")
            _shape(entry, {"sha256", "executable"}, "control-image-file-shape-invalid")
            _hash(entry["sha256"], "control-image-file-hash-invalid")
            need(type(entry["executable"]) is bool, "control-image-file-mode-invalid")
        need(canonical_sha256({k: v for k, v in image.items() if k != "image_sha256"}) == image["image_sha256"],
             "control-image-hash-invalid")
        require_control_image(image)
        intent = get("intent.json")
        _shape(intent, {"operation", "plan_sha256", "issued_at", "tool_surface_proof_sha256",
                        "control_image_sha256", "prompt_sha256", "operation_metadata", "qualification"}, "intent-invalid")
        scope = intent["operation"]
        need(type(scope) is dict and canonical_authority_sha256(scope) == report["operation_sha256"], "operation-hash-mismatch")
        model, workspace = report["model"], scope["workspace"]
        _text(model, "model-invalid")
        need(scope["model"] == model and scope["mission_id"] == report["mission_id"]
             and scope["plan_sha256"] == intent["plan_sha256"] and intent["qualification"] is False
             and intent["issued_at"] == report["origin_issued_at"], "intent-operation-mismatch")
        prompt = raw["prompt.txt"].decode()
        need(bool(prompt.strip()) and digest(raw["prompt.txt"]) == intent["prompt_sha256"], "prompt-pin-mismatch")
        from codex_tool_surface import PROOF_VERSION, require_zero_endpoint_inventory
        proof = get("tool-surface.json")
        need(type(proof) is dict and type(proof.get("version")) is int and proof["version"] == PROOF_VERSION
             and proof.get("verified") is True and proof.get("requested_model") == model
             and proof.get("observed_model") == model, "tool-proof-invalid")
        from codex_tool_surface import canonical_sha256 as surface_hash, TOOL_PROFILES
        need(type(proof.get("requested_tools")) is list and all(type(t) is str for t in proof["requested_tools"])
             and proof.get("observed_tools") == proof["requested_tools"]
             and proof.get("tool_profile") == TOOL_PROFILES.get(tuple(proof["requested_tools"])), "tool-profile-mismatch")
        need(surface_hash({k: v for k, v in proof.items() if k != "proof_sha256"}) == proof.get("proof_sha256"), "tool-proof-hash-invalid")
        binding = proof["capture_binding"]
        need(type(binding) is dict and surface_hash({k: v for k, v in binding.items() if k != "binding_sha256"}) == binding.get("binding_sha256"), "host-binding-invalid")
        for field in ("codex_home", "codex_binary", "codex_binary_sha256", "requested_model", "requested_tools",
                      "lockdown_config", "lockdown_config_sha256", "startup_config", "catalog_projection_sha256", "tool_profile", "effect_policy"):
            need(_same_json(proof.get(field), binding.get(field)), "host-profile-join-invalid")
        for field in ("operation_sha256", "tool_profile_sha256", "tool_surface_proof_sha256", "control_image_sha256", "host_provenance_sha256"):
            _hash(report[field], "report-digest-invalid")
        need(report["tool_surface_proof_sha256"] == canonical_sha256(proof) == intent["tool_surface_proof_sha256"]
             and report["tool_profile_sha256"] == canonical_sha256(proof["requested_tools"])
             and report["host_provenance_sha256"] == canonical_sha256(binding)
             and report["control_image_sha256"] == intent["control_image_sha256"], "report-identity-mismatch")
        process = get("process-start.json")
        _shape(process, {"pid", "executable", "codex_home", "connection_epoch_sha256", "requested_model", "reasoning_effort"}, "process-start-invalid")
        need(type(process["pid"]) is int and process["pid"] > 0 and process["executable"] == proof["codex_binary"]
             and process["codex_home"] == proof["codex_home"] and process["requested_model"] == model
             and process["reasoning_effort"] == "low", "process-host-mismatch")
        _hash(process["connection_epoch_sha256"], "connection-epoch-invalid")
        discovered = get("model-discovery.json")
        _shape(discovered, {"id", "model", "display_name", "latency_ms"}, "model-discovery-invalid")
        need(discovered["id"] == model and discovered["model"] == model
             and (discovered["display_name"] is None or type(discovered["display_name"]) is str)
             and type(discovered["latency_ms"]) in (int, float) and discovered["latency_ms"] >= 0,
             "model-discovery-mismatch")
        timing = get("observation-times.json")
        _shape(timing, {"source", "pid", "connection_epoch_sha256", "started_monotonic_ns",
                        "terminal_monotonic_ns", "cleanup_complete_monotonic_ns"}, "observation-times-invalid")
        need(timing["source"] == "trusted-parent-monotonic-clock-v1"
             and type(timing["pid"]) is int and timing["pid"] == process["pid"]
             and timing["connection_epoch_sha256"] == process["connection_epoch_sha256"]
             and all(type(timing[k]) is int for k in ("started_monotonic_ns", "terminal_monotonic_ns", "cleanup_complete_monotonic_ns"))
             and 0 < timing["started_monotonic_ns"] <= timing["terminal_monotonic_ns"] <= timing["cleanup_complete_monotonic_ns"]
             and (timing["terminal_monotonic_ns"] - timing["started_monotonic_ns"]) <= scope["reservation"]["runtime_seconds"] * 1_000_000_000,
             "observation-duration-invalid")
        allocation = get("allocation-intent.json")
        _shape(allocation, {"mission_id", "operation_id", "allocation_id", "ledger_sequence"}, "allocation-intent-invalid")
        need(allocation["mission_id"] == scope["mission_id"] and allocation["operation_id"] == scope["operation_id"]
             and type(allocation["ledger_sequence"]) is int and allocation["ledger_sequence"] > 0, "allocation-owner-invalid")
        _hash(allocation["allocation_id"], "allocation-id-invalid")
        start, config, turn = get("thread-start.json"), get("thread-config.json"), get("turn-start.json")
        thread = start["thread"]
        tid, turn_id = _text(thread["id"], "thread-id-invalid"), _text(turn["id"], "turn-id-invalid")
        for name in ("endpoint-inventory-before.json", "endpoint-inventory-after.json"):
            require_zero_endpoint_inventory(get(name), thread_id=tid, pid=process["pid"],
                                            connection_epoch_sha256=process["connection_epoch_sha256"])
        need(start.get("model") == model and thread.get("model") == model and thread.get("turns") == []
             and start.get("cwd") == workspace and thread.get("cwd") == workspace
             and start.get("runtimeWorkspaceRoots") == [workspace] and start.get("approvalPolicy") == "never"
             and type(start.get("sandbox")) is dict and start["sandbox"].get("type") == "readOnly"
             and start["sandbox"].get("networkAccess", False) is False
             and start["sandbox"].get("writableRoots", []) == [], "exact-start-or-sandbox-invalid")
        _shape(config, {"request", "response"}, "thread-config-invalid")
        request = config["request"]
        need(_same_json(config["response"], start) and request.get("model") == model
             and request.get("allowProviderModelFallback") is False and request.get("cwd") == workspace
             and request.get("runtimeWorkspaceRoots") == [workspace] and request.get("approvalPolicy") == "never"
             and request.get("sandbox") == "read-only" and request.get("ephemeral") is False
             and _same_json(request.get("config"), proof["lockdown_config"]) and request.get("dynamicTools") == [], "effective-config-invalid")
        need(type(request.get("developerInstructions")) is str and "no-tools precommit fit" in request["developerInstructions"], "fit-phase-invalid")
        turn_intent = get("turn-intent.json")
        need(turn_intent == {"thread_id": tid, "prompt_sha256": intent["prompt_sha256"],
                            "connection_epoch_sha256": process["connection_epoch_sha256"]}, "turn-intent-mismatch")
        from .native_turn_dispatch import validate_turn_dispatch_record
        dispatch = get("turn-dispatch.json")
        need(type(dispatch.get("version")) is int and type(dispatch.get("wire_write_attempt_count")) is int
             and validate_turn_dispatch_record(dispatch) == [] and dispatch["status"] == "acknowledged"
             and dispatch["wire_write_attempt_count"] == 1 and dispatch["thread_id"] == tid
             and dispatch["exact_response_turn_id"] == turn_id and dispatch["preexisting_turn_ids"] == []
             and dispatch["connection_epoch_sha256"] == process["connection_epoch_sha256"], "turn-dispatch-invalid")
        from .native_canary_contracts import canonical_sha256 as domain_hash
        metadata = _shape(intent["operation_metadata"], {"cwo_bead", "cwo_control_turn", "cwo_mission"}, "operation-metadata-invalid")
        need(metadata["cwo_mission"] == scope["mission_id"] and all(type(v) is str and bool(v) for v in metadata.values()), "operation-metadata-mismatch")
        wire = {"id": dispatch["request_id"], "method": "turn/start", "params": {
            "threadId": tid, "input": [{"type": "text", "text": prompt, "text_elements": []}],
            "model": model, "effort": "low", "clientUserMessageId": dispatch["turn_intent_id"],
            "responsesapiClientMetadata": metadata}}
        need(domain_hash(wire, domain="app-server-single-wire-request") == dispatch["wire_request_sha256"], "wire-prompt-join-invalid")
        terminal = get("terminal.json")
        need(terminal.get("id") == tid and terminal.get("model") == model and terminal.get("cwd") == workspace
             and type(terminal.get("turns")) is list and len(terminal["turns"]) == 1, "terminal-thread-invalid")
        completed = terminal["turns"][0]
        need(completed.get("id") == turn_id and completed.get("status") == "completed" and completed.get("error") is None, "terminal-not-completed")
        items = completed.get("items")
        need(type(items) is list and all(type(i) is dict and i.get("type") in {"userMessage", "agentMessage", "reasoning"} for i in items), "qualification-tools-forbidden")
        users = [i for i in items if i["type"] == "userMessage"]
        need(len(users) == 1 and type(users[0].get("content")) is list
             and [c.get("text") for c in users[0]["content"] if type(c) is dict and c.get("type") == "text"] == [prompt], "terminal-prompt-mismatch")
        finals = [i.get("text") for i in items if i["type"] == "agentMessage" and i.get("phase") in ("finalAnswer", "final_answer")]
        need(len(finals) == 1 and type(finals[0]) is str, "final-response-missing")
        fit = parse_json(finals[0])
        _shape(fit, {"decision", "tool_calls_p50", "tool_calls_p90", "runtime_seconds_p50", "runtime_seconds_p90"}, "fit-shape-invalid")
        need(fit["decision"] == "accept", "fit-not-accepted")
        for stem in ("tool_calls", "runtime_seconds"):
            need(type(fit[stem + "_p50"]) is int and type(fit[stem + "_p90"]) is int
                 and 0 < fit[stem + "_p50"] <= fit[stem + "_p90"], "fit-count-invalid")
        source = get("session-source.json")
        _shape(source, {"start_path", "path", "before_identity", "identity", "sha256"}, "session-source-invalid")
        for key in ("identity", "before_identity"):
            identity_fields = {"device", "inode", "uid", "mode", "links", "size", "mtime_ns"}
            _shape(source[key], identity_fields, "source-identity-fields-invalid")
            need(all(type(v) is int and v >= 0 for v in source[key].values()), "source-identity-type-invalid")
        need(source["start_path"] == thread["path"] == terminal["path"], "session-source-path-mismatch")
        _session_path(source["start_path"], process["codex_home"])
        actual, identity = _owned_read(_session_path(source["path"], process["codex_home"]))
        need(identity == source["identity"] and source["before_identity"]["inode"] == identity["inode"]
             and source["before_identity"]["device"] == identity["device"] and digest(actual) == source["sha256"]
             and actual == raw["session.jsonl"] and actual.startswith(raw["session-before-closure.jsonl"]), "original-source-drift")
        need(actual.endswith(b"\n"), "partial-session-record")
        rows = [parse_json(line) for line in actual.splitlines()]
        need(all(type(row) is dict and type(row.get("payload")) is dict
                 and row.get("type") in {"session_meta", "turn_context", "response_item", "event_msg", "world_state", "token_usage_record"} for row in rows), "session-record-invalid")
        _validate_session_metadata(rows, model=model, tid=tid, turn_id=turn_id, workspace=workspace)
        metas = [r["payload"] for r in rows if r.get("type") == "session_meta"]
        contexts = [r["payload"] for r in rows if r.get("type") == "turn_context"]
        need(len(metas) == 1 and metas[0].get("id") == tid and metas[0].get("session_id", tid) == tid
             and metas[0].get("cwd") == workspace, "session-origin-invalid")
        need(bool(contexts) and all(c.get("model") == model and c.get("turn_id") == turn_id
             and c.get("cwd") == workspace and c.get("effort", c.get("reasoning_effort")) == "low"
             and c.get("approval_policy") == "never" and c.get("sandbox_policy", {}).get("type") == "read-only" for c in contexts), "session-context-invalid")
        responses = [r["payload"] for r in rows if r.get("type") == "response_item"]
        need(all(p.get("type") in {"message", "reasoning"} and (p.get("type") != "message"
                 or p.get("role") in {"system", "developer", "user", "assistant"}) for p in responses), "session-tools-forbidden")
        user_text = [c.get("text") for p in responses if p.get("role") == "user" for c in p.get("content", []) if c.get("type") == "input_text"]
        need(user_text.count(prompt) == 1, "original-prompt-join-invalid")
        finals_raw = [c.get("text") for p in responses if p.get("role") == "assistant" and p.get("phase") in ("final_answer", "finalAnswer") for c in p.get("content", []) if c.get("type") == "output_text"]
        need(finals_raw == finals, "original-answer-join-invalid")
        need(not any(r["payload"].get("type") in {"context_compacted", "context_compaction", "compaction",
                     "exec_command_begin", "exec_command_end", "patch_apply_begin", "patch_apply_end",
                     "mcp_tool_call_begin", "mcp_tool_call_end", "web_search_begin", "web_search_end"}
                     for r in rows if r.get("type") == "event_msg"), "session-tools-or-compaction-forbidden")
        starts = [r["payload"] for r in rows if r.get("type") == "event_msg" and r["payload"].get("type") == "task_started"]
        ends = [r["payload"] for r in rows if r.get("type") == "event_msg" and r["payload"].get("type") == "task_complete"]
        need(len(starts) == len(ends) == 1 and starts[0].get("turn_id") == turn_id
             and ends[0].get("turn_id") == turn_id and ends[0].get("last_agent_message") == finals[0], "original-terminal-join-invalid")
        closure, cleanup, archived = get("thread-closure.json"), get("process-closure.json"), get("archived-thread.json")
        count_fields = {"allocated_count": 1, "identified_thread_count": 1, "interrupted_count": 0,
                        "archived_count": 1, "already_contained_count": 0, "unresolved_allocation_intent_count": 0,
                        "unresolved_turn_intent_count": 0, "ambiguous_count": 0}
        _shape(closure, set(count_fields) | {"all_contained", "ledger_consistent", "ledger_error_sha256"}, "thread-closure-shape-invalid")
        need(all(type(closure[k]) is int and closure[k] == v for k, v in count_fields.items())
             and closure["all_contained"] is True and closure["ledger_consistent"] is True
             and closure["ledger_error_sha256"] == [], "thread-closure-invalid")
        need(archived.get("id") == tid and archived.get("path") == source["path"]
             and archived.get("model") == model and archived.get("cwd") == workspace
             and _same_json(archived.get("turns"), terminal["turns"]), "archived-source-join-invalid")
        _shape(cleanup, {"all_contained", "resources_closed", "errors", "pid"}, "process-closure-shape-invalid")
        need(cleanup["all_contained"] is True and cleanup["resources_closed"] is True and cleanup["errors"] == []
             and type(cleanup["pid"]) is int and cleanup["pid"] == process["pid"], "owned-process-closure-invalid")
        return {"kind": "cwo-maintenance-qualification-checked-observation", "version": 1,
                "observation_sha256": observation_sha256, "operation_sha256": report["operation_sha256"],
                "model": model, "thread_id": tid, "turn_id": turn_id,
                "connection_epoch_sha256": process["connection_epoch_sha256"],
                "session_sha256": source["sha256"], "accepted_evidence": True, "authority": False}
    except QualificationError:
        raise
    except (OSError, ValueError, TypeError, KeyError, AttributeError, OverflowError) as exc:
        raise QualificationError("maintenance-qualification-observation-invalid:" + str(exc)) from exc


@dataclass(frozen=True, slots=True)
class _Capability:
    _identity: str
    _pid: int
    _token: object

    def __post_init__(self):
        need(self._token is _TOKEN, "opaque-capability-required")

    @property
    def record(self):
        return deepcopy(_entry(self)["record"])

    @property
    def operation_sha256(self):
        return _entry(self)["origin_operation_sha256"]


class VerifiedQualificationObservation(_Capability):
    pass


class CheckedQualificationExecution(_Capability):
    pass


class VerifiedMaintenanceQualification(_Capability):
    pass


def _mint(cls, *, operation, verifier, record, **state):
    value = cls(uuid.uuid4().hex, os.getpid(), _TOKEN)
    _ISSUED[value._identity] = {"value": value, "operation": operation, "verifier": verifier,
        "origin_operation_sha256": operation.operation_sha256, "record": deepcopy(record),
        "busy": False, "poisoned": False, **state}
    return value


def _entry(value):
    need(type(value) in {VerifiedQualificationObservation, CheckedQualificationExecution, VerifiedMaintenanceQualification}, "opaque-capability-required")
    row = _ISSUED.get(value._identity)
    need(value._pid == os.getpid() and row is not None and row["value"] is value, "foreign-copied-or-serialized-capability")
    need(not row["poisoned"], "capability-invalidated")
    return row


@contextmanager
def _exclusive(value):
    with _LOCK:
        row = _entry(value)
        if row["busy"]:
            row["poisoned"] = True
            raise QualificationError("maintenance-qualification-reentrant")
        row["busy"] = True
        try:
            yield row
            need(not row["poisoned"], "capability-invalidated")
        finally:
            row["busy"] = False


def _observation_current(value, *, operation, verifier, now=None, same_operation=True):
    row = _entry(value)
    need(row["verifier"] is verifier, "foreign-issuer")
    cap = require_maintenance_operation(operation, verifier=verifier)
    scope = cap.evidence()["operation"]
    origin = row["scope"]
    need(scope["mission_id"] == origin["mission_id"] and scope["mission_sha256"] == origin["mission_sha256"]
         and scope["model"] == origin["model"], "owner-scope-mismatch")
    if same_operation:
        need(row["operation"] is operation, "foreign-operation")
    need(_directory_identity(row["root"]) == row["root_identity"], "observation-directory-replaced")
    summary = inspect_observation(root=row["root"], observation_sha256=row["observation_sha256"], now=now)
    need(_same_json(summary, row["summary"]), "observation-drift")
    return row


def observe_qualification(*, operation, verifier, plan, workspace: Path, output: Path,
                          session_ledger, tool_surface_proof: Mapping[str, Any], control_image_sha256: str,
                          fit_prompt: str, timeout_seconds: int = 180, ttl_seconds: int = 900):
    """Observe a genuine bounded no-tools provider turn; failures retain evidence."""
    from run_native_pool_live_canaries import AppServer, AppServerRpcError, THREAD_PHASE_PRECOMMIT_FIT, contain_started_threads
    from codex_tool_surface import require_surface_proof, ALLOWLIST_PARAMETER
    from .maintenance_runtime_support import MaintenanceSessionLedger
    cap = require_maintenance_operation(operation, verifier=verifier, plan=plan)
    scope = cap.evidence()["operation"]
    need(scope["workspace"] == str(workspace), "workspace-mismatch")
    need(type(session_ledger) is MaintenanceSessionLedger and session_ledger.mission_id == scope["mission_id"], "owner-session-ledger-required")
    need(type(timeout_seconds) is int and 1 <= timeout_seconds <= min(900, scope["reservation"]["runtime_seconds"]), "timeout-invalid")
    need(type(ttl_seconds) is int and 1 <= ttl_seconds <= 3600, "expiry-invalid")
    _hash(control_image_sha256, "control-image-hash-invalid")
    control_image = capture_control_image()
    need(control_image["image_sha256"] == control_image_sha256, "actual-control-image-required")
    _text(fit_prompt, "prompt-invalid")
    _path(output)
    need(not output.exists() and not output.is_relative_to(workspace), "fresh-private-output-required")
    key = (verifier, cap.operation_sha256)
    with _LOCK:
        if key in _ATTEMPTS:
            _ATTEMPTS[key] = "invalidated"
            raise QualificationError("maintenance-qualification-operation-already-observed")
        _ATTEMPTS[key] = "observing"
    origin_code_pins = _code_pins()
    proof = require_surface_proof(tool_surface_proof, requested_model=scope["model"], permitted_tools=tool_surface_proof.get("requested_tools"))
    output.mkdir(parents=True, mode=0o700)
    need(stat.S_IMODE(output.stat().st_mode) == 0o700, "output-not-private")
    issued = dt.datetime.now(dt.timezone.utc)
    pins, server, primary, cleanup_errors = {}, None, None, []
    started_ns = time.monotonic_ns()
    terminal_ns = None
    started_at = time.monotonic()
    metadata = {"cwo_bead": plan["children"][0]["bead_id"],
                "cwo_control_turn": plan["transaction_id"], "cwo_mission": scope["mission_id"]}
    source = before_identity = before_raw = archived = None
    tid = None
    keep = lambda name, value: pins.update({name: private_write(output, name, value)})
    keep("intent.json", {"operation": scope, "plan_sha256": plan["plan_sha256"], "issued_at": issued.isoformat(),
        "tool_surface_proof_sha256": canonical_sha256(proof), "control_image_sha256": control_image_sha256,
        "prompt_sha256": digest(fit_prompt.encode()), "operation_metadata": metadata, "qualification": False})
    keep("prompt.txt", fit_prompt.encode())
    keep("tool-surface.json", proof)
    keep("control-image.json", control_image)
    try:
        cap.revalidate(plan=plan)
        server = AppServer(requested_model=scope["model"], reasoning_effort="low", tool_surface_proof=proof,
            operation_metadata=metadata)
        keep("process-start.json", {"pid": server.process.pid, "executable": server.launched_executable,
            "codex_home": str(server.codex_home), "connection_epoch_sha256": server.connection_epoch_sha256,
            "requested_model": server.requested_model, "reasoning_effort": server.reasoning_effort})
        keep("model-discovery.json", server.model_discovery())
        cap.revalidate(plan=plan)
        intent = {"allocation_id": canonical_sha256({"operation_sha256": cap.operation_sha256, "purpose": "qualification"}),
                  "allocation_class": "prelude", "ordinal": 0, "child_id": None}
        count = session_ledger.record_intent(scope["operation_id"], intent)
        keep("allocation-intent.json", {"mission_id": scope["mission_id"], "operation_id": scope["operation_id"],
                                        "allocation_id": intent["allocation_id"], "ledger_sequence": count})
        cap.revalidate(plan=plan)
        require_control_image(control_image)
        response, _ = server.start_thread(workspace, mutable=False, thread_phase=THREAD_PHASE_PRECOMMIT_FIT,
            permitted_tools=list(proof["requested_tools"]), allowlist_parameter=ALLOWLIST_PARAMETER)
        keep("thread-start.json", response)
        tid = response["thread"]["id"]
        keep("thread-config.json", server._effective_thread_start_evidence[tid])
        keep("endpoint-inventory-before.json", server.require_zero_mcp_endpoints(tid))
        keep("turn-intent.json", {"thread_id": tid, "prompt_sha256": digest(fit_prompt.encode()),
                                  "connection_epoch_sha256": server.connection_epoch_sha256})
        cap.revalidate(plan=plan)
        require_control_image(control_image)
        turn, _ = server.start_turn(tid, fit_prompt)
        keep("turn-start.json", turn)
        keep("turn-dispatch.json", server.turn_dispatch_record(tid))
        deadline = started_at + timeout_seconds
        # An acknowledged turn can precede its persisted thread history. Retry
        # only this owned, idempotent read, within one fixed startup horizon.
        # This never supplies a terminal receipt, repeats turn/start or accepts
        # a candidate. Any successful observation ends the startup grace.
        read_startup_deadline = min(deadline, time.monotonic() + 3.0)
        observed_current_turn = False
        read_startup_count = 0
        while True:
            cap.revalidate(plan=plan)
            remaining = deadline - time.monotonic()
            need(remaining > 0, "terminal-timeout")
            try:
                thread, _ = server.read_thread(tid, timeout=min(15, remaining))
            except AppServerRpcError as exc:
                if (exc.method != "thread/read" or exc.code != -32603
                        or observed_current_turn or time.monotonic() >= read_startup_deadline):
                    raise
                # Local diagnostic evidence only; not a success/provenance grant.
                private_write(output, f"thread-read-startup-{read_startup_count}.json", {
                    "classification": "owned-idempotent-startup-read-retry", "thread_id": tid,
                    "turn_id": turn["id"], "method": exc.method, "code": exc.code,
                    "request_id": exc.request_id, "latency_ms": exc.latency_ms,
                    "connection_epoch_sha256": server.connection_epoch_sha256,
                    "read_startup_deadline_monotonic": read_startup_deadline})
                read_startup_count += 1
                time.sleep(min(.25, max(0, read_startup_deadline-time.monotonic())))
                continue
            current = next((t for t in thread.get("turns", []) if t.get("id") == turn["id"]), None)
            observed_current_turn = observed_current_turn or current is not None
            if current and current.get("status") in ("completed", "failed", "interrupted"):
                terminal_ns = time.monotonic_ns()
                keep("terminal.json", thread)
                keep("endpoint-inventory-after.json", server.require_zero_mcp_endpoints(tid))
                break
            time.sleep(min(.25, max(0, deadline - time.monotonic())))
        source = _session_path(response["thread"]["path"], str(server.codex_home))
        before_raw, before_identity = _owned_read(source)
        keep("session-before-closure.jsonl", before_raw)
    except BaseException as exc:
        primary = {"type": type(exc).__name__, "message": str(exc),
                   "observed_cleanup": getattr(exc, "app_server_cleanup", None)}
    finally:
        cleanup_started = time.monotonic()
        if server is not None:
            try:
                keep("thread-closure.json", contain_started_threads(server, allow_same_process_proofs=True))
                if tid is not None:
                    archived, _ = server.read_thread(tid)
                    keep("archived-thread.json", archived)
            except BaseException as exc:
                cleanup_errors.append({"resource": "threads", "type": type(exc).__name__, "message": str(exc)})
            try:
                keep("process-closure.json", server.close())
            except BaseException as exc:
                cleanup_errors.append({"resource": "process", "type": type(exc).__name__, "message": str(exc),
                                       "observed": getattr(exc, "app_server_cleanup", None)})
            if source is not None and archived is not None:
                try:
                    final_path = _session_path(archived["path"], str(server.codex_home))
                    actual, identity = _owned_read(final_path)
                    need(actual.startswith(before_raw) and identity["inode"] == before_identity["inode"]
                         and identity["device"] == before_identity["device"], "session-archive-replaced")
                    keep("session.jsonl", actual)
                    keep("session-source.json", {"start_path": str(source), "path": str(final_path),
                        "before_identity": before_identity, "identity": identity, "sha256": digest(actual)})
                except BaseException as exc:
                    cleanup_errors.append({"resource": "source-capture", "type": type(exc).__name__, "message": str(exc)})
        if time.monotonic() - cleanup_started > scope["reservation"]["cleanup_seconds"]:
            cleanup_errors.append({"resource": "cleanup-reservation", "type": "TimeoutError", "message": "cleanup bound exceeded"})
        if cleanup_started - started_at > scope["reservation"]["runtime_seconds"]:
            primary = primary or {"type": "TimeoutError", "message": "operation runtime bound exceeded"}
        if server is not None and terminal_ns is not None:
            keep("observation-times.json", {"source": "trusted-parent-monotonic-clock-v1",
                "pid": server.process.pid, "connection_epoch_sha256": server.connection_epoch_sha256,
                "started_monotonic_ns": started_ns, "terminal_monotonic_ns": terminal_ns,
                "cleanup_complete_monotonic_ns": time.monotonic_ns()})
        report = {"kind": "cwo-maintenance-qualification-observation", "version": 3, "mission_id": scope["mission_id"],
            "operation_sha256": cap.operation_sha256, "model": scope["model"], "origin_issued_at": issued.isoformat(),
            "origin_expires_at": (issued + dt.timedelta(seconds=ttl_seconds)).isoformat(),
            "tool_profile_sha256": canonical_sha256(proof["requested_tools"]), "tool_surface_proof_sha256": canonical_sha256(proof),
            "control_image_sha256": control_image_sha256, "host_provenance_sha256": canonical_sha256(proof["capture_binding"]),
            "pins": pins, "primary_error": primary, "cleanup_errors": cleanup_errors, "qualified": False}
        observation_hash = private_write(output, "observation.json", report)
    need(primary is None and cleanup_errors == [], "capture-or-cleanup-failed:" + str(output))
    cap.revalidate(plan=plan)
    summary = inspect_observation(root=output, observation_sha256=observation_hash)
    with _LOCK:
        need(_ATTEMPTS[key] == "observing", "observation-reentrant-or-replayed")
        need(origin_code_pins == _code_pins(), "observation-code-drift")
        _ATTEMPTS[key] = "observed"
        return _mint(VerifiedQualificationObservation, operation=cap, verifier=verifier, record=report,
            root=output, root_identity=_directory_identity(output), observation_sha256=observation_hash,
            scope=scope, summary=summary, origin_code_pins=origin_code_pins, check_started=False)


def _code_pins() -> dict[str, str]:
    # Owner-selected installed code, not a path supplied by evidence or a worker.
    root = Path(__file__).resolve().parents[2]
    paths = [root / "scripts/check_maintenance_qualification.py", root / "scripts/codex_tool_surface.py",
             root / "scripts/run_native_pool_live_canaries.py",
             *(root / "scripts/cwo_core" / name for name in (
                 "__init__.py", "maintenance_qualification.py", "maintenance_image.py", "checked_command.py", "maintenance_authority.py",
                 "native_authority.py", "native_pool_contracts.py", "native_turn_dispatch.py",
                 "native_canary_contracts.py", "native_stop_scope.py", "native_tool_isolation.py", "util.py"))]
    pins = {str(path): digest(_owned_read(path)[0]) for path in paths}
    executable = Path(sys.executable).resolve(strict=True)
    need(executable.is_file(), "checker-interpreter-invalid")
    pins[str(executable)] = digest(executable.read_bytes())
    return pins


def _checked_spec(root: Path, observation_hash: str, nonce: str) -> dict[str, Any]:
    checker = Path(__file__).resolve().parents[1] / "check_maintenance_qualification.py"
    return checked_command.normalize_command_spec({"spec_type": "cwo-checked-command-spec", "version": 1,
        "command_id": "maintenance-qualification-" + nonce, "mode": "argv",
        "argv": [str(Path(sys.executable).resolve(strict=True)), "-I", "-B", str(checker), "--root", str(root),
                 "--observation-sha256", observation_hash, "--nonce", nonce],
        "cwd": str(root), "env": {}, "inherit_environment": False, "stdin": None, "source": None,
        "preflights": [], "mutation_intent": "none", "allowed_paths": [], "timeout_seconds": 30})


def check_qualification(observation, *, operation, verifier):
    """Run the fixed actual reader CLI once, then retain its opaque lineage."""
    need(type(observation) is VerifiedQualificationObservation, "opaque-observation-required")
    with _exclusive(observation) as row:
        need(not row["check_started"], "check-already-consumed")
        row["check_started"] = True
        _observation_current(observation, operation=operation, verifier=verifier)
        code_pins = _code_pins()
        need(row["origin_code_pins"] == code_pins, "observation-code-drift")
        nonce = uuid.uuid4().hex
        spec = _checked_spec(row["root"], row["observation_sha256"], nonce)
        execution_pins = {"checker-intent.json": private_write(row["root"], "checker-intent.json", {"spec": spec, "code_pins": code_pins, "nonce": nonce})}
        receipt = checked_command.execute_checked_command(spec)
        execution_pins["checker-receipt.json"] = private_write(row["root"], "checker-receipt.json", receipt)
        need(code_pins == _code_pins(), "checker-source-drift")
        _observation_current(observation, operation=operation, verifier=verifier)
        expected_spec = digest(json.dumps(spec, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode())
        need(type(receipt) is dict and receipt.get("result_type") == "cwo-checked-command-result"
             and type(receipt.get("version")) is int and receipt["version"] == 1
             and receipt.get("spec_sha256") == expected_spec and receipt.get("command_id") == spec["command_id"]
             and receipt.get("execution_status") == "passed" and receipt.get("preflight_status") == "passed"
             and receipt.get("execution_started") is True and type(receipt.get("exit_code")) is int and receipt["exit_code"] == 0
             and receipt.get("hash_match") is True and receipt.get("quarantine_required") is False
             and receipt.get("mutation_started") is False and receipt.get("mutated_paths") == [], "checked-cli-receipt-invalid")
        stdout = receipt.get("diagnostics", {}).get("stdout")
        expected = {**row["summary"], "nonce": nonce}
        need(type(stdout) is str and _same_json(parse_json(stdout), expected), "checked-cli-output-mismatch")
        record = {"spec_sha256": expected_spec, "receipt_sha256": canonical_sha256(receipt),
                  "runner_sha256": canonical_sha256(code_pins), "stdout_sha256": digest(stdout.encode())}
        return _mint(CheckedQualificationExecution, operation=operation, verifier=verifier, record=record,
            observation=observation, code_pins=code_pins, receipt=deepcopy(receipt), spec=spec, execution_pins=execution_pins,
            consumed=False, root=row["root"], root_identity=row["root_identity"], observation_sha256=row["observation_sha256"],
            summary=row["summary"], scope=row["scope"])


def adjudicate_qualification(*, observation, checked_execution, operation, verifier, now=None):
    """Consume genuine parent-issued objects; free JSON/specs/receipts are refused."""
    need(type(observation) is VerifiedQualificationObservation, "opaque-observation-required")
    need(type(checked_execution) is CheckedQualificationExecution, "opaque-checked-execution-required")
    with _exclusive(checked_execution) as checked:
        need(not checked["consumed"], "checked-execution-already-consumed")
        checked["consumed"] = True
        need(checked["observation"] is observation and checked["operation"] is operation
             and checked["verifier"] is verifier, "checked-issuer-or-observation-mismatch")
        row = _observation_current(observation, operation=operation, verifier=verifier, now=now)
        need(checked["code_pins"] == _code_pins(), "checker-source-drift")
        for name in checked["execution_pins"]:
            pinned_bytes(row["root"], name, checked["execution_pins"])
        report, execution = row["record"], checked["record"]
        record = {"model": report["model"], "receipt_sha256": execution["receipt_sha256"],
            "canary_sha256": row["observation_sha256"],
            **{key: report[key] for key in ("origin_issued_at", "origin_expires_at", "tool_profile_sha256", "control_image_sha256", "host_provenance_sha256")},
            "command_sha256": execution["spec_sha256"], "execution_sha256": execution["receipt_sha256"],
            "runner_sha256": execution["runner_sha256"]}
        return _mint(VerifiedMaintenanceQualification, operation=operation, verifier=verifier, record=record,
            root=row["root"], root_identity=row["root_identity"], observation_sha256=row["observation_sha256"], summary=row["summary"],
            scope=row["scope"], code_pins=checked["code_pins"], execution_pins=checked["execution_pins"])


def require_maintenance_qualification(value, *, operation, verifier, now=None):
    need(type(value) is VerifiedMaintenanceQualification, "verified-qualification-required")
    with _exclusive(value) as row:
        _observation_current(value, operation=operation, verifier=verifier, now=now, same_operation=False)
        need(row["code_pins"] == _code_pins(), "checker-source-drift")
        for name in row["execution_pins"]:
            pinned_bytes(row["root"], name, row["execution_pins"])
    return value


def qualification_capability_evidence(value, *, operation, verifier, tool_surface_id):
    """Derive detached evidence from original checked observation; never a grant.

    The caller must separately issue trusted actor provenance and retain its opaque
    qualification join. The legacy capability hash covers only capability fields,
    not the qualification receipt; this function does not create either authority.
    """
    require_maintenance_qualification(value, operation=operation, verifier=verifier)
    with _exclusive(value) as row:
        _observation_current(value, operation=operation, verifier=verifier, same_operation=False)
        report = parse_json(pinned_bytes(row["root"], "observation.json",
                            {"observation.json": row["observation_sha256"]}))
        get = lambda name: parse_json(pinned_bytes(row["root"], name, report["pins"]))
        proof, process = get("tool-surface.json"), get("process-start.json")
        from codex_tool_surface import tool_profile_is_mutable, ALLOWLIST_PARAMETER
        from .native_tool_isolation import default_tool_policy, build_tool_surface_snapshot, CORE_RESOURCE_TOOL_PROFILES
        profile = proof["tool_profile"]
        policy = default_tool_policy(mutable=tool_profile_is_mutable(profile), workload_class="operative",
            **({"tool_profile": profile} if profile in CORE_RESOURCE_TOOL_PROFILES else {}))
        surface = build_tool_surface_snapshot(policy,
            source="codex-app-server-v2-thread-config-proof:" + proof["proof_sha256"],
            server_allowlist_supported=True, allowlist_parameter=ALLOWLIST_PARAMETER,
            effective_allowlist=proof["observed_tools"])
        need(type(tool_surface_id) is str and tool_surface_id == surface["surface_sha256"], "capability-tool-surface-mismatch")
        timing, discovery, terminal = get("observation-times.json"), get("model-discovery.json"), get("terminal.json")
        session = pinned_bytes(row["root"], "session.jsonl", report["pins"])
        contexts = [r["payload"] for r in (parse_json(line) for line in session.splitlines()) if r["type"] == "turn_context"]
        closure, process_closure = get("thread-closure.json"), get("process-closure.json")
        # All absence/closure claims below have just been rechecked by the reader:
        # exact original session kinds, no tool response/items or compaction event,
        # one completed turn, exact archive count, same PID reaped and handles closed.
        evidence = {"requested_model": report["model"], "configured_model": process["requested_model"],
            "advertised": discovery["id"] == report["model"], "advertised_models": [discovery["model"]],
            "spawn_accepted": True, "canary_session_id": terminal["id"],
            "attestation_source": "trusted-session-jsonl", "attested_model": contexts[0]["model"],
            "tool_calls": 0, "context_compactions": 0,
            "runtime_seconds": (timing["terminal_monotonic_ns"] - timing["started_monotonic_ns"]) / 1_000_000_000,
            "closure_receipt": closure["all_contained"] and process_closure["all_contained"] and process_closure["resources_closed"],
            "tool_surface_id": surface["surface_sha256"]}
        return deepcopy(evidence)
