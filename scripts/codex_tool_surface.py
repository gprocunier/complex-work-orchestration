"""Hash-bound proof for the exact connected-Codex operative tool surface.

The Codex app-server does not expose a dedicated built-in-tool allowlist. Its
per-thread ``config`` input can still produce an exact surface when every
optional tool source is disabled and ``dynamicTools`` is empty. This module
keeps that configuration portable and validates a loopback-captured Responses
request before it may be reused by a productive worker thread.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import os
import stat
from pathlib import Path
import re
import shutil
import subprocess
import time
import tomllib
from typing import Any, Mapping


from cwo_core.native_tool_isolation import CORE_RESOURCE_TOOL_PROFILES

PROOF_TYPE = "cwo-codex-config-tool-surface-proof"
PROOF_VERSION = 5
ALLOWLIST_PARAMETER = "config"
EXACT_OPERATIVE_TOOLS = ("apply_patch", "exec_command", "write_stdin")
EXACT_READ_ONLY_TOOLS = ("exec_command", "write_stdin")
TOOL_PROFILES = {
    EXACT_OPERATIVE_TOOLS: "mutating-v1",
    EXACT_READ_ONLY_TOOLS: "read-only-v1",
}
EXACT_CORE_RESOURCE_OPERATIVE_TOOLS = CORE_RESOURCE_TOOL_PROFILES["mutating-core-resources-v2"]
EXACT_CORE_RESOURCE_READ_ONLY_TOOLS = CORE_RESOURCE_TOOL_PROFILES["read-only-core-resources-v2"]
TOOL_PROFILES.update({tools: name for name, tools in CORE_RESOURCE_TOOL_PROFILES.items()})
CURRENT_EFFECT_FIELDS = frozenset({"effect_policy"})
PROFILE_PROOF_FIELDS = frozenset({
    "tool_profile", "startup_config", "catalog_projection_sha256",
})
DIRECT_TOOL_TRANSPORT = "direct-tool-calls-v1"
NAMESPACED_EXEC_TOOL_TRANSPORT = "namespaced-exec-wrapper-v1"
TOOL_TRANSPORTS = frozenset(
    {DIRECT_TOOL_TRANSPORT, NAMESPACED_EXEC_TOOL_TRANSPORT}
)
DISABLED_FEATURES = (
    "apps",
    "current_time_reminder",
    "default_mode_request_user_input",
    "deferred_executor",
    "goals",
    "hooks",
    "image_generation",
    "multi_agent",
    "multi_agent_v2",
    "plugins",
    "recommended_plugins",
    "remote_plugin",
    "request_permissions_tool",
    "rollout_budget",
    "skill_search",
    "sleep_tool",
    "token_budget",
    "tool_suggest",
    "unbounded_connection_retries",
    "view_image",
)
PROOF_FIELDS = frozenset(
    {
        "proof_type",
        "version",
        "source",
        "codex_binary",
        "codex_binary_sha256",
        "codex_version",
        "codex_home",
        "user_config_sha256",
        "model_catalog_sha256",
        "model_entry_sha256",
        "requested_model",
        "requested_tools",
        "observed_model",
        "observed_tools",
        "tool_transport",
        "observed_tool_definitions_sha256",
        "lockdown_config",
        "lockdown_config_sha256",
        "captured_request_sha256",
        "verified",
        "proof_sha256",
    }
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class CodexToolSurfaceError(ValueError):
    """Raised when the effective connected-Codex tool surface is not exact."""


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def file_sha256(path: Path | str) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _same_json(value: Any, expected: Any) -> bool:
    """Compare closed JSON shapes without Python's bool/int/float coercion."""

    if type(value) is not type(expected):
        return False
    if type(expected) is dict:
        return (all(type(key) is str for key in value)
                and value.keys() == expected.keys()
                and all(_same_json(value[key], item) for key, item in expected.items()))
    if type(expected) is list:
        return len(value) == len(expected) and all(
            _same_json(item, other) for item, other in zip(value, expected)
        )
    return type(expected) in (str, bool, int, float, type(None)) and value == expected


def _codex_binary() -> Path:
    located = shutil.which("codex")
    if not located:
        raise CodexToolSurfaceError("codex-binary-unavailable")
    return Path(located).resolve()


def _codex_version(binary: Path) -> str:
    completed = subprocess.run(
        [str(binary), "--version"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    if completed.returncode != 0:
        raise CodexToolSurfaceError("codex-version-unavailable")
    match = re.fullmatch(r"codex-cli\s+([^\s]+)\s*", completed.stdout)
    if match is None:
        raise CodexToolSurfaceError("codex-version-invalid")
    return match.group(1)


def _load_user_config(codex_home: Path) -> tuple[dict[str, Any], str]:
    path = codex_home / "config.toml"
    if not path.is_file():
        return {}, hashlib.sha256(b"").hexdigest()
    try:
        raw = path.read_bytes()
        decoded = tomllib.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise CodexToolSurfaceError("codex-user-config-invalid") from exc
    if type(decoded) is not dict:
        raise CodexToolSurfaceError("codex-user-config-invalid")
    return decoded, hashlib.sha256(raw).hexdigest()


def _catalog_snapshot(codex_home: Path, requested_model: str) -> dict[str, Any]:
    """Read once successfully; projection and fingerprints share this snapshot."""

    if not isinstance(requested_model, str) or not requested_model.strip():
        raise CodexToolSurfaceError("requested-model-catalog-entry-invalid")
    path = (codex_home / "models_cache.json").resolve()
    last_error: BaseException | None = None
    for attempt in range(3):
        try:
            raw = path.read_bytes()
            decoded = json.loads(raw, parse_constant=lambda token: (_ for _ in ()).throw(ValueError(token)))
            break
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            last_error = exc
            if attempt < 2:
                time.sleep(0.05)
    else:
        raise CodexToolSurfaceError("codex-model-catalog-invalid") from last_error
    selected = _selected_model(decoded, requested_model)
    if (selected.get("shell_type") != "unified_exec"
            or selected.get("apply_patch_tool_type") != "freeform"
            or selected.get("experimental_supported_tools") != []):
        raise CodexToolSurfaceError("requested-model-tool-metadata-invalid")
    return {"path": str(path), "value": decoded, "selected": selected,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "entry_sha256": canonical_sha256(selected)}


def _selected_model(value: Any, requested_model: str) -> dict[str, Any]:
    models = value.get("models") if type(value) is dict else None
    if (type(models) is not list or any(type(m) is not dict for m in models)
            or any(not isinstance(m.get("slug"), str) for m in models)):
        raise CodexToolSurfaceError("requested-model-catalog-entry-invalid")
    selected = [m for m in models if m["slug"] == requested_model]
    if len(selected) != 1:
        raise CodexToolSurfaceError("requested-model-catalog-entry-invalid")
    return selected[0]


def _model_catalog(codex_home: Path, requested_model: str) -> tuple[Path, str, str]:
    snapshot = _catalog_snapshot(codex_home, requested_model)
    return Path(snapshot["path"]), snapshot["sha256"], snapshot["entry_sha256"]


def normalized_tools(value: Any) -> list[str]:
    """Reject malformed and unsupported exact profiles before sorting/hashing."""

    if (
        not isinstance(value, (list, tuple))
        or not value
        or any(not isinstance(tool, str) for tool in value)
    ):
        raise CodexToolSurfaceError("codex-tool-surface-permitted-tools-invalid")
    names = sorted(value)
    if tuple(names) not in TOOL_PROFILES:
        raise CodexToolSurfaceError("codex-tool-surface-permitted-tools-unsupported")
    return names


def tool_profile_is_mutable(profile: str) -> bool:
    if type(profile) is not str or profile not in TOOL_PROFILES.values():
        raise CodexToolSurfaceError("codex-tool-surface-profile-invalid")
    return profile in {"mutating-v1", "mutating-core-resources-v2"}


def tools_are_mutable(permitted_tools: Any) -> bool:
    return tool_profile_is_mutable(TOOL_PROFILES[tuple(normalized_tools(permitted_tools))])


def _effect_policy(permitted_tools: Any) -> dict[str, Any]:
    return {"sandbox": "workspaceWrite" if tools_are_mutable(permitted_tools) else "readOnly",
            "network_access": False, "approval_policy": "never", "dynamic_tools": [],
            "mcp_endpoints": "none"}


def require_zero_endpoint_inventory(value: Any, *, thread_id: str, pid: int,
                                    connection_epoch_sha256: str | None = None) -> dict[str, Any]:
    """Validate a complete recorded observation, not an authority assertion."""
    fields = {"source", "version", "thread_id", "pid", "connection_epoch_sha256", "pages", "notification_generation"}
    if (type(value) is not dict or set(value) != fields
            or value.get("source") != "app-server-thread-mcp-inventory-v1"
            or type(value.get("version")) is not int or value["version"] != 1
            or type(value.get("thread_id")) is not str or value["thread_id"] != thread_id
            or type(value.get("pid")) is not int or value["pid"] != pid or pid <= 0
            or type(value.get("connection_epoch_sha256")) is not str
            or _SHA256.fullmatch(value["connection_epoch_sha256"]) is None
            or (connection_epoch_sha256 is not None and value["connection_epoch_sha256"] != connection_epoch_sha256)
            or type(value.get("notification_generation")) is not int or value["notification_generation"] != 0
            or type(value.get("pages")) is not list or not 1 <= len(value["pages"]) <= 100):
        raise CodexToolSurfaceError("codex-zero-endpoint-inventory-invalid")
    cursor, seen = None, set()
    for index, page in enumerate(value["pages"]):
        request = {"threadId": thread_id, "detail": "full", "limit": 100, "cursor": cursor}
        if (type(page) is not dict or set(page) != {"request", "response"}
                or not _same_json(page["request"], request)
                or type(page["response"]) is not dict
                or set(page["response"]) not in ({"data"}, {"data", "nextCursor"})
                or page["response"]["data"] != []):
            raise CodexToolSurfaceError("codex-zero-endpoint-inventory-not-empty")
        cursor = page["response"].get("nextCursor")
        if cursor is None:
            if index != len(value["pages"]) - 1:
                raise CodexToolSurfaceError("codex-zero-endpoint-inventory-trailing-pages")
        elif type(cursor) is not str or not cursor or cursor in seen:
            raise CodexToolSurfaceError("codex-zero-endpoint-inventory-cursor-invalid")
        else:
            seen.add(cursor)
    if cursor is not None:
        raise CodexToolSurfaceError("codex-zero-endpoint-inventory-incomplete")
    return deepcopy(value)


def _catalog_projection(
    home: Path, requested_model: str, path: Path | str,
    *, snapshot: Mapping[str, Any] | None = None,
) -> tuple[Path, str]:
    """Validate a private startup projection against one validated snapshot."""

    try:
        candidate = Path(path).absolute()
        metadata = candidate.lstat()
        if (candidate.is_symlink() or candidate.resolve() != candidate
                or not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or candidate == (home / "models_cache.json").resolve()):
            raise CodexToolSurfaceError("codex-read-only-catalog-path-invalid")
        original = snapshot if snapshot is not None else _catalog_snapshot(home, requested_model)
        raw = candidate.read_bytes()
        projected = json.loads(raw)
        selected = _selected_model(projected, requested_model)
        expected = deepcopy(original["selected"])
        expected["apply_patch_tool_type"] = None
        if selected != expected:
            raise ValueError("selected metadata")
    except CodexToolSurfaceError:
        raise
    except (OSError, ValueError, KeyError, TypeError, UnicodeError) as exc:
        raise CodexToolSurfaceError("codex-read-only-catalog-projection-invalid") from exc
    return candidate, hashlib.sha256(raw).hexdigest()


def prepare_read_only_catalog(
    codex_home: Path | str, *, requested_model: str, output: Path | str,
) -> Path:
    """Create exclusively from one snapshot; never re-read or edit the cache."""

    home = Path(codex_home).resolve()
    snapshot = _catalog_snapshot(home, requested_model)
    value = deepcopy(snapshot["value"])
    _selected_model(value, requested_model)["apply_patch_tool_type"] = None
    target = Path(output).absolute()
    if target.resolve() != target or target == (home / "models_cache.json").resolve():
        raise CodexToolSurfaceError("codex-read-only-catalog-path-invalid")
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(value, handle, sort_keys=True, indent=2, allow_nan=False)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    _catalog_projection(home, requested_model, target, snapshot=snapshot)
    return target


def read_only_startup_config(
    codex_home: Path | str, *, requested_model: str, catalog_projection: Path | str,
) -> dict[str, str]:
    home = Path(codex_home).resolve()
    path, _digest = _catalog_projection(home, requested_model, catalog_projection)
    return {"model_catalog_json": str(path)}


def tool_transport_instructions(permitted_tools: Any, transport: str) -> str:
    """Render only the already validated thread/packet tool policy, never a default trio."""

    if not isinstance(transport, str) or transport not in TOOL_TRANSPORTS:
        raise CodexToolSurfaceError("codex-tool-surface-transport-invalid")
    if permitted_tools is not None and (
        not isinstance(permitted_tools, list) or not permitted_tools
        or any(not isinstance(t, str) or re.fullmatch(r"[a-z][a-z0-9_.:-]{0,127}", t) is None for t in permitted_tools)
        or permitted_tools != sorted(set(permitted_tools))
    ):
        raise CodexToolSurfaceError("codex-tool-surface-permitted-tools-invalid")
    allowed = (", ".join(permitted_tools) if permitted_tools is not None
               else "tools explicitly authorized by the packet allowlist")
    if transport == DIRECT_TOOL_TRANSPORT:
        return (" Use only " + allowed + ". The controller-supplied thread cwd is authoritative. "
                "Omit the workdir argument from direct exec_command calls; do not override the controller cwd.")
    return (" This model uses the functions.exec transport. Every exec wrapper must call "
            "exactly one nested tool and must have exactly this structure, with a valid JSON "
            "argument and no comments or extra statements: const result = await "
            "tools.TOOL(JSON_ARGUMENT); text(JSON.stringify(result));. Use only " + allowed +
            " as TOOL. Every exec_command JSON argument must include the exact current workdir.")


def build_lockdown_config(
    codex_home: Path | str,
    *,
    requested_model: str,
    permitted_tools: Any = EXACT_OPERATIVE_TOOLS,
    catalog_projection: Path | str | None = None,
) -> dict[str, Any]:
    """Build the exact per-thread config whose live request must be probed."""

    home = Path(codex_home).resolve()
    config, _config_sha256 = _load_user_config(home)
    snapshot = _catalog_snapshot(home, requested_model)
    return _lockdown_from_snapshot(home, requested_model, permitted_tools,
                                   catalog_projection, config, snapshot)


def _lockdown_from_snapshot(home, requested_model, permitted_tools,
                            catalog_projection, config, snapshot):
    catalog = Path(snapshot["path"])
    tools = normalized_tools(permitted_tools)
    if not tools_are_mutable(tools):
        if catalog_projection is None:
            raise CodexToolSurfaceError("codex-read-only-catalog-required")
        catalog, _digest = _catalog_projection(home, requested_model, catalog_projection, snapshot=snapshot)
    elif catalog_projection is not None:
        raise CodexToolSurfaceError("codex-mutating-catalog-override-forbidden")
    raw_servers = config.get("mcp_servers", {})
    if not isinstance(raw_servers, Mapping):
        raise CodexToolSurfaceError("codex-mcp-server-config-invalid")
    mcp_servers: dict[str, dict[str, bool]] = {}
    for name in sorted(raw_servers):
        if not isinstance(name, str) or not name.strip():
            raise CodexToolSurfaceError("codex-mcp-server-name-invalid")
        mcp_servers[name] = {"enabled": False}
    return {
        "model_catalog_json": str(catalog),
        "web_search": "disabled",
        "tools": {
            "experimental_request_user_input": {"enabled": False},
            "update_plan": {"enabled": False},
        },
        "agents": {"enabled": False},
        "features": {name: False for name in DISABLED_FEATURES},
        "mcp_servers": mcp_servers,
    }


def probe_thread_config(
    codex_home: Path | str,
    *,
    requested_model: str,
    provider_name: str,
    base_url: str,
    permitted_tools: Any = EXACT_OPERATIVE_TOOLS,
    catalog_projection: Path | str | None = None,
) -> dict[str, Any]:
    """Return a lockdown config extended only with a loopback probe provider."""

    if re.fullmatch(r"[a-z][a-z0-9-]{0,63}", provider_name) is None:
        raise CodexToolSurfaceError("probe-provider-name-invalid")
    if re.fullmatch(r"http://127\.0\.0\.1:[1-9][0-9]{0,4}/v1", base_url) is None:
        raise CodexToolSurfaceError("probe-provider-url-invalid")
    value = build_lockdown_config(
        codex_home,
        requested_model=requested_model,
        permitted_tools=permitted_tools,
        catalog_projection=catalog_projection,
    )
    value.update(
        {
            "model_provider": provider_name,
            "model_providers": {
                provider_name: {
                    "name": "CWO loopback tool-surface probe",
                    "base_url": base_url,
                    "experimental_bearer_token": "cwo-loopback-probe",
                    "wire_api": "responses",
                    "requires_openai_auth": False,
                    "request_max_retries": 0,
                    "stream_max_retries": 0,
                }
            },
        }
    )
    return value


def _tool_name(tool: Any) -> str | None:
    if not isinstance(tool, Mapping):
        return None
    name = tool.get("name")
    if isinstance(name, str):
        return name
    function = tool.get("function")
    if isinstance(function, Mapping) and isinstance(function.get("name"), str):
        return str(function["name"])
    return None


def _captured_tool_definitions(
    captured_request: Mapping[str, Any],
) -> tuple[list[str], list[Any], str]:
    """Project direct and namespaced Codex wire surfaces to operative tools."""

    direct = captured_request.get("tools")
    inputs = captured_request.get("input")
    additions = (
        [
            item
            for item in inputs
            if isinstance(item, Mapping)
            and item.get("type") == "additional_tools"
        ]
        if isinstance(inputs, list)
        else []
    )
    if isinstance(direct, list):
        if additions:
            raise CodexToolSurfaceError("captured-request-tool-surface-ambiguous")
        names = [_tool_name(tool) for tool in direct]
        if any(name is None for name in names):
            raise CodexToolSurfaceError("captured-request-tool-name-invalid")
        return [str(name) for name in names], list(direct), DIRECT_TOOL_TRANSPORT
    if direct is not None or len(additions) != 1:
        raise CodexToolSurfaceError("captured-request-tools-invalid")

    namespaces = additions[0].get("tools")
    if not isinstance(namespaces, list) or len(namespaces) != 1:
        raise CodexToolSurfaceError("captured-request-tool-namespace-invalid")
    namespace = namespaces[0]
    if (
        not isinstance(namespace, Mapping)
        or namespace.get("type") != "namespace"
        or namespace.get("name") != "functions"
    ):
        raise CodexToolSurfaceError("captured-request-tool-namespace-invalid")
    wrappers = namespace.get("tools")
    if not isinstance(wrappers, list):
        raise CodexToolSurfaceError("captured-request-tool-wrapper-invalid")
    wrapper_by_name = {
        _tool_name(wrapper): wrapper
        for wrapper in wrappers
        if isinstance(wrapper, Mapping)
    }
    if set(wrapper_by_name) != {"exec", "wait"} or len(wrappers) != 2:
        raise CodexToolSurfaceError("captured-request-tool-wrapper-mismatch")
    executor = wrapper_by_name["exec"]
    waiter = wrapper_by_name["wait"]
    if executor.get("type") != "custom" or waiter.get("type") != "function":
        raise CodexToolSurfaceError("captured-request-tool-wrapper-invalid")
    description = executor.get("description")
    if not isinstance(description, str):
        raise CodexToolSurfaceError("captured-request-exec-description-invalid")
    declared = re.findall(r"^### `([^`]+)`\s*$", description, flags=re.MULTILINE)
    if not declared or len(declared) != len(set(declared)):
        raise CodexToolSurfaceError("captured-request-tool-surface-mismatch")
    return list(declared), list(namespaces), NAMESPACED_EXEC_TOOL_TRANSPORT


CAPTURE_PROOF_FIELDS = frozenset({"capture_binding", "process_binding"})
# Whole cache bytes and unrelated preferences are provenance, not permanent gates.
_CAPTURE_CAUSAL_FIELDS = (
    "codex_binary", "codex_binary_sha256", "codex_version", "codex_home",
    "requested_model", "requested_tools", "model_entry_sha256",
    "lockdown_config", "lockdown_config_sha256", "startup_config",
    "catalog_projection_sha256", "tool_profile", "effect_policy",
)


def prepare_capture_binding(
    codex_home: Path | str, *, requested_model: str,
    permitted_tools: Any = EXACT_OPERATIVE_TOOLS,
    catalog_projection: Path | str | None = None,
) -> dict[str, Any]:
    """Freeze causal host inputs BEFORE the process and capture exist."""

    home = Path(codex_home).resolve()
    tools = normalized_tools(permitted_tools)
    binary = _codex_binary()
    config, config_sha = _load_user_config(home)
    snapshot = _catalog_snapshot(home, requested_model)
    lockdown = _lockdown_from_snapshot(home, requested_model, tools,
                                       catalog_projection, config, snapshot)
    startup = {}
    projection_sha = None
    if catalog_projection is not None:
        path, projection_sha = _catalog_projection(home, requested_model, catalog_projection,
                                                   snapshot=snapshot)
        startup = {"model_catalog_json": str(path)}
    value = {"codex_binary": str(binary), "codex_binary_sha256": file_sha256(binary),
             "codex_version": _codex_version(binary), "codex_home": str(home),
             "requested_model": requested_model, "requested_tools": tools,
             "user_config_sha256": config_sha, "model_catalog_sha256": snapshot["sha256"],
             "model_entry_sha256": snapshot["entry_sha256"],
             "lockdown_config": lockdown, "lockdown_config_sha256": canonical_sha256(lockdown),
             "startup_config": startup, "catalog_projection_sha256": projection_sha,
             "tool_profile": TOOL_PROFILES[tuple(tools)], "effect_policy": _effect_policy(tools)}
    value["binding_sha256"] = canonical_sha256(value)
    return value


def require_capture_binding(value: Any, *, historical: bool = False) -> dict[str, Any]:
    """Validate shape, seal and causal drift without re-stamping old observations."""

    try:
        if type(value) is not dict:
            raise ValueError("object required")
        body = dict(value)
        digest = body.pop("binding_sha256")
        if canonical_sha256(body) != digest:
            raise ValueError("seal")
        if (type(value["lockdown_config"]) is not dict
                or canonical_sha256(value["lockdown_config"]) != value["lockdown_config_sha256"]):
            raise ValueError("lockdown payload hash")
        startup = value["startup_config"]
        if type(startup) is not dict or set(startup) - {"model_catalog_json"}:
            raise ValueError("startup")
        current = prepare_capture_binding(value["codex_home"], requested_model=value["requested_model"],
            permitted_tools=value["requested_tools"], catalog_projection=startup.get("model_catalog_json"))
        if historical:
            current.pop("tool_profile", None)
            current.pop("effect_policy", None)
        if set(current) != set(value):
            raise ValueError("fields")
        for field in _CAPTURE_CAUSAL_FIELDS:
            if historical and field in {"tool_profile", "effect_policy"}:
                continue
            if not _same_json(value[field], current[field]):
                raise CodexToolSurfaceError("codex-capture-binding-drift:" + field)
        for field in ("user_config_sha256", "model_catalog_sha256"):
            if not isinstance(value[field], str) or _SHA256.fullmatch(value[field]) is None:
                raise ValueError(field)
    except CodexToolSurfaceError:
        raise
    except (KeyError, TypeError, ValueError, OSError, subprocess.SubprocessError) as exc:
        raise CodexToolSurfaceError("codex-capture-binding-invalid") from exc
    return deepcopy(value)


def bind_capture_process(binding: Mapping[str, Any], captured: Mapping[str, Any], *,
                         executable: str, codex_home: str, pid: int,
                         thread_id: str, effective_thread: Mapping[str, Any],
                         endpoint_inventory: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Controller-owned capture association, never supplied by a model."""

    value = {"capture_binding_sha256": binding["binding_sha256"],
             "captured_request_sha256": canonical_sha256(captured),
             "executable": executable, "codex_home": codex_home, "pid": pid,
             "thread_id": thread_id, "effective_thread": deepcopy(dict(effective_thread)),
             "endpoint_inventory": deepcopy(endpoint_inventory)}
    _require_process_binding(value, binding, canonical_sha256(captured))
    return value


def _require_process_binding(value, binding, request_sha, *, version=PROOF_VERSION):
    expected_fields = {"capture_binding_sha256", "captured_request_sha256", "executable",
                       "codex_home", "pid", "thread_id", "effective_thread"}
    if version >= 5:
        expected_fields.add("endpoint_inventory")
    if (type(value) is not dict or set(value) != expected_fields
            or value.get("capture_binding_sha256") != binding["binding_sha256"]
            or value.get("captured_request_sha256") != request_sha
            or value.get("executable") != binding["codex_binary"]
            or value.get("codex_home") != binding["codex_home"]
            or type(value.get("pid")) is not int or value["pid"] <= 0
            or not isinstance(value.get("thread_id"), str) or not value["thread_id"].strip()):
        raise CodexToolSurfaceError("codex-capture-process-binding-invalid")
    expected = {"model": binding["requested_model"], "modelProvider": "cwo-loopback-probe",
                "approvalPolicy": "never", "networkAccess": False,
                "sandbox": "workspaceWrite" if tools_are_mutable(binding["requested_tools"]) else "readOnly",
                "allowProviderModelFallback": False, "dynamicTools": [],
                "lockdown_config_sha256": binding["lockdown_config_sha256"]}
    if not _same_json(value["effective_thread"], expected):
        raise CodexToolSurfaceError("codex-capture-thread-binding-invalid")
    if version >= 5:
        observations = value["endpoint_inventory"]
        if type(observations) is not dict or set(observations) != {"before", "after"}:
            raise CodexToolSurfaceError("codex-capture-endpoint-observations-required")
        before = require_zero_endpoint_inventory(observations["before"], thread_id=value["thread_id"], pid=value["pid"])
        require_zero_endpoint_inventory(observations["after"], thread_id=value["thread_id"], pid=value["pid"],
            connection_epoch_sha256=before["connection_epoch_sha256"])


def build_surface_proof(
    captured_request: Mapping[str, Any],
    *,
    codex_home: Path | str,
    requested_model: str,
    permitted_tools: Any = EXACT_OPERATIVE_TOOLS,
    catalog_projection: Path | str | None = None,
    capture_binding: Mapping[str, Any] | None = None,
    process_binding: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Seal one exact loopback-captured Responses request as host evidence."""

    if not isinstance(captured_request, Mapping):
        raise CodexToolSurfaceError("captured-request-invalid")
    observed_names, tool_definitions, tool_transport = _captured_tool_definitions(
        captured_request
    )
    observed_tools = sorted(observed_names)
    requested_tools = normalized_tools(permitted_tools)
    if captured_request.get("model") != requested_model:
        raise CodexToolSurfaceError("captured-request-model-mismatch")
    if observed_tools != requested_tools or len(observed_tools) != len(set(observed_tools)):
        raise CodexToolSurfaceError("captured-request-tool-surface-mismatch")

    binding = require_capture_binding(capture_binding)
    if (binding["codex_home"] != str(Path(codex_home).resolve())
            or binding["requested_model"] != requested_model
            or binding["requested_tools"] != requested_tools
            or binding["startup_config"].get("model_catalog_json") != (str(Path(catalog_projection).absolute()) if catalog_projection is not None else None)):
        raise CodexToolSurfaceError("codex-capture-request-binding-mismatch")
    _require_process_binding(process_binding, binding, canonical_sha256(captured_request))
    value = {
        "proof_type": PROOF_TYPE,
        "version": PROOF_VERSION,
        "tool_profile": TOOL_PROFILES[tuple(requested_tools)],
        "effect_policy": binding["effect_policy"],
        "capture_binding": deepcopy(binding),
        "process_binding": deepcopy(process_binding),
        "startup_config": binding["startup_config"],
        "catalog_projection_sha256": binding["catalog_projection_sha256"],
        "source": "loopback-app-server-responses-request",
        **{k: binding[k] for k in ("codex_binary", "codex_binary_sha256", "codex_version",
            "codex_home", "user_config_sha256", "model_catalog_sha256", "model_entry_sha256")},
        "requested_model": requested_model,
        "requested_tools": requested_tools,
        "observed_model": captured_request.get("model"),
        "observed_tools": observed_tools,
        "tool_transport": tool_transport,
        "observed_tool_definitions_sha256": canonical_sha256(tool_definitions),
        "lockdown_config": binding["lockdown_config"],
        "lockdown_config_sha256": binding["lockdown_config_sha256"],
        "captured_request_sha256": canonical_sha256(captured_request),
        "verified": True,
    }
    value["proof_sha256"] = canonical_sha256(value)
    return value


def validate_surface_proof(
    value: Any,
    *,
    requested_model: str,
    permitted_tools: list[str] | tuple[str, ...],
) -> list[str]:
    """Validate the proof and every cheap current-host drift boundary."""

    errors: list[str] = []
    if not isinstance(value, Mapping):
        return ["codex-tool-surface-proof-must-be-object"]
    if any(not isinstance(key, str) for key in value):
        return ["codex-tool-surface-proof-fields-invalid"]
    version = value.get("version")
    if type(version) is not int or version not in (2, 3, 4, PROOF_VERSION):
        return ["codex-tool-surface-proof-identity-invalid"]
    fields = PROOF_FIELDS | (PROFILE_PROOF_FIELDS if version >= 3 else frozenset()) | (CAPTURE_PROOF_FIELDS if version >= 4 else frozenset()) | (CURRENT_EFFECT_FIELDS if version >= 5 else frozenset())
    missing, unknown = sorted(fields - set(value)), sorted(set(value) - fields)
    if missing:
        errors.append("codex-tool-surface-proof-missing:" + ",".join(missing))
    if unknown:
        errors.append("codex-tool-surface-proof-unknown:" + ",".join(unknown))
    try:
        expected_tools = normalized_tools(permitted_tools)
    except CodexToolSurfaceError as exc:
        errors.append(str(exc))
        expected_tools = []
    if value.get("proof_type") != PROOF_TYPE:
        errors.append("codex-tool-surface-proof-identity-invalid")
    if version < 5 and tuple(expected_tools) in CORE_RESOURCE_TOOL_PROFILES.values():
        errors.append("codex-tool-surface-legacy-core-profile-forbidden")
    if version >= 5 and (not expected_tools or not _same_json(value.get("effect_policy"), _effect_policy(expected_tools))):
        errors.append("codex-tool-surface-effect-policy-invalid")
    if version == 2 and expected_tools != list(EXACT_OPERATIVE_TOOLS):
        errors.append("codex-tool-surface-legacy-profile-mismatch")
    if version >= 3 and value.get("tool_profile") != TOOL_PROFILES.get(tuple(expected_tools)):
        errors.append("codex-tool-surface-profile-mismatch")
    if value.get("source") != "loopback-app-server-responses-request":
        errors.append("codex-tool-surface-proof-source-invalid")
    if value.get("verified") is not True:
        errors.append("codex-tool-surface-proof-not-verified")
    for field in ("codex_binary", "codex_home", "codex_version", "requested_model", "observed_model"):
        if not isinstance(value.get(field), str) or not value[field].strip():
            errors.append(f"codex-tool-surface-{field}-invalid")
    for field in (
        "codex_binary_sha256", "user_config_sha256", "model_catalog_sha256",
        "model_entry_sha256", "observed_tool_definitions_sha256",
        "lockdown_config_sha256", "captured_request_sha256", "proof_sha256",
    ):
        if not isinstance(value.get(field), str) or _SHA256.fullmatch(value[field]) is None:
            errors.append(f"codex-tool-surface-{field}-invalid")
    if not isinstance(requested_model, str) or not requested_model.strip() or value.get("requested_model") != requested_model or value.get("observed_model") != requested_model:
        errors.append("codex-tool-surface-model-mismatch")
    if value.get("requested_tools") != expected_tools or value.get("observed_tools") != expected_tools:
        errors.append("codex-tool-surface-tools-mismatch")
    if not isinstance(value.get("tool_transport"), str) or value["tool_transport"] not in TOOL_TRANSPORTS:
        errors.append("codex-tool-surface-transport-invalid")
    if not isinstance(value.get("lockdown_config"), dict):
        errors.append("codex-tool-surface-lockdown-config-invalid")
    projection = None
    if version >= 3:
        startup = value.get("startup_config")
        if expected_tools and not tools_are_mutable(expected_tools):
            if not isinstance(startup, dict) or set(startup) != {"model_catalog_json"} or not isinstance(startup.get("model_catalog_json"), str):
                errors.append("codex-tool-surface-startup-config-invalid")
            else:
                projection = startup["model_catalog_json"]
            digest = value.get("catalog_projection_sha256")
            if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
                errors.append("codex-tool-surface-catalog-projection-hash-invalid")
        elif startup != {} or value.get("catalog_projection_sha256") is not None:
            errors.append("codex-tool-surface-startup-config-invalid")
    try:
        body = dict(value)
        digest = body.pop("proof_sha256", None)
        if canonical_sha256(body) != digest:
            errors.append("codex-tool-surface-proof-hash-mismatch")
        if canonical_sha256(value.get("lockdown_config")) != value.get("lockdown_config_sha256"):
            errors.append("codex-tool-surface-lockdown-payload-hash-mismatch")
    except (ValueError, TypeError):
        errors.append("codex-tool-surface-proof-json-invalid")
    if errors:
        return sorted(set(errors))
    if version >= 4:
        try:
            binding = require_capture_binding(value.get("capture_binding"), historical=version == 4)
            _require_process_binding(value.get("process_binding"), binding, value["captured_request_sha256"], version=version)
            for field in (*_CAPTURE_CAUSAL_FIELDS, "user_config_sha256", "model_catalog_sha256"):
                if version == 4 and field in {"tool_profile", "effect_policy"}:
                    continue
                if not _same_json(value.get(field), binding[field]):
                    raise CodexToolSurfaceError("codex-tool-surface-capture-binding-mismatch:" + field)
        except (CodexToolSurfaceError, OSError, ValueError, TypeError) as exc:
            errors.append(str(exc))
    try:
        binary = _codex_binary()
        home = Path(value["codex_home"]).resolve()
        _catalog, _catalog_sha256, entry_sha256 = _model_catalog(home, requested_model)
        lockdown = build_lockdown_config(home, requested_model=requested_model,
                                         permitted_tools=expected_tools, catalog_projection=projection)
        if projection is not None:
            _path, projection_sha256 = _catalog_projection(home, requested_model, projection)
            if projection_sha256 != value["catalog_projection_sha256"]:
                errors.append("codex-tool-surface-catalog-projection-drift")
        if str(binary) != value["codex_binary"]:
            errors.append("codex-tool-surface-binary-path-drift")
        if file_sha256(binary) != value["codex_binary_sha256"]:
            errors.append("codex-tool-surface-binary-drift")
        if _codex_version(binary) != value["codex_version"]:
            errors.append("codex-tool-surface-version-drift")
        # Authoring preferences and derived-cache timestamps are provenance;
        # selected model metadata and the enforced projection are live gates.
        if entry_sha256 != value["model_entry_sha256"]:
            errors.append("codex-tool-surface-model-entry-drift")
        if not _same_json(value["lockdown_config"], lockdown):
            errors.append("codex-tool-surface-lockdown-config-drift")
        if canonical_sha256(lockdown) != value["lockdown_config_sha256"]:
            errors.append("codex-tool-surface-lockdown-hash-drift")
    except (CodexToolSurfaceError, OSError, ValueError, subprocess.SubprocessError) as exc:
        errors.append(str(exc))
    return sorted(set(errors))


def require_surface_proof(
    value: Any,
    *,
    requested_model: str,
    permitted_tools: list[str] | tuple[str, ...],
) -> dict[str, Any]:
    errors = validate_surface_proof(
        value,
        requested_model=requested_model,
        permitted_tools=permitted_tools,
    )
    if errors:
        raise CodexToolSurfaceError(";".join(errors))
    if value.get("version") != PROOF_VERSION:
        raise CodexToolSurfaceError("codex-tool-surface-historical-proof-not-dispatch-authority")
    return deepcopy(dict(value))


def thread_start_enforcement_params(
    value: Any,
    *,
    requested_model: str,
    permitted_tools: list[str] | tuple[str, ...],
) -> dict[str, Any]:
    """Return exact app-server inputs bound to a current valid proof."""

    proof = require_surface_proof(
        value,
        requested_model=requested_model,
        permitted_tools=permitted_tools,
    )
    return {
        ALLOWLIST_PARAMETER: deepcopy(proof["lockdown_config"]),
        "dynamicTools": [],
    }
