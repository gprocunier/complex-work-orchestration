"""Check the Codex App Server wire shapes that CWO reads and writes."""

from __future__ import annotations

from collections.abc import Callable, Iterator, Sequence
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
from typing import Any


class CapabilityError(ValueError):
    """The selected executable could not demonstrate a required wire capability."""


_PROTOCOL = "codex_app_server_protocol.schemas.json"
_PROTOCOL_V2 = "codex_app_server_protocol.v2.schemas.json"
_SCHEMA_BYTES = 16 * 1024 * 1024
_SCHEMA_SECONDS = 15


# These representative outbound payloads cover fields and variants actually sent.
# Native containment supplies no sandbox, permissions or environment override to
# command/exec. The config object is open by design in the upstream wire schema.
_INITIALIZE = {"clientInfo": {"name": "cwo", "version": "1"}}
_THREAD = {"threadId": "thread"}
_TURN = {**_THREAD, "turnId": "turn"}
_THREAD_START_COMMON = {
    "model": "model", "allowProviderModelFallback": False,
    "cwd": "/workspace", "runtimeWorkspaceRoots": ["/workspace"],
}
_THREAD_START = {
    **_THREAD_START_COMMON,
    "approvalPolicy": "never", "sandbox": "read-only", "ephemeral": False,
    "historyMode": "legacy", "developerInstructions": "task",
}
_TURN_START = {
    **_THREAD, "input": [{"type": "text", "text": "task", "text_elements": []}],
    "model": "model", "effort": "low",
}
_COMMAND = {
    "command": ["program"], "cwd": "/workspace", "timeoutMs": 3000, "outputBytesCap": 32768,
}
_DIAGNOSTIC_REQUESTS = {
    "initialize": (_INITIALIZE,),
    "config/read": ({"cwd": "/workspace", "includeLayers": True},),
    "configRequirements/read": (None,),
    "command/exec": (_COMMAND, {
        **_COMMAND, "timeoutMs": 25000, "processId": "process", "streamStdin": False,
        "streamStdoutStderr": True,
    }),
}
_REQUESTS = {
    **_DIAGNOSTIC_REQUESTS,
    "initialize": (_INITIALIZE, {
        "clientInfo": {**_INITIALIZE["clientInfo"], "title": "CWO"},
        "capabilities": {"experimentalApi": True},
    }),
    "model/list": ({"includeHidden": True},),
    "thread/start": (
        _THREAD_START,
        {**_THREAD_START, "modelProvider": "provider", "sandbox": "workspace-write",
         "ephemeral": True, "dynamicTools": [], "config": {"model_provider": "provider"}},
        {**_THREAD_START_COMMON,
            "permissions": "profile", "approvalPolicy": "untrusted", "approvalsReviewer": "user",
            "ephemeral": True, "dynamicTools": [{"type": "function", "name": "tool",
                                                 "description": "tool", "inputSchema": {}}],
        },
    ),
    "thread/read": ({**_THREAD, "includeTurns": True},),
    "thread/archive": (_THREAD,),
    "thread/delete": (_THREAD,),
    "turn/start": (_TURN_START, *(
        {**_TURN_START, "effort": effort, "clientUserMessageId": "request",
         "responsesapiClientMetadata": {"cwo_bead": "bead", "cwo_control_turn": "turn", "cwo_mission": "mission"}}
        for effort in ("low", "medium", "high", "xhigh", "max", "ultra")
    )),
    "turn/interrupt": (_TURN,),
    "mcpServerStatus/list": tuple(
        {**_THREAD, "detail": "full", "limit": 100, "cursor": cursor} for cursor in (None, "cursor")
    ),
}

# Paths follow the declared schema. `[]` is an array item, and `@type=value`
# selects a tagged union branch before testing its fields. A tuple requires the
# listed wire enum values, a string is a JSON type, and None requires presence.
_TURN_FIELDS = {
    "id": "string", "status": ("inProgress", "completed", "failed", "interrupted"), "items": "array",
}
_THREAD_FIELDS = {"id": "string", "turns": "array", **{
    f"turns.[].{path}": shape for path, shape in _TURN_FIELDS.items()
}}
_ITEM_FIELDS = {
    "@type=commandExecution.id": "string",
    "@type=commandExecution.command": "string",
    "@type=commandExecution.cwd": "string",
    "@type=commandExecution.source": ("unifiedExecStartup",),
    "@type=commandExecution.status": ("inProgress", "completed", "failed", "declined"),
    "@type=dynamicToolCall.id": "string",
    "@type=dynamicToolCall.status": ("inProgress", "completed", "failed"),
    "@type=dynamicToolCall.namespace": "string",
    "@type=dynamicToolCall.tool": "string",
    "@type=dynamicToolCall.arguments": None,
}
_REPLIES = {
    "initialize": ("InitializeResponse", {"codexHome": "string"}),
    "model/list": ("ModelListResponse", {"data": "array", "data.[].id": "string",
                                        "data.[].model": "string", "data.[].displayName": "string"}),
    "thread/start": ("ThreadStartResponse", {
        **{f"thread.{path}": shape for path, shape in _THREAD_FIELDS.items()},
        "model": "string", "modelProvider": "string", "cwd": "string", "runtimeWorkspaceRoots.[]": "string",
        "approvalPolicy": ("never", "untrusted"), "approvalsReviewer": ("user",),
        "activePermissionProfile.id": "string", "activePermissionProfile.extends": "null",
        "sandbox.@type=readOnly.networkAccess": "boolean", "sandbox.@type=workspaceWrite.networkAccess": "boolean",
    }),
    "thread/read": ("ThreadReadResponse", {
        **{f"thread.{path}": shape for path, shape in _THREAD_FIELDS.items()},
        "thread.path": "string",
        **{f"thread.turns.[].items.[].{path}": shape for path, shape in _ITEM_FIELDS.items()},
        "thread.turns.[].items.[].@type=agentMessage.text": "string",
        "thread.turns.[].items.[].@type=agentMessage.phase": ("final_answer",),
        "thread.turns.[].items.[].type": (
            "fileChange", "mcpToolCall", "collabAgentToolCall", "webSearch", "imageView", "sleep",
            "imageGeneration", "contextCompaction",
        ),
    }),
    "thread/archive": ("ThreadArchiveResponse", {}),
    "thread/delete": ("ThreadDeleteResponse", {}),
    "turn/start": ("TurnStartResponse", {f"turn.{path}": shape for path, shape in _TURN_FIELDS.items()}),
    "turn/interrupt": ("TurnInterruptResponse", {}),
    "mcpServerStatus/list": ("ListMcpServerStatusResponse", {"data": "array", "nextCursor": "string"}),
    "config/read": ("ConfigReadResponse", {
        "config.approval_policy": ("never",), "config.sandbox_mode": ("workspace-write",),
        "config.sandbox_workspace_write.network_access": "boolean",
        "layers.[].name.type": ("user", "system"), "layers.[].config": None,
    }),
    "configRequirements/read": ("ConfigRequirementsReadResponse", {"requirements": "null"}),
    "command/exec": ("CommandExecResponse", {"exitCode": "integer", "stdout": "string", "stderr": "string"}),
}

_ITEM_NOTICE = {**{f"item.{path}": shape for path, shape in _ITEM_FIELDS.items()},
                "threadId": "string", "turnId": "string"}
_TURN_NOTICE = {"threadId": "string", **{f"turn.{path}": shape for path, shape in _TURN_FIELDS.items()}}
_DIAGNOSTIC_NOTIFICATIONS = {
    "command/exec/outputDelta": {"processId": "string", "deltaBase64": "string", "stream": ("stdout", "stderr")},
    "remoteControl/status/changed": {"status": ("disabled",)},
}
_NOTIFICATIONS = {
    **_DIAGNOSTIC_NOTIFICATIONS,
    "thread/started": {f"thread.{path}": shape for path, shape in _THREAD_FIELDS.items()},
    "thread/archived": {"threadId": "string"},
    "thread/closed": {"threadId": "string"},
    "thread/compacted": {"threadId": "string"},
    "turn/started": _TURN_NOTICE,
    "turn/completed": _TURN_NOTICE,
    "item/started": {**_ITEM_NOTICE, "startedAtMs": "integer"},
    "item/completed": _ITEM_NOTICE,
    "model/rerouted": {"threadId": "string"},
    "thread/tokenUsage/updated": {
        "threadId": "string", **{f"tokenUsage.total.{field}": "integer" for field in (
            "inputTokens", "cachedInputTokens", "outputTokens", "reasoningOutputTokens", "totalTokens",
        )},
    },
    "mcpServer/startupStatus/updated": {},
}

_CORRELATION = {"threadId": "string", "turnId": "string", "itemId": "string", "startedAtMs": "integer"}
_CALLBACKS = {
    "item/commandExecution/requestApproval": ({
        **_CORRELATION, "approvalId": "string", "kind": ("command", "writeStdin"),
        "cwd": "string", "command": "string", "availableDecisions.[]": ("accept", "decline"),
        "additionalPermissions": "object", "environmentId": "string", "networkApprovalContext": "object",
        "proposedExecpolicyAmendment": "array", "proposedNetworkPolicyAmendments": "array",
    }, "CommandExecutionRequestApprovalResponse", tuple({"decision": value} for value in ("accept", "decline", "cancel"))),
    "item/fileChange/requestApproval": (
        {**_CORRELATION, "reason": "string", "grantRoot": "string"},
        "FileChangeRequestApprovalResponse", ({"decision": "decline"}, {"decision": "cancel"}),
    ),
    "item/permissions/requestApproval": (
        {**_CORRELATION, "cwd": "string", "permissions": "object"},
        "PermissionsRequestApprovalResponse", ({"permissions": {}},),
    ),
    "item/tool/call": ({"threadId": "string", "turnId": "string", "callId": "string",
                        "tool": "string", "arguments": None, "namespace": "null"}, "DynamicToolCallResponse", ({
        "success": True, "contentItems": [{"type": "inputText", "text": "result"}],
    },)),
}


def _child(node: Any, key: str, default: Any = None) -> Any:
    return node.get(key, default) if isinstance(node, dict) else default


def _type_matches(node: dict, name: str) -> bool:
    declared = node.get("type")
    return declared == name or isinstance(declared, list) and name in declared


def _declares_value(node: dict, value: Any) -> bool:
    values = node.get("enum")
    return ("const" in node and node["const"] == value
            or isinstance(values, list) and value in values)


def _schema_object(data: bytes) -> dict:
    value = json.loads(data)
    if not isinstance(value, dict) or not isinstance(value.get("definitions"), dict):
        raise ValueError("schema definitions missing")
    return value


def _read_schema(directory_fd: int, filename: str) -> dict:
    try:
        fd = os.open(filename, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=directory_fd)
        with os.fdopen(fd, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError("schema is not a regular file")
            data = stream.read(_SCHEMA_BYTES + 1)
        if len(data) > _SCHEMA_BYTES:
            raise ValueError("schema exceeds the size limit")
        return _schema_object(data)
    except (OSError, ValueError, RecursionError) as error:
        raise CapabilityError(f"cannot read Codex App Server schema {filename}: {error}") from error


class _Schema:
    """Resolve the local definitions and unions emitted by the schema generator."""

    def __init__(self, document: dict):
        self.document = document

    def definition(self, name: str) -> Any:
        return self.document["definitions"].get(name)

    def _resolve(self, reference: str) -> Any:
        node = self.document
        for token in reference.removeprefix("#/").split("/"):
            node = _child(node, token.replace("~1", "/").replace("~0", "~"))
        return node

    def alternatives(self, node: Any, references: tuple = ()) -> Iterator[dict | bool]:
        if isinstance(node, bool):
            yield node
        if not isinstance(node, dict):
            return
        reference = node.get("$ref")
        if isinstance(reference, str) and reference.startswith("#/"):
            if reference not in references and len(references) < 32:
                yield from self.alternatives(self._resolve(reference), (*references, reference))
            return
        wrapper = node.get("allOf")
        if wrapper is not None:
            # The exporter uses a single referenced clause to add annotations.
            if isinstance(wrapper, list) and len(wrapper) == 1 and _child(wrapper[0], "$ref") is not None:
                yield from self.alternatives(wrapper[0], references)
            return
        options = node.get("oneOf", node.get("anyOf", ()))
        # A tagged branch may declare common fields beside a union, as in
        # imageGeneration's inline-data and attachment-store variants.
        if not options or "properties" in node or "type" in node:
            yield node
        for option in options:
            yield from self.alternatives(option, references)

    def allows_value(self, node: Any, value: Any, references: tuple = ()) -> bool:
        if isinstance(node, bool):
            return node
        if not isinstance(node, dict):
            return False
        reference = node.get("$ref")
        if isinstance(reference, str) and reference.startswith("#/"):
            return (reference not in references and len(references) < 32
                    and self.allows_value(self._resolve(reference), value, (*references, reference)))
        return self._accepts_variant(node, value) and self._accepts_groups(node, value, references)

    def _accepts_groups(self, node: dict, value: Any, references: tuple) -> bool:
        if not all(self.allows_value(part, value, references) for part in node.get("allOf", ())):
            return False
        if "oneOf" in node and sum(self.allows_value(part, value, references) for part in node["oneOf"]) != 1:
            return False
        return "anyOf" not in node or any(self.allows_value(part, value, references) for part in node["anyOf"])

    def _accepts_variant(self, node: dict, value: Any) -> bool:
        value_type = {dict: "object", list: "array", str: "string", int: "integer",
                      bool: "boolean", type(None): "null"}[type(value)]
        if "type" in node and not _type_matches(node, value_type):
            return False
        if ("const" in node or "enum" in node) and not _declares_value(node, value):
            return False
        if isinstance(value, list):
            return all(self.allows_value(node.get("items", True), item) for item in value)
        if isinstance(value, dict) and node.keys() & {"type", "properties", "required", "additionalProperties"}:
            return self._accepts_object(node, value)
        return True

    def _accepts_object(self, node: dict, value: dict) -> bool:
        fields = node.get("properties", {})
        # A field must be declared unless the schema explicitly opens the map.
        additional = node.get("additionalProperties", False)
        return set(node.get("required", ())) <= value.keys() and all(
            self.allows_value(fields.get(key, additional), item) for key, item in value.items()
        )

    def _descend(self, node: Any, token: str) -> Iterator[Any]:
        for variant in self.alternatives(node):
            fields = _child(variant, "properties", {})
            if token == "[]":
                yield _child(variant, "items")
            elif token.startswith("@"):
                tag, value = token[1:].split("=", 1)
                if self.has_shape(fields.get(tag), (value,)):
                    yield variant
            else:
                yield fields.get(token)

    def _walk(self, node: Any, path: Sequence[str]) -> Iterator[Any]:
        if not path:
            yield from self.alternatives(node)
            return
        for child in self._descend(node, path[0]):
            yield from self._walk(child, path[1:])

    def has_shape(self, node: Any, expected: Any, path: Sequence[str] = ()) -> bool:
        variants = list(self._walk(node, path))
        if expected is None:
            return any(variant is not False for variant in variants)
        objects = [variant for variant in variants if isinstance(variant, dict)]
        if isinstance(expected, tuple):
            return all(any(_declares_value(variant, value) for variant in objects) for value in expected)
        return any(_type_matches(variant, expected) for variant in objects)

    def require_shape(self, node: Any, shape: dict, label: str) -> None:
        for path, expected in shape.items():
            if not self.has_shape(node, expected, path.split(".") if path else ()):
                raise CapabilityError(f"Codex App Server capability missing: {label}{'.' + path if path else ''}")

    def method(self, envelope: str, name: str) -> dict:
        for variant in self.alternatives(self.definition(envelope)):
            if self.has_shape(variant, (name,), ("method",)):
                return variant
        raise CapabilityError(f"Codex App Server capability missing: {envelope} method {name}")

    def require_value(self, node: Any, value: Any, label: str) -> None:
        if not self.allows_value(node, value):
            field = self._incompatible_field(node, value)
            raise CapabilityError(f"Codex App Server capability missing: {label}{field}")

    def _incompatible_field(self, node: Any, value: Any) -> str:
        if isinstance(value, list):
            items = tuple(self._descend(node, "[]"))
            for index, item in enumerate(value):
                if items and not any(self.allows_value(child, item) for child in items):
                    return f".[{index}]" + self._incompatible_field({"anyOf": list(items)}, item)
        if not isinstance(value, dict):
            return ""
        for key, item in value.items():
            children = tuple(self._descend(node, key))
            if children and not any(self.allows_value(child, item) for child in children):
                return "." + key + self._incompatible_field({"anyOf": list(children)}, item)
        missing = [set(_child(variant, "required", ())) - value.keys()
                   for variant in self.alternatives(node)]
        nearest = min(missing, key=len, default=set())
        if nearest:
            return "." + sorted(nearest)[0] + " (required by Codex)"
        return ""


def _check_requests(protocol: _Schema, v2: _Schema, requests: dict) -> None:
    for method, inputs in requests.items():
        branch = protocol.method("ClientRequest", method)
        for params in inputs:
            protocol.require_value(branch, {"id": 1, "method": method, "params": params}, method)
        reply, fields = _REPLIES[method]
        schema = protocol if method == "initialize" else v2
        schema.require_shape(schema.definition(reply), {"": "object", **fields}, f"{method} reply {reply}")


def _check_callbacks(protocol: _Schema) -> None:
    for method, (fields, response, outputs) in _CALLBACKS.items():
        branch = protocol.method("ServerRequest", method)
        protocol.require_shape(branch, {"id": "integer", "params": "object"}, method)
        protocol.require_shape(branch, {"params." + field: kind for field, kind in fields.items()}, method)
        for result in outputs:
            protocol.require_value(protocol.definition(response), result, f"{method} reply {response}")


def _check_initialized(protocol: _Schema) -> None:
    initialized = protocol.method("ClientNotification", "initialized")
    # Codex declares no params property for this notification and accepts {}.
    fields = initialized["properties"]
    if "params" not in fields and initialized.get("additionalProperties") is not False:
        initialized = {**initialized, "properties": {"params": {"type": "object"}, **fields}}
    protocol.require_value(initialized, {"method": "initialized", "params": {}}, "initialized")


def _check_notifications(protocol: _Schema, notifications: dict) -> None:
    for method, fields in notifications.items():
        branch = protocol.method("ServerNotification", method)
        protocol.require_shape(branch, {"params": "object", **{
            "params." + field: kind for field, kind in fields.items()
        }}, method)


def _check_protocol(protocol: _Schema, v2: _Schema, experimental: bool) -> None:
    _check_requests(protocol, v2, _REQUESTS if experimental else _DIAGNOSTIC_REQUESTS)
    _check_notifications(protocol, _NOTIFICATIONS if experimental else _DIAGNOSTIC_NOTIFICATIONS)
    if experimental:
        _check_initialized(protocol)
        _check_callbacks(protocol)
    protocol.require_shape(protocol.definition("JSONRPCResponse"), {"id": "integer", "result": None}, "JSONRPCResponse")
    protocol.require_shape(protocol.definition("JSONRPCError"), {
        "id": "integer", "error.code": "integer", "error.message": "string",
    }, "JSONRPCError")


def _generate_schema(
    executable: Path, root: Path, launcher: Callable[[Path], Sequence[str]] | None, experimental: bool,
) -> Path:
    home, codex_home, output = (root / name for name in ("home", "codex-home", "schema"))
    for directory in (home, codex_home, output):
        directory.mkdir(mode=0o700)
    prefix = launcher(root) if launcher is not None else ()
    flags = ("--experimental",) if experimental else ()
    command = [*prefix, str(executable), "app-server", "generate-json-schema", *flags, "--out", str(output)]
    env = {"HOME": str(home), "CODEX_HOME": str(codex_home), "TMPDIR": str(root),
           "PATH": os.environ.get("PATH", os.defpath)}
    try:
        subprocess.run(command, cwd=root, env=env, check=True, timeout=_SCHEMA_SECONDS,
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       umask=0o077)
    except subprocess.TimeoutExpired as error:
        raise CapabilityError("Codex App Server schema generation timed out") from error
    except subprocess.CalledProcessError as error:
        raise CapabilityError(f"Codex App Server schema generation failed (exit {error.returncode})") from error
    except OSError as error:
        raise CapabilityError(f"cannot launch Codex App Server schema generator: {error}") from error
    return output


def _check_generated_schemas(output: Path, experimental: bool) -> None:
    try:
        directory_fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as error:
        raise CapabilityError(f"cannot access generated Codex App Server schemas: {error}") from error
    try:
        protocol = _Schema(_read_schema(directory_fd, _PROTOCOL))
        v2 = _Schema(_read_schema(directory_fd, _PROTOCOL_V2))
        _check_protocol(protocol, v2, experimental)
    except (AttributeError, KeyError, RecursionError, TypeError) as error:
        raise CapabilityError("invalid generated Codex App Server schema structure") from error
    finally:
        os.close(directory_fd)


def check_codex_capabilities(
    executable: str | os.PathLike[str], *, launcher: Callable[[Path], Sequence[str]] | None = None,
) -> None:
    """Require the used protocol of a trusted executable without starting a model.

    A containment caller can supply a prefix to run the generator inside its
    boundary. Each schema mode gets a private workspace with new homes and a
    fresh output directory. This check grants no launch authority.
    """
    path = shutil.which(executable)
    if path is None:
        raise CapabilityError(f"Codex App Server executable unavailable: {executable}")
    resolved = Path(path).resolve()
    for experimental in (False, True):
        with tempfile.TemporaryDirectory(prefix="cwo-codex-schema-") as temporary:
            output = _generate_schema(resolved, Path(temporary).resolve(), launcher, experimental)
            _check_generated_schemas(output, experimental)
