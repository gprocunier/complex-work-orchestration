"""Pinned Codex app-server protocol evidence, checked offline.

A pin in ``policy/codex-protocol-pins.yaml`` records one Codex executable's
identity, the commands that generated its JSON Schema bundles (no model call,
no network), each bundle's digest, and schema-level facts the host contract
relies on. Nothing here runs Codex. A caller that generated a bundle passes the
directory; a caller that knows an executable's version text and hash passes
those. Any mismatch means the pin does not apply, so evidence qualified against
it does not carry over.

Facts describe the generated protocol schema only. They say nothing about
effective configuration, runtime behavior or OS enforcement.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
from pathlib import Path
from typing import Any, Iterator, Mapping

from .policy import load_policy

PIN_POLICY = "codex-protocol-pins"
FACT_KINDS = frozenset({
    "enum-includes",
    "method-params-exclude",
    "methods-equal",
    "methods-include",
    "param-property-enum",
    "properties-absent",
    "properties-present",
    "property-description-contains",
    "required-includes",
    "response-decision-union",
    "responses-present",
})
BUNDLES = ("stable", "experimental")
_SHA256 = re.compile(r"[0-9a-f]{64}")


class PinError(ValueError):
    """The pin policy itself is malformed."""


def _validate_file_count(value: Any) -> None:
    """Require a nonnegative integer count without Python's bool/int equivalence."""
    if type(value) is not int or value < 0:
        raise PinError("codex-protocol-pins: file count must be a nonnegative integer")


_FACT_FIELDS = {
    "enum-includes": ({"values": "strings"}, {"definition": "nullable-string"}),
    "method-params-exclude": (
        {"method": "string", "forbidden_required": "strings"}, {}),
    "methods-equal": ({"values": "strings"}, {}),
    "methods-include": ({"values": "strings"}, {}),
    "param-property-enum": (
        {"property": "string", "definition": "nullable-string", "values": "strings", "default": "nullable-string"},
        {"method": "nullable-string"}),
    "properties-absent": ({"names": "strings"}, {}),
    "properties-present": ({"names": "strings"}, {}),
    "property-description-contains": (
        {"property": "string", "text": "string"}, {}),
    "required-includes": ({"names": "strings"}, {}),
    "response-decision-union": (
        {"bundle": "string", "method": "string", "decision_field": "string", "strings": "strings", "objects": "objects"},
        {}),
    "responses-present": ({"bundle": "string"}, {}),
}


def _fact_error(field: str) -> None:
    raise PinError(f"codex-protocol-pins: invalid fact field {field}")


def _validate_fact_value(field: str, expected: str, value: Any) -> None:
    valid = False
    if expected == "string":
        valid = type(value) is str
    elif expected == "nullable-string":
        valid = value is None or type(value) is str
    elif expected == "strings":
        valid = type(value) is list and all(type(item) is str for item in value)
    elif expected == "objects":
        valid = type(value) is dict
    if not valid:
        _fact_error(field)
    if expected == "objects":
        _validate_json_data(value)


def _validate_fact(fact: Any) -> None:
    """The one fact-record contract, shared by policy and direct schema consumers."""
    if not isinstance(fact, Mapping):
        raise PinError("codex-protocol-pins: fact must be a mapping")
    for field in ("id", "kind", "schema"):
        _validate_fact_value(field, "string", fact.get(field))
    if fact["kind"] not in FACT_KINDS:
        raise PinError("codex-protocol-pins: unsupported fact kind")
    required, optional = _FACT_FIELDS[fact["kind"]]
    allowed = {"id", "kind", "schema", "meaning"} | required.keys() | optional.keys()
    if any(type(key) is not str or key not in allowed for key in fact):
        raise PinError("codex-protocol-pins: fact has unexpected fields")
    for field, expected in required.items():
        if field not in fact:
            _fact_error(field)
        _validate_fact_value(field, expected, fact[field])
    for field, expected in {"meaning": "string", **optional}.items():
        if field in fact:
            _validate_fact_value(field, expected, fact[field])


def _validate_facts(facts: Any) -> None:
    if type(facts) is not list:
        raise PinError("codex-protocol-pins: facts must be a list")
    seen: set[str] = set()
    for fact in facts:
        _validate_fact(fact)
        if fact["id"] in seen:
            raise PinError("codex-protocol-pins: repeated fact id")
        seen.add(fact["id"])


def _fact_records(pin: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    if not isinstance(pin, Mapping):
        raise PinError("codex-protocol-pins: facts need a mapping wrapper")
    facts = pin.get("facts")
    _validate_facts(facts)
    return facts


def _json_children(value: Any) -> Any:
    if type(value) is dict:
        if any(type(key) is not str for key in value):
            _fact_error("objects")
        return value.values()
    return value


def _validate_json_scalar(value: Any) -> None:
    if type(value) in (str, int, bool, type(None)):
        return
    if type(value) is float and math.isfinite(value):
        return
    _fact_error("objects")


def _validate_json_data(value: Any) -> None:
    """Validate JSON data iteratively; shared acyclic containers are allowed."""
    pending = [(value, False)]
    active: set[int] = set()
    complete: set[int] = set()
    while pending:
        node, leaving = pending.pop()
        if type(node) not in (dict, list):
            _validate_json_scalar(node)
            continue
        identity = id(node)
        if leaving:
            active.remove(identity)
            complete.add(identity)
            continue
        if identity in active:
            _fact_error("objects")
        if identity in complete:
            continue
        children = _json_children(node)
        active.add(identity)
        pending.append((node, True))
        pending.extend((child, False) for child in children)


def _json_atom_equal(left: Any, right: Any) -> bool:
    if type(left) in (int, float) and type(right) in (int, float):
        return left == right
    return type(left) is type(right) and left == right


def _json_data_equal(left: Any, right: Any) -> bool:
    """Compare JSON data without recursion, coercion or bool/number equivalence."""
    pending = [(left, right)]
    compared: set[tuple[int, int]] = set()
    while pending:
        left, right = pending.pop()
        if type(left) in (dict, list):
            if type(left) is not type(right):
                return False
            if type(left) is dict:
                if left.keys() != right.keys():
                    return False
                children = ((left[key], right[key]) for key in left)
            else:
                if len(left) != len(right):
                    return False
                children = zip(left, right)
            identity = (id(left), id(right))
            if identity not in compared:
                compared.add(identity)
                pending.extend(children)
        elif not _json_atom_equal(left, right):
            return False
    return True


def bundle_digest(manifest: Mapping[str, str]) -> str:
    """The digest of a bundle: SHA-256 over its sorted ``<path>\\0<file sha256>\\n`` lines."""
    lines = sorted(f"{path}\0{digest}\n" for path, digest in manifest.items())
    return hashlib.sha256("".join(lines).encode("utf-8")).hexdigest()


def bundle_manifest(directory: Path) -> dict[str, str]:
    """``relative path -> sha256`` for every file under ``directory``; any symlink or special file is refused."""
    manifest: dict[str, str] = {}
    root = Path(directory)
    if not stat.S_ISDIR(os.lstat(root).st_mode):
        raise PinError(f"not a directory: {root}")
    for path in sorted(_walk(root)):
        mode = os.lstat(path).st_mode
        if not stat.S_ISREG(mode):
            raise PinError(f"not a regular file in the bundle: {path.relative_to(root).as_posix()}")
        manifest[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return manifest


def _walk(root: Path) -> Iterator[Path]:
    for entry in os.scandir(root):
        path = Path(entry.path)
        if entry.is_dir(follow_symlinks=False):
            yield from _walk(path)
        else:
            yield path


def verify_bundle(directory: Path, expected: Mapping[str, str], expected_digest: str) -> list[str]:
    """Differences between a generated bundle and its pinned manifest and digest; empty when it matches."""
    try:
        actual = bundle_manifest(directory)
    except (OSError, PinError) as exc:
        return [f"bundle unreadable: {exc}"]
    problems = [f"missing: {path}" for path in sorted(set(expected) - set(actual))]
    problems += [f"unexpected: {path}" for path in sorted(set(actual) - set(expected))]
    problems += [f"changed: {path}" for path in sorted(set(actual) & set(expected)) if actual[path] != expected[path]]
    if bundle_digest(actual) != expected_digest:
        problems.append("bundle digest differs from the pin")
    return problems


def _metadata_mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise PinError(f"codex-protocol-pins: {field} must be a mapping")
    return value


def _metadata_fields(
    value: Any, field: str, required: tuple[str, ...], optional: tuple[str, ...] = (),
) -> Mapping[str, Any]:
    data = _metadata_mapping(value, field)
    allowed = set(required) | set(optional)
    if any(type(key) is not str or key not in allowed for key in data):
        raise PinError(f"codex-protocol-pins: {field} has unexpected fields")
    if any(key not in data for key in required):
        raise PinError(f"codex-protocol-pins: {field} is missing required fields")
    return data


def _metadata_string(value: Any, field: str, *, nonempty: bool = False) -> None:
    if type(value) is not str or (nonempty and not value):
        raise PinError(f"codex-protocol-pins: {field} must be {'a nonempty string' if nonempty else 'a string'}")


def _metadata_digest(value: Any) -> None:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise PinError("codex-protocol-pins: sha256 must be a lowercase 64-character string")


def _executable_metadata(pin: Mapping[str, Any]) -> Mapping[str, Any]:
    wrapper = _metadata_mapping(pin, "pin")
    executable = _metadata_mapping(wrapper.get("executable"), "executable")
    _metadata_string(executable.get("version_text"), "version_text", nonempty=True)
    _metadata_digest(executable.get("sha256"))
    return executable


def _manifest_metadata(pin: Mapping[str, Any]) -> Mapping[str, Any]:
    wrapper = _metadata_mapping(pin, "pin")
    _metadata_string(wrapper.get("manifest"), "manifest", nonempty=True)
    bundles = _metadata_mapping(wrapper.get("bundles"), "bundles")
    for name in BUNDLES:
        bundle = _metadata_mapping(bundles.get(name), "bundle")
        _metadata_digest(bundle.get("digest"))
        _validate_file_count(bundle.get("files"))
    return bundles


def _validate_header(value: Any) -> None:
    data = _metadata_fields(value, "policy", ("version", "pins"), ("description", "bundle_digest"))
    if type(data["version"]) is not int or data["version"] != 1:
        raise PinError("codex-protocol-pins: version must be integer 1")
    for field in ("description", "bundle_digest"):
        if field in data:
            _metadata_string(data[field], field)


def _validate_executable(pin: Mapping[str, Any]) -> None:
    executable = _metadata_fields(
        _executable_metadata(pin), "executable", ("version_text", "sha256"),
        ("target", "package_json_sha256"),
    )
    if "target" in executable:
        _metadata_string(executable["target"], "target")
    if "package_json_sha256" in executable:
        _metadata_digest(executable["package_json_sha256"])


def _validate_generation(value: Any) -> None:
    generation = _metadata_fields(value, "generation", ("commands",), ("environment", "reproducibility"))
    commands = _metadata_fields(generation["commands"], "commands", BUNDLES)
    for name in BUNDLES:
        _metadata_string(commands[name], "command")
    for field in ("environment", "reproducibility"):
        if field in generation:
            _metadata_string(generation[field], field)


def executable_matches(pin: Mapping[str, Any], version_text: str, sha256: str) -> list[str]:
    """Differences between an executable's reported version and hash and the pin; empty when it matches."""
    executable = _executable_metadata(pin)
    problems = []
    if version_text.strip() != executable["version_text"]:
        problems.append(f"version {version_text.strip()!r} is not the pinned {executable['version_text']!r}")
    if sha256 != executable["sha256"]:
        problems.append("executable hash differs from the pin")
    return problems


def load_pins() -> list[dict[str, Any]]:
    """The pins, validated; PinError if the policy is malformed."""
    data = load_policy(PIN_POLICY)
    _validate_header(data)
    pins = data.get("pins")
    if not isinstance(pins, list) or not pins:
        raise PinError("codex-protocol-pins: pins must be a nonempty list")
    for pin in pins:
        _validate_pin(pin)
    if sum(pin.get("status") == "current" for pin in pins) != 1:
        raise PinError("codex-protocol-pins: exactly one pin must be current")
    return pins


def pin_for(version: str) -> dict[str, Any]:
    for pin in load_pins():
        if pin["version"] == version:
            return pin
    raise PinError(f"no Codex protocol pin for version {version!r}")


def _validate_pin(pin: Any) -> None:
    pin = _metadata_fields(
        pin, "pin", ("version", "status", "manifest", "executable", "generation", "bundles", "facts"),
        ("package_json_note",),
    )
    _metadata_string(pin["version"], "version", nonempty=True)
    label = f"codex-protocol-pins {pin['version']}"
    _metadata_string(pin["status"], "status", nonempty=True)
    if pin["status"] not in ("current", "historical"):
        raise PinError(f"{label}: needs a manifest path and a status of current or historical")
    if "package_json_note" in pin:
        _metadata_string(pin["package_json_note"], "package_json_note")
    _validate_executable(pin)
    _validate_generation(pin["generation"])
    bundles = _manifest_metadata(pin)
    _metadata_fields(bundles, "bundles", BUNDLES)
    for bundle in bundles.values():
        _metadata_fields(bundle, "bundle", ("files", "digest"))
    facts = pin.get("facts")
    if not isinstance(facts, list) or not facts:
        raise PinError(f"{label}: facts must be a nonempty list")
    _validate_facts(facts)


def load_manifest(pin: Mapping[str, Any], root: Path) -> dict[str, dict[str, str]]:
    """The pin's per-file manifest, checked against the pinned bundle digests and counts."""
    bundles = _manifest_metadata(pin)
    manifest = json.loads((Path(root) / pin["manifest"]).read_text(encoding="utf-8"))
    for name in BUNDLES:
        entries = manifest.get(name)
        if not isinstance(entries, dict) or len(entries) != bundles[name]["files"] \
                or bundle_digest(entries) != bundles[name]["digest"]:
            raise PinError(f"manifest {pin['manifest']}: bundle {name} does not match the pin")
    return manifest


def _schema(schema_root: Path, relative: str) -> dict[str, Any]:
    return json.loads((Path(schema_root) / relative).read_text(encoding="utf-8"))


def _decisions(node: Any, found: set[str]) -> None:
    """Enum values and the keys of single-key decision objects under ``node``."""
    if isinstance(node, dict):
        found.update(value for value in node.get("enum", []) if isinstance(value, str))
        required = node.get("required")
        if isinstance(required, list) and len(required) == 1 and "properties" in node and node.get("type") == "object":
            found.add(required[0])
        for value in node.values():
            _decisions(value, found)
    elif isinstance(node, list):
        for value in node:
            _decisions(value, found)


def _methods(schema: Mapping[str, Any]) -> dict[str, str]:
    """``method -> params definition`` for each variant of a ServerRequest or ClientRequest schema."""
    methods = {}
    for variant in schema.get("oneOf", []):
        properties = variant.get("properties", {})
        method = properties.get("method", {}).get("enum", [None])[0]
        reference = str(properties.get("params", {}).get("$ref", "")).rsplit("/", 1)[-1]
        methods[str(method)] = reference
    return methods


def _definition(schema: Mapping[str, Any], reference: Any) -> tuple[str, Any] | None:
    """``(name, definition)`` for a local ``#/definitions/<name>`` reference; None for any other reference."""
    prefix = "#/definitions/"
    if not isinstance(reference, str) or not reference.startswith(prefix):
        return None
    name = reference[len(prefix):]
    definitions = schema.get("definitions", {})
    return (name, definitions[name]) if isinstance(definitions, dict) and name in definitions else None


def _follow(schema: Mapping[str, Any], node: Any) -> tuple[str | None, Any] | None:
    """Follow ``node`` through a ``$ref``, or an ``allOf`` holding exactly one ``$ref``, to the schema it names.

    Returns ``(definition name or None, schema)``; None when a reference does not resolve or the chain loops.

    Constraint keywords beside a ``$ref`` (direct or inside ``allOf``) other than the allowlisted non-semantic
    keywords (description, title, default) are rejected by returning None. This prevents schema changes from
    adding constraints that narrow the reference without breaking facts that follow it.
    """
    name = None
    for _ in range(16):
        if not isinstance(node, dict):
            return None
        all_of = node.get("allOf")
        if "$ref" in node:
            # Reject constraint keywords beside the $ref other than the allowlist.
            if set(node) - _ALLOWED_BESIDE_REF:
                return None
            reference = node["$ref"]
        elif isinstance(all_of, list) and len(all_of) == 1 and isinstance(all_of[0], dict) and "$ref" in all_of[0]:
            # Reject constraint keywords in the wrapper or inside the allOf item beside the $ref.
            if set(node) - {"allOf", "description", "title", "default"} or set(all_of[0]) - _ALLOWED_BESIDE_REF:
                return None
            reference = all_of[0]["$ref"]
        else:
            return name, node
        resolved = _definition(schema, reference)
        if resolved is None:
            return None
        name, node = resolved
    return None


def _method_params(schema: Mapping[str, Any], method: str) -> tuple[str | None, Any] | str:
    """The params schema of the one ``method`` variant of a request schema, followed through its reference."""
    variants = [variant for variant in schema.get("oneOf", []) if isinstance(variant, dict)
                and variant.get("properties", {}).get("method", {}).get("enum") == [method]]
    if len(variants) != 1:
        return f"{len(variants)} request variants for {method}"
    resolved = _follow(schema, variants[0].get("properties", {}).get("params"))
    return resolved if resolved is not None else f"params of {method} do not resolve"


_STRING_BRANCH_KEYS = frozenset({"type", "enum", "description", "title"})
_OBJECT_BRANCH_KEYS = frozenset({"type", "properties", "required", "additionalProperties", "description", "title"})
_UNION_KEYS = frozenset({"oneOf", "description", "title"})
_ALLOWED_BESIDE_REF = frozenset({"$ref", "description", "title", "default"})


def _decision_union_problems(union: Any, strings: list[str], objects: Mapping[str, Any]) -> list[str]:
    """Differences between a decision schema and the complete pinned union of string values and amendment objects.

    Every branch must be a string enum or one of the pinned objects with exactly its pinned shape. Any other branch
    (integer, untyped, a list of types, an unknown object or keyword) is a problem, as is a missing or added value.
    """
    if not isinstance(union, dict) or not isinstance(union.get("oneOf"), list) or not union["oneOf"]:
        return ["decision is not a oneOf union"]
    problems = [f"unexpected union keywords {sorted(set(union) - _UNION_KEYS)}"] if set(union) - _UNION_KEYS else []
    seen_strings: list[str] = []
    seen_objects: list[str] = []
    for index, branch in enumerate(union["oneOf"]):
        if not isinstance(branch, dict):
            problems.append(f"branch {index} is not a schema")
        elif branch.get("type") == "string" and set(branch) <= _STRING_BRANCH_KEYS and isinstance(branch.get("enum"), list) \
                and branch["enum"] and all(isinstance(value, str) for value in branch["enum"]):
            seen_strings.extend(branch["enum"])
        elif branch.get("type") == "object" and set(branch) <= _OBJECT_BRANCH_KEYS \
                and branch.get("additionalProperties") is False and isinstance(branch.get("properties"), dict) \
                and len(branch["properties"]) == 1 and branch.get("required") == list(branch["properties"]):
            name, shape = next(iter(branch["properties"].items()))
            if name not in objects:
                problems.append(f"branch {index} is an unpinned object {name!r}")
            elif not _json_data_equal(shape, objects[name]):
                problems.append(f"branch {index} changes the shape of {name!r}")
            seen_objects.append(name)
        else:
            problems.append(f"branch {index} is neither a string enum nor an amendment object "
                            f"(type {branch.get('type')!r})")
    for label, seen, expected in (("string", seen_strings, list(strings)), ("object", seen_objects, list(objects))):
        duplicated = sorted({value for value in seen if seen.count(value) > 1})
        missing = sorted(set(expected) - set(seen))
        added = sorted(set(seen) - set(expected))
        problems += [f"duplicate {label} decisions {duplicated}"] if duplicated else []
        problems += [f"missing {label} decisions {missing}"] if missing else []
        problems += [f"unpinned {label} decisions {added}"] if added and label == "string" else []
    return problems


def _enum_includes_problem(schema: Mapping[str, Any], fact: Mapping[str, Any]) -> str | None:
    found: set[str] = set()
    target = schema.get("definitions", {}).get(fact["definition"]) if fact.get("definition") else schema
    _decisions(target, found)
    missing = sorted(set(fact["values"]) - found)
    return None if not missing else f"{fact['id']}: missing decisions {missing}"


def evaluate_fact(fact: Mapping[str, Any], schema_root: Path, manifest: Mapping[str, Mapping[str, str]]) -> str | None:
    """None if fact holds, else a problem; malformed metadata raises PinError before schema I/O."""
    _validate_fact(fact)
    try:
        schema = _schema(schema_root, fact["schema"])
    except (OSError, ValueError) as exc:
        return f"{fact['id']}: schema unreadable ({exc})"
    properties = schema.get("properties", {})
    kind = fact["kind"]
    if kind == "methods-equal":
        actual = sorted(_methods(schema))
        return None if actual == sorted(fact["values"]) else f"{fact['id']}: methods are {actual}"
    if kind == "methods-include":
        missing = sorted(set(fact["values"]) - set(_methods(schema)))
        return None if not missing else f"{fact['id']}: missing methods {missing}"
    if kind == "responses-present":
        files = manifest[fact["bundle"]]
        missing = [method for method, params in _methods(schema).items()
                   if not params.endswith("Params") or params[: -len("Params")] + "Response.json" not in files]
        return None if not missing else f"{fact['id']}: no response schema for {missing}"
    if kind == "required-includes":
        missing = sorted(set(fact["names"]) - set(schema.get("required", [])))
        return None if not missing else f"{fact['id']}: not required: {missing}"
    if kind == "properties-present":
        missing = sorted(set(fact["names"]) - set(properties))
        return None if not missing else f"{fact['id']}: missing properties {missing}"
    if kind == "properties-absent":
        present = sorted(set(fact["names"]) & set(properties))
        return None if not present else f"{fact['id']}: unexpected properties {present}"
    if kind == "property-description-contains":
        description = str(properties.get(fact["property"], {}).get("description", ""))
        return None if fact["text"] in description else f"{fact['id']}: description of {fact['property']} changed"
    if kind == "method-params-exclude":
        method_name = fact["method"]
        methods = _methods(schema)
        params_name = methods.get(method_name)
        if not params_name:
            return f"{fact['id']}: method {method_name} not found"
        params_schema = schema.get("definitions", {}).get(params_name, {})
        if not params_schema:
            return f"{fact['id']}: params definition {params_name} not found in schema"
        required_params = params_schema.get("required", [])
        forbidden = sorted(set(fact["forbidden_required"]) & set(required_params))
        return None if not forbidden else f"{fact['id']}: {method_name} requires forbidden params {forbidden}"
    if kind == "param-property-enum":
        if fact.get("method"):
            resolved = _method_params(schema, fact["method"])
            if isinstance(resolved, str):
                return f"{fact['id']}: {resolved}"
            params = resolved[1]
        else:
            params = schema
        params_properties = params.get("properties") if isinstance(params, dict) else None
        prop = params_properties.get(fact["property"]) if isinstance(params_properties, dict) else None
        if not isinstance(prop, dict):
            return f"{fact['id']}: the params have no {fact['property']} property"
        target = _follow(schema, prop)
        if target is None:
            return f"{fact['id']}: {fact['property']} does not resolve"
        name, definition = target
        if name != fact["definition"]:
            return f"{fact['id']}: {fact['property']} refers to {name!r}, not {fact['definition']!r}"
        enum = definition.get("enum")
        if definition.get("type") != "string" or not isinstance(enum, list) \
                or not all(isinstance(value, str) for value in enum) or sorted(enum) != sorted(fact["values"]):
            return f"{fact['id']}: {fact['property']} allows {enum!r} of type {definition.get('type')!r}"
        default = prop.get("default", definition.get("default"))
        return None if _json_data_equal(default, fact["default"]) else f"{fact['id']}: {fact['property']} defaults to {default!r}"
    if kind == "response-decision-union":
        bundle = fact["bundle"]
        params_name = _methods(schema).get(fact["method"])
        if not params_name or not params_name.endswith("Params"):
            return f"{fact['id']}: method {fact['method']} not found"
        response_file = params_name[: -len("Params")] + "Response.json"
        if response_file not in manifest.get(bundle, {}):
            return f"{fact['id']}: response schema {response_file} not in manifest"
        try:
            response_schema = _schema(schema_root, f"{bundle}/{response_file}")
        except (OSError, ValueError) as exc:
            return f"{fact['id']}: response schema {bundle}/{response_file} unreadable ({exc})"
        # The response root must be exactly type "object" (not a union with other types, not missing).
        # This ensures every response is an object that can contain the decision field.
        if response_schema.get("type") != "object":
            return f"{fact['id']}: response root type is {response_schema.get('type')!r}, not exactly 'object'"
        field = fact["decision_field"]
        if field not in response_schema.get("required", []):
            return f"{fact['id']}: decision field {field} is not required"
        target = _follow(response_schema, response_schema.get("properties", {}).get(field))
        if target is None:
            return f"{fact['id']}: decision field {field} does not resolve"
        problems = _decision_union_problems(target[1], fact["strings"], fact["objects"])
        return None if not problems else f"{fact['id']}: " + "; ".join(problems)
    if kind == "enum-includes":
        return _enum_includes_problem(schema, fact)
    raise PinError("codex-protocol-pins: unsupported fact kind")


def check_facts(pin: Mapping[str, Any], schema_root: Path, manifest: Mapping[str, Mapping[str, str]]) -> list[str]:
    """The pin's facts that do not hold for the schemas under ``schema_root``."""
    return [problem for fact in _fact_records(pin) if (problem := evaluate_fact(fact, schema_root, manifest)) is not None]


__all__ = [
    "BUNDLES",
    "FACT_KINDS",
    "PinError",
    "bundle_digest",
    "bundle_manifest",
    "check_facts",
    "evaluate_fact",
    "executable_matches",
    "load_manifest",
    "load_pins",
    "pin_for",
    "verify_bundle",
]
