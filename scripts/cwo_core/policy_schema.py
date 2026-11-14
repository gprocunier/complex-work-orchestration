"""Bounded JSON Schema subset for current policy documents.

Only the keywords in ``SUPPORTED_KEYWORDS`` are understood. A schema that uses
any other keyword is refused instead of having the keyword silently ignored,
so a schema can never look stricter than the checks that actually run.

Rules beyond JSON Schema, all of them stricter:

- every schema node declares ``type``, ``enum`` or ``const``;
- an object node declares ``additionalProperties`` and every ``required``
  name appears in its ``properties``;
- an array node declares ``items``;
- ``integer`` means a JSON integer token: booleans and integral floats such
  as ``1.0`` are not integers; booleans are not numbers;
- ``enum``, ``const`` and ``uniqueItems`` compare JSON values, so ``true`` is
  never equal to ``1``.

Policy files with a registered schema are validated whenever they are loaded
from disk (``cwo_core.policy.load_policy``), so every consumer receives a
document that passed its schema. ``POLICY_VALIDATION_BOUNDARIES`` records the
actual validation boundary of every policy file; only the files listed in
``POLICY_SCHEMAS`` are covered by a whole-document schema.
"""

from __future__ import annotations

import json
import math
import re
import sys
from functools import lru_cache
from typing import Any

from .paths import REPO_ROOT


SCHEMA_DIR = REPO_ROOT / "schemas"
_PROVIDER_REGISTRY_V2_SCHEMA = "provider-registry-v2.schema.json"
_PROVIDER_REGISTRY_V2_MAX_UNDERLYING = 32
_PROVIDER_REGISTRY_V2_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}")

ANNOTATION_KEYWORDS = frozenset({"$schema", "$id", "$comment", "title", "description"})
VALIDATION_KEYWORDS = frozenset(
    {
        "type",
        "properties",
        "required",
        "additionalProperties",
        "items",
        "enum",
        "const",
        "minimum",
        "maximum",
        "minItems",
        "uniqueItems",
        "minLength",
    }
)
SUPPORTED_KEYWORDS = ANNOTATION_KEYWORDS | VALIDATION_KEYWORDS
TYPE_NAMES = ("object", "array", "string", "integer", "number", "boolean", "null")

# Current policy files covered by a whole-document schema, validated at every load.
POLICY_SCHEMAS = {'acceptance-policy.yaml': 'acceptance-policy.schema.json',
 'qualification-target.yaml': 'qualification-target.schema.json',
 'access-profiles.yaml': 'access-profiles.schema.json',
 'contracting-controls.yaml': 'contracting-controls.schema.json',
 'execution-environments.yaml': 'execution-environments.schema.json',
 'executor-registry.yaml': 'executor-registry.schema.json',
 'expert-registry.yaml': 'expert-registry.schema.json',
 'harness-registry.yaml': 'harness-registry.schema.json',
 'model-identity-scope.yaml': 'model-identity-scope.schema.json',
 'model-profiles.yaml': 'model-profiles.schema.json',
 'native-worker-execution.yaml': 'native-worker-execution-policy.schema.json',
 'outbound-screening.yaml': 'outbound-screening.schema.json',
 'peer-review-policy.yaml': 'peer-review-policy.schema.json',
 'provider-registry.yaml': 'provider-registry.schema.json',
 'return-tripwires.yaml': 'return-tripwires.schema.json',
 'risk-features.yaml': 'risk-features.schema.json',
 'routing-policy.yaml': 'routing-policy.schema.json',
 'share-boundaries.yaml': 'share-boundaries.schema.json',
 'synthesis-policy.yaml': 'synthesis-policy.schema.json',
 'zero-trust-consensus-policy.yaml': 'zero-trust-consensus-policy.schema.json'}

# The validation boundary each policy file actually has. Kinds:
#   schema            whole document, bounded schema, checked at every load (POLICY_SCHEMAS)
#   repository-check  typed validator run by the repository validator, not at runtime load
#   consumer-check    whole document checked by its consumer's typed validator at every read, outside load_policy
#   partial           named sections checked by typed code; the rest is read without validation
#   none              read by consumers without a validator (coercive reads included)
POLICY_VALIDATION_BOUNDARIES = {
    "qualification-target.yaml": (
        "schema",
        "schemas/qualification-target.schema.json fixes the selected target and labels every property; "
        "cwo_core.qualification_target.selected_target additionally resolves the existing executable/package pin; "
        "target_for rejects observed identity, profile and configuration drift without granting execution authority",
    ),
    "acceptance-policy.yaml": (
        "schema",
        'schemas/acceptance-policy.schema.json validates current configuration shape at load; section aliases, score/evidence fallbacks and dedicated tripwire thresholds remain additional consumer contracts; labels are data, not authority',
    ),
    "access-profiles.yaml": (
        "schema",
        'schemas/access-profiles.schema.json validates current configuration shape at load; typed registry, hook and readiness validation remain additional contracts; credential names and capabilities are declarations, not usable credentials or authority',
    ),
    "codex-protocol-pins.yaml": (
        "partial",
        "cwo_core.codex_protocol_pin.load_pins validates the version-1 header and complete pin "
        "envelopes, including recorded generation strings, executable and bundle metadata; "
        "direct helpers validate only their consumed metadata before file I/O; shared fact/count "
        "guards remain in use; manifest/schema payloads, source provenance, command execution "
        "and runtime/OS qualification are outside this partial boundary",
    ),
    "contracting-controls.yaml": ("schema", "schemas/contracting-controls.schema.json"),
    "execution-environments.yaml": (
        "schema",
        'schemas/execution-environments.schema.json validates current configuration shape at load; typed harness validation and cross-references remain additional contracts; metadata does not qualify host, tools or permissions',
    ),
    "executor-registry.yaml": (
        "schema",
        'schemas/executor-registry.schema.json validates current configuration shape at load; alias resolution and repository/provider/model cross-reference checks remain additional contracts; declarations do not qualify execution',
    ),
    "expert-registry.yaml": (
        "schema",
        "schemas/expert-registry.schema.json validates current v2 metadata at load; "
        "repository expert, executor and persona cross-reference checks remain additional contracts; "
        "persona paths, roles and descriptive strings are data, not checked provenance or authority",
    ),
    "harness-registry.yaml": (
        "schema",
        "schemas/harness-registry.schema.json validates declared metadata at load; "
        "cwo_core.harness.validate_execution_environment_registry retains presence, exemplar and cross-reference "
        "checks; declared supports_* flags do not qualify installed harnesses or grant execution permissions",
    ),
    "install-projection.yaml": (
        "consumer-check",
        "scripts/check_installed_skill.load_projection checks every key (exact keys, version, skill_name, entry "
        "paths, kinds and overlaps, exclusions) at every read: install.sh listing and staging, and the drift check",
    ),
    "model-identity-scope.yaml": ("schema", "schemas/model-identity-scope.schema.json"),
    "model-profiles.yaml": (
        "schema",
        'schemas/model-profiles.schema.json validates current configuration shape at load; typed profile validation, selection and access-profile lookups remain additional contracts; descriptive model data is not qualification',
    ),
    "native-worker-execution.yaml": (
        "schema",
        "schemas/native-worker-execution-policy.schema.json validates whole-document shape at load; "
        "typed presence, constants, bounds, cross-references and runtime/evidence checks remain additional contracts; "
        "declared models, commands, paths and permissions are data, not authority or host qualification",
    ),
    "outbound-screening.yaml": ("schema", "schemas/outbound-screening.schema.json"),
    "peer-review-policy.yaml": ("schema", "schemas/peer-review-policy.schema.json"),
    "provider-registry.yaml": (
        "schema",
        "schemas/provider-registry.schema.json is the closed V1 default; exact integer version 2 selects "
        "schemas/provider-registry-v2.schema.json and bounded direct-provider references at load; "
        "reliability metadata grants no data access, output trust or execution authority",
    ),
    "return-tripwires.yaml": ("schema", "schemas/return-tripwires.schema.json"),
    "risk-features.yaml": (
        "schema",
        "schemas/risk-features.schema.json validates current v1 configuration shape at load; "
        "cwo_core.risk_features._policy retains floor and validated_scope checks; "
        "task text and metadata confer no narrowing, clearance or dispatch authority",
    ),
    "routing-policy.yaml": ("schema", "schemas/routing-policy.schema.json"),
    "share-boundaries.yaml": (
        "schema",
        "schemas/share-boundaries.schema.json validates current v2 configuration shape at load; "
        "packet secret-field parsing and disclosure checks remain additional consumer contracts; "
        "declared flags and lists do not grant disclosure, repository, patch or execution authority",
    ),
    "synthesis-policy.yaml": ("schema", "schemas/synthesis-policy.schema.json"),
    "zero-trust-consensus-policy.yaml": (
        "schema",
        'schemas/zero-trust-consensus-policy.schema.json validates current configuration shape at load; consensus remains opt-in/informational; provider provenance, domain counting and adjudication checks remain additional contracts',
    ),
}


class PolicySchemaError(SystemExit):
    """A policy schema uses an unsupported construct or a policy document does not match it."""


class PolicyNameError(SystemExit):
    """A policy was requested by something other than its bare name."""


POLICY_SUFFIX = ".yaml"
_POLICY_STEM = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")


def canonical_policy_filename(name: object) -> str:
    """The single identity of a policy file: ``<bare-name>.yaml`` in the policy directory.

    Accepted spellings are the bare lowercase name (``routing-policy``) and the same
    name with the ``.yaml`` suffix. Paths of any kind (``./routing-policy``,
    ``../policy/routing-policy``, absolute paths), other letter case and every other
    spelling are refused, so the schema lookup and the policy cache always use the
    identity of the file that is actually read.
    """
    if type(name) is not str:
        raise PolicyNameError(f"policy name must be a string, not {type(name).__name__}")
    stem = name[: -len(POLICY_SUFFIX)] if name.endswith(POLICY_SUFFIX) else name
    if not _POLICY_STEM.fullmatch(stem):
        raise PolicyNameError(
            f"policy name {name!r} is not a bare policy name; policies are loaded by name from the "
            "policy directory (for example 'routing-policy'), not by path or by another spelling"
        )
    return stem + POLICY_SUFFIX


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate key {key!r}")
        value[key] = item
    return value


def _reject_constant(token: str) -> Any:
    raise ValueError(f"non-finite number {token} is not JSON")


def _finite_float(token: str) -> float:
    value = float(token)
    if not math.isfinite(value):
        raise ValueError(f"number {token} overflows to a non-finite value")
    return value


def _finite_int(token: str) -> int:
    value = int(token)
    if abs(value) > sys.float_info.max:
        raise ValueError(f"integer of {len(token)} characters is outside the finite number range")
    return value


def strict_json_loads(text: str) -> Any:
    """``json.loads`` that refuses duplicate keys, NaN and Infinity, and numbers that overflow.

    A number token such as ``1e309`` would otherwise parse to infinity, and an integer
    beyond the float range cannot be converted to a finite float by a consumer.
    """
    return json.loads(
        text,
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_constant,
        parse_float=_finite_float,
        parse_int=_finite_int,
    )


def json_type(value: Any) -> str | None:
    """The JSON type of a parsed value; None for anything JSON cannot represent."""
    if value is None:
        return "null"
    if type(value) is bool:
        return "boolean"
    if type(value) is int:
        return "integer"
    if type(value) is float:
        return "number" if math.isfinite(value) else None
    if type(value) is str:
        return "string"
    if type(value) is list:
        return "array"
    if type(value) is dict:
        return "object"
    return None


def _is_type(value: Any, name: str) -> bool:
    actual = json_type(value)
    if name == "number":
        return actual in {"integer", "number"}
    return actual == name


def json_equal(left: Any, right: Any) -> bool:
    """JSON value equality: booleans never equal numbers; 1 equals 1.0."""
    left_type, right_type = json_type(left), json_type(right)
    if left_type is None or right_type is None:
        return False
    numeric = {"integer", "number"}
    if left_type in numeric and right_type in numeric:
        return left == right
    if left_type != right_type:
        return False
    if left_type == "array":
        return len(left) == len(right) and all(json_equal(a, b) for a, b in zip(left, right))
    if left_type == "object":
        return set(left) == set(right) and all(json_equal(left[key], right[key]) for key in left)
    return left == right


def _declared_types(schema: dict[str, Any]) -> tuple[str, ...]:
    value = schema.get("type")
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list):
        return tuple(str(item) for item in value)
    return ()


def _is_bound(value: Any) -> bool:
    return json_type(value) in {"integer", "number"}


def _is_count(value: Any) -> bool:
    return json_type(value) == "integer" and value >= 0


def schema_errors(schema: Any, path: str = "#") -> list[str]:
    """Every way ``schema`` falls outside the supported subset."""
    if json_type(schema) != "object":
        return [f"{path}: a schema must be an object"]
    errors: list[str] = []
    for keyword in schema:
        if keyword not in SUPPORTED_KEYWORDS:
            errors.append(f"{path}: unsupported schema keyword {keyword!r}")
    for keyword in ANNOTATION_KEYWORDS & set(schema):
        if json_type(schema[keyword]) != "string":
            errors.append(f"{path}/{keyword}: must be a string")
    if not {"type", "enum", "const"} & set(schema):
        errors.append(f"{path}: declares none of type, enum or const")
    if "type" in schema:
        value = schema["type"]
        names = [value] if json_type(value) == "string" else value if json_type(value) == "array" else None
        if (
            not names
            or any(json_type(name) != "string" or name not in TYPE_NAMES for name in names)
            or len(set(names)) != len(names)
        ):
            errors.append(f"{path}/type: must be a type name or a non-empty list of distinct type names")
    if "enum" in schema:
        enum = schema["enum"]
        if json_type(enum) != "array" or not enum:
            errors.append(f"{path}/enum: must be a non-empty array")
        elif any(json_equal(a, b) for index, a in enumerate(enum) for b in enum[index + 1:]):
            errors.append(f"{path}/enum: values must be distinct")
    if "const" in schema and json_type(schema["const"]) is None:
        errors.append(f"{path}/const: must be a JSON value")
    for keyword in ("minimum", "maximum"):
        if keyword in schema and not _is_bound(schema[keyword]):
            errors.append(f"{path}/{keyword}: must be a number")
    for keyword in ("minItems", "minLength"):
        if keyword in schema and not _is_count(schema[keyword]):
            errors.append(f"{path}/{keyword}: must be a non-negative integer")
    if "uniqueItems" in schema and json_type(schema["uniqueItems"]) != "boolean":
        errors.append(f"{path}/uniqueItems: must be a boolean")
    properties = schema.get("properties", {})
    if json_type(properties) != "object":
        errors.append(f"{path}/properties: must be an object")
        properties = {}
    for name, child in properties.items():
        errors.extend(schema_errors(child, f"{path}/properties/{name}"))
    required = schema.get("required", [])
    if (
        json_type(required) != "array"
        or any(json_type(name) != "string" for name in required)
        or len(set(required)) != len(required)
    ):
        errors.append(f"{path}/required: must be an array of distinct strings")
    else:
        for name in required:
            if name not in properties:
                errors.append(f"{path}/required: {name!r} is not declared in properties")
    types = _declared_types(schema)
    if "additionalProperties" in schema:
        extra = schema["additionalProperties"]
        if json_type(extra) == "object":
            errors.extend(schema_errors(extra, f"{path}/additionalProperties"))
        elif json_type(extra) != "boolean":
            errors.append(f"{path}/additionalProperties: must be a boolean or a schema")
    elif "object" in types:
        errors.append(f"{path}: an object schema must declare additionalProperties")
    if "items" in schema:
        errors.extend(schema_errors(schema["items"], f"{path}/items"))
    elif "array" in types:
        errors.append(f"{path}: an array schema must declare items")
    return errors


def validate_instance(value: Any, schema: dict[str, Any], path: str = "$") -> list[str]:
    """Errors for ``value`` against a schema that already passed ``schema_errors``."""
    actual = json_type(value)
    if actual is None:
        return [f"{path}: not a JSON value"]
    types = _declared_types(schema)
    if types and not any(_is_type(value, name) for name in types):
        return [f"{path}: expected {' or '.join(types)}, found {actual}"]
    errors: list[str] = []
    if "const" in schema and not json_equal(value, schema["const"]):
        errors.append(f"{path}: must equal {json.dumps(schema['const'])}")
    if "enum" in schema and not any(json_equal(value, option) for option in schema["enum"]):
        errors.append(f"{path}: must be one of {json.dumps(schema['enum'])}")
    if actual in {"integer", "number"}:
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(f"{path}: must be at least {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            errors.append(f"{path}: must be at most {schema['maximum']}")
    if actual == "string" and "minLength" in schema and len(value) < schema["minLength"]:
        errors.append(f"{path}: must have at least {schema['minLength']} characters")
    if actual == "array":
        if "minItems" in schema and len(value) < schema["minItems"]:
            errors.append(f"{path}: must have at least {schema['minItems']} items")
        if schema.get("uniqueItems") is True:
            for index, item in enumerate(value):
                if any(json_equal(item, earlier) for earlier in value[:index]):
                    errors.append(f"{path}[{index}]: duplicates an earlier item")
        if "items" in schema:
            for index, item in enumerate(value):
                errors.extend(validate_instance(item, schema["items"], f"{path}[{index}]"))
    if actual == "object":
        properties = schema.get("properties", {})
        for name in schema.get("required", []):
            if name not in value:
                errors.append(f"{path}: missing required field {name!r}")
        extra = schema.get("additionalProperties", True)
        for name, item in value.items():
            child = f"{path}.{name}"
            if name in properties:
                errors.extend(validate_instance(item, properties[name], child))
            elif extra is False:
                errors.append(f"{child}: unexpected field")
            elif isinstance(extra, dict):
                errors.extend(validate_instance(item, extra, child))
    return errors


@lru_cache(maxsize=None)
def _load_schema_cached(name: str) -> dict[str, Any]:
    path = SCHEMA_DIR / name
    try:
        schema = strict_json_loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise PolicySchemaError(f"schemas/{name} cannot be read as strict JSON: {exc}") from exc
    errors = schema_errors(schema)
    if errors:
        raise PolicySchemaError(f"schemas/{name} is outside the supported schema subset: " + "; ".join(errors))
    return schema


def load_policy_schema(name: str) -> dict[str, Any]:
    return _load_schema_cached(name)


def clear_schema_cache() -> None:
    _load_schema_cached.cache_clear()


def _selected_policy_schema(filename: str, value: Any) -> str | None:
    """Select trusted reliability schema metadata without accepting caller paths."""
    default = POLICY_SCHEMAS.get(filename)
    if filename != "provider-registry.yaml":
        return default
    if type(value) is dict and type(value.get("version")) is int and value["version"] == 2:
        return _PROVIDER_REGISTRY_V2_SCHEMA
    return default


def _provider_registry_v2_size_errors(value: Any) -> list[str]:
    """Bound broker reliability lists before quadratic uniqueness validation."""
    providers = value.get("providers") if type(value) is dict else None
    if type(providers) is not dict:
        return []
    errors = []
    for key, entry in providers.items():
        underlying = entry.get("underlying_providers") if type(entry) is dict else None
        if type(underlying) is list and len(underlying) > _PROVIDER_REGISTRY_V2_MAX_UNDERLYING:
            errors.append(f"$.providers.{key}.underlying_providers: reliability list exceeds 32 items")
    return errors


def _provider_registry_v2_id_errors(providers: dict[str, Any]) -> list[str]:
    """Refuse ambiguous provider IDs in V2 reliability metadata."""
    errors = []
    seen = set()
    for key in providers:
        if type(key) is not str or not _PROVIDER_REGISTRY_V2_ID.fullmatch(key):
            errors.append(f"$.providers.{key}: reliability provider ID must be a plain token of 1 to 128 characters")
            continue
        folded = key.casefold()
        if folded in seen:
            errors.append(f"$.providers.{key}: reliability provider ID is ambiguous without case")
        seen.add(folded)
    return errors


def _provider_registry_v2_link_errors(key: str, entry: dict[str, Any],
                                      providers: dict[str, Any]) -> list[str]:
    """Check declared direct-provider references without deriving dispatch reliability."""
    path = f"$.providers.{key}.underlying_providers"
    if entry.get("broker") is not True:
        return [f"{path}: direct reliability metadata cannot declare underlying providers"] if (
            "underlying_providers" in entry) else []
    underlying = entry.get("underlying_providers")
    if underlying is None:
        return [f"{path}: broker reliability metadata requires a nonempty declared set"]
    errors = []
    for target in underlying:
        if not _PROVIDER_REGISTRY_V2_ID.fullmatch(target):
            errors.append(f"{path}: reliability provider IDs must be plain tokens of 1 to 128 characters")
            continue
        direct = providers.get(target)
        if target == key or direct is None or direct.get("broker") is True:
            errors.append(f"{path}: reliability references must name registered direct providers other than this broker")
    return errors


def _provider_registry_v2_errors(value: dict[str, Any]) -> list[str]:
    """Check V2 reliability metadata after whole-document shape validation."""
    providers = value["providers"]
    errors = _provider_registry_v2_id_errors(providers)
    for key, entry in providers.items():
        errors.extend(_provider_registry_v2_link_errors(key, entry, providers))
    return errors


def _policy_instance_errors(value: Any, schema_name: str) -> list[str]:
    """Apply the selected schema and bounded V2 reliability references."""
    schema = load_policy_schema(schema_name)
    if schema_name != _PROVIDER_REGISTRY_V2_SCHEMA:
        return validate_instance(value, schema)
    bounds = _provider_registry_v2_size_errors(value)
    if bounds:
        return bounds
    errors = validate_instance(value, schema)
    return errors or _provider_registry_v2_errors(value)


def policy_document_errors(filename: str, value: Any) -> list[str]:
    """Schema errors for a policy document; empty when it matches or has no registered schema.

    ``filename`` must be the canonical policy filename; any other spelling is refused
    rather than treated as a file without a schema.
    """
    if canonical_policy_filename(filename) != filename:
        raise PolicyNameError(f"policy filename {filename!r} is not canonical; use {canonical_policy_filename(filename)!r}")
    schema_name = _selected_policy_schema(filename, value)
    if schema_name is None:
        return []
    return _policy_instance_errors(value, schema_name)


def validate_policy_document(filename: str, value: Any) -> None:
    """Refuse a policy document that does not match its registered schema."""
    errors = policy_document_errors(filename, value)
    if errors:
        shown = "; ".join(errors[:20])
        more = f"; and {len(errors) - 20} more" if len(errors) > 20 else ""
        raise PolicySchemaError(
            f"policy/{filename} does not match schemas/{_selected_policy_schema(filename, value)} "
            f"({len(errors)} error{'s' if len(errors) != 1 else ''}): {shown}{more}"
        )
