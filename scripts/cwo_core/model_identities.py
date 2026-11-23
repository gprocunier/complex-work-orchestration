"""Resolve exact current Codex identities from the model-role policy."""

from __future__ import annotations

import re
from copy import deepcopy
from collections.abc import Iterable, Mapping
from typing import Any

# Frozen compatibility contracts, including routing v2 and v3, still use these IDs.
SPARK_MODEL = "gpt-5.3-codex-spark"
GPT55_MODEL = "gpt-5.5"
TERRA_MODEL = "gpt-5.6-terra"
LUNA_MODEL = "gpt-5.6-luna"

MODEL_ROLES = ("sol", "astra", "luna", "terra")
OPERATIVE_ROLES = ("luna", "terra")
CYBER_FALLBACK_ROLE = "cyber_fallback"
CYBER_FALLBACK_MODEL = "gpt-daybreak-blue-latest"
CYBER_FALLBACK_ACCESS_PROGRAM = "daybreakBlue"
CYBER_FALLBACK_CODEX_CONFIG = {"daybreak": True}
_FAMILY_MODEL = re.compile(r"gpt-([1-9][0-9]*(?:\.(?:0|[1-9][0-9]*))*)-(sol|astra|luna|terra)")
_startup_catalog: dict[str, dict[str, Any]] | None = None


def is_hidden_codex_model(model: object) -> bool:
    """Recognize reserved Codex identities outside the public role families."""
    return isinstance(model, str) and model.strip().casefold() in {"gpt-reserve", "codex-auto-review"}


def model_family_role(model: Any) -> str | None:
    """Return the family named by a canonical exact ID, without authorizing it."""
    match = _FAMILY_MODEL.fullmatch(model) if type(model) is str else None
    return match[2] if match is not None else None


def _validate_role(role: str, entry: Any) -> None:
    required = {"current", "previous", "selection"}
    if role in ("sol", "astra"):
        required.add("reviewer_rank")
    launch_fields = {"reasoning_effort", "service_tier"} if role == "sol" else set()
    if not isinstance(entry, Mapping) or not required <= set(entry) <= required | {"pin"} | launch_fields:
        raise ValueError(f"model-roles {role} fields are invalid")
    if entry["selection"] not in ("explicit", "latest-in-family"):
        raise ValueError(f"model-roles {role} selection is invalid")
    for key in ("current", "previous", "pin"):
        if key == "previous" and entry[key] is None:
            continue
        if key in entry and model_family_role(entry[key]) != role:
            raise ValueError(f"model-roles {role} {key} must be an exact model in its family")
    if "reviewer_rank" in entry and (type(entry["reviewer_rank"]) is not int or entry["reviewer_rank"] < 1):
        raise ValueError(f"model-roles {role} reviewer_rank must be a positive integer")


def _validate_cyber_fallback(entry: Any) -> None:
    expected = {
        "model": CYBER_FALLBACK_MODEL,
        "required_access_program": CYBER_FALLBACK_ACCESS_PROGRAM,
        "codex_config": CYBER_FALLBACK_CODEX_CONFIG,
    }
    if not isinstance(entry, Mapping) or dict(entry) != expected:
        raise ValueError(
            "model-roles cyber_fallback must select the Daybreak Blue model, access program and daybreak=true"
        )


def validate_model_role_config(config: Any) -> None:
    if (not isinstance(config, Mapping) or set(config) != {"version", "roles"}
            or type(config["version"]) is not int or config["version"] != 1):
        raise ValueError("model-roles policy version or fields are invalid")
    roles = config["roles"]
    permitted = set(MODEL_ROLES) | {CYBER_FALLBACK_ROLE}
    if not isinstance(roles, Mapping) or not set(MODEL_ROLES) <= set(roles) <= permitted:
        raise ValueError("model-roles policy requires sol, astra, luna and terra")
    for role in MODEL_ROLES:
        _validate_role(role, roles[role])
    if roles["astra"]["reviewer_rank"] <= roles["sol"]["reviewer_rank"]:
        raise ValueError("model-roles reviewer_rank must place astra above sol")
    if CYBER_FALLBACK_ROLE in roles:
        _validate_cyber_fallback(roles[CYBER_FALLBACK_ROLE])


def _role_config(config: Mapping[str, Any] | None) -> Mapping[str, Any]:
    if config is None:
        from .policy import load_policy

        config = load_policy("model-roles")
    validate_model_role_config(config)
    return config["roles"]


def _role_entry(role: str, config: Mapping[str, Any] | None) -> Mapping[str, Any]:
    if role not in MODEL_ROLES:
        raise ValueError(f"unknown Codex model role: {role!r}")
    return _role_config(config)[role]


def current_model(role: str, *, config: Mapping[str, Any] | None = None) -> str:
    return _role_entry(role, config)["current"]


def previous_model(role: str, *, config: Mapping[str, Any] | None = None) -> str | None:
    return _role_entry(role, config)["previous"]


def reviewer_rank(role: str, *, config: Mapping[str, Any] | None = None) -> int | None:
    return _role_entry(role, config).get("reviewer_rank")


def _validate_access_programs(value: Any) -> None:
    if value is None:
        return
    if (
        not isinstance(value, Mapping)
        or set(value) != {"cyber"}
        or type(value.get("cyber")) is not list
        or any(type(program) is not str or not program for program in value["cyber"])
        or len(set(value["cyber"])) != len(value["cyber"])
    ):
        raise ValueError("public Codex model catalog access-program metadata is invalid")


def _public_catalog(catalog: Any) -> dict[str, dict[str, Any]]:
    if (not isinstance(catalog, Mapping) or type(catalog.get("data")) is not list
            or catalog.get("nextCursor") is not None):
        raise ValueError("complete public Codex model catalog is required")
    models: dict[str, dict[str, Any]] = {}
    for row in catalog["data"]:
        if (not isinstance(row, Mapping) or type(row.get("id")) is not str
                or type(row.get("model")) is not str or type(row.get("hidden")) is not bool):
            raise ValueError("public Codex model catalog entry is invalid")
        model_id = row["id"]
        if model_id in models:
            raise ValueError("public Codex model catalog has duplicate IDs")
        _validate_access_programs(row.get("availableAccessPrograms"))
        models[model_id] = deepcopy(dict(row))
    return models


def configure_model_catalog(catalog: Mapping[str, Any] | None) -> None:
    """Capture a complete catalog once at process startup, or clear the snapshot."""
    global _startup_catalog
    _startup_catalog = None
    if catalog is not None:
        _startup_catalog = _public_catalog(catalog)


def requires_model_catalog(
    roles: Iterable[str] | None = None, *, config: Mapping[str, Any] | None = None,
) -> bool:
    entries = _role_config(config)
    selected = (
        MODEL_ROLES + ((CYBER_FALLBACK_ROLE,) if CYBER_FALLBACK_ROLE in entries else ())
        if roles is None else tuple(roles)
    )
    if any(role not in (*MODEL_ROLES, CYBER_FALLBACK_ROLE) for role in selected):
        raise ValueError("unknown Codex model role in catalog request")
    if CYBER_FALLBACK_ROLE in selected and CYBER_FALLBACK_ROLE in entries:
        return True
    return any(entries[role]["selection"] == "latest-in-family" and "pin" not in entries[role]
               for role in selected if role in MODEL_ROLES)


def _model_version(model: str) -> tuple[int, ...]:
    return tuple(int(part) for part in model.split("-")[1].split("."))


def resolve_model(
    role: str, *, config: Mapping[str, Any] | None = None, catalog: Mapping[str, Any] | None = None,
) -> str:
    """Resolve the explicit model, pin, or newest public family member to one ID."""
    entry = _role_entry(role, config)
    models = _startup_catalog if catalog is None else _public_catalog(catalog)
    if "pin" in entry or entry["selection"] == "explicit":
        model = entry.get("pin", entry["current"])
        row = models.get(model) if models is not None else None
        if row is not None and (row["hidden"] or row["model"] != model):
            raise ValueError(f"configured model for {role} is hidden or aliased in the Codex catalog")
        return model
    if models is None:
        raise ValueError(f"public Codex model catalog is required for {role}")
    candidates = [
        model for model, row in models.items()
        if not row["hidden"] and row["model"] == model and model_family_role(model) == role
    ]
    if not candidates:
        raise ValueError(f"public Codex model catalog has no selectable model for {role}")
    return max(candidates, key=_model_version)


def role_for_model(
    model: Any, *, config: Mapping[str, Any] | None = None, catalog: Mapping[str, Any] | None = None,
    include_previous: bool = False,
) -> str | None:
    """Find the role for an exact resolved model, optionally reading its rollback ID."""
    role = model_family_role(model)
    if role is None:
        return None
    if include_previous and previous_model(role, config=config) == model:
        return role
    return role if resolve_model(role, config=config, catalog=catalog) == model else None


def operative_models() -> tuple[str, str]:
    return resolve_model("luna"), resolve_model("terra")


def cyber_fallback_availability(
    *, config: Mapping[str, Any] | None = None, catalog: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Report whether the optional Daybreak role is visible to this Codex user."""
    entries = _role_config(config)
    entry = entries.get(CYBER_FALLBACK_ROLE)
    if entry is None:
        return {
            "role": CYBER_FALLBACK_ROLE,
            "status": "unconfigured",
            "reason": "role-absent",
            "model": None,
            "required_access_program": None,
            "codex_config": None,
        }
    projection = {"role": CYBER_FALLBACK_ROLE, **deepcopy(dict(entry))}
    models = _startup_catalog if catalog is None else _public_catalog(catalog)
    if models is None:
        return {**projection, "status": "unavailable", "reason": "catalog-not-loaded"}
    row = models.get(entry["model"])
    if row is None:
        return {**projection, "status": "unavailable", "reason": "model-not-advertised"}
    if row["hidden"] or row["model"] != entry["model"]:
        return {**projection, "status": "unavailable", "reason": "model-not-selectable"}
    access = row.get("availableAccessPrograms")
    programs = access.get("cyber", []) if isinstance(access, Mapping) else []
    if entry["required_access_program"] not in programs:
        return {**projection, "status": "unavailable", "reason": "access-program-not-advertised"}
    return {**projection, "status": "available", "reason": "required-access-program-advertised"}
