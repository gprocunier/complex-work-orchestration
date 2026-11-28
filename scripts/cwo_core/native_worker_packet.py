"""Validate and render native worker packets and returns."""

from __future__ import annotations

import json
import math
from pathlib import Path
import shlex
from typing import Any, Mapping

from .checked_command_sequence import normalize_sequence_spec
from .model_identities import OPERATIVE_ROLES, SPARK_MODEL, model_family_role, operative_models
from .native_containment import containment_error
from .native_disposition import DISPOSITION_FIELDS, validate_disposition
from .native_precommit import canonical_sha256 as _canonical_json_sha256, validate_precommit_receipt
from .native_release import validate_native_release_evidence
from .native_replanning import validate_needs_replan_payload
from .native_tool_isolation import NativeToolIsolationError, require_prompt_preflight, validate_tool_policy
from .native_worker_contracts import (
    ALLOWED_ATTESTATION_FIELDS, ALLOWED_ATTESTATION_STATUSES,
    ALLOWED_BUDGET_FIELDS, ALLOWED_BUDGET_PROVENANCE_FIELDS,
    ALLOWED_CHECKED_COMMAND_SEQUENCE_FIELDS, ALLOWED_COMMAND_CONTRACT_FIELDS,
    ALLOWED_ESCALATION_COMPACTION_FIELDS, ALLOWED_ESCALATION_HARD_LIMIT_FIELDS,
    ALLOWED_ESCALATION_SOFT_LIMIT_FIELDS, ALLOWED_ESCALATION_TRIGGER_FIELDS,
    ALLOWED_INTERRUPT_THRESHOLD_FIELDS, ALLOWED_SUPERVISION_FIELDS,
    ALLOWED_PACKET_FIELDS, ALLOWED_PACKET_V3_FIELDS,
    ALLOWED_RETURN_CONTRACT_FIELDS, ALLOWED_RETURN_FIELDS, ALLOWED_RETURN_USAGE_FIELDS, ALLOWED_MUTATION_STATES,
    ALLOWED_SCOPE_FIELDS,
    ALLOWED_SESSION_POLICY_FIELDS,
    ALLOWED_VALIDATION_LINEAGE_FIELDS,
    PACKET_V3_PHASES, packet_v3_recovery_contract, validate_packet_v3_phase_contract,
)
from .operative_routing import TASK_SELECTED_VERSION, nonoperative_model_refusal, validate_operative_route_for_model
from .paths import is_cwo_temp_path
from .policy import load_policy
from .work_sizing import (
    canonical_work_estimate_sha256, is_read_only_work_estimate, validate_work_estimate, validate_worker_commitment,
)

NATIVE_WORKER_POLICY_PATH = "policy/native-worker-execution.yaml"


def _required_string_list(
    value: Any, field: str, *, min_items: int = 1
) -> tuple[list[str], list[str]]:
    if not isinstance(value, list):
        return [f"{field} must be a list"], []
    if len(value) < min_items:
        return [f"{field} must contain at least {min_items} item(s)"], []
    errors: list[str] = []
    result: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            errors.append(f"{field} items must be non-empty strings")
            break
        result.append(item.strip())
    return errors, result


def load_native_worker_policy() -> dict[str, Any]:
    policy = load_policy("native-worker-execution")
    lane_budgets = policy.get("lane_budgets")
    if not isinstance(lane_budgets, dict) or not lane_budgets:
        raise SystemExit("policy missing lane_budgets")
    return_policy = policy.get("return_statuses")
    if not isinstance(return_policy, list) or not return_policy:
        raise SystemExit("policy missing return_statuses")
    return_policy = [str(item) for item in return_policy]
    execution_bootstrap = policy.get("execution_bootstrap")
    if not isinstance(execution_bootstrap, dict):
        raise SystemExit("policy missing execution_bootstrap")
    return {"policy": policy, "lane_budgets": lane_budgets, "return_statuses": return_policy}


def load_alignment_triggers() -> dict[str, Any]:
    policy = load_policy("native-worker-execution").get("alignment_triggers", {})
    needs_architect = policy.get("needs_architect_realignment")
    if not isinstance(needs_architect, dict):
        raise SystemExit("policy missing alignment_triggers.needs_architect_realignment")
    return needs_architect


def _is_known_packet_model(model: str) -> bool:
    policy = load_policy("native-worker-execution")
    historical = policy["governance"]["native_operative_worker"]["authorized_models"]
    return model in historical or model_family_role(model) in OPERATIVE_ROLES


def policy_lanes() -> list[str]:
    return sorted(load_policy("native-worker-execution").get("lane_budgets", {}).keys())


def policy_budgets_for_lane(lane: str) -> dict[str, int]:
    policy = load_native_worker_policy()
    raw = policy["lane_budgets"].get(lane)
    if not isinstance(raw, dict):
        raise SystemExit(f"policy missing budget profile for lane {lane!r}")
    return {
        "tool_calls_soft": int(raw["tool_calls_soft"]),
        "tool_calls_hard": int(raw["tool_calls_hard"]),
        "runtime_seconds_soft": int(raw["runtime_seconds_soft"]),
        "runtime_seconds_hard": int(raw["runtime_seconds_hard"]),
        "max_compactions": int(raw["max_compactions"]),
        "max_full_suite_runs": int(raw["max_full_suite_runs"]),
    }


def interrupt_thresholds(budget: dict[str, int]) -> dict[str, int]:
    policy = load_policy("native-worker-execution")
    tool_reserve = policy.get("tool_reserve", {})
    runtime_reserve = policy.get("runtime_reserve", {})
    tool_hard = budget["tool_calls_hard"]
    runtime_hard = budget["runtime_seconds_hard"]
    tool_margin = max(int(tool_reserve.get("floor", 3)), math.ceil(tool_hard * float(tool_reserve.get("ratio", 0.10))))
    runtime_margin = max(int(runtime_reserve.get("floor", 5)), math.ceil(runtime_hard * float(runtime_reserve.get("ratio", 0.10))))
    return {
        "tool_calls": max(0, tool_hard - tool_margin),
        "runtime_seconds": max(0, runtime_hard - runtime_margin),
    }


def _policy_return_statuses() -> list[str]:
    return list(load_native_worker_policy()["return_statuses"])


def _resolve_existing_or_future_path(raw: str) -> Path:
    try:
        return Path(raw).expanduser().resolve()
    except OSError as exc:
        raise SystemExit(f"invalid path {raw!r}: {exc}") from exc


def normalize_workdir(workdir: str) -> Path:
    if not isinstance(workdir, str) or not workdir.strip():
        raise SystemExit("workdir is required")
    path = _resolve_existing_or_future_path(workdir)
    if not path.is_dir():
        raise SystemExit(f"workdir is not a directory: {workdir!r}")
    return path


def _normalize_allowed_path(raw: str, workdir: Path, seen: set[str]) -> str:
    if not isinstance(raw, str) or not raw.strip():
        raise SystemExit("allowed path must be a non-empty string")
    stripped = raw.strip()
    candidate = Path(stripped)
    if candidate.is_absolute():
        resolved = _resolve_existing_or_future_path(str(candidate))
    else:
        resolved = _resolve_existing_or_future_path(str(workdir / candidate))
    if ".." in candidate.parts:
        raise SystemExit(f"path traversal is not allowed in allowed path {raw!r}")
    try:
        resolved.relative_to(workdir)
    except ValueError as exc:
        raise SystemExit(f"allowed path {raw!r} is outside workdir {workdir}") from exc
    normalized = resolved.relative_to(workdir).as_posix()
    if normalized in seen:
        return normalized
    seen.add(normalized)
    return normalized


def normalize_allowed_paths(paths: list[Any], workdir: Path) -> list[str]:
    if not paths:
        raise SystemExit("at least one --allowed-path is required")
    seen: set[str] = set()
    normalized: list[str] = []
    for raw in paths:
        normalized.append(_normalize_allowed_path(str(raw), workdir, seen))
    return normalized


def _required_nonempty_str(value: Any, field: str, *, allow_empty: bool = False) -> str | None:
    if not isinstance(value, str):
        return f"{field} must be a string"
    if allow_empty:
        return None
    if not value.strip():
        return f"{field} must be a non-empty string"
    return None


def _required_string_literal(
    values: Mapping[str, object], field: str, expected: str, *, field_path: str | None = None,
) -> str | None:
    field_path = field if field_path is None else field_path
    if (error := _required_nonempty_str(values.get(field), field_path)) is not None:
        return error
    return f"{field_path} must be {expected}" if values[field] != expected else None


def _required_bool(value: Any, field: str, expected: bool | None = None) -> str | None:
    if not isinstance(value, bool):
        return f"{field} must be boolean"
    if expected is not None and value != expected:
        return f"{field} must be {expected}"
    return None


def _required_int(value: Any, field: str, *, minimum: int = 0) -> str | None:
    if not isinstance(value, int) or isinstance(value, bool):
        return f"{field} must be an integer"
    if value < minimum:
        return f"{field} must be >= {minimum}"
    return None


def _required_non_negative_number(value: Any, field: str) -> str | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return f"{field} must be a non-negative number"
    if value < 0:
        return f"{field} must be >= 0"
    return None


def _reject_unknown_fields(
    payload: dict[str, Any], field_path: str, allowed: set[str]
) -> list[str]:
    extras = sorted(set(payload) - allowed)
    if extras:
        return [f"{field_path} has unknown field(s): {', '.join(extras)}"]
    return []


def _normalize_scope_paths(scope_paths: list[str], workdir: Path) -> list[Path]:
    allowed: list[Path] = []
    for raw in scope_paths:
        candidate = Path(raw)
        if ".." in candidate.parts:
            continue
        if candidate.is_absolute():
            resolved = _resolve_existing_or_future_path(str(candidate))
        else:
            resolved = _resolve_existing_or_future_path(str(workdir / candidate))
        try:
            resolved.relative_to(workdir)
        except ValueError:
            continue
        allowed.append(resolved)
    return allowed


def _path_in_scope(raw: str, workdir: Path, allowed_paths: list[Path]) -> str | None:
    if not raw or not str(raw).strip():
        return "files_touched item must be a non-empty string"
    candidate = Path(raw)
    if candidate.is_absolute():
        resolved = _resolve_existing_or_future_path(str(candidate))
    else:
        resolved = _resolve_existing_or_future_path(str(workdir / candidate))
    try:
        resolved.relative_to(workdir)
    except ValueError:
        return f"{raw!r} is outside workdir {workdir}"
    if not allowed_paths:
        return "no allowed_paths available for scope validation"
    for allowed in allowed_paths:
        try:
            resolved.relative_to(allowed)
            return None
        except ValueError:
            continue
    return f"{raw!r} is outside packet scope"


def build_command_contract(policy: dict[str, Any]) -> dict[str, Any]:
    checked = policy.get("checked_command")
    if not isinstance(checked, dict) or checked.get("version") != 1:
        raise SystemExit("native-worker policy checked_command version 1 is required")
    return {
        "required": True,
        "wrapper": "scripts/run_checked_command.py",
        "spec_schema": "schemas/checked-command-spec.schema.json",
        "result_schema": "schemas/checked-command-result.schema.json",
        "modes": list(checked.get("modes", [])),
        "typed_source_required_for": list(checked.get("typed_source_required_for", [])),
        "complex_command_action": "checked-wrapper-required",
        "construction_failure": "pm-realignment-no-quarantine",
        "quarantine_failures": list(checked.get("quarantine_required_for", [])),
    }


def work_plan_execution_contract(work_plan: Any) -> dict[str, Any] | None:
    if not isinstance(work_plan, dict):
        return None
    task_profile = work_plan.get("task_profile")
    if not isinstance(task_profile, dict):
        return None
    contract = task_profile.get("execution_contract")
    return contract if isinstance(contract, dict) else None


def direct_execution_contract_errors(work_plan: Any) -> list[str]:
    if not isinstance(work_plan, dict):
        return []
    task_profile = work_plan.get("task_profile")
    if not isinstance(task_profile, dict):
        return []
    commands = task_profile.get("commands")
    if (
        task_profile.get("task_class") not in {"literal-command", "read-only-validation"}
        or not isinstance(commands, list)
        or not commands
    ):
        return []
    if work_plan_execution_contract(work_plan) != {"mode": "direct", "checked_command_specs": []}:
        return [
            "dispatchable literal-command and read-only-validation plans require "
            "execution_contract mode direct with empty checked_command_specs"
        ]
    return []


def _validate_checked_command_sequence_receipt(
    payload: dict[str, Any],
    work_plan: Any,
) -> list[str]:
    errors: list[str] = []
    contract = work_plan_execution_contract(work_plan)
    sequence_required = bool(contract and contract.get("mode") == "checked-sequence-v1")
    receipt = payload.get("checked_command_sequence")
    if not sequence_required:
        if receipt is not None:
            errors.append("checked_command_sequence is forbidden unless work_plan selects checked-sequence-v1")
        return errors
    if receipt is None:
        return ["checked-sequence-v1 work_plan requires checked_command_sequence"]
    if not isinstance(receipt, dict):
        return ["checked_command_sequence must be an object"]
    errors.extend(
        _reject_unknown_fields(
            receipt,
            "checked_command_sequence",
            ALLOWED_CHECKED_COMMAND_SEQUENCE_FIELDS,
        )
    )
    missing = sorted(ALLOWED_CHECKED_COMMAND_SEQUENCE_FIELDS - set(receipt))
    if missing:
        errors.append(f"checked_command_sequence missing required field(s) {', '.join(missing)}")
        return errors
    if receipt.get("mode") != "checked-sequence-v1":
        errors.append("checked_command_sequence.mode must be checked-sequence-v1")

    embedded = receipt.get("spec")
    normalized_spec: dict[str, Any] | None = None
    try:
        normalized_spec = normalize_sequence_spec(embedded)
    except (TypeError, ValueError) as exc:
        errors.append(f"checked_command_sequence.spec is invalid: {exc}")
    if normalized_spec is not None and embedded != normalized_spec:
        errors.append("checked_command_sequence.spec must be normalized")

    if normalized_spec is not None and isinstance(work_plan, dict):
        if normalized_spec.get("packet_id") != payload.get("packet_id"):
            errors.append("checked_command_sequence.spec.packet_id must match packet_id")
        if normalized_spec.get("work_plan_sha256") != canonical_work_estimate_sha256(work_plan):
            errors.append("checked_command_sequence.spec.work_plan_sha256 must match work_plan")
        scope = payload.get("scope")
        workdir = scope.get("workdir") if isinstance(scope, dict) else None
        if normalized_spec.get("workdir") != workdir:
            errors.append("checked_command_sequence.spec.workdir must match packet scope.workdir")
        expected_commands = contract.get("checked_command_specs") if contract else None
        if normalized_spec.get("commands") != expected_commands:
            errors.append("checked_command_sequence.spec.commands must match work_plan execution contract")

    spec_hash = receipt.get("spec_sha256")
    if normalized_spec is not None and spec_hash != _canonical_json_sha256(normalized_spec):
        errors.append("checked_command_sequence.spec_sha256 must match normalized spec")

    path_fields = ("spec_path", "state_path", "output_path")
    paths: dict[str, Path] = {}
    for field in path_fields:
        raw = receipt.get(field)
        path = Path(raw) if isinstance(raw, str) and raw else None
        if path is None or not path.is_absolute():
            errors.append(f"checked_command_sequence.{field} must be an absolute path")
            continue
        if not is_cwo_temp_path(path):
            errors.append(f"checked_command_sequence.{field} must be under a CWO temp root")
            continue
        if path.is_symlink():
            errors.append(f"checked_command_sequence.{field} must not be a symlink")
            continue
        paths[field] = path
    if len(paths) == len(path_fields):
        if len({path.parent for path in paths.values()}) != 1:
            errors.append("checked_command_sequence paths must be siblings")
        expected_names = {
            "spec_path": "sequence-spec.json",
            "state_path": "sequence-state.json",
            "output_path": "sequence-result.json",
        }
        for field, name in expected_names.items():
            if paths[field].name != name:
                errors.append(f"checked_command_sequence.{field} must end with {name}")

        try:
            persisted_spec = json.loads(paths["spec_path"].read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            errors.append("checked_command_sequence.spec_path must contain readable JSON")
        else:
            if persisted_spec != normalized_spec:
                errors.append("checked_command_sequence persisted spec must match embedded spec")
            if _canonical_json_sha256(persisted_spec) != spec_hash:
                errors.append("checked_command_sequence persisted spec hash must match spec_sha256")

        expected_runner = [
            "python3",
            "scripts/run_checked_command_sequence.py",
            str(paths["spec_path"]),
            "--state",
            str(paths["state_path"]),
            "--output",
            str(paths["output_path"]),
        ]
        if receipt.get("runner_argv") != expected_runner:
            errors.append("checked_command_sequence.runner_argv must exactly match sequence artifact paths")
    elif not isinstance(receipt.get("runner_argv"), list):
        errors.append("checked_command_sequence.runner_argv must be a list")
    return errors


def _packet_route_errors(payload: dict[str, Any], requested_model: str, dispatchable: bool,
                         current_authority: Any) -> list[str]:
    errors: list[str] = []
    operative_routing = payload.get("operative_routing")
    if operative_routing is not None:
        errors.extend(
            "operative_routing: " + error
            for error in validate_operative_route_for_model(
                operative_routing,
                requested_model,
                work_estimate=payload.get("work_plan"),
                current_authority=current_authority,
                historical_parse=not dispatchable,
            )
        )
    elif requested_model and requested_model != SPARK_MODEL:
        errors.append("worker packet requires explicit operative_routing provenance")
    if dispatchable and (refusal := nonoperative_model_refusal(requested_model)) is not None:
        errors.append(refusal)

    return errors


def _is_active_packet_model(model: Any) -> bool:
    current = load_policy("native-worker-execution").get("task_selected_routing", {})
    if current.get("status") != "active":
        return True
    if current.get("version") == TASK_SELECTED_VERSION:
        return model in operative_models()
    return model in current.get("selection", {}).get("approved_portfolio", [])


def _validate_packet_ids(payload: dict[str, Any], errors: list[str]) -> None:
    if (error := _required_nonempty_str(payload.get("packet_id"), "packet_id")) is not None:
        errors.append(error)
    if (error := _required_nonempty_str(payload.get("bead_id"), "bead_id")) is not None:
        errors.append(error)


def _validate_packet_scope_actions(scope: dict[str, Any], errors: list[str]) -> None:
    for field, minimum in (("allowed_actions", 1), ("prohibited_actions", 0)):
        field_path = f"scope.{field}"
        action_errors, actions = _required_string_list(scope.get(field), field_path, min_items=minimum)
        errors.extend(action_errors)
        for action in actions:
            if _required_nonempty_str(action, f"{field_path} item") is not None:
                errors.append(_required_nonempty_str(action, f"{field_path} item") or "")


def _validate_packet_acceptance_checks(payload: dict[str, Any], errors: list[str]) -> list[str]:
    acceptance_errors, acceptance_checks = _required_string_list(
        payload.get("acceptance_checks"), "acceptance_checks"
    )
    if acceptance_errors:
        errors.extend(acceptance_errors)
    elif not acceptance_checks:
        errors.append("acceptance_checks must contain at least one check")
    return acceptance_checks


def _validate_packet_budget_entries(
    budget: dict[str, Any], policy_budgets: dict[str, int] | None,
    lane: Any, version: Any, errors: list[str],
) -> None:
    errors.extend(_reject_unknown_fields(budget, "budget", ALLOWED_BUDGET_FIELDS))
    if policy_budgets is not None:
        for key, value in policy_budgets.items():
            if (error := _required_int(budget.get(key), f"budget.{key}")) is not None:
                errors.append(error)
            elif version == 1 and budget[key] != value:
                errors.append(f"budget.{key} must equal policy profile for lane {lane!r}")
            elif version == 2 and budget[key] > value:
                errors.append(f"budget.{key} may only tighten policy profile for lane {lane!r}")
    _validate_packet_budget_limits(budget, version, errors)


def _validate_packet_budget_limits(budget: dict[str, Any], version: Any, errors: list[str]) -> None:
    if version == 2 and isinstance(budget.get("tool_calls_hard"), int) and budget["tool_calls_hard"] < 5:
        errors.append("budget.tool_calls_hard must be at least 5")
    for resource in ("tool_calls", "runtime_seconds"):
        soft, hard = f"{resource}_soft", f"{resource}_hard"
        if isinstance(budget.get(soft), int) and isinstance(budget.get(hard), int) and budget[soft] > budget[hard]:
            errors.append(f"budget.{soft} must not exceed budget.{hard}")


def _validate_packet_budget_provenance(
    payload: dict[str, Any], budget: Any, policy_budgets: dict[str, int] | None,
    lane: Any, errors: list[str],
) -> None:
    provenance = payload.get("budget_provenance")
    if not isinstance(provenance, dict):
        errors.append("budget_provenance must be an object for packet version 2")
    else:
        errors.extend(_reject_unknown_fields(provenance, "budget_provenance", ALLOWED_BUDGET_PROVENANCE_FIELDS))
        if provenance.get("profile") != lane:
            errors.append("budget_provenance.profile must equal lane")
        if provenance.get("policy_source") != NATIVE_WORKER_POLICY_PATH:
            errors.append("budget_provenance.policy_source must be policy/native-worker-execution.yaml")
        overridden = provenance.get("overridden_fields")
        if not isinstance(overridden, list) or any(item not in ALLOWED_BUDGET_FIELDS for item in overridden):
            errors.append("budget_provenance.overridden_fields is invalid")
        elif policy_budgets is not None and isinstance(budget, dict):
            expected_overridden = sorted(
                key
                for key, policy_value in policy_budgets.items()
                if budget.get(key) != policy_value
            )
            if sorted(overridden) != expected_overridden:
                errors.append("budget_provenance.overridden_fields must match effective budget differences")
            if provenance.get("overrides_applied") != bool(expected_overridden):
                errors.append("budget_provenance.overrides_applied must match effective budget differences")


def _validate_packet_return_contract(payload: dict[str, Any], errors: list[str]) -> None:
    return_contract = payload.get("return_contract")
    if not isinstance(return_contract, dict):
        errors.append("return_contract must be an object")
    else:
        errors.extend(_reject_unknown_fields(return_contract, "return_contract", ALLOWED_RETURN_CONTRACT_FIELDS))
        allowed = return_contract.get("allowed_statuses")
        if not isinstance(allowed, list):
            errors.append("return_contract.allowed_statuses must be a list")
        elif not allowed:
            errors.append("return_contract.allowed_statuses must be non-empty")
        else:
            for status in allowed:
                if not isinstance(status, str):
                    errors.append("return_contract.allowed_statuses must only contain strings")
                    break
            for expected in _policy_return_statuses():
                if expected not in allowed:
                    errors.append(f"return_contract.allowed_statuses missing {expected!r}")
                    break
        required_errors, required = _required_string_list(
            return_contract.get("required_fields"), "return_contract.required_fields"
        )
        if required_errors:
            errors.extend(required_errors)
        elif not required:
            errors.append("return_contract.required_fields must be non-empty")


def _validate_packet_escalation(payload: dict[str, Any], errors: list[str]) -> None:
    escalation = payload.get("escalation_triggers")
    if not isinstance(escalation, dict):
        errors.append("escalation_triggers must be an object")
        return
    errors.extend(_reject_unknown_fields(escalation, "escalation_triggers", ALLOWED_ESCALATION_TRIGGER_FIELDS))
    align = load_alignment_triggers()
    realignment_status = "needs-architect-realignment"
    for field in ("scope_ambiguity", "architecture_ambiguity", "security_ambiguity", "policy_ambiguity"):
        if str(escalation.get(field)) != realignment_status:
            errors.append(f"escalation_triggers.{field} must be {realignment_status}")
    status_rule = ("status", str, realignment_status)
    for section, fields, rules in (
        ("soft_limit", ALLOWED_ESCALATION_SOFT_LIMIT_FIELDS, (("distinct_soft_limits_required", int, 2),)),
        ("hard_limit", ALLOWED_ESCALATION_HARD_LIMIT_FIELDS, (("any_hard_limit", str, "realignment"), status_rule)),
        ("compaction", ALLOWED_ESCALATION_COMPACTION_FIELDS, (("any_compaction", str, "hard-stop/realignment"), status_rule)),
    ):
        section_path = f"escalation_triggers.{section}"
        values = escalation.get(section)
        if not isinstance(values, dict):
            errors.append(f"{section_path} must be an object")
            continue
        errors.extend(_reject_unknown_fields(values, section_path, fields))
        for field, convert, default in rules:
            if values.get(field) != convert(align.get(field, default)):
                errors.append(f"{section_path}.{field} must be {default}")


def validate_native_worker_packet(
    payload: Any,
    *,
    dispatchable: bool = False,
    experimental: bool = False,
    allow_experimental_v3: bool | None = None,
    current_authority: Any = None,
    maintenance_operation: Any = None,
    maintenance_verifier: Any = None,
) -> list[str]:
    errors: list[str] = []
    if not isinstance(payload, dict):
        return ["packet is not a JSON object"]
    if dispatchable and not _is_active_packet_model(payload.get("requested_model")):
        errors.append("historical model records cannot authorize current dispatch")
    if dispatchable:
        work_plan_binding = payload.get("work_plan")
        if containment := containment_error(
            "dispatchable-packet-validation",
            release_evidence=payload.get("release_evidence") if isinstance(payload.get("release_evidence"), dict) else None,
            expected_packet_id=str(payload.get("packet_id") or ""),
            expected_work_plan_sha256=(
                canonical_work_estimate_sha256(work_plan_binding)
                if isinstance(work_plan_binding, dict)
                else None
            ),
            expected_precommit_receipt_sha256=(
                str(payload.get("precommit_receipt_sha256"))
                if isinstance(payload.get("precommit_receipt_sha256"), str)
                else None
            ),
            maintenance_operation=maintenance_operation,
            maintenance_verifier=maintenance_verifier,
        ):
            errors.append(containment)
    if allow_experimental_v3 is not None:
        experimental = allow_experimental_v3
    version = payload.get("version")
    allowed_packet_fields = ALLOWED_PACKET_V3_FIELDS if version == 3 else ALLOWED_PACKET_FIELDS
    field_errors = _reject_unknown_fields(payload, "packet", allowed_packet_fields)
    if field_errors:
        return [*errors, *field_errors]

    if (value := _required_string_literal(payload, "packet_type", "cwo-native-worker-packet")) is not None:
        errors.append(value)

    if version not in {1, 2, 3}:
        errors.append("version must be 1, 2, or 3")
    if version == 3 and not experimental:
        errors.append("packet version 3 requires explicit experimental validation")
    if dispatchable and version != 2:
        errors.append(f"packet version {version} is dispatch-forbidden")
    if dispatchable and payload.get("operative_dispatch_authorized") is not True:
        errors.append("packet release state is operative-dispatch-forbidden")

    _validate_packet_ids(payload, errors)

    lane = payload.get("lane")
    if str(lane) not in policy_lanes():
        errors.append("lane is not a known native-worker lane")

    if (error := _required_nonempty_str(payload.get("requested_model"), "requested_model")) is not None:
        errors.append(error)
    elif not _is_known_packet_model(payload["requested_model"]):
        errors.append("requested_model must be an authorized native operative model")
    requested_model = str(payload.get("requested_model") or "")
    errors.extend(_packet_route_errors(payload, requested_model, dispatchable, current_authority))

    session_policy = payload.get("session_policy")
    if not isinstance(session_policy, dict):
        errors.append("session_policy must be an object")
    else:
        errors.extend(_reject_unknown_fields(session_policy, "session_policy", ALLOWED_SESSION_POLICY_FIELDS))
        for key, expected in (("fresh_session_required", True), ("resume_forbidden", True)):
            if (error := _required_bool(session_policy.get(key), f"session_policy.{key}", expected=expected)) is not None:
                errors.append(error)
        attestation = session_policy.get("attestation")
        if not isinstance(attestation, dict):
            errors.append("session_policy.attestation must be an object")
        else:
            errors.extend(_reject_unknown_fields(attestation, "session_policy.attestation", ALLOWED_ATTESTATION_FIELDS))
            if (error := _required_bool(attestation.get("required"), "session_policy.attestation.required", expected=True)) is not None:
                errors.append(error)
            for field, expected in (
                ("tool_mode", "no-tools"),
                ("model_authority", "trusted-control-plane-session-metadata"),
                ("self_report_authority", "forbidden"),
            ):
                if (error := _required_string_literal(
                    attestation, field, expected, field_path=f"session_policy.attestation.{field}",
                )) is not None:
                    errors.append(error)
            if (error := _required_nonempty_str(attestation.get("required_actual_model"), "session_policy.attestation.required_actual_model")) is not None:
                errors.append(error)
            elif attestation["required_actual_model"] != payload.get("requested_model"):
                errors.append("session_policy.attestation.required_actual_model must match packet.requested_model")
        if (error := _required_string_literal(
            session_policy, "source", NATIVE_WORKER_POLICY_PATH, field_path="session_policy.source",
        )) is not None:
            errors.append(error)

    tool_policy = payload.get("tool_policy")
    if version in {2, 3} and tool_policy is None:
        errors.append("tool_policy must be an object for packet version 2")
    if tool_policy is not None:
        errors.extend(
            error.replace("tool-policy", "tool_policy", 1)
            for error in validate_tool_policy(tool_policy)
        )
        if (
            dispatchable
            and isinstance(tool_policy, Mapping)
            and tool_policy.get("workload_class") == "operative"
            and tool_policy.get("enforcement_mode")
            == "trusted-detect-and-contain"
        ):
            errors.append(
                "tool_policy temporary enforcement requires an admitted-pool "
                "activation capability"
            )

    scope = payload.get("scope")
    if not isinstance(scope, dict):
        errors.append("scope must be an object")
    else:
        errors.extend(_reject_unknown_fields(scope, "scope", ALLOWED_SCOPE_FIELDS))
        if (error := _required_nonempty_str(scope.get("workdir"), "scope.workdir")) is not None:
            errors.append(error)
        else:
            workdir = normalize_workdir(str(scope["workdir"]))
            allowed_paths = scope.get("allowed_paths")
            normalized_path_errors, normalized = _required_string_list(
                allowed_paths, "scope.allowed_paths"
            )
            errors.extend(normalized_path_errors)
            if not normalized:
                errors.append("scope.allowed_paths must contain at least one path")
            for item in normalized:
                if str(item).strip().startswith("/"):
                    abs_path = _resolve_existing_or_future_path(item)
                    try:
                        abs_path.relative_to(workdir)
                    except ValueError:
                        errors.append("scope.allowed_paths contains absolute path outside workdir")
                if ".." in Path(item).parts:
                    errors.append("scope.allowed_paths contains path traversal components")
                _normalize_allowed_path(item, workdir, set())
            _validate_packet_scope_actions(scope, errors)

    acceptance_checks = _validate_packet_acceptance_checks(payload, errors)

    command_contract = payload.get("command_contract")
    if not isinstance(command_contract, dict):
        errors.append("command_contract must be an object")
    else:
        errors.extend(_reject_unknown_fields(command_contract, "command_contract", ALLOWED_COMMAND_CONTRACT_FIELDS))
        try:
            expected_command_contract = build_command_contract(load_policy("native-worker-execution"))
        except SystemExit as exc:
            errors.append(str(exc))
        else:
            if command_contract != expected_command_contract:
                errors.append("command_contract must match native-worker checked-command policy")

    has_work_plan = "work_plan" in payload
    has_worker_commitment = "worker_commitment" in payload
    if has_work_plan != has_worker_commitment:
        errors.append("exactly one of work_plan and worker_commitment was provided")
    elif has_work_plan and has_worker_commitment:
        work_plan = payload.get("work_plan")
        worker_commitment = payload.get("worker_commitment")
        precommit_receipt = payload.get("precommit_receipt")
        if version == 2:
            stage = payload.get("stage")
            release_evidence = payload.get("release_evidence")
            release_evidence_sha256 = payload.get("release_evidence_sha256")
            if stage == "precommit-validated":
                expected_contract = {
                    "operative_dispatch_authorized": False,
                    "release_requires": "complex-work-orchestration-fsh.3",
                }
                if release_evidence is not None or release_evidence_sha256 is not None:
                    errors.append("precommit-validated packet must not contain release evidence")
            elif stage in {"canary-authorized", "operative-authorized"}:
                expected_contract = {
                    "operative_dispatch_authorized": stage == "operative-authorized",
                    "release_requires": (release_evidence.get("mission_id") if type(release_evidence) is dict
                        and release_evidence.get("version") == 2 else "complex-work-orchestration-fsh.3.5"),
                }
                if not isinstance(release_evidence, dict):
                    errors.append(f"{stage} packet requires embedded release_evidence")
                else:
                    errors.extend(
                        "release_evidence: " + error
                        for error in validate_native_release_evidence(
                            release_evidence,
                            expected_packet_id=str(payload.get("packet_id") or ""),
                            expected_work_plan_sha256=(
                                canonical_work_estimate_sha256(work_plan)
                                if isinstance(work_plan, dict)
                                else None
                            ),
                            expected_precommit_receipt_sha256=(
                                str(payload.get("precommit_receipt_sha256"))
                                if stage == "operative-authorized"
                                and isinstance(payload.get("precommit_receipt_sha256"), str)
                                else None
                            ),
                            live=dispatchable,
                            maintenance_operation=maintenance_operation,
                            maintenance_verifier=maintenance_verifier,
                        )
                    )
                    if release_evidence.get("release_state") != stage:
                        errors.append("packet stage must match release_evidence.release_state")
                    if release_evidence_sha256 != release_evidence.get("evidence_sha256"):
                        errors.append("release_evidence_sha256 must match embedded release evidence")
            else:
                expected_contract = {}
                errors.append("planned packet stage must be a known release state")
            for field, expected in expected_contract.items():
                if payload.get(field) != expected:
                    errors.append(f"release-state packet {field} must equal {expected!r}")
            if not isinstance(precommit_receipt, dict):
                errors.append("candidate packet requires an embedded precommit_receipt")
            else:
                errors.extend(
                    "precommit_receipt: " + error
                    for error in validate_precommit_receipt(
                        precommit_receipt,
                        work_plan if isinstance(work_plan, dict) else None,
                        operative_routing=(
                            payload.get("operative_routing")
                            if isinstance(payload.get("operative_routing"), dict)
                            else None
                        ),
                        expected_packet_id=str(payload.get("packet_id") or ""),
                        require_accepting=True,
                        current_authority=current_authority,
                    )
                )
                if payload.get("precommit_receipt_sha256") != precommit_receipt.get("receipt_sha256"):
                    errors.append("precommit_receipt_sha256 must match embedded precommit receipt")
            if isinstance(worker_commitment, dict) and worker_commitment.get("decision") != "accept":
                errors.append("precommit-validated candidate packet requires worker_commitment.decision accept")
        errors.extend("work_plan: " + error for error in validate_work_estimate(work_plan))
        errors.extend(
            "worker_commitment: " + error
            for error in validate_worker_commitment(
                worker_commitment,
                work_plan,
                dispatchable=dispatchable,
                precommit_receipt=precommit_receipt if isinstance(precommit_receipt, dict) else None,
                current_authority=current_authority,
            )
        )
        scope_allowed_paths = scope.get("allowed_paths") if isinstance(scope, dict) else None
        if not isinstance(work_plan, dict):
            errors.append("work_plan must be an object")
        else:
            if dispatchable:
                errors.extend(direct_execution_contract_errors(work_plan))
                if work_plan.get("estimate_contract_version") != 2:
                    errors.append("dispatchable work_plan requires estimate_contract_version 2; version 1 is historical-only")
                for field in ("route", "authority_route", "operative_route"):
                    if work_plan.get(field) != "spark":
                        errors.append(f'work_plan.{field} must be "spark" when dispatchable=True')
            for field in ("bead_id", "requested_model"):
                if str(work_plan.get(field, "")) != str(payload.get(field, "")):
                    errors.append(f"work_plan.{field} must match packet.{field}")
            if is_read_only_work_estimate(work_plan):
                if (
                    isinstance(tool_policy, dict)
                    and "apply_patch" in tool_policy.get("permitted_tools", [])
                ):
                    errors.append(
                        "read-only work_plan tool_policy must not permit apply_patch"
                    )
                manifest_paths = [
                    item.get("path")
                    for item in work_plan.get("context_manifest", [])
                    if isinstance(item, dict)
                ]
                if scope_allowed_paths != manifest_paths:
                    errors.append("read-only work_plan context paths must exactly match packet.scope.allowed_paths")
                allowed_actions = scope.get("allowed_actions", []) if isinstance(scope, dict) else []
                prohibited_actions = scope.get("prohibited_actions", []) if isinstance(scope, dict) else []
                if "edit-scoped-files" in allowed_actions or "source-mutation" not in prohibited_actions:
                    errors.append("read-only work_plan must prohibit source mutation")
                evidence = payload.get("release_evidence")
                if isinstance(evidence, dict) and evidence.get("source_mutation_authorized") is not False:
                    errors.append("read-only release must not authorize source mutation")
            elif scope_allowed_paths != work_plan.get("write_paths"):
                errors.append("work_plan.write_paths must exactly match packet.scope.allowed_paths")
            if acceptance_checks != work_plan.get("acceptance_checks"):
                errors.append("work_plan.acceptance_checks must exactly match packet.acceptance_checks")
        if not isinstance(worker_commitment, dict):
            errors.append("worker_commitment must be an object")
    elif dispatchable and version == 2:
        errors.append("dispatchable packet requires work_plan and worker_commitment")
    elif version == 2:
        for field in (
            "stage",
            "operative_dispatch_authorized",
            "release_requires",
            "precommit_receipt",
            "precommit_receipt_sha256",
            "release_evidence",
            "release_evidence_sha256",
        ):
            if field in payload:
                errors.append(f"draft packet without a work plan must not contain {field}")

    errors.extend(
        _validate_checked_command_sequence_receipt(
            payload,
            payload.get("work_plan"),
        )
    )

    policy_budgets = policy_budgets_for_lane(lane) if isinstance(lane, str) else None
    budget = payload.get("budget")
    if not isinstance(budget, dict):
        errors.append("budget must be an object")
    else:
        _validate_packet_budget_entries(budget, policy_budgets, lane, version, errors)
        if dispatchable and isinstance(payload.get("work_plan"), dict):
            work_plan = payload.get("work_plan")
            aggregate_allowance = work_plan.get("aggregate_allowance")
            if not isinstance(aggregate_allowance, dict):
                errors.append("work_plan.aggregate_allowance malformed: must be an object")
            else:
                for field, limit in (
                    ("tool_calls_hard", aggregate_allowance.get("tool_calls_hard")),
                    ("runtime_seconds_hard", aggregate_allowance.get("runtime_seconds_hard")),
                ):
                    if not isinstance(limit, int) or isinstance(limit, bool):
                        errors.append(f"work_plan.aggregate_allowance malformed: {field} must be an integer")
                    elif isinstance(budget.get(field), int) and budget[field] > limit:
                        errors.append(f"budget.{field} exceeds work_plan aggregate allowance")

    if version in {2, 3}:
        _validate_packet_budget_provenance(payload, budget, policy_budgets, lane, errors)
        supervision = payload.get("supervision")
        if not isinstance(supervision, dict):
            errors.append("supervision must be an object for packet version 2")
        else:
            errors.extend(_reject_unknown_fields(supervision, "supervision", ALLOWED_SUPERVISION_FIELDS))
            expected_policy = load_policy("native-worker-execution")
            if supervision.get("required") is not True or supervision.get("mode") != "live-fail-closed":
                errors.append("supervision must require live-fail-closed mode")
            for field, default in (
                ("poll_interval_ms", 1000), ("poll_lag_tolerance_ms", 1500), ("arm_to_dispatch_max_ms", 5000),
            ):
                if supervision.get(field) != int(expected_policy.get(field, default)):
                    errors.append(f"supervision.{field} must match policy")
            if supervision.get("control_turn_required") is not True:
                errors.append("supervision.control_turn_required must be true")
            if supervision.get("segment_start_grace_seconds") != int(expected_policy.get("segment_start_grace_seconds", 10)):
                errors.append("supervision.segment_start_grace_seconds must match policy")
            if supervision.get("control_adapter") != expected_policy.get("required_control_adapter"):
                errors.append("supervision.control_adapter must match policy")
            if supervision.get("required_capabilities") != expected_policy.get("required_capabilities"):
                errors.append("supervision.required_capabilities must match policy")
            thresholds = supervision.get("interrupt_thresholds")
            if not isinstance(thresholds, dict):
                errors.append("supervision.interrupt_thresholds must be an object")
            else:
                errors.extend(_reject_unknown_fields(thresholds, "supervision.interrupt_thresholds", ALLOWED_INTERRUPT_THRESHOLD_FIELDS))
                if isinstance(budget, dict) and all(isinstance(budget.get(key), int) for key in ALLOWED_BUDGET_FIELDS):
                    if thresholds != interrupt_thresholds(budget):
                        errors.append("supervision.interrupt_thresholds must be derived from effective budget")
        lineage = payload.get("validation_lineage")
        if not isinstance(lineage, dict):
            errors.append("validation_lineage must be an object for packet version 2")
        else:
            errors.extend(_reject_unknown_fields(lineage, "validation_lineage", ALLOWED_VALIDATION_LINEAGE_FIELDS))
            attempt = lineage.get("attempt")
            parent = lineage.get("parent_packet_id")
            if attempt not in {0, 1}:
                errors.append("validation_lineage.attempt must be 0 or 1")
            if attempt == 0 and parent is not None:
                errors.append("validation_lineage attempt 0 requires null parent_packet_id")
            if attempt == 1 and not isinstance(parent, str):
                errors.append("validation_lineage attempt 1 requires parent_packet_id")
            if not isinstance(lineage.get("root_packet_id"), str) or not lineage.get("root_packet_id"):
                errors.append("validation_lineage.root_packet_id is required")
            root = lineage.get("root_packet_id")
            packet_id = payload.get("packet_id")
            if attempt == 0 and root != packet_id:
                errors.append("validation_lineage attempt 0 root_packet_id must equal packet_id")
            if attempt == 1 and lane != "validation":
                errors.append("validation_lineage attempt 1 requires validation lane")
            if attempt == 1 and parent != root:
                errors.append("validation_lineage attempt 1 parent_packet_id must equal root_packet_id")
            if attempt == 1 and packet_id in {parent, root}:
                errors.append("validation_lineage attempt 1 cannot reference its own packet_id")

    _validate_packet_escalation(payload, errors)
    _validate_packet_return_contract(payload, errors)

    if version == 3:
        if payload.get("experimental") is not True:
            errors.append("packet-v3 experimental marker must be true")
        phase = payload.get("phase")
        if phase not in PACKET_V3_PHASES:
            errors.append("packet-v3 phase is not supported")
        phase_contract = payload.get("phase_contract")
        errors.extend(validate_packet_v3_phase_contract(phase_contract, phase=phase if isinstance(phase, str) else None))
        recovery = payload.get("recovery_contract")
        if recovery != packet_v3_recovery_contract():
            errors.append("packet-v3 recovery is disabled and must match the foundation contract")
        lineage = payload.get("lineage_contract")
        if not isinstance(lineage, dict):
            errors.append("packet-v3 lineage_contract must be an object")
        elif lineage != payload.get("validation_lineage"):
            errors.append("packet-v3 lineage_contract must match validation_lineage")

    return errors


def _parse_usage_limits(payload: dict[str, Any]) -> list[str]:
    usage = payload.get("usage")
    errors: list[str] = []
    if not isinstance(usage, dict):
        return ["usage must be an object"]
    errors.extend(_reject_unknown_fields(usage, "usage", ALLOWED_RETURN_USAGE_FIELDS))
    for field, validate in (
        ("tool_calls", _required_int), ("elapsed_seconds", _required_non_negative_number),
        ("context_compactions", _required_int), ("full_suite_runs", _required_int),
    ):
        if (error := validate(usage.get(field), f"usage.{field}")) is not None:
            errors.append(error)
    for key in [
        "input_tokens",
        "output_tokens",
        "total_tokens",
        "cached_input_tokens",
        "reasoning_tokens",
    ]:
        if key in usage and (error := _required_int(usage.get(key), f"usage.{key}", minimum=0)) is not None:
            errors.append(error)
    return errors


def _parse_usage_limits_for_completion(usage: dict[str, Any], packet: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    budget = packet.get("budget", {})
    if not isinstance(budget, dict):
        return errors
    for field, limit, budget_label in (
        ("tool_calls", budget.get("tool_calls_hard"), None),
        ("elapsed_seconds", budget.get("runtime_seconds_hard"), None),
        ("context_compactions", budget.get("max_compactions"), "max_compactions"),
        ("full_suite_runs", budget.get("max_full_suite_runs"), "max_full_suite_runs"),
    ):
        if isinstance(limit, int) and usage[field] > limit:
            detail = budget_label or f"hard budget {usage[field]} > {limit}"
            errors.append(f"usage.{field} exceeds {detail}")
    return errors


def validate_native_worker_return(packet: dict[str, Any], result: Any) -> list[str]:
    """Controlled JSON-shape rejection; malformed supplied returns never escape."""
    if type(packet) is not dict:
        return ["packet must be an object"]
    if type(result) is not dict:
        return ["return is not a JSON object"]
    if type(result.get("version")) is not int:
        return ["version must be integer 1"]
    for field in ("status", "mutation_state", "attestation_status", "artifact_disposition", "session_disposition"):
        if field in result and type(result[field]) is not str:
            return [field + " must be a string"]
    try:
        return _validate_native_worker_return_fields(packet, result)
    except (TypeError, ValueError, KeyError, AttributeError, OverflowError) as exc:
        return ["return shape rejected: " + type(exc).__name__ + ": " + str(exc)]


def _validate_native_worker_return_fields(packet: dict[str, Any], result: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(result, dict):
        return ["return is not a JSON object"]
    errors.extend(_reject_unknown_fields(result, "return", ALLOWED_RETURN_FIELDS))
    if len(errors) > 0:
        return errors

    if (error := _required_string_literal(result, "return_type", "cwo-native-worker-return")) is not None:
        errors.append(error)

    if result.get("version") != 1:
        errors.append("version must be 1")

    for field in [
        "packet_id",
        "bead_id",
        "session_id",
        "segment_id",
        "requested_model",
        "attestation_source",
        "attestation_status",
        "completed_evidence",
    ]:
        if (error := _required_nonempty_str(result.get(field), field)) is not None:
            errors.append(error)

    status = result.get("status")
    if not isinstance(status, str):
        errors.append("status must be a string")
    for field in ("packet_id", "bead_id"):
        if packet.get(field) and result.get(field) != packet.get(field):
            errors.append(f"return.{field} must match packet.{field}")
    if result.get("requested_model") != packet.get("requested_model"):
        errors.append("return.requested_model must match packet.requested_model")
    if result.get("mutation_state") not in ALLOWED_MUTATION_STATES:
        errors.append("mutation_state must be clean, modified, committed, or unknown")

    allowed_statuses = packet.get("return_contract", {}).get("allowed_statuses") or _policy_return_statuses()
    if status and status not in allowed_statuses:
        errors.append(f"status {status!r} is not allowed by this packet")

    attestation_status = result.get("attestation_status")
    if attestation_status not in ALLOWED_ATTESTATION_STATUSES:
        errors.append("attestation_status must be one of trusted, missing, mismatch, untrusted, denied")
    if attestation_status == "trusted" and (
        str(result.get("attestation_source", "")).strip() != "trusted-control-plane-session-metadata"
    ):
        errors.append("attestation_source must be trusted-control-plane-session-metadata for trusted status")
    actual_model = result.get("actual_model")
    if status == "completed":
        if actual_model is None:
            errors.append("completed return requires actual_model to be set")
        elif _required_nonempty_str(actual_model, "actual_model") is not None:
            errors.append("actual_model must be a string when return is completed")
        elif actual_model != result.get("requested_model"):
            errors.append("completed return requires exact model match")
    elif status == "model-mismatch":
        if actual_model is None:
            errors.append("model-mismatch return requires actual_model")
        elif _required_nonempty_str(actual_model, "actual_model") is not None:
            errors.append("actual_model must be a non-empty string for model-mismatch")
        elif actual_model == result.get("requested_model"):
            errors.append("model-mismatch status requires actual_model different from requested_model")
    elif actual_model is not None and _required_nonempty_str(actual_model, "actual_model") is not None:
        errors.append("actual_model must be a string or null")

    files = result.get("files_touched")
    normalized_files_errors, normalized_files = _required_string_list(files, "files_touched", min_items=0)
    errors.extend(normalized_files_errors)
    scope = packet.get("scope", {})
    if not isinstance(scope, dict):
        errors.append("packet.scope must be present for files_touched validation")
    else:
        workdir = scope.get("workdir")
        allowed_paths = scope.get("allowed_paths")
        if isinstance(workdir, str) and isinstance(allowed_paths, list):
            normalized_workdir = normalize_workdir(workdir)
            normalized_allowed = _normalize_scope_paths([str(item) for item in allowed_paths], normalized_workdir)
            for item in normalized_files:
                if file_error := _path_in_scope(item, normalized_workdir, normalized_allowed):
                    errors.append(file_error)
        else:
            errors.append("packet.scope.workdir and packet.scope.allowed_paths are required for files_touched checks")

    if not isinstance(result.get("commands_run"), list) or not all(
        isinstance(item, str) and item.strip() for item in result["commands_run"]
    ):
        errors.append("commands_run must be a list of non-empty strings")

    if not isinstance(result.get("validation"), dict):
        errors.append("validation must be an object")

    for field in ("decision_required", "bounded_options"):
        if not isinstance(result.get(field), list):
            errors.append(f"{field} must be a list")
    if not isinstance(result.get("residual_risks"), list):
        errors.append("residual_risks must be a list")
    elif any(not isinstance(item, str) or not item.strip() for item in result["residual_risks"]):
        errors.append("residual_risks must contain non-empty strings")

    if not isinstance(result.get("remaining_scope"), dict):
        errors.append("remaining_scope must be an object")

    errors.extend(_parse_usage_limits(result))
    required_fields = packet.get("return_contract", {}).get("required_fields", [])
    disposition_required = isinstance(required_fields, list) and DISPOSITION_FIELDS.issubset(set(required_fields))
    disposition_result = result
    if status == "needs-replan":
        disposition_result = {**result, "status": "needs-architect-realignment"}
    errors.extend(validate_disposition(packet=packet, result=disposition_result, required=disposition_required))
    if status == "completed":
        completion_usage = result.get("usage")
        if isinstance(completion_usage, dict):
            errors.extend(_parse_usage_limits_for_completion(completion_usage, packet))
        if result.get("attestation_status") != "trusted":
            errors.append("completed return requires attestation_status 'trusted'")
        if result.get("validation") == {}:
            errors.append("completed return requires explicit validation")
        if is_read_only_work_estimate(packet.get("work_plan")):
            if result.get("files_touched") != [] or result.get("mutation_state") != "clean":
                errors.append("read-only work_plan completion requires no files_touched and clean mutation_state")
        try:
            scope = packet["scope"]
            allowed = _normalize_scope_paths(scope.get("allowed_paths", []), normalize_workdir(scope["workdir"]))
            _, paths_for_validation = _required_string_list(
                result.get("files_touched"), "files_touched", min_items=0
            )
            for path in paths_for_validation:
                file_error = _path_in_scope(
                    path,
                    normalize_workdir(scope["workdir"]),
                    allowed,
                )
                if file_error:
                    errors.append(file_error)
        except (TypeError, KeyError, SystemExit):
            pass

    if status in {"needs-replan", "needs-architect-realignment", "budget-exhausted", "model-mismatch"}:
        if not isinstance(result.get("decision_required"), list) or not result["decision_required"]:
            errors.append("decision_required must be non-empty for realignment-like returns")
        bounded_errors, bounded_options = _required_string_list(result.get("bounded_options"), "bounded_options", min_items=1)
        errors.extend(bounded_errors)
        if not bounded_options:
            errors.append("bounded_options must be non-empty for realignment-like returns")
        recommendation = result.get("recommendation")
        if not isinstance(recommendation, str) or not recommendation.strip():
            errors.append("recommendation must be non-empty for realignment-like returns")
        remaining_scope = result.get("remaining_scope")
        if not remaining_scope:
            errors.append("remaining_scope must be non-empty for realignment-like returns")

    if status == "needs-replan":
        replan = result.get("replan")
        errors.extend(validate_needs_replan_payload(replan))
        if result.get("attestation_status") != "trusted":
            errors.append("needs-replan requires trusted attestation")
        if result.get("actual_model") != result.get("requested_model"):
            errors.append("needs-replan requires exact model match")
        if isinstance(replan, dict):
            for field in ("completed_evidence", "files_touched", "mutation_state"):
                if replan.get(field) != result.get(field):
                    errors.append(f"replan.{field} must match {field}")
            option_ids = [
                option.get("option_id")
                for option in replan.get("bounded_options", [])
                if isinstance(option, dict)
            ]
            if result.get("bounded_options") != option_ids:
                errors.append("bounded_options must list the typed replan option ids in order")
            if result.get("recommendation") != replan.get("recommendation"):
                errors.append("recommendation must match replan.recommendation")
            usage = result.get("usage")
            cumulative = replan.get("cumulative_usage")
            if isinstance(usage, dict) and isinstance(cumulative, dict):
                expected_usage = {
                    "tool_calls": usage.get("tool_calls"),
                    "runtime_seconds": usage.get("elapsed_seconds"),
                    "context_compactions": usage.get("context_compactions"),
                    "full_suite_runs": usage.get("full_suite_runs"),
                }
                if cumulative != expected_usage:
                    errors.append("replan.cumulative_usage must match return usage")
                if usage.get("context_compactions") != 0:
                    errors.append("needs-replan is invalid after context compaction")
                aggregate = packet.get("work_plan", {}).get("aggregate_allowance", {})
                if not isinstance(aggregate, dict):
                    aggregate = {}
                budget = packet.get("budget", {}) if isinstance(packet.get("budget"), dict) else {}
                calls_hard = aggregate.get("tool_calls_hard", budget.get("tool_calls_hard"))
                runtime_hard = aggregate.get("runtime_seconds_hard", budget.get("runtime_seconds_hard"))
                calls_used = usage.get("tool_calls")
                runtime_used = usage.get("elapsed_seconds")
                if (
                    isinstance(calls_hard, int)
                    and isinstance(runtime_hard, int)
                    and isinstance(calls_used, int)
                    and not isinstance(calls_used, bool)
                    and isinstance(runtime_used, (int, float))
                    and not isinstance(runtime_used, bool)
                ):
                    calls_remaining = max(0, calls_hard - calls_used)
                    runtime_remaining = max(0, runtime_hard - float(runtime_used))
                    for index, option in enumerate(replan.get("bounded_options", [])):
                        if not isinstance(option, dict) or option.get("route") == "protected-stop":
                            continue
                        option_calls = option.get("tool_calls_p90")
                        option_runtime = option.get("runtime_seconds_p90")
                        if isinstance(option_calls, int) and option_calls > calls_remaining:
                            errors.append(f"replan.bounded_options[{index}] exceeds remaining tool-call allowance")
                        if isinstance(option_runtime, int) and option_runtime > runtime_remaining:
                            errors.append(f"replan.bounded_options[{index}] exceeds remaining runtime allowance")

    if status == "model-mismatch" and result.get("actual_model") == result.get("requested_model"):
        errors.append("model-mismatch status requires actual_model different from requested_model")

    return errors


# The caller validates the packet and its authority before rendering.
def render_worker_packet_prompt(payload: dict[str, Any]) -> str:
    budget = payload["budget"]
    scope = payload["scope"]
    accepted = "\n".join(f"- {check}" for check in payload["acceptance_checks"][:8])
    paths = "\n".join(f"- {path}" for path in scope["allowed_paths"][:8])
    work_plan = payload.get("work_plan")
    task_profile = work_plan.get("task_profile") if isinstance(work_plan, dict) else None
    task_class = task_profile.get("task_class") if isinstance(task_profile, dict) else None
    execution_contract = work_plan_execution_contract(work_plan)
    checked_sequence = payload.get("checked_command_sequence")
    sequence_argv = (
        checked_sequence.get("runner_argv")
        if isinstance(checked_sequence, dict) and isinstance(checked_sequence.get("runner_argv"), list)
        else None
    )
    exact_argv = (
        sequence_argv is None
        and
        isinstance(work_plan, dict)
        and work_plan.get("fit_mode") == "deterministic"
        and task_class in {"literal-command", "read-only-validation"}
        and execution_contract == {"mode": "direct", "checked_command_specs": []}
        and isinstance(task_profile.get("commands"), list)
        and bool(task_profile.get("commands"))
    )
    declared_commands = task_profile.get("commands", []) if exact_argv else []
    primitive_edit = (isinstance(task_profile, dict)
        and task_class == "narrow-mechanical"
        and all(type(task_profile.get(key)) is int and task_profile[key] == 0
                for key in ("command_count", "focused_test_count", "full_suite_count"))
        and task_profile.get("commands") == []
    )
    command_lines = [
        f"{index}. {shlex.join(command['argv'])}"
        for index, command in enumerate(declared_commands, start=1)
        if isinstance(command, dict) and isinstance(command.get("argv"), list)
    ]
    read_only = is_read_only_work_estimate(work_plan)
    triggers = ", ".join(
        f"{key}:{value}" for key, value in payload["escalation_triggers"].items()
    )
    tool_policy = payload["tool_policy"]
    return_skeleton = {
        "return_type": "cwo-native-worker-return",
        "version": 1,
        "packet_id": payload["packet_id"],
        "bead_id": payload["bead_id"],
        "session_id": "<session id>",
        "segment_id": "<segment id>",
        "status": "completed",
        "requested_model": payload["requested_model"],
        "actual_model": payload["requested_model"],
        "attestation_source": "trusted-control-plane-session-metadata",
        "attestation_status": "trusted",
        "completed_evidence": "<why this is complete>",
        "files_touched": [] if read_only else ["<relative/path.ext>"],
        "mutation_state": "clean" if read_only else "modified",
        "commands_run": (
            [shlex.join(sequence_argv)]
            if sequence_argv is not None
            else [shlex.join(command["argv"]) for command in declared_commands]
            if exact_argv
            else ["<command>"]
        ),
        "validation": {"status": "pass"},
        "decision_required": [],
        "bounded_options": [],
        "recommendation": "",
        "remaining_scope": {},
        "usage": {
            "tool_calls": 0,
            "elapsed_seconds": 0.0,
            "context_compactions": 0,
            "full_suite_runs": 0,
        },
        "session_disposition": "accepted",
        "artifact_disposition": "accepted",
        "artifact_validation": {
            "eligible": False,
            "max_attempts": 1,
            "attempts_used": 0,
            "outcome": "not-run",
            "reason": "completed within policy",
        },
        "residual_risks": [],
    }
    lines = [
        "Native Worker Packet Prompt",
        "",
        f"Packet: {payload['packet_id']}",
        f"Bead: {payload['bead_id']}",
        f"Lane: {payload['lane']}",
        f"Model: {payload['requested_model']}",
        "Session policy: fresh session, no-tools attestation, self-report forbidden",
        f"Permitted tools: {', '.join(tool_policy['permitted_tools'])}",
        f"Tool enforcement: {tool_policy['enforcement_mode']}",
        f"Workdir: {scope['workdir']}",
        "Allowed paths:",
        paths,
        "Allowed actions:",
        *[f"- {item}" for item in payload["scope"]["allowed_actions"]],
        "Prohibited actions:",
        *[f"- {item}" for item in payload["scope"]["prohibited_actions"]],
        "Acceptance checks:",
        accepted,
        *(
            [
                "Deterministic execution contract:",
                f"- Task class: {task_class}",
                f"- Run exactly {len(command_lines)} declared commands in order from the packet workdir.",
                "- The first tool call must execute command 1. Do not acknowledge first, inspect helpers or source, run --help, or build wrapper specifications.",
                "- Execute each command directly as the exact argv shown. Do not prepend cd, wrap, rewrite, combine, or add shell syntax.",
                "- The generic checked-command wrapper does not apply to these architect-approved exact argv commands.",
                f"- No exploratory tool calls are permitted; all {len(command_lines)} tool calls are reserved for the declared commands.",
                "Declared exact commands:",
                *command_lines,
            ]
            if exact_argv
            else [
                "Checked sequence execution contract:",
                "- Run exactly one outer sequence runner command from the packet workdir.",
                "- Do not run, rewrite, combine, or bypass any inner command directly.",
                "- The sequence runner persists terminal state and stops after the first nonzero command.",
                "Declared outer runner command:",
                f"1. {shlex.join(sequence_argv)}",
            ]
            if sequence_argv is not None
            else [
                "Primitive edit execution contract:",
                "- No shell test/mutation commands or checked-command specifications are planned for this unit.",
                "- Use the authorized apply_patch primitive for the declared source edit. Do not invent helper specifications, inspect helpers, run --help, or write temporary specification files.",
                "- If source context is needed, a bounded plain source read or scope/diff check may use the authorized exec_command transport; do not combine commands or use interpreter/nested-language forms.",
                "- This profile-specific instruction does not waive checked-command requirements for other work units.",
            ]
            if primitive_edit
            else [
                "Checked command execution:",
                f"- Wrapper: {payload['command_contract']['wrapper']}",
                f"- Approved helper location: {Path(__file__).resolve().parents[2] / payload['command_contract']['wrapper']}. Do not assume the target workspace contains CWO scripts.",
                f"- Typed modes: {', '.join(payload['command_contract']['modes'])}",
                "- An authorized primitive apply_patch tool call does not require a shell checked-command helper. This does not waive checked-command requirements for exec commands.",
                "- Complex commands, interpreter -c forms, nested quoting/languages, and mutation commands must use the checked wrapper.",
                "- A preflight construction failure is PM-recoverable with no source quarantine; hash, scope, security, or mutation-attribution failures quarantine.",
            ]
        ),
        f"Budget: tool-calls hard {budget['tool_calls_hard']} / soft {budget['tool_calls_soft']}, runtime hard {budget['runtime_seconds_hard']}s, max compactions {budget['max_compactions']}, max full-suite {budget['max_full_suite_runs']}",
        f"Live supervision: poll {payload.get('supervision', {}).get('poll_interval_ms')}ms; interrupt thresholds {payload.get('supervision', {}).get('interrupt_thresholds')}",
        f"Validation lineage: {payload.get('validation_lineage')}",
        f"Escalation triggers: {triggers}",
        f"Allowed statuses: {', '.join(payload['return_contract']['allowed_statuses'])}",
        "",
        "Worker instructions:",
        "- Stay within packet scope",
        "- Do not resume prior sessions",
        "- Do not report completion until attestation is trusted",
        *( ["- Do not send acknowledgments or progress messages; run the declared command, then return the artifact"] if exact_argv or sequence_argv is not None else [] ),
        "- Return exactly one compliant cwo-native-worker-return artifact",
        "",
        "Return skeleton (required fields):",
        json.dumps(return_skeleton, indent=2),
    ]
    rendered = "\n".join(lines).strip() + "\n"
    try:
        require_prompt_preflight(rendered, tool_policy)
    except NativeToolIsolationError as exc:
        raise SystemExit(str(exc)) from exc
    return rendered
