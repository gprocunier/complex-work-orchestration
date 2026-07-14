#!/usr/bin/env python3
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
import math
from pathlib import Path
import shlex
from typing import Any

from cwo_core.checked_command_sequence import normalize_sequence_spec
from cwo_core.paths import assert_safe_output_path, cwo_temp_dir, is_cwo_temp_path
from cwo_core.native_disposition import DISPOSITION_FIELDS, validate_disposition
from cwo_core.native_recovery import verify_native_worker_semantics
from cwo_core.native_worker_contracts import (
    ALLOWED_ATTESTATION_FIELDS,
    ALLOWED_ATTESTATION_STATUSES,
    ALLOWED_BUDGET_FIELDS,
    ALLOWED_BUDGET_PROVENANCE_FIELDS,
    ALLOWED_CHECKED_COMMAND_SEQUENCE_FIELDS,
    ALLOWED_COMMAND_CONTRACT_FIELDS,
    ALLOWED_ESCALATION_COMPACTION_FIELDS,
    ALLOWED_ESCALATION_HARD_LIMIT_FIELDS,
    ALLOWED_ESCALATION_SOFT_LIMIT_FIELDS,
    ALLOWED_ESCALATION_TRIGGER_FIELDS,
    ALLOWED_INTERRUPT_THRESHOLD_FIELDS,
    ALLOWED_MUTATION_STATES,
    ALLOWED_PACKET_FIELDS,
    ALLOWED_PACKET_V3_FIELDS,
    ALLOWED_RETURN_CONTRACT_FIELDS,
    ALLOWED_RETURN_FIELDS,
    ALLOWED_RETURN_USAGE_FIELDS,
    ALLOWED_SCOPE_FIELDS,
    ALLOWED_SESSION_POLICY_FIELDS,
    ALLOWED_SUPERVISION_FIELDS,
    ALLOWED_VALIDATION_LINEAGE_FIELDS,
    PACKET_V3_PHASES,
    packet_v3_lineage_contract,
    packet_v3_phase_contract,
    packet_v3_recovery_contract,
    validate_packet_v3_phase_contract,
)
from cwo_core.native_replanning import validate_needs_replan_payload
from cwo_core.policy import load_policy
from cwo_core.util import atomic_write_text, make_dispatch_id
from cwo_core.work_sizing import (
    build_policy_fit_commitment,
    canonical_work_estimate_sha256,
    validate_work_estimate,
    validate_worker_commitment,
)

REQUESTED_MODEL = "gpt-5.3-codex-spark"
NATIVE_WORKER_POLICY_PATH = "policy/native-worker-execution.yaml"
NATIVE_WORKER_PACKET_SCHEMA = "schemas/native-worker-packet.schema.json"
NATIVE_WORKER_RETURN_SCHEMA = "schemas/native-worker-return.schema.json"
NATIVE_WORK_PLAN_SCHEMA = "schemas/native-work-estimate.schema.json"
NATIVE_WORKER_COMMITMENT_SCHEMA = "schemas/native-worker-commitment.schema.json"


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


def _load_alignment_triggers() -> dict[str, Any]:
    policy = load_policy("native-worker-execution").get("alignment_triggers", {})
    needs_architect = policy.get("needs_architect_realignment")
    if not isinstance(needs_architect, dict):
        raise SystemExit("policy missing alignment_triggers.needs_architect_realignment")
    return needs_architect


def _policy_model_config() -> dict[str, Any]:
    policy = load_policy("native-worker-execution")
    worker = policy.get("governance", {}).get("native_operative_worker", {})
    if not isinstance(worker, dict):
        raise SystemExit("policy missing governance.native_operative_worker")
    preferred = str(worker.get("preferred_model") or "").strip()
    authorized = worker.get("authorized_models")
    if not preferred:
        raise SystemExit("policy missing governance.native_operative_worker.preferred_model")
    if not isinstance(authorized, list) or not authorized:
        raise SystemExit("policy missing governance.native_operative_worker.authorized_models")
    models = [str(item).strip() for item in authorized if str(item).strip()]
    if preferred not in models:
        raise SystemExit("preferred native operative model must be authorized")
    if worker.get("fallback_selection") != "explicit-only":
        raise SystemExit("native operative fallback selection must be explicit-only")
    return {"preferred_model": preferred, "authorized_models": models}


def _policy_models() -> list[str]:
    return list(_policy_model_config()["authorized_models"])


def _policy_model(requested_model: str | None = None) -> str:
    config = _policy_model_config()
    selected = str(requested_model or config["preferred_model"]).strip()
    if selected not in config["authorized_models"]:
        allowed = ", ".join(config["authorized_models"])
        raise SystemExit(f"requested native operative model {selected!r} is not authorized; allowed: {allowed}")
    return selected


def _policy_lanes() -> list[str]:
    return sorted(load_policy("native-worker-execution").get("lane_budgets", {}).keys())


def _policy_budgets_for_lane(lane: str) -> dict[str, int]:
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


def _effective_budget(lane: str, overrides: dict[str, int] | None = None) -> tuple[dict[str, int], list[str]]:
    policy_budget = _policy_budgets_for_lane(lane)
    effective = dict(policy_budget)
    changed: list[str] = []
    for field, value in (overrides or {}).items():
        if field not in ALLOWED_BUDGET_FIELDS:
            raise SystemExit(f"unknown budget override {field!r}")
        if not isinstance(value, int) or value < 0:
            raise SystemExit(f"budget override {field} must be a non-negative integer")
        if value > policy_budget[field]:
            raise SystemExit(f"budget override {field} may only tighten the {lane!r} profile")
        if value != policy_budget[field]:
            effective[field] = value
            changed.append(field)
    if effective["tool_calls_hard"] < 5:
        raise SystemExit("budget override tool_calls_hard must be at least 5")
    if effective["tool_calls_soft"] > effective["tool_calls_hard"]:
        raise SystemExit("budget override tool_calls_soft must not exceed tool_calls_hard")
    if effective["runtime_seconds_soft"] > effective["runtime_seconds_hard"]:
        raise SystemExit("budget override runtime_seconds_soft must not exceed runtime_seconds_hard")
    return effective, sorted(changed)


def _interrupt_thresholds(budget: dict[str, int]) -> dict[str, int]:
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


def _normalize_workdir(workdir: str) -> Path:
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


def _normalize_allowed_paths(paths: list[Any], workdir: Path) -> list[str]:
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


def _build_session_policy(requested_model: str) -> dict[str, Any]:
    policy = load_policy("native-worker-execution")
    spawn = policy.get("execution_bootstrap", {}).get("spawn", {}).get("attestation_gate", {})
    if not isinstance(spawn, dict):
        raise SystemExit("policy missing execution_bootstrap.spawn.attestation_gate")
    return {
        "fresh_session_required": True,
        "resume_forbidden": True,
        "attestation": {
            "required": bool(spawn.get("required", True)),
            "tool_mode": str(spawn.get("tool_mode", "no-tools")),
            "model_authority": str(spawn.get("model_authority", "trusted-control-plane-session-metadata")),
            "self_report_authority": str(spawn.get("self_report_authority", "forbidden")),
            "required_actual_model": requested_model,
        },
        "source": NATIVE_WORKER_POLICY_PATH,
    }


def _build_escalation_triggers() -> dict[str, Any]:
    needs_architect = _load_alignment_triggers()
    return {
        "scope_ambiguity": "needs-architect-realignment",
        "architecture_ambiguity": "needs-architect-realignment",
        "security_ambiguity": "needs-architect-realignment",
        "policy_ambiguity": "needs-architect-realignment",
        "soft_limit": {
            "distinct_soft_limits_required": int(needs_architect.get("distinct_soft_limits_required", 2)),
        },
        "hard_limit": {
            "any_hard_limit": str(needs_architect.get("any_hard_limit", "realignment")),
            "status": str(needs_architect.get("status", "needs-architect-realignment")),
        },
        "compaction": {
            "any_compaction": str(needs_architect.get("any_compaction", "hard-stop/realignment")),
            "status": str(needs_architect.get("status", "needs-architect-realignment")),
        },
    }


def _build_return_contract() -> dict[str, Any]:
    policy = load_policy("native-worker-execution")
    return_contract = policy.get("realignment_return_contract", {})
    required_fields = return_contract.get("required_fields", [])
    return {
        "allowed_statuses": list(policy.get("return_statuses", [])),
        "required_fields": [
            "completed_evidence",
            "files_touched",
            "mutation_state",
            "commands_run",
            "validation",
            "session_disposition",
            "artifact_disposition",
            "artifact_validation",
            "decision_required",
            "bounded_options",
            "recommendation",
            "remaining_scope",
            "usage",
            "residual_risks",
        ],
        "realignment_required_fields": required_fields,
    }


def _build_command_contract(policy: dict[str, Any]) -> dict[str, Any]:
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


def _read_only_work_plan(work_plan: Any) -> bool:
    return (
        isinstance(work_plan, dict)
        and work_plan.get("task_class") in {"literal-command", "read-only-validation"}
        and work_plan.get("fit_mode") == "deterministic"
        and work_plan.get("write_paths") == []
    )


def _execution_contract(work_plan: Any) -> dict[str, Any] | None:
    if not isinstance(work_plan, dict):
        return None
    task_profile = work_plan.get("task_profile")
    if not isinstance(task_profile, dict):
        return None
    contract = task_profile.get("execution_contract")
    return contract if isinstance(contract, dict) else None


def _canonical_json_sha256(value: Any) -> str:
    rendered = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(rendered.encode("utf-8")).hexdigest()


def _build_checked_command_sequence(
    *,
    packet_id: str,
    work_plan: dict[str, Any],
    workdir: Path,
) -> dict[str, Any] | None:
    contract = _execution_contract(work_plan)
    if not contract or contract.get("mode") != "checked-sequence-v1":
        return None

    artifact_dir = cwo_temp_dir(purpose=f"checked-sequence-{packet_id}")
    spec_path = artifact_dir / "sequence-spec.json"
    state_path = artifact_dir / "sequence-state.json"
    output_path = artifact_dir / "sequence-result.json"
    spec = normalize_sequence_spec(
        {
            "spec_type": "cwo-checked-command-sequence-spec",
            "version": 1,
            "sequence_id": f"sequence-{packet_id}",
            "packet_id": packet_id,
            "work_plan_sha256": canonical_work_estimate_sha256(work_plan),
            "workdir": str(workdir),
            "commands": contract.get("checked_command_specs"),
        }
    )
    atomic_write_text(spec_path, json.dumps(spec, indent=2, sort_keys=True) + "\n")
    return {
        "mode": "checked-sequence-v1",
        "spec": spec,
        "spec_path": str(spec_path),
        "spec_sha256": _canonical_json_sha256(spec),
        "state_path": str(state_path),
        "output_path": str(output_path),
        "runner_argv": [
            "python3",
            "scripts/run_checked_command_sequence.py",
            str(spec_path),
            "--state",
            str(state_path),
            "--output",
            str(output_path),
        ],
    }


def build_native_worker_packet(
    *,
    bead_id: str,
    lane: str,
    workdir: str,
    allowed_paths: list[str],
    acceptance_checks: list[str],
    work_plan: dict[str, Any] | None = None,
    worker_commitment: dict[str, Any] | None = None,
    trusted_session_id: str | None = None,
    attested_model: str | None = None,
    packet_id: str | None = None,
    budget_overrides: dict[str, int] | None = None,
    validation_root_packet_id: str | None = None,
    validation_parent_packet_id: str | None = None,
    validation_attempt: int = 0,
    requested_model: str | None = None,
    packet_version: int = 2,
    experimental_v3: bool = False,
    phase: str | None = None,
) -> dict[str, Any]:
    if not str(bead_id).strip():
        raise SystemExit("bead-id must be non-empty")
    if lane not in _policy_lanes():
        raise SystemExit(f"unknown lane {lane!r}")
    if packet_version not in {2, 3}:
        raise SystemExit("packet_version must be 2 or 3")
    if packet_version == 3 and not experimental_v3:
        raise SystemExit("packet version 3 requires explicit experimental_v3=True")
    if packet_version == 2 and experimental_v3:
        raise SystemExit("experimental_v3 requires packet_version 3")
    acceptance_checks = [check.strip() for check in acceptance_checks]
    if not acceptance_checks:
        raise SystemExit("at least one --acceptance-check is required")
    if any(not check.strip() for check in acceptance_checks):
        raise SystemExit("acceptance_check values must be non-empty")
    if work_plan is None and (
        worker_commitment is not None or trusted_session_id is not None or attested_model is not None
    ):
        raise SystemExit("worker commitment or trusted attestation requires a work_plan")
    if work_plan is not None and worker_commitment is None:
        if not trusted_session_id or not attested_model:
            raise SystemExit(
                "work_plan without worker_commitment requires trusted_session_id and attested_model for deterministic policy fit"
            )
        try:
            worker_commitment = build_policy_fit_commitment(
                work_plan,
                session_id=trusted_session_id,
                attested_model=attested_model,
            )
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
    elif worker_commitment is not None and (trusted_session_id is not None or attested_model is not None):
        raise SystemExit("trusted attestation arguments cannot accompany an explicit worker_commitment")
    workdir_path = _normalize_workdir(workdir)
    normalized_paths = _normalize_allowed_paths(allowed_paths, workdir_path)
    packet_id = packet_id or make_dispatch_id(bead_id)
    selected_model = _policy_model(requested_model)
    budget, overridden_fields = _effective_budget(lane, budget_overrides)
    policy = load_policy("native-worker-execution")
    if validation_attempt not in {0, 1}:
        raise SystemExit("validation_attempt must be 0 or 1")
    if validation_attempt == 1 and not validation_parent_packet_id:
        raise SystemExit("validation attempt 1 requires a parent packet id")
    if validation_attempt == 1 and not validation_root_packet_id:
        raise SystemExit("validation attempt 1 requires an explicit root packet id")
    if validation_attempt == 0 and validation_parent_packet_id:
        raise SystemExit("validation attempt 0 cannot have a parent packet id")
    root_packet_id = validation_root_packet_id or packet_id
    read_only_plan = _read_only_work_plan(work_plan)
    if validation_attempt == 0 and root_packet_id != packet_id:
        raise SystemExit("validation attempt 0 root packet id must equal packet id")
    if validation_attempt == 1 and lane != "validation":
        raise SystemExit("validation attempt 1 requires the validation lane")
    if validation_attempt == 1 and validation_parent_packet_id != root_packet_id:
        raise SystemExit("validation attempt 1 parent packet id must equal root packet id")
    if validation_attempt == 1 and packet_id in {root_packet_id, validation_parent_packet_id}:
        raise SystemExit("validation attempt 1 cannot reference itself")
    packet = {
        "packet_type": "cwo-native-worker-packet",
        "version": packet_version,
        "packet_id": packet_id,
        "bead_id": bead_id,
        "lane": lane,
        "requested_model": selected_model,
        "session_policy": _build_session_policy(selected_model),
        "scope": {
            "workdir": str(workdir_path),
            "allowed_paths": normalized_paths,
            "allowed_actions": [
                "read-assigned-bead",
                "run-tests-in-scope",
                "write-packaged-artifacts",
            ] if read_only_plan else [
                "read-assigned-bead",
                "edit-scoped-files",
                "run-tests-in-scope",
                "write-packaged-artifacts",
            ],
            "prohibited_actions": [
                "resume-previous-session",
                "trust-self-reported-model",
                "write-out-of-scope",
                "model-override",
                *(["source-mutation"] if read_only_plan else []),
            ],
        },
        "acceptance_checks": acceptance_checks,
        "budget": budget,
        "budget_provenance": {
            "profile": lane,
            "policy_source": NATIVE_WORKER_POLICY_PATH,
            "overrides_applied": bool(overridden_fields),
            "overridden_fields": overridden_fields,
        },
        "supervision": {
            "required": True,
            "mode": "live-fail-closed",
            "poll_interval_ms": int(policy.get("poll_interval_ms", 1000)),
            "poll_lag_tolerance_ms": int(policy.get("poll_lag_tolerance_ms", 1500)),
            "arm_to_dispatch_max_ms": int(policy.get("arm_to_dispatch_max_ms", 5000)),
            "control_turn_required": policy.get("control_turn_required") is True,
            "segment_start_grace_seconds": int(policy.get("segment_start_grace_seconds", 10)),
            "control_adapter": str(policy.get("required_control_adapter", "native-multi-agent-v1")),
            "required_capabilities": list(policy.get("required_capabilities", ["interrupt", "close", "wait"])),
            "interrupt_thresholds": _interrupt_thresholds(budget),
        },
        "validation_lineage": {
            "root_packet_id": root_packet_id,
            "parent_packet_id": validation_parent_packet_id,
            "attempt": validation_attempt,
        },
        "escalation_triggers": _build_escalation_triggers(),
        "return_contract": _build_return_contract(),
        "command_contract": _build_command_contract(policy),
    }
    if work_plan is not None and worker_commitment is not None:
        packet["work_plan"] = deepcopy(work_plan)
        packet["worker_commitment"] = deepcopy(worker_commitment)
        checked_sequence = _build_checked_command_sequence(
            packet_id=packet_id,
            work_plan=packet["work_plan"],
            workdir=workdir_path,
        )
        if checked_sequence is not None:
            packet["checked_command_sequence"] = checked_sequence
    if packet_version == 3:
        selected_phase = phase or lane
        if selected_phase not in PACKET_V3_PHASES:
            raise SystemExit("packet-v3 phase must be review, implementation, validation, or publish/report/admin")
        packet.update(
            {
                "experimental": True,
                "phase": selected_phase,
                "phase_contract": packet_v3_phase_contract(selected_phase),
                "recovery_contract": packet_v3_recovery_contract(),
                "lineage_contract": packet_v3_lineage_contract(
                    packet_id,
                    root_packet_id=root_packet_id,
                    parent_packet_id=validation_parent_packet_id,
                    attempt=validation_attempt,
                ),
            }
        )
    errors = validate_native_worker_packet(packet, experimental=(packet_version == 3))
    if errors:
        raise SystemExit("packet validation failed:\n- " + "\n- ".join(errors))
    return packet


def _validate_checked_command_sequence_receipt(
    payload: dict[str, Any],
    work_plan: Any,
) -> list[str]:
    errors: list[str] = []
    contract = _execution_contract(work_plan)
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


def validate_native_worker_packet(
    payload: Any,
    *,
    dispatchable: bool = False,
    experimental: bool = False,
    allow_experimental_v3: bool | None = None,
) -> list[str]:
    errors: list[str] = []
    if not isinstance(payload, dict):
        return ["packet is not a JSON object"]
    if allow_experimental_v3 is not None:
        experimental = allow_experimental_v3
    version = payload.get("version")
    allowed_packet_fields = ALLOWED_PACKET_V3_FIELDS if version == 3 else ALLOWED_PACKET_FIELDS
    errors.extend(_reject_unknown_fields(payload, "packet", allowed_packet_fields))
    if len(errors) > 0:
        return errors

    if (value := _required_nonempty_str(payload.get("packet_type"), "packet_type")) is not None:
        errors.append(value)
    elif payload["packet_type"] != "cwo-native-worker-packet":
        errors.append("packet_type must be cwo-native-worker-packet")

    if version not in {1, 2, 3}:
        errors.append("version must be 1, 2, or 3")
    if version == 3 and not experimental:
        errors.append("packet version 3 requires explicit experimental validation")
    if dispatchable and version != 2:
        errors.append(f"packet version {version} is dispatch-forbidden")

    if (error := _required_nonempty_str(payload.get("packet_id"), "packet_id")) is not None:
        errors.append(error)
    if (error := _required_nonempty_str(payload.get("bead_id"), "bead_id")) is not None:
        errors.append(error)

    lane = payload.get("lane")
    if str(lane) not in _policy_lanes():
        errors.append("lane is not a known native-worker lane")

    if (error := _required_nonempty_str(payload.get("requested_model"), "requested_model")) is not None:
        errors.append(error)
    elif payload["requested_model"] not in _policy_models():
        errors.append("requested_model must be an authorized native operative model")

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
            if (error := _required_nonempty_str(attestation.get("tool_mode"), "session_policy.attestation.tool_mode")) is not None:
                errors.append(error)
            elif attestation["tool_mode"] != "no-tools":
                errors.append("session_policy.attestation.tool_mode must be no-tools")
            if (error := _required_nonempty_str(attestation.get("model_authority"), "session_policy.attestation.model_authority")) is not None:
                errors.append(error)
            elif attestation["model_authority"] != "trusted-control-plane-session-metadata":
                errors.append("session_policy.attestation.model_authority must be trusted-control-plane-session-metadata")
            if (error := _required_nonempty_str(attestation.get("self_report_authority"), "session_policy.attestation.self_report_authority")) is not None:
                errors.append(error)
            elif attestation["self_report_authority"] != "forbidden":
                errors.append("session_policy.attestation.self_report_authority must be forbidden")
            if (error := _required_nonempty_str(attestation.get("required_actual_model"), "session_policy.attestation.required_actual_model")) is not None:
                errors.append(error)
            elif attestation["required_actual_model"] != payload.get("requested_model"):
                errors.append("session_policy.attestation.required_actual_model must match packet.requested_model")
        if (error := _required_nonempty_str(session_policy.get("source"), "session_policy.source")) is not None:
            errors.append(error)
        elif session_policy["source"] != NATIVE_WORKER_POLICY_PATH:
            errors.append("session_policy.source must be policy/native-worker-execution.yaml")

    scope = payload.get("scope")
    if not isinstance(scope, dict):
        errors.append("scope must be an object")
    else:
        errors.extend(_reject_unknown_fields(scope, "scope", ALLOWED_SCOPE_FIELDS))
        if (error := _required_nonempty_str(scope.get("workdir"), "scope.workdir")) is not None:
            errors.append(error)
        else:
            workdir = _normalize_workdir(str(scope["workdir"]))
            allowed_paths = scope.get("allowed_paths")
            normalized_path_errors, normalized = _required_string_list(
                allowed_paths, "scope.allowed_paths"
            )
            if normalized_path_errors:
                errors.extend(normalized_path_errors)
            if not normalized:
                errors.append("scope.allowed_paths must contain at least one path")
            else:
                for item in normalized:
                    if str(item).strip().startswith("/"):
                        # Absolute path must stay in workdir
                        abs_path = _resolve_existing_or_future_path(item)
                        try:
                            abs_path.relative_to(workdir)
                        except ValueError:
                            errors.append("scope.allowed_paths contains absolute path outside workdir")
                    if ".." in Path(item).parts:
                        errors.append("scope.allowed_paths contains path traversal components")
                    normalized_path = _normalize_allowed_path(item, workdir, set())
                    _ = normalized_path
            allowed_action_errors, allowed_actions = _required_string_list(
                scope.get("allowed_actions"), "scope.allowed_actions"
            )
            errors.extend(allowed_action_errors)
            if allowed_actions:
                for action in allowed_actions:
                    if _required_nonempty_str(action, "scope.allowed_actions item") is not None:
                        errors.append(_required_nonempty_str(action, "scope.allowed_actions item") or "")
            prohibited_action_errors, prohibited_actions = _required_string_list(
                scope.get("prohibited_actions"), "scope.prohibited_actions", min_items=0
            )
            errors.extend(prohibited_action_errors)
            if prohibited_actions:
                for action in prohibited_actions:
                    if _required_nonempty_str(action, "scope.prohibited_actions item") is not None:
                        errors.append(_required_nonempty_str(action, "scope.prohibited_actions item") or "")

    acceptance_errors, acceptance_checks = _required_string_list(
        payload.get("acceptance_checks"), "acceptance_checks"
    )
    if acceptance_errors:
        errors.extend(acceptance_errors)
    elif not acceptance_checks:
        errors.append("acceptance_checks must contain at least one check")

    command_contract = payload.get("command_contract")
    if not isinstance(command_contract, dict):
        errors.append("command_contract must be an object")
    else:
        errors.extend(_reject_unknown_fields(command_contract, "command_contract", ALLOWED_COMMAND_CONTRACT_FIELDS))
        try:
            expected_command_contract = _build_command_contract(load_policy("native-worker-execution"))
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
        errors.extend("work_plan: " + error for error in validate_work_estimate(work_plan))
        errors.extend(
            "worker_commitment: " + error
            for error in validate_worker_commitment(
                worker_commitment,
                work_plan,
                dispatchable=dispatchable,
            )
        )
        scope_allowed_paths = scope.get("allowed_paths") if isinstance(scope, dict) else None
        if not isinstance(work_plan, dict):
            errors.append("work_plan must be an object")
        else:
            if dispatchable and work_plan.get("estimate_contract_version") != 2:
                errors.append("dispatchable work_plan requires estimate_contract_version 2; version 1 is historical-only")
            if dispatchable and work_plan.get("route") != "spark":
                errors.append("work_plan.route must be \"spark\" when dispatchable=True")
            if dispatchable and work_plan.get("authority_route") != "spark":
                errors.append("work_plan.authority_route must be \"spark\" when dispatchable=True")
            if dispatchable and work_plan.get("operative_route") != "spark":
                errors.append("work_plan.operative_route must be \"spark\" when dispatchable=True")
            if str(work_plan.get("bead_id", "")) != str(payload.get("bead_id", "")):
                errors.append("work_plan.bead_id must match packet.bead_id")
            if str(work_plan.get("requested_model", "")) != str(payload.get("requested_model", "")):
                errors.append("work_plan.requested_model must match packet.requested_model")
            if _read_only_work_plan(work_plan):
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
            elif scope_allowed_paths != work_plan.get("write_paths"):
                errors.append("work_plan.write_paths must exactly match packet.scope.allowed_paths")
            if acceptance_checks != work_plan.get("acceptance_checks"):
                errors.append("work_plan.acceptance_checks must exactly match packet.acceptance_checks")
        if not isinstance(worker_commitment, dict):
            errors.append("worker_commitment must be an object")
    elif dispatchable and version == 2:
        errors.append("dispatchable packet requires work_plan and worker_commitment")

    errors.extend(
        _validate_checked_command_sequence_receipt(
            payload,
            payload.get("work_plan"),
        )
    )

    policy_budgets = _policy_budgets_for_lane(lane) if isinstance(lane, str) else None
    budget = payload.get("budget")
    if not isinstance(budget, dict):
        errors.append("budget must be an object")
    else:
        errors.extend(_reject_unknown_fields(budget, "budget", ALLOWED_BUDGET_FIELDS))
        if policy_budgets is not None:
            for key, value in policy_budgets.items():
                if (error := _required_int(budget.get(key), f"budget.{key}")) is not None:
                    errors.append(error)
                elif version == 1 and budget[key] != value:
                    errors.append(f"budget.{key} must equal policy profile for lane {lane!r}")
                elif version == 2 and budget[key] > value:
                    errors.append(f"budget.{key} may only tighten policy profile for lane {lane!r}")
        if version == 2 and isinstance(budget.get("tool_calls_hard"), int) and budget["tool_calls_hard"] < 5:
            errors.append("budget.tool_calls_hard must be at least 5")
        if isinstance(budget.get("tool_calls_soft"), int) and isinstance(budget.get("tool_calls_hard"), int) and budget["tool_calls_soft"] > budget["tool_calls_hard"]:
            errors.append("budget.tool_calls_soft must not exceed budget.tool_calls_hard")
        if isinstance(budget.get("runtime_seconds_soft"), int) and isinstance(budget.get("runtime_seconds_hard"), int) and budget["runtime_seconds_soft"] > budget["runtime_seconds_hard"]:
            errors.append("budget.runtime_seconds_soft must not exceed budget.runtime_seconds_hard")
        if dispatchable and isinstance(payload.get("work_plan"), dict):
            work_plan = payload.get("work_plan")
            aggregate_allowance = work_plan.get("aggregate_allowance")
            if not isinstance(aggregate_allowance, dict):
                errors.append("work_plan.aggregate_allowance malformed: must be an object")
            else:
                work_plan_tool_calls_hard = aggregate_allowance.get("tool_calls_hard")
                work_plan_runtime_seconds_hard = aggregate_allowance.get("runtime_seconds_hard")
                if not isinstance(work_plan_tool_calls_hard, int) or isinstance(work_plan_tool_calls_hard, bool):
                    errors.append(
                        "work_plan.aggregate_allowance malformed: tool_calls_hard must be an integer"
                    )
                elif (
                    isinstance(budget.get("tool_calls_hard"), int)
                    and budget["tool_calls_hard"] > work_plan_tool_calls_hard
                ):
                    errors.append("budget.tool_calls_hard exceeds work_plan aggregate allowance")
                if not isinstance(work_plan_runtime_seconds_hard, int) or isinstance(
                    work_plan_runtime_seconds_hard, bool
                ):
                    errors.append(
                        "work_plan.aggregate_allowance malformed: runtime_seconds_hard must be an integer"
                    )
                elif (
                    isinstance(budget.get("runtime_seconds_hard"), int)
                    and budget["runtime_seconds_hard"] > work_plan_runtime_seconds_hard
                ):
                    errors.append("budget.runtime_seconds_hard exceeds work_plan aggregate allowance")

    if version in {2, 3}:
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
        supervision = payload.get("supervision")
        if not isinstance(supervision, dict):
            errors.append("supervision must be an object for packet version 2")
        else:
            errors.extend(_reject_unknown_fields(supervision, "supervision", ALLOWED_SUPERVISION_FIELDS))
            expected_policy = load_policy("native-worker-execution")
            if supervision.get("required") is not True or supervision.get("mode") != "live-fail-closed":
                errors.append("supervision must require live-fail-closed mode")
            if supervision.get("poll_interval_ms") != int(expected_policy.get("poll_interval_ms", 1000)):
                errors.append("supervision.poll_interval_ms must match policy")
            if supervision.get("poll_lag_tolerance_ms") != int(expected_policy.get("poll_lag_tolerance_ms", 1500)):
                errors.append("supervision.poll_lag_tolerance_ms must match policy")
            if supervision.get("arm_to_dispatch_max_ms") != int(expected_policy.get("arm_to_dispatch_max_ms", 5000)):
                errors.append("supervision.arm_to_dispatch_max_ms must match policy")
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
                    if thresholds != _interrupt_thresholds(budget):
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

    escalation = payload.get("escalation_triggers")
    if not isinstance(escalation, dict):
        errors.append("escalation_triggers must be an object")
    else:
        errors.extend(_reject_unknown_fields(escalation, "escalation_triggers", ALLOWED_ESCALATION_TRIGGER_FIELDS))
        align = _load_alignment_triggers()
        for key in [
            "scope_ambiguity",
            "architecture_ambiguity",
            "security_ambiguity",
            "policy_ambiguity",
        ]:
            if str(escalation.get(key)) != "needs-architect-realignment":
                errors.append(f"escalation_triggers.{key} must be needs-architect-realignment")
        soft_limit = escalation.get("soft_limit")
        if not isinstance(soft_limit, dict):
            errors.append("escalation_triggers.soft_limit must be an object")
        else:
            errors.extend(
                _reject_unknown_fields(
                    soft_limit, "escalation_triggers.soft_limit", ALLOWED_ESCALATION_SOFT_LIMIT_FIELDS
                )
            )
            if soft_limit.get("distinct_soft_limits_required") != int(align.get("distinct_soft_limits_required", 2)):
                errors.append("escalation_triggers.soft_limit.distinct_soft_limits_required must be 2")
        hard_limit = escalation.get("hard_limit")
        if not isinstance(hard_limit, dict):
            errors.append("escalation_triggers.hard_limit must be an object")
        else:
            errors.extend(
                _reject_unknown_fields(
                    hard_limit, "escalation_triggers.hard_limit", ALLOWED_ESCALATION_HARD_LIMIT_FIELDS
                )
            )
            if hard_limit.get("any_hard_limit") != str(align.get("any_hard_limit", "realignment")):
                errors.append("escalation_triggers.hard_limit.any_hard_limit must be realignment")
            if hard_limit.get("status") != str(align.get("status", "needs-architect-realignment")):
                errors.append("escalation_triggers.hard_limit.status must be needs-architect-realignment")
        compaction = escalation.get("compaction")
        if not isinstance(compaction, dict):
            errors.append("escalation_triggers.compaction must be an object")
        else:
            errors.extend(
                _reject_unknown_fields(
                    compaction,
                    "escalation_triggers.compaction",
                    ALLOWED_ESCALATION_COMPACTION_FIELDS,
                )
            )
            if compaction.get("any_compaction") != str(align.get("any_compaction", "hard-stop/realignment")):
                errors.append("escalation_triggers.compaction.any_compaction must be hard-stop/realignment")
            if compaction.get("status") != str(align.get("status", "needs-architect-realignment")):
                errors.append("escalation_triggers.compaction.status must be needs-architect-realignment")
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


def build_native_worker_packet_v3(**kwargs: Any) -> dict[str, Any]:
    """Explicit experimental/test-only packet-v3 construction path."""
    kwargs["packet_version"] = 3
    kwargs["experimental_v3"] = True
    return build_native_worker_packet(**kwargs)


def _parse_usage_limits(payload: dict[str, Any]) -> list[str]:
    usage = payload.get("usage")
    errors: list[str] = []
    if not isinstance(usage, dict):
        return ["usage must be an object"]
    errors.extend(_reject_unknown_fields(usage, "usage", ALLOWED_RETURN_USAGE_FIELDS))
    for field in ["tool_calls", "elapsed_seconds", "context_compactions", "full_suite_runs"]:
        if field == "elapsed_seconds":
            if (error := _required_non_negative_number(usage.get(field), f"usage.{field}")) is not None:
                errors.append(error)
        else:
            if (error := _required_int(usage.get(field), f"usage.{field}")) is not None:
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
    hard_tool_calls = budget.get("tool_calls_hard")
    hard_runtime = budget.get("runtime_seconds_hard")
    max_compactions = budget.get("max_compactions")
    max_full_suite_runs = budget.get("max_full_suite_runs")
    if isinstance(hard_tool_calls, int) and usage["tool_calls"] > hard_tool_calls:
        errors.append(
            f"usage.tool_calls exceeds hard budget {usage['tool_calls']} > {hard_tool_calls}"
        )
    if isinstance(hard_runtime, int) and usage["elapsed_seconds"] > hard_runtime:
        errors.append(
            f"usage.elapsed_seconds exceeds hard budget {usage['elapsed_seconds']} > {hard_runtime}"
        )
    if isinstance(max_compactions, int) and usage["context_compactions"] > max_compactions:
        errors.append("usage.context_compactions exceeds max_compactions")
    if isinstance(max_full_suite_runs, int) and usage["full_suite_runs"] > max_full_suite_runs:
        errors.append("usage.full_suite_runs exceeds max_full_suite_runs")
    return errors


def validate_native_worker_return(packet: dict[str, Any], result: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(result, dict):
        return ["return is not a JSON object"]
    errors.extend(_reject_unknown_fields(result, "return", ALLOWED_RETURN_FIELDS))
    if len(errors) > 0:
        return errors

    if (error := _required_nonempty_str(result.get("return_type"), "return_type")) is not None:
        errors.append(error)
    elif result["return_type"] != "cwo-native-worker-return":
        errors.append("return_type must be cwo-native-worker-return")

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
    if packet.get("packet_id") and result.get("packet_id") != packet.get("packet_id"):
        errors.append("return.packet_id must match packet.packet_id")
    if packet.get("bead_id") and result.get("bead_id") != packet.get("bead_id"):
        errors.append("return.bead_id must match packet.bead_id")
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
    if normalized_files_errors:
        errors.extend(normalized_files_errors)
    if isinstance(normalized_files, list):
        scope = packet.get("scope", {})
        if not isinstance(scope, dict):
            errors.append("packet.scope must be present for files_touched validation")
        else:
            workdir = scope.get("workdir")
            allowed_paths = scope.get("allowed_paths")
            if isinstance(workdir, str) and isinstance(allowed_paths, list):
                normalized_workdir = _normalize_workdir(workdir)
                normalized_allowed = _normalize_scope_paths([str(item) for item in allowed_paths], normalized_workdir)
                for item in normalized_files:
                    file_error = _path_in_scope(item, normalized_workdir, normalized_allowed)
                    if file_error:
                        errors.append(file_error)
            else:
                errors.append("packet.scope.workdir and packet.scope.allowed_paths are required for files_touched checks")
    elif not normalized_files and normalized_files != []:
        errors.append("files_touched must be a list")

    if not isinstance(result.get("commands_run"), list) or not all(
        isinstance(item, str) and item.strip() for item in result["commands_run"]
    ):
        errors.append("commands_run must be a list of non-empty strings")

    if not isinstance(result.get("validation"), dict):
        errors.append("validation must be an object")

    if not isinstance(result.get("decision_required"), list):
        errors.append("decision_required must be a list")
    if not isinstance(result.get("bounded_options"), list):
        errors.append("bounded_options must be a list")
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
            completion_usage_errors = _parse_usage_limits_for_completion(completion_usage, packet)
            if completion_usage_errors:
                errors.extend(completion_usage_errors)
        if result.get("attestation_status") != "trusted":
            errors.append("completed return requires attestation_status 'trusted'")
        if result.get("validation") == {}:
            errors.append("completed return requires explicit validation")
        if _read_only_work_plan(packet.get("work_plan")):
            if result.get("files_touched") != [] or result.get("mutation_state") != "clean":
                errors.append("read-only work_plan completion requires no files_touched and clean mutation_state")
        try:
            scope = packet["scope"]
            allowed = _normalize_scope_paths(scope.get("allowed_paths", []), _normalize_workdir(scope["workdir"]))
            _, paths_for_validation = _required_string_list(
                result.get("files_touched"), "files_touched", min_items=0
            )
            for path in paths_for_validation:
                file_error = _path_in_scope(
                    path,
                    _normalize_workdir(scope["workdir"]),
                    allowed,
                )
                if file_error:
                    errors.append(file_error)
        except (TypeError, KeyError, SystemExit):
            pass

    if status in {"needs-replan", "needs-architect-realignment", "budget-exhausted", "model-mismatch"}:
        if (
            not isinstance(result.get("decision_required"), list)
            or not result["decision_required"]
        ):
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
            if replan.get("completed_evidence") != result.get("completed_evidence"):
                errors.append("replan.completed_evidence must match completed_evidence")
            if replan.get("files_touched") != result.get("files_touched"):
                errors.append("replan.files_touched must match files_touched")
            if replan.get("mutation_state") != result.get("mutation_state"):
                errors.append("replan.mutation_state must match mutation_state")
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

    if status == "model-mismatch":
        if result.get("actual_model") == result.get("requested_model"):
            errors.append("model-mismatch status requires actual_model different from requested_model")

    return errors


def _load_json_payload(path: str) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise SystemExit(f"unable to read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"invalid JSON in {path}: {exc}") from exc


def _emit_payload(payload: dict[str, Any], output: str | None) -> None:
    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if output:
        atomic_write_text(assert_safe_output_path(Path(output)), rendered)
    else:
        print(rendered)


def _render_prompt(payload: dict[str, Any]) -> str:
    budget = payload["budget"]
    scope = payload["scope"]
    accepted = "\n".join(f"- {check}" for check in payload["acceptance_checks"][:8])
    paths = "\n".join(f"- {path}" for path in scope["allowed_paths"][:8])
    work_plan = payload.get("work_plan")
    task_profile = work_plan.get("task_profile") if isinstance(work_plan, dict) else None
    task_class = task_profile.get("task_class") if isinstance(task_profile, dict) else None
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
        and isinstance(task_profile.get("commands"), list)
    )
    declared_commands = task_profile.get("commands", []) if exact_argv else []
    command_lines = [
        f"{index}. {shlex.join(command['argv'])}"
        for index, command in enumerate(declared_commands, start=1)
        if isinstance(command, dict) and isinstance(command.get("argv"), list)
    ]
    read_only = _read_only_work_plan(work_plan)
    triggers = ", ".join(
        f"{key}:{value}" for key, value in payload["escalation_triggers"].items()
    )
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
        f"Session policy: fresh session, no-tools attestation, self-report forbidden",
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
                "Checked command execution:",
                f"- Wrapper: {payload['command_contract']['wrapper']}",
                f"- Typed modes: {', '.join(payload['command_contract']['modes'])}",
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
    return "\n".join(lines).strip() + "\n"


def validate_schema_files() -> list[str]:
    for relative in [
        NATIVE_WORKER_PACKET_SCHEMA,
        NATIVE_WORKER_RETURN_SCHEMA,
        NATIVE_WORK_PLAN_SCHEMA,
        NATIVE_WORKER_COMMITMENT_SCHEMA,
    ]:
        path = Path(relative)
        try:
            json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return [f"{relative} is not valid JSON: {exc}"]
    return []


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build, validate, and render native-worker packets and returns."
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    build = subcommands.add_parser("build", help="Build a native-worker packet.")
    build.add_argument("--bead-id", required=True)
    build.add_argument("--lane", required=True)
    build.add_argument("--workdir", required=True)
    build.add_argument("--allowed-path", action="append", required=True, dest="allowed_paths")
    build.add_argument("--acceptance-check", action="append", required=True, dest="acceptance_checks")
    build.add_argument("--work-plan")
    build.add_argument("--worker-commitment")
    build.add_argument("--trusted-session-id")
    build.add_argument("--attested-model")
    build.add_argument("--requested-model")
    for field in sorted(ALLOWED_BUDGET_FIELDS):
        build.add_argument("--" + field.replace("_", "-"), type=int, dest=field)
    build.add_argument("--validation-root-packet-id")
    build.add_argument("--validation-parent-packet-id")
    build.add_argument("--validation-attempt", type=int, choices=[0, 1], default=0)
    build.add_argument("--output")

    validate_cmd = subcommands.add_parser("validate", help="Validate a native-worker packet.")
    validate_cmd.add_argument("packet")

    render = subcommands.add_parser("render", help="Render a bounded native-worker task prompt.")
    render.add_argument("packet")

    validate_return = subcommands.add_parser(
        "validate-return", help="Validate a native-worker return against a packet."
    )
    validate_return.add_argument("--packet", required=True)
    validate_return.add_argument("--return", required=True, dest="return_path")

    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    errors = validate_schema_files()
    if errors:
        raise SystemExit(errors[0])

    if args.command == "build":
        overrides = {
            field: getattr(args, field)
            for field in ALLOWED_BUDGET_FIELDS
            if getattr(args, field) is not None
        }
        work_plan = _load_json_payload(args.work_plan) if args.work_plan else None
        worker_commitment = _load_json_payload(args.worker_commitment) if args.worker_commitment else None
        packet = build_native_worker_packet(
            bead_id=args.bead_id,
            lane=args.lane,
            workdir=args.workdir,
            allowed_paths=args.allowed_paths,
            acceptance_checks=args.acceptance_checks,
            work_plan=work_plan,
            worker_commitment=worker_commitment,
            trusted_session_id=args.trusted_session_id,
            attested_model=args.attested_model,
            budget_overrides=overrides,
            validation_root_packet_id=args.validation_root_packet_id,
            validation_parent_packet_id=args.validation_parent_packet_id,
            validation_attempt=args.validation_attempt,
            requested_model=args.requested_model,
        )
        _emit_payload(packet, args.output)
        return

    if args.command == "validate":
        packet = _load_json_payload(args.packet)
        errors = validate_native_worker_packet(packet)
        if errors:
            raise SystemExit("packet validation failed:\n- " + "\n- ".join(errors))
        print("packet valid")
        return

    if args.command == "render":
        packet = _load_json_payload(args.packet)
        errors = validate_native_worker_packet(packet, dispatchable=True)
        if errors:
            raise SystemExit("packet validation failed:\n- " + "\n- ".join(errors))
        print(_render_prompt(packet))
        return

    if args.command == "validate-return":
        packet = _load_json_payload(args.packet)
        packet_errors = validate_native_worker_packet(packet)
        if packet_errors:
            raise SystemExit("packet validation failed:\n- " + "\n- ".join(packet_errors))
        native_return = _load_json_payload(args.return_path)
        return_errors = validate_native_worker_return(packet, native_return)
        if return_errors:
            raise SystemExit("return validation failed:\n- " + "\n- ".join(return_errors))
        print("return valid")
        return

    raise SystemExit(f"unknown command: {args.command!r}")


if __name__ == "__main__":
    main()
