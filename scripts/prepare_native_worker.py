#!/usr/bin/env python3
from __future__ import annotations

import argparse
from copy import deepcopy
import json
from pathlib import Path
import uuid
from typing import Any, Mapping

from cwo_core import native_worker_packet
from cwo_core.checked_command_sequence import normalize_sequence_spec
from cwo_core.model_identities import OPERATIVE_ROLES, SPARK_MODEL, operative_models
from cwo_core.native_containment import require_native_operative_dispatch
from cwo_core.native_precommit import (
    canonical_sha256 as _canonical_json_sha256,
    commit_precommit_receipt_reservation,
    release_precommit_receipt_reservation,
    reserve_precommit_receipt,
    validate_precommit_receipt,
)
from cwo_core.native_tool_isolation import NativeToolIsolationError, default_tool_policy
from cwo_core.native_worker_contracts import (
    ALLOWED_BUDGET_FIELDS, PACKET_V3_PHASES,
    packet_v3_lineage_contract, packet_v3_phase_contract, packet_v3_recovery_contract,
)
from cwo_core.native_worker_packet import (
    NATIVE_WORKER_POLICY_PATH, load_native_worker_policy as load_native_worker_policy,
    render_worker_packet_prompt, validate_native_worker_packet, validate_native_worker_return,
)
from cwo_core.operative_routing import TASK_SELECTED_VERSION, nonoperative_model_refusal, validate_operative_route_for_model
from cwo_core.paths import assert_safe_output_path, cwo_temp_dir
from cwo_core.policy import load_policy
from cwo_core.util import atomic_write_text, make_dispatch_id
from cwo_core.work_sizing import (
    build_policy_fit_commitment,
    build_worker_commitment_from_receipt,
    canonical_work_estimate_sha256,
    is_read_only_work_estimate as _read_only_work_plan,
)

NATIVE_WORKER_PACKET_SCHEMA = "schemas/native-worker-packet.schema.json"
NATIVE_WORKER_RETURN_SCHEMA = "schemas/native-worker-return.schema.json"
NATIVE_WORK_PLAN_SCHEMA = "schemas/native-work-estimate.schema.json"
NATIVE_WORKER_COMMITMENT_SCHEMA = "schemas/native-worker-commitment.schema.json"
NATIVE_PRECOMMIT_STATE_SCHEMA = "schemas/native-precommit-state.schema.json"
NATIVE_PRECOMMIT_RECEIPT_SCHEMA = "schemas/native-precommit-receipt.schema.json"
NATIVE_TOOL_ENFORCEMENT_OVERRIDE_SCHEMA = "schemas/native-tool-enforcement-override.schema.json"

_direct_execution_contract_errors = native_worker_packet.direct_execution_contract_errors
_policy_budgets_for_lane = native_worker_packet.policy_budgets_for_lane
_policy_lanes = native_worker_packet.policy_lanes
_render_prompt = render_worker_packet_prompt


def _policy_model_config() -> dict[str, Any]:
    policy = load_policy("native-worker-execution")
    worker = policy.get("governance", {}).get("native_operative_worker", {})
    if not isinstance(worker, dict):
        raise SystemExit("policy missing governance.native_operative_worker")
    current = policy.get("task_selected_routing", {})
    if current.get("version") == TASK_SELECTED_VERSION and current.get("status") == "active":
        models = list(operative_models())
        return {"preferred_model": models[0], "authorized_models": models}
    preferred = (current.get("selection", {}).get("primary_model")
        if current.get("status") == "active" else policy.get("operative_routing", {}).get("primary_model"))
    preferred = str(preferred or "").strip()
    authorized = worker.get("authorized_models")
    if not preferred:
        raise SystemExit("policy missing the historical operative routing primary_model")
    if not isinstance(authorized, list) or not authorized:
        raise SystemExit("policy missing governance.native_operative_worker.authorized_models")
    models = [str(item).strip() for item in authorized if str(item).strip()]
    if preferred not in models:
        raise SystemExit("preferred native operative model must be authorized")
    if worker.get("fallback_selection") != "explicit-only":
        raise SystemExit("native operative fallback selection must be explicit-only")
    return {"preferred_model": preferred, "authorized_models": models}


def _policy_model(requested_model: str | None = None) -> str:
    config = _policy_model_config()
    selected = config["preferred_model"] if requested_model is None else requested_model
    refusal = nonoperative_model_refusal(selected)
    if refusal is not None:
        raise SystemExit(refusal)
    if type(selected) is not str or selected not in config["authorized_models"]:
        allowed = ", ".join(config["authorized_models"])
        raise SystemExit(f"requested native operative model {selected!r} is not authorized; allowed: {allowed}")
    return selected


def _policy_model_for_plan(requested_model: str | None, work_plan: Mapping[str, Any] | None) -> str:
    if requested_model is None and work_plan is not None:
        requested_model = work_plan.get("requested_model")
    return _policy_model(requested_model)


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
    needs_architect = native_worker_packet.load_alignment_triggers()
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


def _build_checked_command_sequence(
    *,
    packet_id: str,
    work_plan: dict[str, Any],
    workdir: Path,
) -> dict[str, Any] | None:
    contract = native_worker_packet.work_plan_execution_contract(work_plan)
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


def _build_native_worker_packet_unreserved(
    *,
    bead_id: str,
    lane: str,
    workdir: str,
    allowed_paths: list[str],
    acceptance_checks: list[str],
    work_plan: dict[str, Any] | None = None,
    worker_commitment: dict[str, Any] | None = None,
    precommit_receipt: dict[str, Any] | None = None,
    trusted_session_id: str | None = None,
    attested_model: str | None = None,
    packet_id: str | None = None,
    budget_overrides: dict[str, int] | None = None,
    validation_root_packet_id: str | None = None,
    validation_parent_packet_id: str | None = None,
    validation_attempt: int = 0,
    requested_model: str | None = None,
    operative_routing: dict[str, Any] | None = None,
    packet_version: int = 2,
    experimental_v3: bool = False,
    phase: str | None = None,
    permitted_tools: list[str] | None = None,
    tool_profile: str | None = None,
    forbidden_tools: list[str] | None = None,
    tool_enforcement_override: dict[str, Any] | None = None,
    current_authority: Any = None,
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
    if any(
        value is not None
        for value in (work_plan, worker_commitment, precommit_receipt, trusted_session_id, attested_model)
    ):
        if work_plan is None or precommit_receipt is None:
            raise SystemExit("planned candidate packet build requires a trusted precommit receipt")
    if work_plan is None and (
        worker_commitment is not None
        or precommit_receipt is not None
        or trusted_session_id is not None
        or attested_model is not None
    ):
        raise SystemExit("worker commitment, precommit receipt, or trusted attestation requires a work_plan")
    if trusted_session_id is not None or attested_model is not None:
        raise SystemExit("session and model identity must be derived exclusively from a trusted precommit receipt")
    if work_plan is not None and worker_commitment is None:
        try:
            if (work_plan.get("fit_mode") == "deterministic"
                    and precommit_receipt.get("submission_id") == "deterministic-policy"):
                worker_commitment = build_policy_fit_commitment(
                    work_plan,
                    precommit_receipt=precommit_receipt,
                    current_authority=current_authority,
                )
            else:
                worker_commitment = build_worker_commitment_from_receipt(
                    work_plan,
                    precommit_receipt,
                    current_authority=current_authority,
                )
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
    elif worker_commitment is not None and precommit_receipt is None:
        raise SystemExit("explicit worker commitment requires its bound precommit receipt")
    workdir_path = native_worker_packet.normalize_workdir(workdir)
    normalized_paths = native_worker_packet.normalize_allowed_paths(allowed_paths, workdir_path)
    if precommit_receipt is not None:
        receipt_packet_id = str(precommit_receipt.get("packet_id") or "")
        if packet_id is not None and packet_id != receipt_packet_id:
            raise SystemExit("packet_id must match the preallocated precommit receipt packet_id")
        packet_id = receipt_packet_id
    packet_id = packet_id or make_dispatch_id(bead_id)
    selected_model = _policy_model_for_plan(requested_model, work_plan)
    if selected_model != SPARK_MODEL:
        routing_errors = validate_operative_route_for_model(
            operative_routing,
            selected_model,
            work_estimate=work_plan,
            current_authority=current_authority,
        )
        if routing_errors:
            raise SystemExit("operative routing validation failed:\n- " + "\n- ".join(routing_errors))
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
    try:
        tool_policy = default_tool_policy(
            mutable=not read_only_plan,
            workload_class="operative",
            permitted_tools=permitted_tools,
            **({"tool_profile": tool_profile} if tool_profile is not None else {}),
            forbidden_tools=forbidden_tools,
            enforcement_override=tool_enforcement_override,
        )
    except NativeToolIsolationError as exc:
        raise SystemExit(str(exc)) from exc
    if validation_attempt == 0 and root_packet_id != packet_id:
        raise SystemExit("validation attempt 0 root packet id must equal packet id")
    if validation_attempt == 1 and lane != "validation":
        raise SystemExit("validation attempt 1 requires the validation lane")
    if validation_attempt == 1 and validation_parent_packet_id != root_packet_id:
        raise SystemExit("validation attempt 1 parent packet id must equal root packet id")
    if validation_attempt == 1 and packet_id in {root_packet_id, validation_parent_packet_id}:
        raise SystemExit("validation attempt 1 cannot reference itself")
    if work_plan is not None and precommit_receipt is not None:
        receipt_errors = validate_precommit_receipt(
            precommit_receipt,
            work_plan,
            operative_routing=operative_routing,
            expected_packet_id=packet_id,
            live=True,
            require_accepting=True,
            current_authority=current_authority,
        )
        if receipt_errors:
            raise SystemExit("precommit receipt validation failed:\n- " + "\n- ".join(receipt_errors))
    packet = {
        "packet_type": "cwo-native-worker-packet",
        "version": packet_version,
        "packet_id": packet_id,
        "bead_id": bead_id,
        "lane": lane,
        "requested_model": selected_model,
        "session_policy": _build_session_policy(selected_model),
        "tool_policy": tool_policy,
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
            "interrupt_thresholds": native_worker_packet.interrupt_thresholds(budget),
        },
        "validation_lineage": {
            "root_packet_id": root_packet_id,
            "parent_packet_id": validation_parent_packet_id,
            "attempt": validation_attempt,
        },
        "escalation_triggers": _build_escalation_triggers(),
        "return_contract": _build_return_contract(),
        "command_contract": native_worker_packet.build_command_contract(policy),
    }
    if operative_routing is not None:
        packet["operative_routing"] = deepcopy(operative_routing)
    if work_plan is not None and worker_commitment is not None:
        packet["work_plan"] = deepcopy(work_plan)
        packet["worker_commitment"] = deepcopy(worker_commitment)
        packet["stage"] = "precommit-validated"
        packet["operative_dispatch_authorized"] = False
        packet["release_requires"] = "complex-work-orchestration-fsh.3"
        packet["precommit_receipt"] = deepcopy(precommit_receipt)
        packet["precommit_receipt_sha256"] = precommit_receipt["receipt_sha256"]
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
    errors = validate_native_worker_packet(packet, experimental=(packet_version == 3), current_authority=current_authority)
    if errors:
        raise SystemExit("packet validation failed:\n- " + "\n- ".join(errors))
    return packet


def build_native_worker_packet(**kwargs: Any) -> dict[str, Any]:
    # Resolve the current model before reserving any one-use receipt. Historical
    # artifact validation remains separate and does not call this builder.
    _policy_model_for_plan(kwargs.get("requested_model"), kwargs.get("work_plan"))
    precommit_receipt = kwargs.get("precommit_receipt")
    if precommit_receipt is None:
        return _build_native_worker_packet_unreserved(**kwargs)
    if not isinstance(precommit_receipt, dict):
        raise SystemExit("precommit receipt must be an object")
    initial_errors = validate_precommit_receipt(
        precommit_receipt,
        kwargs.get("work_plan"),
        operative_routing=kwargs.get("operative_routing"),
        expected_packet_id=kwargs.get("packet_id") or precommit_receipt.get("packet_id"),
        live=True,
        require_accepting=True,
        current_authority=kwargs.get("current_authority"),
    )
    if initial_errors:
        raise SystemExit("precommit receipt validation failed:\n- " + "\n- ".join(initial_errors))
    packet_build_id = f"packet-build-{uuid.uuid4().hex}"
    try:
        reservation_id = reserve_precommit_receipt(precommit_receipt, packet_build_id)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    try:
        packet = _build_native_worker_packet_unreserved(**kwargs)
        final_errors = validate_precommit_receipt(
            precommit_receipt,
            kwargs.get("work_plan"),
            operative_routing=kwargs.get("operative_routing"),
            expected_packet_id=packet.get("packet_id"),
            live=True,
            require_accepting=True,
        current_authority=kwargs.get("current_authority"),
        )
        if final_errors:
            raise SystemExit(
                "precommit receipt changed during candidate packet construction:\n- "
                + "\n- ".join(final_errors)
            )
        commit_precommit_receipt_reservation(
            precommit_receipt,
            reservation_id,
            _canonical_json_sha256(packet),
        )
        return packet
    except BaseException as exc:
        try:
            release_precommit_receipt_reservation(precommit_receipt, reservation_id)
        except ValueError as release_exc:
            raise SystemExit(
                f"candidate packet construction failed closed and reservation release was refused: {release_exc}"
            ) from exc
        raise


def build_native_worker_packet_v3(**kwargs: Any) -> dict[str, Any]:
    """Explicit experimental/test-only packet-v3 construction path."""
    kwargs["packet_version"] = 3
    kwargs["experimental_v3"] = True
    return build_native_worker_packet(**kwargs)


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


def validate_schema_files() -> list[str]:
    for relative in [
        NATIVE_WORKER_PACKET_SCHEMA,
        NATIVE_WORKER_RETURN_SCHEMA,
        NATIVE_WORK_PLAN_SCHEMA,
        NATIVE_WORKER_COMMITMENT_SCHEMA,
        NATIVE_PRECOMMIT_STATE_SCHEMA,
        NATIVE_PRECOMMIT_RECEIPT_SCHEMA,
        NATIVE_TOOL_ENFORCEMENT_OVERRIDE_SCHEMA,
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
    build.add_argument("--precommit-receipt")
    build.add_argument("--trusted-session-id")
    build.add_argument("--attested-model")
    build.add_argument("--requested-model")
    build.add_argument("--operative-routing", help="Resolved operative route JSON for the exact selected model.")
    build.add_argument("--permitted-tool", action="append", dest="permitted_tools")
    build.add_argument("--tool-profile", choices=["mutating-core-resources-v2", "read-only-core-resources-v2"])
    build.add_argument("--forbidden-tool", action="append", dest="forbidden_tools")
    build.add_argument("--tool-enforcement-override")
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

    for command in (build, validate_cmd, render, validate_return):
        command.add_argument("--current-authority-file")
        command.add_argument("--current-authority-sha256")
    return parser.parse_args()


def main(
    *,
    current_authority: Any = None,
) -> None:
    args = _parse_args()
    from cwo_core.private_authority_input import private_authority_arguments
    from model_catalog_startup import configure_cli_model_catalog

    try:
        supplied = private_authority_arguments(args.current_authority_file, args.current_authority_sha256)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    if supplied:
        if current_authority is not None and supplied['current_authority'] != current_authority:
            raise SystemExit("conflicting current-authority inputs")
        current_authority = supplied['current_authority']
    errors = validate_schema_files()
    if errors:
        raise SystemExit(errors[0])

    if args.command == "build":
        configure_cli_model_catalog(OPERATIVE_ROLES)
        overrides = {
            field: getattr(args, field)
            for field in ALLOWED_BUDGET_FIELDS
            if getattr(args, field) is not None
        }
        work_plan = _load_json_payload(args.work_plan) if args.work_plan else None
        worker_commitment = _load_json_payload(args.worker_commitment) if args.worker_commitment else None
        precommit_receipt = _load_json_payload(args.precommit_receipt) if args.precommit_receipt else None
        operative_routing = _load_json_payload(args.operative_routing) if args.operative_routing else None
        tool_enforcement_override = (
            _load_json_payload(args.tool_enforcement_override)
            if args.tool_enforcement_override
            else None
        )
        packet = build_native_worker_packet(
            bead_id=args.bead_id,
            lane=args.lane,
            workdir=args.workdir,
            allowed_paths=args.allowed_paths,
            acceptance_checks=args.acceptance_checks,
            work_plan=work_plan,
            worker_commitment=worker_commitment,
            precommit_receipt=precommit_receipt,
            trusted_session_id=args.trusted_session_id,
            attested_model=args.attested_model,
            budget_overrides=overrides,
            validation_root_packet_id=args.validation_root_packet_id,
            validation_parent_packet_id=args.validation_parent_packet_id,
            validation_attempt=args.validation_attempt,
            requested_model=args.requested_model,
            operative_routing=operative_routing,
            permitted_tools=args.permitted_tools,
            tool_profile=args.tool_profile,
            current_authority=current_authority,
            forbidden_tools=args.forbidden_tools,
            tool_enforcement_override=tool_enforcement_override,
        )
        _emit_payload(packet, args.output)
        return

    if args.command == "validate":
        packet = _load_json_payload(args.packet)
        errors = validate_native_worker_packet(packet, current_authority=current_authority)
        if errors:
            raise SystemExit("packet validation failed:\n- " + "\n- ".join(errors))
        print("packet valid")
        return

    if args.command == "render":
        packet = _load_json_payload(args.packet)
        work_plan = packet.get("work_plan")
        require_native_operative_dispatch(
            "operative-prompt-render",
            release_evidence=(
                packet.get("release_evidence")
                if isinstance(packet.get("release_evidence"), dict)
                else None
            ),
            expected_packet_id=str(packet.get("packet_id") or ""),
            expected_work_plan_sha256=(
                canonical_work_estimate_sha256(work_plan)
                if isinstance(work_plan, dict)
                else None
            ),
            expected_precommit_receipt_sha256=(
                str(packet.get("precommit_receipt_sha256"))
                if isinstance(packet.get("precommit_receipt_sha256"), str)
                else None
            ),
        )
        configure_cli_model_catalog(OPERATIVE_ROLES)
        errors = validate_native_worker_packet(packet, dispatchable=True, current_authority=current_authority)
        if errors:
            raise SystemExit("packet validation failed:\n- " + "\n- ".join(errors))
        print(_render_prompt(packet))
        return

    if args.command == "validate-return":
        packet = _load_json_payload(args.packet)
        packet_errors = validate_native_worker_packet(packet, current_authority=current_authority)
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
