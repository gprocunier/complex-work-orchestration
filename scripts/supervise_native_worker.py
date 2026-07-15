#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import shlex
from pathlib import Path
from typing import Any

from cwo_core.native_session import (
    SEGMENT_START_EVENT,
    _evaluate_records,
    _extract_command,
    _normalize_response_items,
    _is_user_boundary_record,
    _normalize_event_msg,
    _normalize_turn_context,
    _session_id_matches,
)
from cwo_core.audit import acquire_audit_lock, record_audit_event, release_audit_lock
from cwo_core.native_disposition import derive_disposition
from cwo_core.native_containment import require_native_operative_dispatch
from cwo_core.native_precommit import canonical_sha256
from cwo_core.native_retry import (
    build_retry_authorization,
    canonical_work_sha256,
    evaluate_retry_eligibility,
    validate_retry_authorization,
)
from cwo_core.policy import load_policy
from cwo_core.paths import AUDIT_LOG, cwo_temp_path, is_cwo_temp_path
from cwo_core.util import artifact_hash, atomic_write_text, make_dispatch_id
from cwo_core.workspace import capture_workspace_baseline, compare_workspace_baseline
from prepare_native_worker import validate_native_worker_packet


STATE_TYPE = "cwo-native-supervision-state"
DECISION_TYPE = "cwo-native-supervision-decision"
STATE_SCHEMA = "schemas/native-supervision-state.schema.json"
DECISION_SCHEMA = "schemas/native-supervision-decision.schema.json"
FINAL_STATES = {"completed", "closed", "control-failed"}
EMPTY_USAGE = {"tool_calls": 0, "runtime_seconds": 0}
OPERATIVE_READINESS_CONTRACT = "operative-readiness:v2"


def _fail(message: str) -> None:
    raise SystemExit(message)


def _iso_now(value: str | None = None) -> dt.datetime:
    if value:
        try:
            parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            _fail(f"invalid --now value: {exc}")
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)
    return dt.datetime.now(dt.timezone.utc)


def _iso(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _policy_mapping(policy: dict[str, Any], key: str) -> dict[str, Any]:
    value = policy.get(key)
    if not isinstance(value, dict):
        _fail(f"control-lost: {key} policy is missing or invalid")
    return value


def _scope_relative(workdir: Path, value: str) -> tuple[str, Path] | None:
    candidate = Path(value)
    resolved = candidate.resolve() if candidate.is_absolute() else (workdir / candidate).resolve()
    try:
        relative = resolved.relative_to(workdir).as_posix()
    except ValueError:
        return None
    return relative, resolved


def _path_is_allowed(relative: str, allowed_paths: list[str]) -> bool:
    return any(
        relative == allowed.rstrip("/") or relative.startswith(allowed.rstrip("/") + "/")
        for allowed in allowed_paths
        if allowed
    )


def _context_manifest(
    packet: dict[str, Any],
    work_plan: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[str]]:
    workdir = Path(str(packet["scope"]["workdir"])).resolve()
    raw_allowed = packet["scope"].get("allowed_paths", [])
    allowed_paths: list[str] = []
    errors: list[str] = []
    for raw in raw_allowed if isinstance(raw_allowed, list) else []:
        if not isinstance(raw, str) or not raw:
            errors.append("scope.allowed_paths contains an invalid path")
            continue
        scoped = _scope_relative(workdir, raw)
        if scoped is None:
            errors.append(f"scope path escapes workdir: {raw}")
            continue
        allowed_paths.append(scoped[0])

    manifest = work_plan.get("context_manifest")
    if not isinstance(manifest, list) or not manifest:
        return [], [*errors, "context_manifest must contain at least one semantic unit"]

    units: list[dict[str, Any]] = []
    identities: set[str] = set()
    for index, item in enumerate(manifest):
        prefix = f"context_manifest[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix} must be an object")
            continue
        raw_path = item.get("path")
        selector = item.get("selector")
        sha256 = item.get("sha256")
        if not isinstance(raw_path, str) or not raw_path or Path(raw_path).is_absolute():
            errors.append(f"{prefix}.path must be a relative path")
            continue
        scoped = _scope_relative(workdir, raw_path)
        if scoped is None or not _path_is_allowed(scoped[0], allowed_paths):
            errors.append(f"{prefix}.path is outside packet scope")
            continue
        if selector != "whole-file":
            match = re.fullmatch(r"lines:(\d+)-(\d+)", str(selector))
            if not match or int(match.group(1)) > int(match.group(2)):
                errors.append(f"{prefix}.selector is invalid")
                continue
        if not isinstance(sha256, str) or re.fullmatch(r"[0-9a-f]{64}", sha256) is None:
            errors.append(f"{prefix}.sha256 must be lowercase sha256")
            continue
        relative, resolved = scoped
        try:
            actual_sha256 = hashlib.sha256(resolved.read_bytes()).hexdigest()
        except OSError:
            errors.append(f"{prefix}.path is unreadable")
            continue
        if actual_sha256 != sha256:
            errors.append(f"{prefix}.sha256 does not match current content")
            continue
        identity = f"{relative}::{selector}::{sha256}"
        if identity in identities:
            errors.append(f"{prefix} duplicates semantic unit {identity}")
            continue
        identities.add(identity)
        units.append(
            {
                "identity": identity,
                "path": relative,
                "absolute_path": str(resolved),
                "selector": selector,
                "sha256": sha256,
            }
        )
    return units, errors


def _evaluate_operative_readiness(
    packet: dict[str, Any],
    policy: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    config = _policy_mapping(policy, "operative_packet_readiness")
    limits = config.get("limits")
    if not isinstance(limits, dict):
        _fail("control-lost: operative_packet_readiness.limits is invalid")

    reasons: list[str] = []
    open_decisions: list[str] = []
    work_plan = packet.get("work_plan")
    if not isinstance(work_plan, dict):
        work_plan = {}
        reasons.append("missing-work-plan")

    frozen = work_plan.get("frozen_decisions")
    frozen_decisions = [value for value in frozen if isinstance(value, str)] if isinstance(frozen, list) else []
    if config.get("required_marker") not in frozen_decisions:
        reasons.append("missing-operative-readiness-marker")

    required_markers = config.get("required_frozen_decision_markers")
    if not isinstance(required_markers, list):
        _fail("control-lost: required_frozen_decision_markers is invalid")
    for required in required_markers:
        if not isinstance(required, str) or not any(value.startswith(required) for value in frozen_decisions):
            open_decisions.append(str(required))
    if open_decisions:
        reasons.append("missing-frozen-decision-markers")

    unresolved = work_plan.get("unresolved_decisions")
    if not isinstance(unresolved, list):
        reasons.append("unresolved-decisions-invalid")
        open_decisions.append("unresolved-decisions-shape")
    elif unresolved:
        reasons.append("unresolved-decisions-present")
        open_decisions.extend(str(value) for value in unresolved)

    behavior_clusters = [value for value in frozen_decisions if value.startswith("behavior-cluster:")]
    if len(behavior_clusters) != int(limits.get("max_behavior_clusters", 1)):
        reasons.append("behavior-cluster-count-invalid")

    write_paths = work_plan.get("write_paths")
    owned_files = [value for value in write_paths if isinstance(value, str)] if isinstance(write_paths, list) else []
    lane = packet.get("lane")
    profile = work_plan.get("task_profile")
    profile = profile if isinstance(profile, dict) else {}
    scope = packet.get("scope")
    scope = scope if isinstance(scope, dict) else {}
    prohibited_actions = scope.get("prohibited_actions")
    mutation_count = profile.get("source_mutation_count")
    read_only_validation = (
        lane == "validation"
        and work_plan.get("task_class") == "read-only-validation"
        and profile.get("task_class") == "read-only-validation"
        and write_paths == []
        and isinstance(mutation_count, int)
        and not isinstance(mutation_count, bool)
        and mutation_count == 0
        and profile.get("source_mutation_paths") == []
        and isinstance(prohibited_actions, list)
        and "source-mutation" in prohibited_actions
    )
    if lane == "validation":
        if not read_only_validation:
            reasons.append("read-only-validation-contract-invalid")
    elif not owned_files:
        reasons.append("missing-write-paths")
    if len(set(owned_files)) > int(limits.get("max_source_files", 4)):
        reasons.append("source-file-limit-exceeded")

    context_units, context_errors = _context_manifest(packet, work_plan)
    reasons.extend(context_errors)
    focused_modules = sorted(
        {
            unit["path"]
            for unit in context_units
            if Path(unit["path"]).name.startswith("test_") and unit["path"].endswith(".py")
        }
    )
    if len(focused_modules) > int(limits.get("max_focused_test_modules", 2)):
        reasons.append("focused-test-module-limit-exceeded")

    semantic = work_plan.get("semantic_estimate")
    semantic = semantic if isinstance(semantic, dict) else {}
    if int(semantic.get("estimated_diff_p90", 0) or 0) > int(limits.get("max_expected_diff_lines", 250)):
        reasons.append("expected-diff-limit-exceeded")

    estimates = work_plan.get("estimates")
    estimates = estimates if isinstance(estimates, dict) else {}
    if int(estimates.get("tool_calls_p90", 0) or 0) > int(limits.get("max_tool_calls_p90", 18)):
        reasons.append("tool-call-estimate-limit-exceeded")
    if int(estimates.get("runtime_seconds_p90", 0) or 0) > int(limits.get("max_runtime_seconds_p90", 300)):
        reasons.append("runtime-estimate-limit-exceeded")

    budget = packet.get("budget")
    budget = budget if isinstance(budget, dict) else {}
    if int(budget.get("max_compactions", -1)) != int(limits.get("max_compactions", 0)):
        reasons.append("compaction-limit-invalid")
    lane_budgets = policy.get("lane_budgets")
    lane_budget = lane_budgets.get(lane) if isinstance(lane_budgets, dict) else None
    declared_full_suite_runs = budget.get("max_full_suite_runs")
    expected_full_suite_runs = (
        lane_budget.get("max_full_suite_runs") if isinstance(lane_budget, dict) else None
    )
    if (
        not isinstance(declared_full_suite_runs, int)
        or isinstance(declared_full_suite_runs, bool)
        or not isinstance(expected_full_suite_runs, int)
        or isinstance(expected_full_suite_runs, bool)
        or declared_full_suite_runs != expected_full_suite_runs
    ):
        reasons.append("lane-full-suite-limit-invalid")

    if open_decisions:
        decision = "architect-resolution-required"
    elif reasons:
        decision = "split-required"
    else:
        decision = "operative-ready"

    activity = _policy_mapping(policy, "operative_activity_controls")
    needs_replan = activity.get("needs_replan_before")
    needs_replan = needs_replan if isinstance(needs_replan, dict) else {}
    result = {
        "decision": decision,
        "reasons": sorted(set(reasons)),
        "open_decisions": sorted(set(open_decisions)),
        "owned_files": owned_files,
        "owned_symbols": [],
        "test_matrix": list(work_plan.get("acceptance_checks", []))
        if isinstance(work_plan.get("acceptance_checks"), list)
        else [],
        "context_unit_allowance": max(
            0, int(needs_replan.get("semantic_unit", 4)) - 1
        ),
        "pre_mutation_read_call_allowance": max(
            0, int(needs_replan.get("pre_mutation_read_call", 11)) - 1
        ),
        "total_call_allowance": int(budget.get("tool_calls_hard", 0) or 0),
        "total_runtime_allowance": int(budget.get("runtime_seconds_hard", 0) or 0),
    }
    return result, context_units


def _persist_workspace_baseline(
    packet: dict[str, Any],
    session_id: str,
) -> dict[str, Any]:
    workdir = Path(str(packet["scope"]["workdir"])).resolve()
    work_plan = packet.get("work_plan")
    if not isinstance(work_plan, dict) or not isinstance(work_plan.get("write_paths"), list):
        _fail("control-lost: work plan mutation scope is missing")
    allowed_paths = [str(value) for value in work_plan["write_paths"]]
    baseline = capture_workspace_baseline(
        workdir,
        allowed_paths=allowed_paths,
        include_untracked=True,
    )
    if baseline.get("incomplete") or not baseline.get("baseline_complete"):
        _fail("control-lost: workspace baseline evidence is incomplete")
    payload = json.dumps(baseline, indent=2, sort_keys=True) + "\n"
    path = cwo_temp_path(
        f"{packet['packet_id']}-{session_id}-workspace-baseline.json",
        purpose="native-supervision",
    ).resolve()
    atomic_write_text(path, payload)
    return {
        "path": str(path),
        "sha256": artifact_hash(payload),
        "baseline_complete": True,
        "allowed_paths": allowed_paths,
    }


def _load_workspace_baseline(metadata: Any) -> dict[str, Any]:
    if not isinstance(metadata, dict):
        _fail("control-lost: workspace baseline metadata is missing")
    path_value = metadata.get("path")
    expected_sha256 = metadata.get("sha256")
    if not isinstance(path_value, str) or not isinstance(expected_sha256, str):
        _fail("control-lost: workspace baseline metadata is invalid")
    path = Path(path_value).expanduser().resolve()
    if not is_cwo_temp_path(path):
        _fail("control-lost: workspace baseline is outside CWO temporary state")
    try:
        payload = path.read_text(encoding="utf-8")
        baseline = json.loads(payload)
    except (OSError, json.JSONDecodeError) as exc:
        _fail(f"control-lost: workspace baseline is unreadable: {exc}")
    if artifact_hash(payload) != expected_sha256 or not isinstance(baseline, dict):
        _fail("control-lost: workspace baseline hash mismatch")
    if baseline.get("incomplete") or not baseline.get("baseline_complete"):
        _fail("control-lost: workspace baseline evidence is incomplete")
    return baseline


def _compare_live_workspace(metadata: dict[str, Any]) -> dict[str, Any]:
    before = _load_workspace_baseline(metadata)
    caps = before.get("caps")
    caps = caps if isinstance(caps, dict) else {}
    after = capture_workspace_baseline(
        Path(str(before["cwd"])),
        allowed_paths=list(before.get("allowed_paths", [])),
        include_untracked=bool(before.get("include_untracked", True)),
        max_files=int(caps.get("max_files", 10000)),
        max_bytes=int(caps.get("max_bytes", 50_000_000)),
        max_seconds=float(caps.get("max_seconds", 5.0)),
    )
    report = compare_workspace_baseline(
        before,
        after,
        allowed_paths=list(before.get("allowed_paths", [])),
    )
    allowed_paths = list(before.get("allowed_paths", []))
    mutations = report.get("mutations")
    if isinstance(mutations, list):
        for mutation in mutations:
            if (
                isinstance(mutation, dict)
                and mutation.get("category") == "untracked"
                and _path_is_allowed(str(mutation.get("path", "")), allowed_paths)
            ):
                mutation["category"] = "scoped"
        category_names = (
            "scoped",
            "out-of-scope",
            "untracked",
            "unchanged-dirty",
            "attribution-ambiguous",
        )
        categories = {
            name: sorted(
                str(item["path"])
                for item in mutations
                if isinstance(item, dict) and item.get("category") == name
            )
            for name in category_names
        }
        categories["unchanged-dirty"] = sorted(
            set(categories["unchanged-dirty"]) | set(report.get("unchanged_dirty", []))
        )
        unexpected = [
            item
            for item in mutations
            if isinstance(item, dict)
            and item.get("category") in {"out-of-scope", "untracked", "attribution-ambiguous"}
        ]
        report["mutation_categories"] = categories
        report["allowed_mutations"] = [
            item for item in mutations if isinstance(item, dict) and item.get("category") == "scoped"
        ]
        report["unexpected_mutations"] = unexpected
        report["unexpected_mutation_detected"] = bool(unexpected)
        report["attribution_ambiguous"] = bool(categories["attribution-ambiguous"])
    return report


def _workspace_hard_reasons(report: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    categories = report.get("mutation_categories")
    categories = categories if isinstance(categories, dict) else {}
    if report.get("incomplete"):
        reasons.append("incomplete-mutation-evidence")
    if report.get("attribution_ambiguous") or categories.get("attribution-ambiguous"):
        reasons.append("mutation-attribution-ambiguity")
    if categories.get("out-of-scope"):
        reasons.append("out-of-scope-mutation")
    if categories.get("untracked"):
        reasons.append("unexpected-untracked-mutation")
    return reasons


def _empty_activity() -> dict[str, Any]:
    return {
        "processed_items": 0,
        "category_counts": {
            "targeted-read": 0,
            "broad-scan": 0,
            "memory-read": 0,
            "mutation": 0,
            "focused-validation": 0,
            "unrelated": 0,
        },
        "semantic_units": {},
        "pre_mutation_read_calls": 0,
        "pre_mutation_semantic_units": [],
        "mutation_started": False,
        "warnings": [],
        "violations": [],
    }


def _tool_name(item: dict[str, Any]) -> str:
    for key in ("name", "tool_name"):
        value = item.get(key)
        if isinstance(value, str) and value:
            return value
    return str(item.get("type") or "")


def _tool_arguments(item: dict[str, Any]) -> dict[str, Any] | None:
    raw = item.get("arguments", item.get("input"))
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str):
        return None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _tool_call_id(item: dict[str, Any]) -> str | None:
    value = item.get("call_id")
    return value if isinstance(value, str) and value else None


def _continuation_session_id(value: Any) -> int | None:
    if isinstance(value, dict):
        candidate = value.get("session_id")
        if isinstance(candidate, int) and not isinstance(candidate, bool) and candidate > 0:
            return candidate
        return None
    if not isinstance(value, str):
        return None
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        parsed = None
    if isinstance(parsed, dict):
        candidate = _continuation_session_id(parsed)
        if candidate is not None:
            return candidate
    envelope = value.split("\nOutput:\n", 1)[0]
    match = re.search(
        r"(?m)^Process running with session ID\s+([1-9]\d*)\s*$",
        envelope,
    )
    return int(match.group(1)) if match else None


def _continuation_is_terminal(value: Any) -> bool:
    if isinstance(value, dict):
        exit_code = value.get("exit_code")
        if isinstance(exit_code, int) and not isinstance(exit_code, bool):
            return True
        return False
    if not isinstance(value, str):
        return False
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        parsed = None
    if isinstance(parsed, dict) and _continuation_is_terminal(parsed):
        return True
    lower = value.split("\nOutput:\n", 1)[0].lower()
    return any(
        marker in lower
        for marker in (
            "process exited with code",
            "unknown process id",
            "aborted by user",
        )
    )


def _declared_validation_commands(packet: dict[str, Any]) -> frozenset[tuple[str, ...]]:
    lane = packet.get("lane")
    if lane not in {"implementation", "validation", "publish-report-admin"}:
        return frozenset()
    scope = packet.get("scope")
    work_plan = packet.get("work_plan")
    if not isinstance(scope, dict) or not isinstance(work_plan, dict):
        return frozenset()

    profile = work_plan.get("task_profile")
    if not isinstance(profile, dict):
        return frozenset()
    contract = profile.get("execution_contract")
    if isinstance(contract, dict) and contract.get("mode") == "checked-sequence-v1":
        receipt = packet.get("checked_command_sequence")
        runner = receipt.get("runner_argv") if isinstance(receipt, dict) else None
        if not isinstance(runner, list) or not runner or not all(
            isinstance(value, str) and value for value in runner
        ):
            return frozenset()
        return frozenset({tuple(runner)})
    mutation_count = profile.get("source_mutation_count")
    mutation_paths = profile.get("source_mutation_paths")
    if not isinstance(mutation_count, int) or isinstance(mutation_count, bool):
        return frozenset()
    if not isinstance(mutation_paths, list):
        return frozenset()
    if lane == "validation":
        prohibited = scope.get("prohibited_actions")
        if not isinstance(prohibited, list) or "source-mutation" not in prohibited:
            return frozenset()
        if work_plan.get("write_paths") != []:
            return frozenset()
        if profile.get("task_class") != "read-only-validation":
            return frozenset()
        if mutation_count != 0 or mutation_paths != []:
            return frozenset()
    elif lane == "implementation":
        allowed = scope.get("allowed_actions")
        if not isinstance(allowed, list) or "run-tests-in-scope" not in allowed:
            return frozenset()
        if profile.get("task_class") not in {"narrow-mechanical", "bounded-implementation"}:
            return frozenset()
    else:
        allowed = scope.get("allowed_actions")
        contract = profile.get("execution_contract")
        if (
            not isinstance(allowed, list)
            or "write-packaged-artifacts" not in allowed
            or profile.get("task_class") != "bounded-implementation"
            or mutation_count != 0
            or mutation_paths != []
            or not isinstance(contract, dict)
            or contract.get("mode") != "direct"
        ):
            return frozenset()
    command_count = profile.get("command_count")
    commands = profile.get("commands")
    if (
        not isinstance(command_count, int)
        or isinstance(command_count, bool)
        or not isinstance(commands, list)
        or command_count != len(commands)
    ):
        return frozenset()
    if lane == "publish-report-admin" and command_count != 1:
        return frozenset()

    declared: list[tuple[str, ...]] = []
    for command in commands:
        if not isinstance(command, dict) or set(command) != {"argv"}:
            return frozenset()
        argv = command.get("argv")
        if not isinstance(argv, list) or not argv:
            return frozenset()
        normalized: list[str] = []
        for value in argv:
            if not isinstance(value, str) or not value:
                return frozenset()
            normalized.append(value)
        declared.append(tuple(normalized))
    if len(declared) != len(set(declared)):
        return frozenset()
    return frozenset(declared)


def _exec_command_workdir_violation(
    item: dict[str, Any],
    packet: dict[str, Any],
) -> str | None:
    if _tool_name(item).lower() != "exec_command":
        return None
    scope = packet.get("scope")
    expected_raw = scope.get("workdir") if isinstance(scope, dict) else None
    if not isinstance(expected_raw, str) or not expected_raw:
        return "exec-command-workdir-authority-invalid"
    arguments = _tool_arguments(item)
    observed_raw = arguments.get("workdir") if arguments is not None else None
    if not isinstance(observed_raw, str) or not observed_raw:
        return "exec-command-workdir-missing"
    try:
        expected = Path(expected_raw).expanduser().resolve()
        observed = Path(observed_raw).expanduser().resolve()
    except (OSError, RuntimeError):
        return "exec-command-workdir-mismatch"
    if observed != expected:
        return "exec-command-workdir-mismatch"
    return None


def _command_tokens(command: str) -> list[str]:
    try:
        return shlex.split(command)
    except ValueError:
        return command.split()


def _selector_matches(command: str, selector: str) -> bool:
    if selector == "whole-file":
        return True
    match = re.fullmatch(r"lines:(\d+)-(\d+)", selector)
    if not match:
        return False
    authorized_start, authorized_end = (int(value) for value in match.groups())
    tokens = _command_tokens(command)
    if "sed" not in {Path(token).name for token in tokens}:
        return False
    requested_ranges: list[tuple[int, int]] = []
    for token in tokens:
        requested = re.fullmatch(r"(\d+)\s*,\s*(\d+)p", token)
        if requested is not None:
            requested_ranges.append(tuple(int(value) for value in requested.groups()))
    if len(requested_ranges) != 1:
        return False
    requested_start, requested_end = requested_ranges[0]
    return (
        requested_start <= requested_end
        and authorized_start <= requested_start
        and requested_end <= authorized_end
    )


def _referenced_units(command: str, units: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for unit in units:
        if (
            unit["path"] in command or unit["absolute_path"] in command
        ) and _selector_matches(command, unit["selector"]):
            result.append(unit)
    return result


def _activity_category(
    item: dict[str, Any],
    command: str,
    units: list[dict[str, Any]],
    declared_validation_commands: frozenset[tuple[str, ...]],
    authorized_continuation_calls: frozenset[str] = frozenset(),
) -> tuple[str, list[dict[str, Any]], bool]:
    name = _tool_name(item).lower()
    lower = command.lower()
    tokens = _command_tokens(command)
    executables = {Path(token).name for token in tokens if token and not token.startswith("-")}
    referenced = _referenced_units(command, units)

    if "apply_patch" in name:
        return "mutation", [], False
    if name == "write_stdin":
        call_id = _tool_call_id(item)
        if call_id is not None and call_id in authorized_continuation_calls:
            return "focused-validation", [], False
        return "unrelated", [], False
    if ".codex/memories" in lower or "/memories/" in lower:
        return "memory-read", [], False
    if (
        "rg --files" in lower
        or "git grep" in lower
        or "ls -r" in lower
        or "find" in executables
    ):
        return "broad-scan", [], False
    if executables & {"cp", "mv", "rm", "install", "mkdir", "touch"} or re.search(
        r"(?:^|\s)(?:>>?|tee)(?:\s|$)", command
    ):
        return "mutation", [], False
    try:
        exact_argv = tuple(shlex.split(command))
    except ValueError:
        exact_argv = ()
    if exact_argv and exact_argv in declared_validation_commands:
        return "focused-validation", [], False
    if (
        "python -m unittest" in lower
        or "python3 -m unittest" in lower
        or "compileall" in lower
        or "git diff --check" in lower
    ):
        return "focused-validation", [], False

    readers = executables & {"sed", "cat", "head", "tail", "nl", "rg", "wc"}
    if readers:
        if not referenced:
            return "broad-scan", [], False
        content_chunk = bool(readers & {"sed", "cat", "head", "tail", "nl"})
        return "targeted-read", referenced, content_chunk
    return "unrelated", [], False


def _authorized_continuation_calls(
    records: list[dict[str, Any]],
    packet: dict[str, Any],
    declared_validation_commands: frozenset[tuple[str, ...]],
) -> frozenset[str]:
    declared_exec_calls: set[str] = set()
    active_sessions: set[int] = set()
    continuation_sessions: dict[str, int] = {}
    authorized_calls: set[str] = set()

    for record in records:
        for item in _normalize_response_items(record):
            if not isinstance(item, dict):
                continue
            item_type = item.get("type")
            call_id = _tool_call_id(item)
            if item_type in {"function_call", "custom_tool_call"}:
                name = _tool_name(item).lower()
                if name == "exec_command" and call_id is not None:
                    command = _extract_command(item) or ""
                    category, _, _ = _activity_category(
                        item,
                        command,
                        [],
                        declared_validation_commands,
                    )
                    if (
                        category == "focused-validation"
                        and _exec_command_workdir_violation(item, packet) is None
                    ):
                        declared_exec_calls.add(call_id)
                elif name == "write_stdin" and call_id is not None:
                    arguments = _tool_arguments(item)
                    session_id = arguments.get("session_id") if arguments is not None else None
                    chars = arguments.get("chars", "") if arguments is not None else None
                    if (
                        isinstance(session_id, int)
                        and not isinstance(session_id, bool)
                        and session_id in active_sessions
                        and chars == ""
                    ):
                        authorized_calls.add(call_id)
                        continuation_sessions[call_id] = session_id
            elif item_type in {"function_call_output", "custom_tool_call_output"}:
                if call_id in declared_exec_calls:
                    session_id = _continuation_session_id(item.get("output"))
                    if session_id is not None:
                        active_sessions.add(session_id)
                elif call_id in continuation_sessions:
                    session_id = continuation_sessions[call_id]
                    if _continuation_is_terminal(item.get("output")):
                        active_sessions.discard(session_id)

    return frozenset(authorized_calls)


def _execution_command_plan(
    packet: dict[str, Any],
) -> tuple[str | None, list[tuple[str, ...]], dict[str, Any] | None]:
    work_plan = packet.get("work_plan")
    profile = work_plan.get("task_profile") if isinstance(work_plan, dict) else None
    contract = profile.get("execution_contract") if isinstance(profile, dict) else None
    if not isinstance(contract, dict):
        return None, [], None
    mode = contract.get("mode")
    if mode == "checked-sequence-v1":
        receipt = packet.get("checked_command_sequence")
        runner = receipt.get("runner_argv") if isinstance(receipt, dict) else None
        if isinstance(runner, list) and runner and all(isinstance(v, str) and v for v in runner):
            return mode, [tuple(runner)], receipt
        return "invalid", [], None
    if mode != "direct":
        return "invalid", [], None
    commands = profile.get("commands")
    if not isinstance(commands, list):
        return "invalid", [], None
    declared: list[tuple[str, ...]] = []
    for command in commands:
        argv = command.get("argv") if isinstance(command, dict) else None
        if not isinstance(argv, list) or not argv or not all(isinstance(v, str) and v for v in argv):
            return "invalid", [], None
        declared.append(tuple(argv))
    return mode, declared, None


def _native_output_evidence(value: Any) -> tuple[str, int | None, int | None]:
    parsed = value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            parsed = None
    if isinstance(parsed, dict):
        if "exit_code" in parsed:
            code = parsed.get("exit_code")
            return ("terminal", code, None) if isinstance(code, int) and not isinstance(code, bool) else ("invalid", None, None)
        session_id = _continuation_session_id(parsed)
        return ("running", None, session_id) if session_id is not None else ("invalid", None, None)
    if not isinstance(value, str):
        return "invalid", None, None
    envelope = value.split("\nOutput:\n", 1)[0]
    match = re.search(r"(?m)^Process exited with code\s+(-?\d+)\s*$", envelope)
    if match:
        return "terminal", int(match.group(1)), None
    session_id = _continuation_session_id(value)
    return ("running", None, session_id) if session_id is not None else ("invalid", None, None)


def _checked_sequence_result_valid(packet: dict[str, Any], receipt: dict[str, Any]) -> bool:
    spec = receipt.get("spec")
    output_path = receipt.get("output_path")
    if not isinstance(spec, dict) or not isinstance(output_path, str):
        return False
    try:
        result = json.loads(Path(output_path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False
    commands = spec.get("commands")
    command_results = result.get("command_results") if isinstance(result, dict) else None
    expected = {
        "result_type": "cwo-checked-command-sequence-result",
        "version": 1,
        "sequence_id": spec.get("sequence_id"),
        "packet_id": packet.get("packet_id"),
        "work_plan_sha256": spec.get("work_plan_sha256"),
        "spec_sha256": receipt.get("spec_sha256"),
        "workdir": spec.get("workdir"),
        "status": "passed",
        "failed_command_id": None,
        "failure_class": None,
    }
    if not isinstance(result, dict) or any(result.get(key) != value for key, value in expected.items()):
        return False
    if not isinstance(commands, list) or not isinstance(command_results, list):
        return False
    if result.get("completed_count") != len(commands) or len(command_results) != len(commands):
        return False
    return all(
        isinstance(actual, dict)
        and isinstance(declared, dict)
        and actual.get("command_id") == declared.get("command_id")
        and actual.get("execution_status") == "passed"
        and actual.get("exit_code") == 0
        for declared, actual in zip(commands, command_results)
    )


def _analyze_command_evidence(
    records: list[dict[str, Any]],
    packet: dict[str, Any],
    *,
    task_complete: bool,
) -> dict[str, Any]:
    mode, declared, receipt = _execution_command_plan(packet)
    evidence: dict[str, Any] = {
        "enabled": mode is not None,
        "mode": mode,
        "declared_count": len(declared),
        "observed_count": 0,
        "completed_count": 0,
        "paired_output_count": 0,
        "active_session_count": 0,
        "failed_command_index": None,
        "failed_exit_code": None,
        "sequence_result": None,
        "violations": [],
    }
    if mode is None:
        return evidence
    violations: set[str] = set()
    if mode == "invalid" or not declared:
        violations.add("command-contract-invalid")
    calls: dict[str, tuple[str, str]] = {}
    commands: dict[str, dict[str, Any]] = {}
    command_states = ["unseen"] * len(declared)
    active_sessions: dict[int, str] = {}
    failed = False
    output_seen: set[str] = set()

    for record in records:
        for item in _normalize_response_items(record):
            if not isinstance(item, dict):
                continue
            item_type = item.get("type")
            call_id = _tool_call_id(item)
            if item_type in {"function_call", "custom_tool_call"}:
                name = _tool_name(item).lower()
                if failed:
                    violations.add("command-after-terminal-failure")
                if call_id is not None:
                    if call_id in calls:
                        violations.add("command-call-id-duplicate")
                    calls[call_id] = (str(item_type), name)
                if name == "exec_command":
                    command = _extract_command(item) or ""
                    try:
                        argv = tuple(shlex.split(command))
                    except ValueError:
                        argv = ()
                    if argv not in declared:
                        continue
                    index = declared.index(argv)
                    if call_id is None:
                        violations.add("declared-command-call-id-missing")
                        continue
                    if index != evidence["observed_count"] or (index and command_states[index - 1] != "passed"):
                        violations.add("declared-command-order-invalid")
                    evidence["observed_count"] = max(int(evidence["observed_count"]), index + 1)
                    command_states[index] = "pending"
                    commands[call_id] = {"index": index, "session_id": None, "parent": None}
                elif name == "write_stdin":
                    arguments = _tool_arguments(item)
                    session_id = arguments.get("session_id") if isinstance(arguments, dict) else None
                    chars = arguments.get("chars", "") if isinstance(arguments, dict) else None
                    parent = active_sessions.get(session_id) if isinstance(session_id, int) and not isinstance(session_id, bool) else None
                    if call_id is None or chars != "" or parent is None:
                        violations.add("pty-continuation-invalid")
                    else:
                        commands[call_id] = {"index": commands[parent]["index"], "session_id": session_id, "parent": parent}
            elif item_type in {"function_call_output", "custom_tool_call_output"}:
                if call_id is None or call_id not in calls:
                    violations.add("command-output-orphan")
                    continue
                expected_type = "function_call_output" if calls[call_id][0] == "function_call" else "custom_tool_call_output"
                if item_type != expected_type:
                    violations.add("command-output-type-mismatch")
                if call_id in output_seen:
                    violations.add("command-output-duplicate")
                    continue
                output_seen.add(call_id)
                command = commands.get(call_id)
                if command is None:
                    continue
                evidence["paired_output_count"] = int(evidence["paired_output_count"]) + 1
                status, exit_code, session_id = _native_output_evidence(item.get("output"))
                parent_id = command.get("parent") or call_id
                parent = commands[parent_id]
                index = int(parent["index"])
                if status == "running" and session_id is not None:
                    previous_session = parent.get("session_id")
                    if previous_session not in {None, session_id}:
                        violations.add("pty-session-mismatch")
                    parent["session_id"] = session_id
                    active_sessions[session_id] = parent_id
                elif status == "terminal" and exit_code is not None:
                    bound_session = parent.get("session_id")
                    if bound_session is not None:
                        active_sessions.pop(bound_session, None)
                    if exit_code == 0:
                        if command_states[index] != "passed":
                            command_states[index] = "passed"
                            evidence["completed_count"] = int(evidence["completed_count"]) + 1
                        if mode == "checked-sequence-v1":
                            valid = isinstance(receipt, dict) and _checked_sequence_result_valid(packet, receipt)
                            evidence["sequence_result"] = "passed" if valid else "invalid"
                            if not valid:
                                violations.add("checked-sequence-result-invalid")
                    else:
                        command_states[index] = "failed"
                        failed = True
                        evidence["failed_command_index"] = index
                        evidence["failed_exit_code"] = exit_code
                        violations.add("declared-command-nonzero-exit")
                else:
                    violations.add("command-terminal-evidence-invalid")

    if task_complete:
        if any(state == "pending" for state in command_states):
            violations.add("command-terminal-evidence-missing")
        if any(state == "unseen" for state in command_states):
            violations.add("declared-command-missing")
    evidence["active_session_count"] = len(active_sessions)
    evidence["violations"] = sorted(violations)
    return evidence


def _classify_native_activity(
    records: list[dict[str, Any]],
    context_units: list[dict[str, Any]],
    previous: Any,
    *,
    scoped_mutation: bool,
    policy: dict[str, Any],
    packet: dict[str, Any],
) -> dict[str, Any]:
    activity = json.loads(json.dumps(previous)) if isinstance(previous, dict) else _empty_activity()
    items = [
        item
        for record in records
        for item in _normalize_response_items(record)
        if isinstance(item, dict)
        and item.get("type") in {"function_call", "custom_tool_call"}
    ]
    processed = int(activity.get("processed_items", 0) or 0)
    violations = set(str(value) for value in activity.get("violations", []))
    warnings = set(str(value) for value in activity.get("warnings", []))
    if processed > len(items):
        violations.add("native-activity-telemetry-truncated")
        processed = len(items)

    controls = _policy_mapping(policy, "operative_activity_controls")
    max_chunks = int(controls.get("max_chunks_per_unit", 4))
    warning = controls.get("warning")
    warning = warning if isinstance(warning, dict) else {}
    replan = controls.get("needs_replan_before")
    replan = replan if isinstance(replan, dict) else {}

    mutation_already_started = bool(activity.get("mutation_started"))
    semantic_units = activity.setdefault("semantic_units", {})
    pre_units = set(str(value) for value in activity.get("pre_mutation_semantic_units", []))
    category_counts = activity.setdefault("category_counts", _empty_activity()["category_counts"])
    declared_validation_commands = _declared_validation_commands(packet)
    authorized_continuation_calls = _authorized_continuation_calls(
        records,
        packet,
        declared_validation_commands,
    )

    for item in items[processed:]:
        command = _extract_command(item) or ""
        workdir_violation = _exec_command_workdir_violation(item, packet)
        if workdir_violation is not None:
            category_counts["unrelated"] = int(category_counts.get("unrelated", 0)) + 1
            violations.add(workdir_violation)
            continue
        category, referenced, content_chunk = _activity_category(
            item,
            command,
            context_units,
            declared_validation_commands,
            authorized_continuation_calls,
        )
        category_counts[category] = int(category_counts.get(category, 0)) + 1

        if category == "targeted-read" and not mutation_already_started:
            activity["pre_mutation_read_calls"] = int(
                activity.get("pre_mutation_read_calls", 0)
            ) + 1
            for unit in referenced:
                identity = unit["identity"]
                pre_units.add(identity)
                unit_state = semantic_units.setdefault(
                    identity,
                    {
                        "path": unit["path"],
                        "selector": unit["selector"],
                        "sha256": unit["sha256"],
                        "chunks": 0,
                        "read_calls": 0,
                    },
                )
                unit_state["read_calls"] = int(unit_state.get("read_calls", 0)) + 1
                if content_chunk:
                    unit_state["chunks"] = int(unit_state.get("chunks", 0)) + 1
                    if unit_state["chunks"] > max_chunks:
                        violations.add("read-unit-chunk-limit-exceeded")
        elif category == "broad-scan":
            violations.add("broad-scan-denied")
        elif category == "memory-read":
            violations.add("unauthorized-memory-read")
        elif category == "unrelated":
            violations.add("unrelated-activity-denied")

    activity["processed_items"] = len(items)
    activity["pre_mutation_semantic_units"] = sorted(pre_units)
    read_calls = int(activity.get("pre_mutation_read_calls", 0))
    unit_count = len(pre_units)
    if unit_count >= int(replan.get("semantic_unit", 4)):
        violations.add("needs-replan-semantic-unit-limit")
    if read_calls >= int(replan.get("pre_mutation_read_call", 11)):
        violations.add("needs-replan-pre-mutation-read-limit")
    if unit_count >= int(warning.get("semantic_units", 3)):
        warnings.add("semantic-unit-warning")
    if read_calls >= int(warning.get("pre_mutation_read_calls", 6)):
        warnings.add("pre-mutation-read-warning")

    activity["mutation_started"] = mutation_already_started or scoped_mutation
    activity["warnings"] = sorted(warnings)
    activity["violations"] = sorted(violations)
    return activity


def _elapsed_ms(start: str, end: dt.datetime) -> int:
    delta = end - _iso_now(start)
    return max(0, round(delta.total_seconds() * 1000))


def _load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        _fail(f"could not load {label} {path}: {exc}")
    if not isinstance(value, dict):
        _fail(f"{label} must be a JSON object")
    return value


def _recovery_payload(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {
            "attempt": 0,
            "cumulative_usage": dict(EMPTY_USAGE),
            "eligibility": None,
            "authorization": None,
        }
    cumulative = value.get("cumulative_usage")
    usage = cumulative if isinstance(cumulative, dict) else {}
    for field in ("tool_calls", "runtime_seconds"):
        if not isinstance(usage.get(field), int) or isinstance(usage.get(field), bool):
            usage[field] = int(EMPTY_USAGE[field])
    return {
        "attempt": int(value.get("attempt", 0)) if isinstance(value.get("attempt"), int) and not isinstance(value.get("attempt"), bool) else 0,
        "cumulative_usage": {
            "tool_calls": int(usage["tool_calls"]),
            "runtime_seconds": int(usage["runtime_seconds"]),
        },
        "eligibility": value.get("eligibility"),
        "authorization": value.get("authorization"),
    }


def _retry_policy() -> dict[str, Any]:
    policy = load_policy("native-worker-execution").get("bounded_native_retry")
    if not isinstance(policy, dict):
        _fail("control-lost: bounded_native_retry policy is missing or invalid")
    return policy


def _require_state_packet(path: str | None, state: dict[str, Any], label: str) -> dict[str, Any]:
    if not path:
        _fail(f"{label}: supervision state missing packet_file binding")
    packet_path = Path(path).expanduser().resolve()
    packet = _load_json(packet_path, "packet")
    expected_sha256 = artifact_hash(json.dumps(packet, sort_keys=True))
    if state.get("packet_sha256") != expected_sha256:
        _fail("retry lifecycle requires preserved immutable work hash: packet artifact hash changed for this supervision state")
    return packet


def _require_closed_for_retry(state: dict[str, Any]) -> None:
    if state.get("status") != "closed":
        _fail("retry lifecycle requires a closed supervision state")
    receipts = state.get("control_receipts", [])
    if not isinstance(receipts, list):
        _fail("retry lifecycle requires control receipts list in state")
    for required in ("interrupt-confirmed", "close-confirmed"):
        if required not in receipts:
            _fail("retry lifecycle requires interrupt-confirmed and close-confirmed control receipts")


def _require_native_retry_decision(state: dict[str, Any]) -> None:
    if state.get("decision") != "interrupt":
        _fail("retry lifecycle requires decision=interrupt; control-lost is a protected stop")


def _read_session(path: Path) -> tuple[list[dict[str, Any]], bool]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        _fail(f"control-lost: could not read session file {path}: {exc}")
    records: list[dict[str, Any]] = []
    lines = text.splitlines(keepends=True)
    trailing_partial = False
    for index, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            if index == len(lines) and not line.endswith(("\n", "\r")):
                trailing_partial = True
                continue
            _fail(f"control-lost: malformed completed JSONL record at line {index}: {exc}")
        if not isinstance(value, dict):
            _fail(f"control-lost: session record {index} is not an object")
        records.append(value)
    if not records:
        _fail("control-lost: session file has no complete records")
    return records, trailing_partial


def _trusted_models(records: list[dict[str, Any]]) -> set[str]:
    result: set[str] = set()
    for record in records:
        context = _normalize_turn_context(record)
        if isinstance(context, dict) and isinstance(context.get("model"), str):
            model = context["model"].strip()
            if model:
                result.add(model)
    return result


def _state_path(packet: dict[str, Any], session_id: str, raw: str | None) -> Path:
    path = Path(raw).expanduser() if raw else cwo_temp_path(
        f"{packet['packet_id']}-{session_id}.json",
        purpose="native-supervision",
    )
    path = path.resolve()
    if not is_cwo_temp_path(path):
        _fail("supervision state must be under a CWO-owned temporary directory")
    return path


def _write_state(path: Path, state: dict[str, Any]) -> None:
    lock, _ = acquire_audit_lock(path)
    try:
        atomic_write_text(path, json.dumps(state, indent=2, sort_keys=True) + "\n")
    finally:
        release_audit_lock(lock)


def _decision(state: dict[str, Any]) -> dict[str, Any]:
    recovery = _recovery_payload(state.get("recovery"))
    return {
        "result_type": DECISION_TYPE,
        "version": 1,
        "schema": DECISION_SCHEMA,
        "state_id": state["state_id"],
        "packet_id": state["packet_id"],
        "session_id": state["session_id"],
        "decision": state["decision"],
        "reasons": list(state.get("reasons", [])),
        "immutable_work_sha256": state.get("immutable_work_sha256"),
        "observed": dict(state.get("observed", {})),
        "interrupt_thresholds": dict(state["interrupt_thresholds"]),
        "control_turn_id": state.get("control_turn_id"),
        "control_timing": dict(state["control_timing"]),
        "control_action_required": bool(state.get("control_action_required")),
        "recovery": dict(recovery),
        "session_disposition": state["session_disposition"],
        "artifact_disposition": state["artifact_disposition"],
        "artifact_validation": dict(state["artifact_validation"]),
        "trailing_partial_record_ignored": bool(state.get("trailing_partial_record_ignored")),
    }


def _bounded_strings(values: Any, *, limit: int = 8, width: int = 120) -> tuple[list[str], int, str]:
    normalized = [str(value) for value in values] if isinstance(values, list) else []
    digest = hashlib.sha256(json.dumps(normalized, separators=(",", ":")).encode("utf-8")).hexdigest()
    return [value[:width] for value in normalized[:limit]], len(normalized), digest


def _compact_projection(state: dict[str, Any]) -> dict[str, Any]:
    observed = state.get("observed") if isinstance(state.get("observed"), dict) else {}
    activity = observed.get("activity") if isinstance(observed.get("activity"), dict) else {}
    command = observed.get("command_evidence") if isinstance(observed.get("command_evidence"), dict) else {}
    workspace = observed.get("workspace_report") if isinstance(observed.get("workspace_report"), dict) else {}
    categories = workspace.get("mutation_categories") if isinstance(workspace.get("mutation_categories"), dict) else {}
    reasons, reason_count, reason_sha256 = _bounded_strings(state.get("reasons"))
    violations, violation_count, violation_sha256 = _bounded_strings(activity.get("violations"))
    warnings, warning_count, warning_sha256 = _bounded_strings(activity.get("warnings"))
    command_violations, command_count, command_sha256 = _bounded_strings(command.get("violations"))
    compact = {
        "result_type": DECISION_TYPE,
        "version": 1,
        "state_id": str(state.get("state_id", ""))[:160],
        "packet_id": str(state.get("packet_id", ""))[:160],
        "session_id": str(state.get("session_id", ""))[:160],
        "status": state.get("status"),
        "decision": state.get("decision"),
        "reasons": reasons,
        "reason_evidence": {"count": reason_count, "sha256": reason_sha256},
        "control_action_required": bool(state.get("control_action_required")),
        "usage": {
            "tool_calls": observed.get("tool_calls", 0),
            "elapsed_seconds": observed.get("elapsed_seconds", 0),
            "context_compactions": observed.get("context_compactions", 0),
            "full_suite_runs": observed.get("full_suite_runs", 0),
        },
        "activity": {
            "category_counts": activity.get("category_counts", {}),
            "violations": violations,
            "violation_evidence": {"count": violation_count, "sha256": violation_sha256},
            "warnings": warnings,
            "warning_evidence": {"count": warning_count, "sha256": warning_sha256},
        },
        "control_timing": state.get("control_timing", {}),
        "mutation": {
            "detected": bool(workspace.get("mutation_detected")),
            "unexpected": bool(workspace.get("unexpected_mutation_detected")),
            "incomplete": bool(workspace.get("incomplete")),
            "attribution_ambiguous": bool(workspace.get("attribution_ambiguous")),
            "category_counts": {
                name: len(value) if isinstance(value, list) else 0
                for name, value in sorted(categories.items())
            },
        },
        "command_evidence": {
            key: command.get(key)
            for key in (
                "enabled", "mode", "declared_count", "observed_count", "completed_count",
                "paired_output_count", "active_session_count", "failed_command_index",
                "failed_exit_code", "sequence_result",
            )
        } | {
            "violations": command_violations,
            "violation_evidence": {"count": command_count, "sha256": command_sha256},
        },
        "session_disposition": state.get("session_disposition"),
        "artifact_disposition": state.get("artifact_disposition"),
        "started_at": state.get("started_at"),
        "updated_at": state.get("updated_at"),
        "finalized_at": state.get("finalized_at"),
    }
    rendered = json.dumps(compact, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(rendered) > 4096:
        compact["reasons"] = []
        compact["activity"]["violations"] = []
        compact["activity"]["warnings"] = []
        compact["command_evidence"]["violations"] = []
        compact["projection_truncated"] = True
    if len(json.dumps(compact, sort_keys=True, separators=(",", ":")).encode("utf-8")) > 4096:
        _fail("control-lost: compact projection exceeds 4096 bytes")
    return compact


def _audit_event(
    state: dict[str, Any],
    event_type: str,
    *,
    control_action: str | None = None,
) -> dict[str, Any]:
    observed = state.get("observed", {})
    recovery = _recovery_payload(state.get("recovery"))
    eligibility = recovery.get("eligibility") if isinstance(recovery.get("eligibility"), dict) else {}
    authorization = recovery.get("authorization") if isinstance(recovery.get("authorization"), dict) else {}
    budget = state["budget"]
    thresholds = state["interrupt_thresholds"]
    timing = state["control_timing"]
    decision = str(state.get("decision") or "continue")
    delegation_status = {
        "continue": "started",
        "warn": "started",
        "complete": "completed",
        "interrupt": "blocked",
        "control-lost": "blocked",
    }.get(decision, "started")
    include_plan = event_type == "native_supervision_started"
    include_actual = include_plan or (
        event_type == "native_supervision_decision"
        and decision in {"complete", "interrupt", "control-lost"}
    )
    include_usage = event_type == "native_supervision_decision" and decision in {
        "complete",
        "interrupt",
        "control-lost",
    }
    return record_audit_event(
        {
            "event_type": event_type,
            "telemetry_kind": "native_supervision",
            "telemetry_status": decision,
            "dispatch_id": state["packet_id"],
            "packet_sha256": state["packet_sha256"],
            "bead_id": state["bead_id"],
            "session_id": state["session_id"],
            "native_supervision_state_id": state["state_id"],
            "native_supervision_required": True,
            "native_supervision_status": state["status"],
            "native_supervision_decision": decision,
            "native_supervision_reasons": state.get("reasons", []),
            "model": state["requested_model"],
            "role": state["lane"],
            "control_adapter": state["control_adapter"],
            "control_turn_id": state.get("control_turn_id"),
            "submission_id": state.get("submission_id"),
            "monitor_armed_before_dispatch": timing.get("monitor_armed_before_dispatch"),
            "arm_to_dispatch_ms": timing.get("arm_to_dispatch_ms"),
            "dispatch_to_first_poll_ms": timing.get("dispatch_to_first_poll_ms"),
            "max_poll_gap_ms": timing.get("max_poll_gap_ms"),
            "late_poll_count": timing.get("late_poll_count"),
            "poll_interval_ms": state["poll_interval_ms"],
            "poll_lag_tolerance_ms": state["poll_lag_tolerance_ms"],
            "control_action": control_action,
            "control_action_required": bool(state.get("control_action_required")),
            "control_receipt_confirmed": control_action is not None,
            "control_receipts": state.get("control_receipts", []),
            "trailing_partial_record_ignored": bool(state.get("trailing_partial_record_ignored")),
            "planned_tool_calls_hard": budget["tool_calls_hard"],
            "interrupt_tool_calls_threshold": thresholds["tool_calls"],
            "observed_tool_calls": observed.get("tool_calls", 0),
            "planned_runtime_seconds_hard": budget["runtime_seconds_hard"],
            "interrupt_runtime_seconds_threshold": thresholds["runtime_seconds"],
            "observed_runtime_seconds": observed.get("elapsed_seconds", 0),
            "observed_context_compactions": observed.get("context_compactions", 0),
            "observed_full_suite_runs": observed.get("full_suite_runs", 0),
            "native_command_evidence": observed.get("command_evidence"),
            "validation_lineage_attempt": state["validation_lineage"]["attempt"],
            "agent_model_calls": observed.get("tool_calls", 0) if include_usage else None,
            "elapsed_seconds": observed.get("elapsed_seconds", 0) if include_usage else None,
            "workerbee_planned_mode": "implementation-capable" if include_plan else None,
            "workerbee_planned_model": state["requested_model"] if include_plan else None,
            "workerbee_planned_lanes": [state["lane"]] if include_plan else [],
            "workerbee_actual_mode": "implementation-capable" if include_actual else None,
            "workerbee_actual_model": state["requested_model"] if include_actual else None,
            "workerbee_actual_lanes": [state["lane"]] if include_actual else [],
            "workerbee_delegation_status": delegation_status if include_actual else None,
            "workerbee_delegation_source": "trusted-native-supervisor" if include_actual else None,
            "completion_state": state["status"],
            "session_disposition": state["session_disposition"],
            "artifact_disposition": state["artifact_disposition"],
            "artifact_validation": state["artifact_validation"],
            "native_retry_work_sha256": state.get("immutable_work_sha256"),
            "native_retry_attempt": recovery.get("attempt"),
            "native_retry_eligibility": eligibility,
            "native_retry_eligibility_reasons": eligibility.get("reasons"),
            "native_retry_next_action": eligibility.get("next_action"),
            "native_retry_receipt_sha256": authorization.get("receipt_sha256"),
            "native_retry_cumulative_usage": recovery.get("cumulative_usage"),
            "native_retry_remaining_before_retry": eligibility.get("remaining_before_retry"),
        },
        Path(state["audit_file"]),
    )


def start(args: argparse.Namespace) -> dict[str, Any]:
    packet_path = Path(args.packet).expanduser().resolve()
    packet = _load_json(packet_path, "packet")
    _require_packet_release(packet, "supervision-start")
    errors = validate_native_worker_packet(packet, dispatchable=True)
    if errors:
        _fail("packet validation failed: " + "; ".join(errors))
    session_file = Path(args.session_file).expanduser().resolve()
    if not session_file.is_file() or not _session_id_matches(session_file, args.session_id):
        _fail("control-lost: session file identity does not match --session-id")
    records, trailing = _read_session(session_file)
    models = _trusted_models(records)
    requested_model = str(packet["requested_model"])
    if models != {requested_model}:
        _fail(f"control-lost: trusted attestation mismatch: expected {requested_model!r}, observed {sorted(models)!r}")
    policy = load_policy("native-worker-execution")
    readiness, context_units = _evaluate_operative_readiness(packet, policy)
    if packet.get("lane") == "implementation" and readiness["decision"] != "operative-ready":
        details = ", ".join([*readiness["reasons"], *readiness["open_decisions"]])
        _fail(f"implementation packet not ready: {readiness['decision']}: {details}")
    path = _state_path(packet, args.session_id, args.state_file)
    if path.exists():
        previous = _load_json(path, "supervision state")
        if previous.get("status") not in FINAL_STATES:
            _fail("duplicate active supervision state for packet/session")
        _fail("finalized supervision state cannot be reopened")
    now = _iso_now(args.now)
    baseline = _persist_workspace_baseline(packet, args.session_id)
    clean_budget = {key: int(value) for key, value in packet["budget"].items()}
    disposition = derive_disposition(
        status="within-budget",
        requested_model=requested_model,
        actual_model=requested_model,
        usage={"tool_calls": 0, "elapsed_seconds": 0, "context_compactions": 0, "full_suite_runs": 0},
        budget=clean_budget,
    )
    immutable_work_sha256 = canonical_work_sha256(packet)
    recovery = _recovery_payload(None)
    retry_authorization = None
    if args.retry_authorization:
        authorization = _load_json(Path(args.retry_authorization).expanduser().resolve(), "retry authorization")
        errors = validate_retry_authorization(authorization)
        if errors:
            _fail("retry authorization validation failed: " + "; ".join(errors))
        if authorization["retry_packet_id"] != packet["packet_id"]:
            _fail("retry authorization packet mismatch")
        if authorization["bead_id"] != packet["bead_id"]:
            _fail("retry authorization bead mismatch")
        if authorization["requested_model"] != requested_model or authorization["attested_model"] != requested_model:
            _fail("retry authorization model mismatch")
        if authorization["attempt_from"] != 0 or authorization["attempt_to"] != 1:
            _fail("retry authorization attempt lineage must be 0->1")
        if authorization["work_sha256"] != immutable_work_sha256:
            _fail("retry authorization work hash mismatch")
        recovery = _recovery_payload({
            "attempt": int(authorization["attempt_to"]),
            "cumulative_usage": authorization["cumulative_usage"],
            "eligibility": None,
            "authorization": authorization,
        })
    state = {
        "result_type": STATE_TYPE,
        "version": 1,
        "schema": STATE_SCHEMA,
        "state_id": make_dispatch_id(f"supervision-{packet['packet_id']}"),
        "packet_id": packet["packet_id"],
        "packet_sha256": artifact_hash(json.dumps(packet, sort_keys=True)),
        "packet_file": str(packet_path),
        "bead_id": packet["bead_id"],
        "lane": packet["lane"],
        "agent_id": args.agent_id,
        "session_id": args.session_id,
        "session_file": str(session_file),
        "baseline_record_count": len(records),
        "requested_model": requested_model,
        "budget": clean_budget,
        "budget_provenance": packet["budget_provenance"],
        "interrupt_thresholds": packet["supervision"]["interrupt_thresholds"],
        "poll_interval_ms": packet["supervision"]["poll_interval_ms"],
        "poll_lag_tolerance_ms": packet["supervision"]["poll_lag_tolerance_ms"],
        "arm_to_dispatch_max_ms": packet["supervision"]["arm_to_dispatch_max_ms"],
        "control_turn_required": packet["supervision"]["control_turn_required"],
        "segment_start_grace_seconds": packet["supervision"]["segment_start_grace_seconds"],
        "control_adapter": packet["supervision"]["control_adapter"],
        "required_capabilities": packet["supervision"]["required_capabilities"],
        "immutable_work_sha256": immutable_work_sha256,
        "validation_lineage": packet["validation_lineage"],
        "recovery": recovery,
        "audit_file": str(Path(args.audit_file).expanduser().resolve() if args.audit_file else AUDIT_LOG.resolve()),
        "status": "created",
        "decision": "continue",
        "reasons": [],
        "control_action_required": False,
        "control_receipts": [],
        "observed": {
            "tool_calls": 0,
            "elapsed_seconds": 0.0,
            "context_compactions": 0,
            "full_suite_runs": 0,
            "operative_readiness": readiness,
            "context_units": context_units,
            "workspace_baseline": baseline,
            "workspace_report": None,
            "activity": _empty_activity(),
        },
        "session_disposition": disposition["session_disposition"],
        "artifact_disposition": disposition["artifact_disposition"],
        "artifact_validation": disposition["artifact_validation"],
        "trailing_partial_record_ignored": trailing,
        "started_at": _iso(now),
        "updated_at": _iso(now),
        "finalized_at": None,
        "last_audited_decision": "continue",
        "control_turn_id": None,
        "submission_id": None,
        "control_timing": {
            "monitor_armed_before_dispatch": False,
            "armed_at": None,
            "dispatched_at": None,
            "first_poll_at": None,
            "last_poll_at": None,
            "arm_to_dispatch_ms": None,
            "dispatch_to_first_poll_ms": None,
            "max_poll_gap_ms": 0,
            "late_poll_count": 0,
        },
    }
    _write_state(path, state)
    _audit_event(state, "native_supervision_started")
    state["state_file"] = str(path)
    return state


def _load_control_state(path_value: str) -> tuple[Path, dict[str, Any]]:
    path = Path(path_value).expanduser().resolve()
    if not is_cwo_temp_path(path):
        _fail("supervision state must be under a CWO-owned temporary directory")
    return path, _load_json(path, "supervision state")


def _require_packet_release(packet: dict[str, Any], operation: str) -> None:
    work_plan = packet.get("work_plan")
    require_native_operative_dispatch(
        operation,
        release_evidence=(
            packet.get("release_evidence")
            if isinstance(packet.get("release_evidence"), dict)
            else None
        ),
        expected_packet_id=str(packet.get("packet_id") or ""),
        expected_work_plan_sha256=(
            canonical_sha256(work_plan) if isinstance(work_plan, dict) else None
        ),
        expected_precommit_receipt_sha256=(
            str(packet.get("precommit_receipt_sha256"))
            if isinstance(packet.get("precommit_receipt_sha256"), str)
            else None
        ),
    )


def _require_direct_release(args: argparse.Namespace, operation: str) -> dict[str, Any] | None:
    evidence = None
    path_value = getattr(args, "release_evidence", None)
    if isinstance(path_value, str) and path_value:
        evidence = _load_json(Path(path_value).expanduser().resolve(), "native release evidence")
    require_native_operative_dispatch(operation, release_evidence=evidence)
    return evidence


def _require_state_release(
    state: dict[str, Any],
    operation: str,
    supplied_evidence: dict[str, Any] | None = None,
) -> None:
    packet_file = state.get("packet_file")
    if not isinstance(packet_file, str) or not packet_file:
        _fail("control-lost: supervision state is missing its packet binding")
    packet = _load_json(Path(packet_file).expanduser().resolve(), "bound packet")
    if artifact_hash(json.dumps(packet, sort_keys=True)) != state.get("packet_sha256"):
        _fail("control-lost: bound packet changed after supervision start")
    if supplied_evidence is not None and packet.get("release_evidence") != supplied_evidence:
        _fail("control-lost: supplied release evidence does not match the bound packet")
    _require_packet_release(packet, operation)


def _control_turn(value: str) -> str:
    control_turn_id = str(value or "").strip()
    if not control_turn_id:
        _fail("control-turn-id must be non-empty")
    return control_turn_id


def _require_control_turn(state: dict[str, Any], value: str) -> str:
    control_turn_id = _control_turn(value)
    if state.get("control_turn_id") != control_turn_id:
        _fail("control-turn-id does not match the armed supervisor state")
    return control_turn_id


def _set_control_lost(
    state: dict[str, Any],
    *,
    reason: str,
    now: dt.datetime,
    validation_reason: str,
) -> None:
    state.update(
        {
            "decision": "control-lost",
            "status": "interrupt-pending",
            "reasons": [reason],
            "control_action_required": True,
            "session_disposition": "quarantined",
            "artifact_disposition": "architect-adjudication-required",
            "artifact_validation": {
                "eligible": False,
                "max_attempts": 1,
                "attempts_used": 0,
                "outcome": "not-run",
                "reason": validation_reason,
            },
            "updated_at": _iso(now),
        }
    )


def arm(args: argparse.Namespace) -> dict[str, Any]:
    release_evidence = _require_direct_release(args, "supervision-arm")
    path, state = _load_control_state(args.state_file)
    _require_state_release(state, "supervision-arm", release_evidence)
    if state.get("status") != "created":
        _fail("arm requires a newly created supervision state")
    now = _iso_now(args.now)
    state["control_turn_id"] = _control_turn(args.control_turn_id)
    state["status"] = "armed"
    state["control_timing"]["armed_at"] = _iso(now)
    state["updated_at"] = _iso(now)
    _audit_event(state, "native_supervision_armed")
    _write_state(path, state)
    return state


def mark_dispatched(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    release_evidence = _require_direct_release(args, "native-dispatch")
    path, state = _load_control_state(args.state_file)
    _require_state_release(state, "native-dispatch", release_evidence)
    if state.get("status") != "armed":
        _fail("mark-dispatched requires an armed supervision state")
    supplied_control_turn = _control_turn(args.control_turn_id)
    submission_id = str(args.submission_id or "").strip()
    if not submission_id:
        _fail("submission-id must be non-empty")
    now = _iso_now(args.now)
    timing = state["control_timing"]
    arm_to_dispatch_ms = _elapsed_ms(timing["armed_at"], now)
    timing["arm_to_dispatch_ms"] = arm_to_dispatch_ms
    timing["dispatched_at"] = _iso(now)
    state["submission_id"] = submission_id
    state["updated_at"] = _iso(now)
    control_failure = None
    validation_reason = None
    if state.get("control_turn_id") != supplied_control_turn:
        control_failure = "control-turn-mismatch-after-dispatch"
        validation_reason = "dispatch control-turn binding lost"
    elif arm_to_dispatch_ms > state["arm_to_dispatch_max_ms"]:
        control_failure = "arm-to-dispatch-latency-exceeded"
        validation_reason = "arm-to-dispatch control timing lost"
    if control_failure:
        _set_control_lost(
            state,
            reason=control_failure,
            now=now,
            validation_reason=str(validation_reason),
        )
        _audit_event(state, "native_supervision_decision")
        state["last_audited_decision"] = "control-lost"
        _write_state(path, state)
        return state, 2
    timing["monitor_armed_before_dispatch"] = True
    state["status"] = "running"
    _audit_event(state, "native_supervision_dispatched")
    _write_state(path, state)
    return state, 0


def _record_poll_timing(state: dict[str, Any], now: dt.datetime) -> bool:
    timing = state["control_timing"]
    reference = timing.get("last_poll_at") or timing.get("dispatched_at")
    if not reference:
        _fail("control-lost: dispatched supervisor state has no poll reference")
    gap_ms = _elapsed_ms(reference, now)
    if timing.get("first_poll_at") is None:
        timing["first_poll_at"] = _iso(now)
        timing["dispatch_to_first_poll_ms"] = gap_ms
    timing["last_poll_at"] = _iso(now)
    timing["max_poll_gap_ms"] = max(int(timing.get("max_poll_gap_ms") or 0), gap_ms)
    allowed_gap_ms = state["poll_interval_ms"] + state["poll_lag_tolerance_ms"]
    if gap_ms > allowed_gap_ms:
        timing["late_poll_count"] = int(timing.get("late_poll_count") or 0) + 1
        return True
    return False


def check(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    path, state = _load_control_state(args.state_file)
    if state.get("status") in {"running", "interrupt-pending", "interrupt-confirmed"}:
        try:
            _require_control_turn(state, args.control_turn_id)
        except SystemExit:
            now = _iso_now(args.now)
            _set_control_lost(
                state,
                reason="control-turn-mismatch-during-monitoring",
                now=now,
                validation_reason="live monitoring control-turn binding lost",
            )
            if state.get("last_audited_decision") != "control-lost":
                _audit_event(state, "native_supervision_decision")
                state["last_audited_decision"] = "control-lost"
            _write_state(path, state)
            return _decision(state), 2
    else:
        _require_control_turn(state, args.control_turn_id)
    if state.get("status") in FINAL_STATES:
        return _decision(state), 2 if state.get("decision") == "control-lost" else 0
    if state.get("status") not in {"running", "interrupt-pending", "interrupt-confirmed"}:
        _fail("check requires a marked-dispatched supervision state")
    now = _iso_now(args.now)
    previous_audited_decision = state.get("last_audited_decision")
    try:
        packet_file = state.get("packet_file")
        if not isinstance(packet_file, str) or not packet_file:
            _fail("control-lost: supervision state has no packet binding")
        packet = _load_json(Path(packet_file).expanduser().resolve(), "packet")
        if artifact_hash(json.dumps(packet, sort_keys=True)) != state.get("packet_sha256"):
            _fail("control-lost: bound packet artifact changed after supervision started")
        policy = load_policy("native-worker-execution")
        all_records, trailing = _read_session(Path(state["session_file"]))
        baseline_record_count = state["baseline_record_count"]
        poll_latency_exceeded = _record_poll_timing(state, now)
        if len(all_records) < baseline_record_count:
            _fail("control-lost: session log was truncated below the supervision watermark")
        records = all_records[baseline_record_count:]
        has_boundary = any(
            _normalize_event_msg(record) == SEGMENT_START_EVENT
            or _is_user_boundary_record(record)
            for record in records
            if isinstance(record, dict)
        )
        if not has_boundary:
            dispatched_at = _iso_now(state["control_timing"]["dispatched_at"])
            elapsed = max(0.0, (now - dispatched_at).total_seconds())
            if elapsed <= state["segment_start_grace_seconds"]:
                reasons = ["awaiting-task-boundary"]
                decision = "warn" if poll_latency_exceeded else "continue"
                if poll_latency_exceeded:
                    reasons.append("poll-latency-observed")
                state.update(
                    {
                        "decision": decision,
                        "status": "running",
                        "reasons": reasons,
                        "control_action_required": False,
                        "trailing_partial_record_ignored": trailing,
                        "updated_at": _iso(now),
                    }
                )
                _write_state(path, state)
                return _decision(state), 0
            _fail("control-lost: task boundary did not appear within startup grace")
        segments, aggregate, overall_status, selected = _evaluate_records(
            records,
            state["budget"],
            state["requested_model"],
            now,
        )
        _ = segments
        _ = aggregate
        previous_observed = state.get("observed")
        if not isinstance(previous_observed, dict):
            _fail("control-lost: supervision state observed evidence is invalid")
        baseline = previous_observed.get("workspace_baseline")
        context_units = previous_observed.get("context_units")
        if not isinstance(baseline, dict) or not isinstance(context_units, list):
            _fail("control-lost: supervision state is missing baseline or context evidence")
        workspace_report = _compare_live_workspace(baseline)
        categories = workspace_report.get("mutation_categories")
        categories = categories if isinstance(categories, dict) else {}
        activity = _classify_native_activity(
            records,
            context_units,
            previous_observed.get("activity"),
            scoped_mutation=bool(categories.get("scoped")),
            policy=policy,
            packet=packet,
        )
        command_evidence = _analyze_command_evidence(
            records,
            packet,
            task_complete=bool(selected.get("complete")),
        )
        observed = dict(previous_observed)
        observed.update(
            {
                "tool_calls": int(selected["tool_calls"]),
                "elapsed_seconds": float(selected["runtime_seconds"]),
                "context_compactions": int(selected["context_compactions"]),
                "full_suite_runs": int(selected["full_suite_runs"]),
                "workspace_report": workspace_report,
                "activity": activity,
                "command_evidence": command_evidence,
            }
        )
        hard_reasons: list[str] = []
        if overall_status == "model-mismatch":
            hard_reasons.append("model-mismatch")
        if observed["context_compactions"] > state["budget"]["max_compactions"]:
            hard_reasons.append("context-compaction")
        if observed["full_suite_runs"] > state["budget"]["max_full_suite_runs"]:
            hard_reasons.append("full-suite-limit")
        hard_reasons.extend(_workspace_hard_reasons(workspace_report))
        hard_reasons.extend(str(reason) for reason in activity.get("violations", []))
        hard_reasons.extend(str(reason) for reason in command_evidence.get("violations", []))

        reserve_reasons: list[str] = []
        if observed["tool_calls"] >= state["interrupt_thresholds"]["tool_calls"]:
            reserve_reasons.append("tool-call-interrupt-threshold")
        if observed["elapsed_seconds"] >= state["interrupt_thresholds"]["runtime_seconds"]:
            reserve_reasons.append("runtime-interrupt-threshold")

        warning_reasons = [str(reason) for reason in activity.get("warnings", [])]
        if poll_latency_exceeded:
            warning_reasons.append("poll-latency-observed")
        if observed["tool_calls"] > state["budget"]["tool_calls_soft"]:
            warning_reasons.append("tool-call-soft-limit")
        if observed["elapsed_seconds"] > state["budget"]["runtime_seconds_soft"]:
            warning_reasons.append("runtime-soft-limit")

        complete = bool(selected.get("complete"))
        if hard_reasons:
            decision = "interrupt"
            reasons = list(dict.fromkeys(hard_reasons))
        elif complete:
            decision = "complete"
            reasons = []
        elif reserve_reasons:
            decision = "interrupt"
            reasons = list(dict.fromkeys(reserve_reasons))
        elif warning_reasons:
            decision = "warn"
            reasons = list(dict.fromkeys(warning_reasons))
        else:
            decision = "continue"
            reasons = []
        disposition = {
            "session_disposition": selected["session_disposition"],
            "artifact_disposition": selected["artifact_disposition"],
            "artifact_validation": selected["artifact_validation"],
        }
        if decision == "interrupt" and disposition["session_disposition"] != "quarantined":
            if hard_reasons:
                disposition = {
                    "session_disposition": "quarantined",
                    "artifact_disposition": "architect-adjudication-required",
                    "artifact_validation": {
                        "eligible": False,
                        "max_attempts": 1,
                        "attempts_used": 0,
                        "outcome": "not-run",
                        "reason": "protected live execution boundary reached",
                    },
                }
            else:
                disposition = {
                    "session_disposition": "quarantined",
                    "artifact_disposition": "independent-validation-required",
                    "artifact_validation": {
                        "eligible": True,
                        "max_attempts": 1,
                        "attempts_used": 0,
                        "outcome": "not-run",
                        "reason": "reserved live budget threshold reached",
                    },
                }
        state.update(
            {
                "decision": decision,
                "status": "interrupt-pending" if decision == "interrupt" else state["status"],
                "reasons": reasons,
                "control_action_required": decision == "interrupt",
                "observed": observed,
                "trailing_partial_record_ignored": trailing,
                "updated_at": _iso(now),
                **disposition,
            }
        )
    except SystemExit as exc:
        state.update(
            {
                "decision": "control-lost",
                "status": "interrupt-pending",
                "reasons": [str(exc)],
                "control_action_required": True,
                "session_disposition": "quarantined",
                "artifact_disposition": "architect-adjudication-required",
                "artifact_validation": {
                    "eligible": False,
                    "max_attempts": 1,
                    "attempts_used": 0,
                    "outcome": "not-run",
                    "reason": "live telemetry or control state lost",
                },
                "updated_at": _iso(now),
            }
        )
    if state.get("decision") != previous_audited_decision:
        _audit_event(state, "native_supervision_decision")
        state["last_audited_decision"] = state.get("decision")
    _write_state(path, state)
    decision = _decision(state)
    return decision, 2 if decision["decision"] in {"interrupt", "control-lost"} else 0


def finalize(args: argparse.Namespace) -> dict[str, Any]:
    path, state = _load_control_state(args.state_file)
    _require_control_turn(state, args.control_turn_id)
    if state.get("status") in FINAL_STATES:
        _fail("finalized supervision state cannot be reopened")
    action = args.control_action
    if action == "worker-completed" and state.get("decision") != "complete":
        _fail("worker-completed requires a complete supervisor decision")
    if action == "interrupt-confirmed" and state.get("decision") not in {"interrupt", "control-lost"}:
        _fail("interrupt-confirmed requires an interrupt or control-lost supervisor decision")
    receipts = list(state.get("control_receipts", []))
    receipts.append(action)
    state["control_receipts"] = receipts
    if action == "interrupt-confirmed":
        state["status"] = "interrupt-confirmed"
    elif action == "close-confirmed":
        if "interrupt-confirmed" not in receipts:
            _fail("close-confirmed requires an interrupt-confirmed receipt")
        state["status"] = "closed"
        state["control_action_required"] = False
        state["finalized_at"] = _iso(_iso_now(args.now))
    elif action == "worker-completed":
        state["status"] = "completed"
        state["decision"] = "complete"
        state["control_action_required"] = False
        state["finalized_at"] = _iso(_iso_now(args.now))
    elif action == "control-failed":
        state["status"] = "control-failed"
        state["decision"] = "control-lost"
        state["session_disposition"] = "quarantined"
        state["artifact_disposition"] = "architect-adjudication-required"
        state["control_action_required"] = False
        state["finalized_at"] = _iso(_iso_now(args.now))
    state["updated_at"] = _iso(_iso_now(args.now))
    _audit_event(state, "native_supervision_control_receipt", control_action=action)
    _write_state(path, state)
    return state


def assess_retry(args: argparse.Namespace) -> dict[str, Any]:
    path, state = _load_control_state(args.state_file)
    _require_control_turn(state, args.control_turn_id)
    _require_closed_for_retry(state)
    _require_native_retry_decision(state)
    parent = _require_state_packet(state.get("packet_file"), state, "parent packet")
    canonical = canonical_work_sha256(parent)
    if state.get("immutable_work_sha256") != canonical:
        _fail("retry lifecycle requires preserved immutable work hash")
    workspace_report = _load_json(Path(args.workspace_report).expanduser().resolve(), "workspace report")
    semantic_result = _load_json(Path(args.semantic_result).expanduser().resolve(), "semantic result")
    policy = _retry_policy()
    eligibility = evaluate_retry_eligibility(
        packet=parent,
        supervision_state=state,
        workspace_report=workspace_report,
        semantic_result=semantic_result,
        recovery_policy=policy,
    )
    recovery = _recovery_payload(state.get("recovery"))
    recovery["eligibility"] = dict(eligibility)
    state["recovery"] = recovery
    state["updated_at"] = _iso(_iso_now(args.now))
    _audit_event(state, "native_retry_assessed")
    _write_state(path, state)
    return eligibility


def authorize_retry(args: argparse.Namespace) -> dict[str, Any]:
    release_evidence = _require_direct_release(args, "native-retry")
    path, state = _load_control_state(args.state_file)
    _require_state_release(state, "native-retry", release_evidence)
    _require_control_turn(state, args.control_turn_id)
    _require_closed_for_retry(state)
    _require_native_retry_decision(state)
    parent = _require_state_packet(state.get("packet_file"), state, "parent packet")
    canonical = canonical_work_sha256(parent)
    if state.get("immutable_work_sha256") != canonical:
        _fail("retry lifecycle requires preserved immutable work hash")
    workspace_report = _load_json(Path(args.workspace_report).expanduser().resolve(), "workspace report")
    semantic_result = _load_json(Path(args.semantic_result).expanduser().resolve(), "semantic result")
    fresh_attestation = _load_json(Path(args.fresh_attestation).expanduser().resolve(), "fresh attestation")
    retry_packet = _load_json(Path(args.retry_packet).expanduser().resolve(), "retry packet")
    errors = validate_native_worker_packet(retry_packet, dispatchable=True)
    if errors:
        _fail("retry packet validation failed: " + "; ".join(errors))
    policy = _retry_policy()
    current = evaluate_retry_eligibility(
        packet=parent,
        supervision_state=state,
        workspace_report=workspace_report,
        semantic_result=semantic_result,
        recovery_policy=policy,
    )
    stored = state.get("recovery", {}).get("eligibility")
    if stored != current:
        _fail("retry requires re-assessing with the same inputs and policy")
    authorization = build_retry_authorization(
        parent_packet=parent,
        retry_packet=retry_packet,
        supervision_state=state,
        workspace_report=workspace_report,
        semantic_result=semantic_result,
        recovery_policy=policy,
        fresh_attestation=fresh_attestation,
    )
    validation_errors = validate_retry_authorization(authorization)
    if validation_errors:
        _fail("retry authorization validation failed: " + "; ".join(validation_errors))
    recovery = _recovery_payload(state.get("recovery"))
    recovery["authorization"] = authorization
    state["recovery"] = recovery
    state["updated_at"] = _iso(_iso_now(args.now))
    _audit_event(state, "native_retry_authorized")
    _write_state(path, state)
    return authorization


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Supervise one native worker against packet-v2 live budgets.")
    commands = parser.add_subparsers(dest="command", required=True)
    start_cmd = commands.add_parser("start")
    start_cmd.add_argument("--packet", required=True)
    start_cmd.add_argument("--session-id", required=True)
    start_cmd.add_argument("--session-file", required=True)
    start_cmd.add_argument("--agent-id", required=True)
    start_cmd.add_argument("--audit-file")
    start_cmd.add_argument("--state-file")
    start_cmd.add_argument("--retry-authorization")
    start_cmd.add_argument("--now")
    start_cmd.add_argument("--json", action="store_true")
    arm_cmd = commands.add_parser("arm")
    arm_cmd.add_argument("--state-file", required=True)
    arm_cmd.add_argument("--control-turn-id", required=True)
    arm_cmd.add_argument("--release-evidence")
    arm_cmd.add_argument("--now")
    arm_cmd.add_argument("--json", action="store_true")
    dispatched_cmd = commands.add_parser("mark-dispatched")
    dispatched_cmd.add_argument("--state-file", required=True)
    dispatched_cmd.add_argument("--control-turn-id", required=True)
    dispatched_cmd.add_argument("--submission-id", required=True)
    dispatched_cmd.add_argument("--release-evidence")
    dispatched_cmd.add_argument("--now")
    dispatched_cmd.add_argument("--json", action="store_true")
    check_cmd = commands.add_parser("check")
    check_cmd.add_argument("--state-file", required=True)
    check_cmd.add_argument("--control-turn-id", required=True)
    check_cmd.add_argument("--now")
    check_cmd.add_argument("--projection", choices=["full", "compact"], default="full")
    check_cmd.add_argument("--json", action="store_true")
    finalize_cmd = commands.add_parser("finalize")
    finalize_cmd.add_argument("--state-file", required=True)
    finalize_cmd.add_argument("--control-turn-id", required=True)
    finalize_cmd.add_argument("--control-action", required=True, choices=["interrupt-confirmed", "close-confirmed", "worker-completed", "control-failed"])
    finalize_cmd.add_argument("--now")
    finalize_cmd.add_argument("--json", action="store_true")
    assess_cmd = commands.add_parser("assess-retry")
    assess_cmd.add_argument("--state-file", required=True)
    assess_cmd.add_argument("--control-turn-id", required=True)
    assess_cmd.add_argument("--workspace-report", required=True)
    assess_cmd.add_argument("--semantic-result", required=True)
    assess_cmd.add_argument("--now")
    assess_cmd.add_argument("--json", action="store_true")
    authorize_cmd = commands.add_parser("authorize-retry")
    authorize_cmd.add_argument("--state-file", required=True)
    authorize_cmd.add_argument("--control-turn-id", required=True)
    authorize_cmd.add_argument("--retry-packet", required=True)
    authorize_cmd.add_argument("--fresh-attestation", required=True)
    authorize_cmd.add_argument("--workspace-report", required=True)
    authorize_cmd.add_argument("--semantic-result", required=True)
    authorize_cmd.add_argument("--release-evidence")
    authorize_cmd.add_argument("--now")
    authorize_cmd.add_argument("--json", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.command == "start":
        result, code = start(args), 0
    elif args.command == "arm":
        result, code = arm(args), 0
    elif args.command == "mark-dispatched":
        result, code = mark_dispatched(args)
    elif args.command == "check":
        result, code = check(args)
        if args.projection == "compact":
            result = _compact_projection(_load_json(Path(args.state_file).expanduser().resolve(), "supervision state"))
    elif args.command == "finalize":
        result, code = finalize(args), 0
    elif args.command == "assess-retry":
        result, code = assess_retry(args), 0
    elif args.command == "authorize-retry":
        result, code = authorize_retry(args), 0
    else:
        _fail(f"unsupported command {args.command!r}")
    if getattr(args, "json", False):
        if args.command == "check" and args.projection == "compact":
            print(json.dumps(result, sort_keys=True, separators=(",", ":")), end="")
        else:
            print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"{args.command}: {result.get('decision', result.get('status'))}")
        if result.get("state_file"):
            print(f"state_file: {result['state_file']}")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
