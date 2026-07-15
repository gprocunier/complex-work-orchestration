"""Pure fast-path proportional execution evaluator for native worker briefs."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Any, Mapping

from cwo_core.native_capability import capability_receipt_applies
from cwo_core.native_containment import containment_error


BRIEF_TYPE = "cwo-proportional-execution-brief"
VERSION = 1
VALID_PATH_CLASSIFICATIONS = {"ignored", "ephemeral", "non-publishable"}

REQUIRED_STEPS = [
    "validate-proportional-brief",
    "evaluate-required-boundaries",
    "evaluate-usage-breakdown",
    "evaluate-visual-adjudication",
    "emit-immutable-task-evidence",
]

SKIPPED_HEAVY_GATES = [
    "scheduler-delay-canary",
    "tool-use-canary",
    "non-essential-policy-checks",
]

FAST_PATH_ROUTE = "native-productive-fast-path"
STANDARD_ORCHESTRATION_ROUTE = "standard-orchestration"

REQUIRED_TOP_LEVEL_KEYS = {
    "brief_type",
    "version",
    "identity",
    "model",
    "tool_surface",
    "output_artifacts",
    "mutation_boundaries",
    "access_boundaries",
    "deterministic_checks",
    "estimates",
    "unresolved_decisions",
    "required_worker_capabilities",
    "available_worker_capabilities",
    "visual_validation",
    "validation_outputs",
    "usage_breakdown",
}

REQUIRED_IDENTITY_KEYS = {"task_id", "lane"}
REQUIRED_MODEL_KEYS = {"requested_model"}
REQUIRED_TOOL_SURFACE_KEYS = {"surface"}
REQUIRED_ARTIFACT_KEYS = {"path", "classification", "tracked", "publishable"}
REQUIRED_MUTATION_BOUNDARY_KEYS = {
    "tracked_source",
    "policy",
    "schema",
    "credential",
    "beads_database",
    "production",
}
REQUIRED_ACCESS_BOUNDARY_KEYS = {
    "privileged_access",
    "secrets",
    "external_disclosure",
    "network",
}
REQUIRED_ESTIMATE_KEYS = {"lines", "tool_calls", "runtime_seconds"}
REQUIRED_UNRESOLVED_KEYS = {"architecture", "security", "policy"}
VISUAL_VALIDATION_KEYS = {"owner", "trusted_screenshots"}
USAGE_BUCKETS = {
    "productive-artifact",
    "validation",
    "orchestration-setup",
    "harness-recovery",
}


def _required_string(value: Any, field_name: str, errors: list[str]) -> str | None:
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{field_name}-must-be-non-empty-string")
        return None
    return value.strip()


def _required_nonempty_string_list(value: Any) -> list[str] | None:
    if not isinstance(value, list):
        return None
    if not value:
        return None
    normalized: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            return None
        normalized.append(item.strip())
    return normalized


def _required_boolean(value: Any, field_name: str, *, errors: list[str]) -> bool | None:
    if not isinstance(value, bool):
        errors.append(f"{field_name}-must-be-boolean")
        return None
    return value


def _required_false(value: Any, field_name: str, *, errors: list[str]) -> bool | None:
    normalized = _required_boolean(value, field_name, errors=errors)
    if normalized is None:
        return None
    if normalized:
        errors.append(f"{field_name}-must-be-false")
    return normalized


def _required_relative_posix_path(path: Any, *, field_name: str, errors: list[str]) -> str | None:
    if not isinstance(path, str):
        errors.append(f"{field_name}-must-be-string")
        return None
    normalized = path.strip()
    if not normalized:
        errors.append(f"{field_name}-must-be-non-empty-string")
        return None
    if "\\" in normalized:
        errors.append(f"{field_name}-must-be-posix")
    normalized_path = PurePosixPath(normalized)
    if normalized_path.is_absolute():
        errors.append(f"{field_name}-must-be-relative")
    parts = normalized.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        errors.append(f"{field_name}-path-traversal-or-empty-segment")
    if normalized != normalized.replace("//", "/"):
        errors.append(f"{field_name}-must-not-duplicate-separators")
    return normalized


def _required_exact_object(
    value: Any,
    field_name: str,
    expected: set[str],
    *,
    errors: list[str],
) -> Mapping[str, Any] | None:
    if not isinstance(value, Mapping):
        errors.append(f"{field_name}-must-be-object")
        return None
    actual = set(value.keys())
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    if missing:
        errors.append(f"{field_name}-missing-fields:" + ",".join(missing))
    if extra:
        errors.append(f"{field_name}-unknown-fields:" + ",".join(extra))
    if missing or extra:
        return None
    return value


def validate_usage_breakdown(value: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(value, Mapping):
        return ["usage-breakdown-must-be-object"]
    actual_buckets = set(value.keys())
    missing_buckets = sorted(USAGE_BUCKETS - actual_buckets)
    unknown_buckets = sorted(actual_buckets - USAGE_BUCKETS)
    if missing_buckets:
        errors.append("usage-breakdown-missing-bucket:" + ",".join(missing_buckets))
    if unknown_buckets:
        errors.append("usage-breakdown-unknown-bucket:" + ",".join(unknown_buckets))

    for bucket in (
        "productive-artifact",
        "validation",
        "orchestration-setup",
        "harness-recovery",
    ):
        if bucket not in value:
            continue
        bucket_value = value[bucket]
        if not isinstance(bucket_value, Mapping):
            errors.append(f"usage-bucket-{bucket}-must-be-object")
            continue
        bucket_keys = set(bucket_value.keys())
        if bucket_keys != {"tool_calls", "elapsed_seconds"}:
            missing = sorted({"tool_calls", "elapsed_seconds"} - bucket_keys)
            unknown = sorted(bucket_keys - {"tool_calls", "elapsed_seconds"})
            if missing:
                errors.append(f"usage-bucket-{bucket}-missing-fields:" + ",".join(missing))
            if unknown:
                errors.append(f"usage-bucket-{bucket}-unknown-fields:" + ",".join(unknown))
        tool_calls = bucket_value.get("tool_calls")
        elapsed_seconds = bucket_value.get("elapsed_seconds")
        if not isinstance(tool_calls, int) or isinstance(tool_calls, bool) or tool_calls < 0:
            errors.append(f"usage-bucket-{bucket}-tool-calls-nonnegative-int")
        if not isinstance(elapsed_seconds, int) or isinstance(elapsed_seconds, bool) or elapsed_seconds < 0:
            errors.append(f"usage-bucket-{bucket}-elapsed-seconds-nonnegative-int")
    return errors


def validate_proportional_brief(brief: Any) -> list[str]:
    if not isinstance(brief, Mapping):
        return ["brief-must-be-object"]

    errors: list[str] = []
    actual_top_level = set(brief.keys())
    missing_top_level = sorted(REQUIRED_TOP_LEVEL_KEYS - actual_top_level)
    extra_top_level = sorted(actual_top_level - REQUIRED_TOP_LEVEL_KEYS)
    if missing_top_level:
        errors.append("brief-missing-top-level-fields:" + ",".join(missing_top_level))
    if extra_top_level:
        errors.append("brief-unknown-top-level-fields:" + ",".join(extra_top_level))

    if brief.get("brief_type") != BRIEF_TYPE:
        errors.append("invalid-brief-type")
    version = brief.get("version")
    if not isinstance(version, int) or isinstance(version, bool) or version != VERSION:
        errors.append("invalid-version")

    identity = _required_exact_object(
        brief.get("identity"),
        "identity",
        REQUIRED_IDENTITY_KEYS,
        errors=errors,
    )
    if identity is not None:
        for key in ("task_id", "lane"):
            _required_string(identity.get(key), f"identity-{key}", errors=errors)

    model = brief.get("model")
    if not isinstance(model, Mapping):
        errors.append("model-must-be-object")
    else:
        _required_exact_object(model, "model", REQUIRED_MODEL_KEYS, errors=errors)
        _required_string(model.get("requested_model"), "model-requested_model", errors=errors)

    tool_surface = brief.get("tool_surface")
    if not isinstance(tool_surface, Mapping):
        errors.append("tool-surface-must-be-object")
    else:
        _required_exact_object(tool_surface, "tool-surface", REQUIRED_TOOL_SURFACE_KEYS, errors=errors)
        _required_string(tool_surface.get("surface"), "tool-surface-surface", errors=errors)

    output_artifacts = brief.get("output_artifacts")
    if not isinstance(output_artifacts, list):
        errors.append("output-artifacts-must-be-array")
    elif len(output_artifacts) != 1:
        errors.append("output-artifacts-must-be-single")
    else:
        artifact = output_artifacts[0]
        if not isinstance(artifact, Mapping):
            errors.append("output-artifact-must-be-object")
        else:
            _required_exact_object(artifact, "output-artifact", REQUIRED_ARTIFACT_KEYS, errors=errors)
            _required_relative_posix_path(
                artifact.get("path"),
                field_name="output-artifact-path",
                errors=errors,
            )
            if artifact.get("classification") not in VALID_PATH_CLASSIFICATIONS:
                errors.append("output-artifact-classification-invalid")
            tracked = _required_boolean(
                artifact.get("tracked"),
                "output-artifact-tracked",
                errors=errors,
            )
            publishable = _required_boolean(
                artifact.get("publishable"),
                "output-artifact-publishable",
                errors=errors,
            )
            if tracked is not None and publishable is not None and (tracked or publishable):
                errors.append("output-artifact-must-be-unpublishable-and-untracked")

    for boundary_key, expected_keys in (
        ("mutation_boundaries", REQUIRED_MUTATION_BOUNDARY_KEYS),
        ("access_boundaries", REQUIRED_ACCESS_BOUNDARY_KEYS),
    ):
        boundaries = brief.get(boundary_key)
        if not isinstance(boundaries, Mapping):
            errors.append(f"{boundary_key.replace('_', '-')}-must-be-object")
            continue
        obj = _required_exact_object(boundaries, boundary_key.replace("_", "-"), expected_keys, errors=errors)
        if obj is None:
            continue
        for key in expected_keys:
            _required_false(obj.get(key), f"{boundary_key}-{key}", errors=errors)

    deterministic_checks = _required_nonempty_string_list(brief.get("deterministic_checks"))
    if deterministic_checks is None:
        errors.append("deterministic-checks-must-be-non-empty-string-list")

    estimates = _required_exact_object(
        brief.get("estimates"),
        "estimates",
        REQUIRED_ESTIMATE_KEYS,
        errors=errors,
    )
    if estimates is not None:
        lines = estimates.get("lines")
        tool_calls = estimates.get("tool_calls")
        runtime_seconds = estimates.get("runtime_seconds")
        if not isinstance(lines, int) or isinstance(lines, bool) or lines < 0 or lines > 500:
            errors.append("estimates-lines-out-of-bound")
        if (
            not isinstance(tool_calls, int)
            or isinstance(tool_calls, bool)
            or tool_calls < 0
            or tool_calls > 12
        ):
            errors.append("estimates-tool-calls-out-of-bound")
        if (
            not isinstance(runtime_seconds, int)
            or isinstance(runtime_seconds, bool)
            or runtime_seconds > 600
            or runtime_seconds < 0
        ):
            errors.append("estimates-runtime-seconds-out-of-bound")

    unresolved = brief.get("unresolved_decisions")
    if not isinstance(unresolved, Mapping):
        errors.append("unresolved-decisions-must-be-object")
    else:
        unresolved_obj = _required_exact_object(
            unresolved,
            "unresolved-decisions",
            REQUIRED_UNRESOLVED_KEYS,
            errors=errors,
        )
        if unresolved_obj is not None:
            for key in REQUIRED_UNRESOLVED_KEYS:
                values = unresolved_obj.get(key)
                if not isinstance(values, list):
                    errors.append(f"unresolved-{key}-must-be-list")
                elif len(values) != 0:
                    errors.append(f"unresolved-{key}-must-be-empty-list")

    required_worker_capabilities = _required_nonempty_string_list(brief.get("required_worker_capabilities"))
    if required_worker_capabilities is None:
        errors.append("required-worker-capabilities-must-be-non-empty-string-list")

    available_worker_capabilities = _required_nonempty_string_list(brief.get("available_worker_capabilities"))
    if available_worker_capabilities is None:
        errors.append("available-worker-capabilities-must-be-non-empty-string-list")

    if not isinstance(brief.get("validation_outputs"), list) or not _required_nonempty_string_list(
        brief.get("validation_outputs")
    ):
        errors.append("validation-outputs-must-be-non-empty-string-list")

    visual_validation = brief.get("visual_validation")
    if not isinstance(visual_validation, Mapping):
        errors.append("visual-validation-must-be-object")
    else:
        visual = _required_exact_object(
            visual_validation,
            "visual-validation",
            VISUAL_VALIDATION_KEYS,
            errors=errors,
        )
        if visual is not None:
            owner = visual.get("owner")
            if owner not in {"worker", "pm", "none"}:
                errors.append("visual-validation-owner-invalid")
            trusted_screenshots = visual.get("trusted_screenshots")
            if not isinstance(trusted_screenshots, list):
                errors.append("trusted-screenshots-must-be-list")
            elif any(not isinstance(item, str) for item in trusted_screenshots):
                errors.append("trusted-screenshots-must-be-list-of-strings")
            elif owner == "worker" and trusted_screenshots:
                errors.append("trusted-screenshots-not-allowed-for-worker-owner")

    errors.extend(validate_usage_breakdown(brief.get("usage_breakdown")))
    if required_worker_capabilities is not None:
        _ = required_worker_capabilities
    if available_worker_capabilities is not None:
        _ = available_worker_capabilities

    return sorted(set(errors))


def immutable_task_payload(brief: Mapping[str, Any]) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    for key, value in brief.items():
        if key in {"validation_outputs", "usage_breakdown", "assessed_at"}:
            continue
        if key == "visual_validation" and isinstance(value, Mapping):
            visual = dict(value)
            visual.pop("trusted_screenshots", None)
            payload[key] = visual
            continue
        payload[key] = value
    return json.loads(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True))


def immutable_task_sha256(brief: Mapping[str, Any]) -> str:
    payload = immutable_task_payload(brief)
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()


def _assess_capability_receipt(
    requested_model: str,
    tool_surface_id: str,
    capability_receipt: Mapping[str, Any] | None,
    assessed_at: str,
) -> str:
    if capability_receipt is None:
        return "receipt-required"
    try:
        if capability_receipt_applies(capability_receipt, requested_model, tool_surface_id, assessed_at):
            return "reuse-existing"
        return "receipt-invalid"
    except Exception:
        return "receipt-invalid"


def _normalize_usage_breakdown(value: Mapping[str, Any]) -> dict[str, dict[str, int]]:
    return {
        bucket: {"tool_calls": int(value[bucket]["tool_calls"]), "elapsed_seconds": int(value[bucket]["elapsed_seconds"])}
        for bucket in (
            "productive-artifact",
            "validation",
            "orchestration-setup",
            "harness-recovery",
        )
    }


def _parse_time(value: Any) -> str:
    if value is None:
        return datetime.now(tz=timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    if isinstance(value, str):
        cleaned = value.replace("Z", "+00:00")
        return datetime.fromisoformat(cleaned).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    raise TypeError("at must be null, ISO timestamp, or datetime")


def evaluate_proportional_execution(
    brief: Mapping[str, Any],
    capability_receipt: Mapping[str, Any] | None = None,
    at: Any = None,
) -> dict[str, Any]:
    reasons = validate_proportional_brief(brief)
    if containment := containment_error("proportional-native-fast-path"):
        reasons.append(containment)
    selected = len(reasons) == 0
    usage_breakdown = brief.get("usage_breakdown")
    usage_valid = not validate_usage_breakdown(usage_breakdown)
    normalized_usage = (
        _normalize_usage_breakdown(usage_breakdown)
        if usage_valid and isinstance(usage_breakdown, Mapping)
        else {
            "productive-artifact": {"tool_calls": 0, "elapsed_seconds": 0},
            "validation": {"tool_calls": 0, "elapsed_seconds": 0},
            "orchestration-setup": {"tool_calls": 0, "elapsed_seconds": 0},
            "harness-recovery": {"tool_calls": 0, "elapsed_seconds": 0},
        }
    )

    assessed_at = _parse_time(at)
    visual_validation = brief.get("visual_validation") if isinstance(brief.get("visual_validation"), Mapping) else {}
    visual_owner = str(visual_validation.get("owner") or "none")
    trusted_screenshots = list(visual_validation.get("trusted_screenshots") or [])
    required_caps = _required_nonempty_string_list(brief.get("required_worker_capabilities")) or []
    available_caps = _required_nonempty_string_list(brief.get("available_worker_capabilities")) or []
    required_caps_missing = sorted(set(required_caps) - set(available_caps))
    if visual_owner == "worker" and "image-input" not in available_caps:
        reasons.append("worker-visual-validation-requires-image-input")
        required_caps_missing = [cap for cap in required_caps_missing if cap != "image-input"]
    if required_caps_missing:
        reasons.append("required-capabilities-missing:" + ",".join(required_caps_missing))

    model_value = brief.get("model", {}).get("requested_model") if isinstance(brief.get("model"), Mapping) else None
    tool_surface_id = (
        brief.get("tool_surface", {}).get("surface")
        if isinstance(brief.get("tool_surface"), Mapping)
        else None
    )
    if model_value is None or tool_surface_id is None:
        capability_action = "receipt-invalid"
    else:
        capability_action = _assess_capability_receipt(model_value, tool_surface_id, capability_receipt, assessed_at)
    if capability_action in {"receipt-required", "receipt-invalid"}:
        reasons.append(capability_action)

    reasons = sorted(set(reasons))
    dispatchable = selected and len(reasons) == 0

    pm_visual_adjudication_required = visual_owner == "pm" and len(trusted_screenshots) > 0

    return {
        "selected": selected,
        "dispatchable": dispatchable,
        "selected_work_plan": dispatchable,
        "dispatch_required": dispatchable,
        "route": FAST_PATH_ROUTE if dispatchable else STANDARD_ORCHESTRATION_ROUTE,
        "reasons": reasons,
        "immutable_task_sha256": immutable_task_sha256(brief),
        "capability_action": capability_action,
        "pm_visual_adjudication_required": pm_visual_adjudication_required,
        "required_steps": list(REQUIRED_STEPS),
        "skipped_steps": list(SKIPPED_HEAVY_GATES),
        "normalized_usage": normalized_usage,
        "assessed_at": assessed_at,
        "usage_breakdown_valid": usage_valid,
    }
