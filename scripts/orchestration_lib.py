#!/usr/bin/env python3
from __future__ import annotations

import datetime as dt
import fnmatch
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
POLICY_DIR = REPO_ROOT / "policy"
AUDIT_DIR = REPO_ROOT / ".orchestration-audit"
AUDIT_LOG = AUDIT_DIR / "audit.jsonl"

RISK_ORDER = ["low", "medium", "high", "critical"]
SENSITIVITY_ORDER = ["public", "redacted", "internal", "restricted"]
EXTERNAL_GUARD_LABELS = ["contractor-only", "no-codex-exec"]
LOCAL_WORKER_GUARD_LABELS = ["local-worker-only", "no-codex-exec"]
MANDATORY_EXCLUDED_ARTIFACTS = {"full_bead_json", "secrets", "production_access"}
CONTRACTOR_PACKET_REQUIRED_FIELDS = [
    "dispatch_id",
    "generated_at",
    "bead_id",
    "executor",
    "share_boundary",
    "job_description_label",
    "expert_profile_included",
    "degraded_context_justification",
    "external_opt_in",
    "opt_in_basis",
    "boundary_description",
    "bead_summary",
    "selected_snippets",
    "included_artifacts",
    "excluded_artifacts",
    "required_return_sections",
    "acceptance_rule",
    "quota_checked",
    "packet_sha256",
]
BLOCKED_PACKET_PATH_PARTS = {".git", ".beads", ".orchestration-audit"}
BLOCKED_PACKET_FILE_NAMES = {
    ".env",
    ".env.local",
    ".env.production",
    ".envrc",
    "id_rsa",
    "id_ed25519",
}
BLOCKED_PACKET_SUFFIXES = {".pem", ".key", ".p12", ".pfx"}


def repo_relative_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(REPO_ROOT).as_posix()
    except ValueError as exc:
        raise SystemExit(f"refusing path outside repository: {path}") from exc


def assert_repo_safe_path(path: Path) -> Path:
    resolved = path.resolve()
    relative = Path(repo_relative_path(resolved))
    parts = set(relative.parts)
    blocked_parts = sorted(parts & BLOCKED_PACKET_PATH_PARTS)
    if blocked_parts:
        raise SystemExit(f"refusing forbidden packet path component: {', '.join(blocked_parts)}")
    lowered_parts = {part.lower() for part in relative.parts}
    name = resolved.name.lower()
    if name in BLOCKED_PACKET_FILE_NAMES:
        raise SystemExit(f"refusing likely secret file in packet: {relative.as_posix()}")
    if ".kube" in lowered_parts and name == "config":
        raise SystemExit(f"refusing kube config in packet: {relative.as_posix()}")
    if resolved.suffix.lower() in BLOCKED_PACKET_SUFFIXES:
        raise SystemExit(f"refusing private key or certificate bundle in packet: {relative.as_posix()}")
    if not resolved.is_file():
        raise SystemExit(f"packet artifact is not a regular file: {relative.as_posix()}")
    probe = resolved.read_bytes()[:4096]
    if b"\0" in probe:
        raise SystemExit(f"refusing binary packet artifact: {relative.as_posix()}")
    return resolved


def load_json_compatible_yaml(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(
            f"{path} is not JSON-compatible YAML: {exc}. "
            "Policy files use a JSON-compatible YAML subset so helpers can run with the Python standard library."
        ) from exc
    if not isinstance(value, dict):
        raise SystemExit(f"{path} must contain a top-level object")
    return value


def load_policy(name: str) -> dict[str, Any]:
    filename = name if name.endswith(".yaml") else f"{name}.yaml"
    path = POLICY_DIR / filename
    if not path.is_file():
        raise SystemExit(f"missing policy file: {path}")
    return load_json_compatible_yaml(path)


def read_text_arg(text: str | None, file_path: str | None) -> str:
    parts: list[str] = []
    if text:
        parts.append(text)
    if file_path:
        parts.append(Path(file_path).read_text(encoding="utf-8"))
    if not parts:
        raise SystemExit("provide task text or --file")
    return "\n\n".join(parts)


def term_hits(text: str, terms: list[str]) -> list[str]:
    haystack = text.lower()
    hits: list[str] = []
    for term in terms:
        needle = term.lower()
        if needle and needle in haystack:
            hits.append(term)
    return hits


def rank_max(values: list[str], order: list[str], default: str) -> str:
    current = default
    for value in values:
        if value in order and order.index(value) > order.index(current):
            current = value
    return current


def rank_allows(value: str, limit: str, order: list[str]) -> bool:
    if value not in order or limit not in order:
        return False
    return order.index(value) <= order.index(limit)


def detect_sensitivity(text: str, routing: dict[str, Any]) -> str:
    sensitivity_terms = routing.get("sensitivity_terms", {})
    for level in ["restricted", "redacted", "public"]:
        if term_hits(text, sensitivity_terms.get(level, [])):
            return level
    if term_hits(text, routing.get("restricted_terms", [])):
        return "restricted"
    return "internal"


def dispatch_sensitivity_for_boundary(sensitivity: str, share_boundary: str) -> str:
    if share_boundary == "redacted-packet" and sensitivity == "internal":
        return "redacted"
    return sensitivity


def path_hits(paths: list[str], patterns: list[str]) -> list[str]:
    hits: list[str] = []
    for path in paths:
        for pattern in patterns:
            if fnmatch.fnmatch(path, pattern):
                hits.append(f"{path}:{pattern}")
    return hits


def score_experts_v2(
    text: str,
    expert_registry: dict[str, Any],
    *,
    requested_roles: list[str] | None = None,
    file_paths: list[str] | None = None,
    stage: str | None = None,
) -> list[dict[str, Any]]:
    requested = {role.lower() for role in (requested_roles or [])}
    paths = file_paths or []
    scoring = load_policy("routing-policy").get("scoring", {}).get("expert", {})
    results: list[dict[str, Any]] = []

    for name, profile in expert_registry.get("experts", {}).items():
        aliases = [name, profile.get("discipline", ""), profile.get("job_description_label", "")]
        aliases.extend(profile.get("aliases", []))
        alias_hits = [alias for alias in aliases if alias and alias.lower() in requested]
        triggers = term_hits(text, profile.get("trigger_terms", []))
        paths_matched = path_hits(paths, profile.get("file_path_patterns", []))
        stage_match = bool(stage and stage == profile.get("review_stage"))

        score = 0
        reasons: list[str] = []
        if alias_hits:
            score += scoring.get("explicit_role", 8) * len(alias_hits)
            reasons.append("requested role: " + ", ".join(alias_hits))
        if triggers:
            score += scoring.get("trigger_term", 3) * len(triggers)
            reasons.append("trigger terms: " + ", ".join(triggers))
        if paths_matched:
            score += scoring.get("path_match", 4) * len(paths_matched)
            reasons.append("path patterns: " + ", ".join(paths_matched[:5]))
        if stage_match:
            score += scoring.get("stage_match", 3)
            reasons.append(f"stage match: {stage}")

        if score <= 0:
            continue

        result = {
            "name": name,
            "display_name": profile.get("display_name", name),
            "discipline": profile.get("discipline", name),
            "persona_file": profile.get("persona_file"),
            "job_description_label": profile.get("job_description_label", "contract-jd-general-reasoning"),
            "task_class": profile.get("task_class", "domain-review"),
            "review_stage": profile.get("review_stage", "pre-implementation"),
            "default_risk": profile.get("default_risk", "medium"),
            "default_share_boundary": profile.get("default_share_boundary", "redacted-packet"),
            "preferred_executors": profile.get("preferred_executors", []),
            "matched_terms": triggers,
            "matched_paths": paths_matched,
            "score": score,
            "reasons": reasons,
            "output_contract": profile.get("output_contract", []),
            "acceptance_checks": profile.get("acceptance_checks", []),
            "escalation_rules": profile.get("escalation_rules", []),
        }
        results.append(result)

    results.sort(key=lambda item: (-int(item["score"]), item["name"]))
    return results


def boundary_config(share_boundary: str) -> dict[str, Any]:
    boundaries = load_policy("share-boundaries").get("boundaries", {})
    boundary = boundaries.get(share_boundary)
    if not isinstance(boundary, dict):
        raise SystemExit(f"unknown share boundary: {share_boundary}")
    return boundary


def boundary_allows_external(share_boundary: str) -> bool:
    return bool(boundary_config(share_boundary).get("allows_external"))


def executor_policy_violations(
    executor: dict[str, Any],
    *,
    task_class: str,
    external_ok: bool,
    local_ok: bool = False,
    share_boundary: str,
    sensitivity: str,
    risk: str,
    unattended: bool = False,
) -> list[str]:
    violations: list[str] = []
    boundary = boundary_config(share_boundary)
    if executor.get("external") and not external_ok:
        violations.append("external dispatch requires user opt-in")
    if executor.get("external") and not boundary.get("allows_external"):
        violations.append(f"share boundary {share_boundary} does not allow external dispatch")
    if executor.get("external") and sensitivity == "restricted" and executor.get("dispatch_mode") != "human":
        violations.append("restricted data cannot be sent to non-human external executors")
    if executor.get("dispatch_mode") == "local_openai_compatible":
        local_policy = load_policy("routing-policy").get("local_worker", {})
        allowed_classes = set(local_policy.get("allowed_task_classes", []))
        allowed_risks = set(local_policy.get("allowed_risks", []))
        if not local_ok:
            violations.append("local worker dispatch requires --local-ok")
        if allowed_classes and task_class not in allowed_classes:
            violations.append(f"task class {task_class} is not allowed for local worker dispatch")
        if allowed_risks and risk not in allowed_risks:
            violations.append(f"risk {risk} is not allowed for local worker dispatch")
        if sensitivity == "restricted":
            violations.append("restricted data cannot be sent to local worker dispatch")
    if not rank_allows(risk, executor.get("max_risk", "low"), RISK_ORDER):
        violations.append(f"risk {risk} exceeds executor max_risk {executor.get('max_risk')}")
    if not rank_allows(sensitivity, executor.get("max_data_sensitivity", "public"), SENSITIVITY_ORDER):
        violations.append(
            f"sensitivity {sensitivity} exceeds executor max_data_sensitivity {executor.get('max_data_sensitivity')}"
        )
    if unattended and executor.get("manual_dispatch_required"):
        violations.append("manual dispatch executor cannot run unattended")
    return violations


def score_executors(
    *,
    task_class: str,
    risk: str,
    sensitivity: str,
    share_boundary: str,
    external_ok: bool,
    local_ok: bool = False,
    prefer_local: bool = False,
    experts: list[dict[str, Any]],
    text: str,
    unattended: bool = False,
) -> list[dict[str, Any]]:
    registry = load_policy("executor-registry").get("executors", {})
    scoring = load_policy("routing-policy").get("scoring", {}).get("executor", {})
    preferred: set[str] = set()
    for expert in experts:
        preferred.update(expert.get("preferred_executors", []))

    need_web = bool(term_hits(text, ["web", "research", "standards", "vendor", "ecosystem", "latest"]))
    need_shell = bool(term_hits(text, ["shell", "repo", "patch", "command", "test", "ci", "script"]))
    results: list[dict[str, Any]] = []

    for key, executor in registry.items():
        capabilities = executor.get("capabilities", [])
        score = 0
        reasons: list[str] = []
        violations = executor_policy_violations(
            executor,
            task_class=task_class,
            external_ok=external_ok,
            local_ok=local_ok,
            share_boundary=share_boundary,
            sensitivity=sensitivity,
            risk=risk,
            unattended=unattended,
        )
        if violations:
            score += scoring.get("policy_violation", -100) * len(violations)
        if key in preferred:
            score += 8
            reasons.append("preferred by matched expert")
        allowed_local_classes = executor.get("allowed_task_classes", [])
        if (
            task_class in capabilities
            or task_class in allowed_local_classes
            or any(part in capabilities for part in [task_class.split("-")[0], "domain-review"])
        ):
            score += scoring.get("task_class_fit", 6)
            reasons.append("task class fit")
        if prefer_local and executor.get("dispatch_mode") == "local_openai_compatible" and not violations:
            score += scoring.get("prefer_local_fit", 12)
            reasons.append("preferred local worker")
        if need_web and executor.get("supports_web"):
            score += scoring.get("tooling_fit", 5)
            reasons.append("web/tooling fit")
        if need_shell and executor.get("supports_shell"):
            score += scoring.get("tooling_fit", 5)
            reasons.append("shell/repo tooling fit")
        if rank_allows(sensitivity, executor.get("max_data_sensitivity", "public"), SENSITIVITY_ORDER):
            score += scoring.get("privacy_fit", 5)
            reasons.append("privacy fit")
        if executor.get("acceptance_required"):
            score += scoring.get("evidence_fit", 4)
            reasons.append("acceptance loop required")
        if executor.get("latency_tier") in ["low", "medium"]:
            score += scoring.get("latency_fit", 3)
        if executor.get("cost_tier") in ["low", "medium"]:
            score += scoring.get("cost_fit", 2)

        results.append(
            {
                "key": key,
                "display_name": executor.get("display_name", key),
                "dispatch_mode": executor.get("dispatch_mode"),
                "external": bool(executor.get("external")),
                "score": score,
                "policy_violations": violations,
                "reasons": reasons,
                "codex_pickup": executor.get("codex_pickup", "allowed"),
                "acceptance_required": bool(executor.get("acceptance_required")),
                "architect_review_required": bool(executor.get("architect_review_required")),
            }
        )

    results.sort(key=lambda item: (-int(item["score"]), item["key"]))
    return results


def select_executor_for_expert(
    expert: dict[str, Any],
    *,
    text: str,
    risk: str,
    sensitivity: str,
    share_boundary: str,
    external_ok: bool,
    local_ok: bool = False,
    prefer_local: bool = False,
    unattended: bool = False,
) -> dict[str, Any]:
    ranked = score_executors(
        task_class=expert.get("task_class", "domain-review"),
        risk=rank_max([risk, expert.get("default_risk", "medium")], RISK_ORDER, "low"),
        sensitivity=sensitivity,
        share_boundary=share_boundary,
        external_ok=external_ok,
        local_ok=local_ok,
        prefer_local=prefer_local,
        experts=[expert],
        text=" ".join(
            str(part)
            for part in [
                text,
                expert.get("discipline", ""),
                expert.get("review_stage", ""),
                expert.get("job_description_label", ""),
            ]
            if part
        ),
        unattended=unattended,
    )
    viable = [item for item in ranked if not item["policy_violations"]]
    selected = viable[0] if viable else ranked[0]
    return {
        "recommended_executor": selected["key"],
        "selected_executor": selected,
        "executor_policy_violations": selected.get("policy_violations", []),
        "executor_candidates": ranked,
    }


def classify_work(
    text: str,
    *,
    external_ok: bool = False,
    local_ok: bool = False,
    prefer_local: bool = False,
    share_boundary: str = "no-outside-sharing",
    requested_roles: list[str] | None = None,
    file_paths: list[str] | None = None,
    stage: str | None = None,
    unattended: bool = False,
) -> dict[str, Any]:
    routing = load_policy("routing-policy")
    experts = score_experts_v2(
        text,
        load_policy("expert-registry"),
        requested_roles=requested_roles,
        file_paths=file_paths,
        stage=stage,
    )
    if not experts:
        experts = score_experts_v2(text + " independent review", load_policy("expert-registry"))

    sensitivity = detect_sensitivity(text, routing)
    dispatch_sensitivity = dispatch_sensitivity_for_boundary(sensitivity, share_boundary)
    risk = rank_max([expert.get("default_risk", "medium") for expert in experts], RISK_ORDER, "low")
    enriched_experts: list[dict[str, Any]] = []
    for expert in experts:
        expert_result = dict(expert)
        expert_result.update(
            select_executor_for_expert(
                expert,
                text=text,
                risk=risk,
                sensitivity=dispatch_sensitivity,
                share_boundary=share_boundary,
                external_ok=external_ok,
                local_ok=local_ok,
                prefer_local=prefer_local,
                unattended=unattended,
            )
        )
        enriched_experts.append(expert_result)
    experts = enriched_experts
    primary = experts[0] if experts else {}
    task_class = primary.get("task_class", routing.get("defaults", {}).get("task_class", "implementation"))
    ranked_executors = primary.get("executor_candidates") or score_executors(
        task_class=task_class,
        risk=risk,
        sensitivity=dispatch_sensitivity,
        share_boundary=share_boundary,
        external_ok=external_ok,
        local_ok=local_ok,
        prefer_local=prefer_local,
        experts=experts,
        text=text,
        unattended=unattended,
    )
    selected = primary.get("selected_executor") or ranked_executors[0]
    recommended_executor = primary.get("recommended_executor", selected["key"])

    dispatch_mode = selected.get("dispatch_mode")
    if selected.get("external"):
        route = "external-contract"
    elif dispatch_mode == "local_openai_compatible":
        route = "local-worker"
    elif recommended_executor in ["frontier_architect", "contractor_evaluator"]:
        route = "architect-review"
    else:
        route = "internal-worker"

    hard_stops = selected.get("policy_violations", [])
    guard_labels: list[str] = []
    if route == "external-contract":
        guard_labels = EXTERNAL_GUARD_LABELS + [primary.get("job_description_label", "contract-jd-general-reasoning")]
    elif route == "local-worker":
        guard_labels = LOCAL_WORKER_GUARD_LABELS + [primary.get("job_description_label", "contract-jd-general-reasoning")]

    evaluator_required = route in ["external-contract", "local-worker"]
    architect_adjudication_required = evaluator_required or route == "architect-review" or risk in ["high", "critical"]
    external_experts = [
        str(expert.get("name"))
        for expert in experts
        if expert_uses_external_contract(expert, recommended_executor)
    ]
    local_worker_experts = [
        str(expert.get("name"))
        for expert in experts
        if expert_uses_local_worker(expert, recommended_executor)
    ]
    internal_experts = [
        str(expert.get("name"))
        for expert in experts
        if not expert_uses_external_contract(expert, recommended_executor)
        and not expert_uses_local_worker(expert, recommended_executor)
    ]
    acceptance_required_experts = [
        str(expert.get("name"))
        for expert in experts
        if expert_uses_external_contract(expert, recommended_executor)
        or expert_uses_local_worker(expert, recommended_executor)
    ]

    return {
        "route": route,
        "task_class": task_class,
        "risk_level": risk,
        "data_sensitivity": sensitivity,
        "dispatch_sensitivity": dispatch_sensitivity,
        "share_boundary": share_boundary,
        "external_opt_in": external_ok,
        "external_contract_allowed": route == "external-contract" and not hard_stops,
        "local_worker_allowed": local_ok,
        "prefer_local_worker": prefer_local,
        "has_external_expert_contracts": bool(external_experts),
        "has_local_worker_contracts": bool(local_worker_experts),
        "external_experts": external_experts,
        "local_worker_experts": local_worker_experts,
        "internal_experts": internal_experts,
        "acceptance_required_experts": acceptance_required_experts,
        "recommended_executor": recommended_executor,
        "selected_executor": selected,
        "required_experts": experts,
        "ranked_experts": experts,
        "ranked_executors": ranked_executors,
        "guard_labels": guard_labels,
        "evaluator_required": evaluator_required,
        "architect_adjudication_required": architect_adjudication_required,
        "architect_review_required": architect_adjudication_required,
        "beads_required_for_full_handoff": True,
        "hard_stops": hard_stops,
        "reasons": [
            "ranked experts: " + ", ".join(f"{item['name']}={item['score']}" for item in experts[:5]),
            "ranked executors: " + ", ".join(f"{item['key']}={item['score']}" for item in ranked_executors[:5]),
        ],
    }


def metadata_json(metadata: dict[str, Any]) -> str:
    return json.dumps(metadata, sort_keys=True, separators=(",", ":"))


def redact_text(value: str) -> str:
    redacted = value
    for pattern in load_policy("share-boundaries").get("redaction_patterns", []):
        redacted = re.sub(pattern, "[REDACTED]", redacted)
    return redacted


def sanitize_bead(bead_json: Any, share_boundary: str) -> dict[str, Any]:
    boundary = boundary_config(share_boundary)
    whitelist = set(boundary.get("field_whitelist", []))
    forbidden = set(boundary.get("forbidden_fields", []))
    if not isinstance(bead_json, dict):
        return {"raw_type": type(bead_json).__name__}
    source = bead_json.get("issue") if isinstance(bead_json.get("issue"), dict) else bead_json
    sanitized: dict[str, Any] = {}
    for key, value in source.items():
        if key in forbidden:
            continue
        if whitelist and key not in whitelist:
            continue
        sanitized[key] = redact_value(value)
    return sanitized


def redact_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, dict):
        return {key: redact_value(item) for key, item in value.items()}
    return value


def artifact_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def make_dispatch_id(bead_id: str, generated_at: str | None = None) -> str:
    timestamp = generated_at or dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_bead = re.sub(r"[^A-Za-z0-9_.-]+", "-", bead_id).strip("-") or "unassigned"
    return f"dispatch-{safe_bead}-{timestamp}"


def packet_payload_hash(packet: dict[str, Any]) -> str:
    payload = dict(packet)
    payload.pop("packet_sha256", None)
    return artifact_hash(json.dumps(payload, sort_keys=True))


def parse_iso_datetime(value: str, field_name: str) -> dt.datetime:
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SystemExit(f"{field_name} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise SystemExit(f"{field_name} must include a timezone")
    return parsed.astimezone(dt.timezone.utc)


def artifact_whitelist_for_boundary(share_boundary: str) -> set[str]:
    return set(boundary_config(share_boundary).get("artifact_whitelist", []))


def selected_executor_for_expert(expert: dict[str, Any], fallback_executor: str | None = None) -> dict[str, Any]:
    selected = expert.get("selected_executor")
    if isinstance(selected, dict):
        return selected
    key = expert.get("recommended_executor") or fallback_executor
    registry = load_policy("executor-registry").get("executors", {})
    executor = registry.get(key) if key else None
    if isinstance(executor, dict):
        value = dict(executor)
        value.setdefault("key", key)
        return value
    return {"key": str(key or ""), "external": False, "codex_pickup": "allowed", "dispatch_mode": ""}


def expert_uses_external_contract(expert: dict[str, Any], fallback_executor: str | None = None) -> bool:
    return bool(selected_executor_for_expert(expert, fallback_executor).get("external"))


def expert_uses_local_worker(expert: dict[str, Any], fallback_executor: str | None = None) -> bool:
    return selected_executor_for_expert(expert, fallback_executor).get("dispatch_mode") == "local_openai_compatible"


def expert_review_lane(expert: dict[str, Any]) -> str:
    raw = str(expert.get("name") or expert.get("discipline") or expert.get("display_name") or "review")
    slug = re.sub(r"[^a-z0-9]+", "-", raw.lower()).strip("-") or "review"
    return f"expert-review-{slug}"


def expert_review_labels(expert: dict[str, Any], route: dict[str, Any]) -> list[str]:
    stage = str(expert.get("review_stage", "pre-implementation"))
    job_label = str(expert.get("job_description_label", "contract-jd-general-reasoning"))
    if expert_uses_external_contract(expert, route.get("recommended_executor")):
        return [*EXTERNAL_GUARD_LABELS, job_label, stage]
    if expert_uses_local_worker(expert, route.get("recommended_executor")):
        return [*LOCAL_WORKER_GUARD_LABELS, job_label, stage]
    return ["expert-review", job_label, stage]


def expert_review_metadata(expert: dict[str, Any], route: dict[str, Any]) -> dict[str, Any]:
    selected = selected_executor_for_expert(expert, route.get("recommended_executor"))
    executor = expert.get("recommended_executor") or selected.get("key") or route.get("recommended_executor")
    external = bool(selected.get("external"))
    dispatch_mode = selected.get("dispatch_mode")
    local_worker = dispatch_mode == "local_openai_compatible"
    return {
        "expert": expert.get("name"),
        "discipline": expert.get("discipline"),
        "job_description_label": expert.get("job_description_label"),
        "review_stage": expert.get("review_stage"),
        "share_boundary": route.get("share_boundary"),
        "executor": executor,
        "selected_executor": selected,
        "executor_policy_violations": expert.get("executor_policy_violations", []),
        "codex_pickup": "forbidden" if external or local_worker else selected.get("codex_pickup", "allowed"),
        "architect_review_required": True,
        "acceptance_bead_required": external or local_worker,
    }


def validate_opt_in_record(path: str | Path, *, executor: str, share_boundary: str) -> dict[str, Any]:
    record_path = Path(path)
    if not record_path.is_file():
        raise SystemExit(f"opt-in record does not exist: {record_path}")
    try:
        record = json.loads(record_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"opt-in record is not valid JSON: {record_path}: {exc}") from exc
    if not isinstance(record, dict):
        raise SystemExit("opt-in record must contain a top-level object")

    if record.get("allowed") is not True and record.get("external_contracting_allowed") is not True:
        raise SystemExit("opt-in record must set allowed=true or external_contracting_allowed=true")

    boundaries = record.get("share_boundaries", record.get("share_boundary"))
    if isinstance(boundaries, str):
        boundary_allowed = boundaries in [share_boundary, "*"]
    elif isinstance(boundaries, list):
        boundary_allowed = share_boundary in boundaries or "*" in boundaries
    else:
        boundary_allowed = False
    if not boundary_allowed:
        raise SystemExit(f"opt-in record does not allow share boundary {share_boundary!r}")

    executors = record.get(
        "allowed_external_executors",
        record.get("allowed_executors", record.get("executors", record.get("executor"))),
    )
    if isinstance(executors, str):
        executor_allowed = executors in [executor, "*"]
    elif isinstance(executors, list):
        executor_allowed = executor in executors or "*" in executors
    else:
        executor_allowed = False
    if not executor_allowed:
        raise SystemExit(f"opt-in record does not allow executor {executor!r}")

    if not record.get("decision_source"):
        raise SystemExit("opt-in record must include decision_source")
    if not record.get("recorded_at"):
        raise SystemExit("opt-in record must include recorded_at")
    parse_iso_datetime(str(record["recorded_at"]), "recorded_at")
    expires_at = record.get("expires_at")
    if expires_at:
        expiry = parse_iso_datetime(str(expires_at), "expires_at")
        if expiry <= dt.datetime.now(dt.timezone.utc):
            raise SystemExit("opt-in record has expired")
    if not record.get("scope"):
        raise SystemExit("opt-in record must include scope")
    return record


def find_forbidden_fields(value: Any, forbidden_fields: set[str], prefix: str = "") -> list[str]:
    hits: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if key in forbidden_fields:
                hits.append(path)
            hits.extend(find_forbidden_fields(item, forbidden_fields, path))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            path = f"{prefix}[{index}]" if prefix else f"[{index}]"
            hits.extend(find_forbidden_fields(item, forbidden_fields, path))
    return hits


def validate_contractor_packet(packet: dict[str, Any], *, allow_degraded_packet: bool = False) -> list[str]:
    errors: list[str] = []
    if not isinstance(packet, dict):
        return ["packet must contain a top-level object"]

    for field in CONTRACTOR_PACKET_REQUIRED_FIELDS:
        if field not in packet:
            errors.append(f"packet is missing required field {field!r}")
    if errors:
        return errors

    executor_key = str(packet.get("executor", ""))
    executors = load_policy("executor-registry").get("executors", {})
    executor = executors.get(executor_key)
    if not isinstance(executor, dict):
        errors.append(f"packet executor {executor_key!r} is unknown")
    elif not executor.get("external"):
        errors.append(f"packet executor {executor_key!r} is not an outside contractor executor")

    controls = load_contracting_controls()
    allowed_external = set(controls.get("allowed_external_executors", []))
    if allowed_external and executor_key not in allowed_external:
        errors.append(f"packet executor {executor_key!r} is not allowed by contracting controls")

    share_boundary = str(packet.get("share_boundary", ""))
    try:
        boundary = boundary_config(share_boundary)
    except SystemExit as exc:
        errors.append(str(exc))
        boundary = {}
    if boundary and not boundary.get("allows_external"):
        errors.append(f"packet share boundary {share_boundary!r} does not allow external contracting")

    if packet.get("external_opt_in") is not True:
        errors.append("packet external_opt_in must be true")
    if packet.get("opt_in_basis") in [None, "", "not-recorded"]:
        errors.append("packet opt_in_basis must record explicit user opt-in")
    if not str(packet.get("job_description_label", "")).startswith("contract-jd-"):
        errors.append("packet job_description_label must be a contract-jd label")
    if packet.get("expert_profile_included") is not True and not allow_degraded_packet:
        errors.append("packet is missing the expert profile; pass --allow-degraded-packet to dispatch anyway")
    if packet.get("expert_profile_included") is not True and not str(packet.get("degraded_context_justification", "")).strip():
        errors.append("degraded packet is missing degraded_context_justification")

    expected_hash = packet_payload_hash(packet)
    if packet.get("packet_sha256") != expected_hash:
        errors.append("packet_sha256 does not match packet payload")

    forbidden_fields = set(boundary.get("forbidden_fields", [])) if boundary else set()
    forbidden_hits = find_forbidden_fields(packet.get("bead_summary", {}), forbidden_fields)
    if forbidden_hits:
        errors.append("bead_summary contains forbidden boundary fields: " + ", ".join(sorted(forbidden_hits)))

    excluded_types = {
        artifact.get("type")
        for artifact in packet.get("excluded_artifacts", [])
        if isinstance(artifact, dict)
    }
    missing_exclusions = sorted(MANDATORY_EXCLUDED_ARTIFACTS - excluded_types)
    if missing_exclusions:
        errors.append("excluded_artifacts is missing mandatory exclusions: " + ", ".join(missing_exclusions))

    whitelist = set(boundary.get("artifact_whitelist", [])) if boundary else set()
    included_artifacts = [item for item in packet.get("included_artifacts", []) if isinstance(item, dict)]
    selected_snippets = [item for item in packet.get("selected_snippets", []) if isinstance(item, dict)]
    snippet_limit = int(boundary.get("snippet_line_limit", 0)) if boundary else 0
    for artifact in packet.get("included_artifacts", []):
        artifact_type = artifact.get("type") if isinstance(artifact, dict) else None
        if not artifact_type:
            errors.append("included_artifacts contains an artifact without a type")
        elif artifact_type not in whitelist:
            errors.append(f"artifact type {artifact_type!r} is not allowed by share boundary {share_boundary!r}")

    for snippet in packet.get("selected_snippets", []):
        if not isinstance(snippet, dict):
            errors.append("selected_snippets contains a non-object entry")
            continue
        required_snippet_fields = {"type", "path", "line_count", "truncated", "sha256", "content"}
        missing = sorted(required_snippet_fields - set(snippet))
        if missing:
            errors.append(f"selected snippet {snippet.get('path', '<unknown>')} is missing fields: {', '.join(missing)}")
        snippet_type = snippet.get("type") if isinstance(snippet, dict) else None
        if snippet_type and snippet_type not in whitelist:
            errors.append(f"snippet artifact type {snippet_type!r} is not allowed by share boundary {share_boundary!r}")
        line_count = snippet.get("line_count")
        if not isinstance(line_count, int):
            errors.append(f"selected snippet {snippet.get('path', '<unknown>')} has non-integer line_count")
        elif snippet_limit and line_count > snippet_limit:
            errors.append(
                f"selected snippet {snippet.get('path', '<unknown>')} exceeds boundary line limit {snippet_limit}"
            )
        content = snippet.get("content")
        sha256 = snippet.get("sha256")
        if isinstance(content, str) and isinstance(sha256, str) and artifact_hash(content) != sha256:
            errors.append(f"selected snippet {snippet.get('path', '<unknown>')} sha256 does not match content")

    assignment = next((item for item in included_artifacts if item.get("type") == "assignment_summary"), None)
    if not assignment:
        errors.append("included_artifacts is missing assignment_summary")
    elif assignment.get("sha256") != artifact_hash(json.dumps(packet.get("bead_summary", {}), sort_keys=True)):
        errors.append("assignment_summary sha256 does not match bead_summary")

    if packet.get("expert_profile_included"):
        profile = packet.get("expert_profile") or {}
        profile_artifact = next((item for item in included_artifacts if item.get("type") == "expert_profile"), None)
        if not profile_artifact:
            errors.append("included_artifacts is missing expert_profile")
        elif isinstance(profile, dict):
            if profile_artifact.get("path") != profile.get("path") or profile_artifact.get("sha256") != profile.get("sha256"):
                errors.append("expert_profile artifact does not match expert_profile payload")

    for artifact in included_artifacts:
        artifact_type = artifact.get("type")
        if artifact_type in {"selected_file_snippet", "inline_snippet"}:
            match = next(
                (
                    snippet
                    for snippet in selected_snippets
                    if snippet.get("type") == artifact_type
                    and snippet.get("path") == artifact.get("path")
                    and snippet.get("sha256") == artifact.get("sha256")
                ),
                None,
            )
            if not match:
                errors.append(f"included artifact {artifact_type}:{artifact.get('path')} has no matching selected snippet")

    if not packet.get("required_return_sections"):
        errors.append("packet required_return_sections must not be empty")
    return errors


def require_valid_contractor_packet(packet: dict[str, Any], *, allow_degraded_packet: bool = False) -> None:
    errors = validate_contractor_packet(packet, allow_degraded_packet=allow_degraded_packet)
    if errors:
        raise SystemExit("invalid contractor packet:\n- " + "\n- ".join(errors))


def load_expert_profile(persona_file: str | None) -> dict[str, str]:
    if not persona_file:
        return {}
    safe_path = assert_repo_safe_path(REPO_ROOT / persona_file)
    content = safe_path.read_text(encoding="utf-8")
    return {
        "path": repo_relative_path(safe_path),
        "sha256": artifact_hash(content),
        "content": content,
    }


def file_snippet(path: Path, *, max_lines: int) -> dict[str, Any]:
    repo_path = assert_repo_safe_path(path)
    relative = repo_relative_path(repo_path)
    lines = repo_path.read_text(encoding="utf-8", errors="replace").splitlines()
    selected = "\n".join(lines[:max_lines])
    redacted = redact_text(selected)
    return {
        "type": "selected_file_snippet",
        "path": relative,
        "line_count": min(len(lines), max_lines),
        "truncated": len(lines) > max_lines,
        "sha256": artifact_hash(redacted),
        "content": redacted,
    }


def load_contracting_controls() -> dict[str, Any]:
    return load_policy("contracting-controls")


def executor_external(executor_key: str) -> bool:
    executor = load_policy("executor-registry").get("executors", {}).get(executor_key)
    if not isinstance(executor, dict):
        raise SystemExit(f"unknown executor {executor_key!r}; see policy/executor-registry.yaml")
    return bool(executor.get("external"))


def executor_dispatch_mode(executor_key: str) -> str:
    executor = load_policy("executor-registry").get("executors", {}).get(executor_key)
    if not isinstance(executor, dict):
        raise SystemExit(f"unknown executor {executor_key!r}; see policy/executor-registry.yaml")
    return str(executor.get("dispatch_mode", ""))


def iter_audit_events(audit_file: Path | None = None) -> list[dict[str, Any]]:
    audit_file = audit_file or AUDIT_LOG
    if not audit_file.exists():
        return []
    events: list[dict[str, Any]] = []
    for line in audit_file.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            events.append(value)
    return events


def count_audit_events(
    event_type: str,
    epic_id: str | None,
    executor_external: bool,
    *,
    ignore_dispatch_id: str | None = None,
) -> int:
    unique_dispatches: set[str] = set()
    for event in iter_audit_events():
        if event.get("quota_event_type") != event_type:
            continue
        event_epic = event.get("epic_id")
        if epic_id is None:
            if event_epic not in [None, ""]:
                continue
        elif event_epic != epic_id:
            continue
        if bool(event.get("executor_external")) != executor_external:
            continue
        dispatch_id = str(event.get("dispatch_id") or event.get("event_hash") or json.dumps(event, sort_keys=True))
        if ignore_dispatch_id and dispatch_id == ignore_dispatch_id:
            continue
        unique_dispatches.add(dispatch_id)
    return len(unique_dispatches)


def enforce_contracting_quota(
    epic_id: str | None,
    executor: str,
    route: str,
    *,
    dispatch_id: str | None = None,
) -> dict[str, Any]:
    controls = load_contracting_controls()
    quotas = controls.get("quota_policy", {})
    is_external = executor_external(executor)
    dispatch_mode = executor_dispatch_mode(executor)
    if is_external:
        quota_key = "external_manual_dispatches_per_epic"
        quota_event_type = "external_manual_dispatch"
    elif route == "local-worker" or dispatch_mode == "local_openai_compatible":
        quota_key = "local_worker_dispatches_per_epic"
        quota_event_type = "local_worker_dispatch"
    else:
        return {
            "quota_checked": False,
            "quota_event_type": None,
            "quota_limit": None,
            "quota_remaining": None,
            "executor_external": is_external,
        }
    limit = int(quotas.get(quota_key, 0))
    if limit <= 0:
        raise SystemExit(f"quota {quota_key} is not configured")
    used = count_audit_events(quota_event_type, epic_id, is_external, ignore_dispatch_id=dispatch_id)
    remaining_before = limit - used
    if remaining_before <= 0:
        scope = epic_id or "global"
        raise SystemExit(f"{quota_key} exhausted for {scope}: used {used} of {limit}")
    return {
        "quota_checked": True,
        "quota_event_type": quota_event_type,
        "quota_limit": limit,
        "quota_remaining": remaining_before - 1,
        "executor_external": is_external,
    }


def parse_return_sections(text: str) -> dict[str, str]:
    sections: dict[str, str] = {}
    current: str | None = None
    buffer: list[str] = []
    header_re = re.compile(r"^\s*([A-Za-z][A-Za-z /-]+)\s*:\s*(.*)$")
    for line in text.splitlines():
        match = header_re.match(line)
        if match:
            if current:
                sections[current] = "\n".join(buffer).strip()
            current = match.group(1).strip()
            buffer = [match.group(2).strip()] if match.group(2).strip() else []
        elif current:
            buffer.append(line)
    if current:
        sections[current] = "\n".join(buffer).strip()
    return sections


def section_value(sections: dict[str, str], *names: str) -> str:
    normalized = {key.lower(): value for key, value in sections.items()}
    for name in names:
        value = normalized.get(name.lower())
        if value is not None:
            return value.strip()
    return ""


def negative_field(value: str) -> bool:
    normalized = value.strip().lower()
    if not normalized:
        return False
    return bool(
        re.match(r"^(no|false|none|not observed|not present|not applicable|n/a|na)\b", normalized)
        or re.search(r"\b(no|not observed|not present|none)\s+(boundary violation|secret|personal-data spill|scope creep|patch)\b", normalized)
    )


def affirmative_field(value: str) -> bool:
    normalized = value.strip().lower()
    if not normalized or negative_field(value):
        return False
    return bool(
        re.match(r"^(yes|true|required|present|observed|found|confirmed|compliant|approved|authorized|unauthorized|unapproved)\b", normalized)
        or re.search(r"\b(violation observed|secret spill|personal-data spill|outside assigned scope|broadened scope|without approval)\b", normalized)
    )


def nonempty_work_field(value: str) -> bool:
    return bool(value.strip()) and not negative_field(value)


def make_acceptance_decision(
    text: str,
    *,
    bead_id: str | None = None,
    dispatch_id: str | None = None,
    share_boundary: str | None = None,
    job_description_label: str | None = None,
) -> dict[str, Any]:
    policy = load_policy("acceptance-policy")
    sections = parse_return_sections(text)
    required = policy.get("contractor_return_required_sections", [])
    missing = [section for section in required if not sections.get(section)]
    penalties = policy.get("score", {}).get("penalties", {})
    score = int(policy.get("score", {}).get("start", 100))
    penalty_reasons: list[str] = []
    hard_disqualifiers: list[str] = []

    if missing:
        score -= penalties.get("missing_required_section", 20) * len(missing)
        penalty_reasons.append("missing sections: " + ", ".join(missing))
    evidence = sections.get("Evidence", "")
    if not evidence or len(evidence.split()) < 4:
        score -= penalties.get("no_concrete_evidence", 20)
        penalty_reasons.append("evidence is missing or too thin")
    validation = sections.get("Validation result", "")
    if not validation or re.search(r"\b(none|not run|n/a)\b", validation, re.I):
        score -= penalties.get("non_reproducible_validation", 15)
        penalty_reasons.append("validation is missing or non-reproducible")
    recommendation = sections.get("Recommended next bead", "")
    if not recommendation or len(recommendation.split()) < 4:
        score -= penalties.get("vague_recommendation", 15)
        penalty_reasons.append("recommended next bead is vague")
    if not sections.get("Confidence"):
        score -= penalties.get("missing_confidence", 10)
        penalty_reasons.append("confidence missing")
    if not sections.get("Risks or gaps"):
        score -= penalties.get("missing_residual_risk", 10)
        penalty_reasons.append("risks or gaps missing")

    boundary_violation = section_value(sections, "Boundary violation")
    if affirmative_field(boundary_violation):
        hard_disqualifiers.append("boundary violation")

    patch_authorization = section_value(sections, "Patch authorization")
    files_changed = section_value(sections, "Files changed")
    commands_run = section_value(sections, "Commands run")
    if share_boundary == "patch-branch":
        if not nonempty_work_field(files_changed) or not nonempty_work_field(commands_run):
            hard_disqualifiers.append("patch branch return missing files changed or commands run")
    elif nonempty_work_field(files_changed) and not affirmative_field(patch_authorization):
        hard_disqualifiers.append("unapproved patch or repo access")
    if affirmative_field(patch_authorization) and re.search(r"\b(unapproved|unauthorized|without approval)\b", patch_authorization, re.I):
        hard_disqualifiers.append("unapproved patch or repo access")

    lower = text.lower()
    if job_description_label and job_description_label not in lower and sections.get("Contractor job description"):
        hard_disqualifiers.append("missing assigned job-description alignment")
    secret_spill = section_value(sections, "Secret or personal-data spill", "Secret spill", "Personal-data spill")
    if affirmative_field(secret_spill):
        hard_disqualifiers.append("suspected secret or personal-data spill")
    if re.search(r"(?i)(secret|password|api[_ -]?key|private key)\s*[:=]", text):
        hard_disqualifiers.append("suspected secret or personal-data spill")
    scope_compliance = section_value(sections, "Scope compliance")
    scope_lower = scope_compliance.strip().lower()
    scope_noncompliant = bool(
        re.match(r"^(no|false)\b", scope_lower)
        and not re.search(r"\b(no scope creep|no deviation|no out-of-scope work)\b", scope_lower)
    ) or bool(
        scope_compliance
        and re.search(r"\b(outside assigned scope|broadened scope|scope creep)\b", scope_compliance, re.I)
        and not re.search(r"\b(no|not observed|not present)\s+(scope creep|out-of-scope|deviation)\b", scope_compliance, re.I)
    )
    if scope_compliance and not affirmative_field(scope_compliance) and not scope_noncompliant:
        penalty_reasons.append("scope compliance field is unclear")
    if scope_noncompliant:
        hard_disqualifiers.append("scope creep beyond assigned bead")
        score -= penalties.get("scope_creep", 10)

    score = max(0, min(100, score))
    escalation = re.search(r"^\s*Escalation needed\s*:\s*(yes|true|required)", text, re.I | re.M)
    thresholds = policy.get("score", {}).get("thresholds", {})
    if hard_disqualifiers:
        verdict = "reject"
    elif escalation:
        verdict = "escalate"
    elif score >= thresholds.get("accept", 85):
        verdict = "accept"
    elif score >= thresholds.get("clarify", 70):
        verdict = "clarify"
    elif score >= thresholds.get("partial_accept", 50):
        verdict = "partial-accept"
    else:
        verdict = "reject"

    return {
        "dispatch_id": dispatch_id,
        "bead_id": bead_id,
        "share_boundary": share_boundary,
        "verdict": verdict,
        "score": score,
        "missing_sections": missing,
        "penalty_reasons": penalty_reasons,
        "hard_disqualifiers": hard_disqualifiers,
        "escalation_flagged": bool(escalation),
        "architect_review_required": True,
        "sections": sections,
    }


def record_audit_event(event: dict[str, Any], audit_file: Path | None = None) -> dict[str, Any]:
    audit_file = audit_file or AUDIT_LOG
    audit_file.parent.mkdir(parents=True, exist_ok=True)
    enriched = dict(event)
    enriched.setdefault("timestamp", dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    enriched.setdefault("event_hash", artifact_hash(json.dumps(enriched, sort_keys=True)))
    with audit_file.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(enriched, sort_keys=True) + "\n")
    return enriched


def require_bd() -> None:
    if not shutil.which("bd"):
        raise SystemExit("bd was not found; install Beads or use --dry-run")


def run_bd(args: list[str]) -> str:
    require_bd()
    completed = subprocess.run(
        ["bd", *args],
        check=False,
        cwd=REPO_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        raise SystemExit(completed.stderr.strip() or completed.stdout.strip() or "bd command failed")
    return completed.stdout


def parse_created_issue_id(output: str) -> str:
    match = re.search(r"Created issue:\s+([^\s]+)", output)
    if match:
        return match.group(1)
    stripped = output.strip()
    if stripped and " " not in stripped:
        return stripped
    return ""


def create_bead(
    title: str,
    *,
    issue_type: str = "task",
    priority: int = 2,
    parent: str | None = None,
    labels: list[str] | None = None,
    description: str | None = None,
    acceptance: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    args = ["create", title, "--type", issue_type, "--priority", str(priority)]
    if parent:
        args.extend(["--parent", parent])
    if labels:
        args.extend(["--labels", ",".join(labels)])
    if description:
        args.extend(["--description", description])
    if acceptance:
        args.extend(["--acceptance", acceptance])
    if metadata:
        args.extend(["--metadata", metadata_json(metadata)])
    output = run_bd(args)
    return {"id": parse_created_issue_id(output), "title": title, "raw_output": output.strip()}


def show_bead_json(bead_id: str) -> Any:
    output = run_bd(["show", bead_id, "--json"])
    return json.loads(output)


def add_dependency(blocked: str, blocker: str) -> None:
    run_bd(["dep", "add", blocked, blocker])
