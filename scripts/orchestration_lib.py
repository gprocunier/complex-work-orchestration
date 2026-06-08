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
    external_ok: bool,
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
            external_ok=external_ok,
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
        if task_class in capabilities or any(part in capabilities for part in [task_class.split("-")[0], "domain-review"]):
            score += scoring.get("task_class_fit", 6)
            reasons.append("task class fit")
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
    unattended: bool = False,
) -> dict[str, Any]:
    ranked = score_executors(
        task_class=expert.get("task_class", "domain-review"),
        risk=rank_max([risk, expert.get("default_risk", "medium")], RISK_ORDER, "low"),
        sensitivity=sensitivity,
        share_boundary=share_boundary,
        external_ok=external_ok,
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

    evaluator_required = route in ["external-contract", "local-worker"]
    architect_adjudication_required = evaluator_required or route == "architect-review" or risk in ["high", "critical"]

    return {
        "route": route,
        "task_class": task_class,
        "risk_level": risk,
        "data_sensitivity": sensitivity,
        "dispatch_sensitivity": dispatch_sensitivity,
        "share_boundary": share_boundary,
        "external_opt_in": external_ok,
        "external_contract_allowed": route == "external-contract" and not hard_stops,
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

    lower = text.lower()
    if "boundary violation" in lower:
        hard_disqualifiers.append("boundary violation")
    if "unapproved patch" in lower or "pushed branch without approval" in lower:
        hard_disqualifiers.append("unapproved patch or repo access")
    if job_description_label and job_description_label not in lower and sections.get("Contractor job description"):
        hard_disqualifiers.append("missing assigned job-description alignment")
    if re.search(r"(?i)(secret|password|api[_ -]?key|private key)\s*[:=]", text):
        hard_disqualifiers.append("suspected secret or personal-data spill")
    if "outside assigned scope" in lower or "broadened scope" in lower:
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
