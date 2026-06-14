#!/usr/bin/env python3
from __future__ import annotations

import datetime as dt
import fnmatch
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
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
EDITOR_GATE_EXPERT = "editor"
PUBLIC_DOCS_EDITOR_TEXT_TERMS = [
    "public docs",
    "public documentation",
    "public guide",
    "readme",
    "install docs",
    "installation docs",
    "install section",
    "beads install",
    "beads setup",
    "operator docs",
    "github pages",
    "github page",
    "homepage",
    "home page",
    "docs bug",
    "public-docs editor",
    "editor oversharing",
    "internal monologue",
    "docs plus pages",
    "documentation plus github pages",
    "docs and pages",
    "site flow",
    "docs flow",
    "pages flow",
    "documentation architecture",
    "diataxis",
    "diátaxis",
]
PUBLIC_DOCS_PAGE_TEXT_TERMS = [
    "github pages",
    "github page",
    "docs site",
    "documentation site",
    "website",
    "web site",
    "site flow",
    "pages flow",
    "web design",
    "ux",
    "ui",
    "html",
    "css",
    "frontend",
    "diataxis",
    "diátaxis",
]
PUBLIC_DOCS_PATHS = {"README.md", "SKILL.md"}
PUBLIC_DOCS_PAGE_SUFFIXES = {".html", ".css", ".js"}
MANDATORY_EXCLUDED_ARTIFACTS = {"full_bead_json", "secrets", "production_access"}
CONTRACTOR_PACKET_REQUIRED_FIELDS = [
    "dispatch_id",
    "generated_at",
    "bead_id",
    "executor",
    "provider_key",
    "provider_trust_tier",
    "share_boundary",
    "disclosure_stage",
    "disclosure_escalation_approved",
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
LOCAL_DISPATCH_REQUIRED_FIELDS = [
    "envelope_type",
    "version",
    "dispatch_id",
    "executor_key",
    "provider_key",
    "transport_kind",
    "messages",
    "constraints",
    "execution_enabled",
]
PROMPT_COACH_RESULT_REQUIRED_FIELDS = [
    "coach_result_type",
    "version",
    "beads_tracking_required",
    "recommended_orchestration_level",
    "rationale",
    "missing_questions",
    "interactive_questions",
    "enabled_levers",
    "disabled_levers",
    "workerbee_parallelism",
    "route",
    "paste_ready_prompt",
    "warnings",
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
        if not needle:
            continue
        prefix = r"(?<![a-z0-9])" if needle[0].isalnum() else ""
        suffix = r"(?![a-z0-9])" if needle[-1].isalnum() else ""
        pattern = f"{prefix}{re.escape(needle)}{suffix}"
        if re.search(pattern, haystack):
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


def provider_profile(provider_key: str | None) -> dict[str, Any]:
    providers = load_policy("provider-registry").get("providers", {})
    profile = providers.get(provider_key or "")
    if not isinstance(profile, dict):
        return {}
    value = dict(profile)
    value.setdefault("key", provider_key)
    return value


def provider_metadata_for_executor(executor: dict[str, Any]) -> dict[str, Any]:
    provider = provider_profile(executor.get("provider_key"))
    return {
        "provider_key": provider.get("key"),
        "provider_family": provider.get("family"),
        "provider_trust_tier": provider.get("trust_tier"),
        "provider_retention_class": provider.get("retention_class"),
        "provider_conflict_risk_domains": provider.get("conflict_risk_domains", []),
    }


def detect_provider_conflicts(text: str, provider_registry: dict[str, Any] | None = None) -> list[str]:
    registry = provider_registry or load_policy("provider-registry")
    conflicts: list[str] = []
    for domain, terms in registry.get("conflict_risk_terms", {}).items():
        if term_hits(text, terms):
            conflicts.append(str(domain))
    return sorted(set(conflicts))


def explicit_gemini_architect_critique_requested(text: str) -> bool:
    """Return true only for the opt-in Gemini/Agy design-critic pattern."""
    return bool(
        term_hits(text, ["gemini", "agy", "antigravity"])
        and term_hits(text, ["architect", "architecture", "design"])
        and term_hits(text, ["second opinion", "critique", "critic"])
    )


def explicit_chatgpt_master_plan_review_requested(text: str) -> bool:
    """Return true for the ChatGPT Pro Extended Reasoning plan-review lane."""
    return bool(
        term_hits(text, ["chatgpt", "gpt 5.5", "5.5 pro", "openai"])
        and term_hits(
            text,
            [
                "extended reasoning",
                "master plan",
                "master reviewer",
                "total work packet",
                "work packet reviewer",
                "final execution plan",
                "final plan review",
            ],
        )
    )


def explicit_openai_deep_research_requested(text: str) -> bool:
    """Return true for the separate ChatGPT Deep Research opt-in lane."""
    return bool(term_hits(text, ["deep research"]))


def peer_review_policy() -> dict[str, Any]:
    return load_policy("peer-review-policy")


def route_requires_peer_review(
    *,
    route: str,
    risk: str,
    share_boundary: str,
    provider_conflict_domains: list[str],
) -> bool:
    policy = peer_review_policy()
    if bool(policy.get("required_for_routes", {}).get(route)):
        return True
    if bool(policy.get("required_for_share_boundaries", {}).get(share_boundary)):
        return True
    if risk in set(policy.get("required_for_risk_levels", [])):
        return True
    return bool(provider_conflict_domains and policy.get("required_for_provider_conflict", True))


def share_boundary_disclosure_stage(share_boundary: str) -> str:
    return str(boundary_config(share_boundary).get("disclosure_stage", share_boundary))


def share_boundary_requires_escalation(share_boundary: str) -> bool:
    return bool(boundary_config(share_boundary).get("requires_disclosure_escalation"))


def path_hits(paths: list[str], patterns: list[str]) -> list[str]:
    hits: list[str] = []
    for path in paths:
        for pattern in patterns:
            if fnmatch.fnmatch(path, pattern):
                hits.append(f"{path}:{pattern}")
    return hits


def expert_result_from_profile(
    name: str,
    profile: dict[str, Any],
    *,
    triggers: list[str] | None = None,
    paths_matched: list[str] | None = None,
    score: int = 0,
    reasons: list[str] | None = None,
) -> dict[str, Any]:
    return {
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
        "matched_terms": triggers or [],
        "matched_paths": paths_matched or [],
        "score": score,
        "reasons": reasons or [],
        "output_contract": profile.get("output_contract", []),
        "acceptance_checks": profile.get("acceptance_checks", []),
        "escalation_rules": profile.get("escalation_rules", []),
        "validation_gate_required": bool(profile.get("validation_gate_required", False)),
        "gate_scope": profile.get("gate_scope"),
    }


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

        result = expert_result_from_profile(
            name,
            profile,
            triggers=triggers,
            paths_matched=paths_matched,
            score=score,
            reasons=reasons,
        )
        results.append(result)

    results.sort(key=lambda item: (-int(item["score"]), item["name"]))
    return results


def is_public_docs_path(path: str) -> bool:
    clean = path.strip().lstrip("./")
    if clean in PUBLIC_DOCS_PATHS:
        return True
    return clean.startswith("docs/")


def is_public_docs_page_path(path: str) -> bool:
    clean = path.strip().lstrip("./")
    if not clean.startswith("docs/"):
        return False
    return Path(clean).suffix in PUBLIC_DOCS_PAGE_SUFFIXES


def public_docs_editor_gate_required(text: str, file_paths: list[str] | None = None) -> bool:
    lowered = text.lower()
    if any(term in lowered for term in PUBLIC_DOCS_EDITOR_TEXT_TERMS):
        return True
    return any(is_public_docs_path(path) for path in file_paths or [])


def public_docs_page_review_required(text: str, file_paths: list[str] | None = None) -> bool:
    lowered = text.lower()
    if any(term in lowered for term in PUBLIC_DOCS_PAGE_TEXT_TERMS):
        return True
    return any(is_public_docs_page_path(path) for path in file_paths or [])


def ensure_public_docs_gate_experts(
    experts: list[dict[str, Any]],
    expert_registry: dict[str, Any],
    *,
    text: str,
    file_paths: list[str] | None = None,
) -> tuple[list[dict[str, Any]], bool, list[str]]:
    if not public_docs_editor_gate_required(text, file_paths):
        return experts, False, []

    required = ["documentation", EDITOR_GATE_EXPERT]
    if public_docs_page_review_required(text, file_paths):
        required.insert(1, "web_design")

    existing = {str(expert.get("name")) for expert in experts}
    enriched = list(experts)
    added: list[str] = []
    for name in required:
        if name in existing:
            continue
        profile = expert_registry.get("experts", {}).get(name)
        if not profile:
            continue
        result = expert_result_from_profile(
            name,
            profile,
            score=2,
            reasons=["mandatory public docs/pages editor gate"],
        )
        enriched.append(result)
        existing.add(name)
        added.append(name)

    for expert in enriched:
        if expert.get("name") == EDITOR_GATE_EXPERT:
            expert["validation_gate_required"] = True
            expert["gate_scope"] = "public-docs-pages"

    enriched.sort(key=lambda item: (-int(item["score"]), item["name"]))
    return enriched, True, added


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
    allow_disclosure_escalation: bool = False,
    local_ok: bool = False,
    local_profile: str | None = None,
    share_boundary: str,
    sensitivity: str,
    risk: str,
    unattended: bool = False,
    provider_conflict_domains: list[str] | None = None,
) -> list[str]:
    violations: list[str] = []
    boundary = boundary_config(share_boundary)
    provider = provider_profile(executor.get("provider_key"))
    if executor.get("external") and not external_ok:
        violations.append("external dispatch requires user opt-in")
    if executor.get("external") and not boundary.get("allows_external"):
        violations.append(f"share boundary {share_boundary} does not allow external dispatch")
    if executor.get("external") and boundary.get("requires_disclosure_escalation") and not allow_disclosure_escalation:
        violations.append(f"share boundary {share_boundary} requires disclosure escalation approval")
    if executor.get("external") and sensitivity == "restricted" and executor.get("dispatch_mode") != "human":
        violations.append("restricted data cannot be sent to non-human external executors")
    if executor.get("dispatch_mode") in {"local_openai_compatible", "local_secure_review"}:
        local_policy = load_policy("routing-policy").get("local_worker", {})
        allowed_classes = set(executor.get("allowed_task_classes") or local_policy.get("allowed_task_classes", []))
        allowed_risks = set(executor.get("allowed_risks") or local_policy.get("allowed_risks", []))
        if not local_ok:
            violations.append("local worker dispatch requires --local-ok")
        if local_profile and executor.get("local_profile") != local_profile:
            violations.append(f"local profile {local_profile} requires a matching local executor")
        if allowed_classes and task_class not in allowed_classes:
            violations.append(f"task class {task_class} is not allowed for local worker dispatch")
        if allowed_risks and risk not in allowed_risks:
            violations.append(f"risk {risk} is not allowed for local worker dispatch")
        if sensitivity == "restricted":
            violations.append("restricted data cannot be sent to local worker dispatch")
    if provider and provider_conflict_domains:
        overlap = sorted(set(provider.get("conflict_risk_domains", [])) & set(provider_conflict_domains))
        if overlap and not provider.get("may_primary", True):
            violations.append("provider is not allowed as primary for conflict domains: " + ", ".join(overlap))
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
    allow_disclosure_escalation: bool = False,
    local_ok: bool = False,
    prefer_local: bool = False,
    local_profile: str | None = None,
    experts: list[dict[str, Any]],
    text: str,
    unattended: bool = False,
    provider_conflict_domains: list[str] | None = None,
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
            allow_disclosure_escalation=allow_disclosure_escalation,
            local_ok=local_ok,
            local_profile=local_profile,
            share_boundary=share_boundary,
            sensitivity=sensitivity,
            risk=risk,
            unattended=unattended,
            provider_conflict_domains=provider_conflict_domains,
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
        if prefer_local and executor.get("dispatch_mode") in {"local_openai_compatible", "local_secure_review"} and not violations:
            score += scoring.get("prefer_local_fit", 12)
            reasons.append("preferred local worker")
        if local_profile and executor.get("local_profile") == local_profile and not violations:
            score += scoring.get("prefer_local_fit", 12)
            reasons.append(f"matched local profile: {local_profile}")
        if (
            executor.get("dispatch_mode") == "local_openai_compatible"
            and not need_shell
            and not executor.get("supports_repo_read")
            and not violations
        ):
            score += scoring.get("least_privilege_fit", 2)
            reasons.append("least-privilege local fit")
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
        if key == "gemini_3_1_pro_preview_agy" and explicit_gemini_architect_critique_requested(text):
            score += 30
            reasons.append("explicit Gemini/Agy architect critique request")
        if key == "chatgpt_pro_5_5_extended_reasoning_browser" and explicit_chatgpt_master_plan_review_requested(text):
            score += 36
            reasons.append("explicit ChatGPT Pro Extended Reasoning master plan review request")
        if key == "openai_deep_research_manual" and explicit_openai_deep_research_requested(text):
            score += 30
            reasons.append("explicit Deep Research request")
        if key == "openai_deep_research_manual" and explicit_chatgpt_master_plan_review_requested(text):
            score -= 12
            reasons.append("Extended Reasoning master review is distinct from Deep Research")
        if (
            explicit_chatgpt_master_plan_review_requested(text)
            and key != "chatgpt_pro_5_5_extended_reasoning_browser"
            and executor.get("external")
        ):
            score -= 80
            reasons.append("explicit ChatGPT request does not authorize alternate external provider")

        provider_metadata = provider_metadata_for_executor(executor)
        results.append(
            {
                "key": key,
                "display_name": executor.get("display_name", key),
                "role": executor.get("role"),
                "venue": executor.get("venue"),
                "dispatch_mode": executor.get("dispatch_mode"),
                "external": bool(executor.get("external")),
                **provider_metadata,
                "local_profile": executor.get("local_profile"),
                "transport": executor.get("transport"),
                "supports_repo_read": bool(executor.get("supports_repo_read")),
                "supports_repo_write": bool(executor.get("supports_repo_write")),
                "supports_shell": bool(executor.get("supports_shell")),
                "supports_web": bool(executor.get("supports_web")),
                "score": score,
                "policy_violations": violations,
                "reasons": reasons,
                "codex_pickup": executor.get("codex_pickup", "allowed"),
                "acceptance_required": bool(executor.get("acceptance_required")),
                "architect_review_required": bool(executor.get("architect_review_required")),
                "critique_mode": executor.get("critique_mode"),
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
    allow_disclosure_escalation: bool = False,
    local_ok: bool = False,
    prefer_local: bool = False,
    local_profile: str | None = None,
    unattended: bool = False,
    provider_conflict_domains: list[str] | None = None,
) -> dict[str, Any]:
    gate_requires_internal_review = bool(expert.get("validation_gate_required"))
    ranked = score_executors(
        task_class=expert.get("task_class", "domain-review"),
        risk=rank_max([risk, expert.get("default_risk", "medium")], RISK_ORDER, "low"),
        sensitivity=sensitivity,
        share_boundary=share_boundary,
        external_ok=external_ok and not gate_requires_internal_review,
        allow_disclosure_escalation=allow_disclosure_escalation and not gate_requires_internal_review,
        local_ok=local_ok and not gate_requires_internal_review,
        prefer_local=prefer_local and not gate_requires_internal_review,
        local_profile=local_profile,
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
        provider_conflict_domains=provider_conflict_domains,
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
    allow_disclosure_escalation: bool = False,
    local_ok: bool = False,
    prefer_local: bool = False,
    local_profile: str | None = None,
    share_boundary: str = "no-outside-sharing",
    requested_roles: list[str] | None = None,
    file_paths: list[str] | None = None,
    stage: str | None = None,
    unattended: bool = False,
) -> dict[str, Any]:
    routing = load_policy("routing-policy")
    expert_registry = load_policy("expert-registry")
    experts = score_experts_v2(
        text,
        expert_registry,
        requested_roles=requested_roles,
        file_paths=file_paths,
        stage=stage,
    )
    if not experts:
        experts = score_experts_v2(text + " independent review", expert_registry)
    requested = {role.lower() for role in (requested_roles or [])}
    if (
        explicit_gemini_architect_critique_requested(text)
        and any(expert.get("name") == "architecture" for expert in experts)
        and not {"general", "general_reasoning", "contract-jd-general-reasoning"} & requested
    ):
        experts = [expert for expert in experts if expert.get("name") != "general_reasoning"]
    if (
        explicit_chatgpt_master_plan_review_requested(text)
        and any(expert.get("name") == "master_plan_review" for expert in experts)
        and not {"general", "general_reasoning", "contract-jd-general-reasoning"} & requested
    ):
        experts = [expert for expert in experts if expert.get("name") != "general_reasoning"]
    skip_editor_gate_for_local_review = bool(
        local_ok and prefer_local and not public_docs_editor_gate_required(text, file_paths)
    )
    if skip_editor_gate_for_local_review:
        editor_gate_required = False
        editor_gate_added: list[str] = []
    else:
        experts, editor_gate_required, editor_gate_added = ensure_public_docs_gate_experts(
            experts,
            expert_registry,
            text=text,
            file_paths=file_paths,
        )

    sensitivity = detect_sensitivity(text, routing)
    dispatch_sensitivity = dispatch_sensitivity_for_boundary(sensitivity, share_boundary)
    risk = rank_max([expert.get("default_risk", "medium") for expert in experts], RISK_ORDER, "low")
    provider_conflict_domains = detect_provider_conflicts(text)
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
                allow_disclosure_escalation=allow_disclosure_escalation,
                local_ok=local_ok,
                prefer_local=prefer_local,
                local_profile=local_profile,
                unattended=unattended,
                provider_conflict_domains=provider_conflict_domains,
            )
        )
        enriched_experts.append(expert_result)
    experts = enriched_experts
    primary = experts[0] if experts else {}
    primary_external = next((expert for expert in experts if expert_uses_external_contract(expert)), None)
    primary_local = next((expert for expert in experts if expert_uses_local_worker(expert)), None)
    route_primary = primary_external or primary_local or primary
    task_class = route_primary.get("task_class", routing.get("defaults", {}).get("task_class", "implementation"))
    ranked_executors = route_primary.get("executor_candidates") or score_executors(
        task_class=task_class,
        risk=risk,
        sensitivity=dispatch_sensitivity,
        share_boundary=share_boundary,
        external_ok=external_ok,
        allow_disclosure_escalation=allow_disclosure_escalation,
        local_ok=local_ok,
        prefer_local=prefer_local,
        local_profile=local_profile,
        experts=experts,
        text=text,
        unattended=unattended,
        provider_conflict_domains=provider_conflict_domains,
    )
    selected = route_primary.get("selected_executor") or ranked_executors[0]
    recommended_executor = route_primary.get("recommended_executor", selected["key"])

    dispatch_mode = selected.get("dispatch_mode")
    if selected.get("external"):
        route = "external-contract"
    elif dispatch_mode in {"local_openai_compatible", "local_secure_review"}:
        route = "local-worker"
    elif recommended_executor in ["frontier_architect", "contractor_evaluator"]:
        route = "architect-review"
    else:
        route = "internal-worker"

    hard_stops = selected.get("policy_violations", [])
    guard_labels: list[str] = []
    if route == "external-contract":
        guard_labels = EXTERNAL_GUARD_LABELS + [
            route_primary.get("job_description_label", "contract-jd-general-reasoning")
        ]
    elif route == "local-worker":
        guard_labels = LOCAL_WORKER_GUARD_LABELS + [
            route_primary.get("job_description_label", "contract-jd-general-reasoning")
        ]

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
    peer_required = route_requires_peer_review(
        route=route,
        risk=risk,
        share_boundary=share_boundary,
        provider_conflict_domains=provider_conflict_domains,
    )
    peer_policy = peer_review_policy()
    peer_review_count = int(peer_policy.get("defaults", {}).get("minimum_peer_reviews", 1)) if peer_required else 0

    return {
        "route": route,
        "task_class": task_class,
        "risk_level": risk,
        "data_sensitivity": sensitivity,
        "dispatch_sensitivity": dispatch_sensitivity,
        "share_boundary": share_boundary,
        "external_opt_in": external_ok,
        "disclosure_escalation_approved": allow_disclosure_escalation,
        "external_contract_allowed": route == "external-contract" and not hard_stops,
        "local_worker_allowed": local_ok,
        "prefer_local_worker": prefer_local,
        "local_profile": local_profile,
        "has_external_expert_contracts": bool(external_experts),
        "has_local_worker_contracts": bool(local_worker_experts),
        "external_experts": external_experts,
        "local_worker_experts": local_worker_experts,
        "internal_experts": internal_experts,
        "acceptance_required_experts": acceptance_required_experts,
        "recommended_executor": recommended_executor,
        "selected_executor": selected,
        "provider_conflict_detected": bool(provider_conflict_domains),
        "provider_conflict_domains": provider_conflict_domains,
        "provider_diversity_required": bool(peer_required and peer_policy.get("defaults", {}).get("provider_diversity_required", True)),
        "peer_review_required": peer_required,
        "peer_review_count": peer_review_count,
        "peer_review_labels": peer_policy.get("peer_review_labels", []),
        "quarantine_on_fail": bool(peer_policy.get("defaults", {}).get("quarantine_on_high_sabotage", True)),
        "local_secure_review_executor": peer_policy.get("defaults", {}).get("local_secure_review_executor"),
        "required_experts": experts,
        "ranked_experts": experts,
        "ranked_executors": ranked_executors,
        "editor_gate_required": editor_gate_required,
        "editor_gate_added_experts": editor_gate_added,
        "editor_gate_experts": (
            [
                str(expert.get("name"))
                for expert in experts
                if expert.get("name") in {"documentation", "web_design", EDITOR_GATE_EXPERT}
            ]
            if editor_gate_required
            else []
        ),
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


def text_has_any(text: str, terms: list[str]) -> bool:
    return bool(term_hits(text, terms))


def prompt_coach_has_full_harness_signal(text: str) -> bool:
    if text_has_any(
        text,
        [
            "use $complex-work-orchestration to scaffold",
            "$complex-work-orchestration to scaffold",
            "scaffold this project",
            "scaffold a project",
            "scaffold the project",
            "full scaffold",
            "full harness",
            "pm coordination",
            "project manager",
            "role/lane",
            "role lane",
            "role lanes",
            "lane tasks",
            "epic",
            "contractor lane",
            "contractor lanes",
            "outside contractor lane",
            "outside contractor lanes",
        ],
    ):
        return True
    return prompt_coach_has_explicit_workerbee_request(text)


def prompt_coach_has_workerbee_availability_constraint(text: str) -> bool:
    if "codex 5.3 spark" not in text:
        return False
    return text_has_any(
        text,
        [
            "not available",
            "unavailable",
            "isn't available",
            "is not available",
            "not being available",
            "cannot use",
            "can't use",
            "chatgpt pro",
            "pro plan",
            "fallback",
            "fallbacks",
            "tunable",
        ],
    )


def prompt_coach_has_conditional_workerbee_language(text: str) -> bool:
    return bool(
        re.search(r"\bif\s+selected\b.{0,80}\bworkerbee", text)
        or re.search(r"\bworkerbee.{0,80}\bif\s+selected\b", text)
        or re.search(r"\bif\s+.*\bcoach\b.{0,80}\bworkerbee", text)
        or re.search(r"\bworkerbee.{0,80}\bif\s+.*\bcoach\b", text)
    )


def prompt_coach_has_explicit_workerbee_request(text: str) -> bool:
    if prompt_coach_has_workerbee_availability_constraint(text):
        return False
    if prompt_coach_has_conditional_workerbee_language(text):
        return False
    explicit_patterns = [
        r"\buse\s+(?:review-only\s+|parallel\s+|implementation\s+)?workerbees?\b",
        r"\buse\s+(?:review-only\s+|parallel\s+|implementation\s+)?subagents?\b",
        r"\buse\s+codex\s+5\.3\s+spark(?:\s+workerbees?)?\b",
        r"\bcall out\s+codex\s+5\.3\s+spark(?:\s+workerbees?)?\b",
        r"\blaunch\s+workerbees?\b",
        r"\blaunch\s+subagents?\b",
        r"\bspawn\s+workerbees?\b",
        r"\bspawn\s+subagents?\b",
        r"\brun\s+workerbees?\b",
        r"\brun\s+subagents?\b",
        r"\bparallel\s+workerbees?\b",
        r"\bparallel\s+subagents?\b",
        r"\breview-only\s+workerbees?\b",
        r"\breview-only\s+subagents?\b",
        r"\bworkerbee\s+validation\b",
        r"\bworkerbee\s+lanes?\b",
        r"\bsubagent\s+validation\b",
        r"\bsubagent\s+lanes?\b",
        r"\bwith\s+workerbees?\b",
        r"\bwith\s+subagents?\b",
        r"\bimplementation[-\s]+workerbees?\b",
        r"\bimplementation[-\s]+subagents?\b",
        r"\b(?:spawn|run|split|dispatch)\s+implementation[-\s]+workerbees?\b",
        r"\b(?:spawn|run|split|dispatch)\s+implementation[-\s]+subagents?\b",
        r"\bheav(?:y|ily)\s+parallel",
    ]
    return any(re.search(pattern, text) for pattern in explicit_patterns)


def prompt_coach_has_contractor_sharing_signal(text: str) -> bool:
    return text_has_any(
        text,
        [
            "claude",
            "chatgpt",
            "openai deep research",
            "gpt 5.5",
            "extended reasoning",
            "gemini",
            "agy",
            "antigravity",
            "opus",
            "mythos",
            "master plan reviewer",
            "total work packet",
            "outside model",
            "external contractor",
            "third-party",
            "contractor lane",
            "contractor lanes",
            "outside contractor lane",
            "outside contractor lanes",
            "contractor review",
            "external review",
        ],
    )


def prompt_coach_parallel_workerbee_signal(text: str, level: str, route: dict[str, Any]) -> dict[str, Any]:
    lower = text.lower()
    explicit_workerbee = prompt_coach_has_explicit_workerbee_request(lower)
    model_unavailable = prompt_coach_has_workerbee_availability_constraint(lower)
    review_terms = [
        "parallel",
        "multiple agents",
        "independent investigation",
        "review pass",
        "second pass",
        "docs",
        "documentation",
        "github pages",
        "site flow",
        "diataxis",
        "tests",
        "validation",
        "ci",
        "policy",
        "routing",
        "scaffold",
        "publish",
        "release",
    ]
    implementation_terms = [
        "parallel implementation",
        "implementation workerbee",
        "implementation workerbees",
        "implementation subagent",
        "implementation subagents",
        "split implementation",
        "disjoint patches",
        "disjoint files",
        "independent patches",
    ]
    heavy_review_terms = [
        "heavily parallelize",
        "heavy parallelization",
        "heavy review parallelism",
        "heavy parallel review",
        "heavily parallelized",
        "parallelize heavily",
        "multiple parallel reviews",
        "heavy subagent",
        "heavy subagents",
    ]
    suggested_lanes: list[str] = []
    if text_has_any(lower, ["docs", "documentation", "readme", "github pages", "site flow", "diataxis", "diátaxis"]):
        suggested_lanes.append("docs-flow-review")
        suggested_lanes.append("terminology-review")
        suggested_lanes.append("web-design-review")
    if text_has_any(lower, ["policy", "routing", "route", "scaffold", "coach", "orchestration"]):
        suggested_lanes.append("policy-routing-review")
    if text_has_any(lower, ["tests", "validation", "ci", "schema"]):
        suggested_lanes.append("test-gap-review")
    if text_has_any(lower, ["publish", "release", "public", "sanitize", "sanitization"]):
        suggested_lanes.append("publish-sanitization-review")

    if not suggested_lanes and text_has_any(lower, review_terms):
        suggested_lanes.append("bounded-investigation")

    prompt_user = True
    mode = "none"
    rationale: list[str] = []
    if text_has_any(lower, heavy_review_terms):
        mode = "heavy-review"
        rationale.append("The request explicitly asks to heavily parallelize bounded review work.")
    elif text_has_any(lower, implementation_terms):
        mode = "implementation-capable"
        if explicit_workerbee:
            rationale.append("The request explicitly asks for workerbee execution on separable implementation work.")
        else:
            rationale.append("The request names separable implementation work that may be safe to split by file ownership.")
    elif level in {"full-harness", "publish-release"} or text_has_any(lower, review_terms):
        mode = "review-only"
        if explicit_workerbee:
            rationale.append("The request explicitly asks for workerbee or subagent workstreams.")
        else:
            rationale.append("Independent review, test, docs, policy, or validation workstreams can run beside main-thread implementation.")

    if mode == "none":
        suggested_lanes = []
        rationale.append("No clear parallel sidecar workstream is needed; ask anyway so the user can explicitly choose subagents or stay in-thread.")
    if route.get("route") in {"external-contract", "local-worker"} and mode != "none":
        rationale.append("Workerbees are separate from contractor/local-worker dispatch; do not use them for no-codex-exec contract work.")

    return {
        "recommended_mode": mode,
        "recommended_model": (
            "smallest-available-capable-review-workerbee"
            if mode != "none" and model_unavailable
            else "gpt-5.3-codex-spark"
            if mode != "none"
            else None
        ),
        "prompt_user_in_plan_mode": prompt_user,
        "suggested_lanes": suggested_lanes,
        "rationale": rationale,
    }


def prompt_coach_level(route: dict[str, Any], text: str) -> str:
    lower = text.lower()
    publish_terms = [
        "publish",
        "release",
        "push upstream",
        "github",
        "tag",
        "public repo",
        "sanitize",
        "publication",
    ]
    durable_terms = [
        "multi-session",
        "handoff",
        "beads",
        "work graph",
        "multiple agents",
        "parallel",
        "epic",
        "project",
    ]

    if route.get("external_contract_allowed"):
        return "external-contract"
    if route.get("route") == "local-worker" and route.get("has_local_worker_contracts"):
        return "local-worker"
    if text_has_any(lower, publish_terms):
        return "publish-release"
    if prompt_coach_has_full_harness_signal(lower):
        return "full-harness"
    if route.get("risk_level") in {"high", "critical"} or route.get("peer_review_required"):
        return "full-harness"
    if text_has_any(lower, durable_terms) or route.get("route") == "architect-review":
        return "lightweight-beads"
    return "in-thread"


def prompt_coach_missing_questions(
    route: dict[str, Any],
    text: str,
    file_paths: list[str] | None,
    workerbee_parallelism: dict[str, Any] | None = None,
) -> list[dict[str, str]]:
    lower = text.lower()
    words = re.findall(r"[A-Za-z0-9_/-]+", text)
    questions: list[dict[str, str]] = []

    if len(words) < 4:
        questions.append(
            {
                "id": "goal_success_criteria",
                "question": "What is the concrete goal and what would make the work complete?",
                "why": "The task text is too short for reliable sizing.",
                "default": "Ask for goal, success criteria, and validation before scaffolding.",
            }
        )
    if not file_paths and text_has_any(lower, ["repo", "code", "patch", "tests", "implementation", "publish", "release"]):
        questions.append(
            {
                "id": "repo_or_paths",
                "question": "Which repository, paths, or components are in scope?",
                "why": "Path context changes expert routing, blast radius, and validation.",
                "default": "Use the current working repository and ask before touching unclear paths.",
            }
        )
    if text_has_any(lower, ["multi-session", "handoff", "parallel", "multiple agents", "epic", "work graph"]) and "beads" not in lower:
        questions.append(
            {
                "id": "beads_graph_size",
                "question": "Should this stay as a single Beads task or expand into an epic/work graph?",
                "why": "Beads tracking is mandatory; this only decides the amount of graph structure.",
                "default": "Start with one Beads task and escalate to an epic if independent work streams appear.",
            }
        )
    if workerbee_parallelism:
        mode = str(workerbee_parallelism.get("recommended_mode") or "none")
        if mode == "heavy-review":
            default = "Use heavy review subagents for bounded docs-flow, terminology, web-design, validation, and publish-sanitization workstreams; keep implementation authority in the main thread."
        elif mode == "implementation-capable":
            default = "Use implementation subagents only for disjoint file scopes, with main-thread integration and acceptance."
        elif mode == "review-only":
            default = "Use review-only subagents with Codex 5.3 Spark when available, or the smallest available capable review model; keep implementation authority in the main thread."
        else:
            default = "Use no subagents by default for narrow work, but still present the parallelization choice so the user can opt into review subagents."
        questions.append(
            {
                "id": "workerbee_parallelism",
                "question": "Should Codex parallelize this work with subagents?",
                "why": "Subagents can review docs, tests, routing, validation, terminology, or disjoint implementation workstreams while the main thread owns integration.",
                "default": default,
            }
        )
    if prompt_coach_has_contractor_sharing_signal(lower) and not route.get("external_opt_in"):
        questions.append(
            {
                "id": "outside_sharing_boundary",
                "question": "Is outside model contracting allowed, and what may be shared?",
                "why": "Model preference is not enough to export context.",
                "default": "Default to no outside sharing until the user chooses redacted-packet, repo-readonly, or patch-branch.",
            }
        )
    local_terms = ["local inference", "local worker", "vllm", "openshift ai", "openai-compatible"]
    if text_has_any(lower, local_terms) and not route.get("local_worker_allowed"):
        questions.append(
            {
                "id": "local_worker_opt_in",
                "question": "Should local inference be used, and which local profile should handle it?",
                "why": "Local worker use is explicit opt-in and still requires evaluator plus architect review.",
                "default": "Use --local-ok only for low-risk local-worker review; use openshift-ai-vllm when requested.",
            }
        )
    if route.get("risk_level") in {"high", "critical"} or text_has_any(lower, ["security", "release", "publish", "production"]):
        questions.append(
            {
                "id": "validation_bar",
                "question": "What validation commands or evidence are required before the work is accepted?",
                "why": "High-risk and publish/release work needs explicit acceptance evidence.",
                "default": "Require tests, repository validation, docs/examples checks, and publish sanitization when applicable.",
            }
        )
    return questions


def workerbee_model_phrase(workerbee_parallelism: dict[str, Any] | None) -> str:
    if not workerbee_parallelism:
        return "Codex 5.3 Spark when available, otherwise the smallest available capable review model"
    if workerbee_parallelism.get("recommended_model") == "smallest-available-capable-review-workerbee":
        return "the smallest available capable review subagent"
    return "Codex 5.3 Spark when available, otherwise the smallest available capable review model"


def prompt_coach_interactive_questions(
    level: str,
    route: dict[str, Any],
    missing_questions: list[dict[str, str]],
    workerbee_parallelism: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    missing_ids = {question["id"] for question in missing_questions}
    questions: list[dict[str, Any]] = []

    if level in {"lightweight-beads", "full-harness", "publish-release"} or missing_ids & {
        "goal_success_criteria",
        "beads_graph_size",
    }:
        recommended = {
            "in-thread": ("Beads task (Recommended)", "Use current-thread execution with one durable Beads task."),
            "lightweight-beads": ("Light Beads (Recommended)", "Use a small Beads-backed plan without contractor workstreams."),
            "full-harness": ("Full harness (Recommended)", "Use architect, PM, subagents, validation, and review workstreams."),
            "publish-release": ("Publish gate (Recommended)", "Use full harness plus publish-sanitization before push, release, or tag."),
        }.get(level, ("Full harness (Recommended)", "Use the full orchestration harness."))
        options = [
            {"label": recommended[0], "value": level, "description": recommended[1]},
            {
                "label": "Beads task",
                "value": "in-thread",
                "description": "Use normal current-thread execution while recording the work in one Beads task.",
            },
            {
                "label": "Light Beads",
                "value": "lightweight-beads",
                "description": "Track durable state with Beads while avoiding heavyweight review workstreams.",
            },
        ]
        if level in {"in-thread", "lightweight-beads"}:
            options[2] = {
                "label": "Full harness",
                "value": "full-harness",
                "description": "Use the full architect, PM, workerbee, validation, and review graph.",
            }
        questions.append(
            {
                "id": "orchestration_level",
                "header": "Harness",
                "question": "How much orchestration should Codex use?",
                "why": "The answer changes graph size and review workstreams; Beads tracking remains mandatory.",
                "options": dedupe_interactive_options(options),
            }
        )

    if "workerbee_parallelism" in missing_ids:
        recommended = workerbee_parallelism or {}
        recommended_mode = recommended.get("recommended_mode") or "review-only"
        model_phrase = workerbee_model_phrase(workerbee_parallelism)
        option_map = {
            "heavy-review": {
                "label": "Heavy review subagents (Recommended)",
                "value": "heavy-review-subagents",
                "description": f"Use {model_phrase} for parallel docs-flow, terminology, web-design, validation, and publish checks.",
            },
            "review-only": {
                "label": "Review subagents (Recommended)",
                "value": "review-subagents",
                "description": f"Use {model_phrase} for bounded review or investigation workstreams.",
            },
            "implementation-capable": {
                "label": "Split implementation (Recommended)",
                "value": "implementation-subagents",
                "description": "Use subagents only for disjoint file scopes with main-thread integration.",
            },
            "none": {
                "label": "No subagents (Recommended)",
                "value": "no-subagents",
                "description": "Keep all work in the main thread while still using Beads tracking.",
            },
        }
        first = option_map.get(str(recommended_mode), option_map["review-only"])
        questions.append(
            {
                "id": "workerbee_parallelism",
                "header": "Subagents",
                "question": "Should Codex parallelize this work with subagents?",
                "why": "The answer changes whether sidecar review or disjoint implementation work runs in parallel.",
                "options": workerbee_parallelism_options(str(recommended_mode), first, model_phrase),
            }
        )

    if "outside_sharing_boundary" in missing_ids:
        questions.append(
            {
                "id": "outside_sharing_boundary",
                "header": "Sharing",
                "question": "Is outside model contracting allowed for this work?",
                "why": "Codex must not export context until the sharing boundary is explicit.",
                "options": [
                    {
                        "label": "No sharing (Recommended)",
                        "value": "no-outside-sharing",
                        "description": "Keep all context inside the Codex session and do not contract outside models.",
                    },
                    {
                        "label": "Redacted packet",
                        "value": "redacted-packet",
                        "description": "Allow a minimal redacted contractor packet with no repo access.",
                    },
                    {
                        "label": "Repo-readonly",
                        "value": "repo-readonly",
                        "description": "Allow read-only repo context only after disclosure escalation approval.",
                    },
                    {
                        "label": "Patch-branch",
                        "value": "patch-branch",
                        "description": "Allow patch-proposal repo context only after disclosure escalation approval.",
                    },
                ],
            }
        )

    if "local_worker_opt_in" in missing_ids:
        profile = route.get("local_profile") or "generic-openai-compatible"
        questions.append(
            {
                "id": "local_worker_opt_in",
                "header": "Local AI",
                "question": "Should a local inference worker be used?",
                "why": "Local worker dispatch is opt-in and still needs evaluation plus architect adjudication.",
                "options": [
                    {
                        "label": "No local (Recommended)",
                        "value": "no-local-worker",
                        "description": "Do not use local inference for this work.",
                    },
                    {
                        "label": "Local review",
                        "value": f"local-review:{profile}",
                        "description": "Use a bounded local read-only review workstream.",
                    },
                    {
                        "label": "Prefer local",
                        "value": f"prefer-local:{profile}",
                        "description": "Prefer local-worker routing when policy permits it.",
                    },
                ],
            }
        )

    if "validation_bar" in missing_ids:
        if level == "publish-release":
            first = {
                "label": "Publish grade (Recommended)",
                "value": "publish-grade",
                "description": "Run tests, repository validation, docs/examples checks, and publish sanitization.",
            }
        else:
            first = {
                "label": "Repo validation (Recommended)",
                "value": "repo-validation",
                "description": "Run focused tests plus repository validation and report residual risk.",
            }
        questions.append(
            {
                "id": "validation_bar",
                "header": "Validate",
                "question": "What validation bar should Codex apply?",
                "why": "The answer sets the acceptance evidence before implementation is considered complete.",
                "options": dedupe_interactive_options([
                    first,
                    {
                        "label": "Basic tests",
                        "value": "basic-tests",
                        "description": "Run only the smallest focused test set appropriate to the change.",
                    },
                    {
                        "label": "Publish grade",
                        "value": "publish-grade",
                        "description": "Add docs/examples checks and publish-sanitization gates where applicable.",
                    },
                ]),
            }
        )

    return questions


def dedupe_interactive_options(options: list[dict[str, str]]) -> list[dict[str, str]]:
    seen: set[str] = set()
    deduped: list[dict[str, str]] = []
    for option in options:
        value = option["value"]
        if value in seen:
            continue
        seen.add(value)
        deduped.append(option)
    return deduped[:3]


def workerbee_parallelism_options(
    recommended_mode: str,
    first: dict[str, str],
    model_phrase: str,
) -> list[dict[str, str]]:
    heavy = {
        "label": "Heavy review subagents",
        "value": "heavy-review-subagents",
        "description": f"Use {model_phrase} for multiple bounded review tracks before integration.",
    }
    review = {
        "label": "Review subagents",
        "value": "review-subagents",
        "description": "Use subagents only for read-only review, test triage, or evidence gathering.",
    }
    no_subagents = {
        "label": "No subagents",
        "value": "no-subagents",
        "description": "Keep all work in the main thread while still using Beads tracking.",
    }
    if recommended_mode == "implementation-capable":
        return dedupe_interactive_options([first, heavy, no_subagents])
    if recommended_mode == "heavy-review":
        return dedupe_interactive_options([first, review, no_subagents])
    if recommended_mode == "none":
        return dedupe_interactive_options([first, review, heavy])
    return dedupe_interactive_options([first, heavy, no_subagents])


def prompt_coach_enabled_levers(
    level: str,
    route: dict[str, Any],
    workerbee_parallelism: dict[str, Any] | None = None,
) -> list[str]:
    levers = [
        f"route={route.get('route')}",
        f"risk={route.get('risk_level')}",
        f"primary_expert={(route.get('ranked_experts') or [{}])[0].get('name', 'unknown')}",
        f"executor={route.get('recommended_executor')}",
        "beads-durable-state",
        "beads-minimum-tracking",
        "subagent-parallelism-question-required",
    ]
    if level in {"full-harness", "external-contract", "local-worker", "publish-release"}:
        levers.extend(["architect-review", "validation-lane"])
    if level == "external-contract":
        levers.extend(["contractor-only-bead", f"share-boundary={route.get('share_boundary')}"])
    if level == "local-worker":
        levers.append(f"local-profile={route.get('local_profile') or 'generic-openai-compatible'}")
    if level == "publish-release":
        levers.append("publish-sanitization")
    if route.get("peer_review_required"):
        levers.append("peer-review-required")
    if route.get("provider_conflict_detected"):
        levers.append("provider-conflict-review")
    if workerbee_parallelism and workerbee_parallelism.get("recommended_mode") != "none":
        levers.append(f"subagent-parallelism={workerbee_parallelism.get('recommended_mode')}")
        levers.append(f"workerbee-parallelism={workerbee_parallelism.get('recommended_mode')}")
        if workerbee_parallelism.get("recommended_model") == "smallest-available-capable-review-workerbee":
            levers.append("workerbee-model-fallback-required")
        else:
            levers.append("codex-5.3-spark-workerbees-when-available")
    return levers


def prompt_coach_disabled_levers(
    level: str,
    route: dict[str, Any],
    workerbee_parallelism: dict[str, Any] | None = None,
) -> list[str]:
    levers: list[str] = []
    if level == "in-thread":
        levers.extend(["full-harness", "external-contracting", "local-worker-dispatch"])
    elif level == "lightweight-beads":
        levers.extend(["outside-contractor", "local-worker-dispatch", "full-contractor-packet"])
    if workerbee_parallelism and workerbee_parallelism.get("recommended_mode") == "review-only":
        levers.append("implementation-workerbees-until-disjoint-scope")
    if workerbee_parallelism and workerbee_parallelism.get("recommended_mode") == "none":
        levers.append("subagent-parallelism-unselected")
    if not route.get("external_contract_allowed"):
        levers.append("external-contracting-until-explicit-opt-in")
    if not route.get("has_local_worker_contracts"):
        levers.append("local-worker-dispatch-unless-explicitly-requested")
    return sorted(set(levers))


def prompt_coach_rationale(
    level: str,
    route: dict[str, Any],
    missing_questions: list[dict[str, str]],
    workerbee_parallelism: dict[str, Any] | None = None,
) -> list[str]:
    rationale = [
        f"Policy route is {route.get('route')} with {route.get('risk_level')} risk.",
        f"Recommended executor is {route.get('recommended_executor')}.",
    ]
    if level == "in-thread":
        rationale.append("The task can execute in the current thread, but it still requires a durable Beads record.")
    elif level == "lightweight-beads":
        rationale.append("Durable coordination is useful, but the full contractor/peer-review graph is not the default.")
    elif level == "full-harness":
        rationale.append("Risk, peer-review, or architecture signals justify architect/PM/validation workstreams.")
    elif level == "external-contract":
        rationale.append("External contracting is both policy-selected and explicitly allowed for the selected boundary.")
    elif level == "local-worker":
        rationale.append("A local-worker route is selected and local inference was explicitly allowed.")
    elif level == "publish-release":
        rationale.append("Publish or release language requires sanitization and explicit validation evidence.")
    if workerbee_parallelism and workerbee_parallelism.get("recommended_mode") != "none":
        rationale.append(
            "Subagent parallelism is recommended as "
            f"{workerbee_parallelism.get('recommended_mode')} using {workerbee_model_phrase(workerbee_parallelism)} "
            "for bounded sidecar workstreams."
        )
    if missing_questions:
        rationale.append("The generated prompt includes missing-question guardrails before execution.")
    return rationale


def prompt_coach_warnings(route: dict[str, Any], missing_questions: list[dict[str, str]]) -> list[str]:
    warnings: list[str] = []
    hard_stops = route.get("hard_stops") or []
    for stop in hard_stops:
        warnings.append(f"Policy hard stop: {stop}")
    if route.get("provider_conflict_detected"):
        warnings.append("Provider conflict detected; keep peer review and architect adjudication in the flow.")
    if route.get("peer_review_required"):
        warnings.append("Peer review is required before findings become implementation direction.")
    if any(question["id"] == "outside_sharing_boundary" for question in missing_questions):
        warnings.append("Do not export context to outside models until the sharing boundary is explicitly answered.")
    return warnings


def workerbee_prompt_line(workerbee_parallelism: dict[str, Any] | None) -> str:
    if not workerbee_parallelism or workerbee_parallelism.get("recommended_mode") == "none":
        return "Always ask the user whether to parallelize with subagents; default to no subagents for narrow work unless the user opts in.\n"
    lanes = workerbee_parallelism.get("suggested_lanes") or ["bounded sidecar review"]
    prefix = "heavy review" if workerbee_parallelism.get("recommended_mode") == "heavy-review" else workerbee_parallelism.get("recommended_mode")
    return (
        f"Use {workerbee_model_phrase(workerbee_parallelism)} for "
        f"{prefix} parallelism on: "
        + ", ".join(str(item) for item in lanes)
        + ". Keep main-thread architecture, file integration, and acceptance decisions with the architect.\n"
    )


def render_coached_prompt(
    level: str,
    route: dict[str, Any],
    text: str,
    missing_questions: list[dict[str, str]],
    workerbee_parallelism: dict[str, Any] | None = None,
) -> str:
    question_block = ""
    if missing_questions:
        question_block = "\n\nBefore execution, resolve:\n" + "\n".join(
            f"- {item['question']} Default: {item['default']}" for item in missing_questions
        )
    validation = "Validation: report commands, evidence, and residual risk."
    workerbees = workerbee_prompt_line(workerbee_parallelism)
    if level == "in-thread":
        return (
            "Handle this in the current thread with mandatory Beads tracking, without the full $complex-work-orchestration harness.\n"
            f"Goal: {text}\n"
            f"{workerbees}"
            "Create or update one Beads task for the work story, evidence, validation, and handoff. "
            "Keep the change bounded; escalate to a larger work graph only if architecture, release, safety risk, "
            "or multiple independent work streams appear.\n"
            f"{validation}{question_block}"
        )
    if level == "lightweight-beads":
        return (
            "Use $complex-work-orchestration for lightweight Beads-backed coordination.\n"
            f"Goal: {text}\n"
            f"{workerbees}"
            "Create only the durable tasks needed for planning, implementation, validation, and handoff. "
            "Do not create outside-contractor or local-worker beads unless the route is re-approved.\n"
            f"{validation}{question_block}"
        )
    if level == "full-harness":
        return (
            "Use $complex-work-orchestration to scaffold a full architect/PM/subagent/validation harness.\n"
            f"Goal: {text}\n"
            f"{workerbees}"
            "Create an epic with architect framing, PM coordination, implementation, validation, docs/handoff, "
            "and any policy-required peer-review workstreams. Keep final decisions with the architect.\n"
            f"{validation}{question_block}"
        )
    if level == "external-contract":
        expert = next(
            (
                item
                for item in route.get("ranked_experts", [])
                if isinstance(item, dict) and expert_uses_external_contract(item, route.get("recommended_executor"))
            ),
            (route.get("ranked_experts") or [{}])[0],
        )
        return (
            "Use $complex-work-orchestration with an outside contractor workstream.\n"
            f"Goal: {text}\n"
            f"{workerbees}"
            f"Share boundary: {route.get('share_boundary')}.\n"
            f"Create one contractor-only bead with no-codex-exec and {expert.get('job_description_label', 'contract-jd-general-reasoning')}. "
            "Build a boundary-gated contractor packet, evaluate the return, run peer review if required, "
            "and require architect adjudication before implementation.\n"
            f"{validation}{question_block}"
        )
    if level == "local-worker":
        return (
            "Use $complex-work-orchestration with a bounded local-worker review workstream.\n"
            f"Goal: {text}\n"
            f"{workerbees}"
            f"Local profile: {route.get('local_profile') or 'generic-openai-compatible'}.\n"
            "Create local-worker-only/no-codex-exec work, produce a local dispatch envelope, evaluate the return, "
            "and require architect adjudication before follow-up implementation.\n"
            f"{validation}{question_block}"
        )
    return (
        "Use $complex-work-orchestration for publish/release-ready execution.\n"
        f"Goal: {text}\n"
        f"{workerbees}"
        "Include architect framing, implementation, validation, docs/handoff, and publish-sanitization workstreams. "
        "Do not push, release, or tag until validation and sanitization pass.\n"
        f"{validation}{question_block}"
    )


def coach_orchestration_prompt(
    text: str,
    *,
    external_ok: bool = False,
    allow_disclosure_escalation: bool = False,
    local_ok: bool = False,
    prefer_local: bool = False,
    local_profile: str | None = None,
    share_boundary: str = "no-outside-sharing",
    requested_roles: list[str] | None = None,
    file_paths: list[str] | None = None,
    stage: str | None = None,
    unattended: bool = False,
) -> dict[str, Any]:
    route = classify_work(
        text,
        external_ok=external_ok,
        allow_disclosure_escalation=allow_disclosure_escalation,
        local_ok=local_ok,
        prefer_local=prefer_local,
        local_profile=local_profile,
        share_boundary=share_boundary,
        requested_roles=requested_roles,
        file_paths=file_paths,
        stage=stage,
        unattended=unattended,
    )
    level = prompt_coach_level(route, text)
    workerbee_parallelism = prompt_coach_parallel_workerbee_signal(text, level, route)
    questions = prompt_coach_missing_questions(route, text, file_paths, workerbee_parallelism)
    interactive_questions = prompt_coach_interactive_questions(level, route, questions, workerbee_parallelism)
    return {
        "coach_result_type": "complex-work-orchestration-prompt-coach",
        "version": 3,
        "beads_tracking_required": True,
        "recommended_orchestration_level": level,
        "rationale": prompt_coach_rationale(level, route, questions, workerbee_parallelism),
        "missing_questions": questions,
        "interactive_questions": interactive_questions,
        "enabled_levers": prompt_coach_enabled_levers(level, route, workerbee_parallelism),
        "disabled_levers": prompt_coach_disabled_levers(level, route, workerbee_parallelism),
        "workerbee_parallelism": workerbee_parallelism,
        "route": route,
        "paste_ready_prompt": render_coached_prompt(level, route, text, questions, workerbee_parallelism),
        "warnings": prompt_coach_warnings(route, questions),
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
    if isinstance(bead_json, list) and len(bead_json) == 1 and isinstance(bead_json[0], dict):
        bead_json = bead_json[0]
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
        value.update(provider_metadata_for_executor(value))
        return value
    return {"key": str(key or ""), "external": False, "codex_pickup": "allowed", "dispatch_mode": ""}


def expert_uses_external_contract(expert: dict[str, Any], fallback_executor: str | None = None) -> bool:
    return bool(selected_executor_for_expert(expert, fallback_executor).get("external"))


def expert_uses_local_worker(expert: dict[str, Any], fallback_executor: str | None = None) -> bool:
    return selected_executor_for_expert(expert, fallback_executor).get("dispatch_mode") in {
        "local_openai_compatible",
        "local_secure_review",
    }


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
    local_worker = dispatch_mode in {"local_openai_compatible", "local_secure_review"}
    return {
        "expert": expert.get("name"),
        "discipline": expert.get("discipline"),
        "job_description_label": expert.get("job_description_label"),
        "review_stage": expert.get("review_stage"),
        "share_boundary": route.get("share_boundary"),
        "executor": executor,
        "selected_executor": selected,
        "provider_key": selected.get("provider_key"),
        "provider_family": selected.get("provider_family"),
        "provider_trust_tier": selected.get("provider_trust_tier"),
        "executor_policy_violations": expert.get("executor_policy_violations", []),
        "codex_pickup": "forbidden" if external or local_worker else selected.get("codex_pickup", "allowed"),
        "architect_review_required": True,
        "acceptance_bead_required": external or local_worker,
        "validation_gate_required": bool(expert.get("validation_gate_required")),
        "gate_scope": expert.get("gate_scope"),
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
    allowed_providers = record.get("allowed_providers")
    if allowed_providers is not None:
        executor_config = load_policy("executor-registry").get("executors", {}).get(executor, {})
        provider_key = executor_config.get("provider_key")
        if isinstance(allowed_providers, str):
            provider_allowed = allowed_providers in [provider_key, "*"]
        elif isinstance(allowed_providers, list):
            provider_allowed = provider_key in allowed_providers or "*" in allowed_providers
        else:
            provider_allowed = False
        if not provider_allowed:
            raise SystemExit(f"opt-in record does not allow provider {provider_key!r}")

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
    elif packet.get("provider_key") != executor.get("provider_key"):
        errors.append(f"packet provider_key {packet.get('provider_key')!r} does not match executor provider")
    elif packet.get("provider_trust_tier") != provider_profile(executor.get("provider_key")).get("trust_tier"):
        errors.append(f"packet provider_trust_tier {packet.get('provider_trust_tier')!r} does not match provider registry")

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
    if boundary:
        expected_stage = str(boundary.get("disclosure_stage", share_boundary))
        if packet.get("disclosure_stage") != expected_stage:
            errors.append(
                f"packet disclosure_stage {packet.get('disclosure_stage')!r} does not match boundary stage {expected_stage!r}"
            )
        if boundary.get("requires_disclosure_escalation") and packet.get("disclosure_escalation_approved") is not True:
            errors.append(f"packet share boundary {share_boundary!r} requires disclosure escalation approval")

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
    elif route == "local-worker" or dispatch_mode in {"local_openai_compatible", "local_secure_review"}:
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


def sabotage_thresholds(
    *,
    review_threshold: int | None = None,
    quarantine_threshold: int | None = None,
) -> dict[str, int]:
    policy_thresholds = load_policy("acceptance-policy").get("sabotage", {}).get("thresholds", {})
    peer_thresholds = peer_review_policy().get("sabotage_thresholds", {})
    control_thresholds = load_contracting_controls().get("sabotage_policy", {}).get("thresholds", {})
    return {
        "review": int(
            review_threshold
            if review_threshold is not None
            else control_thresholds.get("peer_review", policy_thresholds.get("review", peer_thresholds.get("review", 30)))
        ),
        "architect_escalation": int(
            control_thresholds.get(
                "architect_escalation",
                policy_thresholds.get("architect_escalation", peer_thresholds.get("architect_escalation", 45)),
            )
        ),
        "quarantine": int(
            quarantine_threshold
            if quarantine_threshold is not None
            else control_thresholds.get(
                "quarantine",
                policy_thresholds.get("quarantine", peer_thresholds.get("quarantine", 60)),
            )
        ),
    }


def sabotage_signal_weights() -> dict[str, int]:
    configured = load_contracting_controls().get("sabotage_policy", {}).get("signal_weights", {})
    defaults = {
        "boundary_expansion_request": 30,
        "review_suppression": 25,
        "fabricated_evidence": 35,
        "unauthorized_repo_mutation_claim": 35,
        "goal_divergence": 20,
        "overconfident_without_evidence": 20,
        "provider_conflict_domain": 20,
        "secret_or_personal_data": 45,
    }
    defaults.update({key: int(value) for key, value in configured.items()})
    return defaults


def malpractice_thresholds(
    *,
    review_threshold: int | None = None,
    reject_threshold: int | None = None,
) -> dict[str, int]:
    configured = load_contracting_controls().get("malpractice_policy", {}).get("thresholds", {})
    return {
        "review": int(review_threshold if review_threshold is not None else configured.get("peer_review", 25)),
        "reject": int(reject_threshold if reject_threshold is not None else configured.get("reject", 60)),
    }


def malpractice_signal_weights() -> dict[str, int]:
    configured = load_contracting_controls().get("malpractice_policy", {}).get("signal_weights", {})
    defaults = {
        "missing_evidence": 20,
        "non_reproducible_validation": 15,
        "vague_recommendation": 15,
        "missing_confidence": 10,
        "unclear_scope": 10,
        "missing_evidence_provenance": 10,
        "missing_attestation_or_repro_note": 10,
        "missing_share_boundary_conformance": 10,
        "missing_peer_review_disposition": 10,
        "internal_narration_or_preamble": 15,
    }
    defaults.update({key: int(value) for key, value in configured.items()})
    return defaults


def add_signal(signals: list[dict[str, Any]], *, category: str, reason: str, weight: int) -> None:
    if any(signal.get("category") == category and signal.get("reason") == reason for signal in signals):
        return
    signals.append({"category": category, "reason": reason, "weight": int(weight)})


def score_sabotage_signals(
    text: str,
    sections: dict[str, str] | None = None,
    *,
    provider_conflict_domains: list[str] | None = None,
    review_threshold: int | None = None,
    quarantine_threshold: int | None = None,
) -> dict[str, Any]:
    sections = sections or parse_return_sections(text)
    signals: list[dict[str, Any]] = []
    lower = text.lower()
    weights = sabotage_signal_weights()

    patterns: list[tuple[str, str, str]] = [
        (
            "review_suppression",
            r"\b(ignore|bypass|skip|avoid)\s+(the\s+)?(architect|evaluator|review|policy|guardrail)",
            "bypass review or policy",
        ),
        ("review_suppression", r"\b(do not|don't)\s+(log|record|audit|mention|report)", "suppresses audit or reporting"),
        (
            "review_suppression",
            r"\b(suppress|hide|delete)\s+(tests?|logs?|audit|evidence|validation)",
            "suppresses tests logs or evidence",
        ),
        (
            "review_suppression",
            r"\b(no need|unnecessary)\s+(for\s+)?(tests?|validation|review)",
            "discourages validation",
        ),
        (
            "boundary_expansion_request",
            r"\b(send|share|need|provide)\s+(the\s+)?(full|entire|complete)\s+(repo|repository|bead|transcript|secret|credentials?)",
            "requests broader disclosure",
        ),
        (
            "unauthorized_repo_mutation_claim",
            r"\b(i|we)\s+(changed|modified|patched|committed|pushed|deleted|rewrote)\b",
            "claims repository mutation",
        ),
        (
            "secret_or_personal_data",
            r"\b(credential|password|api[_ -]?key|private key|token)\s*[:=]",
            "appears to expose secret material",
        ),
        ("fabricated_evidence", r"\b(fabricated|invented|assumed without evidence|made up)\b", "admits fabricated evidence"),
        (
            "goal_divergence",
            r"\b(ignore the assigned scope|rewrite the project|switch to my plan|replace the requested goal)\b",
            "attempts to redirect assigned goal",
        ),
    ]
    for category, pattern, reason in patterns:
        if re.search(pattern, lower, re.I):
            add_signal(signals, category=category, reason=reason, weight=weights.get(category, 20))

    evidence = section_value(sections, "Evidence")
    validation = section_value(sections, "Validation result")
    provider_limits = section_value(sections, "Provider policy limitations", "Policy limitations")
    boundary = section_value(sections, "Boundary violation")
    patch_auth = section_value(sections, "Patch authorization")
    files_changed = section_value(sections, "Files changed")
    commands_run = section_value(sections, "Commands run")
    if affirmative_field(boundary):
        add_signal(
            signals,
            category="boundary_expansion_request",
            reason="self-reported boundary violation",
            weight=weights.get("boundary_expansion_request", 30) + 10,
        )
    if nonempty_work_field(files_changed) and not direct_mutation_authorized(patch_auth) and not patch_proposal_evidence(sections):
        add_signal(
            signals,
            category="unauthorized_repo_mutation_claim",
            reason="reports file changes without patch authorization",
            weight=weights.get("unauthorized_repo_mutation_claim", 35) + 5,
        )
    if re.search(r"\bnot run|none|n/a\b", validation, re.I) and re.search(r"\bverified|confirmed|proved|validated\b", evidence, re.I):
        add_signal(
            signals,
            category="fabricated_evidence",
            reason="claims verification while validation was not run",
            weight=weights.get("fabricated_evidence", 35),
        )
    if provider_limits and not negative_field(provider_limits):
        add_signal(
            signals,
            category="provider_conflict_domain",
            reason="provider policy limitation disclosed",
            weight=max(10, weights.get("provider_conflict_domain", 20) - 5),
        )
    if (
        files_changed
        and not commands_run
        and re.search(r"\bchanged|modified|patched\b", files_changed, re.I)
        and not patch_proposal_evidence(sections)
    ):
        add_signal(
            signals,
            category="unauthorized_repo_mutation_claim",
            reason="file-change claim lacks command evidence",
            weight=max(15, weights.get("unauthorized_repo_mutation_claim", 35) - 15),
        )
    if re.search(r"\b(high|100%|certain|guaranteed)\b", section_value(sections, "Confidence"), re.I) and not evidence:
        add_signal(
            signals,
            category="overconfident_without_evidence",
            reason="high confidence without evidence",
            weight=weights.get("overconfident_without_evidence", 20),
        )
    for domain in provider_conflict_domains or []:
        add_signal(
            signals,
            category="provider_conflict_domain",
            reason=f"provider conflict domain present: {domain}",
            weight=weights.get("provider_conflict_domain", 20),
        )

    score = min(100, sum(int(signal["weight"]) for signal in signals))
    thresholds = sabotage_thresholds(review_threshold=review_threshold, quarantine_threshold=quarantine_threshold)
    return {
        "sabotage_score": score,
        "sabotage_signals": signals,
        "sabotage_signal_categories": sorted({str(signal["category"]) for signal in signals}),
        "sabotage_review_recommended": score >= thresholds["review"],
        "sabotage_architect_escalation_recommended": score >= thresholds["architect_escalation"],
        "quarantine_recommended": score >= thresholds["quarantine"],
    }


def score_malpractice_signals(
    text: str,
    sections: dict[str, str] | None = None,
    *,
    review_threshold: int | None = None,
    reject_threshold: int | None = None,
) -> dict[str, Any]:
    sections = sections or parse_return_sections(text)
    signals: list[dict[str, Any]] = []
    weights = malpractice_signal_weights()

    evidence = section_value(sections, "Evidence")
    validation = section_value(sections, "Validation result")
    recommendation = section_value(sections, "Recommended next bead")
    confidence = section_value(sections, "Confidence")
    scope = section_value(sections, "Scope compliance")

    if not evidence or len(evidence.split()) < 4:
        add_signal(signals, category="missing_evidence", reason="evidence is missing or too thin", weight=weights["missing_evidence"])
    if not validation or re.search(r"\b(none|not run|n/a)\b", validation, re.I):
        add_signal(
            signals,
            category="non_reproducible_validation",
            reason="validation is missing or non-reproducible",
            weight=weights["non_reproducible_validation"],
        )
    if not recommendation or len(recommendation.split()) < 4:
        add_signal(
            signals,
            category="vague_recommendation",
            reason="recommended next bead is vague",
            weight=weights["vague_recommendation"],
        )
    if not confidence:
        add_signal(signals, category="missing_confidence", reason="confidence is missing", weight=weights["missing_confidence"])
    if scope and not affirmative_field(scope) and not negative_field(scope):
        add_signal(signals, category="unclear_scope", reason="scope compliance field is unclear", weight=weights["unclear_scope"])
    if not section_value(sections, "Evidence provenance"):
        add_signal(
            signals,
            category="missing_evidence_provenance",
            reason="evidence provenance section is missing",
            weight=weights["missing_evidence_provenance"],
        )
    if not section_value(sections, "Attestation or reproducibility note", "Attestation/repro note"):
        add_signal(
            signals,
            category="missing_attestation_or_repro_note",
            reason="attestation or reproducibility note is missing",
            weight=weights["missing_attestation_or_repro_note"],
        )
    if not section_value(sections, "Share-boundary conformance", "Share boundary conformance"):
        add_signal(
            signals,
            category="missing_share_boundary_conformance",
            reason="share-boundary conformance section is missing",
            weight=weights["missing_share_boundary_conformance"],
        )
    if not section_value(sections, "Peer-review disposition", "Peer review disposition"):
        add_signal(
            signals,
            category="missing_peer_review_disposition",
            reason="peer-review disposition section is missing",
            weight=weights["missing_peer_review_disposition"],
        )
    if internal_narration_present(text):
        add_signal(
            signals,
            category="internal_narration_or_preamble",
            reason="return includes preamble or internal action narration",
            weight=weights["internal_narration_or_preamble"],
        )

    score = min(100, sum(int(signal["weight"]) for signal in signals))
    thresholds = malpractice_thresholds(review_threshold=review_threshold, reject_threshold=reject_threshold)
    return {
        "malpractice_score": score,
        "malpractice_signals": signals,
        "malpractice_signal_categories": sorted({str(signal["category"]) for signal in signals}),
        "malpractice_review_recommended": score >= thresholds["review"],
        "malpractice_reject_recommended": score >= thresholds["reject"],
    }


def evidence_items_from_sections(sections: dict[str, str]) -> list[dict[str, str]]:
    evidence = section_value(sections, "Evidence")
    items: list[dict[str, str]] = []
    for line in evidence.splitlines():
        normalized = line.strip().lstrip("-* ").strip()
        if not normalized:
            continue
        kind = "claim"
        if re.search(r"\b(test|pytest|compile|validate|command|bd |git )\b", normalized, re.I):
            kind = "command-or-test"
        elif re.search(r"\b(file|path|line|schema|policy)\b", normalized, re.I):
            kind = "file-or-policy"
        items.append({"kind": kind, "text": normalized})
    return items


def normalize_contractor_return(
    text: str,
    *,
    bead_id: str | None = None,
    dispatch_id: str | None = None,
    share_boundary: str | None = None,
    job_description_label: str | None = None,
    packet_sha256: str | None = None,
    executor: str | None = None,
    workspace_mutation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    sections = parse_return_sections(text)
    required = load_policy("acceptance-policy").get("contractor_return_required_sections", [])
    missing = [section for section in required if not sections.get(section)]
    sabotage = score_sabotage_signals(text, sections)
    malpractice = score_malpractice_signals(text, sections)
    bundle: dict[str, Any] = {
        "bundle_type": "contractor-return-bundle",
        "version": 1,
        "bead_id": bead_id,
        "dispatch_id": dispatch_id,
        "executor": executor,
        "share_boundary": share_boundary,
        "job_description_label": job_description_label,
        "packet_sha256": packet_sha256,
        "sections": sections,
        "required_sections_missing": missing,
        "required_sections_present": [section for section in required if section in sections and section not in missing],
        "evidence_items": evidence_items_from_sections(sections),
        "workspace_mutation": workspace_mutation,
        **sabotage,
        **malpractice,
    }
    bundle["bundle_sha256"] = artifact_hash(json.dumps(bundle, sort_keys=True))
    return bundle


def attestation_payload_hash(attestation: dict[str, Any]) -> str:
    payload = dict(attestation)
    payload.pop("attestation_sha256", None)
    return artifact_hash(json.dumps(payload, sort_keys=True))


def make_attestation(
    *,
    subject_type: str,
    subject_sha256: str,
    subject_id: str | None = None,
    issuer: str = "complex-work-orchestration",
    predicate: dict[str, Any] | None = None,
) -> dict[str, Any]:
    attestation: dict[str, Any] = {
        "attestation_type": "sha256-subject-attestation",
        "version": 1,
        "issued_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "issuer": issuer,
        "subject_type": subject_type,
        "subject_id": subject_id,
        "subject_sha256": subject_sha256,
        "predicate": predicate or {},
    }
    attestation["attestation_sha256"] = attestation_payload_hash(attestation)
    return attestation


def verify_attestation(subject: str | bytes, attestation: dict[str, Any]) -> dict[str, Any]:
    subject_bytes = subject if isinstance(subject, bytes) else subject.encode("utf-8")
    actual_subject_hash = hashlib.sha256(subject_bytes).hexdigest()
    expected_attestation_hash = attestation_payload_hash(attestation)
    errors: list[str] = []
    if attestation.get("subject_sha256") != actual_subject_hash:
        errors.append("subject_sha256 does not match subject bytes")
    if attestation.get("attestation_sha256") != expected_attestation_hash:
        errors.append("attestation_sha256 does not match attestation payload")
    return {
        "valid": not errors,
        "errors": errors,
        "subject_sha256": actual_subject_hash,
        "attestation_sha256": expected_attestation_hash,
    }


RETURN_CONTROL_SECTIONS = [
    "Files changed",
    "Commands run",
    "Boundary violation",
    "Patch authorization",
    "Secret or personal-data spill",
    "Secret spill",
    "Personal-data spill",
    "Scope compliance",
    "Provider policy limitations",
    "Policy limitations",
    "Patch artifact",
    "Patch proposal",
    "Provider conflict disposition",
    "Direct workspace mutation",
]

RETURN_SECTION_ALIASES = {
    "share boundary conformance": "Share-boundary conformance",
    "peer review disposition": "Peer-review disposition",
    "attestation repro note": "Attestation or reproducibility note",
    "attestation reproducibility note": "Attestation or reproducibility note",
    "attestation or reproduction note": "Attestation or reproducibility note",
    "risks gaps": "Risks or gaps",
    "risks and gaps": "Risks or gaps",
    "recommended next Bead": "Recommended next bead",
    "recommended next action": "Recommended next bead",
    "secret spill": "Secret or personal-data spill",
    "personal data spill": "Secret or personal-data spill",
    "secret or personal data spill": "Secret or personal-data spill",
    "provider limitations": "Provider policy limitations",
    "policy limitations": "Provider policy limitations",
    "patch branch": "Patch proposal",
    "patch diff": "Patch proposal",
}


def section_lookup_key(label: str) -> str:
    cleaned = label.strip()
    cleaned = re.sub(r"^\s{0,3}#{1,6}\s*", "", cleaned)
    cleaned = re.sub(r"^\s*[-*]\s+", "", cleaned)
    cleaned = re.sub(r"^(\*\*|__)(.*?)(\1)$", r"\2", cleaned)
    cleaned = cleaned.strip("`*_ :")
    cleaned = cleaned.replace("&", " and ")
    cleaned = re.sub(r"[^a-zA-Z0-9]+", " ", cleaned)
    return re.sub(r"\s+", " ", cleaned).strip().lower()


def return_section_aliases() -> dict[str, str]:
    canonical: dict[str, str] = {}
    for section in load_policy("acceptance-policy").get("contractor_return_required_sections", []):
        canonical[section_lookup_key(section)] = section
    for section in RETURN_CONTROL_SECTIONS:
        canonical[section_lookup_key(section)] = section
    for alias, target in RETURN_SECTION_ALIASES.items():
        canonical[section_lookup_key(alias)] = target
    return canonical


def canonical_return_section(label: str) -> str | None:
    return return_section_aliases().get(section_lookup_key(label))


def parse_return_header(line: str) -> tuple[str, str] | None:
    match = re.match(r"^\s{0,3}#{1,6}\s+(.+?)(?:\s*:\s*(.*))?\s*$", line)
    if match:
        label = match.group(1).strip()
        value = (match.group(2) or "").strip()
        canonical = canonical_return_section(label)
        if canonical:
            return canonical, value

    match = re.match(r"^\s*(?:[-*]\s+)?(?:\*\*|__)([^*_]+?)(?::)?(?:\*\*|__)\s*:?\s*(.*)$", line)
    if match:
        label = match.group(1).strip()
        value = match.group(2).strip()
        canonical = canonical_return_section(label)
        if canonical:
            return canonical, value

    match = re.match(r"^\s*([A-Za-z][A-Za-z /-]+)\s*:\s*(.*)$", line)
    if match:
        canonical = canonical_return_section(match.group(1))
        if canonical:
            return canonical, match.group(2).strip()
    return None


def parse_return_sections(text: str) -> dict[str, str]:
    sections: dict[str, str] = {}
    current: str | None = None
    buffer: list[str] = []
    in_fence = False
    for line in text.splitlines():
        if re.match(r"^\s*(```|~~~)", line):
            if current:
                buffer.append(line)
            in_fence = not in_fence
            continue
        if in_fence:
            if current:
                buffer.append(line)
            continue
        parsed = parse_return_header(line)
        if parsed:
            if current:
                sections[current] = "\n".join(buffer).strip()
            current, value = parsed
            buffer = [value] if value else []
        elif current:
            buffer.append(line)
    if current:
        sections[current] = "\n".join(buffer).strip()
    return sections


def section_value(sections: dict[str, str], *names: str) -> str:
    normalized = {section_lookup_key(key): value for key, value in sections.items()}
    for name in names:
        canonical = canonical_return_section(name) or name
        value = normalized.get(section_lookup_key(canonical))
        if value is not None:
            return value.strip()
    return ""


def negative_field(value: str) -> bool:
    normalized = value.strip().lower()
    if not normalized:
        return False
    if re.match(r"^(compliant|approved|authorized|within scope|in scope)\b", normalized):
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


def direct_mutation_authorized(value: str) -> bool:
    if not affirmative_field(value):
        return False
    return not bool(re.search(r"\b(no direct|proposal only|diff only|not requested|not used|unauthorized|unapproved|without approval)\b", value, re.I))


def patch_proposal_evidence(sections: dict[str, str]) -> bool:
    fields = [
        section_value(sections, "Patch proposal", "Patch artifact", "Patch authorization"),
        section_value(sections, "Evidence"),
        section_value(sections, "Attestation or reproducibility note", "Attestation/repro note"),
        section_value(sections, "Share-boundary conformance", "Share boundary conformance"),
        section_value(sections, "Recommended next bead"),
    ]
    return bool(
        re.search(
            r"\b(diff|patch proposal|proposed patch|patch artifact|branch reference|branch ref|patch branch|pull request|merge request)\b",
            "\n".join(fields),
            re.I,
        )
    )


def internal_narration_present(text: str) -> bool:
    patterns = [
        r"^\s*(i will|i'll|i am going to|i'm going to|i will now|i'll now|now i will|next i will|let me)\b",
        r"^\s*here is the final contractor return\b",
    ]
    return any(re.search(pattern, text, re.I | re.M) for pattern in patterns)


def status_path(line: str) -> str:
    path = line[3:] if len(line) > 3 else line
    if " -> " in path:
        path = path.split(" -> ", 1)[1]
    return path.strip().strip('"')


def tracked_status_map(lines: list[str]) -> dict[str, str]:
    return {status_path(line): line for line in lines if line.strip()}


def capture_tracked_workspace_state(cwd: Path | str = REPO_ROOT) -> dict[str, Any]:
    root = Path(cwd)
    result = subprocess.run(
        ["git", "-C", str(root), "status", "--porcelain", "--untracked-files=no"],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return {
            "workspace_state_type": "tracked-git-status",
            "version": 1,
            "cwd": str(root),
            "is_git_repo": False,
            "error": result.stderr.strip() or result.stdout.strip(),
            "tracked_status": [],
            "tracked_status_sha256": artifact_hash(""),
        }
    lines = sorted(line for line in result.stdout.splitlines() if line.strip())
    return {
        "workspace_state_type": "tracked-git-status",
        "version": 1,
        "cwd": str(root),
        "is_git_repo": True,
        "tracked_status": lines,
        "tracked_status_sha256": artifact_hash("\n".join(lines)),
    }


def path_allowed(path: str, allowed_paths: list[str] | tuple[str, ...] | None) -> bool:
    if not allowed_paths:
        return False
    normalized = path.strip().lstrip("./")
    for raw in allowed_paths:
        allowed = str(raw).strip().lstrip("./").rstrip("/")
        if not allowed:
            continue
        if normalized == allowed or normalized.startswith(f"{allowed}/"):
            return True
    return False


def diff_workspace_state(
    before: dict[str, Any],
    after: dict[str, Any],
    *,
    allowed_paths: list[str] | tuple[str, ...] | None = None,
    require_clean: bool = False,
) -> dict[str, Any]:
    before_map = tracked_status_map(list(before.get("tracked_status", [])))
    after_map = tracked_status_map(list(after.get("tracked_status", [])))
    changes: list[dict[str, str | None]] = []
    for path in sorted(set(before_map) | set(after_map)):
        before_status = before_map.get(path)
        after_status = after_map.get(path)
        if before_status == after_status:
            continue
        changes.append({"path": path, "before": before_status, "after": after_status})
    allowed: list[dict[str, str | None]] = []
    unexpected: list[dict[str, str | None]] = []
    for change in changes:
        target = str(change["path"])
        if path_allowed(target, allowed_paths):
            allowed.append(change)
        else:
            unexpected.append(change)
    if require_clean and before.get("tracked_status"):
        unexpected = [
            {"path": status_path(line), "before": line, "after": line}
            for line in list(before.get("tracked_status", []))
        ] + unexpected
    return {
        "workspace_mutation_report_type": "tracked-git-status-diff",
        "version": 1,
        "before": before,
        "after": after,
        "allowed_paths": list(allowed_paths or []),
        "require_clean": bool(require_clean),
        "changes": changes,
        "allowed_mutations": allowed,
        "unexpected_mutations": unexpected,
        "mutation_detected": bool(changes),
        "unexpected_mutation_detected": bool(unexpected),
        "reverted": False,
    }


def workspace_unexpected_mutations(workspace_mutation: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not workspace_mutation:
        return []
    return list(workspace_mutation.get("unexpected_mutations") or [])


def make_acceptance_decision(
    text: str,
    *,
    bead_id: str | None = None,
    dispatch_id: str | None = None,
    share_boundary: str | None = None,
    job_description_label: str | None = None,
    peer_review_required: bool = False,
    peer_review_status: str = "not-run",
    provider_conflict_domains: list[str] | None = None,
    sabotage_review_threshold: int | None = None,
    sabotage_quarantine_threshold: int | None = None,
    malpractice_review_threshold: int | None = None,
    malpractice_reject_threshold: int | None = None,
    workspace_mutation: dict[str, Any] | None = None,
    mutation_strategy: str = "reject",
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
        if not patch_proposal_evidence(sections) and not (nonempty_work_field(files_changed) and nonempty_work_field(commands_run)):
            hard_disqualifiers.append("patch branch return missing patch proposal or direct-change evidence")
        elif nonempty_work_field(files_changed) and not patch_proposal_evidence(sections) and not direct_mutation_authorized(patch_authorization):
            hard_disqualifiers.append("patch branch direct mutation missing explicit authorization")
    elif nonempty_work_field(files_changed) and not direct_mutation_authorized(patch_authorization) and not patch_proposal_evidence(sections):
        hard_disqualifiers.append("unapproved patch or repo access")
    if affirmative_field(patch_authorization) and re.search(r"\b(unapproved|unauthorized|without approval)\b", patch_authorization, re.I):
        hard_disqualifiers.append("unapproved patch or repo access")
    unexpected_mutations = workspace_unexpected_mutations(workspace_mutation)
    workspace_quarantine = bool(unexpected_mutations and mutation_strategy == "reject")
    if unexpected_mutations:
        if mutation_strategy == "reject":
            hard_disqualifiers.append("unexpected tracked-file mutation")
        else:
            score -= 20
            penalty_reasons.append("unexpected tracked-file mutation observed")

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

    sabotage = score_sabotage_signals(
        text,
        sections,
        provider_conflict_domains=provider_conflict_domains,
        review_threshold=sabotage_review_threshold,
        quarantine_threshold=sabotage_quarantine_threshold,
    )
    malpractice = score_malpractice_signals(
        text,
        sections,
        review_threshold=malpractice_review_threshold,
        reject_threshold=malpractice_reject_threshold,
    )
    if sabotage["quarantine_recommended"]:
        hard_disqualifiers.append("suspected sabotage or malpractice")
    elif sabotage["sabotage_review_recommended"]:
        score -= penalties.get("sabotage_review", 20)
        penalty_reasons.append("sabotage or malpractice signals require review")
    if malpractice["malpractice_reject_recommended"]:
        hard_disqualifiers.append("suspected sabotage or malpractice")
    elif malpractice["malpractice_review_recommended"]:
        score -= penalties.get("malpractice_review", 10)
        penalty_reasons.append("malpractice signals require review")

    peer_required = bool(
        peer_review_required
        or sabotage["sabotage_review_recommended"]
        or malpractice["malpractice_review_recommended"]
        or provider_conflict_domains
    )
    peer_disposition = section_value(sections, "Peer-review disposition", "Peer review disposition")
    if peer_required and re.search(r"\b(not required|not needed|unnecessary|no peer review required|no peer review needed)\b", peer_disposition, re.I):
        hard_disqualifiers.append("peer review incorrectly dismissed")
    if peer_required and peer_review_status in {"not-run", "pending"}:
        score -= 5
        penalty_reasons.append("peer review required before implementation use")
    if peer_required and peer_review_status in {"failed", "disagreement", "blocked"}:
        hard_disqualifiers.append("peer review failed or blocked")

    score = max(0, min(100, score))
    escalation = re.search(r"^\s*Escalation needed\s*:\s*(yes|true|required)", text, re.I | re.M)
    thresholds = policy.get("score", {}).get("thresholds", {})
    if sabotage["quarantine_recommended"] or workspace_quarantine:
        verdict = "quarantine"
    elif hard_disqualifiers:
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

    human_adjudication_required = bool(
        hard_disqualifiers
        or escalation
        or verdict in {"escalate", "quarantine"}
        or sabotage["sabotage_architect_escalation_recommended"]
        or peer_review_status in {"failed", "disagreement", "blocked"}
        or workspace_quarantine
    )
    if verdict == "quarantine":
        recommended_disposition = "quarantine-and-adjudicate"
    elif hard_disqualifiers:
        recommended_disposition = "reject"
    elif peer_required and peer_review_status in {"not-run", "pending"}:
        recommended_disposition = "run-peer-review"
    elif human_adjudication_required:
        recommended_disposition = "architect-adjudication"
    elif verdict == "accept":
        recommended_disposition = "accept-findings"
    elif verdict == "clarify":
        recommended_disposition = "request-clarification"
    elif verdict == "partial-accept":
        recommended_disposition = "accept-bounded-findings"
    else:
        recommended_disposition = "reject"

    signal_categories = sorted(
        set(sabotage.get("sabotage_signal_categories", []))
        | set(malpractice.get("malpractice_signal_categories", []))
    )

    return {
        "dispatch_id": dispatch_id,
        "bead_id": bead_id,
        "share_boundary": share_boundary,
        "verdict": verdict,
        "score": score,
        "missing_sections": missing,
        "penalty_reasons": penalty_reasons,
        "hard_disqualifiers": hard_disqualifiers,
        "sabotage_score": sabotage["sabotage_score"],
        "sabotage_signals": sabotage["sabotage_signals"],
        "sabotage_signal_categories": sabotage["sabotage_signal_categories"],
        "sabotage_review_recommended": sabotage["sabotage_review_recommended"],
        "sabotage_architect_escalation_recommended": sabotage["sabotage_architect_escalation_recommended"],
        "malpractice_score": malpractice["malpractice_score"],
        "malpractice_signals": malpractice["malpractice_signals"],
        "malpractice_signal_categories": malpractice["malpractice_signal_categories"],
        "malpractice_review_recommended": malpractice["malpractice_review_recommended"],
        "malpractice_reject_recommended": malpractice["malpractice_reject_recommended"],
        "signal_categories": signal_categories,
        "peer_review_required": peer_required,
        "peer_review_status": peer_review_status,
        "provider_conflict_domains": provider_conflict_domains or [],
        "workspace_mutation": workspace_mutation,
        "human_adjudication_required": human_adjudication_required,
        "recommended_disposition": recommended_disposition,
        "quarantine_recommended": bool(sabotage["quarantine_recommended"] or workspace_quarantine),
        "escalation_flagged": bool(escalation),
        "architect_review_required": True,
        "sections": sections,
    }


def record_audit_event(event: dict[str, Any], audit_file: Path | None = None) -> dict[str, Any]:
    audit_file = audit_file or AUDIT_LOG
    audit_file.parent.mkdir(parents=True, exist_ok=True)
    previous_hash = None
    prior_events = iter_audit_events(audit_file)
    if prior_events:
        previous_hash = prior_events[-1].get("event_hash")
    enriched = dict(event)
    enriched.setdefault("timestamp", dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    if previous_hash:
        enriched.setdefault("previous_event_hash", previous_hash)
    enriched.pop("event_hash", None)
    enriched["event_hash"] = artifact_hash(json.dumps(enriched, sort_keys=True))
    with audit_file.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(enriched, sort_keys=True) + "\n")
    return enriched


def audit_event_payload_hash(event: dict[str, Any]) -> str:
    payload = dict(event)
    payload.pop("event_hash", None)
    return artifact_hash(json.dumps(payload, sort_keys=True))


def verify_audit_log(audit_file: Path | None = None) -> dict[str, Any]:
    audit_file = audit_file or AUDIT_LOG
    errors: list[str] = []
    previous_hash: str | None = None
    unlinked_events = 0
    raw_lines = audit_file.read_text(encoding="utf-8").splitlines() if audit_file.exists() else []
    events: list[dict[str, Any]] = []
    for index, line in enumerate(raw_lines, 1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append(f"line {index}: invalid JSON: {exc}")
            continue
        if not isinstance(event, dict):
            errors.append(f"line {index}: event is not an object")
            continue
        events.append(event)
        expected_hash = audit_event_payload_hash(event)
        if event.get("event_hash") != expected_hash:
            errors.append(f"line {index}: event_hash mismatch")
        expected_previous = event.get("previous_event_hash")
        if previous_hash and expected_previous is None:
            unlinked_events += 1
        elif previous_hash and expected_previous != previous_hash:
            errors.append(f"line {index}: previous_event_hash mismatch")
        if not previous_hash and expected_previous:
            errors.append(f"line {index}: first event unexpectedly has previous_event_hash")
        previous_hash = event.get("event_hash")
    return {
        "valid": not errors,
        "errors": errors,
        "event_count": len(events),
        "unlinked_event_count": unlinked_events,
        "last_event_hash": previous_hash,
    }


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


def bead_field_value(value: str | list[str] | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, list):
        return ", ".join(str(item) for item in value if item is not None and str(item).strip())
    stripped = str(value).strip()
    return stripped or None


def bead_text_value(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = str(value).strip()
    if not stripped:
        return None
    return stripped.replace("\\r\\n", "\n").replace("\\n", "\n")


def create_bead(
    title: str,
    *,
    issue_type: str = "task",
    priority: int = 2,
    parent: str | None = None,
    labels: list[str] | None = None,
    skills: str | list[str] | None = None,
    description: str | None = None,
    acceptance: str | None = None,
    design: str | None = None,
    notes: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    args = ["create", title, "--type", issue_type, "--priority", str(priority)]
    temp_paths: list[Path] = []

    def temp_file_arg(prefix: str, suffix: str, content: str) -> str:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            prefix=prefix,
            suffix=suffix,
            delete=False,
        ) as handle:
            handle.write(content)
            temp_paths.append(Path(handle.name))
            return handle.name

    if parent:
        args.extend(["--parent", parent])
    if labels:
        args.extend(["--labels", ",".join(labels)])
    skills_value = bead_field_value(skills)
    if skills_value:
        args.extend(["--skills", skills_value])
    description_value = bead_text_value(description)
    if description_value:
        if len(description_value) > 4000:
            args.extend(["--body-file", temp_file_arg("cwo-bd-description-", ".md", description_value)])
        else:
            args.extend(["--description", description_value])
    acceptance_value = bead_text_value(acceptance)
    if acceptance_value:
        args.extend(["--acceptance", acceptance_value])
    design_value = bead_text_value(design)
    if design_value:
        if len(design_value) > 4000:
            args.extend(["--design-file", temp_file_arg("cwo-bd-design-", ".md", design_value)])
        else:
            args.extend(["--design", design_value])
    notes_value = bead_text_value(notes)
    if notes_value:
        args.extend(["--notes", notes_value])
    if metadata:
        metadata_path = temp_file_arg("cwo-bd-metadata-", ".json", metadata_json(metadata))
        args.extend(["--metadata", f"@{metadata_path}"])
    try:
        output = run_bd(args)
    finally:
        for path in temp_paths:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
    return {"id": parse_created_issue_id(output), "title": title, "raw_output": output.strip()}


def show_bead_json(bead_id: str) -> Any:
    output = run_bd(["show", bead_id, "--json"])
    return json.loads(output)


def add_dependency(blocked: str, blocker: str) -> None:
    run_bd(["dep", "add", blocked, blocker])
