from __future__ import annotations

import fnmatch
import re
from pathlib import Path
from typing import Any

from .policy import (
    EDITOR_GATE_EXPERT,
    EXTERNAL_GUARD_LABELS,
    LOCAL_WORKER_GUARD_LABELS,
    PUBLIC_DOCS_EDITOR_TEXT_TERMS,
    PUBLIC_DOCS_PAGE_SUFFIXES,
    PUBLIC_DOCS_PAGE_TEXT_TERMS,
    PUBLIC_DOCS_PATHS,
    RISK_ORDER,
    SENSITIVITY_ORDER,
    boundary_config,
    detect_provider_conflicts,
    executor_config,
    load_policy,
    peer_review_policy,
    provider_metadata_for_executor,
    provider_profile,
    route_requires_peer_review,
    validate_peer_review_controls,
)
from .routing_signals import (
    architecture_review_complexity,
    claude_architecture_effort,
    command_with_claude_effort,
    explicit_chatgpt_master_plan_review_requested,
    explicit_claude_architect_critique_requested,
    explicit_gemini_architect_critique_requested,
    explicit_glm_architect_critique_requested,
    explicit_openai_deep_research_requested,
    requested_architecture_critic_executor_keys,
)
from .synthesis import recommend_model_synthesis, zero_trust_route_requirement
from .util import rank_allows, rank_max, term_hits


SENSITIVITY_HEURISTIC_DISCLAIMER = (
    "Data sensitivity is an advisory text heuristic and can miss paraphrases or context; "
    "operators should pass --data-sensitivity when sensitivity is known."
)


def normalize_data_sensitivity(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    if normalized not in SENSITIVITY_ORDER:
        raise SystemExit(
            "data_sensitivity must be one of: " + ", ".join(SENSITIVITY_ORDER)
        )
    return normalized


def detect_sensitivity(text: str, routing: dict[str, Any]) -> str:
    sensitivity_terms = routing.get("sensitivity_terms", {})
    for level in ["restricted", "redacted", "public"]:
        if term_hits(text, sensitivity_terms.get(level, [])):
            return level
    if term_hits(text, routing.get("restricted_terms", [])):
        return "restricted"
    return "internal"


def resolve_data_sensitivity(
    text: str,
    routing: dict[str, Any],
    *,
    data_sensitivity: str | None = None,
) -> dict[str, Any]:
    declared = normalize_data_sensitivity(data_sensitivity)
    heuristic = detect_sensitivity(text, routing)
    if declared:
        effective = max([declared, heuristic], key=SENSITIVITY_ORDER.index)
        source = "operator-declared"
        if effective == declared:
            reason = f"Operator declared data sensitivity {declared}; heuristic estimate was {heuristic}."
        else:
            reason = (
                f"Operator declared data sensitivity floor {declared}; "
                f"heuristic estimate {heuristic} raised the effective sensitivity to {effective}."
            )
    else:
        effective = heuristic
        source = "heuristic"
        reason = f"Text heuristic estimated data sensitivity {heuristic}."
    return {
        "data_sensitivity": effective,
        "data_sensitivity_source": source,
        "data_sensitivity_heuristic": heuristic,
        "data_sensitivity_disclaimer": SENSITIVITY_HEURISTIC_DISCLAIMER,
        "data_sensitivity_provenance": {
            "source": source,
            "declared_sensitivity": declared,
            "heuristic_sensitivity": heuristic,
            "effective_sensitivity": effective,
            "advisory_heuristic": True,
            "disclaimer": SENSITIVITY_HEURISTIC_DISCLAIMER,
            "reason": reason,
        },
    }


def dispatch_sensitivity_for_boundary(sensitivity: str, share_boundary: str) -> str:
    if share_boundary == "redacted-packet" and sensitivity == "internal":
        return "redacted"
    return sensitivity


CHATGPT_MASTER_REVIEW_GATE = "chatgpt-pro-5.5-master-plan-review"
CHATGPT_MASTER_REVIEW_EXECUTOR = "chatgpt_pro_browser_master_reviewer"
CHATGPT_MASTER_REVIEW_JOB = "contract-jd-master-plan-review"
CHATGPT_MASTER_REVIEW_FAILURE_BEHAVIOR = "stop-before-implementation-unless-explicit-operator-waiver"
CHATGPT_MASTER_REVIEW_REQUIRED_EVIDENCE = [
    "confirmed model_attestation for ChatGPT Pro 5.5 Extended Reasoning",
    "share-link return ingested with dispatch_id and packet_sha256",
    "contractor return evaluated before use",
    "Codex architect adjudication recorded before implementation",
]

DEFAULT_EXECUTION_ENVIRONMENT = "connected-codex"
GLM_PRIMARY_EXECUTION_ENVIRONMENT = "connected-codex-glm-primary"
GLM_BF16_ARCHITECTURE_CRITIC_EXECUTOR = "rhoai_glm_architecture_critic"
GLM_BF16_PRIMARY_ARCHITECT_EXECUTOR = "rhoai_glm_primary_architect"
CODEX_XHIGH_ARCHITECTURE_CRITIC_EXECUTOR = "codex_architecture_critic"
LOCAL_DISPATCH_MODES = {"local_openai_compatible", "local_secure_review"}


BEADS_CONTEXT_DEPTHS = ["none", "summary", "focused", "heavy", "audit"]
COMMENT_BEARING_BEADS_CONTEXT_DEPTHS = {"focused", "heavy", "audit"}
BEADS_CONTEXT_DEPTH_ALIASES = {
    "off": "none",
    "disabled": "none",
    "minimal": "summary",
    "brief": "summary",
    "default": "focused",
    "deep": "heavy",
    "full": "heavy",
    "forensic": "audit",
}


def resolve_execution_environment(execution_environment: str | None) -> tuple[str, dict[str, Any]]:
    key = str(execution_environment or DEFAULT_EXECUTION_ENVIRONMENT)
    profiles = load_policy("execution-environments").get("profiles", {})
    profile = profiles.get(key)
    if not isinstance(profile, dict):
        raise SystemExit(f"unknown execution environment: {key}")
    return key, profile


def execution_environment_role_binding(environment: dict[str, Any], role: str) -> dict[str, Any]:
    binding = (environment.get("role_bindings") or {}).get(role)
    return dict(binding) if isinstance(binding, dict) else {}


def execution_environment_role_executor(environment: dict[str, Any], role: str) -> str | None:
    executor = execution_environment_role_binding(environment, role).get("executor")
    return str(executor) if executor else None


def executor_registry_entry(executor_key: str | None) -> dict[str, Any]:
    if not executor_key:
        return {}
    try:
        return executor_config(executor_key)
    except SystemExit:
        return {}


def execution_environment_summary(environment_key: str, environment: dict[str, Any]) -> dict[str, Any]:
    bindings: dict[str, Any] = {}
    for role, binding in (environment.get("role_bindings") or {}).items():
        if isinstance(binding, dict):
            bindings[str(role)] = {
                key: value
                for key, value in binding.items()
                if key in {"harness", "executor", "agent", "model_profile"}
            }
    return {
        "key": environment_key,
        "display_name": environment.get("display_name"),
        "mode": environment.get("mode"),
        "default_harness": environment.get("default_harness"),
        "role_bindings": bindings,
    }


def normalize_beads_context_depth(value: str | None, *, field_name: str = "beads_context_depth") -> str | None:
    if value is None:
        return None
    normalized = str(value).strip().lower().replace("_", "-")
    normalized = BEADS_CONTEXT_DEPTH_ALIASES.get(normalized, normalized)
    if normalized not in BEADS_CONTEXT_DEPTHS:
        raise SystemExit(
            f"{field_name} must be one of {', '.join(BEADS_CONTEXT_DEPTHS)}"
        )
    return normalized


def higher_beads_context_depth(current: str, candidate: str) -> str:
    if BEADS_CONTEXT_DEPTHS.index(candidate) > BEADS_CONTEXT_DEPTHS.index(current):
        return candidate
    return current


def autosize_beads_context_depth(
    text: str,
    *,
    route: str,
    risk: str,
    task_class: str,
    workerbee_mode: str | None = None,
    model_synthesis_active: bool = False,
    editor_gate_required: bool = False,
) -> tuple[str, list[str]]:
    lower = text.lower()
    depth = "summary"
    rationale = ["Start with summary Beads context: assigned-bead JSON without comments."]

    focused_terms = [
        "architecture",
        "architect",
        "coach",
        "orchestration",
        "scaffold",
        "work graph",
        "workgraph",
        "subagent",
        "subagents",
        "workerbee",
        "workerbees",
        "contractor",
        "contractors",
        "local worker",
        "validation",
        "docs",
        "documentation",
        "github pages",
        "handoff",
        "release",
        "publish",
    ]
    heavy_terms = [
        "deep analysis",
        "deep pass",
        "deep 2nd pass",
        "second pass",
        "2nd pass",
        "refactor",
        "previous plan",
        "previous plans",
        "previous work",
        "prior work",
        "history",
        "comments",
        "context compaction",
        "memory",
        "synthesis",
        "multiple model",
        "model synthesis",
    ]
    audit_terms = [
        "audit",
        "forensic",
        "incident",
        "sabotage",
        "malpractice",
        "credential",
        "secret",
        "security incident",
        "boundary-tainted",
        "quarantine",
        "quarantined",
    ]

    if route in {"architect-review", "external-contract", "local-worker"} or risk in {"high", "critical"}:
        depth = higher_beads_context_depth(depth, "focused")
        rationale.append("Use focused context for high-risk, architect, contractor, or local-worker routes.")
    if task_class in {"architecture-review", "domain-review"} or term_hits(lower, focused_terms):
        depth = higher_beads_context_depth(depth, "focused")
        rationale.append("The task has architecture, review, docs, validation, or orchestration signals.")
    if workerbee_mode in {"review-only", "heavy-review", "implementation-capable"}:
        depth = higher_beads_context_depth(depth, "focused")
        rationale.append("Subagent work benefits from assigned-bead comments as evidence.")
    if model_synthesis_active:
        depth = higher_beads_context_depth(depth, "heavy")
        rationale.append("Model synthesis needs broader provenance across reviewed returns.")
    if editor_gate_required:
        depth = higher_beads_context_depth(depth, "focused")
        rationale.append("Public documentation/editor gates need focused Beads evidence.")
    if term_hits(lower, heavy_terms):
        depth = higher_beads_context_depth(depth, "heavy")
        rationale.append("Deep-pass, history, synthesis, or prior-work language warrants heavy Beads context.")
    if risk == "critical" or term_hits(lower, audit_terms):
        depth = higher_beads_context_depth(depth, "audit")
        rationale.append("Audit, incident, sabotage, credential, or quarantine language warrants audit context.")
    return depth, list(dict.fromkeys(rationale))


def resolve_beads_context_depth(
    text: str,
    *,
    route: str,
    risk: str,
    task_class: str,
    workerbee_mode: str | None = None,
    model_synthesis_active: bool = False,
    editor_gate_required: bool = False,
    beads_context_depth: str | None = None,
    actor_context: str = "routing",
) -> dict[str, Any]:
    explicit_context = normalize_beads_context_depth(beads_context_depth, field_name="beads_context_depth")

    computed, rationale = autosize_beads_context_depth(
        text,
        route=route,
        risk=risk,
        task_class=task_class,
        workerbee_mode=workerbee_mode,
        model_synthesis_active=model_synthesis_active,
        editor_gate_required=editor_gate_required,
    )
    requested = explicit_context
    if requested:
        effective = requested
        source = "explicit"
        override_field = "beads_context_depth"
        rationale.append(f"Explicit {override_field} override selected {effective}.")
    else:
        effective = computed
        source = "autosized"
        override_field = None

    return {
        "beads_context_depth": effective,
        "beads_context_depth_source": source,
        "beads_context_depth_rationale": rationale,
        "beads_context_depth_provenance": {
            "source": source,
            "requested_depth": requested,
            "computed_depth": computed,
            "effective_depth": effective,
            "override_field": override_field,
            "reason": rationale[-1] if rationale else "",
            "actor_context": actor_context,
        },
    }


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


DOC_SAFE_EXPERTS_FOR_TRIVIAL_CHANGE = {"documentation", "general_reasoning"}
DOC_FILE_SUFFIXES = {".adoc", ".md", ".mdx", ".rst", ".txt"}
DOC_PATH_PREFIXES = ("docs/", "references/", "templates/", "examples/")


def is_documentation_file_path(path: str) -> bool:
    clean = path.strip().lstrip("./")
    name = Path(clean).name
    if clean in PUBLIC_DOCS_PATHS or name in {"README.md", "SKILL.md", "CHANGELOG.md"}:
        return True
    return clean.startswith(DOC_PATH_PREFIXES) and Path(clean).suffix in DOC_FILE_SUFFIXES


def public_docs_editor_gate_required(text: str, file_paths: list[str] | None = None) -> bool:
    if trivial_single_file_docs_change(text, file_paths):
        return False
    lowered = text.lower()
    if any(term in lowered for term in PUBLIC_DOCS_EDITOR_TEXT_TERMS):
        return True
    return any(is_public_docs_path(path) for path in file_paths or [])


def public_docs_page_review_required(text: str, file_paths: list[str] | None = None) -> bool:
    lowered = text.lower()
    if any(term in lowered for term in PUBLIC_DOCS_PAGE_TEXT_TERMS):
        return True
    return any(is_public_docs_page_path(path) for path in file_paths or [])


def trivial_single_file_docs_change(text: str, file_paths: list[str] | None = None) -> bool:
    lowered = text.lower()
    trivial_terms = [
        "typo",
        "spelling",
        "grammar",
        "punctuation",
        "copy edit",
        "copy-edit",
        "wording",
        "single-file",
        "single file",
        "one-file",
        "one file",
    ]
    public_or_publish_terms = [
        "publish",
        "release",
        "public docs",
        "public documentation",
        "public guide",
        "operator docs",
        "install docs",
        "installation docs",
        "install section",
        "github pages",
        "github page",
        "docs site",
        "documentation site",
        "site flow",
        "docs flow",
        "pages flow",
        "documentation architecture",
        "diataxis",
        "diátaxis",
    ]
    mixed_intent_terms = [
        "auth",
        "authn",
        "authz",
        "credential",
        "harden",
        "secret",
        "security",
        "token",
    ]
    docs_scope_terms = [
        "readme",
        "skill.md",
        "docs",
        "documentation",
        "markdown",
    ]
    if not any(term in lowered for term in trivial_terms):
        return False
    if any(term in lowered for term in public_or_publish_terms):
        return False
    if term_hits(lowered, mixed_intent_terms):
        return False
    paths = [path.strip().lstrip("./") for path in (file_paths or []) if str(path).strip()]
    if paths:
        if len(paths) > 1:
            return False
        if is_public_docs_page_path(paths[0]):
            return False
        return is_documentation_file_path(paths[0])
    return bool(term_hits(lowered, docs_scope_terms))


def expert_has_non_path_reason(expert: dict[str, Any]) -> bool:
    return any(
        not str(reason).startswith("path patterns:")
        for reason in expert.get("reasons", [])
    )


def trivial_docs_only_change(
    text: str,
    file_paths: list[str] | None,
    experts: list[dict[str, Any]],
) -> bool:
    if not trivial_single_file_docs_change(text, file_paths):
        return False
    for expert in experts:
        if expert.get("name") in DOC_SAFE_EXPERTS_FOR_TRIVIAL_CHANGE:
            continue
        if expert_has_non_path_reason(expert):
            return False
    return True


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
    if executor.get("dispatch_mode") in LOCAL_DISPATCH_MODES:
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
        if prefer_local and executor.get("dispatch_mode") in LOCAL_DISPATCH_MODES and not violations:
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
        is_architecture_review_task = task_class == "architecture-review"
        if key == CODEX_XHIGH_ARCHITECTURE_CRITIC_EXECUTOR:
            score -= 100
            reasons.append("reserved for explicit architecture counter-review lanes")
        if is_architecture_review_task and key == "gemini_architecture_critic" and explicit_gemini_architect_critique_requested(text):
            score += 30
            reasons.append("explicit Gemini/Agy architect critique request")
        if is_architecture_review_task and key == "claude_architecture_critic" and explicit_claude_architect_critique_requested(text):
            score += 32
            reasons.append("explicit Claude Opus architect critique request")
        if is_architecture_review_task and key == "rhoai_glm_architecture_critic" and explicit_glm_architect_critique_requested(text):
            score += 34
            reasons.append("explicit GLM-5.2 BF16 architect critique request")
        if key == "chatgpt_pro_browser_master_reviewer" and explicit_chatgpt_master_plan_review_requested(text):
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
            and key != "chatgpt_pro_browser_master_reviewer"
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
                "model_profile": executor.get("model_profile"),
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
    model_synthesis: bool = False,
    beads_context_depth: str | None = None,
    data_sensitivity: str | None = None,
    execution_environment: str | None = None,
) -> dict[str, Any]:
    routing = load_policy("routing-policy")
    expert_registry = load_policy("expert-registry")
    execution_environment_key, execution_environment_config = resolve_execution_environment(execution_environment)
    environment_project_manager_executor = execution_environment_role_executor(
        execution_environment_config, "project_manager"
    )
    environment_architect_executor = execution_environment_role_executor(execution_environment_config, "architect")
    environment_counter_review_executor = execution_environment_role_executor(
        execution_environment_config, "architecture_counter_review"
    )
    environment_architect_config = executor_registry_entry(environment_architect_executor)
    environment_implies_local_architect = bool(
        execution_environment
        and environment_architect_config.get("dispatch_mode") in LOCAL_DISPATCH_MODES
    )
    effective_local_ok = bool(local_ok or environment_implies_local_architect)
    effective_local_profile = local_profile
    if environment_implies_local_architect and not effective_local_profile:
        effective_local_profile = environment_architect_config.get("local_profile")
    experts = score_experts_v2(
        text,
        expert_registry,
        requested_roles=requested_roles,
        file_paths=file_paths,
        stage=stage,
    )
    small_docs_change = trivial_docs_only_change(text, file_paths, experts)
    if small_docs_change:
        experts = [
            expert
            for expert in experts
            if expert.get("name") in {"documentation", "general_reasoning"}
        ]
    if not experts:
        experts = score_experts_v2(text + " independent review", expert_registry)
    requested = {role.lower() for role in (requested_roles or [])}
    if (
        requested_architecture_critic_executor_keys(text)
        and any(expert.get("name") == "architecture" for expert in experts)
        and requested <= {"architecture", "architect", "system-design", "design-review", "architect-critique", "architecture-critique"}
    ):
        keep_names = {"architecture"}
        if explicit_chatgpt_master_plan_review_requested(text):
            keep_names.add("master_plan_review")
        experts = [expert for expert in experts if expert.get("name") in keep_names]
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

    sensitivity_signal = resolve_data_sensitivity(text, routing, data_sensitivity=data_sensitivity)
    sensitivity = sensitivity_signal["data_sensitivity"]
    dispatch_sensitivity = dispatch_sensitivity_for_boundary(sensitivity, share_boundary)
    risk = rank_max([expert.get("default_risk", "medium") for expert in experts], RISK_ORDER, "low")
    if small_docs_change:
        risk = "low"
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
                local_ok=effective_local_ok,
                prefer_local=prefer_local,
                local_profile=effective_local_profile,
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
        local_ok=effective_local_ok,
        prefer_local=prefer_local,
        local_profile=effective_local_profile,
        experts=experts,
        text=text,
        unattended=unattended,
        provider_conflict_domains=provider_conflict_domains,
    )
    selected = route_primary.get("selected_executor") or ranked_executors[0]
    recommended_executor = route_primary.get("recommended_executor", selected["key"])
    architecture_complexity = architecture_review_complexity(text, risk)
    claude_effort = claude_architecture_effort(architecture_complexity)
    requested_critic_keys = requested_architecture_critic_executor_keys(text)
    ranked_by_key = {str(item.get("key")): item for item in ranked_executors}
    if execution_environment_key == GLM_PRIMARY_EXECUTION_ENVIRONMENT:
        requested_critic_keys = [
            key for key in requested_critic_keys if key != GLM_BF16_ARCHITECTURE_CRITIC_EXECUTOR
        ]
        if (
            environment_counter_review_executor
            and environment_counter_review_executor not in requested_critic_keys
        ):
            requested_critic_keys.append(environment_counter_review_executor)
    if (
        execution_environment_key == GLM_PRIMARY_EXECUTION_ENVIRONMENT
        and task_class == "architecture-review"
        and environment_architect_executor in ranked_by_key
    ):
        selected = ranked_by_key[str(environment_architect_executor)]
        recommended_executor = str(environment_architect_executor)
        for expert in experts:
            if expert.get("name") == "architecture":
                expert["recommended_executor"] = recommended_executor
                expert["selected_executor"] = selected
                expert["executor_policy_violations"] = selected.get("policy_violations", [])
                expert["executor_candidates"] = ranked_executors
        if primary.get("name") == "architecture":
            primary = next((expert for expert in experts if expert.get("name") == "architecture"), primary)
            route_primary = primary
    architecture_critic_contracts: list[dict[str, Any]] = []
    for key in requested_critic_keys:
        candidate = ranked_by_key.get(key)
        if not candidate or candidate.get("policy_violations"):
            continue
        contract = {
            "executor": key,
            "display_name": candidate.get("display_name", key),
            "provider_key": candidate.get("provider_key"),
            "provider_family": candidate.get("provider_family"),
            "provider_trust_tier": candidate.get("provider_trust_tier"),
            "job_description_label": "contract-jd-architecture-reasoning",
            "critique_mode": candidate.get("critique_mode"),
            "share_boundary": share_boundary,
            "codex_pickup": "forbidden",
            "architect_review_required": True,
            "acceptance_required": True,
            "selected_executor": candidate,
        }
        transport = candidate.get("transport") if isinstance(candidate.get("transport"), dict) else {}
        default_command = str(transport.get("default_command", ""))
        if key == "claude_architecture_critic":
            contract["architecture_complexity"] = architecture_complexity
            contract["claude_effort"] = claude_effort
            if default_command:
                contract["manual_command"] = command_with_claude_effort(default_command, claude_effort)
        elif key == "rhoai_glm_architecture_critic":
            contract["local_profile"] = candidate.get("local_profile")
            contract["model_profile"] = candidate.get("model_profile")
        elif default_command:
            contract["manual_command"] = default_command
        architecture_critic_contracts.append(contract)

    chatgpt_master_review_required = explicit_chatgpt_master_plan_review_requested(text)
    dispatch_mode = selected.get("dispatch_mode")
    if selected.get("external"):
        route = "external-contract"
    elif dispatch_mode in LOCAL_DISPATCH_MODES:
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
    sabotage_review_required = bool(
        any(str(expert.get("name")) == "sabotage_review" for expert in experts)
        and (
            route in {"external-contract", "local-worker"}
            or term_hits(
                text,
                [
                    "contractor return",
                    "model return",
                    "work rerouting",
                    "work_rerouting_or_subversion",
                    "objective dilution",
                    "critical path deferral",
                    "non-equivalent substitution",
                    "quarantine",
                ],
            )
        )
    )
    peer_required = route_requires_peer_review(
        route=route,
        risk=risk,
        share_boundary=share_boundary,
        provider_conflict_domains=provider_conflict_domains,
    ) or sabotage_review_required
    peer_policy = peer_review_policy()
    peer_review_count = int(peer_policy.get("defaults", {}).get("minimum_peer_reviews", 1)) if peer_required else 0
    zero_trust_route = zero_trust_route_requirement(text, risk=risk)

    synthesis_result = recommend_model_synthesis(text, {}, force_accepted=model_synthesis)
    beads_depth = resolve_beads_context_depth(
        text,
        route=route,
        risk=risk,
        task_class=task_class,
        model_synthesis_active=bool(synthesis_result.get("active")),
        editor_gate_required=editor_gate_required,
        beads_context_depth=beads_context_depth,
        actor_context=stage or "routing",
    )

    result = {
        "route": route,
        "task_class": task_class,
        "risk_level": risk,
        **sensitivity_signal,
        "dispatch_sensitivity": dispatch_sensitivity,
        "share_boundary": share_boundary,
        "execution_environment": execution_environment_key,
        "execution_environment_profile": execution_environment_summary(
            execution_environment_key, execution_environment_config
        ),
        "project_manager_executor": environment_project_manager_executor,
        "primary_architect_executor": environment_architect_executor,
        "architecture_counter_review_executor": environment_counter_review_executor,
        "architecture_authority": (
            "glm-5.2-primary-architect"
            if execution_environment_key == GLM_PRIMARY_EXECUTION_ENVIRONMENT
            else "codex-frontier-architect"
        ),
        "external_opt_in": external_ok,
        "disclosure_escalation_approved": allow_disclosure_escalation,
        "external_contract_allowed": route == "external-contract" and not hard_stops,
        "local_worker_allowed": effective_local_ok,
        "local_worker_opt_in_source": (
            "execution-environment" if environment_implies_local_architect and not local_ok else "operator-flag" if local_ok else None
        ),
        "prefer_local_worker": prefer_local,
        "local_profile": effective_local_profile,
        "has_external_expert_contracts": bool(external_experts),
        "has_local_worker_contracts": bool(local_worker_experts),
        "external_experts": external_experts,
        "local_worker_experts": local_worker_experts,
        "internal_experts": internal_experts,
        "acceptance_required_experts": acceptance_required_experts,
        "recommended_executor": recommended_executor,
        "selected_executor": selected,
        "blocking_review_required": chatgpt_master_review_required,
        "blocking_review_active": bool(
            chatgpt_master_review_required
            and route == "external-contract"
            and recommended_executor == CHATGPT_MASTER_REVIEW_EXECUTOR
            and not hard_stops
        ),
        "blocking_review_gate": CHATGPT_MASTER_REVIEW_GATE if chatgpt_master_review_required else None,
        "blocking_review_executor": CHATGPT_MASTER_REVIEW_EXECUTOR if chatgpt_master_review_required else None,
        "blocking_review_job_description_label": CHATGPT_MASTER_REVIEW_JOB if chatgpt_master_review_required else None,
        "blocking_review_waiver_required": chatgpt_master_review_required,
        "blocking_review_failure_behavior": (
            CHATGPT_MASTER_REVIEW_FAILURE_BEHAVIOR if chatgpt_master_review_required else None
        ),
        "blocking_review_required_evidence": (
            list(CHATGPT_MASTER_REVIEW_REQUIRED_EVIDENCE) if chatgpt_master_review_required else []
        ),
        "architecture_review_complexity": architecture_complexity,
        "claude_architecture_effort": claude_effort,
        "requested_architecture_critic_executors": requested_critic_keys,
        "architecture_critic_contracts": architecture_critic_contracts,
        "provider_conflict_detected": bool(provider_conflict_domains),
        "provider_conflict_domains": provider_conflict_domains,
        "provider_diversity_required": bool(peer_required and peer_policy.get("defaults", {}).get("provider_diversity_required", True)),
        "peer_review_required": peer_required,
        "sabotage_review_required": sabotage_review_required,
        "peer_review_count": peer_review_count,
        "peer_review_labels": peer_policy.get("peer_review_labels", []),
        "quarantine_on_fail": bool(peer_policy.get("defaults", {}).get("quarantine_on_high_sabotage", True)),
        "local_secure_review_executor": peer_policy.get("defaults", {}).get("local_secure_review_executor"),
        **zero_trust_route,
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
        **beads_depth,
        "hard_stops": hard_stops,
        "reasons": [
            "ranked experts: " + ", ".join(f"{item['name']}={item['score']}" for item in experts[:5]),
            "ranked executors: " + ", ".join(f"{item['key']}={item['score']}" for item in ranked_executors[:5]),
        ],
    }
    result["model_synthesis"] = recommend_model_synthesis(text, result, force_accepted=model_synthesis)
    if result["model_synthesis"].get("active") and beads_depth["beads_context_depth"] != "audit":
        refreshed = resolve_beads_context_depth(
            text,
            route=route,
            risk=risk,
            task_class=task_class,
            model_synthesis_active=True,
            editor_gate_required=editor_gate_required,
            beads_context_depth=beads_context_depth,
            actor_context=stage or "routing",
        )
        result.update(refreshed)
    return result


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
    return selected_executor_for_expert(expert, fallback_executor).get("dispatch_mode") in LOCAL_DISPATCH_MODES


def expert_review_lane(expert: dict[str, Any]) -> str:
    raw = str(expert.get("name") or expert.get("discipline") or expert.get("display_name") or "review")
    slug = re.sub(r"[^a-z0-9]+", "-", raw.lower()).strip("-") or "review"
    return f"expert-review-{slug}"


def expert_review_labels(expert: dict[str, Any], route: dict[str, Any]) -> list[str]:
    stage = str(expert.get("review_stage", "pre-implementation"))
    job_label = str(expert.get("job_description_label", "contract-jd-general-reasoning"))
    selected = selected_executor_for_expert(expert, route.get("recommended_executor"))
    if bool(selected.get("external")):
        return [*EXTERNAL_GUARD_LABELS, job_label, stage]
    if selected.get("dispatch_mode") in LOCAL_DISPATCH_MODES:
        return [*LOCAL_WORKER_GUARD_LABELS, job_label, stage]
    if selected.get("codex_pickup") == "forbidden":
        return ["expert-review", "no-codex-exec", job_label, stage]
    return ["expert-review", job_label, stage]


def expert_review_metadata(expert: dict[str, Any], route: dict[str, Any]) -> dict[str, Any]:
    selected = selected_executor_for_expert(expert, route.get("recommended_executor"))
    executor = expert.get("recommended_executor") or selected.get("key") or route.get("recommended_executor")
    external = bool(selected.get("external"))
    dispatch_mode = selected.get("dispatch_mode")
    local_worker = dispatch_mode in LOCAL_DISPATCH_MODES
    contract = expert.get("contractor_contract") if isinstance(expert.get("contractor_contract"), dict) else {}
    contract_acceptance_required = bool(contract.get("acceptance_required"))
    contract_codex_pickup = contract.get("codex_pickup")
    metadata = {
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
        "codex_pickup": (
            contract_codex_pickup
            or ("forbidden" if external or local_worker else selected.get("codex_pickup", "allowed"))
        ),
        "architect_review_required": True,
        "acceptance_bead_required": external or local_worker or contract_acceptance_required,
        "validation_gate_required": bool(expert.get("validation_gate_required")),
        "gate_scope": expert.get("gate_scope"),
    }
    if contract:
        metadata["architecture_critic_contract"] = {
            key: value
            for key, value in contract.items()
            if key
            in {
                "executor",
                "display_name",
                "provider_key",
                "provider_family",
                "provider_trust_tier",
                "job_description_label",
                "critique_mode",
                "manual_command",
                "architecture_complexity",
                "claude_effort",
            }
        }
    if (
        route.get("blocking_review_required")
        and route.get("blocking_review_executor") == executor
        and route.get("blocking_review_job_description_label") == expert.get("job_description_label")
    ):
        metadata.update(
            {
                "blocking_review_required": True,
                "blocking_review_gate": route.get("blocking_review_gate"),
                "blocking_review_active": bool(route.get("blocking_review_active")),
                "blocking_review_waiver_required": bool(route.get("blocking_review_waiver_required")),
                "blocking_review_failure_behavior": route.get("blocking_review_failure_behavior"),
                "blocking_review_required_evidence": route.get("blocking_review_required_evidence", []),
            }
        )
    return metadata
