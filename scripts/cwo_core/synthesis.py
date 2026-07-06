from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from .policy import load_policy
from .util import term_hits


def synthesis_policy() -> dict[str, Any]:
    return load_policy("synthesis-policy")


def zero_trust_consensus_policy() -> dict[str, Any]:
    return load_policy("zero-trust-consensus-policy")


def zero_trust_policy_sha256(policy: dict[str, Any] | None = None) -> str:
    config = policy or zero_trust_consensus_policy()
    encoded = json.dumps(config, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def mentioned_provider_camps(text: str, policy: dict[str, Any] | None = None) -> list[str]:
    config = policy or synthesis_policy()
    camps = config.get("provider_camps", {})
    mentioned: list[str] = []
    for camp, details in camps.items():
        if term_hits(text, list(details.get("terms", []))):
            mentioned.append(str(camp))
    return sorted(set(mentioned))


def zero_trust_route_requirement(
    text: str,
    *,
    risk: str = "low",
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return route-level zero-trust trigger state without changing dispatch authority."""

    config = policy or zero_trust_consensus_policy()
    triggers = dict(config.get("routing_triggers", {}))
    explicit_hits = term_hits(text, list(triggers.get("explicit_terms", [])))
    security_hits = term_hits(text, list(triggers.get("security_sensitive_terms", [])))
    context_hits = term_hits(text, list(triggers.get("activation_context_terms", [])))
    required_risks = {str(item) for item in triggers.get("required_risk_levels", ["high", "critical"])}
    reasons: list[str] = []
    if explicit_hits:
        reasons.append("explicit zero-trust or cross-domain divergence request: " + ", ".join(explicit_hits[:5]))
    if security_hits and context_hits:
        reasons.append("security-sensitive review terms: " + ", ".join(security_hits[:5]))
    required = bool(explicit_hits or (security_hits and context_hits))
    if not required and security_hits and risk in required_risks and term_hits(text, ["security", "secure", "threat", "vulnerability"]):
        required = True
        reasons.append("high-risk security-sensitive work: " + ", ".join(security_hits[:5]))
    defaults = dict(config.get("defaults", {}))
    return {
        "zero_trust_consensus_required": required,
        "zero_trust_consensus_trigger_reasons": reasons if required else [],
        "zero_trust_minimum_independent_domains": int(defaults.get("minimum_independent_domains", 2)),
        "zero_trust_policy_version": config.get("version"),
    }


def _route_has_architecture_signal(text: str, route: dict[str, Any], policy: dict[str, Any]) -> bool:
    if route.get("route") == "architect-review":
        return True
    if route.get("task_class") == "architecture-review":
        return True
    if any(expert.get("name") == "architecture" for expert in route.get("ranked_experts", [])):
        return True
    return bool(term_hits(text, list(policy.get("architecture_terms", []))))


def active_synthesis_modes(policy: dict[str, Any] | None = None) -> set[str]:
    config = policy or synthesis_policy()
    return {str(item) for item in config.get("active_modes", ["requested", "accepted"])}


def route_provider_camps(route: dict[str, Any]) -> list[str]:
    camps: set[str] = set()
    architecture_authority = str(route.get("architecture_authority") or "")
    if architecture_authority == "glm-5.2-primary-architect":
        camps.update({"local", "codex"})
    return sorted(camps)


def synthesis_owner_for_route(policy: dict[str, Any], route: dict[str, Any]) -> str:
    if route.get("architecture_authority") == "glm-5.2-primary-architect" and route.get("primary_architect_executor"):
        return str(route["primary_architect_executor"])
    return str(policy.get("synthesis_owner", "frontier_architect"))


def synthesis_panel_for_route(policy: dict[str, Any], route: dict[str, Any]) -> list[dict[str, Any]]:
    if route.get("architecture_authority") == "glm-5.2-primary-architect":
        primary_architect = str(
            route.get("primary_architect_executor")
            or "rhoai_glm_primary_architect"
        )
        counter_review = str(
            route.get("architecture_counter_review_executor")
            or "codex_architecture_critic"
        )
        return [
            {
                "executor": primary_architect,
                "role": "primary-architect",
                "provider_camp": "local",
                "effort": "thinking-enabled",
                "external": False,
            },
            {
                "executor": counter_review,
                "role": "architecture-counter-review",
                "provider_camp": "codex",
                "effort": "xhigh",
                "external": False,
            },
        ]
    return [dict(item) for item in policy.get("default_panel", [])]


def provider_conflict_flags(route: dict[str, Any], camps: list[str]) -> list[dict[str, Any]]:
    flags: list[dict[str, Any]] = []
    if route.get("provider_conflict_detected"):
        flags.append(
            {
                "kind": "route-provider-conflict",
                "domains": [str(item) for item in route.get("provider_conflict_domains", [])],
                "required_handling": "preserve provider provenance and summarize material provider-camp disagreements",
            }
        )
    if len(camps) >= 2:
        flags.append(
            {
                "kind": "multi-camp-request",
                "provider_camps": camps,
                "required_handling": "keep independent model-camp returns separate before synthesis",
            }
        )
    return flags


def _normalize_disposition(value: Any) -> str:
    disposition = str(value or "missing").strip().lower().replace("_", "-").replace(" ", "-")
    aliases = {
        "accept": "accepted",
        "accepted-with-modifications": "accepted-with-modification",
        "accept-with-modification": "accepted-with-modification",
        "modified-accept": "accepted-with-modification",
        "partial-accept": "accepted-with-modification",
        "timeout": "timed-out",
        "timedout": "timed-out",
        "blank": "empty",
        "quarantine": "quarantined",
        "boundary-taint": "boundary-tainted",
        "tainted": "boundary-tainted",
        "reject": "rejected",
        "failure": "failed-evaluation",
        "failed": "failed-evaluation",
    }
    return aliases.get(disposition, disposition)


def _normalize_boundary_status(value: Any) -> str:
    status = str(value or "unknown").strip().lower().replace("_", "-").replace(" ", "-")
    aliases = {
        "clean": "clear",
        "not-tainted": "clear",
        "boundary-taint": "boundary-tainted",
        "tainted": "boundary-tainted",
    }
    return aliases.get(status, status)


def _normalize_synthesis_use(value: Any) -> str | None:
    if value is None:
        return None
    use = str(value).strip().lower().replace("_", "-").replace(" ", "-")
    aliases = {
        "use": "primary",
        "usable": "primary",
        "use-as-input": "primary",
        "use-as-primary": "primary",
        "salvage": "salvage-only",
        "salvageonly": "salvage-only",
        "partial": "partial-only",
        "partialonly": "partial-only",
        "openrisk": "open-risk",
        "quarantined": "quarantine",
        "rejected": "reject",
    }
    normalized = aliases.get(use, use)
    if normalized in {"primary", "salvage-only", "partial-only", "open-risk", "quarantine", "reject"}:
        return normalized
    return None


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def evaluate_synthesis_inputs(
    inputs: list[dict[str, Any]],
    policy: dict[str, Any] | None = None,
    *,
    zero_trust_required: bool = False,
) -> dict[str, Any]:
    """Apply synthesis disposition policy to independently evaluated model returns."""

    config = policy or synthesis_policy()
    disposition_policy = dict(config.get("input_disposition_policy", {}))
    partial_policy = dict(config.get("partial_synthesis_policy", {}))
    use_as_input = {
        _normalize_disposition(item)
        for item in disposition_policy.get(
            "use_as_synthesis_input",
            disposition_policy.get("use_as_primary", ["accepted", "accepted-with-modification"]),
        )
    }
    open_risk = {
        _normalize_disposition(item) for item in disposition_policy.get("summarize_as_open_risk", [])
    }
    salvage_only = {
        _normalize_disposition(item) for item in disposition_policy.get("salvage_only", ["salvage-only"])
    }
    salvage_only_camps = {str(item) for item in config.get("salvage_only_provider_camps", [])}
    partial_only = {
        _normalize_disposition(item) for item in disposition_policy.get("partial_only", [])
    }
    quarantine = {
        _normalize_disposition(item)
        for item in disposition_policy.get("quarantine", ["quarantined", "boundary-tainted"])
    }
    rejected = {
        _normalize_disposition(item)
        for item in disposition_policy.get("exclude_as_rejected", disposition_policy.get("reject", ["rejected"]))
    }
    rejected.update({"rejected", "failed-evaluation"})

    input_summaries: list[dict[str, Any]] = []
    primary_inputs: list[dict[str, Any]] = []
    salvage_inputs: list[dict[str, Any]] = []
    partial_inputs: list[dict[str, Any]] = []
    open_risk_inputs: list[dict[str, Any]] = []
    quarantined_inputs: list[dict[str, Any]] = []
    rejected_inputs: list[dict[str, Any]] = []
    unknown_inputs: list[dict[str, Any]] = []
    held_inputs: list[dict[str, Any]] = []
    external_inputs: list[dict[str, Any]] = []

    for index, entry in enumerate(inputs, start=1):
        disposition = _normalize_disposition(entry.get("disposition"))
        boundary_status = _normalize_boundary_status(
            entry.get("boundary_taint_status")
            or entry.get("boundary_status")
            or entry.get("share_boundary_status")
        )
        effective_disposition = "boundary-tainted" if boundary_status == "boundary-tainted" else disposition
        lane = str(entry.get("lane") or entry.get("id") or entry.get("name") or f"input-{index}")
        external = bool(entry.get("external", True))
        provider_camp = str(entry.get("provider_camp") or "")
        implementation_blocked = _truthy(entry.get("implementation_blocked"))
        hold_reasons = [str(item) for item in entry.get("hold_reasons", []) if str(item).strip()]
        hold_classification = str(entry.get("hold_classification") or "none")
        requested_synthesis_use = _normalize_synthesis_use(
            entry.get("synthesis_use") or entry.get("recommended_synthesis_use")
        )

        requested_primary_authorized = bool(
            entry.get("architect_adjudicated")
            or entry.get("architect_upgrade")
            or entry.get("architect_adjudication_authorized")
            or entry.get("implementation_block_override_authorized")
            or str(entry.get("synthesis_use_authority") or "").strip().lower() in {"architect", "architect-adjudication"}
        )

        if effective_disposition in quarantine:
            synthesis_use = "quarantine"
        elif effective_disposition in rejected:
            synthesis_use = "reject"
        elif implementation_blocked and not requested_primary_authorized:
            synthesis_use = "open-risk"
        elif requested_synthesis_use == "primary" and not requested_primary_authorized:
            synthesis_use = "salvage-only" if provider_camp in salvage_only_camps else "unknown"
        elif requested_synthesis_use:
            synthesis_use = requested_synthesis_use
        elif effective_disposition in salvage_only:
            synthesis_use = "salvage-only"
        elif provider_camp in salvage_only_camps and effective_disposition in use_as_input:
            synthesis_use = "salvage-only"
        elif effective_disposition in use_as_input:
            synthesis_use = "primary"
        elif effective_disposition in partial_only:
            synthesis_use = "partial-only"
        elif effective_disposition in open_risk:
            synthesis_use = "open-risk"
        else:
            synthesis_use = "unknown"

        summary = {
            "lane": lane,
            "provider_camp": entry.get("provider_camp"),
            "disposition": disposition,
            "effective_disposition": effective_disposition,
            "boundary_status": boundary_status,
            "synthesis_use": synthesis_use,
            "requested_synthesis_use": requested_synthesis_use,
            "evidence_quality_score": entry.get("evidence_quality_score"),
            "external": external,
            "reason": entry.get("reason"),
            "implementation_blocked": implementation_blocked,
            "hold_classification": hold_classification,
            "hold_reasons": hold_reasons,
        }
        input_summaries.append(summary)
        if implementation_blocked:
            held_inputs.append(summary)
        if external:
            external_inputs.append(summary)
        if synthesis_use == "primary":
            primary_inputs.append(summary)
        elif synthesis_use == "salvage-only":
            salvage_inputs.append(summary)
        elif synthesis_use == "partial-only":
            partial_inputs.append(summary)
        elif synthesis_use == "quarantine":
            quarantined_inputs.append(summary)
        elif synthesis_use == "reject":
            rejected_inputs.append(summary)
        elif synthesis_use == "open-risk":
            open_risk_inputs.append(summary)
        else:
            unknown_inputs.append(summary)

    minimum_usable_inputs = int(partial_policy.get("minimum_usable_inputs", 2))
    blocked_reasons: list[str] = []
    if len(primary_inputs) < minimum_usable_inputs:
        blocked_reasons.append("fewer than minimum_usable_inputs accepted or accepted-with-modification inputs")
        if salvage_inputs:
            blocked_reasons.append("salvage-only inputs do not satisfy minimum_usable_inputs")
    if external_inputs and all(item["effective_disposition"] in quarantine for item in external_inputs):
        blocked_reasons.append("all external inputs are quarantined or boundary-tainted")
    if unknown_inputs:
        blocked_reasons.append("one or more inputs have unknown evaluator dispositions")

    zero_trust_consensus = evaluate_zero_trust_consensus(
        inputs,
        input_summaries,
        required=zero_trust_required,
    )
    if zero_trust_consensus["required"]:
        if zero_trust_consensus["consensus_status"] == "blocked":
            blocked_reasons.extend(zero_trust_consensus["blocked_reasons"])
        elif zero_trust_consensus["recommended_action"] in {"escalate", "quarantine"}:
            blocked_reasons.append(
                "zero-trust cross-domain divergence requires architect resolution"
            )

    allow_partial = bool(partial_policy.get("allow_partial", True))
    status = "ready"
    if blocked_reasons:
        status = "blocked"
    elif partial_inputs or open_risk_inputs or rejected_inputs or quarantined_inputs or unknown_inputs:
        status = str(partial_policy.get("partial_status", "partial")) if allow_partial else "blocked"
        if not allow_partial:
            blocked_reasons.append("partial synthesis is disabled by policy")

    return {
        "status": status,
        "blocked": bool(blocked_reasons),
        "blocked_reasons": blocked_reasons,
        "allow_partial": allow_partial,
        "minimum_usable_inputs": minimum_usable_inputs,
        "input_count": len(input_summaries),
        "usable_input_count": len(primary_inputs),
        "primary_input_count": len(primary_inputs),
        "salvage_input_count": len(salvage_inputs),
        "partial_input_count": len(partial_inputs),
        "open_risk_input_count": len(open_risk_inputs),
        "quarantined_input_count": len(quarantined_inputs),
        "rejected_input_count": len(rejected_inputs),
        "unknown_input_count": len(unknown_inputs),
        "held_input_count": len(held_inputs),
        "input_summaries": input_summaries,
        "primary_inputs": primary_inputs,
        "salvage_inputs": salvage_inputs,
        "partial_inputs": partial_inputs,
        "open_risk_inputs": open_risk_inputs,
        "quarantined_inputs": quarantined_inputs,
        "rejected_inputs": rejected_inputs,
        "unknown_inputs": unknown_inputs,
        "held_inputs": held_inputs,
        "zero_trust_consensus": zero_trust_consensus,
    }


def _zero_trust_normalize(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip().lower())


def _zero_trust_normalize_claim_value(value: Any, *, category: str) -> str:
    """Normalize short technical identifiers without treating prose as equivalent."""

    normalized = _zero_trust_normalize(value)
    if category not in {"crypto", "auth", "network"}:
        return normalized
    if len(normalized) > 64:
        return normalized
    if re.search(r"https?://|[/\\{}\\[\\]=]", normalized):
        return normalized
    if "." in normalized:
        return normalized
    if not re.fullmatch(r"[a-z0-9][a-z0-9\s_-]*[a-z0-9]", normalized):
        return normalized
    compact = re.sub(r"[\s_-]+", "", normalized)
    tokens = re.findall(r"[a-z]+|\d+", compact)
    if 2 <= len(tokens) <= 6 and "".join(tokens) == compact:
        return " ".join(tokens)
    return normalized


def _zero_trust_domain_for_input(
    entry: dict[str, Any],
    policy: dict[str, Any],
) -> dict[str, Any]:
    resolution = dict(policy.get("trust_domain_resolution", {}))
    precedence = list(resolution.get("field_precedence", ["trust_domain", "provider_family", "provider_camp"]))
    aliases = {
        _zero_trust_normalize(key): _zero_trust_normalize(value)
        for key, value in dict(resolution.get("domain_aliases", {})).items()
    }
    observed: list[dict[str, str]] = []
    for field in precedence:
        raw = entry.get(field)
        if raw is None:
            continue
        normalized = _zero_trust_normalize(raw)
        if not normalized:
            continue
        observed.append({"field": str(field), "value": aliases.get(normalized, normalized)})
    unknown = str(resolution.get("unknown_domain", "unknown"))
    if len({item["value"] for item in observed}) > 1:
        return {
            "trust_domain": unknown,
            "source_field": "conflict",
            "conflicting_domain_fields": observed,
            "unknown": True,
        }
    if observed and observed[0]["field"] == "trust_domain" and len(observed) == 1:
        return {
            "trust_domain": unknown,
            "source_field": "trust_domain-unbound",
            "conflicting_domain_fields": [],
            "unknown": True,
        }
    selected = observed[0] if observed else {"field": "none", "value": unknown}
    conflicts = [
        item for item in observed[1:] if item["value"] != selected["value"]
    ]
    return {
        "trust_domain": selected["value"],
        "source_field": selected["field"],
        "conflicting_domain_fields": conflicts,
        "unknown": selected["value"] == unknown,
    }


def _zero_trust_normalize_claims(
    entry: dict[str, Any],
    *,
    lane: str,
    trust_domain: str,
    policy: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[str]]:
    allowed_types = {str(item) for item in policy.get("claim_types", ["security_assertion"])}
    allowed_categories = set(policy.get("claim_categories", {}).keys())
    claims: list[dict[str, Any]] = []
    warnings: list[str] = []
    for index, raw_claim in enumerate(entry.get("zero_trust_claims") or [], start=1):
        if not isinstance(raw_claim, dict):
            warnings.append(f"{lane}: claim {index} is not an object")
            continue
        category = _zero_trust_normalize(raw_claim.get("category"))
        key = _zero_trust_normalize(raw_claim.get("key"))
        value = str(raw_claim.get("value", "")).strip()
        if not category or not key or not value:
            warnings.append(f"{lane}: claim {index} missing category, key, or value")
            continue
        if allowed_categories and category not in allowed_categories:
            warnings.append(f"{lane}: claim {index} unknown category {category!r}")
            continue
        claim_type = _zero_trust_normalize(raw_claim.get("claim_type") or "security_assertion")
        if claim_type not in allowed_types:
            warnings.append(f"{lane}: claim {index} unknown claim_type {claim_type!r}")
            continue
        claim_id = _zero_trust_normalize(raw_claim.get("claim_id")) or f"{category}:{key}"
        claims.append(
            {
                "claim_id": claim_id,
                "category": category,
                "key": key,
                "value": value,
                "normalized_value": _zero_trust_normalize_claim_value(value, category=category),
                "claim_type": claim_type,
                "evidence": str(raw_claim.get("evidence", "")).strip(),
                "lane": lane,
                "trust_domain": trust_domain,
            }
        )
    return claims, warnings


def _zero_trust_weakness_findings(
    claims: list[dict[str, Any]],
    *,
    policy: dict[str, Any],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for pattern in policy.get("weakness_patterns", []):
        if not isinstance(pattern, dict):
            continue
        terms = [_zero_trust_normalize(term) for term in pattern.get("terms", [])]
        if not terms:
            continue
        for claim in claims:
            haystack = _zero_trust_normalize(" ".join([claim["value"], claim.get("evidence", "")]))
            hits = [term for term in terms if term and term in haystack]
            if hits:
                findings.append(
                    {
                        "id": pattern.get("id"),
                        "name": pattern.get("name"),
                        "category": pattern.get("category"),
                        "severity": pattern.get("severity", "informational"),
                        "lane": claim["lane"],
                        "trust_domain": claim["trust_domain"],
                        "claim_id": claim["claim_id"],
                        "matched_terms": hits,
                        "effect": "informational-only",
                    }
                )
    return findings


def evaluate_zero_trust_consensus(
    inputs: list[dict[str, Any]],
    input_summaries: list[dict[str, Any]],
    *,
    required: bool = False,
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    config = policy or zero_trust_consensus_policy()
    defaults = dict(config.get("defaults", {}))
    thresholds = dict(config.get("thresholds", {}))
    category_weights = {
        str(key): int(value.get("weight", value) if isinstance(value, dict) else value)
        for key, value in dict(config.get("claim_categories", {})).items()
    }
    minimum = int(defaults.get("minimum_independent_domains", 2))
    allowed_statuses = {str(item) for item in config.get("status_values", ["informational", "blocked", "divergent"])}
    disclaimer = str(config.get("trust_domain_independence_disclaimer", "Agreement is not verification."))
    resolution_authority = str(config.get("resolution_authority", "architect"))

    trust_domain_summaries: list[dict[str, Any]] = []
    excluded_inputs: list[dict[str, Any]] = []
    eligible_claims: list[dict[str, Any]] = []
    claim_warnings: list[str] = []
    independent_domains: set[str] = set()

    for entry, summary in zip(inputs, input_summaries):
        lane = str(summary.get("lane") or entry.get("lane") or entry.get("id") or "input")
        domain_info = _zero_trust_domain_for_input({**entry, **summary}, config)
        synthesis_use = str(summary.get("synthesis_use") or "unknown")
        included = synthesis_use == "primary" and not domain_info["unknown"]
        trust_domain_summaries.append(
            {
                "lane": lane,
                "trust_domain": domain_info["trust_domain"],
                "source_field": domain_info["source_field"],
                "synthesis_use": synthesis_use,
                "included_for_independence": included,
                "conflicting_domain_fields": domain_info["conflicting_domain_fields"],
            }
        )
        if not included:
            excluded_inputs.append(
                {
                    "lane": lane,
                    "trust_domain": domain_info["trust_domain"],
                    "synthesis_use": synthesis_use,
                    "reason": "only primary synthesis inputs with known trust domains count",
                }
            )
            continue
        independent_domains.add(domain_info["trust_domain"])
        claims, warnings = _zero_trust_normalize_claims(
            entry,
            lane=lane,
            trust_domain=domain_info["trust_domain"],
            policy=config,
        )
        eligible_claims.extend(claims)
        claim_warnings.extend(warnings)

    by_claim: dict[str, list[dict[str, Any]]] = {}
    for claim in eligible_claims:
        by_claim.setdefault(str(claim["claim_id"]), []).append(claim)

    divergence_report: list[dict[str, Any]] = []
    divergence_score = 0
    comparable_claim_count = 0
    for claim_id, claims in sorted(by_claim.items()):
        domains = {claim["trust_domain"] for claim in claims}
        if len(domains) < 2:
            continue
        comparable_claim_count += 1
        values = {}
        for claim in claims:
            values.setdefault(claim["normalized_value"], []).append(claim)
        if len(values) < 2:
            continue
        sample = claims[0]
        weight = int(category_weights.get(sample["category"], 10))
        score = weight * max(1, len(domains) - 1)
        divergence_score += score
        divergence_report.append(
            {
                "claim_id": claim_id,
                "category": sample["category"],
                "key": sample["key"],
                "claim_type": sample["claim_type"],
                "score": score,
                "resolution_authority": resolution_authority,
                "values": [
                    {
                        "value": grouped[0]["value"],
                        "trust_domains": sorted({item["trust_domain"] for item in grouped}),
                        "lanes": sorted({item["lane"] for item in grouped}),
                        "evidence": [item["evidence"] for item in grouped if item.get("evidence")],
                    }
                    for grouped in values.values()
                ],
            }
        )

    weakness_findings = _zero_trust_weakness_findings(eligible_claims, policy=config)
    blocked_reasons: list[str] = []
    if required and len(independent_domains) < minimum:
        blocked_reasons.append(
            f"zero-trust consensus requires {minimum} independent trust domains; observed {len(independent_domains)}"
        )
    if required and not eligible_claims:
        blocked_reasons.append("zero-trust consensus requires explicit zero_trust_claims on accepted primary inputs")
    elif required and comparable_claim_count == 0:
        blocked_reasons.append("zero-trust consensus requires comparable claims across independent trust domains")
    recommended_action = "none"
    if divergence_score >= int(thresholds.get("quarantine", 70)):
        recommended_action = "quarantine"
    elif divergence_score >= int(thresholds.get("escalation", 40)):
        recommended_action = "escalate"
    elif divergence_score >= int(thresholds.get("review", 20)):
        recommended_action = "review"

    if blocked_reasons:
        status = "blocked"
        recommended_action = "block"
    elif divergence_report:
        status = "divergent"
    else:
        status = "informational"
    if status not in allowed_statuses:
        status = "blocked"
        blocked_reasons.append("zero-trust policy produced disallowed status")

    return {
        "required": bool(required),
        "policy_version": config.get("version"),
        "policy_sha256": zero_trust_policy_sha256(config),
        "minimum_independent_domains": minimum,
        "independent_trust_domain_count": len(independent_domains),
        "independent_trust_domains": sorted(independent_domains),
        "trust_domain_summaries": trust_domain_summaries,
        "excluded_input_count": len(excluded_inputs),
        "excluded_inputs": excluded_inputs,
        "claim_count": len(eligible_claims),
        "comparable_claim_count": comparable_claim_count,
        "claim_warnings": claim_warnings,
        "divergence_score": divergence_score,
        "divergence_report": divergence_report,
        "weakness_pattern_findings": weakness_findings,
        "weakness_pattern_source_version": config.get("weakness_pattern_source_version"),
        "consensus_status": status,
        "recommended_action": recommended_action,
        "blocked_reasons": blocked_reasons,
        "trust_domain_independence_disclaimer": disclaimer,
        "resolution_authority": resolution_authority,
        "agreement_is_not_validation": True,
    }


def recommend_model_synthesis(
    text: str,
    route: dict[str, Any],
    *,
    force_requested: bool = False,
    force_accepted: bool = False,
    disabled: bool = False,
) -> dict[str, Any]:
    policy = synthesis_policy()
    explicit_hits = term_hits(text, list(policy.get("explicit_terms", [])))
    creativity_hits = term_hits(text, list(policy.get("creativity_terms", [])))
    camps = sorted(set(mentioned_provider_camps(text, policy)) | set(route_provider_camps(route)))
    trigger_reasons: list[str] = []

    if force_accepted:
        trigger_reasons.append("operator accepted model synthesis")
    elif force_requested:
        trigger_reasons.append("operator explicitly enabled model synthesis")
    if explicit_hits:
        trigger_reasons.append("explicit synthesis language: " + ", ".join(explicit_hits[:5]))
    if route.get("provider_conflict_detected"):
        domains = route.get("provider_conflict_domains") or ["provider conflict"]
        trigger_reasons.append("provider conflict domain: " + ", ".join(str(item) for item in domains))
    if creativity_hits:
        trigger_reasons.append("creative or novel design signal: " + ", ".join(creativity_hits[:5]))

    risk = str(route.get("risk_level") or "low")
    has_architecture = _route_has_architecture_signal(text, route, policy)
    if risk in {"high", "critical"} and has_architecture:
        trigger_reasons.append(f"{risk}-risk architecture work")
    if len(camps) >= 2:
        trigger_reasons.append("multiple model camps mentioned: " + ", ".join(camps))

    if disabled:
        mode = "disabled"
    elif force_accepted:
        mode = "accepted"
    elif force_requested or explicit_hits:
        mode = "requested"
    elif trigger_reasons and (
        route.get("provider_conflict_detected")
        or risk in {"high", "critical"}
        or creativity_hits
        or len(camps) >= 2
    ):
        mode = "recommended"
    else:
        mode = "none"

    panel = synthesis_panel_for_route(policy, route)
    external_panel = any(bool(item.get("external")) for item in panel)
    active_modes = active_synthesis_modes(policy)
    active = mode in active_modes
    share_boundary = str(route.get("share_boundary") or "no-outside-sharing")
    required_share_boundary = (
        share_boundary
        if route.get("external_opt_in") and share_boundary != "no-outside-sharing"
        else str(policy.get("default_share_boundary", "redacted-packet"))
    )
    rationale: list[str] = []
    if mode == "accepted":
        rationale.append("The operator accepted the coach recommendation or enabled synthesis for this scaffold.")
    elif mode == "requested":
        rationale.append("The request explicitly asks models to synthesize, fuse, or work together.")
    elif mode == "recommended":
        rationale.append("The coach should offer synthesis as an opt-in choice for this risk/creativity profile.")
    elif mode == "disabled":
        rationale.append("Synthesis was explicitly disabled; keep independent evidence lanes and normal adjudication.")
    else:
        rationale.append("No conservative synthesis trigger matched.")
    if external_panel:
        rationale.append("External panel members still require explicit opt-in and the selected share boundary.")
    rationale.append("Synthesis preserves independent evidence and does not replace architect adjudication.")
    conflict_flags = provider_conflict_flags(route, camps)

    return {
        "recommended_mode": mode,
        "activation_state": mode,
        "active": active,
        "active_modes": sorted(active_modes),
        "requires_user_acceptance": mode == "recommended",
        "prompt_user_in_plan_mode": mode == "recommended",
        "synthesis_pattern": str(policy.get("default_pattern", "independent-then-synthesize")),
        "synthesis_owner": synthesis_owner_for_route(policy, route),
        "trigger_reasons": trigger_reasons if mode not in {"none", "disabled"} else [],
        "recommended_panel": panel if mode not in {"none", "disabled"} else [],
        "mentioned_provider_camps": camps if mode not in {"none", "disabled"} else [],
        "required_share_boundary": required_share_boundary if mode not in {"none", "disabled"} else None,
        "external_reviewers_require_opt_in": bool(external_panel and mode not in {"none", "disabled"}),
        "artifact_contract": list(policy.get("artifact_contract", [])) if mode not in {"none", "disabled"} else [],
        "input_disposition_policy": dict(policy.get("input_disposition_policy", {})),
        "partial_synthesis_policy": dict(policy.get("partial_synthesis_policy", {})),
        "provider_conflict_policy": dict(policy.get("provider_conflict_policy", {})),
        "provider_conflict_flags": conflict_flags if mode not in {"none", "disabled"} else [],
        "rationale": rationale,
    }


def synthesis_lane_enabled(model_synthesis: dict[str, Any] | None) -> bool:
    if not isinstance(model_synthesis, dict):
        return False
    if "active" in model_synthesis:
        return bool(model_synthesis.get("active"))
    mode = str(model_synthesis.get("recommended_mode") or "none")
    active_modes = {str(item) for item in model_synthesis.get("active_modes", ["requested", "accepted"])}
    return mode in active_modes
