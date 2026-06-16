from __future__ import annotations

from typing import Any

from .policy import load_policy
from .util import term_hits


def synthesis_policy() -> dict[str, Any]:
    return load_policy("synthesis-policy")


def mentioned_provider_camps(text: str, policy: dict[str, Any] | None = None) -> list[str]:
    config = policy or synthesis_policy()
    camps = config.get("provider_camps", {})
    mentioned: list[str] = []
    for camp, details in camps.items():
        if term_hits(text, list(details.get("terms", []))):
            mentioned.append(str(camp))
    return sorted(set(mentioned))


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


def evaluate_synthesis_inputs(
    inputs: list[dict[str, Any]],
    policy: dict[str, Any] | None = None,
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
    partial_inputs: list[dict[str, Any]] = []
    open_risk_inputs: list[dict[str, Any]] = []
    quarantined_inputs: list[dict[str, Any]] = []
    rejected_inputs: list[dict[str, Any]] = []
    unknown_inputs: list[dict[str, Any]] = []
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

        if effective_disposition in use_as_input:
            synthesis_use = "primary"
        elif effective_disposition in partial_only:
            synthesis_use = "partial-only"
        elif effective_disposition in quarantine:
            synthesis_use = "quarantine"
        elif effective_disposition in rejected:
            synthesis_use = "reject"
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
            "external": external,
            "reason": entry.get("reason"),
        }
        input_summaries.append(summary)
        if external:
            external_inputs.append(summary)
        if synthesis_use == "primary":
            primary_inputs.append(summary)
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
    if external_inputs and all(item["effective_disposition"] in quarantine for item in external_inputs):
        blocked_reasons.append("all external inputs are quarantined or boundary-tainted")
    if unknown_inputs:
        blocked_reasons.append("one or more inputs have unknown evaluator dispositions")

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
        "partial_input_count": len(partial_inputs),
        "open_risk_input_count": len(open_risk_inputs),
        "quarantined_input_count": len(quarantined_inputs),
        "rejected_input_count": len(rejected_inputs),
        "unknown_input_count": len(unknown_inputs),
        "input_summaries": input_summaries,
        "primary_inputs": primary_inputs,
        "partial_inputs": partial_inputs,
        "open_risk_inputs": open_risk_inputs,
        "quarantined_inputs": quarantined_inputs,
        "rejected_inputs": rejected_inputs,
        "unknown_inputs": unknown_inputs,
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
    camps = mentioned_provider_camps(text, policy)
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

    panel = [dict(item) for item in policy.get("default_panel", [])]
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
        "synthesis_owner": str(policy.get("synthesis_owner", "frontier_architect")),
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
