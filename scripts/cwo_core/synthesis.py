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


def recommend_model_synthesis(
    text: str,
    route: dict[str, Any],
    *,
    force_requested: bool = False,
) -> dict[str, Any]:
    policy = synthesis_policy()
    explicit_hits = term_hits(text, list(policy.get("explicit_terms", [])))
    creativity_hits = term_hits(text, list(policy.get("creativity_terms", [])))
    camps = mentioned_provider_camps(text, policy)
    trigger_reasons: list[str] = []

    if force_requested:
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

    if force_requested or explicit_hits:
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
    share_boundary = str(route.get("share_boundary") or "no-outside-sharing")
    required_share_boundary = (
        share_boundary
        if route.get("external_opt_in") and share_boundary != "no-outside-sharing"
        else str(policy.get("default_share_boundary", "redacted-packet"))
    )
    rationale: list[str] = []
    if mode == "requested":
        rationale.append("The request explicitly asks models to synthesize, fuse, or work together.")
    elif mode == "recommended":
        rationale.append("The coach should offer synthesis as an opt-in choice for this risk/creativity profile.")
    else:
        rationale.append("No conservative synthesis trigger matched.")
    if external_panel:
        rationale.append("External panel members still require explicit opt-in and the selected share boundary.")
    rationale.append("Synthesis preserves independent evidence and does not replace architect adjudication.")

    return {
        "recommended_mode": mode,
        "prompt_user_in_plan_mode": mode == "recommended",
        "synthesis_pattern": str(policy.get("default_pattern", "independent-then-synthesize")),
        "synthesis_owner": str(policy.get("synthesis_owner", "frontier_architect")),
        "trigger_reasons": trigger_reasons if mode != "none" else [],
        "recommended_panel": panel if mode != "none" else [],
        "mentioned_provider_camps": camps if mode != "none" else [],
        "required_share_boundary": required_share_boundary if mode != "none" else None,
        "external_reviewers_require_opt_in": bool(external_panel and mode != "none"),
        "artifact_contract": list(policy.get("artifact_contract", [])) if mode != "none" else [],
        "rationale": rationale,
    }


def synthesis_lane_enabled(model_synthesis: dict[str, Any] | None) -> bool:
    if not isinstance(model_synthesis, dict):
        return False
    return model_synthesis.get("recommended_mode") == "requested"
