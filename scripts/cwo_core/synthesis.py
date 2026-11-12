from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .adjudication import (
    AUTHORITY_ENFORCEMENT,
    RESTRICTIVE_DECISIONS,
    Binding,
    Clearance,
    Resolution,
    bind_inputs,
    hold_clearance,
    load_registries,
    resolve_adjudication,
)
from .policy import load_policy
from .synthesis_inputs import (
    UNRESOLVED,
    Claim,
    ConsensusLane,
    ConsensusPolicy,
    SynthesisInput,
    SynthesisPolicy,
    call_view,
    consensus_lanes_from_summaries,
    consensus_policy_view,
    policy_sha256,
    synthesis_policy_view,
    zero_trust_normalize,
)
from .util import provider_term_intent, term_hits, term_intent


def synthesis_policy() -> dict[str, Any]:
    return load_policy("synthesis-policy")


def zero_trust_consensus_policy() -> dict[str, Any]:
    return load_policy("zero-trust-consensus-policy")


def zero_trust_policy_sha256(policy: dict[str, Any] | None = None) -> str:
    return policy_sha256(policy or zero_trust_consensus_policy())


def mentioned_provider_camps(text: str, policy: dict[str, Any] | None = None) -> list[str]:
    config = policy or synthesis_policy()
    camps = config.get("provider_camps", {})
    mentioned: list[str] = []
    for camp, details in camps.items():
        affirmative, excluded = provider_term_intent(text, list(details.get("terms", [])))
        if affirmative and not excluded:
            mentioned.append(str(camp))
    return sorted(set(mentioned))


def excluded_provider_camps(text: str, policy: dict[str, Any] | None = None) -> list[str]:
    config = policy or synthesis_policy()
    camps = config.get("provider_camps", {})
    excluded_camps: list[str] = []
    for camp, details in camps.items():
        _, excluded = provider_term_intent(text, list(details.get("terms", [])))
        if excluded:
            excluded_camps.append(str(camp))
    return sorted(set(excluded_camps))


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


def model_synthesis_intent(
    text: str,
    policy: dict[str, Any] | None = None,
) -> tuple[bool, bool]:
    """Return affirmative/prohibited model-synthesis intent."""

    config = policy or synthesis_policy()
    return term_intent(text, list(config.get("explicit_terms", [])))


def model_synthesis_intent_conflicts(
    text: str,
    *,
    force_requested: bool = False,
    force_accepted: bool = False,
    disabled: bool = False,
    policy: dict[str, Any] | None = None,
) -> list[str]:
    """Return fail-closed conflicts between synthesis requests and prohibitions."""

    affirmative, prohibited = model_synthesis_intent(text, policy)
    if prohibited and not disabled and (affirmative or force_requested or force_accepted):
        return [
            "conflicting model synthesis intent: synthesis is both requested and prohibited"
        ]
    return []


def route_provider_camps(route: dict[str, Any]) -> list[str]:
    camps: set[str] = set()
    architecture_authority = str(route.get("architecture_authority") or "")
    if architecture_authority == "glm-5.2-primary-architect":
        camps.update({"local", "codex"})
    for contract in route.get("architecture_critic_contracts", []):
        if isinstance(contract, dict):
            camps.add(_contract_provider_camp(contract))
    return sorted(camps)


def synthesis_owner_for_route(policy: dict[str, Any], route: dict[str, Any]) -> str:
    if route.get("architecture_authority") == "glm-5.2-primary-architect" and route.get("primary_architect_executor"):
        return str(route["primary_architect_executor"])
    return str(policy.get("synthesis_owner", "frontier_architect"))


def _contract_provider_camp(contract: dict[str, Any]) -> str:
    provider = " ".join(
        str(contract.get(field) or "")
        for field in ("provider_family", "provider_key", "executor")
    ).lower()
    if "anthropic" in provider or "claude" in provider:
        return "anthropic"
    if "google" in provider or "gemini" in provider or "agy" in provider:
        return "google"
    if "local" in provider or "rhoai" in provider or "glm" in provider or "vllm" in provider:
        return "local"
    if "openai" in provider or "chatgpt" in provider:
        return "openai"
    return "codex"


def _contract_panel_entry(
    contract: dict[str, Any],
    default_panel: list[dict[str, Any]],
) -> dict[str, Any]:
    executor = str(contract.get("executor") or "")
    provider_camp = _contract_provider_camp(contract)
    selected = contract.get("selected_executor")
    selected_executor = selected if isinstance(selected, dict) else {}
    transport = selected_executor.get("transport")
    transport_config = transport if isinstance(transport, dict) else {}
    template = next(
        (
            item
            for item in default_panel
            if item.get("executor") == executor
            or (
                item.get("role") == "architecture-critic"
                and item.get("provider_camp") == provider_camp
            )
        ),
        {},
    )
    if contract.get("claude_effort"):
        effort = str(contract["claude_effort"])
    elif transport_config.get("thinking_required"):
        effort = "thinking-enabled"
    else:
        effort = str(template.get("effort") or "configured")
    entry = {
        "executor": executor,
        "role": "architecture-critic",
        "provider_camp": provider_camp,
        "effort": effort,
        "external": bool(selected_executor.get("external")),
    }
    if template.get("synthesis_use"):
        entry["synthesis_use"] = template["synthesis_use"]
    return entry


def synthesis_panel_for_route(
    policy: dict[str, Any],
    route: dict[str, Any],
    *,
    text: str = "",
) -> list[dict[str, Any]]:
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
                "effort": "codex-5.6-sol",
                "external": False,
            },
        ]
    default_panel = [dict(item) for item in policy.get("default_panel", [])]
    excluded_camps = set(excluded_provider_camps(text, policy))
    contracts = [
        contract
        for contract in route.get("architecture_critic_contracts", [])
        if isinstance(contract, dict)
    ]
    if contracts:
        owner = synthesis_owner_for_route(policy, route)
        owner_entry = next(
            (dict(item) for item in default_panel if item.get("executor") == owner),
            {
                "executor": owner,
                "role": "synthesis-owner",
                "provider_camp": "codex",
                "effort": "configured",
                "external": False,
            },
        )
        panel = [owner_entry]
        panel.extend(
            _contract_panel_entry(contract, default_panel)
            for contract in contracts
            if _contract_provider_camp(contract) not in excluded_camps
        )
        if "openai" in mentioned_provider_camps(text, policy):
            master_review = next(
                (
                    dict(item)
                    for item in default_panel
                    if item.get("role") == "master-plan-review"
                ),
                None,
            )
            if master_review:
                panel.append(master_review)
        return panel
    return [
        item
        for item in default_panel
        if item.get("role") in {"synthesis-owner", "primary-architect"}
        or str(item.get("provider_camp") or "") not in excluded_camps
    ]


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


# ---------------------------------------------------------------------------
# Synthesis input evaluation. Every raw input, record and argument is parsed
# once by cwo_core.synthesis_inputs; the code below reads only parsed forms.
# An UNRESOLVED field maps to the most restrictive outcome any well-formed
# value of it could produce, in every context.


_FINAL_USES = frozenset({"primary", "salvage-only", "partial-only", "open-risk", "quarantine", "reject"})


@dataclass(frozen=True)
class _Lane:
    item: SynthesisInput
    binding: Binding
    resolution: Resolution
    clearance: Clearance
    synthesis_use: str
    effective_disposition: str
    requested_use: str | None
    use_hold_resolved_by: str | None
    primary_use_withheld: str | None
    quarantine_sources: tuple[str, ...]
    overridden_restrictions: tuple[str, ...]
    unresolved_primary_request: bool
    # Why the lane's use or inclusion is unresolved (empty when every field
    # that decides it is resolved). A lane with unresolved data that carries
    # zero-trust claims keeps them as unresolved claims when it is excluded.
    unresolved_data: tuple[str, ...]

    @property
    def quarantine_in_force(self) -> bool:
        return bool(self.quarantine_sources)


def _decide_lane(item: SynthesisInput, binding: Binding, resolution: Resolution, config: SynthesisPolicy) -> _Lane:
    clearance = hold_clearance(item, resolution, config)
    decision = resolution.decision if resolution.applied else None
    # A failed, invalid or ambiguous resolution never discards a refusal:
    # refusals in records that are not provably history stay in force.
    pending = resolution.pending_restrictions
    authorized = clearance.authorized
    effective = "boundary-tainted" if item.boundary_status == "boundary-tainted" else item.disposition
    local_v2_unusable = item.local_v2.unresolved or (item.local_v2.valid and item.local_v2.value is False)
    if item.local_v2_marker_unresolved or local_v2_unusable:
        effective = "quarantined"
    explicit = item.explicit_use.value if item.explicit_use.valid else None
    recommended = item.recommended_use.value if item.recommended_use.valid else None
    requested = explicit or recommended
    # The salvage-only provider rule applies when any caller provider label
    # or the dispatch-derived family names a salvage-only provider; a label
    # can add the restriction but never remove it.
    derived_family = binding.provider_family if binding.provenance_known else None
    salvage_provider = bool(item.provider_labels & config.salvage_only_camps) or derived_family in config.salvage_only_camps
    use_hold_resolved_by = None

    if not item.is_object:
        use = "reject"
    elif decision == "rejected":
        # A bound rejection resolves this return's use-hold without accepting
        # its advice; the return is excluded from use.
        use = "reject"
        if item.held or effective in config.quarantine:
            use_hold_resolved_by = resolution.adjudication_id
    elif effective in config.quarantine or decision == "quarantined":
        use = "quarantine"
    elif effective in config.rejected:
        use = "reject"
    elif item.held and not authorized:
        use = "open-risk"
    elif "quarantined" in pending:
        # An unresolved refusal stays in force. It does not resolve a hold (a
        # held return stays open-risk above); it keeps an otherwise usable
        # return out of use.
        use = "quarantine"
    elif "rejected" in pending:
        use = "reject"
    elif requested == "primary" and not authorized:
        use = "salvage-only" if salvage_provider else "unknown"
    elif requested:
        use = requested
    elif effective in config.salvage_only:
        use = "salvage-only"
    elif salvage_provider and effective in config.use_as_input:
        use = "salvage-only"
    elif effective in config.use_as_input:
        use = "primary"
    elif effective in config.partial_only:
        use = "partial-only"
    elif effective in config.open_risk:
        use = "open-risk"
    else:
        use = "unknown"

    disposition_unresolved = item.disposition_state == UNRESOLVED
    # A requested primary use that no applied adjudication decides is
    # unresolved ("unknown") whatever else sets the final use: a hold, a
    # quarantine or a rejection does not resolve the request.
    unresolved_primary_request = (
        item.is_object
        and requested == "primary"
        and not authorized
        and not salvage_provider
        and decision not in RESTRICTIVE_DECISIONS
        and use != "unknown"
    )
    primary_use_withheld = None
    if use == "primary":
        if item.use_unresolved:
            use, primary_use_withheld = "unknown", "invalid synthesis_use or recommended_synthesis_use"
        elif recommended == "quarantine":
            # An explicit use, even one an adjudication authorizes, does not
            # clear a recommended quarantine.
            use, primary_use_withheld = "quarantine", "recommended_synthesis_use is quarantine"
        elif disposition_unresolved and not item.disposition_missing:
            # An adjudication can promote a recognized evaluation; it does not
            # turn an unreadable one into a primary input. (A missing
            # disposition reads as "missing", withheld below.)
            use, primary_use_withheld = "unknown", "unrecognized evaluator disposition"
        elif item.disposition in config.partial_only or item.disposition in config.open_risk:
            # Nor does it turn a missing, empty, timed-out or deferred
            # evaluation into a primary input.
            use = "partial-only" if item.disposition in config.partial_only else "open-risk"
            primary_use_withheld = "evaluator disposition cannot be promoted to primary"
        elif binding.state == "failed":
            # A binding was attempted and failed or is ambiguous. That is not
            # the absence of a binding, so legacy treatment does not apply.
            use, primary_use_withheld = "open-risk", "dispatch binding was attempted and failed or is ambiguous"
        elif resolution.unresolved:
            use, primary_use_withheld = "open-risk", f"adjudication resolution is {resolution.state}"
        elif binding.provenance_unresolved:
            # The registry identity and the record's labels disagree, or the
            # executor is unknown: adjudication cannot settle identity.
            use, primary_use_withheld = "salvage-only", "dispatch provenance is unknown or conflicting"
        elif item.provider_labels_unresolved:
            use, primary_use_withheld = "salvage-only", "malformed provider label"

    # A quarantine is in force when the evaluator or the boundary set it, when
    # a bound adjudication applied it, when a quarantining record is still
    # pending, when the final, requested or recommended use is quarantine, or
    # when a use field or the disposition is unresolved or the input is not an
    # object, and so may be read as quarantine. The external-input block reads
    # this, and any quarantine in force keeps the result from being ready.
    quarantine_sources = tuple(
        source
        for source, active in (
            ("evaluator disposition or boundary status", effective in config.quarantine),
            ("applied adjudication", decision == "quarantined"),
            ("pending adjudication record", "quarantined" in pending),
            ("final synthesis use", use == "quarantine"),
            ("synthesis_use", explicit == "quarantine"),
            ("recommended_synthesis_use", recommended == "quarantine"),
            ("malformed use field", item.use_unresolved),
            ("unresolved evaluator disposition", item.is_object and disposition_unresolved),
            ("input is not an object", not item.is_object),
        )
        if active
    )
    # A use field may lower an input to salvage-only, but it does not clear an
    # open-risk or partial-only evaluation, a more restrictive recommendation,
    # an unresolved adjudication, or an unreadable evaluation or use field.
    overridden: list[str] = []
    if use == "salvage-only":
        if effective in config.partial_only or effective in config.open_risk:
            overridden.append(f"evaluator disposition {effective}")
        if explicit is not None and recommended in {"partial-only", "open-risk", "reject"}:
            overridden.append(f"recommended_synthesis_use {recommended}")
        if resolution.unresolved:
            overridden.append(f"adjudication resolution is {resolution.state}")
        if item.is_object and disposition_unresolved:
            overridden.append("evaluator disposition is unresolved")
        if item.use_unresolved:
            overridden.append("a use field is malformed")
    unresolved_data = list(item.errors)
    if binding.state == "failed":
        unresolved_data.append("dispatch binding was attempted and failed or is ambiguous")
    if binding.provenance_unresolved:
        unresolved_data.append("dispatch provenance is unknown or conflicting")
    if resolution.unresolved or resolution.state == "unbound":
        unresolved_data.append(f"adjudication resolution is {resolution.state}")
    return _Lane(
        item=item,
        binding=binding,
        resolution=resolution,
        clearance=clearance,
        synthesis_use=use,
        effective_disposition=effective,
        requested_use=requested,
        use_hold_resolved_by=use_hold_resolved_by,
        primary_use_withheld=primary_use_withheld,
        quarantine_sources=quarantine_sources,
        overridden_restrictions=tuple(overridden),
        unresolved_primary_request=unresolved_primary_request,
        unresolved_data=tuple(unresolved_data),
    )


def _lane_summary(lane: _Lane) -> dict[str, Any]:
    item = lane.item
    local_v2_unusable = item.local_v2.unresolved or (item.local_v2.valid and item.local_v2.value is False)
    return {
        "lane": item.lane,
        "provider_camp": item.reported_provider_camp,
        "disposition": item.disposition,
        "effective_disposition": lane.effective_disposition,
        "boundary_status": item.boundary_status,
        "synthesis_use": lane.synthesis_use,
        "requested_synthesis_use": lane.requested_use,
        "recommended_synthesis_use": item.recommended_use.value if item.recommended_use.valid else None,
        "evidence_quality_score": item.reported_evidence_quality_score,
        "external": not (item.external.valid and item.external.value is False),
        "reason": "unusable GLM critic v2 dispatch evidence" if local_v2_unusable else item.reported_reason,
        "implementation_blocked": item.held,
        "hold_flag_malformed": item.hold_flag_unresolved,
        "hold_reasons_malformed": item.hold_reasons_unresolved,
        "hold_classification": item.hold_classification,
        "hold_reasons": list(item.hold_reasons),
        "dispatch_binding": lane.binding.as_dict(),
        "adjudication": {
            **lane.resolution.as_dict(),
            "authorizes_requested_use": lane.clearance.authorized,
            "uncleared_hold_reasons": list(lane.clearance.uncleared_hold_reasons),
            "not_authorized_reason": None if lane.clearance.authorized else lane.clearance.reason,
        },
        "use_hold_resolved_by": lane.use_hold_resolved_by,
        "pending_restrictions": list(lane.resolution.pending_restrictions),
        "quarantine_in_force": lane.quarantine_in_force,
        "quarantine_sources": list(lane.quarantine_sources),
        "overridden_restrictions": list(lane.overridden_restrictions),
        "adjudication_unresolved": lane.resolution.unresolved,
        "primary_use_withheld": lane.primary_use_withheld,
        "unresolved_data": list(lane.unresolved_data),
        "input_errors": list(item.errors),
        "ignored_authority_claims": list(item.ignored_authority_claims),
    }


def evaluate_synthesis_inputs(
    inputs: list[dict[str, Any]],
    policy: dict[str, Any] | None = None,
    *,
    zero_trust_required: bool = False,
    dispatch_records: list[dict[str, Any]] | None = None,
    adjudications: list[dict[str, Any]] | None = None,
    candidate: str | None = None,
    scope: str | None = None,
) -> dict[str, Any]:
    """Apply synthesis disposition policy to independently evaluated model returns.

    Every argument is parsed once by ``cwo_core.synthesis_inputs``; nothing
    below reads a raw record. Provider identity for independence counting and
    the salvage-only provider rule comes from each return's bound dispatch
    record (see ``cwo_core.adjudication``). Primary use of a
    recommended-primary return and clearing of an adjudication hold need an
    adjudication record bound to the same dispatch, return digest, exact
    ``candidate`` and ``scope``; role labels on the input are reported and
    ignored.
    """

    config = synthesis_policy_view(policy or synthesis_policy())
    consensus_config = consensus_policy_view(zero_trust_consensus_policy())
    call = call_view(
        inputs,
        dispatch_records=dispatch_records,
        adjudications=adjudications,
        candidate=candidate,
        scope=scope,
        zero_trust_required=zero_trust_required,
        policy=config,
        consensus_policy=consensus_config,
    )
    bindings = bind_inputs(call, load_registries())
    claimed = frozenset(item.dispatch_id.value for item in call.inputs if item.dispatch_id.valid)
    lanes = tuple(
        _decide_lane(item, binding, resolve_adjudication(item, binding, call, claimed_dispatch_ids=claimed), config)
        for item, binding in zip(call.inputs, bindings)
    )

    adjudication_errors: list[str] = []
    unattributable_restrictions: list[int] = []
    unattributable_records: list[int] = []
    if call.adjudications.unresolved:
        adjudication_errors.append("adjudications must be a list")
    for record in call.adjudication_items:
        if record.dispatch_id.unresolved:
            if record.decision.valid and record.decision.value in RESTRICTIVE_DECISIONS:
                unattributable_restrictions.append(record.position)
            else:
                # Not an object, or no readable dispatch_id, and no readable
                # refusal either: what it decides and whom it concerns are unknown.
                unattributable_records.append(record.position)
        if not (record.dispatch_id.valid and record.dispatch_id.value in claimed):
            adjudication_errors.append(
                f"adjudications[{record.position}] does not name the dispatch_id of any input and was not applied"
            )

    summaries = [_lane_summary(lane) for lane in lanes]
    rejections = list(call.record_rejections)
    for lane in lanes:
        if lane.item.errors:
            rejections.append(
                {"source": "inputs", "index": lane.item.position, "id": lane.item.lane, "errors": list(lane.item.errors)}
            )

    def with_use(*uses: str) -> list[dict[str, Any]]:
        return [summary for lane, summary in zip(lanes, summaries) if lane.synthesis_use in uses]

    primary_inputs = with_use("primary")
    salvage_inputs = with_use("salvage-only")
    partial_inputs = with_use("partial-only")
    open_risk_inputs = with_use("open-risk")
    quarantined_inputs = with_use("quarantine")
    rejected_inputs = with_use("reject")
    unknown_inputs = [
        summary for lane, summary in zip(lanes, summaries) if lane.synthesis_use not in _FINAL_USES
    ]
    held_inputs = [summary for lane, summary in zip(lanes, summaries) if lane.item.held]
    external_lanes = [lane for lane in lanes if lane.item.external.valid and lane.item.external.value is True]
    ambiguous_external = [lane for lane in lanes if lane.item.external.unresolved]

    minimum_usable_inputs = config.minimum_usable_inputs
    blocked_reasons: list[str] = []
    if len(primary_inputs) < minimum_usable_inputs:
        blocked_reasons.append("fewer than minimum_usable_inputs accepted or accepted-with-modification inputs")
        if salvage_inputs:
            blocked_reasons.append("salvage-only inputs do not satisfy minimum_usable_inputs")
    # A malformed external flag may be read either way; the block applies if it
    # applies under any reading, which means counting the ambiguous inputs that
    # are quarantined and ignoring the ambiguous inputs that are not.
    quarantined_ambiguous = [lane for lane in ambiguous_external if lane.quarantine_in_force]
    if (external_lanes or quarantined_ambiguous) and all(lane.quarantine_in_force for lane in external_lanes):
        blocked_reasons.append("all external inputs are quarantined or boundary-tainted")
    if unknown_inputs or any(lane.item.is_object and lane.item.disposition_state == UNRESOLVED for lane in lanes):
        blocked_reasons.append("one or more inputs have unknown evaluator dispositions")
    if any(lane.unresolved_primary_request for lane in lanes):
        blocked_reasons.append(
            "one or more inputs request primary use that no applied adjudication authorizes, "
            "and a hold or another restriction does not resolve the request"
        )
    if any(not lane.item.is_object for lane in lanes):
        blocked_reasons.append("one or more inputs are not objects, so what they would decide is unresolved")
    if any(lane.item.use_unresolved for lane in lanes):
        blocked_reasons.append("one or more inputs have an invalid synthesis_use or recommended_synthesis_use")
    if unattributable_restrictions:
        blocked_reasons.append(
            "an adjudication record states a restrictive decision but has no readable dispatch_id, "
            "so the input it restricts is unknown"
        )
    if unattributable_records:
        blocked_reasons.append(
            "an adjudication record is not an object or has no readable dispatch_id, so what it decides "
            "and the input it concerns are unresolved"
        )
    if call.adjudications.unresolved:
        blocked_reasons.append("adjudications is not a list, so the records it holds are unresolved")
    blocked_reasons.extend(call.argument_errors)

    consensus = _zero_trust_consensus(
        tuple(
            ConsensusLane(
                lane=lane.item.lane,
                synthesis_use=lane.synthesis_use,
                bound=lane.binding.bound,
                provenance_known=lane.binding.provenance_known,
                provider_family=zero_trust_normalize(lane.binding.provider_family),
                domain_labels=lane.item.domain_labels,
                claims=lane.item.claims,
                unresolved_data=lane.unresolved_data,
            )
            for lane in lanes
        ),
        required=call.zero_trust_required,
        policy=consensus_config,
    )
    if consensus.required:
        if consensus.status == "blocked":
            blocked_reasons.extend(consensus.blocked_reasons)
        elif consensus.recommended_action in {"escalate", "quarantine"}:
            blocked_reasons.append("zero-trust cross-domain divergence requires architect resolution")

    status = "ready"
    if blocked_reasons:
        status = "blocked"
    elif (
        partial_inputs
        or open_risk_inputs
        or rejected_inputs
        or quarantined_inputs
        or unknown_inputs
        or any(lane.quarantine_in_force or lane.overridden_restrictions or lane.resolution.unresolved for lane in lanes)
    ):
        status = config.partial_status if config.allow_partial else "blocked"
        if not config.allow_partial:
            blocked_reasons.append("partial synthesis is disabled by policy")

    return {
        "status": status,
        "blocked": bool(blocked_reasons),
        "blocked_reasons": blocked_reasons,
        "allow_partial": config.allow_partial,
        "minimum_usable_inputs": minimum_usable_inputs,
        "input_count": len(summaries),
        "usable_input_count": len(primary_inputs),
        "primary_input_count": len(primary_inputs),
        "salvage_input_count": len(salvage_inputs),
        "partial_input_count": len(partial_inputs),
        "open_risk_input_count": len(open_risk_inputs),
        "quarantined_input_count": len(quarantined_inputs),
        "rejected_input_count": len(rejected_inputs),
        "unknown_input_count": len(unknown_inputs),
        "held_input_count": len(held_inputs),
        "input_summaries": summaries,
        "primary_inputs": primary_inputs,
        "salvage_inputs": salvage_inputs,
        "partial_inputs": partial_inputs,
        "open_risk_inputs": open_risk_inputs,
        "quarantined_inputs": quarantined_inputs,
        "rejected_inputs": rejected_inputs,
        "unknown_inputs": unknown_inputs,
        "held_inputs": held_inputs,
        "quarantine_in_force_inputs": [lane.item.lane for lane in lanes if lane.quarantine_in_force],
        "candidate": candidate,
        "scope": scope,
        "adjudication_errors": adjudication_errors,
        "record_rejections": rejections,
        "authority_enforcement": AUTHORITY_ENFORCEMENT,
        "trusted_host_authority": False,
        "zero_trust_consensus": consensus.as_dict(),
    }


@dataclass(frozen=True)
class _Domain:
    trust_domain: str
    source_field: str
    conflicting_domain_fields: tuple[tuple[str, str], ...]
    unknown: bool


def _zero_trust_domain(lane: ConsensusLane, policy: ConsensusPolicy) -> _Domain:
    """Resolve a trust domain from the bound dispatch record only.

    Caller labels are compared with the derived family; any disagreement
    excludes the input. An unbound return or unknown provenance has the
    unknown domain.
    """

    unknown = policy.unknown_domain
    if not lane.bound:
        return _Domain(unknown, "unbound", (), True)
    if not lane.provenance_known or not lane.provider_family:
        return _Domain(unknown, "provenance-unknown", (), True)
    derived = policy.alias(lane.provider_family)
    conflicts = tuple((name, value) for name, value in lane.domain_labels if value != derived)
    if conflicts or derived == unknown:
        return _Domain(unknown, "conflict" if conflicts else "provenance-unknown", conflicts, True)
    return _Domain(derived, "dispatch-record", (), False)


@dataclass(frozen=True)
class _PlacedClaim:
    claim: Claim
    lane: str
    trust_domain: str


@dataclass(frozen=True)
class _UnresolvedClaim:
    lane: str
    claim: int | None
    claim_id: str | None
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return {"lane": self.lane, "claim": self.claim, "claim_id": self.claim_id, "reason": self.reason}

    def blocked_reason(self) -> str:
        claim = "" if self.claim is None else f" claim {self.claim}"
        claim_id = "" if self.claim_id is None else f" ({self.claim_id})"
        return f"zero-trust consensus is unresolved: {self.lane}{claim}{claim_id}: {self.reason}"


_unresolved_claim = _UnresolvedClaim


@dataclass(frozen=True)
class _Consensus:
    required: bool
    status: str
    recommended_action: str
    blocked_reasons: tuple[str, ...]
    fields: tuple[tuple[str, Any], ...]

    def as_dict(self) -> dict[str, Any]:
        result = {name: value for name, value in self.fields}
        result.update(
            consensus_status=self.status,
            recommended_action=self.recommended_action,
            blocked_reasons=list(self.blocked_reasons),
        )
        return result


def _zero_trust_consensus(lanes: tuple[ConsensusLane, ...], *, required: bool, policy: ConsensusPolicy) -> _Consensus:
    minimum = policy.minimum_independent_domains
    trust_domain_summaries: list[dict[str, Any]] = []
    excluded_inputs: list[dict[str, Any]] = []
    eligible: list[_PlacedClaim] = []
    claim_warnings: list[str] = []
    unresolved_claims: list[_UnresolvedClaim] = []
    independent_domains: set[str] = set()

    for lane in lanes:
        # Structural summary uncertainty is blocking even when the omitted or
        # mismatched lane happens not to carry readable claims.
        unresolved_claims.extend(_unresolved_claim(lane.lane, None, None, reason)
                                 for reason in lane.summary_errors)
        domain = _zero_trust_domain(lane, policy)
        use = lane.synthesis_use
        included = use == "primary" and not domain.unknown
        conflicts = [{"field": name, "value": value} for name, value in domain.conflicting_domain_fields]
        trust_domain_summaries.append(
            {
                "lane": lane.lane,
                "trust_domain": domain.trust_domain,
                "source_field": domain.source_field,
                "synthesis_use": use,
                "included_for_independence": included,
                "conflicting_domain_fields": conflicts,
            }
        )
        if not included:
            excluded_inputs.append(
                {
                    "lane": lane.lane,
                    "trust_domain": domain.trust_domain,
                    "synthesis_use": use,
                    "reason": "only primary synthesis inputs with a trust domain derived from a bound dispatch record count",
                }
            )
            if lane.claims.carried and use == "primary":
                # A primary input still feeds the synthesis. When its domain is
                # unknown or its labels conflict with the dispatch record, its
                # claims cannot be compared, so any disagreement they carry is
                # unresolved rather than absent.
                unresolved_claims.append(
                    _unresolved_claim(
                        lane.lane,
                        None,
                        None,
                        f"the input is primary but its trust domain is {domain.source_field}, "
                        "so its zero_trust_claims cannot be compared",
                    )
                )
            elif lane.claims.carried and lane.unresolved_data:
                # A lane is excluded from consensus only by a resolved, readable
                # reason. Its use, binding, provenance, eligibility or
                # adjudication is unresolved, and a well-formed value might
                # have made it primary, so its claims are unresolved rather
                # than absent.
                unresolved_claims.append(
                    _unresolved_claim(
                        lane.lane,
                        None,
                        None,
                        f"the input is {use} because of malformed or unresolved data, "
                        "so whether its zero_trust_claims count is unresolved",
                    )
                )
            continue
        independent_domains.add(domain.trust_domain)
        for claim in lane.claims.items:
            if claim.comparable:
                eligible.append(_PlacedClaim(claim, lane.lane, domain.trust_domain))
            else:
                claim_warnings.append(str(claim.warning))
                unresolved_claims.append(
                    _unresolved_claim(lane.lane, claim.index, claim.reported_claim_id, str(claim.reason))
                )

    by_claim: dict[str, list[_PlacedClaim]] = {}
    for placed in eligible:
        if placed.claim.claim_id not in by_claim:
            by_claim[placed.claim.claim_id] = []
        by_claim[placed.claim.claim_id].append(placed)

    divergence_report: list[dict[str, Any]] = []
    divergence_score = 0
    comparable_claim_count = 0
    for claim_id in sorted(by_claim):
        placed_claims = by_claim[claim_id]
        shapes = {(placed.claim.category, placed.claim.key, placed.claim.claim_type) for placed in placed_claims}
        if len(shapes) > 1:
            # Claims under one ID that name different categories, keys or claim
            # types are not the same claim; which one sets the weight must not
            # depend on input order, and the conflict is unresolved.
            unresolved_claims.append(
                _unresolved_claim(
                    ", ".join(sorted({placed.lane for placed in placed_claims})),
                    None,
                    claim_id,
                    "the claims under this claim_id differ in category, key or claim_type",
                )
            )
        domains = {placed.trust_domain for placed in placed_claims}
        if len(domains) < 2:
            continue
        comparable_claim_count += 1
        values: dict[str, list[_PlacedClaim]] = {}
        for placed in placed_claims:
            if placed.claim.normalized_value not in values:
                values[placed.claim.normalized_value] = []
            values[placed.claim.normalized_value].append(placed)
        if len(values) < 2:
            continue
        sample = placed_claims[0].claim
        weight = max(policy.weight(placed.claim.category) for placed in placed_claims)
        score = weight * max(1, len(domains) - 1)
        divergence_score += score
        divergence_report.append(
            {
                "claim_id": claim_id,
                "category": sample.category,
                "key": sample.key,
                "claim_type": sample.claim_type,
                "score": score,
                "resolution_authority": policy.resolution_authority,
                "values": [
                    {
                        "value": grouped[0].claim.value,
                        "trust_domains": sorted({placed.trust_domain for placed in grouped}),
                        "lanes": sorted({placed.lane for placed in grouped}),
                        "evidence": [placed.claim.evidence for placed in grouped if placed.claim.evidence],
                    }
                    for grouped in (values[normalized] for normalized in values)
                ],
            }
        )

    weakness_findings: list[dict[str, Any]] = []
    for pattern in policy.weakness_patterns:
        for placed in eligible:
            haystack = zero_trust_normalize(" ".join([placed.claim.value, placed.claim.evidence]))
            hits = [term for term in pattern.terms if term and term in haystack]
            if hits:
                weakness_findings.append(
                    {
                        "id": pattern.pattern_id,
                        "name": pattern.name,
                        "category": pattern.category,
                        "severity": pattern.severity,
                        "lane": placed.lane,
                        "trust_domain": placed.trust_domain,
                        "claim_id": placed.claim.claim_id,
                        "matched_terms": hits,
                        "effect": "informational-only",
                    }
                )

    blocked_reasons: list[str] = []
    if required and len(independent_domains) < minimum:
        blocked_reasons.append(
            f"zero-trust consensus requires {minimum} independent trust domains; observed {len(independent_domains)}"
        )
    if required and not eligible:
        blocked_reasons.append("zero-trust consensus requires explicit zero_trust_claims on accepted primary inputs")
    elif required and comparable_claim_count == 0:
        blocked_reasons.append("zero-trust consensus requires comparable claims across independent trust domains")
    if required:
        # A claim that could not be compared would have fed the divergence; it
        # leaves the consensus unresolved instead of dropping out of it.
        blocked_reasons.extend(item.blocked_reason() for item in unresolved_claims)
    recommended_action = "none"
    if divergence_score >= policy.quarantine_threshold:
        recommended_action = "quarantine"
    elif divergence_score >= policy.escalation_threshold:
        recommended_action = "escalate"
    elif divergence_score >= policy.review_threshold:
        recommended_action = "review"

    if blocked_reasons:
        status = "blocked"
        recommended_action = "block"
    elif divergence_report:
        status = "divergent"
    else:
        status = "informational"
    if status not in policy.allowed_statuses:
        status = "blocked"
        blocked_reasons.append("zero-trust policy produced disallowed status")

    return _Consensus(
        required=bool(required),
        status=status,
        recommended_action=recommended_action,
        blocked_reasons=tuple(blocked_reasons),
        fields=(
            ("required", bool(required)),
            ("policy_version", policy.version),
            ("policy_sha256", policy.sha256),
            ("minimum_independent_domains", minimum),
            ("independent_trust_domain_count", len(independent_domains)),
            ("independent_trust_domains", sorted(independent_domains)),
            ("trust_domain_summaries", trust_domain_summaries),
            ("excluded_input_count", len(excluded_inputs)),
            ("excluded_inputs", excluded_inputs),
            ("claim_count", len(eligible)),
            ("comparable_claim_count", comparable_claim_count),
            ("claim_warnings", claim_warnings),
            ("unresolved_claims", [item.as_dict() for item in unresolved_claims]),
            ("divergence_score", divergence_score),
            ("divergence_report", divergence_report),
            ("weakness_pattern_findings", weakness_findings),
            ("weakness_pattern_source_version", policy.weakness_pattern_source_version),
            ("consensus_status", None),
            ("recommended_action", None),
            ("blocked_reasons", None),
            ("trust_domain_independence_disclaimer", policy.disclaimer),
            ("resolution_authority", policy.resolution_authority),
            ("agreement_is_not_validation", True),
        ),
    )


def evaluate_zero_trust_consensus(
    inputs: list[dict[str, Any]],
    input_summaries: list[dict[str, Any]],
    *,
    required: bool = False,
    policy: dict[str, Any] | None = None,
    synthesis_policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Zero-trust consensus over caller-supplied inputs and synthesis summaries.

    Both are parsed by ``cwo_core.synthesis_inputs``; a summary that does not
    record whether its data is resolved is read as unresolved. When the producer
    uses a custom synthesis policy, supply that same context as ``synthesis_policy``.
    """

    config = consensus_policy_view(policy or zero_trust_consensus_policy())
    # A value that is not a boolean may mean either, so consensus is required.
    required = required if isinstance(required, bool) else True
    return _zero_trust_consensus(
        consensus_lanes_from_summaries(
            inputs, input_summaries, config,
            synthesis_config=synthesis_policy_view(synthesis_policy or load_policy("synthesis-policy")),
        ), required=required, policy=config
    ).as_dict()


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
    explicit_requested, explicit_prohibited = model_synthesis_intent(text, policy)
    creativity_hits = term_hits(text, list(policy.get("creativity_terms", [])))
    camps = sorted(set(mentioned_provider_camps(text, policy)) | set(route_provider_camps(route)))
    trigger_reasons: list[str] = []

    if force_accepted:
        trigger_reasons.append("operator accepted model synthesis")
    elif force_requested:
        trigger_reasons.append("operator explicitly enabled model synthesis")
    if explicit_requested:
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

    if disabled or explicit_prohibited:
        mode = "disabled"
    elif force_accepted:
        mode = "accepted"
    elif force_requested or explicit_requested:
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

    panel = synthesis_panel_for_route(policy, route, text=text)
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
    if external_panel and mode not in {"none", "disabled"}:
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
