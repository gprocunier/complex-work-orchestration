"""Select Codex effort for existing dispatch roles without granting authority."""
from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Any

from . import return_advisory
from .policy import load_policy
from .risk_features import assess_risk_features, assessed_texts, normalized_tokens
from .routing_signals import architecture_review_complexity
from .util import term_intent


REASONING_EFFORTS = frozenset({"low", "medium", "high", "xhigh"})
EFFORT_REASONS = frozenset({"default", "delivery-failed-at-default-effort", "security-or-containment",
                            "high-risk-review", "wide-architecture-or-planning"})
_SECURITY_FEATURES = frozenset({"asset:credentials", "asset:authentication"})
_CONTROL_SCOPE = [
    "approval controls", "approval flow", "approval policy", "approval boundary",
    "containment controls", "containment policy", "containment boundary", "container isolation",
    "network access", "network controls", "network isolation", "network permissions", "network policy",
    "sandbox boundary", "sandbox configuration", "sandbox controls", "sandbox mode", "sandbox policy",
    "sandbox rules", "security controls", "security review", "security policy", "security vulnerability",
    "threat model", "privilege escalation", "sql injection", "cross site scripting",
]
_UNCHANGED_SCOPE = re.compile(r"\b(?:do not|don't|never)\s+(?:change|modify|touch)\b", re.I)
_PLANNING_SCOPE = frozenset({"architecture", "architect", "plan", "planning"})


@dataclass(frozen=True)
class FailedDelivery:
    dispatch_record_sha256: str
    evaluation_record_sha256: str


def failed_delivery_metadata(failure: FailedDelivery | None) -> dict[str, dict[str, str]]:
    if type(failure) is not FailedDelivery:
        return {}
    return {"codex_retry_evidence": {"dispatch_record_sha256": failure.dispatch_record_sha256,
                                     "evaluation_record_sha256": failure.evaluation_record_sha256}}


def reasoning_effort_selection(role: str, *, risk: str = "medium", security_scope: bool = False,
                               wide_scope: bool = False, failed_delivery: FailedDelivery | None = None,
                               ) -> dict[str, str]:
    """Use the configured escalation for a specific, existing route signal."""
    sol = load_policy("model-roles")["roles"]["sol"]
    default = sol.get("reasoning_effort", "high")
    escalation = sol.get("escalation_reasoning_effort", default)
    reason = "default"
    if role in {"worker", "reviewer", "adjudicator"}:
        reason = _escalation_reason(role, risk, security_scope, wide_scope, failed_delivery)
    return {"reasoning_effort": default if reason == "default" else escalation, "reasoning_effort_reason": reason}


def _escalation_reason(role: str, risk: str, security_scope: bool, wide_scope: bool,
                       failed_delivery: FailedDelivery | None) -> str:
    if type(failed_delivery) is FailedDelivery:
        return "delivery-failed-at-default-effort"
    if security_scope:
        return "security-or-containment"
    if role in {"reviewer", "adjudicator"} and risk in {"high", "critical"}:
        return "high-risk-review"
    if wide_scope:
        return "wide-architecture-or-planning"
    return "default"


def _security_scope(texts: list[str], risk_features: dict[str, list[str]]) -> bool:
    return bool(_SECURITY_FEATURES & risk_features.keys()) or any(
        term_intent(_UNCHANGED_SCOPE.sub("without changing", item), _CONTROL_SCOPE)[0] for item in texts
    )


def routing_efforts(text: str, *, segments: list[str] | None = None, task_class: str,
                    risk: str, risk_features: dict[str, list[str]], architecture_complexity: str,
                    failed_delivery: FailedDelivery | None = None) -> dict[str, dict[str, str]]:
    texts = assessed_texts(text, segments)
    tokens = {token for item in texts for token in normalized_tokens(item)}
    security = _security_scope(texts, risk_features)
    wide = architecture_complexity in {"high", "critical"} and (
        task_class == "architecture-review" or bool(tokens & _PLANNING_SCOPE)
    )
    return {role: reasoning_effort_selection(role, risk=risk, security_scope=security,
                wide_scope=wide, failed_delivery=failed_delivery)
            for role in ("lead", "worker", "reviewer", "adjudicator")}


def worker_effort_for_estimate(estimate: dict[str, Any], risk: str) -> dict[str, str]:
    """Recompute effort from the original scope bound into the fit evidence."""
    text = estimate.get("primary_outcome", "")
    tokens = set(normalized_tokens(text))
    security = _security_scope([text], assess_risk_features(text).features)
    wide = bool(tokens & _PLANNING_SCOPE) and architecture_review_complexity(text, risk) in {"high", "critical"}
    return reasoning_effort_selection("worker", risk=risk, security_scope=security, wide_scope=wide)


def effort_arguments(effort: str) -> tuple[str, str]:
    """Return the config argument pair for an existing Codex command."""
    if effort not in REASONING_EFFORTS:
        raise ValueError("Unsupported Codex reasoning effort.")
    return "-c", f"model_reasoning_effort={json.dumps(effort)}"


def _failed_evaluation(store: Any, dispatch: dict[str, Any], evaluation: dict[str, Any]) -> str | None:
    decision = evaluation.get("evaluation", {})
    if not (decision.get("verdict") == "reject" and decision.get("recommended_disposition") == "reject"
            and decision.get("screening_eligible") is True and decision.get("implementation_blocked") is False):
        return None
    receipt = store.require_return(dispatch["dispatch_id"], evaluation["return_sha256"])
    if (receipt.get("capture_provenance") != "host-capture-v1"
            or receipt["dispatch_record_sha256"] != dispatch["_record_sha256"]
            or receipt["_record_sha256"] != evaluation["return_record_sha256"]):
        return None
    if return_advisory.advisory_hold_reasons(store, dispatch, receipt):
        return None
    return evaluation["_record_sha256"]


def failed_default_delivery(store: Any, dispatch_id: str, bead_id: str, request_sha256: str) -> FailedDelivery | None:
    """Recognize a rejected default-effort return on the exact original delivery."""
    dispatch = store.require_dispatch(dispatch_id)
    selected = dispatch["evaluation_metadata"].get("codex_reasoning", {})
    if not (dispatch["dispatch_role"] == "executor" and dispatch["provider"] == "openai"
            and dispatch.get("session_id") and dispatch.get("model_id")
            and bead_id and dispatch.get("bead_id") == bead_id
            and dispatch.get("request_sha256") == request_sha256
            and selected.get("reasoning_effort_reason") == "default"
            and selected.get("reasoning_effort") == dispatch.get("reasoning_effort")):
        return None
    if store.find("acceptance-decision", dispatch_id=dispatch_id):
        return None
    matching = store.find("evaluation", dispatch_id=dispatch_id, bead_id=bead_id,
                          dispatch_record_sha256=dispatch["_record_sha256"])
    rejected = sorted(filter(None, (_failed_evaluation(store, dispatch, row) for row in matching)))
    if rejected:
        return FailedDelivery(dispatch["_record_sha256"], rejected[0])
    return None
