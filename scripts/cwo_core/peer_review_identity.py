"""Recorded peer-review model identities; shared adjudication provenance, no dispatch effects."""
from __future__ import annotations

import hashlib
import re
from typing import Any

from .adjudication import dispatch_provenance
from .errors import CWOPolicyError
from .policy import load_policy
from .host_records import configured_store

IDENTITY_FIELDS = frozenset({"provider", "model_family", "model_id", "reasoning_effort", "dispatch_id"})
_SEPARATION_FIELDS = frozenset({"level", "executor_identity", "executor_session_id", "reviewer_session_id",
                              "executor_dispatch_sha256", "reviewer_dispatch_sha256"})


def identity_token(value: object) -> str:
    """Constrain every identity component before file selection or persistence."""
    if type(value) is not str or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}", value) is None:
        raise CWOPolicyError("peer-review identity requires 1..128 ASCII identity characters")
    return value


def review_identity(value: object) -> dict[str, str]:
    if type(value) is not dict or set(value) != IDENTITY_FIELDS:
        raise CWOPolicyError("peer-review identity requires provider/model_family/model_id/reasoning_effort/dispatch_id")
    identity = {name: identity_token(item) for name, item in value.items()}
    if "/" in identity["dispatch_id"]:
        raise CWOPolicyError("peer-review dispatch id must be a single file component")
    return identity


def _registered_model(identity: dict[str, str]) -> dict[str, Any]:
    models = load_policy("provider-registry").get("review_models", {})
    model = models.get(identity["provider"], {}).get(identity["model_id"])
    if model is None or model["model_family"] != identity["model_family"]:
        raise CWOPolicyError("peer-review recorded model family is not registered for this provider/model")
    return model


def separation_level(executor: dict[str, str], reviewer: dict[str, str],
                     executor_session: str, reviewer_session: str) -> str:
    if executor["dispatch_id"] == reviewer["dispatch_id"]:
        raise CWOPolicyError("peer-review same dispatch is refused")
    if executor_session == reviewer_session:
        raise CWOPolicyError("peer-review same session is refused")
    if executor["model_id"] == reviewer["model_id"]:
        raise CWOPolicyError("peer-review same model at any effort is refused")
    _registered_model(executor)
    model = _registered_model(reviewer)
    if (executor["provider"], executor["model_family"]) != (reviewer["provider"], reviewer["model_family"]):
        return "cross-family"
    if executor["model_id"] not in model["stronger_than"]:
        raise CWOPolicyError("peer-review same-family reviewer is not a policy-approved stronger model")
    return "escalation"


def _recorded_dispatch(dispatch_id: str) -> tuple[dict[str, Any], dict[str, str], str]:
    """Only host-written, chain-verified records establish dispatch identity."""
    identity_token(dispatch_id)
    if "/" in dispatch_id or dispatch_id in (".", ".."):
        raise CWOPolicyError("peer-review dispatch id must be a single file component")
    record = configured_store().require_dispatch(dispatch_id)
    identity = review_identity({name: record.get(name) for name in IDENTITY_FIELDS})
    identity_token(record.get("session_id"))
    # Executor registry claims remain a consistency check when the host records
    # an executor alias. Authority is the host record and its chain event.
    if record.get("executor") is not None:
        provenance = dispatch_provenance({**{key: value for key, value in record.items() if value is not None},
            "record_type": "cwo-dispatch-record", "version": 1,
            "candidate": "host-recorded-dispatch", "return_sha256": "0" * 64})
        if provenance["known"] is not True or provenance["provider_family"] != identity["provider"]:
            raise CWOPolicyError("peer-review dispatch provenance is unresolved or conflicting")
    return record, identity, record["_record_sha256"]


def recorded_separation(inputs: dict[str, Any], reviewer: dict[str, str]) -> dict[str, Any]:
    store = configured_store()
    returned = hashlib.sha256(inputs["text"].encode("utf-8")).hexdigest()
    receipt = store.require_return(inputs["dispatch_id"], returned)
    own, executor, own_sha = _recorded_dispatch(inputs["dispatch_id"])
    if receipt["dispatch_record_sha256"] != own_sha:
        raise CWOPolicyError("peer-review executor dispatch return digest binding mismatch")
    if own.get("dispatch_role") != "executor":
        raise CWOPolicyError("peer-review executor dispatch must record the executor role")
    if inputs.get("executor") is not None and own.get("executor") != inputs["executor"]:
        raise CWOPolicyError("peer-review executor identity does not match recorded return")
    review, observed, review_sha = _recorded_dispatch(reviewer["dispatch_id"])
    if review.get("dispatch_role") != "peer-review":
        raise CWOPolicyError("peer-review reviewer dispatch must record the peer-review role")
    if observed != reviewer:
        raise CWOPolicyError("peer-review identity does not match recorded review dispatch")
    record = inputs["peer_review_record"]
    target = {"dispatch_id": inputs["dispatch_id"], "return_sha256": record["return_sha256"],
              "evaluation_sha256": record["evaluation_sha256"]}
    if review.get("review_target") != target:
        raise CWOPolicyError("peer-review recorded dispatch does not bind this exact review target")
    from .peer_review import pending_evaluation_sha256
    store.require_return(reviewer["dispatch_id"], pending_evaluation_sha256(record))
    level = separation_level(executor, observed, own["session_id"], review["session_id"])
    return {"level": level, "executor_identity": executor,
        "executor_session_id": own["session_id"], "reviewer_session_id": review["session_id"],
        "executor_dispatch_sha256": own_sha, "reviewer_dispatch_sha256": review_sha}


def validate_separation(reviewer: dict[str, str], value: object) -> dict[str, Any]:
    """Bound the persisted metadata; evaluation already resolved the source files."""
    if type(value) is not dict or set(value) != _SEPARATION_FIELDS:
        raise CWOPolicyError("peer-review requires complete recorded separation metadata")
    executor = review_identity(value["executor_identity"])
    sessions = [identity_token(value[name]) for name in ("executor_session_id", "reviewer_session_id")]
    for name in ("executor_dispatch_sha256", "reviewer_dispatch_sha256"):
        if type(value[name]) is not str or re.fullmatch(r"[0-9a-f]{64}", value[name]) is None:
            raise CWOPolicyError("peer-review separation requires dispatch SHA-256 digests")
    if value["level"] != separation_level(executor, reviewer, *sessions):
        raise CWOPolicyError("peer-review separation level mismatch")
    return value
