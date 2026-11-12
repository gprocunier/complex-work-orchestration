"""Parse every synthesis input once into validated, typed forms.

This module is the only place where the raw records handed to
``evaluate_synthesis_inputs`` are read: the evaluated returns, the dispatch
records, the adjudication records and their decisions and evidence, the
zero-trust claims, the local critic evidence, the call arguments and the
configuration they are judged against. ``cwo_core.adjudication`` and the
evaluation code in ``cwo_core.synthesis`` consume only the forms built here.

Every field is parsed into one of three states:

- ``VALID``: a readable value the field's validator accepts;
- ``ABSENT``: the field is missing where a missing field is allowed and has a
  defined meaning;
- ``UNRESOLVED``: the value is unknown, invalid, conflicting or unreadable,
  including a required field that is missing.

Validation and meaning share one parser per field, so a value that fails
validation is never read as a valid value anywhere. The consumers apply one
rule to ``UNRESOLVED``: it maps to the most restrictive outcome that any
well-formed value of the field could produce, in every context. Where the
strictest reading of a field is local (a boundary status reads as tainted, a
hold flag as held and unclearable), the parsed form carries that reading and
records that it was unresolved; where it depends on other records (a
dispatch_id that may name any dispatch, a decision that may be either
refusal), the consumer applies it.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from .policy import load_policy, local_v2_critic_eligible, local_v2_critic_subject, resolve_executor_key

VALID = "valid"
ABSENT = "absent"
UNRESOLVED = "unresolved"

DISPATCH_RECORD_TYPE = "cwo-dispatch-record"
ADJUDICATION_RECORD_TYPE = "cwo-return-adjudication"
RECORD_VERSION = 1
ADJUDICATION_DECISIONS = ("accepted", "accepted-with-changes", "rejected", "quarantined")
ACCEPTING_DECISIONS = frozenset({"accepted", "accepted-with-changes"})
RESTRICTIVE_DECISIONS = ("quarantined", "rejected")
# Input fields whose presence means the return attempted a dispatch binding.
BINDING_FIELDS = ("dispatch_id", "return_sha256")
EVIDENCE_ARTIFACT_TYPES = frozenset(
    {"beads-comment", "contractor-return", "evaluator-result", "synthesis-result", "validation-log"}
)
# Caller fields that used to authorize primary use or clear a hold by
# themselves. They are still read so that historical records stay readable,
# and reported as ignored claims.
ROLE_LABEL_FIELDS = (
    "architect_adjudicated",
    "architect_upgrade",
    "architect_adjudication_authorized",
    "implementation_block_override_authorized",
    "synthesis_use_authority",
)
# Identity labels a dispatch record may carry; each must agree with the
# identity derived from the executor or the provenance is conflicting.
RECORD_IDENTITY_CLAIMS = ("provider_key", "provider_family", "underlying_provider_key")
BOUNDARY_FIELDS = ("boundary_taint_status", "boundary_status", "share_boundary_status")
# The boundary statuses the evaluator writes (cwo_core.returns), after aliases.
KNOWN_BOUNDARY_STATUSES = frozenset({"clear", "not-applicable", "boundary-tainted"})
PROVIDER_LABEL_FIELDS = ("provider_camp", "provider_family", "trust_domain")
# Fields that make an input local critic v2 evidence. The evaluator writes
# null in them for a return that is not local critic evidence.
LOCAL_V2_MARKER_FIELDS = ("executor", "local_expected_response_contract", "local_response_contract")
# The evidence a local critic v2 return must carry, with the kind each field
# must have to be readable. A field that is missing or of another kind leaves
# the eligibility unresolved; a readable value other than the eligible one is
# a readable failure.
LOCAL_V2_EVIDENCE_FIELDS = (
    ("local_response_contract_status", "text"),
    ("local_completion_status", "text"),
    ("local_usable_final_content", "bool"),
    ("local_normalized_return_matches", "bool"),
    ("local_v2_frame_valid", "bool"),
    ("local_v2_identity_consistent", "bool"),
    ("local_response_model_status", "text"),
    ("local_model_preflight_status", "text"),
    ("local_http_status", "int"),
)
ZERO_TRUST_CLAIM_FIELDS = ("claim_id", "category", "key", "value", "claim_type", "evidence")
# Fields that name or carry the claim. A present one that is blank is malformed.
ZERO_TRUST_CLAIM_TEXT_FIELDS = ("claim_id", "category", "key", "value", "claim_type")
SYNTHESIS_USES = ("primary", "salvage-only", "partial-only", "open-risk", "quarantine", "reject")
# Functions that parse trusted configuration rather than inputs; the field
# table covers every other field read in this module.
CONFIGURATION_PARSERS = ("synthesis_policy_view", "consensus_policy_view", "Registries")

_TRUE_STRINGS = frozenset({"1", "true", "yes", "y", "on"})
# An empty or "none" string is the null class: a malformed flag, not a false one.
_FALSE_STRINGS = frozenset({"0", "false", "no", "n", "off"})
_SHA256 = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class Field:
    """One parsed field: its state and, when valid, its value."""

    state: str
    value: Any = None

    @property
    def valid(self) -> bool:
        return self.state == VALID

    @property
    def unresolved(self) -> bool:
        return self.state == UNRESOLVED


def text(value: Any) -> str | None:
    """A non-blank string without surrounding whitespace, else None."""

    if isinstance(value, str) and value.strip() and value == value.strip():
        return value
    return None


def digest(value: Any) -> str | None:
    if isinstance(value, str) and _SHA256.fullmatch(value):
        return value
    return None


def id_list(value: Any) -> tuple[str, ...] | None:
    if not isinstance(value, list) or not value:
        return None
    items = [text(item) for item in value]
    if any(item is None for item in items) or len(set(items)) != len(items):
        return None
    return tuple(str(item) for item in items)


def _text_field(container: dict[str, Any], name: str) -> Field:
    """A required text field: VALID or UNRESOLVED (a missing one included)."""

    value = text(container.get(name))
    return Field(VALID, value) if value is not None else Field(UNRESOLVED)


def _digest_field(container: dict[str, Any], name: str) -> Field:
    value = digest(container.get(name))
    return Field(VALID, value) if value is not None else Field(UNRESOLVED)


def parse_decision(record: Any) -> Field:
    """The one decision parser, shared by record validation and resolution.

    Only the exact decision strings are valid. Anything else, including a
    different case, surrounding whitespace, a missing, null or non-string
    decision, or a record that is not an object, is UNRESOLVED.
    """

    value = record.get("decision") if isinstance(record, dict) else None
    if isinstance(value, str) and value in ADJUDICATION_DECISIONS:
        return Field(VALID, value)
    return Field(UNRESOLVED)


def normalize_disposition(value: Any) -> str:
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


def normalize_boundary_status(value: Any) -> str:
    status = str(value or "unknown").strip().lower().replace("_", "-").replace(" ", "-")
    aliases = {
        "clean": "clear",
        "not-tainted": "clear",
        "boundary-taint": "boundary-tainted",
        "tainted": "boundary-tainted",
    }
    return aliases.get(status, status)


def normalize_synthesis_use(value: Any) -> str | None:
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
    return normalized if normalized in SYNTHESIS_USES else None


def zero_trust_normalize(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip().lower())


def zero_trust_normalize_claim_value(value: Any, *, category: str) -> str:
    """Normalize short technical identifiers without treating prose as equivalent."""

    normalized = zero_trust_normalize(value)
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


def policy_sha256(config: dict[str, Any]) -> str:
    encoded = json.dumps(config, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


# ---------------------------------------------------------------------------
# Configuration


@dataclass(frozen=True)
class SynthesisPolicy:
    use_as_input: frozenset[str]
    open_risk: frozenset[str]
    salvage_only: frozenset[str]
    partial_only: frozenset[str]
    quarantine: frozenset[str]
    rejected: frozenset[str]
    known_dispositions: frozenset[str]
    salvage_only_camps: frozenset[str]
    minimum_usable_inputs: int
    allow_partial: bool
    partial_status: str
    authority_rule: str | None
    authority_decisions: frozenset[str]
    clearable_hold_reasons: frozenset[str]
    clearable_hold_reason_prefixes: tuple[str, ...]


def synthesis_policy_view(config: dict[str, Any]) -> SynthesisPolicy:
    disposition_policy = dict(config.get("input_disposition_policy", {}))
    partial_policy = dict(config.get("partial_synthesis_policy", {}))

    def dispositions(key: str, default: Any) -> frozenset[str]:
        return frozenset(normalize_disposition(item) for item in disposition_policy.get(key, default))

    use_as_input = dispositions(
        "use_as_synthesis_input", disposition_policy.get("use_as_primary", ["accepted", "accepted-with-modification"])
    )
    open_risk = dispositions("summarize_as_open_risk", [])
    salvage_only = dispositions("salvage_only", ["salvage-only"])
    partial_only = dispositions("partial_only", [])
    quarantine = dispositions("quarantine", ["quarantined", "boundary-tainted"])
    rejected = dispositions("exclude_as_rejected", disposition_policy.get("reject", ["rejected"])) | {
        "rejected",
        "failed-evaluation",
    }
    authority = config.get("adjudication_authority")
    authority = authority if isinstance(authority, dict) else {}
    exact = authority.get("clearable_hold_reasons", [])
    prefixes = authority.get("clearable_hold_reason_prefixes", [])
    return SynthesisPolicy(
        use_as_input=use_as_input,
        open_risk=open_risk,
        salvage_only=salvage_only,
        partial_only=partial_only,
        quarantine=quarantine,
        rejected=rejected,
        known_dispositions=use_as_input | open_risk | salvage_only | partial_only | quarantine | rejected,
        salvage_only_camps=frozenset(str(item).strip().lower() for item in config.get("salvage_only_provider_camps", [])),
        minimum_usable_inputs=int(partial_policy.get("minimum_usable_inputs", 2)),
        allow_partial=bool(partial_policy.get("allow_partial", True)),
        partial_status=str(partial_policy.get("partial_status", "partial")),
        authority_rule=text(authority.get("rule_id")),
        authority_decisions=frozenset(str(item) for item in authority.get("decisions", [])),
        clearable_hold_reasons=frozenset(
            item for item in (exact if isinstance(exact, list) else []) if isinstance(item, str) and item
        ),
        clearable_hold_reason_prefixes=tuple(
            item for item in (prefixes if isinstance(prefixes, list) else []) if isinstance(item, str) and item
        ),
    )


@dataclass(frozen=True)
class WeaknessPattern:
    pattern_id: Any
    name: Any
    category: Any
    severity: Any
    terms: tuple[str, ...]


@dataclass(frozen=True)
class ConsensusPolicy:
    version: Any
    sha256: str
    minimum_independent_domains: int
    review_threshold: int
    escalation_threshold: int
    quarantine_threshold: int
    category_weights: tuple[tuple[str, int], ...]
    allowed_statuses: frozenset[str]
    disclaimer: str
    resolution_authority: str
    claim_types: frozenset[str]
    claim_categories: frozenset[str]
    unknown_domain: str
    domain_aliases: tuple[tuple[str, str], ...]
    claimed_domain_fields: tuple[str, ...]
    weakness_patterns: tuple[WeaknessPattern, ...]
    weakness_pattern_source_version: Any

    def weight(self, category: str) -> int:
        for name, weight in self.category_weights:
            if name == category:
                return weight
        return 10

    def alias(self, value: str) -> str:
        for name, target in self.domain_aliases:
            if name == value:
                return target
        return value


def consensus_policy_view(config: dict[str, Any]) -> ConsensusPolicy:
    defaults = dict(config.get("defaults", {}))
    thresholds = dict(config.get("thresholds", {}))
    resolution = dict(config.get("trust_domain_resolution", {}))
    patterns: list[WeaknessPattern] = []
    for pattern in config.get("weakness_patterns", []):
        if not isinstance(pattern, dict):
            continue
        terms = tuple(zero_trust_normalize(term) for term in pattern.get("terms", []))
        if not terms:
            continue
        patterns.append(
            WeaknessPattern(
                pattern_id=pattern.get("id"),
                name=pattern.get("name"),
                category=pattern.get("category"),
                severity=pattern.get("severity", "informational"),
                terms=terms,
            )
        )
    return ConsensusPolicy(
        version=config.get("version"),
        sha256=policy_sha256(config),
        minimum_independent_domains=int(defaults.get("minimum_independent_domains", 2)),
        review_threshold=int(thresholds.get("review", 20)),
        escalation_threshold=int(thresholds.get("escalation", 40)),
        quarantine_threshold=int(thresholds.get("quarantine", 70)),
        category_weights=tuple(
            (str(key), int(value.get("weight", value) if isinstance(value, dict) else value))
            for key, value in dict(config.get("claim_categories", {})).items()
        ),
        allowed_statuses=frozenset(str(item) for item in config.get("status_values", ["informational", "blocked", "divergent"])),
        disclaimer=str(config.get("trust_domain_independence_disclaimer", "Agreement is not verification.")),
        resolution_authority=str(config.get("resolution_authority", "architect")),
        claim_types=frozenset(str(item) for item in config.get("claim_types", ["security_assertion"])),
        claim_categories=frozenset(config.get("claim_categories", {}).keys()),
        unknown_domain=str(resolution.get("unknown_domain", "unknown")),
        domain_aliases=tuple(
            (zero_trust_normalize(key), zero_trust_normalize(value))
            for key, value in dict(resolution.get("domain_aliases", {})).items()
        ),
        claimed_domain_fields=tuple(
            str(item)
            for item in (
                resolution.get("claimed_domain_fields")
                or resolution.get("field_precedence")
                or ["trust_domain", "provider_family", "provider_camp"]
            )
        ),
        weakness_patterns=tuple(patterns),
        weakness_pattern_source_version=config.get("weakness_pattern_source_version"),
    )


@dataclass(frozen=True)
class ProviderEntry:
    family: str | None
    # VALID True or False, ABSENT (not a broker) or UNRESOLVED (not a boolean).
    broker: Field
    # The configured underlying providers, or None when the value is not a list.
    underlying_providers: tuple[Any, ...] | None


class Registries:
    """The executor and provider registries, parsed once."""

    def __init__(self, executor_data: dict[str, Any], provider_data: dict[str, Any]) -> None:
        self._executor_data = executor_data
        executors = executor_data.get("executors", {})
        self._executors: dict[str, str | None] = {}
        if isinstance(executors, dict):
            for key, value in executors.items():
                if isinstance(value, dict):
                    self._executors[str(key)] = text(value.get("provider_key"))
        providers = provider_data.get("providers", {})
        self._providers: dict[str, ProviderEntry] = {}
        if isinstance(providers, dict):
            for key, value in providers.items():
                if not isinstance(value, dict):
                    continue
                if "broker" not in value:
                    broker = Field(ABSENT)
                elif isinstance(value.get("broker"), bool):
                    broker = Field(VALID, value.get("broker"))
                else:
                    broker = Field(UNRESOLVED)
                underlying = value.get("underlying_providers")
                self._providers[str(key)] = ProviderEntry(
                    family=text(value.get("family")),
                    broker=broker,
                    underlying_providers=tuple(underlying) if isinstance(underlying, list) else None,
                )

    def executor_provider_key(self, executor: Field) -> tuple[bool, str | None]:
        """Whether the executor is registered, and its provider key (None when unreadable)."""

        if not executor.valid:
            return False, None
        try:
            key = resolve_executor_key(executor.value, self._executor_data)
        except SystemExit:
            return False, None
        if key not in self._executors:
            return False, None
        return True, self._executors[key]

    def provider(self, key: str | None) -> ProviderEntry | None:
        if key is None or key not in self._providers:
            return None
        return self._providers[key]


# ---------------------------------------------------------------------------
# Dispatch and adjudication records


@dataclass(frozen=True)
class DispatchRecord:
    position: int
    is_object: bool
    dispatch_id: Field
    executor: Field
    candidate: Field
    return_sha256: Field
    # (field, state) for each identity label: ABSENT, VALID or UNRESOLVED.
    identity_claims: tuple[tuple[str, Field], ...]
    errors: tuple[str, ...]

    @property
    def valid(self) -> bool:
        return not self.errors

    def identity_claim(self, name: str) -> Field:
        for claim_name, claim in self.identity_claims:
            if claim_name == name:
                return claim
        return Field(ABSENT)


def dispatch_record_view(record: Any, position: int = 0) -> DispatchRecord:
    if not isinstance(record, dict):
        return DispatchRecord(
            position=position,
            is_object=False,
            dispatch_id=Field(UNRESOLVED),
            executor=Field(UNRESOLVED),
            candidate=Field(UNRESOLVED),
            return_sha256=Field(UNRESOLVED),
            identity_claims=(),
            errors=("dispatch record must be an object",),
        )
    errors: list[str] = []
    if record.get("record_type") != DISPATCH_RECORD_TYPE:
        errors.append(f"record_type must be {DISPATCH_RECORD_TYPE}")
    if type(record.get("version")) is not int or record.get("version") != RECORD_VERSION:
        errors.append(f"version must be the integer {RECORD_VERSION}")
    fields = {name: _text_field(record, name) for name in ("dispatch_id", "executor", "candidate")}
    for name, parsed in fields.items():
        if parsed.unresolved:
            errors.append(f"{name} must be a non-empty string")
    return_sha256 = _digest_field(record, "return_sha256")
    if return_sha256.unresolved:
        errors.append("return_sha256 must be a lowercase SHA-256 hex digest")
    claims: list[tuple[str, Field]] = []
    for name in RECORD_IDENTITY_CLAIMS:
        if name not in record:
            claims.append((name, Field(ABSENT)))
            continue
        parsed = _text_field(record, name)
        claims.append((name, parsed))
        if parsed.unresolved:
            errors.append(f"{name} must be a non-empty string when present")
    return DispatchRecord(
        position=position,
        is_object=True,
        dispatch_id=fields["dispatch_id"],
        executor=fields["executor"],
        candidate=fields["candidate"],
        return_sha256=return_sha256,
        identity_claims=tuple(claims),
        errors=tuple(errors),
    )


@dataclass(frozen=True)
class AdjudicationRecord:
    position: int
    is_object: bool
    dispatch_id: Field
    adjudication_id: Field
    return_sha256: Field
    candidate: Field
    scope: Field
    decision: Field
    finding_ids: Field
    errors: tuple[str, ...]

    @property
    def label(self) -> str:
        return self.adjudication_id.value if self.adjudication_id.valid else "<unnamed>"


def adjudication_record_view(record: Any, policy: SynthesisPolicy, position: int = 0) -> AdjudicationRecord:
    decision = parse_decision(record)
    if not isinstance(record, dict):
        return AdjudicationRecord(
            position=position,
            is_object=False,
            dispatch_id=Field(UNRESOLVED),
            adjudication_id=Field(UNRESOLVED),
            return_sha256=Field(UNRESOLVED),
            candidate=Field(UNRESOLVED),
            scope=Field(UNRESOLVED),
            decision=decision,
            finding_ids=Field(UNRESOLVED),
            errors=("adjudication record must be an object",),
        )
    errors: list[str] = []
    if record.get("record_type") != ADJUDICATION_RECORD_TYPE:
        errors.append(f"record_type must be {ADJUDICATION_RECORD_TYPE}")
    if type(record.get("version")) is not int or record.get("version") != RECORD_VERSION:
        errors.append(f"version must be the integer {RECORD_VERSION}")
    fields = {
        name: _text_field(record, name)
        for name in ("adjudication_id", "dispatch_id", "candidate", "scope", "rationale", "adjudicator")
    }
    for name, parsed in fields.items():
        if parsed.unresolved:
            errors.append(f"{name} must be a non-empty string")
    return_sha256 = _digest_field(record, "return_sha256")
    if return_sha256.unresolved:
        errors.append("return_sha256 must be a lowercase SHA-256 hex digest")
    findings = id_list(record.get("finding_ids"))
    if findings is None:
        errors.append("finding_ids must be a non-empty list of distinct non-empty strings")
    if decision.unresolved:
        errors.append("decision must be one of: " + ", ".join(ADJUDICATION_DECISIONS))
    rule = policy.authority_rule
    record_authority = record.get("authority")
    if not isinstance(record_authority, dict) or rule is None or text(record_authority.get("rule")) != rule:
        errors.append("authority.rule must name the configured adjudication authority rule")
    elif decision.valid and decision.value not in policy.authority_decisions:
        errors.append("the configured authority rule does not cover this decision")
    evidence = record.get("supporting_evidence", [])
    if not isinstance(evidence, list):
        errors.append("supporting_evidence must be a list")
        evidence = []
    covered: set[str] = set()
    for index, item in enumerate(evidence):
        prefix = f"supporting_evidence[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix} must be an object")
            continue
        if text(item.get("artifact")) is None:
            errors.append(f"{prefix}.artifact must be a non-empty string")
        if text(item.get("artifact_type")) not in EVIDENCE_ARTIFACT_TYPES:
            errors.append(f"{prefix}.artifact_type must be one of: " + ", ".join(sorted(EVIDENCE_ARTIFACT_TYPES)))
        item_digest = digest(item.get("sha256"))
        if item_digest is None:
            errors.append(f"{prefix}.sha256 must be a lowercase SHA-256 hex digest")
        item_findings = id_list(item.get("finding_ids"))
        if item_findings is None:
            errors.append(f"{prefix}.finding_ids must be a non-empty list of distinct non-empty strings")
            continue
        if findings is not None and not set(item_findings) <= set(findings):
            errors.append(f"{prefix}.finding_ids names a finding the adjudication does not")
        # The adjudicated return cannot be the evidence for accepting itself.
        if item_digest is not None and item_digest != return_sha256.value:
            covered.update(item_findings)
    if decision.valid and decision.value in ACCEPTING_DECISIONS and findings is not None:
        missing = [finding for finding in findings if finding not in covered]
        if missing:
            errors.append(
                "an accepting decision needs supporting evidence other than the return itself for: "
                + ", ".join(missing)
            )
    return AdjudicationRecord(
        position=position,
        is_object=True,
        dispatch_id=fields["dispatch_id"],
        adjudication_id=fields["adjudication_id"],
        return_sha256=return_sha256,
        candidate=fields["candidate"],
        scope=fields["scope"],
        decision=decision,
        finding_ids=Field(VALID, findings) if findings is not None else Field(UNRESOLVED),
        errors=tuple(errors),
    )


# ---------------------------------------------------------------------------
# Zero-trust claims


@dataclass(frozen=True)
class Claim:
    index: int | None
    comparable: bool
    # For an unresolved claim: the reported claim_id (or None) and the reason.
    reported_claim_id: str | None
    reason: str | None
    warning: str | None
    claim_id: str = ""
    category: str = ""
    key: str = ""
    value: str = ""
    normalized_value: str = ""
    claim_type: str = ""
    evidence: str = ""


@dataclass(frozen=True)
class Claims:
    # ABSENT (no field), VALID (a list) or UNRESOLVED (not a list).
    state: str
    items: tuple[Claim, ...]

    @property
    def carried(self) -> bool:
        """Whether the input carries anything that could be a claim."""

        return not (self.state == ABSENT or (self.state == VALID and not self.items))


def claims_view(entry: dict[str, Any], *, lane: str, policy: ConsensusPolicy) -> Claims:
    if "zero_trust_claims" not in entry:
        return Claims(ABSENT, ())
    raw_claims = entry.get("zero_trust_claims")
    if not isinstance(raw_claims, list):
        return Claims(
            UNRESOLVED,
            (
                Claim(
                    index=None,
                    comparable=False,
                    reported_claim_id=None,
                    reason="zero_trust_claims is null or not a list",
                    warning=f"{lane}: zero_trust_claims is null or not a list",
                ),
            ),
        )
    items: list[Claim] = []
    for index, raw_claim in enumerate(raw_claims, start=1):
        items.append(_claim_view(raw_claim, index=index, lane=lane, policy=policy))
    return Claims(VALID, tuple(items))


def _claim_view(raw_claim: Any, *, index: int, lane: str, policy: ConsensusPolicy) -> Claim:
    def unresolved(reason: str, warning: str) -> Claim:
        claim_id = raw_claim.get("claim_id") if isinstance(raw_claim, dict) else None
        return Claim(
            index=index,
            comparable=False,
            reported_claim_id=claim_id if isinstance(claim_id, str) and claim_id.strip() else None,
            reason=reason,
            warning=f"{lane}: {warning}",
        )

    if not isinstance(raw_claim, dict):
        return unresolved("the claim is not an object", f"claim {index} is not an object")
    null_fields = [name for name in ZERO_TRUST_CLAIM_FIELDS if name in raw_claim and raw_claim.get(name) is None]
    if null_fields:
        # A present null is not a missing field: it neither defaults nor
        # becomes the text "None".
        return unresolved(f"null {', '.join(null_fields)}", f"claim {index} has null {', '.join(null_fields)}")
    malformed = [
        name
        for name in ZERO_TRUST_CLAIM_FIELDS
        if name in raw_claim
        and (
            not isinstance(raw_claim.get(name), str)
            or (name in ZERO_TRUST_CLAIM_TEXT_FIELDS and not raw_claim.get(name).strip())
        )
    ]
    if malformed:
        return unresolved(
            f"blank or non-string {', '.join(malformed)}", f"claim {index} has blank or non-string {', '.join(malformed)}"
        )
    category = zero_trust_normalize(raw_claim.get("category"))
    key = zero_trust_normalize(raw_claim.get("key"))
    value = str(raw_claim.get("value", "")).strip()
    if not category or not key or not value:
        return unresolved("missing category, key or value", f"claim {index} missing category, key, or value")
    if policy.claim_categories and category not in policy.claim_categories:
        return unresolved(f"unknown category {category!r}", f"claim {index} unknown category {category!r}")
    claim_type = zero_trust_normalize(raw_claim.get("claim_type") or "security_assertion")
    if claim_type not in policy.claim_types:
        return unresolved(f"unknown claim_type {claim_type!r}", f"claim {index} unknown claim_type {claim_type!r}")
    return Claim(
        index=index,
        comparable=True,
        reported_claim_id=None,
        reason=None,
        warning=None,
        claim_id=zero_trust_normalize(raw_claim.get("claim_id")) or f"{category}:{key}",
        category=category,
        key=key,
        value=value,
        normalized_value=zero_trust_normalize_claim_value(value, category=category),
        claim_type=claim_type,
        evidence=str(raw_claim.get("evidence", "")).strip(),
    )


def domain_labels_view(entry: dict[str, Any], policy: ConsensusPolicy) -> tuple[tuple[str, str], ...]:
    """The caller's trust-domain labels, normalized and aliased; they only ever exclude."""

    observed: list[tuple[str, str]] = []
    for name in policy.claimed_domain_fields:
        raw = entry.get(name)
        if raw is None:
            continue
        normalized = zero_trust_normalize(raw)
        if not normalized:
            continue
        observed.append((name, policy.alias(normalized)))
    return tuple(observed)


# ---------------------------------------------------------------------------
# Evaluated returns


@dataclass(frozen=True)
class SynthesisInput:
    position: int
    is_object: bool
    lane: str
    # Diagnostics for every field that is unresolved; each one is reported.
    errors: tuple[str, ...]
    # The disposition reading used for the use decision (a missing one reads
    # as "missing"), and whether it is resolved.
    disposition: str
    disposition_state: str
    disposition_missing: bool
    disposition_malformed: bool
    # The strictest reading of the boundary fields.
    boundary_status: str
    local_v2_marker_unresolved: bool
    # VALID None (not local critic v2 evidence), VALID True or False (eligible
    # or a readable failure), or UNRESOLVED (missing or malformed evidence).
    local_v2: Field
    # VALID True or False (a missing flag reads True), or UNRESOLVED (both readings).
    external: Field
    provider_labels: frozenset[str]
    provider_labels_unresolved: bool
    held: bool
    hold_flag_unresolved: bool
    hold_reasons: tuple[str, ...]
    hold_reasons_unresolved: bool
    explicit_use: Field
    recommended_use: Field
    dispatch_id: Field
    return_sha256: Field
    binding_attempted: bool
    claims: Claims
    domain_labels: tuple[tuple[str, str], ...]
    ignored_authority_claims: tuple[str, ...]
    reported_provider_camp: Any
    reported_reason: Any
    reported_evidence_quality_score: Any
    hold_classification: str

    @property
    def use_unresolved(self) -> bool:
        return self.explicit_use.unresolved or self.recommended_use.unresolved

    @property
    def dispatch_wildcard(self) -> bool:
        """Whether this input may name any dispatch: it is not an object, or it
        attempted a binding without a readable dispatch_id."""

        return not self.is_object or (self.binding_attempted and not self.dispatch_id.valid)


def _use_field(entry: dict[str, Any], name: str, errors: list[str]) -> Field:
    """One use field. A missing field gives no use; a present one that is not a
    known use (null included) is UNRESOLVED."""

    if name not in entry:
        return Field(ABSENT)
    value = entry.get(name)
    normalized = normalize_synthesis_use(value) if isinstance(value, str) else None
    if normalized is None:
        errors.append(f"{name} is null or not a recognized synthesis use; the input cannot be primary")
        return Field(UNRESOLVED)
    return Field(VALID, normalized)


def _hold_flag(entry: dict[str, Any], errors: list[str]) -> tuple[bool, bool]:
    """Whether the input is held, and whether its hold flag is unresolved.

    A missing flag means not held. A present flag that is null or not a
    boolean, the integer 0 or 1 or a known true or false string is
    unresolved: it holds the input, and the hold cannot be cleared.
    """

    if "implementation_blocked" not in entry:
        return False, False
    value = entry.get("implementation_blocked")
    if isinstance(value, bool):
        return value, False
    if type(value) is int and value in (0, 1):
        return bool(value), False
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in _TRUE_STRINGS:
            return True, False
        if lowered in _FALSE_STRINGS:
            return False, False
    errors.append("implementation_blocked is null or not a boolean; the input is held and the hold cannot be cleared")
    return True, True


def malformed_hold_reasons(hold_reasons: Any) -> bool:
    """Whether a hold-reason list cannot be read element by element.

    It is malformed when it is not a list, or when any element is not a
    string, is blank, has surrounding whitespace, or repeats another element
    (compared without case or surrounding whitespace). Dropping such an
    element would hide a hold reason, so none of them can be cleared.
    """

    if not isinstance(hold_reasons, list):
        return True
    seen: set[str] = set()
    for reason in hold_reasons:
        if text(reason) is None:
            return True
        key = reason.strip().casefold()
        if key in seen:
            return True
        seen.add(key)
    return False


def _hold_reasons(entry: dict[str, Any], errors: list[str]) -> tuple[tuple[str, ...], bool]:
    if "hold_reasons" not in entry:
        return (), False
    value = entry.get("hold_reasons")
    if malformed_hold_reasons(value):
        errors.append(
            "hold_reasons is null, not a list, or holds a blank, non-string, space-padded or repeated "
            "element; the input is held and the hold cannot be cleared"
        )
        items = value if isinstance(value, list) else []
        return tuple(item for item in items if isinstance(item, str) and item.strip()), True
    return tuple(value), False


def _boundary_status(entry: dict[str, Any], errors: list[str]) -> str:
    """Any tainted or unresolved boundary field taints the input; the fields cannot outvote it.

    A missing field says nothing. A present field that is null, blank or not a
    string, or a string that is not a recognized status, is unresolved and
    taints the input: it may be a taint.
    """

    statuses: list[str] = []
    tainted = False
    for name in BOUNDARY_FIELDS:
        if name not in entry:
            continue
        value = entry.get(name)
        if not isinstance(value, str) or not value.strip():
            errors.append(f"{name} is null, blank or not a string; the input is treated as boundary-tainted")
            tainted = True
            continue
        status = normalize_boundary_status(value)
        if status not in KNOWN_BOUNDARY_STATUSES:
            errors.append(f"{name} is not a recognized boundary status; the input is treated as boundary-tainted")
            tainted = True
            continue
        statuses.append(status)
    if "boundary-tainted" in statuses and len(set(statuses)) > 1:
        errors.append("boundary status fields conflict; the input is treated as boundary-tainted")
    if tainted or "boundary-tainted" in statuses:
        return "boundary-tainted"
    return statuses[0] if statuses else normalize_boundary_status(None)


def _external(entry: dict[str, Any], errors: list[str]) -> Field:
    if "external" not in entry:
        return Field(VALID, True)
    value = entry.get("external")
    if isinstance(value, bool):
        return Field(VALID, value)
    errors.append("external is not a boolean; the external-input block is evaluated under both readings")
    return Field(UNRESOLVED)


def _local_v2_marker_unresolved(entry: dict[str, Any], errors: list[str]) -> bool:
    """Whether a local critic v2 marker is present but unreadable.

    A missing or null marker says the input is not local critic evidence (the
    evaluator writes null). Any other value that is not a non-blank string
    may be a v2 marker that cannot be checked.
    """

    unresolved = False
    for name in LOCAL_V2_MARKER_FIELDS:
        value = entry.get(name)
        if value is None or (isinstance(value, str) and value.strip()):
            continue
        errors.append(f"{name} is blank or not a string; the input is treated as unusable local critic evidence")
        unresolved = True
    return unresolved


def _local_v2(entry: dict[str, Any], errors: list[str]) -> Field:
    if not local_v2_critic_subject(
        executor=entry.get("executor"),
        expected_contract=entry.get("local_expected_response_contract"),
        response_contract=entry.get("local_response_contract"),
    ):
        return Field(VALID, None)
    unreadable: list[str] = []
    for name, kind in LOCAL_V2_EVIDENCE_FIELDS:
        value = entry.get(name)
        if kind == "text":
            readable = text(value) is not None
        elif kind == "bool":
            readable = isinstance(value, bool)
        else:
            readable = type(value) is int
        if name not in entry or not readable:
            unreadable.append(name)
    if unreadable:
        errors.append(
            "local critic v2 evidence " + ", ".join(unreadable) + " is missing or malformed; the input is "
            "treated as unusable local critic evidence and its eligibility is unresolved"
        )
        return Field(UNRESOLVED)
    eligible = local_v2_critic_eligible(
        executor=entry.get("executor"),
        expected_contract=entry.get("local_expected_response_contract"),
        response_contract=entry.get("local_response_contract"),
        contract_status=entry.get("local_response_contract_status"),
        completion_status=entry.get("local_completion_status"),
        usable_final_content=entry.get("local_usable_final_content"),
        normalized_return_matches=entry.get("local_normalized_return_matches"),
        frame_valid=entry.get("local_v2_frame_valid"),
        identity_consistent=entry.get("local_v2_identity_consistent"),
        response_model_status=entry.get("local_response_model_status"),
        model_preflight_status=entry.get("local_model_preflight_status"),
        http_status=entry.get("local_http_status"),
    )
    return Field(VALID, bool(eligible))


def _provider_labels(entry: dict[str, Any], errors: list[str]) -> tuple[frozenset[str], bool]:
    labels: set[str] = set()
    unresolved = False
    for name in PROVIDER_LABEL_FIELDS:
        if name not in entry:
            continue
        value = entry.get(name)
        if not isinstance(value, str) or not value.strip():
            errors.append(f"{name} is null, blank or not a string; the input cannot be primary")
            unresolved = True
            continue
        labels.add(value.strip().lower())
    return frozenset(labels), unresolved


def _role_label_claims(entry: dict[str, Any]) -> tuple[str, ...]:
    claims: list[str] = []
    for name in ROLE_LABEL_FIELDS:
        value = entry.get(name)
        if value is None or value is False or (isinstance(value, str) and not value.strip()):
            continue
        claims.append(name)
    return tuple(claims)


def input_view(
    raw: Any, position: int, *, policy: SynthesisPolicy, consensus_policy: ConsensusPolicy
) -> SynthesisInput:
    is_object = isinstance(raw, dict)
    entry: dict[str, Any] = raw if is_object else {}
    errors: list[str] = []
    if not is_object:
        errors.append("input record must be an object; it is rejected")
    raw_disposition = entry.get("disposition")
    disposition = normalize_disposition(raw_disposition)
    # A missing disposition reads as "missing"; a present one that is null,
    # blank or not a string is malformed, not missing.
    disposition_malformed = "disposition" in entry and not (isinstance(raw_disposition, str) and raw_disposition.strip())
    if disposition_malformed:
        errors.append("disposition is null, blank or not a string; the input cannot be primary")
    # The evaluator always records a disposition. A record without one is
    # read as "missing" for its use, and the evaluation is unresolved.
    disposition_missing = is_object and "disposition" not in entry
    if disposition_missing:
        errors.append("disposition is missing; the evaluation is unresolved")
    disposition_resolved = not disposition_malformed and not disposition_missing and disposition in policy.known_dispositions
    boundary_status = _boundary_status(entry, errors)
    marker_unresolved = _local_v2_marker_unresolved(entry, errors)
    local_v2 = _local_v2(entry, errors)
    lane = str(entry.get("lane") or entry.get("id") or entry.get("name") or f"input-{position + 1}")
    # A non-object input has no readable external flag either.
    external = _external(entry, errors) if is_object else Field(UNRESOLVED)
    provider_labels, labels_unresolved = _provider_labels(entry, errors)
    held, hold_flag_unresolved = _hold_flag(entry, errors)
    hold_reasons, hold_reasons_unresolved = _hold_reasons(entry, errors)
    if hold_reasons_unresolved:
        held = True
    if hold_reasons and not held:
        # The evaluator sets the flag exactly when it records a reason, so
        # reasons without the flag are a conflict, read as a held input.
        errors.append(
            "hold_reasons are recorded but implementation_blocked is false or missing; "
            "the input is held and the hold cannot be cleared"
        )
        held = True
        hold_flag_unresolved = True
    explicit_use = _use_field(entry, "synthesis_use", errors)
    recommended_use = _use_field(entry, "recommended_synthesis_use", errors)
    if "dispatch_id" not in entry:
        dispatch_id = Field(ABSENT)
    else:
        dispatch_id = _text_field(entry, "dispatch_id")
    if "return_sha256" not in entry:
        return_sha256 = Field(ABSENT)
    else:
        return_sha256 = _digest_field(entry, "return_sha256")
    return SynthesisInput(
        position=position,
        is_object=is_object,
        lane=lane,
        errors=tuple(errors),
        disposition=disposition,
        disposition_state=VALID if disposition_resolved else UNRESOLVED,
        disposition_missing=disposition_missing,
        disposition_malformed=disposition_malformed,
        boundary_status=boundary_status,
        local_v2_marker_unresolved=marker_unresolved,
        local_v2=local_v2,
        external=external,
        provider_labels=provider_labels,
        provider_labels_unresolved=labels_unresolved,
        held=held,
        hold_flag_unresolved=hold_flag_unresolved,
        hold_reasons=hold_reasons,
        hold_reasons_unresolved=hold_reasons_unresolved,
        explicit_use=explicit_use,
        recommended_use=recommended_use,
        dispatch_id=dispatch_id,
        return_sha256=return_sha256,
        binding_attempted=any(name in entry for name in BINDING_FIELDS),
        claims=claims_view(entry, lane=lane, policy=consensus_policy),
        domain_labels=domain_labels_view(entry, consensus_policy),
        ignored_authority_claims=_role_label_claims(entry),
        reported_provider_camp=entry.get("provider_camp"),
        reported_reason=entry.get("reason"),
        reported_evidence_quality_score=entry.get("evidence_quality_score"),
        hold_classification=str(entry.get("hold_classification") or "none"),
    )


# ---------------------------------------------------------------------------
# The call


@dataclass(frozen=True)
class SynthesisCall:
    inputs: tuple[SynthesisInput, ...]
    # VALID tuple of records, ABSENT (None) or UNRESOLVED (not a list).
    dispatch_records: Field
    adjudications: Field
    candidate: Field
    scope: Field
    zero_trust_required: bool
    argument_errors: tuple[str, ...]
    record_rejections: tuple[dict[str, Any], ...]

    @property
    def dispatch_record_items(self) -> tuple[DispatchRecord, ...]:
        return self.dispatch_records.value if self.dispatch_records.valid else ()

    @property
    def adjudication_items(self) -> tuple[AdjudicationRecord, ...]:
        return self.adjudications.value if self.adjudications.valid else ()


def _record_list(value: Any, parse: Any) -> Field:
    if value is None:
        return Field(ABSENT, ())
    if not isinstance(value, list):
        return Field(UNRESOLVED)
    return Field(VALID, tuple(parse(record, position) for position, record in enumerate(value)))


def call_view(
    inputs: Any,
    *,
    dispatch_records: Any,
    adjudications: Any,
    candidate: Any,
    scope: Any,
    zero_trust_required: Any,
    policy: SynthesisPolicy,
    consensus_policy: ConsensusPolicy,
) -> SynthesisCall:
    argument_errors: list[str] = []
    if not isinstance(inputs, list):
        argument_errors.append("inputs must be a list; nothing in it can be evaluated")
        inputs = []
    if isinstance(zero_trust_required, bool):
        required = zero_trust_required
    else:
        # Either reading is possible, so the stricter one applies.
        argument_errors.append("zero_trust_required is not a boolean; zero-trust consensus is required")
        required = True
    dispatch_field = _record_list(dispatch_records, lambda record, position: dispatch_record_view(record, position))
    adjudication_field = _record_list(
        adjudications, lambda record, position: adjudication_record_view(record, policy, position)
    )
    rejections: list[dict[str, Any]] = []
    for source, raw, parsed, id_field in (
        ("dispatch_records", dispatch_records, dispatch_field, "dispatch_id"),
        ("adjudications", adjudications, adjudication_field, "adjudication_id"),
    ):
        if parsed.state == ABSENT:
            continue
        if parsed.unresolved:
            rejections.append({"source": source, "index": None, "id": None, "errors": [f"{source} must be a list"]})
            continue
        for record, item in zip(raw, parsed.value):
            if item.errors:
                identifier = text(record.get(id_field)) if isinstance(record, dict) else None
                rejections.append(
                    {"source": source, "index": item.position, "id": identifier, "errors": list(item.errors)}
                )
    rejections.extend({"source": "arguments", "index": None, "id": None, "errors": [error]} for error in argument_errors)
    candidate_text = text(candidate)
    scope_text = text(scope)
    return SynthesisCall(
        inputs=tuple(
            input_view(raw, position, policy=policy, consensus_policy=consensus_policy)
            for position, raw in enumerate(inputs)
        ),
        dispatch_records=dispatch_field,
        adjudications=adjudication_field,
        candidate=Field(VALID, candidate_text) if candidate_text is not None else Field(UNRESOLVED),
        scope=Field(VALID, scope_text) if scope_text is not None else Field(UNRESOLVED),
        zero_trust_required=required,
        argument_errors=tuple(argument_errors),
        record_rejections=tuple(rejections),
    )


# ---------------------------------------------------------------------------
# Consensus lanes read back from synthesis summaries


@dataclass(frozen=True)
class ConsensusLane:
    lane: str
    synthesis_use: str
    bound: bool
    provenance_known: bool
    provider_family: str
    domain_labels: tuple[tuple[str, str], ...]
    claims: Claims
    # Why the lane's inclusion is unresolved; empty when every field that
    # decides it is resolved.
    unresolved_data: tuple[str, ...]
    summary_errors: tuple[str, ...] = ()


def _summary_binding(entry: dict[str, Any], summary: dict[str, Any], errors: list[str], registries: Registries) -> dict[str, Any]:
    """Validate every binding field consumed by the public summary boundary."""

    binding = summary.get("dispatch_binding")
    if not isinstance(binding, dict):
        errors.append("dispatch_binding is missing or not an object")
        return {}
    state = binding.get("state")
    if state not in ("absent", "failed", "bound"):
        errors.append("dispatch binding state is unresolved")
    for field in ("attempted", "bound", "provenance_known"):
        if type(binding.get(field)) is not bool:
            errors.append(f"dispatch binding {field} is not a boolean")
    attempted = any(field in entry for field in BINDING_FIELDS)
    if binding.get("attempted") is not attempted:
        errors.append("dispatch binding attempt does not match the input")
    if binding.get("bound") is not (state == "bound") or (state == "absent") == attempted:
        errors.append("dispatch binding state and flags disagree")
    for field, parse in (("dispatch_id", text), ("return_sha256", digest)):
        value = binding.get(field)
        expected = entry.get(field)
        if value != expected or (attempted and (parse(value) is None or parse(expected) is None)):
            errors.append(f"dispatch binding {field} does not match a readable input identity")
    if state == "failed":
        errors.append("dispatch binding failed")
    if binding.get("provenance_known") is True:
        provider_key = text(binding.get("provider_key"))
        underlying_key = text(binding.get("underlying_provider_key"))
        provider = registries.provider(provider_key)
        underlying = registries.provider(underlying_key)
        if binding.get("bound") is not True or underlying is None or underlying.family is None or underlying.family != binding.get("provider_family"):
            errors.append("known provenance lacks a bound registered provider family")
        if provider is None or provider.broker.unresolved:
            errors.append("provider identity is unresolved")
        elif provider.broker.valid and provider.broker.value is True:
            if provider.underlying_providers is None or underlying_key not in provider.underlying_providers:
                errors.append("broker underlying provider is unresolved")
            if underlying is not None and (underlying.broker.unresolved or
                                           (underlying.broker.valid and underlying.broker.value is True)):
                errors.append("broker underlying provider is not a registered direct provider")
        elif provider_key != underlying_key:
            errors.append("direct provider and underlying provider disagree")
    elif binding.get("bound") is True:
        errors.append("bound dispatch provenance is unresolved")
    return binding


def _summary_lane(entry: Any, summary: Any, position: int, policy: ConsensusPolicy,
                  collection_errors: tuple[str, ...], registries: Registries,
                  synthesis_config: SynthesisPolicy) -> ConsensusLane:
    item = input_view(entry, position, policy=synthesis_config, consensus_policy=policy)
    errors = list(collection_errors) + list(item.errors)
    if item.disposition_state != VALID:
        errors.append("original input disposition is unresolved")
    if not isinstance(entry, dict):
        errors.append("input is not an object")
        entry = {}
    if not isinstance(summary, dict):
        errors.append("summary is missing or not an object")
        summary = {}
    lane = item.lane
    if text(summary.get("lane")) != lane:
        errors.append("summary lane does not match its input")
    use = summary.get("synthesis_use")
    if not isinstance(use, str) or use not in SYNTHESIS_USES:
        errors.append("summary synthesis_use is missing or unresolved")
        use = "unknown"
    binding = _summary_binding(entry, summary, errors, registries)
    unresolved = summary.get("unresolved_data")
    if not isinstance(unresolved, list) or any(text(item) is None for item in unresolved):
        errors.append("summary unresolved_data is missing or malformed")
        unresolved = []
    # The producer emits null for an absent display label. It is deliberately
    # absent on this output surface; an original input null is still an error
    # from input_view above. Other malformed summary labels stay unresolved.
    _provider_labels({name: summary[name] for name in PROVIDER_LABEL_FIELDS if summary.get(name) is not None}, errors)
    if "adjudication_unresolved" in summary:
        if summary.get("adjudication_unresolved") is not False:
            errors.append("summary adjudication is unresolved or malformed")
    # Diagnostics supplied by a caller may add restrictions, never erase a
    # parser-detected problem. Input and summary labels only ever exclude;
    # merging dictionaries would let the summary overwrite a conflicting label.
    return ConsensusLane(
        lane=lane,
        synthesis_use=str(use),
        bound=not errors and binding.get("bound") is True,
        provenance_known=not errors and binding.get("provenance_known") is True,
        provider_family=zero_trust_normalize(binding.get("provider_family")),
        domain_labels=item.domain_labels + domain_labels_view(summary, policy),
        claims=item.claims,
        unresolved_data=tuple(unresolved) + tuple(errors),
        summary_errors=tuple(errors),
    )


def consensus_lanes_from_summaries(
    inputs: Any, input_summaries: Any, policy: ConsensusPolicy, *,
    synthesis_config: SynthesisPolicy | None = None,
) -> tuple[ConsensusLane, ...]:
    """Normalize every public-helper summary, preserving unmatched inputs.

    Correspondence is positional and bound to available lane, dispatch and
    return identities. This is cooperative consistency, not trusted production
    provenance. Any collection mismatch remains unresolved for required consensus.
    """

    collection_errors: list[str] = []
    if not isinstance(inputs, list):
        collection_errors.append("inputs is not a list")
    if not isinstance(input_summaries, list):
        collection_errors.append("input_summaries is not a list")
    entries = inputs if isinstance(inputs, list) else []
    summaries = input_summaries if isinstance(input_summaries, list) else []
    if len(entries) != len(summaries):
        collection_errors.append("input and summary counts do not match")
    identities = []
    for summary in summaries:
        if isinstance(summary, dict):
            binding = summary.get("dispatch_binding")
            binding = binding if isinstance(binding, dict) else {}
            identities.append((text(summary.get("lane")), text(binding.get("dispatch_id")),
                               digest(binding.get("return_sha256"))))
    if len(set(identities)) != len(identities):
        collection_errors.append("duplicate summary identity")
    registries = Registries({}, load_policy("provider-registry"))
    synthesis_config = synthesis_config or synthesis_policy_view(load_policy("synthesis-policy"))
    lanes = tuple(
        _summary_lane(entry, summaries[position] if position < len(summaries) else None,
                      position, policy, tuple(collection_errors), registries, synthesis_config)
        for position, entry in enumerate(entries)
    )
    if not lanes and collection_errors:
        lanes = (_summary_lane({}, None, 0, policy, tuple(collection_errors), registries, synthesis_config),)
    return lanes
