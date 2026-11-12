"""Bind return adjudication to recorded evidence and derive provider provenance.

Every record this module decides on has already been parsed by
``cwo_core.synthesis_inputs``; nothing here reads a raw record. A field the
parser marks UNRESOLVED (unknown, invalid, conflicting or unreadable) maps to
the most restrictive outcome any well-formed value of it could produce.

A return is bound when it names exactly one recorded dispatch, its return
digest equals the digest recorded for that dispatch and the dispatch was made
for the exact candidate under consideration. Provider identity comes from the
dispatch record's executor through the trusted executor and provider
registries; provider, family, camp or trust-domain labels on the return or on
the record never establish identity. A label that disagrees with the derived
identity makes the provenance conflicting, and unknown provenance reduces
eligibility instead of inventing an identity.

A return with no binding metadata at all (neither ``dispatch_id`` nor
``return_sha256``) is a legacy input. A return that names either field
attempted a binding; if that binding fails or is ambiguous, the failure is
reported as such and is never read as the absence of a binding. An unreadable
``dispatch_id`` may name any dispatch: on an input it may be another input's
dispatch, and on a dispatch record it may be any input's record, so every
other attempted binding is ambiguous and fails.

An adjudication applies only to a bound return. It must name the dispatch,
return digest, candidate and scope, the affected finding IDs, a decision, a
rationale, supporting evidence for an accepting decision and the configured
authority rule. Role labels such as "architect" are recorded as claims and
never authorize anything. A stale record (another return digest, candidate or
scope) is kept as history and does not apply. A malformed or duplicate current
record makes the resolution invalid or ambiguous, which holds the return from
primary use, and a restrictive decision (rejected or quarantined) in any record
that is not provably history is preserved. A record that cannot be tied to a
dispatch (it is not an object or names no readable ``dispatch_id``) may
concern any return, so it stays unresolved for every input. Only the exact
decision strings are decisions; any other value (another case, surrounding
whitespace, a wrong type) may be either refusal, for validation and resolution
alike, because both read the one parsed decision.

These checks are cooperative workflow enforcement. Whoever can write the
inputs can also write the records, so a digest or a self-hash does not make a
record trusted-host authority.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .policy import load_policy
from .synthesis_inputs import (
    ABSENT,
    ACCEPTING_DECISIONS,
    ADJUDICATION_DECISIONS,
    ADJUDICATION_RECORD_TYPE,
    BINDING_FIELDS,
    DISPATCH_RECORD_TYPE,
    EVIDENCE_ARTIFACT_TYPES,
    RECORD_IDENTITY_CLAIMS,
    RECORD_VERSION,
    RESTRICTIVE_DECISIONS,
    ROLE_LABEL_FIELDS,
    UNRESOLVED,
    AdjudicationRecord,
    DispatchRecord,
    Field,
    Registries,
    SynthesisCall,
    SynthesisInput,
    SynthesisPolicy,
    dispatch_record_view,
)

__all__ = [
    "ACCEPTING_DECISIONS",
    "ADJUDICATION_DECISIONS",
    "ADJUDICATION_RECORD_TYPE",
    "AUTHORITY_ENFORCEMENT",
    "BINDING_FIELDS",
    "DISPATCH_RECORD_TYPE",
    "EVIDENCE_ARTIFACT_TYPES",
    "RECORD_IDENTITY_CLAIMS",
    "RECORD_VERSION",
    "RESTRICTIVE_DECISIONS",
    "ROLE_LABEL_FIELDS",
    "Binding",
    "Clearance",
    "Provenance",
    "Resolution",
    "bind_inputs",
    "derive_provenance",
    "dispatch_provenance",
    "hold_clearance",
    "load_registries",
    "possible_refusals",
    "resolve_adjudication",
]

AUTHORITY_ENFORCEMENT = "cooperative"
PROVENANCE_SOURCE = "dispatch-record executor via executor and provider registries"
# A prefix-matched clearable hold reason ends in one identifier token, such as
# the tripwire category in "return-tripwire:credential_request". Anything
# appended after it (another hold class, a separator) makes it unclearable.
_HOLD_REASON_SUFFIX = re.compile(r"[a-z0-9][a-z0-9_-]*")


def possible_refusals(decision: Field) -> tuple[str, ...]:
    """The refusals a parsed decision may state.

    A valid refusal is kept as stated and a valid acceptance states none. An
    unresolved decision may be either refusal, so both are kept.
    """

    if decision.valid:
        return (decision.value,) if decision.value in RESTRICTIVE_DECISIONS else ()
    return RESTRICTIVE_DECISIONS


# ---------------------------------------------------------------------------
# Provenance


@dataclass(frozen=True)
class Provenance:
    known: bool
    provider_key: str | None
    underlying_provider_key: str | None
    provider_family: str | None
    reasons: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "known": self.known,
            "provider_key": self.provider_key,
            "underlying_provider_key": self.underlying_provider_key,
            "provider_family": self.provider_family,
            "provenance_source": PROVENANCE_SOURCE,
            "reasons": list(self.reasons),
        }


def load_registries(
    executor_registry: dict[str, Any] | None = None, provider_registry: dict[str, Any] | None = None
) -> Registries:
    return Registries(
        executor_registry or load_policy("executor-registry"),
        provider_registry or load_policy("provider-registry"),
    )


def derive_provenance(record: DispatchRecord, registries: Registries) -> Provenance:
    """Derive provider identity from a parsed dispatch record and the trusted registries."""

    def unknown(reason: str, provider_key: str | None = None) -> Provenance:
        return Provenance(False, provider_key, None, None, (reason,))

    registered, provider_key = registries.executor_provider_key(record.executor)
    if not registered:
        return unknown("dispatch executor is not in the executor registry")
    provider = registries.provider(provider_key)
    if provider is None:
        return unknown("executor provider is not in the provider registry")
    underlying_key, underlying = provider_key, provider
    if provider.broker.unresolved:
        # A broker flag that is not a boolean could mean either reading.
        return unknown("provider registry broker flag is not a boolean", provider_key)
    if provider.broker.valid and provider.broker.value is True:
        observed_claim = record.identity_claim("underlying_provider_key")
        observed = observed_claim.value if observed_claim.valid else None
        if observed is None:
            return unknown("broker dispatch does not record the observed underlying provider", provider_key)
        allowed = provider.underlying_providers
        if allowed is None or observed not in allowed:
            return unknown("observed underlying provider is not configured for this broker", provider_key)
        observed_provider = registries.provider(observed)
        if observed_provider is None:
            return unknown("observed underlying provider is not a registered direct provider", provider_key)
        if observed_provider.broker.unresolved:
            return unknown("observed underlying provider broker flag is not a boolean", provider_key)
        if observed_provider.broker.valid and observed_provider.broker.value is True:
            return unknown("observed underlying provider is not a registered direct provider", provider_key)
        underlying_key, underlying = observed, observed_provider
    if underlying.family is None:
        return unknown("provider registry entry has no family", provider_key)
    derived = {"provider_key": provider_key, "underlying_provider_key": underlying_key, "provider_family": underlying.family}
    conflicts = tuple(
        f"dispatch record {name} conflicts with the registry-derived value"
        for name, claim in record.identity_claims
        if claim.state != ABSENT and (claim.unresolved or claim.value != derived[name])
    )
    if conflicts:
        return Provenance(False, provider_key, None, None, conflicts)
    return Provenance(True, provider_key, underlying_key, underlying.family, ())


def dispatch_provenance(
    record: Any,
    *,
    executor_registry: dict[str, Any] | None = None,
    provider_registry: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Derive provider identity for one raw dispatch record (parsed first)."""

    return derive_provenance(dispatch_record_view(record), load_registries(executor_registry, provider_registry)).as_dict()


# ---------------------------------------------------------------------------
# Binding


@dataclass(frozen=True)
class Binding:
    """``state`` is ``bound``, ``absent`` (a legacy input with no binding
    metadata) or ``failed`` (an attempted binding that failed or is ambiguous)."""

    state: str
    attempted: bool
    dispatch_id: str | None
    return_sha256: str | None
    reasons: tuple[str, ...]
    provenance: Provenance | None = None

    @property
    def bound(self) -> bool:
        return self.state == "bound"

    @property
    def provenance_known(self) -> bool:
        return self.provenance is not None and self.provenance.known

    @property
    def provenance_unresolved(self) -> bool:
        return self.bound and not self.provenance_known

    @property
    def provider_family(self) -> str | None:
        return self.provenance.provider_family if self.provenance is not None else None

    def as_dict(self) -> dict[str, Any]:
        provenance = self.provenance
        result: dict[str, Any] = {
            "state": self.state,
            "attempted": self.attempted,
            "bound": self.bound,
            "dispatch_id": self.dispatch_id,
            "return_sha256": self.return_sha256,
            "provider_key": provenance.provider_key if provenance is not None else None,
            "underlying_provider_key": provenance.underlying_provider_key if provenance is not None else None,
            "provider_family": provenance.provider_family if provenance is not None else None,
            "provenance_known": self.provenance_known,
            "reasons": list(self.reasons),
        }
        if provenance is not None:
            result["provenance_reasons"] = list(provenance.reasons)
        return result


def bind_inputs(call: SynthesisCall, registries: Registries) -> tuple[Binding, ...]:
    """Bind each input to exactly one recorded dispatch for the exact candidate.

    One dispatch cannot stand behind two inputs, so inputs that share a
    dispatch_id do not bind. An input that attempted a binding without a
    readable dispatch_id (or is not an object) may name any dispatch, so no
    other attempted binding holds; nor does any attempted binding hold beside
    a dispatch record without a readable dispatch_id, which may be a second
    record for the dispatch.
    """

    readable = [item.dispatch_id.value for item in call.inputs if item.dispatch_id.valid]
    shared = frozenset(dispatch_id for dispatch_id in readable if readable.count(dispatch_id) > 1)
    wildcards = [item.position for item in call.inputs if item.dispatch_wildcard]
    record_wildcard = any(record.dispatch_id.unresolved for record in call.dispatch_record_items)
    return tuple(
        _bind(item, call, registries, shared, any(position != item.position for position in wildcards), record_wildcard)
        for item in call.inputs
    )


def _bind(
    item: SynthesisInput,
    call: SynthesisCall,
    registries: Registries,
    shared: frozenset[str],
    other_wildcard: bool,
    record_wildcard: bool,
) -> Binding:
    dispatch_id = item.dispatch_id.value if item.dispatch_id.valid else None
    return_sha256 = item.return_sha256.value if item.return_sha256.valid else None
    state = "failed" if item.binding_attempted else "absent"
    reasons: list[str] = []

    def done(*extra: str) -> Binding:
        return Binding(state, item.binding_attempted, dispatch_id, return_sha256, (*reasons, *extra))

    if call.candidate.unresolved:
        reasons.append("no exact candidate was supplied")
    if dispatch_id is None:
        reasons.append("return does not name a dispatch_id")
    if return_sha256 is None:
        reasons.append("return does not carry a lowercase SHA-256 return digest")
    if dispatch_id is not None and dispatch_id in shared:
        reasons.append("more than one input names this dispatch_id")
    if dispatch_id is not None and other_wildcard:
        reasons.append("another input has no readable dispatch_id, so it may name this dispatch")
    if call.dispatch_records.unresolved:
        return done("dispatch records must be a list")
    if reasons:
        return done()
    if record_wildcard:
        return done("a dispatch record is not an object or has no readable dispatch_id, so it may be this dispatch's record")
    matches = [record for record in call.dispatch_record_items if record.dispatch_id.valid and record.dispatch_id.value == dispatch_id]
    if not matches:
        return done("no recorded dispatch has this dispatch_id")
    if len(matches) > 1:
        return done("more than one recorded dispatch has this dispatch_id")
    record = matches[0]
    if record.errors:
        return done(*(f"dispatch record: {error}" for error in record.errors))
    mismatches = []
    if record.return_sha256.value != return_sha256:
        mismatches.append("return digest differs from the digest recorded for this dispatch")
    if record.candidate.value != call.candidate.value:
        mismatches.append("dispatch was recorded for a different candidate")
    if mismatches:
        return done(*mismatches)
    return Binding("bound", True, dispatch_id, return_sha256, tuple(reasons), derive_provenance(record, registries))


# ---------------------------------------------------------------------------
# Adjudication resolution


@dataclass(frozen=True)
class Resolution:
    state: str
    decision: str | None = None
    adjudication_id: str | None = None
    finding_ids: tuple[str, ...] = ()
    historical_adjudication_ids: tuple[str, ...] = ()
    unattributed_adjudications: tuple[int, ...] = ()
    restrictive_decisions: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()

    @property
    def applied(self) -> bool:
        return self.state == "applied"

    @property
    def unresolved(self) -> bool:
        return self.state in ("invalid", "ambiguous")

    @property
    def pending_restrictions(self) -> tuple[str, ...]:
        """Refusals that stay in force because the resolution did not apply."""

        return () if self.applied else self.restrictive_decisions

    def as_dict(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "decision": self.decision,
            "adjudication_id": self.adjudication_id,
            "finding_ids": list(self.finding_ids),
            "historical_adjudication_ids": list(self.historical_adjudication_ids),
            "unattributed_adjudications": list(self.unattributed_adjudications),
            "restrictive_decisions": list(self.restrictive_decisions),
            "errors": list(self.errors),
        }


def _provably_historical(record: AdjudicationRecord, binding: Binding, call: SynthesisCall) -> bool:
    """Whether a record is readable enough to show that it concerns another return, candidate or scope."""

    if not (record.return_sha256.valid and record.candidate.valid and record.scope.valid):
        return False
    if binding.return_sha256 is None or not call.candidate.valid or not call.scope.valid:
        return False
    stated = (record.return_sha256.value, record.candidate.value, record.scope.value)
    return stated != (binding.return_sha256, call.candidate.value, call.scope.value)


def resolve_adjudication(
    item: SynthesisInput,
    binding: Binding,
    call: SynthesisCall,
    *,
    claimed_dispatch_ids: frozenset[str],
) -> Resolution:
    """Return the single current adjudication for a bound return, or why none applies.

    A record concerns this return when it names the return's readable
    ``dispatch_id``. A record that names no readable ``dispatch_id`` (or is
    not an object) may concern any return. So may a refusal for a dispatch no
    input names when this return is not bound (a legacy input or a failed
    binding), and a refusal for any dispatch when this return attempted a
    binding without a readable ``dispatch_id``. Such records are
    unattributed. A record is otherwise unrelated when it names another
    readable dispatch, and history only when it is provably history. An
    unattributed record that is not history makes the resolution invalid.

    ``claimed_dispatch_ids`` are the readable dispatch IDs that inputs name.

    ``restrictive_decisions`` lists the refusals (quarantined, rejected) that
    the records concerning this return may state and that are not provably
    history; an unresolved decision may be either refusal. When the state is
    not ``applied`` the caller preserves them.
    """

    if call.adjudications.state == ABSENT:
        return Resolution("none")
    if call.adjudications.state == UNRESOLVED:
        # Nothing in it can be read, so anything in it may concern this return.
        return Resolution(
            "invalid",
            restrictive_decisions=RESTRICTIVE_DECISIONS,
            errors=("adjudications must be a list; what it holds may concern this return",),
        )
    targeted: list[AdjudicationRecord] = []
    unattributed: list[tuple[AdjudicationRecord, str]] = []
    for record in call.adjudication_items:
        target = record.dispatch_id.value if record.dispatch_id.valid else None
        if target is None:
            unattributed.append(
                (record, f"adjudications[{record.position}] is not an object or names no readable dispatch_id, "
                         "so it may concern this return")
            )
        elif binding.dispatch_id is not None and target == binding.dispatch_id:
            targeted.append(record)
        elif not binding.bound and possible_refusals(record.decision):
            if target not in claimed_dispatch_ids:
                unattributed.append(
                    (record, f"adjudications[{record.position}] states a refusal for a dispatch no input names, and "
                             "this return is not bound to a dispatch, so it may concern this return")
                )
            elif item.dispatch_wildcard:
                unattributed.append(
                    (record, f"adjudications[{record.position}] states a refusal for a dispatch, and this return has "
                             "no readable dispatch_id, so it may concern this return")
                )
    history: list[str] = []
    live_targeted: list[AdjudicationRecord] = []
    for record in targeted:
        if _provably_historical(record, binding, call):
            history.append(record.label)
        else:
            live_targeted.append(record)
    live_unattributed = [(record, error) for record, error in unattributed if not _provably_historical(record, binding, call)]
    stated: set[str] = set()
    for record in [*live_targeted, *(record for record, _ in live_unattributed)]:
        stated.update(possible_refusals(record.decision))
    restrictive = tuple(decision for decision in RESTRICTIVE_DECISIONS if decision in stated)
    if live_unattributed:
        return Resolution(
            "invalid",
            historical_adjudication_ids=tuple(history),
            unattributed_adjudications=tuple(record.position for record, _ in live_unattributed),
            restrictive_decisions=restrictive,
            errors=tuple(error for _, error in live_unattributed),
        )
    if not live_targeted:
        return Resolution("none", historical_adjudication_ids=tuple(history), restrictive_decisions=restrictive)
    if not binding.bound:
        return Resolution(
            "unbound",
            historical_adjudication_ids=tuple(history),
            restrictive_decisions=restrictive,
            errors=("the return is not bound to a recorded dispatch for this candidate",),
        )
    current: list[AdjudicationRecord] = []
    errors: list[str] = []
    for record in live_targeted:
        record_errors = list(record.errors)
        if call.candidate.unresolved or call.scope.unresolved:
            # Without a readable candidate and scope under evaluation, no
            # record can be shown to be current or history.
            record_errors.append("the candidate or scope under evaluation is not readable")
        if record_errors:
            # A malformed binding field is not evidence of another return: the
            # record is rejected rather than filed as history.
            errors.extend(f"{record.label}: {error}" for error in record_errors)
            continue
        current.append(record)
    if errors:
        return Resolution(
            "invalid", historical_adjudication_ids=tuple(history), restrictive_decisions=restrictive, errors=tuple(errors)
        )
    if len(current) > 1:
        return Resolution(
            "ambiguous",
            historical_adjudication_ids=tuple(history),
            restrictive_decisions=restrictive,
            errors=(
                "more than one current adjudication for this return: "
                + ", ".join(sorted(str(record.adjudication_id.value) for record in current)),
            ),
        )
    record = current[0]
    return Resolution(
        "applied",
        decision=record.decision.value,
        adjudication_id=record.adjudication_id.value,
        finding_ids=record.finding_ids.value,
        historical_adjudication_ids=tuple(history),
        restrictive_decisions=restrictive,
    )


# ---------------------------------------------------------------------------
# Hold clearance


@dataclass(frozen=True)
class Clearance:
    authorized: bool
    uncleared_hold_reasons: tuple[str, ...] = ()
    reason: str | None = None


def clearable_hold_reason(reason: str, policy: SynthesisPolicy) -> bool:
    """Whether the configured rule lets an adjudication clear this hold reason.

    Exact reasons (the packet-only GO hold) match only in full. A prefix
    (``return-tripwire:``) matches only when one identifier token follows it.
    """

    if reason in policy.clearable_hold_reasons:
        return True
    return any(
        reason.startswith(prefix) and _HOLD_REASON_SUFFIX.fullmatch(reason[len(prefix):]) is not None
        for prefix in policy.clearable_hold_reason_prefixes
    )


def hold_clearance(item: SynthesisInput, resolution: Resolution, policy: SynthesisPolicy) -> Clearance:
    """Decide whether an applied accepting adjudication covers the return's holds.

    Only hold reasons the configured rule names as clearable by adjudication
    (return tripwires and the packet-only GO hold) can be covered, and each
    must be named among the adjudication's finding IDs. Peer-review holds are
    not clearable here; they clear through a recorded peer review. An
    unresolved hold flag or hold-reason list cannot be covered.
    """

    if not resolution.applied or resolution.decision not in ACCEPTING_DECISIONS:
        return Clearance(False, reason="no applied accepting adjudication")
    if item.hold_reasons_unresolved:
        return Clearance(False, reason="hold reasons are malformed, so no adjudication can cover them")
    if item.hold_flag_unresolved:
        return Clearance(False, reason="the hold flag is malformed, so no adjudication can clear it")
    if not item.held:
        return Clearance(True)
    if not item.hold_reasons:
        return Clearance(False, reason="held return records no hold reasons, so no adjudication can cover them")
    uncleared = tuple(
        reason
        for reason in item.hold_reasons
        if not clearable_hold_reason(reason, policy) or reason not in resolution.finding_ids
    )
    if uncleared:
        return Clearance(
            False,
            uncleared_hold_reasons=uncleared,
            reason="adjudication does not cover every hold reason with a clearable, named finding",
        )
    return Clearance(True)
