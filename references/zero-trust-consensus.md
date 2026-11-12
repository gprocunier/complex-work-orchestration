# Zero-Trust Consensus

Use this comparison when requested or required by policy. It is not a
prerequisite for the first-project tutorial. Apply it when a consequential decision
depends on claims from several accepted reviews. CWO matches explicit claim fields and reports where the
values differ; it does not infer truth from a vote. A **trust domain** groups
reviews by provider or deployment boundary for source counting, not as proof of
statistical independence. The lead resolves material disagreements.

For the reader walkthrough, see [claim comparison](../docs/zero-trust-consensus.html).
The exact input fields, normalization rules and blocked states follow below.

## Threat Model And Claim Boundaries

The assets are structured security claims, evidence references, trust-domain
metadata, and the architect's implementation decision. Inputs from models and
providers are untrusted evidence; the evaluator and architect are the review
boundary, while the control plane remains responsible for routing and record
integrity. Consensus compares claims and records divergence; it does not grant
RBAC, dispatch authority, or proof of a security property.

Hash-bound or immutable fields in a consensus record freeze the contract and
binding semantics only. They do not prevent a privileged same-user writer,
compromised control plane, or an operator from creating an unrecorded input.
The resulting status is therefore evidence for adjudication, not authorization.
Suspected disclosure or manipulation follows the repository [security
policy](../SECURITY.md), retaining the relevant claim, evidence, and audit
identifiers for responsible disclosure.

Use this reference when CWO has multiple accepted model returns and the work
contains security-sensitive, high-risk, or explicitly requested cross-domain
agreement checks.

Zero-trust consensus does not mean the models proved a claim true. It means CWO
compares structured claims from independent trust domains, records agreement and
divergence, and leaves the decision with the architect.

## When It Activates

Route output sets `zero_trust_consensus_required=true` when the task explicitly
asks for zero-trust consensus, cross-domain divergence handling, independent
trust domains, or agreement-not-proof review.

It can also activate for security-sensitive review work, such as authentication,
authorization, TLS, cryptography, supply chain, privilege boundaries,
concurrency, or network configuration when the surrounding request is
implementation, architecture, review, contractor, or synthesis work.

## Invocation boundary

The checked-in Python helper `evaluate_synthesis_inputs` must be invoked explicitly
with evaluated input records and comparable claims. Routing can emit
`zero_trust_consensus_required`; that flag does not execute the comparison. No
checked-in dispatch CLI directly calls this helper. Individual-return evaluation
is a separate path through `evaluate_return.py` and `cwo_core/returns.py`.
Tests exercise the helper directly; they are not live multi-provider runs.

Different models can broaden review evidence, but model count is not a measured
accuracy guarantee. Default local/OpenShift aliases form one local trust domain;
same-provider cloud models do not automatically add independent domains.
Provider labels on a return never establish a domain. Domain counting does not
establish statistical independence.

## Dispatch binding

Pass the recorded dispatches as `dispatch_records`, plus the exact `candidate`.
Each input names its `dispatch_id` and the SHA-256 of its return text as
`return_sha256`. The input is bound when exactly one record has that
`dispatch_id`, the record's `return_sha256` equals the input's, and the record
was made for the same candidate. A record looks like this:

```json
{
  "record_type": "cwo-dispatch-record",
  "version": 1,
  "dispatch_id": "dispatch-opus-1",
  "executor": "claude_architecture_critic",
  "return_sha256": "<64 lowercase hex characters>",
  "candidate": "commit:<sha> tree:<sha>"
}
```

The provider family comes from the record's executor through
`policy/executor-registry.yaml` and `policy/provider-registry.yaml`. A
`provider_key`, `provider_family` or `underlying_provider_key` on the record
must agree with that derived identity. A broker provider resolves only to an
observed underlying provider listed for it in the registry, and only when that
provider is a direct provider: its own `broker` flag must be absent or the
boolean `false`. A `broker` flag that is not a boolean, on the selected or the
underlying provider, leaves the provenance unknown, as does anything else. A bound return whose provenance is unknown or
conflicting is never a primary input, and an adjudication does not change that:
no reading of the record may make the return more eligible than another. Its
`zero_trust_claims` are not dropped: they stay unresolved (see Malformed
Records).

A failed binding is not a missing one. Only an input that carries neither
`dispatch_id` nor `return_sha256` is a legacy input, evaluated by its
disposition as before. An input that names either field has attempted a
binding. If that binding fails or is ambiguous (a malformed, duplicated or
missing dispatch record, a record for another candidate, a differing or
malformed digest, or a `dispatch_id` that another input also names), the
input is never primary: a computed `primary` becomes `open-risk`, the summary
reports `dispatch_binding.state: failed` with the reasons and
`primary_use_withheld`, and every other restriction on the input still applies.

A `dispatch_id` that cannot be read may name any dispatch. An input that
attempted a binding without a readable `dispatch_id`, or an input that is not
an object, may name another input's dispatch, so no other attempted binding
holds beside it ("another input has no readable dispatch_id"). A dispatch
record that is not an object or has no readable `dispatch_id` may be a second
record for any dispatch, so no attempted binding holds beside it either.
Legacy inputs, which attempt no binding, are not affected.

These records are cooperative. Whoever writes the inputs can also write the
records, so a digest does not make a record trusted-host authority; the result
reports `authority_enforcement: cooperative`.

## What Counts

Only primary synthesis inputs whose trust domain comes from a bound dispatch
record count toward independent domain coverage. Unbound returns, unknown
provenance, boundary-tainted, rejected, quarantined, salvage-only,
partial-only, open-risk, unknown and missing returns are reported, but they do
not satisfy independence.

`trust_domain`, `provider_family` and `provider_camp` on an input are claims.
They are compared with the dispatch-derived family after aliasing, and any
disagreement excludes the input. A primary input outside the domain count
still feeds the synthesis, so when it carries `zero_trust_claims` they cannot
be compared and are listed in `unresolved_claims`, which blocks required
consensus. Aliases normalize local OpenAI-compatible and
OpenShift AI vLLM workers to a local trust domain.

The salvage-only provider rule applies when the input's `provider_camp`,
`provider_family` or `trust_domain`, or the dispatch-derived family, names a
salvage-only provider. A label can add the restriction but cannot remove it.

## Adjudication

Promoting a recommended-primary return, upgrading a salvage-only return or
clearing an adjudication hold needs an adjudication record passed in
`adjudications`, together with the `scope` it applies to. The record names the
dispatch, return digest, candidate and scope, the affected `finding_ids`, a
`decision` (`accepted`, `accepted-with-changes`, `rejected` or `quarantined`),
a rationale, the adjudicator and `authority.rule`, which must be the rule in
`policy/synthesis-policy.yaml` under `adjudication_authority`. An accepting
decision needs supporting evidence for every finding, and the return itself
does not count as its own evidence. Only return-tripwire holds and the
packet-only GO hold can be cleared this way, and only when each hold reason is
named among the finding IDs; peer-review holds clear through a recorded peer
review. The packet-only GO reason must match exactly. A tripwire reason is
`return-tripwire:` followed by one category token, so appended text makes it
unclearable. A bound rejection excludes the return and resolves its use-hold while
the other inputs continue.

A record for another return digest, candidate or scope is kept as history and
does not apply. A malformed current record makes the resolution `invalid`, and
more than one current record makes it `ambiguous`. Either one holds the return
from primary use (a computed `primary` becomes `open-risk`) until the records
are resolved. A restrictive decision (`quarantined` or `rejected`) in any
record for the return's dispatch that is not provably history stays in force
when the resolution is invalid, ambiguous or unbound, even if that record is
itself malformed; the summary lists it under `pending_restrictions`. A record
is provable history only when its digest, candidate and scope are all well
formed and at least one differs from the return's. A held return stays
`open-risk`. A record that states a restrictive decision but has no readable
`dispatch_id` cannot be tied to an input, so it blocks the result.

A record that cannot be read never drops out. A record that is not an object
or has no readable `dispatch_id` may concern any return, so it is unresolved
for every input it is not provable history for: that input's resolution is
`invalid` and the result blocks. A refusal naming a dispatch that no input
names is unresolved for any input that names no readable `dispatch_id` (a
legacy input, or a failed binding without a readable `dispatch_id`). A record
is unrelated to an input only when both name readable dispatch IDs and they
differ, or when it is provable history. A decision that cannot be read
(missing, `null`, blank, not a string, not a known decision, or a known
decision in another case or with surrounding whitespace, such as `ACCEPTED` or
`" accepted "`) may be either refusal, so both stay pending and the input is quarantined, and an
`adjudications` value that is not a list is unresolved for every input in the
same way. Without a readable candidate and scope under evaluation no record
can be current or history, so every record for the dispatch is invalid. An
invalid or ambiguous resolution restricts the input whatever its final use: a
computed `primary` becomes `open-risk`, and a salvage-only input keeps the
result partial (`adjudication resolution is invalid` or `ambiguous` under
`overridden_restrictions`, and `adjudication_unresolved` in the summary).
A requested primary use (the explicit `synthesis_use`, or the recommendation
when no explicit use is given) that no applied adjudication authorizes or
decides blocks the result even when a hold, a quarantine or a pending refusal
sets the final use; a hold does not resolve the request. (The evaluator itself
never recommends primary use for a held return.)

Role labels such as `architect_adjudicated` or
`synthesis_use_authority: architect` are reported under
`ignored_authority_claims` and grant nothing.

## Malformed Records

Every argument of `evaluate_synthesis_inputs` (the inputs, dispatch records,
adjudication records with their decisions and evidence, claims, local critic
evidence, `candidate`, `scope`, `zero_trust_required`) is parsed exactly once
by `cwo_core.synthesis_inputs` into a typed form in which every field is
valid, absent where absence is allowed, or unresolved (unknown, invalid,
conflicting or unreadable). `cwo_core.adjudication` and the evaluation in
`cwo_core.synthesis` read only those forms; a test checks that neither module
reads a raw record. Validation and meaning share one parser per field, so a
value that fails validation is never read as a valid value. An unresolved
field always maps to the most restrictive outcome that any well-formed value
of it could produce, whatever the lane (internal or external), the explicit
use or the consensus setting.

Conflicting or malformed data never makes an input more eligible, and a
malformed record never stops the evaluation of other records. Each dispatch
record, adjudication record or input with a field of the wrong kind (an array
or object where a string, integer or boolean belongs) gets an entry in
`record_rejections` naming its source list, position, identifier and errors.

- A missing field means the field was not given. A present field that is
  `null` is malformed, not missing, and is reported for that input.
- A malformed or overridden input never clears a refusal. A malformed element
  is unresolved and blocks the decision it would have fed, and a well-formed
  override does not clear a restriction. Every field that can restrict, hold,
  block or quarantine is listed with its well-formed and malformed values in
  `FIELD_TABLE` in `tests/test_return_adjudication.py`, which a test checks
  against every field `cwo_core.synthesis_inputs` reads; a malformed or
  unresolved value of any of them (a conflicting dispatch label or an
  unregistered executor included), beside any override, leaves the result no
  less restrictive than the unmutated input and than the most restrictive
  well-formed value of that field.
- `synthesis_use` and `recommended_synthesis_use` are checked separately. An
  invalid value, including `null`, does not hide the other field, an input
  with an invalid use field is never primary, and an invalid use field blocks
  the result even when the other field is valid.
- An explicit `synthesis_use` sets the final use over the recommendation, but
  it does not clear a restriction the recommendation states. A
  `recommended_synthesis_use` of quarantine stays in force whatever the
  explicit use (see the external-input block below), and an explicit
  `primary`, even with a bound acceptance, becomes quarantine. A salvage-only
  use does not clear an open-risk or partial-only disposition, nor a
  partial-only, open-risk or reject recommendation overridden by an explicit
  salvage-only, an unresolved disposition, a malformed use field, or an
  invalid or ambiguous adjudication: the result stays at least partial and the
  summary lists the restriction under `overridden_restrictions`.
- A missing `implementation_blocked` means not held and a missing
  `hold_reasons` means no reasons. A present `implementation_blocked` that is
  `null`, empty, `"none"` or anything other than a boolean, the integer 0 or 1
  or a known true or false string, and a present `hold_reasons` that is `null`
  or not a list of strings, hold the input with a diagnostic. A hold reason
  that is blank, has surrounding whitespace or repeats another (ignoring case)
  makes the list malformed in the same way; it is never dropped. Hold reasons
  recorded while the flag is false or missing are a conflict and also hold the
  input. None of these holds can be cleared by an adjudication.
- Any boundary status field that is tainted, `null`, blank, not a string or
  not a recognized status (`clear`, `not-applicable` or `boundary-tainted`,
  after aliases such as `clean` and `tainted`) taints the input. A missing
  boundary status field says nothing.
- `executor`, `local_expected_response_contract` and `local_response_contract`
  mark local critic v2 evidence. A missing or `null` marker says the return is
  not such evidence (the evaluator writes `null`); any other value that is not
  a non-blank string quarantines the input. On local critic v2 evidence, each
  eligibility field (`local_response_contract_status`,
  `local_completion_status`, `local_usable_final_content`,
  `local_normalized_return_matches`, `local_v2_frame_valid`,
  `local_v2_identity_consistent`, `local_response_model_status`,
  `local_model_preflight_status`, `local_http_status`) that is missing or not
  of its kind (a non-blank string, a boolean, an integer) leaves the
  eligibility unresolved: the input is quarantined, the field is diagnosed,
  and its claims stay unresolved. A readable value other than the eligible
  one (for example `local_http_status: 500`) is a readable failure: the input
  is quarantined and excluded.
- A provider label that is `null`, blank or not a string, or a disposition the
  policy does not recognize, keeps the input out of primary use. A present disposition that is
  `null`, blank or not a string is malformed, not missing. An adjudication does
  not promote a partial-only or open-risk disposition (`missing`, `empty`,
  `timed-out`, `deferred`, `needs-investigation`) to primary. A malformed or
  unrecognized disposition blocks the result whatever the use fields say and
  counts as a possible quarantine. A missing disposition is read as `missing`
  for the input's use and is unresolved in the same way.
- An `external` value that is not a boolean is read both ways: the
  external-input block applies if it applies under either reading.
- The external-input block ("all external inputs are quarantined or
  boundary-tainted") counts every quarantine in force: an evaluator
  quarantine, a boundary taint, a quarantine applied by a bound adjudication,
  and a quarantining record still pending after an invalid, ambiguous or
  unbound resolution, including on a held return. It also counts a use-level
  quarantine: an input whose final use is quarantine, an input whose
  requested use (`synthesis_use`, or `recommended_synthesis_use` when no
  explicit use is given) is quarantine although a hold or a bound rejection
  decides its final use, an input whose `recommended_synthesis_use` is
  quarantine although an explicit use decides its final use, and an input
  with a malformed use field or an unresolved disposition, or one that is not
  an object, which may be read as quarantine, and a refusal pending from an
  unreadable record or decision. A rejection alone does not count. The summary reports this as
  `quarantine_in_force`, with each active source in `quarantine_sources`, and
  the result lists the lanes in `quarantine_in_force_inputs`. Any quarantine
  in force keeps the result from being `ready`.
- A claim that cannot be compared is unresolved, not discarded: a
  `zero_trust_claims` value that is `null` or not a list, a claim that is not
  an object, a claim with a `null`, blank or non-string `claim_id`,
  `category`, `key`, `value` or `claim_type`, a `null` or non-string
  `evidence`, a missing category, key or value, or an unknown category or
  claim type. Each is reported in `claim_warnings` and listed in
  `unresolved_claims`, and under required consensus each blocks with a reason
  naming the lane and claim. A missing `evidence` is allowed. A lane is
  excluded from consensus only by a resolved, readable reason. An input that
  is out of primary use while any of its deciding data is unresolved (a
  malformed field, a failed binding, unknown or conflicting provenance, an
  unresolved local critic v2 eligibility, or an invalid, ambiguous or unbound
  adjudication), and that carries `zero_trust_claims`, has them listed in
  `unresolved_claims` too, on an internal or an external lane: had its data
  been readable it might have been primary. The summary lists that data under
  `unresolved_data`.
- A non-object input is rejected and blocks the result, and no attempted
  binding holds beside it (it may claim any dispatch). An `inputs` value that
  is not a list blocks, and a `zero_trust_required` value that is not a
  boolean requires consensus.

## Claim Shape

The evaluator compares explicit structured claims. It does not infer security
claims from prose.

```json
{
  "lane": "opus",
  "dispatch_id": "dispatch-opus-1",
  "return_sha256": "<64 lowercase hex characters>",
  "disposition": "accepted",
  "zero_trust_claims": [
    {
      "claim_id": "auth:jwt_algorithms",
      "category": "auth",
      "key": "jwt_algorithms",
      "value": "RS256 only",
      "claim_type": "security_assertion",
      "evidence": "Reviewer cited the configured allow-list."
    }
  ]
}
```

Use a stable `claim_id` when two reviewers are describing the same claim with
different local wording. Without `claim_id`, CWO falls back to `category:key`.

## Claim Value Normalization

Current comparison lowercases values and normalizes whitespace, then applies
additional separator normalization to some short technical identifiers. For
example, `AES-256-GCM` and `aes256gcm` can match, while `TLS-1.2` and `TLS-1.3`
remain different.

Do not rely on normalized equality for case-sensitive paths, URLs or configuration
values: `/Admin` and `/admin` currently normalize identically. Inspect original
values and reconcile category, key and claim type before sharing a claim ID.
Claims under one ID that differ in category, key or claim type are listed in
`unresolved_claims` and block required consensus; the divergence weight is the
highest category weight in the group, so input order cannot lower it. These are
limits to investigate, not a basis for treating agreement as validation.


## Output Fields

`evaluate_synthesis_inputs(..., zero_trust_required=True)` returns a
`zero_trust_consensus` object with:

- `policy_version` and `policy_sha256`
- `minimum_independent_domains`
- `independent_trust_domain_count`
- `trust_domain_summaries`
- `excluded_inputs`
- `claim_warnings`
- `unresolved_claims`
- `divergence_score`
- `divergence_report`
- `weakness_pattern_findings`
- `consensus_status`
- `recommended_action`
- `blocked_reasons`
- `resolution_authority`
- `agreement_is_not_validation`

The only allowed status values are `informational`, `blocked`, and
`divergent`. The policy deliberately avoids positive words such as `confirmed`
or `validated`.

## Architect Rules

- Agreement is evidence, not validation.
- Divergence is routed to architect adjudication.
- Weakness-pattern matches are informational unless another gate escalates
  them.
- If required and fewer than the minimum independent domains are present,
  synthesis is blocked.
- If required and any claim is unresolved, synthesis is blocked.
- If divergence reaches the escalation or quarantine threshold, implementation
  conversion is blocked until the architect resolves it.

## Policy File

The control file is `policy/zero-trust-consensus-policy.yaml`. It defines the
minimum independent domains, route trigger terms, trust-domain precedence,
allowed claim categories, divergence thresholds, weakness-pattern source
version, status vocabulary, and the no-positive-confidence disclaimer.

### Public summary consistency

The public consensus helper normalizes summaries as a separate input surface.
Every input retains a slot, even if its summary is missing. Counts, positional
lane correspondence, available dispatch and return identities, binding flags,
use enums and diagnostics must agree. Parser-detected uncertainty cannot be
cleared by supplying an empty diagnostics list. Required consensus refuses
unresolved summaries; optional consensus remains informational. A readable
quarantine or other legitimate exclusion remains possible. These are cooperative
checks, not trusted production evidence: source production, evidence rereads,
consumer binding and producer qualification remain separate prerequisites.
