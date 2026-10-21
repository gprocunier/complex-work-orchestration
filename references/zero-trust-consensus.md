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
Conflicting supplied domain fields and an unbound self-declared domain are
excluded. Domain counting does not establish statistical independence.

## What Counts

Provider-camp restrictions also require canonical upstream metadata. The helper's
salvage policy reads `provider_camp`; it does not derive that field automatically
from `provider_family`. Verify the binding instead of relying on a display name.


Only primary synthesis inputs with known trust domains count toward independent
domain coverage. Boundary-tainted, rejected, quarantined, salvage-only,
partial-only, open-risk, unknown, and missing returns are reported, but they do
not satisfy independence.

Trust-domain identity is resolved in this order:

1. `trust_domain`
2. `provider_family`
3. `provider_camp`

Aliases normalize local OpenAI-compatible and OpenShift AI vLLM workers to a
local trust domain. Unknown domains are excluded from the independent-domain
count.

## Claim Shape

The evaluator compares explicit structured claims. It does not infer security
claims from prose.

```json
{
  "lane": "opus",
  "provider_family": "anthropic",
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
The helper does not reject inconsistent categories under a shared ID; the first
category can determine the weight and change escalation according to input order.
These are limits to investigate, not a basis for treating agreement as validation.


## Output Fields

`evaluate_synthesis_inputs(..., zero_trust_required=True)` returns a
`zero_trust_consensus` object with:

- `policy_version` and `policy_sha256`
- `minimum_independent_domains`
- `independent_trust_domain_count`
- `trust_domain_summaries`
- `excluded_inputs`
- `claim_warnings`
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
- If divergence reaches the escalation or quarantine threshold, implementation
  conversion is blocked until the architect resolves it.

## Policy File

The control file is `policy/zero-trust-consensus-policy.yaml`. It defines the
minimum independent domains, route trigger terms, trust-domain precedence,
allowed claim categories, divergence thresholds, weakness-pattern source
version, status vocabulary, and the no-positive-confidence disclaimer.
