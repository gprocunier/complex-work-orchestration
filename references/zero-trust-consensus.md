# Zero-Trust Consensus

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

## What Counts

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
