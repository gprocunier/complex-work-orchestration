# CWO security threat model

This document is the security claim boundary for the repository. It describes
the helper-managed workflow and does not certify operators, hosts, providers,
or manually bypassed workflows.

## Assets

Assets include repository source and policy, Beads task and acceptance data,
worker packets and returns, model and provider metadata, credentials and secrets
that must not enter packets or logs, worktree contents, audit journals, hashes,
and the integrity of validation and adjudication evidence.

## Actors and trust boundaries

Actors are the operator, the trusted control plane, native or local workers,
external providers, repository maintainers and reviewers, and an attacker.
The control plane boundary separates packet construction, validation, dispatch,
evaluation, audit, and architect adjudication from worker output. The worker
boundary contains model-generated input and output. The provider boundary is a
separate trust domain: provider metadata and routing are recorded, but provider
responses remain evidence rather than authority.

The baseline assumes a same-process attacker may influence worker prompts,
outputs, and untrusted input, but does not control the trusted control-plane
verifier or its replay state. It assumes a filesystem attacker may read or
alter files the operating-system account can access, including local audit
evidence. When the audit hash chain is checked, it detects a retained event
that was altered and a broken link between retained events. The configured host chain keeps a private head checkpoint and ordered segment
seals, so missing/truncated retained history also refuses. Custom legacy diagnostic
logs have no equivalent checkpoint and cannot provide host authority. A writer who can rewrite the file can also recompute every
hash, and there is no external anchor, so the chain does not detect deliberate
rewriting by the same account. A compromised host, operating-system account,
credentials, or trust root is outside this model and needs an external trust
anchor.

## Threats, mechanisms, and residual risk

| Threat or claim | Mechanism and evidence | Residual risk |
|---|---|---|
| Scope or disclosure escape | Allowlisted paths, packet redaction, an outbound screen of the exact exported or sent bytes, explicit opt-in and disclosure boundaries, packet validation, and audit records | An operator can copy data or bypass helpers; redaction and screening are pattern checks, not access control, and miss secrets with no recognizable shape |
| Forged or replayed activation | Trusted verifier, exact capability binding, expiry, replay state, and preflight checks | Trust-root or host compromise is not covered |
| Worker output treated as authority | Evaluator scoring, sabotage/quarantine checks, autonomous architect adjudication, verified host acceptance and required hold records | Correlated model mistakes remain possible |
| Audit evidence altered locally | Host chain, private current-head checkpoint and ordered segment seals detect changed events, links and incomplete retained history | Custom legacy logs do not provide host authority; a same-account writer can rewrite and rehash the chain and checkpoint; local evidence is not immutable and cannot prove an unrecorded action did not occur |
| Worker or caller self-clears acceptance holds | Configured host records outside every sandbox-writable root, content digests, bounded segmented audit-chain verification, original host-only peer capture, manual executor-only CLI intake, exact return/evaluation/adjudication and hold evidence | Host records are integrity-only; unrestricted same-user history rewriting is not prevented |
| Closure selects another database | Setup-time random database identity plus physical binding, verified host record and repeated checks before Beads calls; identity in acceptance and closure audit | A compromised host can bypass helpers; database custody remains cooperative among host editors |
| Privileged or unsafe execution | Bounded dispatch, server-side tool enforcement, fixed scopes, and fail-closed checks | Exact guarantees depend on the trusted host and configured enforcement path |

## Out of scope

This model does not cover a compromised host or provider, malicious repository
maintainers, stolen credentials, denial of service or availability, model
misuse outside CWO, vulnerabilities in the operating system or dependencies,
or confidentiality after an authorized operator deliberately shares data.

Optional external anchors such as signed releases, independent attestations,
or a provider's security documentation may strengthen assurance, but none is
claimed as present by this document.

## Peer-review independence and recorded model identity

An executor can write a version 1 review string, compute the current return and
pending-evaluation digests, or name a stronger model without invoking it. Current
passed reviews therefore require a structured version 2 identity and two separate
recorded dispatches. The executor identity comes from its own return-bound
dispatch; reviewer provider, family, model and effort must match a recorded
`peer-review` dispatch that records this exact dispatch/return/evaluation as its
`review_target`. An unrelated recorded review cannot be recycled. Missing/ambiguous provenance, same dispatch/session, and
same model at any effort refuse. Identity components and session labels are
bounded before persisted audit. Access-channel aliases for the same provider do
not establish cross-provider separation.

Cross-family separation is preferred. Same-provider model escalation uses only
`provider-registry.yaml`'s `review_models` table and is weaker separation: shared
provider and training lineage can preserve correlated mistakes or intervention.
Both levels are accepted procedural review evidence and are visible in the
hold-clearance metadata, audit and CLI report. Neither clears quarantine,
tripwires or unrelated holds, nor grants execution or trusted-host authority.

Dispatch provenance comes only from the configured host record store, outside
every N1 and pool sandbox-writable root. Caller-selected dispatch directories
and caller-written dispatch files are refused. Each record is checked against
its content digest and matching event on the existing hash chain. The qualified
broker rechecks verified records on reevaluation. File hashes establish
integrity, not cryptographic authentication; an unrestricted same-user process
can replace the whole history. A caller-written review record is never used as
dispatch proof.
See [the exact record and source contract](peer-review-record.md).

## Autonomous production closure

The host acceptance pipeline records evaluation, adjudication and the evidence
that clears every required hold, including independently dispatched peer review
where policy requires it. Closure verifies that acceptance for the exact bead,
return, evaluation and setup-time database identity. Caller-written production
approval files are retired. Human confirmation and signing are not part of the
pipeline. The production source gate stays false and is checked before any
validation, I/O or effect.

Sandboxed workers cannot write the configured store; a separate test exercises
that boundary through the offline N1 host. A same-user process can alter records
but a changed retained record digest or broken chain is detected and refused.
This is tamper-evident, not tamper-proof: no immutable or external trust anchor
prevents an unrestricted same-user process from replacing and rehashing the
complete history. Missing records or chain events refuse rather than authorize.

Default audit history lives beside the package under
`../.cwo-host-state/<package-name>/`. [Segment seals and automatic recovery](host-audit-history.md)
preserve one bounded chain, old record anchors and quota history. A pending or
uncertain rotation fails closed without allowing a legacy-log fallback. The
existing completed-adjudication observation persists eligible autonomous
acceptance for the uniquely initialized workspace database. Database setup has a
product entry point and changes no Beads logical state; it never grants closure.
