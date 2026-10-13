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
evidence; hashes make tampering detectable when evidence is later checked, not
impossible. A compromised host, operating-system account, credentials, or trust
root is outside this model and needs an external trust anchor.

## Threats, mechanisms, and residual risk

| Threat or claim | Mechanism and evidence | Residual risk |
|---|---|---|
| Scope or disclosure escape | Allowlisted paths, packet redaction, explicit opt-in and disclosure boundaries, packet validation, and audit records | An operator can copy data or bypass helpers; redaction is not access control |
| Forged or replayed activation | Trusted verifier, exact capability binding, expiry, replay state, and preflight checks | Trust-root or host compromise is not covered |
| Worker output treated as authority | Evaluator scoring, sabotage/quarantine checks, and architect adjudication | Human review can still miss a subtle issue |
| Audit evidence altered locally | Hashes and append-only journal conventions provide tamper-evident detection | Local evidence is not immutable and cannot prove an unrecorded action did not occur |
| Privileged or unsafe execution | Bounded dispatch, server-side tool enforcement, fixed scopes, and fail-closed checks | Exact guarantees depend on the trusted host and configured enforcement path |

## Out of scope

This model does not cover a compromised host or provider, malicious repository
maintainers, stolen credentials, denial of service or availability, model
misuse outside CWO, vulnerabilities in the operating system or dependencies,
or confidentiality after an authorized operator deliberately shares data.

Optional external anchors such as signed releases, independent attestations,
or a provider's security documentation may strengthen assurance, but none is
claimed as present by this document.
