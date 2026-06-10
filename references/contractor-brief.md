# Outside Contractor Brief

Use this brief when assigning one Beads task to Claude, Opus, Mythos, or
another outside model contractor. The assigned Bead is the contract. Do not
infer broader authority from this brief.

This brief may be embedded in a generated packet from
`scripts/build_contractor_packet.py`. The packet's assigned Bead, share
boundary, job-description label, and forbidden areas override any generic text
in this brief.

## Assignment Packet

Fill these values before dispatch:

```text
Project:
Repository:
Branch:
Assigned bead:
Coordinator:
Architect:
Contractor job description:
Contract labels:
Discipline lens:
Share boundary:
Disclosure stage:
Packet SHA-256:
Allowed files or areas:
Forbidden files or areas:
Expected deliverable:
Validation required:
Deadline or stopping point:
```

## Operating Model

- Architect: owns architecture, final integration, acceptance, release
  judgment, and escalation decisions.
- Project manager: owns task graph hygiene, dependency state, assignments,
  status, and handoff completeness.
- Workerbee: owns bounded implementation, investigation, test triage, or
  evidence gathering.
- Outside contractor: works one assigned bead at a time, follows the posted job
  description, and reports evidence through Beads or a clearly named branch.

## Job Description Contracts

The contract labels calibrate the reasoning lens for this assignment. Honor the
assigned job description; do not turn a security review, architecture review, or
other discipline-specific contract into a generic project review.

- `contract-jd-general-reasoning`: assumptions, tradeoffs, failure modes,
  alternatives, and second-opinion critique.
- `contract-jd-security-reasoning`: threat model, privilege boundaries,
  authn/authz, inputs, secrets, dependencies, and supply-chain risk.
- `contract-jd-architecture-reasoning`: system boundaries, coupling, migration
  paths, data flow, maintainability, and reversibility.
- `contract-jd-peer-review`: independent gate for contractor or local-worker
  returns before implementation use.
- `contract-jd-sabotage-review`: integrity review for suspected sabotage,
  malpractice, fabricated evidence, or boundary-breaking output.
- `contract-jd-domain-<name>`: discipline-specific review, such as SELinux,
  API compatibility, compliance, performance, reliability, or docs.

Packets normally include an `experts/<discipline>.md` Distinguished Engineer
profile. Use that profile as the operating lens for the assignment. If the
packet says no profile was included, treat the context as degraded and say so in
your return; use the packet's degraded-context justification to understand why
the profile is missing.

## Required Startup

1. Read the assignment packet.
2. Inspect the assigned Bead before touching code.
3. Confirm the scope and forbidden areas.
4. If blocked or underspecified, comment on the Bead instead of widening scope.

```bash
bd sync
bd show <assigned-id> --json
```

## Authority Boundaries

Do:

- work inside the assigned Bead
- use the assigned job description as the review lens
- leave evidence, commands, outputs, and residual risks in Beads
- create a focused branch or patch only when code changes are explicitly allowed

Escalate:

- architecture changes
- scope changes
- conflicting findings
- unclear validation
- suspected secret exposure
- production, release, tag, or public-publication impact
- provider policy limitations that materially affect the answer

Do not:

- publish, release, tag, rotate secrets, or run destructive commands
- close parent epics
- re-plan the whole project
- provide hidden chain-of-thought

Provide conclusions, assumptions, evidence, alternatives considered, risks,
confidence, and next actions.

## Beads Interaction

```bash
bd show <id> --json
bd comment <id> "Status:
Contractor job description:
Summary:
Files changed:
Commands run:
Validation result:
Provider policy limitations:
Evidence:
Evidence provenance:
Attestation or reproducibility note:
Share-boundary conformance:
Peer-review disposition:
Alternatives considered:
Confidence:
Risks or gaps:
Recommended next bead:
Escalation needed:"
bd sync
```

If the assignment is blocked, leave the Bead open or blocked with a clear reason
instead of broadening scope.

## Completion Rule

A Bead is only done when the deliverable exists, validation has been reported,
residual risk is explicit, and the next coordination action is clear.

The coordinator may run `scripts/evaluate_return.py` against your return. Missing
required sections can send the assignment back for clarification before the
architect reviews it. The evaluator checks structure, concrete evidence,
validation, confidence, residual risk, recommended next Bead, and boundary
violations. It also scores sabotage or malpractice signals and may quarantine a
return for peer review or architect adjudication. Passing evaluation does not
mean the finding is accepted; architect adjudication is still required before
Codex workers implement follow-up work.
