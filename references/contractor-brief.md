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

For architect-design critique assignments, also include:

```text
Design scope:
Affected interfaces or modules:
Migration constraints:
Rollback or reversibility expectations:
Known non-goals:
Residual risks already identified:
```

When the selected executor is Claude Opus 4.6, use `--effort high` as the
floor. Use `--effort xhigh` or `--effort max` only when the Codex architect or
route metadata marks the architecture as broad, cross-cutting, persistent-state,
public-contract, or otherwise high complexity.

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
- `contract-jd-master-plan-review`: final execution plan or total work packet
  review before implementation handoff.
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

For ChatGPT Pro browser-mediated master-plan review, the share link is the
return channel. Do not ask for raw hidden reasoning. Return conclusions,
evidence, plan risks, rejected alternatives, recommended revisions, confidence,
and escalation triggers in the required contractor return template.

For Gemini or Agy second-opinion work, treat the return as a salvage-only input
by default. The model can still be useful for spotting missing cases or
alternative framing, but broad or generic advice must not be promoted to
consensus evidence. A Gemini/Agy finding becomes primary only when the architect
explicitly upgrades that specific finding after evaluator and evidence review.

## Required Startup

1. Read the assignment packet.
2. Inspect the assigned Bead before touching code.
3. Confirm the scope and forbidden areas.
4. If blocked or underspecified, comment on the Bead instead of widening scope.

```bash
bd dolt pull    # only when a Dolt remote exists
bd show <assigned-id> --json
```

## Authority Boundaries

Do:

- work inside the assigned Bead
- use the assigned job description as the review lens
- leave evidence, commands, outputs, and residual risks in Beads
- return a focused diff, patch proposal, or branch reference when patch work is
  allowed

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
- mutate the active checkout unless direct workspace mutation is explicitly
  authorized by the assigned Bead and operator flow
- provide hidden chain-of-thought

Provide conclusions, assumptions, evidence, alternatives considered, risks,
confidence, and next actions.

Avoid generic evidence. Phrases like "looks good", "best practice", "robust",
or "no issues found" are not reusable evidence unless tied to a concrete packet
artifact, file/path, policy clause, command output, or explicit inference.

For research-style claims, add optional `Research evidence`, `Research
contradictions`, and `Research reflection` sections after `Evidence`. Include
source locators, citation spans or short excerpts, reliability and relevance
scores, support type, access status, contradiction handling, and replan notes.

## Beads Interaction

Output only the final contractor return. Do not include a preamble, internal
action narration, hidden chain-of-thought, or step-by-step planning.

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
bd dolt commit
bd dolt push    # only when a Dolt remote exists
```

If the assignment is blocked, leave the Bead open or blocked with a clear reason
instead of broadening scope.

## Completion Rule

A Bead is only done when the deliverable exists, validation has been reported,
residual risk is explicit, and the next coordination action is clear.

For non-trivial closure, the coordinator must add a final closure-memory comment
before closing the Bead. The comment should be terse and reusable by future
agents: who was involved, what changed, why closed, how validated, when closed,
where executed, key decisions, evidence, residual risk, and follow-up. Keep the
`bd close` reason short; do not put raw transcripts, secrets, local paths, or
hidden reasoning into the closure summary.

The coordinator may run `scripts/evaluate_return.py` against your return. Missing
required sections can send the assignment back for clarification before the
architect reviews it. The evaluator checks structure, concrete evidence,
validation, confidence, residual risk, recommended next Bead, boundary
violations, peer-review disposition, and unexpected workspace mutation evidence.
It also scores evidence_quality_score, evidence-quality signals, sabotage or
malpractice signals, and may quarantine a return for peer review or architect
adjudication. Passing evaluation does not mean the finding is accepted;
architect adjudication is still required before Codex workers implement
follow-up work. The acceptance decision may report advisory
`recommended_synthesis_use`, but model-synthesis remains the authority that
applies salvage-only policy and keeps weak or provider-conflicted returns out
of primary consensus. For security-sensitive synthesis, the coordinator may ask
for explicit `zero_trust_claims` with stable claim IDs, categories, values, and
evidence. Those claims are compared across independent trust domains; agreement
is not validation, and material divergence is resolved by the architect.
