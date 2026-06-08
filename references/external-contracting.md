# External Contracting Operator Guide

This reference explains how to post and manage outside model contracts for the
`complex-work-orchestration` skill.

## Contracting Model

Outside model work is a contract, not an open-ended delegation. The contract is
a Beads task with:

- a specific purpose
- a bounded scope
- a sharing boundary
- guard labels that prevent Codex pickup
- a job-description label that calibrates the model's reasoning lens
- a required handoff format
- architect review before decisions or follow-up implementation

Codex can coordinate, brief, and review contractor beads. Codex must not execute
or close them as if they were normal ready work.

## Policy Control Plane

Use the policy files as the source of truth for contractor routing:

- `policy/routing-policy.yaml`: route classes, guard labels, and restricted
  terms.
- `policy/executor-registry.yaml`: registered internal and outside executors.
- `policy/expert-registry.yaml`: discipline triggers, job-description labels,
  and expected reasoning lenses.
- `policy/share-boundaries.yaml`: allowed sharing modes.
- `policy/acceptance-policy.yaml`: required contractor return sections.
- `policy/contracting-controls.yaml`: manual dispatch, audit, and
  adjudication requirements.
- `schemas/`: machine-readable shapes for route results, contractor packets,
  returns, acceptance decisions, Beads metadata, and audit events.

The helpers are gates, not authority. If a helper recommends an external
contract but the user has not opted in or the share boundary is unclear, do not
export context.

Generated contractor packets include the matched Distinguished Engineer profile
by default. That profile is part of the contract artifact and gives the outside
model the operating lens for the assigned discipline. A packet generated without
the profile is degraded and must be justified in the Beads handoff.

## Invocation Patterns

Full scaffold:

```text
Use $complex-work-orchestration to scaffold this project.
```

Outside contractor scaffold:

```text
Use $complex-work-orchestration and post an outside security reasoning contract
for this work.
```

General reasoning review:

```text
Use $complex-work-orchestration to create a general-reasoning outside contract
for an independent second opinion.
```

Domain-specific review:

```text
Use $complex-work-orchestration to create a contractor-only SELinux reasoning
bead and keep Codex workers from picking it up.
```

## Third-Party Collaboration Question

Ask this before external contracting unless the user has already answered it:

```text
Should this project use a third-party model contractor for deep reasoning? If
yes, what may be shared: redacted packet only, repo read-only, patch branch, or
no outside sharing?
```

Interpret the answer conservatively:

- `no outside sharing`: do not create external packets.
- `redacted packet only`: share only a prepared brief, snippets, and sanitized
  evidence.
- `repo read-only`: contractor may inspect the repo but should not push changes.
- `patch branch`: contractor may prepare a focused branch or patch under the
  assigned bead.

Never share secrets, private credentials, production access, or unreleased
third-party material unless the user explicitly authorizes that exact sharing.

Run the route twice when needed: first with the default no-sharing boundary, then
again after the user has explicitly approved a boundary:

```bash
python3 scripts/route_work.py "<task text>"
python3 scripts/route_work.py \
  --external-ok \
  --share-boundary redacted-packet \
  "<task text>"
```

## Beads Setup

Full external contracting expects Beads:

```bash
command -v bd
test -d .beads && bd ready --json || true
bd sync
```

Create the graph if this repo should own the work state:

```bash
bd init
```

If Beads is not available, create a temporary Markdown plan with the same
fields. That fallback is less durable and does not provide automatic ready-work
filtering, dependency state, or shared comments.

## Required Labels

Guard labels:

```text
contractor-only
no-codex-exec
```

Primary job-description labels:

```text
contract-jd-general-reasoning
contract-jd-security-reasoning
contract-jd-architecture-reasoning
contract-jd-reliability-reasoning
contract-jd-performance-reasoning
contract-jd-docs-reasoning
contract-jd-domain-<name>
```

Use exactly one primary job-description label per contractor bead. If the work
really needs two disciplines, create two beads so the findings remain
separable.

## Discipline Calibration

General reasoning:

- assumptions
- tradeoffs
- failure modes
- missing alternatives
- confidence and next actions

Security reasoning:

- threat model
- trust boundaries
- privilege and identity
- input parsing and validation
- authn/authz
- secret exposure
- dependency and supply-chain risk
- abuse paths and mitigations

Architecture reasoning:

- module boundaries
- coupling and cohesion
- migration risk
- reversibility
- data flow
- compatibility
- long-term maintainability

Reliability reasoning:

- operational failure modes
- retries, timeouts, backoff
- state recovery
- observability
- rollout and rollback
- concurrency and race conditions

Performance reasoning:

- hot paths
- algorithmic cost
- resource pressure
- caching
- scale assumptions
- benchmark gaps

Docs reasoning:

- correctness
- audience fit
- missing warnings
- examples
- publishability
- support burden

Domain reasoning:

- name the discipline in the label, metadata, and assignment packet
- define the expected lens in the bead body
- keep the contract narrow enough for a specialist review

## Posting A Contract

Security-focused example:

```bash
bd create "Claude Opus review: security-focused reasoning for auth flow" \
  --type task \
  --parent "$EPIC_ID" \
  --labels contractor-only,no-codex-exec,contract-jd-security-reasoning \
  --assignee external-claude-opus \
  --metadata '{"executor":"external-llm","codex_pickup":"forbidden","job_description":"security-focused reasoning","discipline":"security","share_boundary":"redacted-packet","return_channel":"bd-comment","architect_review_required":true}' \
  --description "Purpose:
Security-focused review of the auth flow before implementation continues.

Scope:
Review the provided design notes and selected files only.

Inputs:
- bd show output for this bead
- redacted design packet
- relevant file snippets

Allowed changes:
No direct repo changes.

Do not touch:
Secrets, credentials, production systems, release tags, parent epics.

Expected output:
Security findings, severity, evidence, likely exploit path, mitigations,
confidence, and recommended next beads.

Validation required:
State whether findings are based on code, design notes, or inference.

Escalation triggers:
Missing context, suspected secret exposure, architecture changes, or conflicting
evidence.

Handoff format:
Beads comment using the required contractor return format.

Contractor job description:
Security-focused reasoning.

Contract labels:
contractor-only,no-codex-exec,contract-jd-security-reasoning

Share boundary:
redacted-packet

Codex handling rule:
Codex agents may coordinate, brief, and review this bead, but must not execute
or close it as contractor work."
```

For generated packets, create the contractor Bead first, then run:

```bash
python3 scripts/build_contractor_packet.py \
  --bead <id> \
  --executor external_security_reviewer \
  --share-boundary redacted-packet \
  --external-ok \
  --epic <epic-id> \
  --format json \
  --output contractor-packet.json
```

## Dispatch Flow

1. PM classifies the work with `scripts/route_work.py`.
2. PM confirms sharing boundary.
3. PM creates the contractor bead with labels and metadata.
4. PM prepares the packet:

   ```bash
   bd show <id> --json
   python3 scripts/build_contractor_packet.py \
     --bead <id> \
     --share-boundary <mode> \
     --external-ok \
     --epic <epic-id> \
     --format json \
     --output contractor-packet.json
   ```

   Use `--opt-in-record <path>` instead of `--external-ok` when opt-in is
   recorded in a local audit note.

5. PM verifies the packet includes the expert profile, opt-in basis, quota
   metadata, and only safe redacted snippets.
6. PM gives the contractor `references/contractor-brief.md`, the packet, and
   the bead assignment.
7. PM generates a manual dispatch prompt and audit event:

   ```bash
   python3 scripts/dispatch_work.py --packet contractor-packet.json --mode manual
   ```

8. Contractor returns a Beads comment or patch branch.
9. PM checks the return format and evidence:

   ```bash
   python3 scripts/evaluate_return.py --bead <id> --file contractor-return.md
   ```

10. Architect reviews findings and decides what to accept, reject, or convert
   into Codex workerbee tasks.
11. PM updates dependencies and ready-work state.

## Codex Worker Filters

Codex agents should not pick up contractor-only work:

```bash
bd ready --exclude-label contractor-only --exclude-label no-codex-exec --json
```

To inspect contractor work deliberately:

```bash
bd ready --label contractor-only --json
bd show <id> --json
```

## Handoff Format

```text
Status:
Contractor job description:
Summary:
Files changed:
Commands run:
Validation result:
Evidence:
Alternatives considered:
Confidence:
Risks or gaps:
Recommended next bead:
Escalation needed:
```

## Architect Review

The architect must review contractor output before it becomes project direction.
Treat contractor findings as evidence, not authority. Convert accepted findings
into normal Codex-executable beads that do not carry `contractor-only` or
`no-codex-exec`.
