---
name: "complex-work-orchestration"
description: "Use for complex multi-session or multi-agent projects that need architect, project-manager, workerbee, contractor, Beads work-graph, validation, and handoff coordination."
metadata:
  short-description: "Orchestrate complex multi-agent work"
---

# Complex Work Orchestration

Use this skill to turn complex work into a durable operating model: architect
judgment, project-manager coordination, bounded workerbees, optional outside
contractors, and a Beads-backed work graph.

## When To Use

Use this skill when any of these are true:

- the work spans multiple sessions, repos, environments, or agents
- the user asks for a Mixture of Experts, PM, workerbee, contractor, Claude, or handoff setup
- the task needs durable state beyond chat history
- multiple independent investigations or implementation lanes can run in parallel
- release, lab, production, or publication risk means final judgment must stay with a senior architect

Do not use the full harness for a narrow single-thread fix. Use normal local
implementation flow unless durable coordination would materially help.

## Installation

This skill is meant to be installed from a cloned or copied repository. From the
repository root, run:

```bash
./scripts/install.sh
```

The installer autodetects the Codex skills directory from `CODEX_SKILLS_DIR`,
`CODEX_HOME`, or `$HOME/.codex/skills`, then prompts for confirmation or a path
override when running interactively. For unattended installs, pass an explicit
target:

```bash
./scripts/install.sh --skills-dir /path/to/codex/skills --yes
```

The installer does not build a tarball. It copies `README.md`, `SKILL.md`,
`agents/`, `assets/`, `references/`, and `scripts/` into the selected skills
directory. It checks for the Beads CLI (`bd`) and never treats a missing Beads
install as fatal. On Fedora/RPM-style hosts it prints package-install guidance,
including the public `greg-at-redhat/beads` COPR as a fallback when the user
does not have their own Beads package source. Set `BEADS_COPR` to print a
different COPR enable command. On other systems it prints a warning and leaves
the skill installed.

## Documentation

Use `README.md` as the human-facing operating guide for invocation, flow,
external contracting, job-description labels, and Beads requirements. Use
`references/external-contracting.md` when posting or reviewing outside model
contracts. Use `assets/interaction.html` as the briefing artifact given to an
outside contractor with a specific Beads assignment.

## Role Model

Default roles:

- **Architect**: Codex 5.5 x-high if available. Owns decomposition, architecture, final integration, acceptance, release judgment, and escalation decisions.
- **Project Manager**: simpler model. Owns Beads graph hygiene, status, dependencies, assignments, stale-work detection, and handoff completeness. Coordinates; does not decide architecture.
- **Workerbee**: Codex 5.3-spark if available. Owns bounded investigation, focused patches, test triage, file search, evidence gathering, and narrow validation tasks.
- **Outside Contractor**: Claude or another external LLM. Receives one explicit bead/contract at a time, calibrated by a job-description label, and reports findings through Beads or a patch branch.

The main thread remains the final decision owner. Escalate architecture changes,
scope changes, release decisions, destructive actions, secret handling, and
conflicting findings back to the architect.

## Startup Protocol

1. State whether the work is coherent in-thread or needs the harness.
2. If launching agents, clean stale agent state first using the local harness convention.
3. Check for Beads:

```bash
command -v bd
test -d .beads && bd ready --json || true
```

4. If Beads is available and durable coordination is appropriate, initialize or sync it:

```bash
bd init    # only if this repo should own the work graph and .beads is absent
bd sync    # when a remote/synced graph is configured
```

5. If Beads is unavailable, create the same structure in a temporary Markdown plan and say that durability is reduced.

## Scaffold Shape

Create one epic for the project goal, then create role/lane tasks under it.
Use dependencies to represent real ordering, not decorative hierarchy.

Recommended lanes:

- Architect framing
- Project manager coordination
- Implementation workerbee lane
- Test/validation workerbee lane
- Outside contractor lane with job-description contracts
- Release or publish sanitization lane, when relevant
- Docs/handoff lane, when relevant

Useful Beads patterns:

```bash
bd create "<project goal>" --type epic
bd create "<bounded task>" --type task
bd dep add <blocked-id> <blocker-id>
bd ready --json
bd show <id> --json
bd comment <id> "<evidence, findings, validation, risk>"
bd close <id>
bd sync
```

Each task should include:

```text
Purpose:
Scope:
Inputs:
Allowed changes:
Do not touch:
Expected output:
Validation required:
Escalation triggers:
Handoff format:
```

For outside-contractor tasks, also include:

```text
Contractor job description:
Contract labels:
Share boundary:
Codex handling rule:
```

## Contractor Job Descriptions

Treat outside-contractor work as posted contracts. A contract has a narrow job
description that calibrates the outside model's reasoning lens. The label is not
decorative: it tells the contractor what kind of review to perform and tells
Codex agents not to pick up the bead as normal ready work.

Ask one explicit collaboration question before creating outside contracts unless
the user has already opted in:

```text
Should this project use a third-party model contractor for deep reasoning? If
yes, what may be shared: redacted packet only, repo read-only, patch branch, or
no outside sharing?
```

Default to no outside sharing. If the user asks for Claude, Opus, Mythos, or
another outside model, treat that as model opt-in, but still confirm the sharing
boundary before exporting private context, secrets, unreleased content, or repo
state.

Every outside contract should have these guard labels:

- `contractor-only`
- `no-codex-exec`

Add exactly one primary job-description label:

- `contract-jd-general-reasoning`: independent second opinion, assumptions, tradeoffs, failure modes, and alternative approaches.
- `contract-jd-security-reasoning`: security-focused glance, threat model, privilege boundaries, input handling, authn/authz, secret exposure, dependency and supply-chain risk.
- `contract-jd-architecture-reasoning`: system design, boundaries, coupling, migration paths, data flow, long-term maintainability, and reversibility.
- `contract-jd-reliability-reasoning`: operational failure modes, recovery, observability, rollout, concurrency, state, and incident risk.
- `contract-jd-performance-reasoning`: scaling behavior, algorithmic cost, resource pressure, hot paths, caching, and benchmark gaps.
- `contract-jd-docs-reasoning`: correctness, clarity, audience fit, missing warnings, examples, and publishability.
- `contract-jd-domain-<name>`: any other discipline-specific contract, such as `contract-jd-domain-selinux` or `contract-jd-domain-api-compat`.

Use metadata to make the contract machine-readable:

```bash
bd create "Claude Opus review: security-focused reasoning for <scope>" \
  --type task \
  --labels contractor-only,no-codex-exec,contract-jd-security-reasoning \
  --assignee external-claude-opus \
  --metadata '{"executor":"external-llm","codex_pickup":"forbidden","job_description":"security-focused reasoning","discipline":"security","share_boundary":"redacted-packet","return_channel":"bd-comment","architect_review_required":true}' \
  --description "Purpose:
Scope:
Inputs:
Allowed changes:
Do not touch:
Expected output:
Validation required:
Escalation triggers:
Handoff format:
Contractor job description:
Contract labels:
Share boundary:
Codex handling rule: Codex agents may coordinate, brief, and review this bead, but must not execute or close it as contractor work."
```

Codex agents should use ready-work filters that exclude contractor-only work:

```bash
bd ready --exclude-label contractor-only --exclude-label no-codex-exec --json
```

Project-manager or architect dispatch may inspect contractor work explicitly:

```bash
bd ready --label contractor-only --json
bd show <id> --json
```

Do not ask outside models for raw chain-of-thought. Ask for conclusions,
assumptions, evidence, alternatives considered, risks, confidence, and
recommended next actions.

## Contractor Interaction

For Claude or another outside agent, use
`assets/interaction.html` as the reusable briefing artifact. Provide the
contractor with the file plus a specific bead assignment. The assignment packet
must name the job-description label and the discipline-specific review lens.

Contractor rules:

- start with `bd sync`, then `bd show <id> --json`
- work only the assigned bead unless a blocker is discovered
- honor the assigned job description; do not convert a security contract into a generic review
- do not re-plan the whole project
- do not close parent epics
- do not publish, release, tag, rotate secrets, or run destructive commands
- leave evidence in `bd comment`
- close or block the assigned bead with a clear reason
- sync before handoff when Beads sync is configured

## Required Output

When this skill is used, produce a concise orchestration packet:

- harness decision: in-thread, PM-only, or full architect/PM/workerbee/contractor setup
- role roster with model/effort choices
- Beads epic and task list, with IDs when created
- dependency graph summary
- contractor-ready assignments
- validation matrix
- escalation rules
- resume instructions using `bd ready --json`

For broad or risky work, do not begin worker execution until the user has seen
the scaffold unless they explicitly asked you to proceed end to end.
