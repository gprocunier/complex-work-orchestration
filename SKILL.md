---
name: "complex-work-orchestration"
description: "Use for complex multi-session or multi-agent projects that need architect, project-manager, workerbee, contractor, Beads work-graph, validation, and handoff coordination."
metadata:
  short-description: "Orchestrate complex multi-agent work"
---

# Complex Work Orchestration

Use this skill to scale orchestration while keeping work durable through Beads,
evidence, validation, and handoff.

## When To Use

Use CWO when:

- work spans sessions, repos, environments, or agents
- the user asks for a coach, PM, architect, workerbee, contractor, model synthesis, prompt review, or handoff setup
- work needs durable state beyond chat history
- independent investigations can run in parallel
- release, lab, production, publication, or security risk needs architect judgment

Beads tracking is mandatory for non-trivial work. In ordinary Codex sessions, handle narrow fixes in-thread with one Bead.

## Operating Defaults

Registered N1 needs original signed admission, provider disclosure consent and separate authentication.
Registered contained pools run two or three approved workers. Raw native and generic pools stay held.
Campaigns, live activation, standalone calibration, tool-surface capture and maintenance observation are retired.
Preview stays offline. Verify host capability and model. [Routes](references/native-live-route-holds.md)
The lead uses host permissions. The controller contains registered workers and owns protected
approvals and review evidence. [Threat model](references/security-threat-model.md#trust-on-the-supervisor-host)

- The opt-in architect profile loads `prompts/cwo-architect.md` in a fresh session. See `references/cwo-system-prompt.md`.
- Default to `no-outside-sharing`; ask only when an outside lane adds material value.
- Prefer review-only workers before implementation unless write ownership is disjoint.
- For local model calls, require `--local-ok`, an explicitly configured endpoint
  and original workload admission. Review and adjudicate the captured advisory
  return before implementation. [Local model dispatch](references/local-inference.md#dispatch).
- Size native work first. Luna handles focused work. Sol handles recorded coding escalation, architecture and adjudication. Terra handles interface, visual and computer-use work. Astra reviews unresolved architecture. Spark records are historical.
- Default mode is conservative. Explicit coach requests present coach options before plan creation unless execution was requested; Plan mode asks only questions that change execution.
- Keep model names and versions in policy and use executor aliases from `policy/executor-registry.yaml` in plans and docs.

## First Moves

1. Decide the execution shape: in-thread, PM-only, tight-chain scaffold, or full harness.
2. If sizing is unclear, use the prompt coach:

```bash
python3 scripts/coach_prompt.py "<task text>"
```

3. [Classify work](references/prompt-coach.md#routing-risk). Appends cannot lower risk.

```bash
python3 scripts/route_work.py "<task text>"
```

4. Check for stale local agent sessions before launching agents (signals nothing):

```bash
python3 scripts/cleanup_stale_agents.py --json
```

The CLI detects and prunes; termination flags report `termination-unavailable`. Use `--workspace-root <path>` above the repo.
`--dry-run` or `--no-prune-state` skips pruning. In-process `cleanup()` needs the original `owned_controller` and opaque
`owned_capabilities` from `cleanup_capability(receipt)`; KILL also needs `allow_kill_owned=True` and lifetime, context, age and ancestry checks.
A pidfd identifies one lifetime; registry records, argv and serialized fields grant no authority. See [cleanup limits](README.md#limits).

5. Check Beads and sync only when a Dolt remote exists:

```bash
command -v bd
test -d .beads && bd ready --json || true
bd dolt remote list
```

If Beads is unavailable, use a temporary Markdown plan and say durability is
reduced. Do not claim local Beads state is synced without a Dolt remote.

## Scaffold Choices

Use one manual Bead for narrow work; no smaller scaffold tier exists. Use a tight
chain (architecture, implementation and docs, validation, wrap-up) without optional fan-out:

```bash
python3 scripts/scaffold_workgraph.py \
  --title "<goal>" \
  --description "<scope>" \
  --scaffold-size tight
```

Use the full graph for broad, risky, multi-lane, reviewed, synthesized, or release-sensitive work:

```bash
python3 scripts/scaffold_workgraph.py --title "<goal>" --description "<scope>"
```

`--dry-run --format beads-graph` renders a graph accepted by
`bd create --graph`; normal execution creates Beads directly.

## Proportional Fast Path

Use `scripts/evaluate_proportional_execution.py --brief <path>` only for one ignored, ephemeral, or non-publishable artifact under 500 lines, 12 calls, and 600 seconds when identity, model, tool scope, deterministic checks, false mutation/access flags, and closed architecture/security/policy decisions are explicit. For delegated native execution, use the registered route through an authorized embedding host when configured.

`operative-readiness:v2` bounds hashed context units and mutation evidence:
three units or six reads warn; four or eleven require replanning.

## Routing and Maintenance Controls

- Use the exact role models in `policy/model-roles.yaml`. Record the escalation
  reason for Sol. Set `work_kind` in the estimate for Terra assignments.
- Current dispatch needs verified model, tool profile, workspace, ownership,
  qualification, source image and attempt bindings. Caller JSON is evidence,
  not a grant. Omitted authority must not revive historical Spark dispatch. The absent-by-default `cyber_fallback` permits one unchanged, same-budget retry only with catalog access and an owner-private mark outside worker roots.
- Historical version-2 records remain inspectable. They cannot authorize new
  dispatch once the current routing policy is activated.
- Preserve ordinary finite budgets. Explicit mission-scoped maintenance may
  use an unbounded mission with finite per-operation reservations and timeouts.
  Never infer maintenance authority from a filename, worker return or summary.
- When the user authorizes CWO self-repair, broken CWO admission is not a
  prerequisite for authorized editing/testing. Repair with available tools,
  then prove the repaired installed path works. Preserve old receipts and UNKNOWN
  findings; establish present ownership/isolation for new operations.
- Diagnose failed steps and repair them within scope. Revalidate bindings and
  rerun failed checks before dependent work resumes. Record blockers with
  their causes and continue independent work within scope.
- Consult the strongest authorized available adviser for unresolved architecture
  or repeated materially different failed repairs. Advice is evidence, not authority
  to waive a gate. Disclose genuine access/outage/security boundaries plainly.
- No stopped worker resumes. Use fresh identities after terminal failure;
  realignment remains nonaccepted. Containment precedes owned-state restoration.
- For one known text output, use `cwo-delegation` in local `cwo-codex` to get the operator's standing approval, then run `cwo delegate` with the same task and baseline.
  Lead-run supervision checks are advisory. [Production requirements](references/native-live-route-holds.md#standing-approved-delegation).
- Native pool work additionally needs trusted-controller factory authority (not shipped), so
  the version-2 launcher refuses ordinary plans, even `--validate-only`. Cohorts
  stay N=1..3; concurrency needs actual compatible capability evidence.
- Maintenance transactions use the explicit version-8 plan and opaque owner
  capabilities. Missing authority rejects before runtime adapter execution,
  including validate-only. The trusted parent selects/pins the installed factory.
- Qualification retains original provider/session/terminal/cleanup observations
  and independent checked execution. A serialized success Boolean is insufficient.
- Read-only semantic validation has zero consistent mutation claims and an
  actually enforced read-only sandbox/tool profile. Arbitrary tests and command
  prefixes do not establish read-only safety.
- Install only the coherent accepted projection, retain a backup, verify byte
  parity and loaded fresh-runtime identity, then prove productive, read-only and
  subsequent-operation behavior. Import success or a dry run is not completion.

## Reference Map

- Human operating guide: `README.md`
- Prompt coach: `references/prompt-coach.md`
- External contracting and trust boundary: `references/external-contracting.md`
- Contractor briefing: `references/contractor-brief.md`
- Execution environments and local inference: `references/execution-environments.md`,
  `references/local-inference.md`
- Native supervision: `references/native-supervision.md`
- Multi-worker concurrency Tech Preview: `references/native-supervision-pools.md`
- Zero-trust consensus: `references/zero-trust-consensus.md`
- Run readiness: `references/run-readiness.md`
- Beads hook display: `references/codex-beads-hooks.md`
- Incident response and quarantine: `references/incident-response-playbook.md`
- Red Hat expert catalog: `references/redhat-expert-catalog.md`
- Publishable workflow pages: `docs/workflows.html`, `docs/local-workers.html`

`policy/` is the machine-readable control plane; `templates/`, `experts/`,
`schemas/`, and `examples/` provide reusable artifacts.

## Contractor And Local Worker Gates

Outside packets require explicit opt-in, one primary `contract-jd-*` label, guard labels,
share boundary, provider metadata, redaction, screening, validation, audit,
return normalization, evaluation and architect adjudication.

```bash
python3 scripts/build_contractor_packet.py --bead <id> --executor <executor> --share-boundary redacted-packet --opt-in-record="$APPROVAL_REF" --format json --output contractor-packet.json
python3 scripts/dispatch_work.py --packet contractor-packet.json --mode manual
python3 scripts/normalize_contractor_return.py --bead <id> --dispatch-id <id> --packet-sha256 <sha> --file contractor-return.md --output contractor-return-bundle.json
python3 scripts/evaluate_return.py --bead <id> --file contractor-return.md
```

Required plan reviews remain blocking until the approved route, model and any
required settings, return evidence, evaluation and adjudication are established
or the operator explicitly changes that requirement. For ChatGPT Pro, follow the
[ChatGPT desktop app workflow](references/chatgpt-pro-browser.md). Local inference
requires `--local-ok`. Use `--prefer-local` only for an intended low-risk local review lane.

Use the configured Luna model first for focused native work. Each assignment fixes its exact model.
Stop on missing or mismatched attestation. Do not substitute another model.
Spark records remain available for historical inspection.

Use `scripts/workspace_mutation_guard.py` around external CLIs with checkout access.
Quarantine returns for sabotage scores of 50 or higher, high malpractice, provider conflict, or boundary taint pending peer review and architect adjudication.

## Run Readiness And Closeout

Lead status updates and closeouts with the outcome, project goal in words, changes,
checks and blockers. Use task titles with IDs. Name who acts next and what
that enables. State any gaps in ownership or verification. Say whether the
reader needs to decide and what their decision unlocks.

Use `templates/operator-handoff-packet.md` for the operator continuation packet in every closeout or handoff.
Put `Next executable Bead`, `Commit/push status`, and `Execution prompt` below the summary.

```bash
python3 scripts/validate_run_readiness_plan.py <plan.json>
python3 scripts/render_run_projection.py <plan.json> --projection run-sheet
python3 scripts/render_execution_status_report.py <inputs>
```

Before closing meaningful Beads, add a compact closure-memory comment. Record delivered work as `pending-acceptance`. A configured registered host posts the exact delivery and leaves the Bead open for a separate reviewer. [Independent hand acceptance](references/run-readiness.md#accepting-a-delivery-by-hand).
Verified completion through `qualified_closure.py` requires single-use host acceptance bound to the original dispatch, exact requirement baseline and candidate, exact original observations seen by the accepted final review, current policy and setup database identity, an adjudicator distinct from the executor, every required clearance and no open blockers or children. It records consumption intent in the host audit before the first Beads write. Failure or reopening never permits reuse. The narrative command below records a summary. [Closure requirements](references/run-readiness.md#verified-closure-library).

```bash
python3 scripts/close_bead_with_summary.py --bead <id> --disposition pending-acceptance --why "<short reason>" --who "<actors>" --what "<result>" --how "<validation>" --when "<date or commit>" --where "<repo/env>" --decision "<decision>" --evidence "<evidence>" --residual-risk "<risk>" --follow-up "<next>" --meaningful
```

Validate drafts with `python3 scripts/validate_operator_handoff.py --require-scoped-continuation <handoff.md>`.
Supply matching state when both scoped fields are `None`. [Scoped continuation](references/run-readiness.md#human-template).
