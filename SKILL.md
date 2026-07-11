---
name: "complex-work-orchestration"
description: "Use for complex multi-session or multi-agent projects that need architect, project-manager, workerbee, contractor, Beads work-graph, validation, and handoff coordination."
metadata:
  short-description: "Orchestrate complex multi-agent work"
---

# Complex Work Orchestration

Use this skill to decide how much orchestration a task needs, then keep the
work durable through Beads, evidence, validation, and handoff.

## When To Use

Use CWO when any of these are true:

- the work spans multiple sessions, repos, environments, or agents
- the user asks for a coach, PM, architect, workerbee, contractor, model
  synthesis, prompt review, or handoff setup
- the work needs durable state beyond chat history
- multiple independent investigations can run in parallel
- release, lab, production, publication, or security risk needs final architect
  judgment

Do not use the full harness for a narrow single-thread fix. Use normal local
implementation flow for coherent execution, but keep one Beads task when the
project uses Beads. Beads tracking is mandatory for non-trivial work stories.

## Operating Defaults

- The main Codex thread is the final decision owner.
- External and local-worker outputs are evidence, not authority.
- Default share boundary is `no-outside-sharing`.
- Ask for outside sharing only when a contractor lane is materially useful.
- Use review-only workerbees before implementation workerbees unless ownership boundaries are disjoint.
- Default role split in connected-Codex work is: Codex 5.6 Sol for architecture, counter-review, and architect-adjudication reasoning; Codex 5.3 Spark for operative workerbee execution.
- Sol is not treated as the automatic external critic lane; it is internal architecture/control authority and is applied only by explicit external-review or internal counter-review requirement.
- In Default mode, apply conservative defaults unless the user explicitly asked for the coach.
- Explicit coach requests require presenting coach options before plan creation unless the user already requested execution.
- In Plan mode, surface coach questions whose answers change execution behavior, including subagent parallelism and Beads context depth.
- Keep model names and provider versions in policy. Prefer role-like executor
  aliases from `policy/executor-registry.yaml` when writing new docs or plans.

## First Moves

1. Decide the execution shape: in-thread, PM-only, tight-chain scaffold, or full
   harness.
2. If sizing is unclear, use the prompt coach:

```bash
python3 scripts/coach_prompt.py "<task text>"
```

3. If routing matters, classify the work:

```bash
python3 scripts/route_work.py "<task text>"
```

4. Clean stale harness-owned local agent state before launching agents:

```bash
python3 scripts/cleanup_stale_agents.py --json
```

Use `--workspace-root <path>` when the shell is above the target repo. Use
`--terminate-unowned-codex` only when explicitly authorized.

5. Check Beads and sync only when a Dolt remote exists:

```bash
command -v bd
test -d .beads && bd ready --json || true
bd dolt remote list
```

If Beads is unavailable, use a temporary Markdown plan and say durability is
reduced. Do not claim local Beads state is synced without a Dolt remote.

## Scaffold Choices

Use one manual Bead for narrow work. Use tight-chain scaffolds when the task
needs architecture, implementation, validation, and wrap-up without optional
fan-out:

```bash
python3 scripts/scaffold_workgraph.py \
  --title "<goal>" \
  --description "<scope>" \
  --scaffold-size tight
```

Use the full graph for broad, risky, multi-lane, contractor-reviewed,
synthesized, or release-sensitive work:

```bash
python3 scripts/scaffold_workgraph.py --title "<goal>" --description "<scope>"
```

`--dry-run --format beads-graph` renders a graph accepted by
`bd create --graph`; normal execution creates Beads directly.

## Bootstrap Policy Controls

- For every native-operative segment, use `policy/native-worker-execution.yaml` as the bootstrap policy.
- Sol remains architecture/adjudication only. Spark runs operative work.
- Operative worker segments start with a `no-tools` attestation gate. The gate must use trusted control-plane/session metadata; model self-report does not authorize work.
- Every operative task segment begins a fresh attestation boundary.
- `resume_agent` is forbidden by default. If explicitly waived, keep the segment quarantined until post-resume attestation exactly matches `gpt-5.3-codex-spark`.
- Missing or mismatched model attestation must quarantine output and trigger a fresh Spark redispatch.
- Durable continuation uses Beads checkpoint + fresh Spark worker, not operative agent resume.
- Realignment return requires: completed evidence, files touched, mutation state, decision required, bounded options, recommendation, remaining scope, and usage.
- In realignment, worker must stop mutating and await architect decision.
- Fix -> reload -> resume means reinstall/reload this skill, then resume from Beads. Never resume the operative agent session.
- Hard-stop returns for bootstrap policy are `needs-architect-realignment`, `budget-exhausted`, and `model-mismatch`.
- Sol operative break-fix is forbidden by default. A self-hosting CWO incident requires explicit operator approval in the current interaction, an audited Bead-scoped authorization with a heavy warning, and fresh Spark validation; the exception expires when that Bead closes and must never be selected automatically.

`scripts/check_native_worker_session.py` is the trusted monitor for native segment attestation; see
`references/execution-environments.md` for session-file lookup, segmenting, and exit-code
rules.

## Reference Map

- Human operating guide: `README.md`
- Prompt coach: `references/prompt-coach.md`
- External contracting and trust boundary: `references/external-contracting.md`
- Contractor briefing: `references/contractor-brief.md`
- ChatGPT Pro browser lane: `references/chatgpt-pro-browser.md`
- Execution environments and local inference: `references/execution-environments.md`,
  `references/local-inference.md`
- Zero-trust consensus: `references/zero-trust-consensus.md`
- Run readiness: `references/run-readiness.md`
- Beads hook display: `references/codex-beads-hooks.md`
- Incident response and quarantine: `references/incident-response-playbook.md`
- Red Hat expert catalog: `references/redhat-expert-catalog.md`
- Publishable workflow pages: `docs/workflows.html`, `docs/local-workers.html`

Use `policy/` as the machine-readable control plane, `templates/` for reusable
Beads bodies, `experts/` for discipline calibration, `schemas/` for helper
output contracts, and `examples/` for smoke-test artifacts.

## Contractor And Local Worker Gates

Outside contractor packets require explicit opt-in, one primary
`contract-jd-*` label, guard labels, share boundary, provider metadata, packet
validation, audit, return normalization, evaluation, and architect
adjudication. Build and dispatch through helpers:

```bash
python3 scripts/build_contractor_packet.py --bead <id> --executor <executor> --share-boundary redacted-packet --external-ok --format json --output contractor-packet.json
python3 scripts/dispatch_work.py --packet contractor-packet.json --mode manual
python3 scripts/normalize_contractor_return.py --bead <id> --dispatch-id <id> --packet-sha256 <sha> --file contractor-return.md --output contractor-return-bundle.json
python3 scripts/evaluate_return.py --bead <id> --file contractor-return.md
```

For ChatGPT Pro browser review, use `scripts/chatgpt_browser_review.py` and
require confirmed model attestation plus a share-link return before using the
result. For local inference, require `--local-ok`; use `--prefer-local` only for
low-risk work where a local review lane is intended.

Spark is native-only in this policy. Use native subagents with `gpt-5.3-codex-spark`
and enforce model attestation from trusted control-plane/session metadata.

Hard-stop if the attested actual model is missing or does not exactly match the
requested model (`gpt-5.3-codex-spark`). Do not substitute Sol or any other model.

Use `scripts/workspace_mutation_guard.py` around external CLIs that can see a checkout. Quarantine high-sabotage, high-malpractice, provider-conflict, and boundary-tainted returns until peer review and architect adjudication complete.

## Run Readiness And Closeout

Before broad implementation handoff, validate a run-readiness plan:

```bash
python3 scripts/validate_run_readiness_plan.py <plan.json>
python3 scripts/render_run_projection.py <plan.json> --projection run-sheet
python3 scripts/render_execution_status_report.py <inputs>
```

Before closing meaningful Beads, add a compact closure-memory comment. Prefer:

```bash
python3 scripts/close_bead_with_summary.py --bead <id> --disposition completed --why "<short reason>" --who "<actors>" --what "<result>" --how "<validation>" --when "<date or commit>" --where "<repo/env>" --decision "<decision>" --evidence "<evidence>" --residual-risk "<risk>" --follow-up "<next>" --meaningful --close
```

Before the final user-visible response for any CWO closeout, pushed commit,
parked sprint, blocked sprint, or carry-forward handoff, produce an operator
continuation packet. Artifacts and Beads comments do not satisfy this by
themselves; the final TUI response must include the packet. Use
`templates/operator-handoff-packet.md` and, when drafting to a file, validate it:

```bash
python3 scripts/validate_operator_handoff.py <handoff.md>
```

For closeout and resume guidance, use the existing continuation format in
`references/run-readiness.md`.

For closeout/handoff, retain the required fields:
`Next executable Bead`, `Commit/push status`, and `Execution prompt`.
