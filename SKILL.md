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

- The main thread decides; worker and contractor outputs are evidence.
- Default to `no-outside-sharing`; ask only when an outside lane adds material value.
- Prefer review-only workers before implementation unless write ownership is disjoint.
- In connected Codex work, Sol handles architecture and adjudication while Spark handles operative work. Sol is an external critic only when explicitly requested.
- Default mode is conservative. Explicit coach requests present coach options before plan creation unless execution was requested; Plan mode asks only questions that change execution.
- Keep model names and versions in policy and use executor aliases from `policy/executor-registry.yaml` in plans and docs.

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

## Proportional Fast Path

Use `scripts/evaluate_proportional_execution.py --brief <path>` only for one ignored, ephemeral, or non-publishable artifact under 500 lines, 12 calls, and 600 seconds when identity, model, tool scope, deterministic checks, false mutation/access flags, and closed architecture/security/policy decisions are explicit. Otherwise use standard native supervision.

Implementation packets use `operative-readiness:v2`: hashed path/selector context units and content-aware mutation evidence. Three units or six pre-mutation reads warn; four units or eleven reads require replanning.

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
- Native operative packets are emitted as version 2. Version 1 remains readable for historical inspection but is dispatch-forbidden.
- Every native operative worker requires `scripts/supervise_native_worker.py`. After trusted no-tools attestation, create and arm supervision before sending the task.
- Bind `arm`, native `send_input`, `mark-dispatched`, one-second checks, interrupt, close, and receipts to one control-turn ID and one uninterrupted tool-orchestration turn. No assistant/model round-trip may occur between task submission and the first check.
- Record dispatch and poll latency. Delay alone warns; missing trusted telemetry or control-turn binding is control loss.
- Healthy packet-contract failures allow one PM refinement and one bounded Sol replan within the original budget; recursive salvage and budget reset remain forbidden.
- `interrupt` or `control-lost` requires native interrupt, close, and receipts.
- Before packet build, evaluate operative work with semantic work-estimate contract v2. The estimate separates architect authority from operative routing and includes diff, behavior, state/schema, self-hosting/live-control, contract/CLI/policy/telemetry surfaces, test construction, command complexity, expected reads, mutations, and their ratio.
- Before packet build, use the trusted precommit supervisor and receipt-derived commitment v2; FSH.2 candidates remain non-operative until FSH.3. See `references/execution-environments.md`.
- During execution, use `scripts/cwo_core/native_progress.py` to compare planned and observed calls, runtime, tokens, reads, mutations, tests, and artifacts. Retained productive artifacts are not pure waste.
- The PM may autonomously refine a packet, ask the current architect one bounded reasoning question, or split material work within the original objective and aggregate allowance. These routine corrections do not require operator approval.
- Packet `scope.workdir` governs commands, mutation baselines, and receipts; ignore inherited worker cwd.
- Closure pressure starts at acceptance or independent validation. Continue the work unit, record `retain`, `correct`, `quarantine`, `defer`, or `close`, and reject routine repair children.
- Convergence ledgers and replays are append-only. Keep historical unknowns null and never rewrite prior evidence.
- Reports show absolute call categories and replay-target results.
- Main-thread model and effort recommendations are advisory. User selection is authoritative; mismatch alone cannot stop or pivot execution.
- Reserve protected stops for model, control, security, authority, mutation-attribution, contradictory-validation, or aggregate-budget boundaries.
- Route complex or mutation-sensitive commands through `scripts/run_checked_command.py`. Raw `python -c`, `bash -c`, and `sh -c` are not valid checked-command inputs; use typed Python or shell source.
- If the active tool surface cannot interrupt, close, wait, or expose trusted session telemetry, stop before dispatch. Do not substitute Sol or another model.
- Sol operative break-fix is forbidden by default. A self-hosting CWO incident requires explicit operator approval in the current interaction, an audited Bead-scoped authorization with a heavy warning, and fresh Spark validation; the exception expires when that Bead closes and must never be selected automatically.

`scripts/check_native_worker_session.py` provides retrospective/session checks;
`scripts/supervise_native_worker.py` enforces live packet-v2 limits. See
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

Every closeout or handoff response must include an operator continuation packet;
artifacts and Beads comments do not replace it. Use
`templates/operator-handoff-packet.md` and validate file drafts:

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

Follow `references/run-readiness.md` and retain `Next executable Bead`,
`Commit/push status`, and `Execution prompt`.
