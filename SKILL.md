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
implementation flow for execution, but still create or update one Beads task so
the work story, evidence, validation, and handoff are durable.

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

The installer does not build a tarball. It copies `README.md`, `LICENSE`,
`SKILL.md`, `AGENTS.md`, `agents/`, `policy/`, `templates/`, `experts/`,
`references/`, `schemas/`, `examples/`, `docs/`, and `scripts/` into the
selected skills directory. It checks for the Beads CLI (`bd`) and never treats
a missing Beads install as fatal. On Fedora/RPM-style hosts it prints package-install guidance,
including the public `greg-at-redhat/beads` COPR as a fallback when the user
does not have their own Beads package source. Set `BEADS_COPR` to print a
different COPR enable command. On other systems it prints a warning and leaves
the skill installed.

## Documentation

Use `README.md` as the human-facing operating guide for invocation, flow,
external contracting, job-description labels, and Beads requirements. Use
`policy/` as the machine-readable control plane, `templates/` for reusable Beads
bodies, `experts/` for discipline calibration, `schemas/` for helper output
contracts, `examples/` for smoke-test artifacts, `references/external-contracting.md`
when posting or reviewing outside model contracts,
`references/incident-response-playbook.md` for quarantine or suspected
sabotage, `references/prompt-coach.md` when sizing the invocation,
`references/redhat-expert-catalog.md` when selecting Red Hat product-focused
Distinguished Engineer lenses, and `references/contractor-brief.md` as the
briefing artifact given to an outside contractor with a specific Beads
assignment. Use `scripts/close_bead_with_summary.py` when closing meaningful
Beads so the final comment preserves compact agent-memory context before the
short close reason is recorded. Use `docs/workflows.html` for the publishable walkthrough of
Codex-native `/plan` invocation, prompt-coach sizing, Beads work-graph
creation, optional contractor or local-worker lanes, validation, and manual
`claude -p`, `gemini -p`, `agy -p`, or ChatGPT Pro browser contractor handoff
when external sharing is approved.
Use `docs/local-workers.html` for the first-class in-Codex local-worker flow,
including coach opt-in, OpenShift AI vLLM profile selection, dispatch envelope
generation, explicit `--execute-local`, return evaluation, and architect
adjudication. For public documentation, README/install docs, GitHub Pages,
site structure, or Diataxis work, route through documentation plus web-design when a
site/page is involved, then require the internal editor expert as the final
validation gate before publish sanitization. Public narrative pages must not
expose internal planning labels, contract labels, framework bookkeeping, or
editor-gate mechanics as reader-facing product copy; translate those details
into plain reader value unless the page is an explicit reference/operator
lookup.

The policy files intentionally use JSON-compatible YAML so helper scripts can
run with the Python standard library only.

## Role Model

Default roles:

- **Architect**: Codex 5.5 x-high if available. Owns decomposition, architecture, final integration, acceptance, release judgment, and escalation decisions.
- **Project Manager**: simpler model. Owns Beads task-graph hygiene, status, dependencies, assignments, stale-work detection, and handoff completeness. Coordinates; does not decide architecture.
- **Workerbee**: Codex 5.3-spark when available, otherwise the
  smallest available capable review model. Owns bounded investigation, focused
  patches, test triage, file search, evidence gathering, and narrow validation
  tasks.
- **Outside Contractor**: Claude or another external LLM. Receives one explicit bead/contract at a time, calibrated by a job-description label, and reports findings through Beads or a patch branch.
- **Gemini/Agy Architect Critic**: opt-in outside-contractor lane for
  `agy --model gemini-3.1-pro-preview` second-opinion critique of a Codex
  architect design. It uses `contract-jd-architecture-reasoning`, starts with a
  redacted packet by default, and produces evidence for evaluation and
  architect adjudication, not implementation authority.
- **ChatGPT Pro Master Reviewer**: opt-in browser-mediated outside-contractor
  lane for ChatGPT Pro 5.5 Extended Reasoning review of the final architect
  plan or total work packet. It uses `contract-jd-master-plan-review`, starts
  with a redacted packet by default, requires a share-link return, and remains
  evidence for Codex plan revision. It is separate from Deep Research.
- **Local Worker**: local OpenAI-compatible inference. Receives only low-risk
  local-worker review contracts after explicit `--local-ok`; output is evidence
  and still needs evaluator scoring plus architect adjudication.
- **OpenShift AI vLLM Worker**: named local profile selected with
  `--local-profile openshift-ai-vllm`. It uses an OpenAI-compatible endpoint
  configured by environment variables and is still treated as bounded
  local-worker evidence, not implementation authority.
- **Local Secure Reviewer**: local read-only reviewer for security, peer-review,
  sabotage-review, or repo-review contracts. It can inspect approved repo
  context locally, but has no web, shell, or repo-write authority and is still
  forbidden from normal Codex pickup.

The main thread remains the final decision owner. Escalate architecture changes,
scope changes, release decisions, destructive actions, secret handling, and
conflicting findings back to the architect.

## Startup Protocol

1. State whether the work is coherent in-thread or needs the harness. Beads tracking is mandatory either way; narrow in-thread work gets one Beads task.
2. If the right amount of harness is unclear, use the prompt coach before
   scaffolding. In Codex, this is normally triggered by a terse `/plan` request
   that asks for `$complex-work-orchestration` prompt coaching:

```text
/plan Use $complex-work-orchestration prompt coach:
<task text>
```

   Codex may run the helper behind the scenes to compile the launch prompt. Use
   direct script execution only for advanced automation, CI, troubleshooting, or
   an operator shell outside Codex:

```bash
python3 scripts/coach_prompt.py "<task text>"
```

   Use the coach output to avoid under- or over-leveraging Beads, contractors,
   local inference, peer review, workerbee parallelism, or
   publish-sanitization. The coach always includes a subagent parallelization
   choice in `interactive_questions`; surface it in Plan mode even when the
   recommended default is no subagents. If
   `workerbee_parallelism.recommended_mode` is `review-only` or `heavy-review`,
   use Codex 5.3 Spark when available, or the smallest available capable review
   model, for bounded parallel review or investigation lanes before automatic
   workerbee handling exists.
   Use implementation workerbees only when file ownership or workstream
   boundaries are disjoint.
   If the result includes `interactive_questions` and Codex is in Plan mode,
   present those as selectable prompts because the answer changes execution
   behavior. In Default mode, ask only the concise blocking question or apply the
   conservative default.
3. If the work is non-trivial, risky, or may use outside contractors, classify
   it against the policy. Read provider-conflict and peer-review fields as part
   of the result:

```bash
python3 scripts/route_work.py "<task text>"
```

4. If outside contracting may help, ask the third-party collaboration question
   unless the user already opted in. Default to `no-outside-sharing`; if the user
   permits sharing, re-run the route with `--external-ok --share-boundary <mode>`.
   Repo-readonly and patch-branch packet builds require
   `--allow-disclosure-escalation`, not just `--external-ok`.
   For local inference, use `--local-ok` and only add `--prefer-local` when
   low-risk local worker dispatch is the intended route. Use
   `--local-profile openshift-ai-vllm` to require the OpenShift AI vLLM
   executor profile.
5. Before launching agents, automatically clean stale harness-owned agent
   sessions and local state:

```bash
python3 scripts/cleanup_stale_agents.py --json
```

   The helper protects the current Codex process tree. It terminates only
   harness-owned stale sessions by default. Run it from the target workspace, or
   pass `--workspace-root <path>` when Codex was launched from a broader parent
   directory. Use `--terminate-unowned-codex` only when the operator explicitly
   wants to clean stale unowned Codex, Claude, or Agy processes in that
   workspace.
6. Check for Beads:

```bash
command -v bd
test -d .beads && bd ready --json || true
```

7. If Beads is available, initialize it when needed and check whether a Dolt
   remote is configured:

```bash
bd init    # only if this repo should own the work story and .beads is absent
bd dolt remote list
bd dolt pull    # only when a Dolt remote exists
```

8. If Beads has no Dolt remote, keep the graph local and do not claim it is
   synced. If Beads is unavailable, create the same task or graph structure in a
   temporary Markdown plan and say that durability is reduced.

## Scaffold Shape

Create one epic for the project goal, then create role/lane tasks under it.
Use dependencies to represent real ordering, not decorative hierarchy.

When helper scripts are available, prefer:

```bash
python3 scripts/scaffold_workgraph.py --title "<project goal>" --description "<scope>"
python3 scripts/spawn_expert_reviews.py --parent <epic-or-task-id> "<review scope>"
```

For validation or advanced automation, `scaffold_workgraph.py --dry-run
--format beads-graph` emits a JSON plan accepted by `bd create --graph`; normal
execution still creates Beads directly so native `skills`, `acceptance`,
`design`, and `notes` fields are populated.

Recommended lanes:

- Architect framing
- Project manager coordination
- Implementation workerbee lane
- Test/validation workerbee lane
- Review-only workerbee lane for parallel docs, policy, routing, validation, or publish-sanitization sidecar work
- Outside contractor lane with job-description contracts
- ChatGPT Pro master-plan review lane when explicitly requested before
  implementation handoff
- Peer-review lane when route output sets `peer_review_required=true`
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
bd dolt commit
bd dolt push    # only when a Dolt remote exists
```

Before closing a non-trivial Bead, add a final closure-memory comment. This is
required for epics, contractor or local-worker lanes, evaluation and architect
adjudication lanes, validation and publish-sanitization lanes, abandoned or
superseded work, and any task with a non-obvious technical decision. The close
reason should stay terse; the final comment should preserve disposition, why it
closed, key decisions, evidence, residual risk, and follow-up. Tiny mechanical
leaf tasks may rely on the close reason only when it fully explains the outcome.

Preferred helper:

```bash
python3 scripts/close_bead_with_summary.py \
  --bead <id> \
  --disposition completed \
  --why "accepted change validated" \
  --decision "kept close_reason terse and stored reusable context in the final comment" \
  --evidence "python scripts/validate_repository.py" \
  --residual-risk "none known" \
  --follow-up "none" \
  --close
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

Generated Beads should also populate native `bd create` fields:

```text
--skills      Required skills or expert lens
--acceptance  Concrete done criteria
--design      Approach, boundaries, and control model
--notes       Route summary, assumptions, and handoff context
```

When creating Beads manually, do not type literal `\n` into text fields. Use
real newlines through a heredoc, `--body-file`, `--design-file`, or shell
command substitution.

For outside-contractor tasks, also include:

```text
Contractor job description:
Contract labels:
Share boundary:
Output rule: Output-only by default; use the exact contractor return template.
Patch rule: patch-branch means diff/proposal unless direct mutation is explicitly authorized.
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
state. Packet generation must still record explicit opt-in with `--external-ok`
or `--opt-in-record`; model preference alone is not enough to export context.
Structured opt-in records may also include `allowed_providers` to constrain
which provider profile is approved.

Provider identity is part of contractor control. Executors are bound to provider
profiles in `policy/provider-registry.yaml`; route output can set
`provider_conflict_detected` and list domains such as frontier model work or
model-provider competition. Provider conflict forces peer review and architect
adjudication before findings can become implementation direction.

Every outside contract should have these guard labels:

- `contractor-only`
- `no-codex-exec`

Every local-worker review contract should have these guard labels:

- `local-worker-only`
- `no-codex-exec`

Add exactly one primary job-description label:

The `contract-jd-*` labels calibrate the reasoning lens for any contract-style
review lane. They are used by outside contractors, local-worker review beads,
peer-review gates, and editor gates; guard labels such as `contractor-only` or
`local-worker-only` still determine who may pick up the work.

- `contract-jd-general-reasoning`: independent second opinion, assumptions, tradeoffs, failure modes, and alternative approaches.
- `contract-jd-security-reasoning`: security-focused glance, threat model, privilege boundaries, input handling, authn/authz, secret exposure, dependency and supply-chain risk.
- `contract-jd-architecture-reasoning`: system design, boundaries, coupling, migration paths, data flow, long-term maintainability, and reversibility.
- `contract-jd-master-plan-review`: independent master review of the final
  execution plan or total work packet before implementation handoff.
- `contract-jd-reliability-reasoning`: operational failure modes, recovery, observability, rollout, concurrency, state, and incident risk.
- `contract-jd-performance-reasoning`: scaling behavior, algorithmic cost, resource pressure, hot paths, caching, and benchmark gaps.
- `contract-jd-docs-reasoning`: correctness, clarity, audience fit, missing warnings, examples, and publishability.
- `contract-jd-editorial-reasoning`: final public docs/pages editorial review for flow, documentation-architecture fit, redundancy, circular content, draft-like wording, and publishable narrative.
- `contract-jd-peer-review`: independent gate for contractor or local-worker
  returns when route output sets `peer_review_required=true`.
- `contract-jd-sabotage-review`: integrity review for suspected sabotage,
  malpractice, fabricated evidence, provider conflict, or boundary-breaking
  output.
- `contract-jd-domain-<name>`: any other discipline-specific contract, such as `contract-jd-domain-selinux` or `contract-jd-domain-api-compat`.

Use metadata to make the contract machine-readable:

```bash
body=$(cat <<'EOF'
Purpose:
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
Codex handling rule: Codex agents may coordinate, brief, and review this bead, but must not execute or close it as contractor work.
EOF
)

bd create "Claude Opus review: security-focused reasoning for <scope>" \
  --type task \
  --labels contractor-only,no-codex-exec,contract-jd-security-reasoning \
  --assignee external-claude-opus \
  --skills security,contractor-control,beads \
  --acceptance "Security findings cite evidence, mitigations are testable, and architect review remains required." \
  --design "Apply the security job-description lens within the approved share boundary; do not perform implementation work." \
  --notes "Share boundary: redacted-packet. Codex pickup: forbidden. Return channel: bd-comment." \
  --metadata '{"executor":"external-llm","codex_pickup":"forbidden","job_description":"security-focused reasoning","discipline":"security","share_boundary":"redacted-packet","return_channel":"bd-comment","architect_review_required":true}' \
  --description "$body"
```

Codex agents should use ready-work filters that exclude contractor and
local-worker contract work:

```bash
bd ready --exclude-label contractor-only --exclude-label local-worker-only --exclude-label no-codex-exec --json
```

Project-manager or architect dispatch may inspect contract work explicitly:

```bash
bd ready --label contractor-only --json
bd ready --label local-worker-only --json
bd show <id> --json
```

Do not ask outside models for raw chain-of-thought. Ask for conclusions,
assumptions, evidence, alternatives considered, risks, confidence, and
recommended next actions. The rendered contractor prompt must require output
only: no preamble, no internal action narration, and no hidden reasoning text.

Before giving a Bead to an outside model, build a packet through the gate:

```bash
python3 scripts/build_contractor_packet.py \
  --bead <id> \
  --executor external_security_reviewer \
  --share-boundary redacted-packet \
  --external-ok \
  --attest-packet \
  --format json \
  --output contractor-packet.json
```

For repo-readonly or patch-branch packets:

```bash
python3 scripts/build_contractor_packet.py \
  --bead <id> \
  --executor external_security_reviewer \
  --share-boundary repo-readonly \
  --allow-disclosure-escalation \
  --external-ok \
  --format json \
  --output contractor-packet.json
```

Treat `patch-branch` as a patch proposal boundary by default: the contractor may
return a diff, patch artifact, or branch reference for architect review. Direct
mutation of the active checkout requires an explicit Bead/operator
authorization and must be checked with a tracked-workspace mutation report.

The packet includes the matched Distinguished Engineer profile by default. A
packet without that profile is degraded and must be built with
`--degraded-context-justification`; dispatch still requires
`--allow-degraded-packet`. Multi-discipline reviews require multiple contractor
Beads, each with exactly one primary job-description label and one matching
profile. Pass `--epic <id>` when an epic exists so dispatch quotas are scoped
correctly. Use `--opt-in-record <path>` instead of `--external-ok` when opt-in
is recorded in a structured local JSON audit note. Preferred opt-in records use
`allowed_external_executors`, a timezone-aware `recorded_at`, optional
`expires_at`, optional `allowed_providers`, and project/epic/bead scope fields;
legacy `allowed_executors` records remain accepted. Packet build audits by
default; use `--no-audit` only for tests or dry rehearsals that must not
consume quota.

Generate the manual dispatch prompt from an approved packet. Do not claim that
this helper called the outside model automatically. Dispatch revalidates the
packet hash, executor, provider binding, opt-in basis, boundary, disclosure
stage, expert profile, mandatory exclusions, selected snippets, and artifact
whitelist before rendering. It also audits by default:

```bash
python3 scripts/dispatch_work.py --packet contractor-packet.json --mode manual
```

The prompt includes `CONTRACTOR RETURN TEMPLATE - COPY EXACTLY` and tells the
contractor not to include a preamble, internal action narration, or direct
checkout mutation claims unless explicitly authorized.

For ChatGPT Pro 5.5 Extended Reasoning master-plan review, use the dedicated
browser helper instead of `dispatch_work.py`. First assemble the final plan
bundle from `templates/master-review-plan-packet.md`; the packet must include
the execution plan, Beads graph summary, validation plan, repository evidence,
route/coach outputs, known risks, and open questions:

```bash
cp templates/master-review-plan-packet.md /tmp/master-review-plan.md
# Fill /tmp/master-review-plan.md with the actual plan and evidence.

python3 scripts/build_contractor_packet.py \
  --bead <id> \
  --executor chatgpt_pro_5_5_extended_reasoning_browser \
  --share-boundary redacted-packet \
  --external-ok \
  --job-description contract-jd-master-plan-review \
  --snippet-file /tmp/master-review-plan.md \
  --attest-packet \
  --format json \
  --output master-plan-review-packet.json

python3 scripts/chatgpt_browser_review.py \
  --packet master-plan-review-packet.json \
  --confirm-only \
  --json \
  > master-plan-review-confirmation.json

python3 scripts/chatgpt_browser_review.py \
  --packet master-plan-review-packet.json \
  --json \
  > master-plan-review-dispatch.json

python3 scripts/ingest_chatgpt_share_return.py \
  "$(jq -r '.share_url' master-plan-review-dispatch.json)" \
  --bead <id> \
  --dispatch-id <dispatch-id> \
  --packet-sha256 <packet-sha256> \
  --output master-plan-review-return.md
```

The browser config comes from `CWO_CHATGPT_BROWSER_CONFIG` or
`$HOME/.config/cwo/chatgpt-browser.json`; keep it outside the repo with mode
`0600` and operator-managed browser authentication. Do not put Google
credentials, browser session material, or private packet content in prompts,
Beads comments, audit logs, or public docs.
ChatGPT Pro reviews are expensive and slow, so the browser helper is
fail-closed by default. With `require_model_confirmation` enabled, it must
observe configured selectors proving both `model_label` and `reasoning_label`
before submitting the prompt. Treat a share link as valid master-review
evidence only when the dispatch result includes `model_attestation.status` of
`confirmed`. If the visible answer came from the wrong model or unproven effort,
record the invalidation in Beads and do not use it to revise the plan. Use
`--dry-run` before live Pro work and require
`model_confirmation_configured: true` in the summary.
When Cloudflare or account prompts require a normal browser session, launch
Chrome manually with the dedicated profile and a localhost remote-debugging
port, then set `connect_over_cdp_url` in the local config. CDP attach URLs must
be unauthenticated localhost URLs; do not expose the debugging port remotely.
If the ChatGPT sharing UI copies the public link directly to the OS clipboard,
the helper may read the local clipboard after pressing Share and accept only a
validated ChatGPT share URL. Do not grant ChatGPT page-side clipboard-read
permission for this workflow.

For direct route dispatch without a packet, pass `--dispatch-id` when the
operator needs quota checks, output, and audit entries to share a stable
identity.

After the contractor returns, evaluate the handoff before converting findings to
implementation work:

```bash
python3 scripts/normalize_contractor_return.py \
  --bead <id> \
  --dispatch-id <dispatch-id> \
  --packet-sha256 <packet-sha256> \
  --file contractor-return.md \
  --workspace-mutation-report mutation-report.json \
  --output contractor-return-bundle.json

python3 scripts/evaluate_return.py \
  --bead <id> \
  --file contractor-return.md \
  --workspace-mutation-report mutation-report.json
```

Evaluation emits `sabotage_score`, `malpractice_score`,
`peer_review_required`, `peer_review_status`,
`human_adjudication_required`, and `recommended_disposition`. If evaluation
returns `quarantine`, a high sabotage score, or a high malpractice score,
isolate the return, run peer review or local secure review as appropriate, and
require architect adjudication before any implementation dependency is created.
When an external CLI can see a checkout, use `scripts/workspace_mutation_guard.py`
to snapshot before the run and compare after it. If route policy requires peer
review or provider conflict is present, a contractor cannot dismiss that gate.

## Contractor Interaction

For Claude or another outside agent, use
`references/contractor-brief.md` as the reusable briefing artifact. Provide the
contractor with the file plus a specific bead assignment. The assignment packet
must name the job-description label and the discipline-specific review lens.

Contractor rules:

- start with `bd dolt pull` only when a Dolt remote exists, then
  `bd show <id> --json`
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

- harness decision: in-thread with Beads task, PM-only, or full architect/PM/workerbee/contractor setup
- prompt coach result when sizing was unclear: recommended level, missing
  questions, `beads_tracking_required`, enabled/disabled levers, warnings, and
  paste-ready prompt
- policy route: route class, task class, risk, data sensitivity, dispatch
  sensitivity, share boundary, provider conflict domains, peer-review status,
  selected experts, and recommended executor
- role roster with model/effort choices
- Beads task or epic/task list, with IDs when created
- dependency graph summary
- contractor-ready assignments
- dispatch, evaluation, and architect-adjudication requirements
- return normalization, sabotage/quarantine handling, and attestation/audit
  verification requirements when external or local contracts are used
- validation matrix
- escalation rules
- resume instructions using `bd ready --json`

For broad or risky work, do not begin worker execution until the user has seen
the scaffold unless they explicitly asked you to proceed end to end.
