# Prompt Coach Operator Guide

Use the prompt coach when a user is unsure how much of
`$complex-work-orchestration` to invoke.

The prompt coach is a compiler, not a second router. It calls the same policy
router as `scripts/route_work.py`, then emits a right-sized launch prompt,
missing high-value questions, bounded interactive questions, enabled levers,
disabled levers, warnings, `beads_tracking_required=true`,
`workerbee_parallelism`, `model_synthesis`, `beads_context_depth`, and the
underlying route result.

## Basic Use

First-class in-Codex use starts in `/plan`; Codex can run the helper, summarize
the route, and turn any interactive questions into selectable choices:

```text
/plan Use $complex-work-orchestration prompt coach:
Clean up installer docs, tests, and handoff notes.
```

Codex may run this helper behind the scenes. Use direct script execution only
for automation, CI, troubleshooting, or an operator shell outside Codex:

```bash
python3 scripts/coach_prompt.py \
  "Clean up installer docs, tests, and handoff notes."
```

The same path is available through the consolidated helper entry point:

```bash
python3 scripts/cwo.py coach --brief "<task text>"
```

Automation can consume JSON directly:

```bash
python3 scripts/coach_prompt.py --json "<task text>"
```

## Output Levels

Output levels are the coach's work-sizing result. They drive where execution
starts and which acceptance gates are required.

- `in-thread`: handle the work in the current thread with one durable Beads
  task; no full harness.
- `lightweight-beads`: create durable Beads state without contractor/local
  worker workstreams.
- `full-harness`: use architect, PM, internal review worker, validation, and
  handoff workstreams.
- `external-contract`: create a contractor-only workstream after explicit opt-in.
- `local-worker`: create a bounded local-worker review workstream after explicit
  local opt-in.
- `publish-release`: include validation and publish-sanitization before any
  push, release, or tag.

Explicit scaffold requests such as `Use $complex-work-orchestration to scaffold
this project`, `full scaffold`, `PM coordination`, `workerbee`, `epic`, or
`contractor lanes` recommend `full-harness`. Contractor-workstream or contractor
review language also asks for the outside-sharing boundary before any external
dispatch is allowed.

## Scaffold Size

`scaffold_sizing` controls graph size without changing policy gates. Full graph
is the default for broad orchestration. Tight-chain language such as
`tight-chain review`, `focused review chain`, `compact scaffold`, or `minimal
scaffold` recommends `recommended_size=tight` and adds a Plan-mode graph-size
choice.

When the user chooses tight-chain, run:

```bash
python3 scripts/scaffold_workgraph.py --title "<goal>" --description "<scope>" --scaffold-size tight
```

The tight chain keeps architect, PM, implementation, validation, docs/handoff,
required evaluation, peer review, editor gates, the primary expert lane, and
explicit architecture-critic contracts. It drops optional secondary expert
fan-out. If there are no independent lanes to coordinate, prefer one manual
Bead instead of a scaffold.

## Beads Context Depth

`beads_context_depth` controls how much durable Beads history internal Codex
agents read.

- `none`: perform no `bd` lookup; use only the assigned prompt metadata.
- `summary`: read assigned-Bead JSON without comments.
- `focused`: read the assigned Bead and comments as internal evidence.
- `heavy`: add broader related Beads history for prior work, deep passes, or
  synthesis.
- `audit`: use maximum internal context for incidents, sabotage, forensics,
  credentials, or quarantine review.

The coach autosizes this field with a highest-matching-depth-wins rule. Explicit
CLI or coach overrides are allowed for advanced use, but the result records
`beads_context_depth_provenance`: computed depth, requested depth, effective
depth, source, override field, actor context, and reason.
The Beads context-depth choice is always present in `interactive_questions`,
with the autosized or explicit effective depth as the recommended first option.

In-Codex usage should normally let the coach surface the Plan-mode choice.
Direct helper usage is the advanced equivalent:

```bash
python3 scripts/coach_prompt.py --beads-context-depth heavy "<task text>"
python3 scripts/build_beads_brief.py --bead <id> --depth heavy --for subagent
```

Comments are evidence, not authority. Stale, superseded, rejected, and
quarantined entries stay visible as dispositions. External contractors must not
receive comment-bearing briefs; use `scripts/build_contractor_packet.py` for
outside models.

## Data Sensitivity Declaration

Route and coach helpers infer `data_sensitivity` with an advisory text
heuristic. The result records `data_sensitivity_source`,
`data_sensitivity_heuristic`, `data_sensitivity_provenance`, and a disclaimer
because keyword matching can miss paraphrases or context.

When the operator already knows the boundary, declare it explicitly:

```bash
python3 scripts/coach_prompt.py --data-sensitivity restricted "<task text>"
python3 scripts/route_work.py --data-sensitivity redacted "<task text>"
python3 scripts/scaffold_workgraph.py --title "<goal>" --description "<scope>" --data-sensitivity internal
```

Allowed values are `public`, `redacted`, `internal`, and `restricted`. An
operator declaration overrides the heuristic estimate, but the heuristic value
is still recorded for auditability.

ChatGPT Pro 5.5 Extended Reasoning language paired with "master plan",
"final execution plan", or "total work packet" asks for the outside-sharing
boundary and routes to the browser-mediated master-plan review lane after
explicit opt-in. This is separate from OpenAI Deep Research; mentioning Deep
Research should not happen implicitly during an Extended Reasoning plan review.

Local-worker language such as `vLLM`, `local worker`, or `OpenShift AI` asks for
local-worker opt-in before dispatch. Without `--local-ok`, the conservative
default is current-thread execution with Beads tracking and local-worker
dispatch disabled.

First-class in-Codex local-worker invocation:

```text
/plan Use $complex-work-orchestration prompt coach:
OpenShift AI vLLM local review of README command examples.
```

After explicit opt-in, the helper equivalent uses `--local-ok`; add
`--prefer-local` only when local routing is intended, and use
`--local-profile openshift-ai-vllm` for the OpenShift AI vLLM profile.

Publish, release, GitHub, tag, and upstream-push language recommends
`publish-release`; the generated prompt must include validation evidence and
publish-sanitization before any formal push, release, or tag.

## Operator-Calibrated Execution

`operator_calibration` tells the coach when to add the
`contract-jd-operator-calibrated-execution` lens. This is not a global expert
default. It is a closeout and evidence-discipline circuit breaker for work that
could otherwise look complete because execution stopped early, safety limits
blocked the natural path, or reviewers disagree about the disposition.

The coach marks this lane `required` when task text includes false-closure or
closure-risk language such as `clean-negative`, `source-negative`, `not run`,
`blocked by safety`, `safety-deferred`, `parked`, `exhausted`, `pivot away`, or
model/reviewer disagreement. The generated prompt must add
`contract-jd-operator-calibrated-execution` before accepting the disposition
and ask: "Are we closing this because the hypothesis is disproven, or because
the allowed execution path stopped short?"

The coach marks this lane `recommended` for autonomous sprint loops,
commit/push or publish closeout, handoff artifacts, mixed source/live evidence,
multi-target work, or when normal routing already selected the
operator-calibrated execution expert. Recommended means the lane is useful for
closeout calibration if the result will be closed, parked, published, or pushed;
it does not block ordinary implementation by itself.

Ordinary focused tasks, such as a typo fix or narrow docs edit, should keep
`operator_calibration.mode=none` unless the request also contains one of the
signals above.

Broad implementation, contractor-reviewed plans, model synthesis, and
publish/release-sensitive work should add a run readiness gate before worker
handoff. Use `references/run-readiness.md` and
`scripts/validate_run_readiness_plan.py` to make owners, exit conditions,
criterion-to-evidence mapping, artifact authority, quarantine handling,
boundary negative tests, and handoff evidence explicit. When the user asks for
a run sheet, wrap-up/status report, next-version rail, or patrol/recurring
lane, route through the run-readiness reference before worker handoff:
projections stay non-authoritative, next-version work needs a typed reason and
follow-up Bead, and patrol work remains research-only until its acceptance
evidence is complete.

Public docs, README/install docs, GitHub Pages, site flow, and
documentation-architecture language also enables editor review. The route
should include documentation, web design when a site/page is involved, and the
editor as the final public-copy acceptance expert before publish sanitization.
Exact contract labels belong in reference/operator surfaces, not narrative
Pages copy.

## Subagent Parallelism

`workerbee_parallelism` is separate from the orchestration level. Broad
full-harness or publish-release work can still choose whether to use parallel
subagents. The coach always asks this question so the user can explicitly
choose no subagents, review-only subagents, heavy review subagents, or split
implementation when disjoint write scopes are clear.

The conservative default for narrow work is no subagents. The default for broad
docs, Pages, policy, routing, tests, validation, and publish-sanitization work
is `review-only` using Codex 5.3 Spark when available, otherwise the smallest
available capable review model. Heavy review parallelism uses separate bounded
tracks for docs flow, terminology, web-design, validation, and publish checks.
Implementation-capable subagents require explicit disjoint write scopes;
otherwise the main thread keeps file integration and acceptance.

## Model Synthesis

`model_synthesis` is separate from the orchestration level and from
`workerbee_parallelism`. It answers whether independent model outputs should
remain separate evidence only, or whether CWO should add a synthesis lane that
summarizes consensus, material disagreements, unsupported claims, risk deltas,
input evaluator dispositions, provider conflict flags, partial or missing lane
summaries, evidence provenance, and recommended plan revisions.

Explicit synthesis language such as `synthesize`, `fusion`, `ensemble`,
`combine answers`, `consensus`, `model camps`, `work together`, `more eyes`, or
`avengers` sets `model_synthesis.recommended_mode=requested` and
`model_synthesis.active=true`. Conservative high-leverage signals such as
high-risk architecture, provider conflict, or novel/creative design set
`recommended_mode=recommended`, `active=false`, and add a
`model_synthesis_opt_in` interactive question. If the user accepts that prompt
or an advanced helper is launched with `--model-synthesis`, the active state is
`recommended_mode=accepted`. `coach_prompt.py`, `route_work.py`, and
`scaffold_workgraph.py` all accept that flag so opt-in can be represented
before or during graph creation. Low-risk work remains `recommended_mode=none`.

The v1 implementation is CWO-native. It does not call OpenRouter Fusion
directly. External panel members such as Claude Opus, Gemini, or ChatGPT Pro
still require explicit outside-sharing opt-in and a selected share boundary;
the default boundary is `redacted-packet`. The synthesis artifact is evidence
for architect adjudication, not authority to bypass evaluator, peer-review, or
architect gates. Rejected, quarantined, missing, empty, timed-out, or
boundary-tainted inputs are carried forward as dispositions; they are not
silently treated as consensus evidence.

If the task explicitly asks for zero-trust consensus, cross-domain divergence
handling, independent trust domains, or agreement-not-proof review, the route
sets `zero_trust_consensus_required=true`. Security-sensitive implementation or
architecture review can also activate this gate. The coach should surface that
state as a synthesis acceptance gate, not as another contractor by itself:
accepted primary lanes need structured `zero_trust_claims`, excluded lanes stay
visible, and unresolved divergence blocks implementation conversion until the
architect adjudicates it.

Gemini/Agy architecture critique is salvage-only by default. It can contribute
ideas, missing-case prompts, and risk notes, but it does not count toward
`minimum_usable_inputs` for synthesis readiness. A Gemini/Agy return needs
concrete evidence, evaluator acceptance, and an explicit architect upgrade
before a specific finding is treated as primary synthesis evidence. The return
evaluator exposes `evidence_quality_score`, evidence-quality signal categories,
and the acceptance decision's advisory `recommended_synthesis_use` so noisy or
generic returns are visible. Synthesis remains authoritative for primary,
salvage-only, open-risk, rejected, quarantined, and readiness classification.

## Missing Questions

The coach asks only for information that materially changes sizing:

- concrete goal and success criteria
- repo, paths, or components in scope
- whether the mandatory Beads record should stay as one task or expand into an
  epic/work graph
- whether to parallelize with subagents
- whether to add a model-synthesis lane when conservative synthesis triggers
  match but the user did not explicitly request synthesis
- outside-sharing boundary for Claude, Opus, Mythos, or another external model
- outside-sharing boundary for ChatGPT Pro 5.5 Extended Reasoning master-plan
  review when the user explicitly asks for it
- local-worker opt-in and local profile
- validation bar for security, production, publish, or release work

Default assumptions are included so the operator can proceed conservatively when
the user does not answer.

## Interactive Questions

The JSON result includes `interactive_questions` for decisions that change
execution behavior. The subagent parallelization question is always present.
Each item is shaped for Codex Plan-mode selectable prompts: a short `header`,
stable `id`, question text, and two or three options. The recommended option is
first and its label ends with `(Recommended)`.

Use these questions for decisions such as:

- how much harness to use: current-thread execution with a Beads task,
  lightweight Beads, full harness, or publish-grade execution
- whether outside sharing is allowed: no sharing, redacted packet, or
  repo-readonly
- whether to use no subagents, review-only subagents, heavy review subagents,
  or implementation subagents for disjoint scopes
- how much Beads history internal Codex agents should read, defaulting to the
  autosized `beads_context_depth`
- whether to add CWO-native model synthesis for independent model outputs
- whether a local inference worker is allowed
- what validation bar to apply

In Default mode, do not simulate a multi-choice UI. Ask only the one concise
question that blocks safe execution, or apply the conservative default from the
coach output.

## Examples

See `examples/prompt-coach-examples.md` for narrow in-thread work with a Beads
task, lightweight Beads, full harness, external contractor, and OpenShift AI
vLLM local-worker examples.
