# Prompt Coach Examples

Use these examples to right-size `$complex-work-orchestration` before launching
the harness. The first-class path is an in-Codex `/plan` request. Direct
`python3 scripts/coach_prompt.py` execution is the advanced helper equivalent
for automation, CI, troubleshooting, or an operator shell outside Codex.

All examples require Beads tracking; narrow work uses one Beads task instead of
a full harness.

## Narrow In-Thread Work

```text
/plan Use $complex-work-orchestration prompt coach:
Fix README typo; run docs check.
```

Advanced helper equivalent:

```bash
python3 scripts/coach_prompt.py \
  "Fix README typo; run docs check."
```

Expected sizing: `in-thread` with `beads_tracking_required=true`.

## Lightweight Beads Plan

```text
/plan Use $complex-work-orchestration prompt coach:
Clean up installer docs, tests, and handoff notes.
```

Advanced helper equivalent:

```bash
python3 scripts/coach_prompt.py \
  "Clean up installer docs, tests, and handoff notes."
```

Expected sizing: `lightweight-beads`.

## Full Harness

```text
/plan Use $complex-work-orchestration prompt coach:
Refactor routing, schemas, docs, and CI.
```

Advanced helper equivalent:

```bash
python3 scripts/coach_prompt.py \
  --requested-role architecture \
  "Refactor routing, schemas, docs, and CI."
```

Expected sizing: `full-harness`.

## Explicit Scaffold

```text
/plan Use $complex-work-orchestration prompt coach:
Full harness for routing, schemas, docs, and CI.
```

Advanced helper equivalent:

```bash
python3 scripts/coach_prompt.py \
  'Use $complex-work-orchestration to scaffold this project.'
```

Expected sizing: `full-harness`.

## Contractor Workstream Scaffold

```text
/plan Use $complex-work-orchestration prompt coach:
Full harness with contractor review for docs and validation.
```

Advanced helper equivalent:

```bash
python3 scripts/coach_prompt.py \
  'Use $complex-work-orchestration to scaffold this project with contractor lanes.'
```

Expected sizing: `full-harness` with an `outside_sharing_boundary` question
until the user explicitly chooses a sharing boundary.

The example uses legacy routing words that the coach still understands. In
reader-facing docs, describe the same choice as internal review workers and
contractor workstreams.

The JSON output includes `interactive_questions` for Plan-mode prompts when the
recommended harness level, sharing boundary, local worker use, or validation
bar needs user confirmation. The subagent parallelization question is always
present so the user can choose no subagents, review subagents, heavy review
subagents, or split implementation when scopes are disjoint. Each question has
two or three options with the recommended option first.

## Parallel Subagent Review

```text
/plan Use $complex-work-orchestration prompt coach:
Second pass on docs, Pages, policy, and tests.
```

Advanced helper equivalent:

```bash
python3 scripts/coach_prompt.py \
  "Second pass on docs, Pages, policy, and tests."
```

Expected sizing: `publish-release` or `full-harness` depending policy route,
with `workerbee_parallelism.recommended_mode=review-only`,
`workerbee-parallelism=review-only`, and a Plan-mode
`workerbee_parallelism` question whose recommended option is
`review-subagents`. Use Codex 5.3 Spark when available, otherwise the
smallest available capable review model, for bounded parallel
review/investigation workstreams while the main thread keeps integration and final
acceptance.

## Heavy Subagent Review

```text
/plan Use $complex-work-orchestration prompt coach:
Heavily parallelize docs, terminology, design, validation, and publish review.
```

Advanced helper equivalent:

```bash
python3 scripts/coach_prompt.py \
  "Heavily parallelize docs, terminology, design, validation, and publish review."
```

Expected sizing includes
`workerbee_parallelism.recommended_mode=heavy-review`,
`workerbee-parallelism=heavy-review`, and a Plan-mode
`workerbee_parallelism` question whose recommended option is
`heavy-review-subagents`.

## Model Synthesis

```text
/plan Use $complex-work-orchestration prompt coach:
Use model synthesis to combine Claude Opus, Gemini, and ChatGPT Pro findings
into consensus, disagreements, and recommended plan revisions.
```

Advanced helper equivalent after explicit outside-sharing opt-in:

```bash
python3 scripts/coach_prompt.py \
  --external-ok \
  --share-boundary redacted-packet \
  --requested-role architecture \
  --requested-role master-plan-review \
  "Use model synthesis to combine Claude Opus, Gemini, and ChatGPT Pro findings."
```

Expected sizing includes `model_synthesis.recommended_mode=requested`,
`model-synthesis=requested`, and a CWO-native synthesis lane when scaffolding.
The lane preserves separate model evidence, captures consensus and
disagreement, and remains input to architect adjudication.

## External Security Contractor

```text
/plan Use $complex-work-orchestration prompt coach:
Outside security review of packet redaction and audit behavior.
```

Advanced helper equivalent after explicit outside-sharing opt-in:

```bash
python3 scripts/coach_prompt.py \
  --external-ok \
  --share-boundary redacted-packet \
  --requested-role security \
  "Outside security review of packet redaction and audit behavior."
```

Expected sizing: `external-contract`.

## OpenShift AI vLLM Local Worker

```text
/plan Use $complex-work-orchestration prompt coach:
OpenShift AI vLLM local review of README command examples.
```

Equivalent shell command after explicit local opt-in:

```bash
python3 scripts/coach_prompt.py \
  --local-ok \
  --prefer-local \
  --local-profile openshift-ai-vllm \
  --requested-role documentation \
  "OpenShift AI vLLM local review of README command examples."
```

Expected sizing: `local-worker`, with `local-worker-only`,
`no-codex-exec`, evaluator requirement, and architect adjudication.

## Local Worker Mention Without Opt-In

```text
/plan Use $complex-work-orchestration prompt coach:
Local vLLM review of README examples.
```

Advanced helper equivalent:

```bash
python3 scripts/coach_prompt.py \
  --requested-role documentation \
  "Local vLLM review of README examples."
```

Expected sizing: `in-thread` with a `local_worker_opt_in` question and
local-worker dispatch disabled until the user opts in.

## Publish Release Gate

```text
/plan Use $complex-work-orchestration prompt coach:
Publish skill after release validation.
```

Advanced helper equivalent:

```bash
python3 scripts/coach_prompt.py \
  "Publish skill after release validation."
```

Expected sizing: `publish-release` with `publish-sanitization`, a validation
bar, and repository/path confirmation before any formal push, release, or tag.

## Publication Editorial Review

```text
/plan Use $complex-work-orchestration prompt coach:
Diataxis docs plus GitHub Pages.
```

Advanced helper equivalent:

```bash
python3 scripts/coach_prompt.py \
  "Diataxis docs plus GitHub Pages."
```

Expected sizing: `publish-release` with documentation, web design, and
editor review before publish sanitization. Narrative Pages should explain
reader value and workflow rationale; exact contract labels belong in
reference/operator lookup sections.
