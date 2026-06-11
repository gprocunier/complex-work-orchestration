# Prompt Coach Examples

Use these examples to right-size `$complex-work-orchestration` before launching
the harness. All examples require Beads tracking; narrow work uses one Beads
task instead of a full harness.

## Narrow In-Thread Work

```bash
python3 scripts/coach_prompt.py \
  "Fix the typo in README.md and run the relevant docs check."
```

Expected sizing: `in-thread` with `beads_tracking_required=true`.

## Lightweight Beads Plan

```bash
python3 scripts/coach_prompt.py \
  "Plan a multi-session cleanup of installer docs, tests, and handoff notes."
```

Expected sizing: `lightweight-beads`.

## Full Harness

```bash
python3 scripts/coach_prompt.py \
  --requested-role architecture \
  "Refactor the orchestration control plane across routing, schema validation, docs, and CI."
```

Expected sizing: `full-harness`.

## Explicit Scaffold

```bash
python3 scripts/coach_prompt.py \
  'Use $complex-work-orchestration to scaffold this project.'
```

Expected sizing: `full-harness`.

## Contractor Lane Scaffold

```bash
python3 scripts/coach_prompt.py \
  'Use $complex-work-orchestration to scaffold this project with Beads epic, PM coordination, workerbee validation, and contractor lanes.'
```

Expected sizing: `full-harness` with an `outside_sharing_boundary` question
until the user explicitly chooses a sharing boundary.

The JSON output includes `interactive_questions` for Plan-mode prompts when the
recommended harness level, workerbee parallelism, sharing boundary, local
worker use, or validation bar needs user confirmation. Each question has two or
three options with the recommended option first.

## Parallel Workerbee Review

```bash
python3 scripts/coach_prompt.py \
  "Do a deep second pass on docs, GitHub Pages flow, routing policy, and tests."
```

Expected sizing: `publish-release` or `full-harness` depending policy route,
with `workerbee_parallelism.recommended_mode=review-only`,
`workerbee-parallelism=review-only`, and a Plan-mode
`workerbee_parallelism` question whose recommended option is
`review-workerbees`. Use Codex 5.3 Spark workerbees for bounded parallel
review/investigation lanes while the main thread keeps integration and final
acceptance.

## External Security Contractor

```bash
python3 scripts/coach_prompt.py \
  --external-ok \
  --share-boundary redacted-packet \
  --requested-role security \
  "Claude security review for contractor packet redaction and audit behavior."
```

Expected sizing: `external-contract`.

## OpenShift AI vLLM Local Worker

First-class in-Codex prompt:

```text
/plan Use $complex-work-orchestration prompt coach to size this work:
Use a local OpenShift AI vLLM worker to review a bounded README command example.
```

Advanced operator-shell equivalent after explicit local opt-in:

```bash
python3 scripts/coach_prompt.py \
  --local-ok \
  --prefer-local \
  --local-profile openshift-ai-vllm \
  --requested-role documentation \
  "Use an OpenShift AI vLLM local worker to review a bounded README command example."
```

Expected sizing: `local-worker`, with `local-worker-only`,
`no-codex-exec`, evaluator requirement, and architect adjudication.

## Local Worker Mention Without Opt-In

```bash
python3 scripts/coach_prompt.py \
  --requested-role documentation \
  "Use local worker vLLM to review README examples."
```

Expected sizing: `in-thread` with a `local_worker_opt_in` question and
local-worker dispatch disabled until the user opts in.

## Publish Release Gate

```bash
python3 scripts/coach_prompt.py \
  "Publish the skill to GitHub after release validation."
```

Expected sizing: `publish-release` with `publish-sanitization`, a validation
bar, and repository/path confirmation before any formal push, release, or tag.

## Public Docs Pages Editor Gate

```bash
python3 scripts/coach_prompt.py \
  "Create documentation plus GitHub Pages for a project using Diataxis."
```

Expected sizing: `publish-release` with documentation, web design, and
`contract-jd-editorial-reasoning`. The editor gate must check docs/pages flow,
Diataxis fit, redundancy, circular content, AI-slop wording, and publishable
narrative before publish sanitization.
