# Prompt Coach Operator Guide

Use the prompt coach when a user is unsure how much of
`$complex-work-orchestration` to invoke.

The prompt coach is a compiler, not a second router. It calls the same policy
router as `scripts/route_work.py`, then emits a right-sized launch prompt,
missing high-value questions, bounded interactive questions, enabled levers,
disabled levers, warnings, `beads_tracking_required=true`, and the underlying
route result.

## Basic Use

```bash
python3 scripts/coach_prompt.py \
  "Plan a multi-session cleanup of installer docs, tests, and handoff notes."
```

For automation:

```bash
python3 scripts/coach_prompt.py --json "<task text>"
```

## Output Levels

- `in-thread`: handle the work in the current thread with one durable Beads
  task; no full harness.
- `lightweight-beads`: create durable Beads state without contractor/local
  worker lanes.
- `full-harness`: use architect, PM, workerbee, validation, and handoff lanes.
- `external-contract`: create a contractor-only lane after explicit opt-in.
- `local-worker`: create a bounded local-worker review lane after explicit
  local opt-in.
- `publish-release`: include validation and publish-sanitization before any
  push, release, or tag.

Explicit scaffold requests such as `Use $complex-work-orchestration to scaffold
this project`, `full scaffold`, `PM coordination`, `workerbee`, `epic`, or
`contractor lanes` recommend `full-harness`. Contractor-lane or contractor
review language also asks for the outside-sharing boundary before any external
dispatch is allowed.

Local-worker language such as `vLLM`, `local worker`, or `OpenShift AI` asks for
local-worker opt-in before dispatch. Without `--local-ok`, the conservative
default is current-thread execution with Beads tracking and local-worker
dispatch disabled.

Publish, release, GitHub, tag, and upstream-push language recommends
`publish-release`; the generated prompt must include validation evidence and
publish-sanitization before any formal push, release, or tag.

## Missing Questions

The coach asks only for information that materially changes sizing:

- concrete goal and success criteria
- repo, paths, or components in scope
- whether the mandatory Beads record should stay as one task or expand into an
  epic/work graph
- outside-sharing boundary for Claude, Opus, Mythos, or another external model
- local-worker opt-in and local profile
- validation bar for security, production, publish, or release work

Default assumptions are included so the operator can proceed conservatively when
the user does not answer.

## Interactive Questions

The JSON result includes `interactive_questions` when a user answer would change
execution behavior. Each item is shaped for Codex Plan-mode selectable prompts:
a short `header`, stable `id`, question text, and two or three options. The
recommended option is first and its label ends with `(Recommended)`.

Use these questions for decisions such as:

- how much harness to use: current-thread execution with a Beads task,
  lightweight Beads, full harness, or publish-grade execution
- whether outside sharing is allowed: no sharing, redacted packet, or
  repo-readonly
- whether a local inference worker is allowed
- what validation bar to apply

In Default mode, do not simulate a multi-choice UI. Ask only the one concise
question that blocks safe execution, or apply the conservative default from the
coach output.

## Examples

See `examples/prompt-coach-examples.md` for narrow in-thread work with a Beads
task, lightweight Beads, full harness, external contractor, and OpenShift AI
vLLM local-worker examples.
