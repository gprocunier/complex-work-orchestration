# Sprint Continuation Brief

> Continuation artifact only. Beads has native epics and issues, not native
> stories or sprints. Stories and sprints are planning language represented by
> issue metadata, labels, descriptions, dependencies, status, and repo artifacts.

## Current Frame

- Epic: `<epic-id>`
- Sprint artifact: `<sprint-id or none>`
- Goal: `<sprint goal>`
- Durability: `<durable|reduced>`

## Recommended Next Issue

- Issue: `<issue-id>`
- Why next: `<priority, dependency, validation, or unblock reason>`

## Operator Handoff Packet

- Next executable Bead: `<issue-id or none - stop condition met>`
- Why it is next: `<priority, dependency, validation, unblock, or stop condition>`
- Exact command/resume: `<copy-paste command>`
- Execution prompt: `<prompt to resume the next bounded lane>`
- What must NOT run yet: `<blocked, unsafe, unapproved, or out-of-scope work>`
- Commit/push status: `<commit, push, remote verification, or not requested>`
- Validation status: `<commands run, not run, or blocked>`
- Escalation rule: `<when to stop and ask the operator>`

## Ready Work

- `<issue-id>`: `<title>`

## Blocked Work

- `<issue-id>`: `<blocker>`

## Evidence Expectations

- Commands and validation output.
- Changed artifacts or Beads issue ids.
- Closure-memory comment for meaningful issue closure.
- Residual risk and follow-up issue ids when work carries forward.

## Resume Commands

```bash
python3 scripts/cwo.py continue --epic <epic-id>
bd ready --exclude-label contractor-only --exclude-label local-worker-only --exclude-label no-codex-exec --json
```
