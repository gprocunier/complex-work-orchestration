# Operator Handoff Packet

## Status Summary

- Outcome: `<current result in plain language>`
- Goal: `<project or epic title in words>`
- Completed and verified: `<completed task titles with IDs in parentheses and what was checked>`
- What stands in the way: `<affected task titles, IDs and specific blockers, or No blockers are recorded.>`
- Next step: `<who acts next and the task title with its ID in parentheses, or No next step is needed.>`
- What it enables: `<named task or result this step enables, with any remaining prerequisites>`
- Reader action: `<Please and the exact decision needed and what it unlocks, or No decision is needed from you right now.>`

## Execution Details

- Next action: `<specific work that can proceed now, or None>`
- Waiting on: `<affected work and specific dependency, or None>`
- Next executable Bead: `<task title and ID or reason no Bead is ready>`
- Why it is next: `<priority, named dependency, or validation>`
- Exact command/resume: `<copy-paste command>`
- Execution prompt: `<prompt to resume the next bounded lane>`
- What must NOT run yet: `<blocked, unsafe, unapproved, or out-of-scope work>`
- Commit/push status: `<commit, push, remote verification, or not requested>`
- Validation status: `<commands run, not run, or blocked>`
- Escalation rule: `<applicable project rule or how to follow up on the blocker>`

Use this packet in the final response for closeout, sprint parking, blocked
work, pushed commits, or carry-forward handoff. Lead with the status summary.
For a task recorded as closed, say what evidence you checked. If none was
checked, say so. If no work is recorded as closed, write “No work is recorded
as closed. Verification was not checked.” If there is no next step, write
“No further work depends on a next step in this scope” under **What it enables**.
When work is blocked and the record does not assign a reader decision, write
“No decision is recorded for you.”

Record work that can proceed under **Next action** even when **Waiting on**
names a dependency for other work. Use `--require-scoped-continuation` to
validate the status summary and both fields. If source-derived continuation state exists, pass
`--continuation-state <path>` to check both values against it. Provide that
state when both fields are `None` in a scoped packet. The JSON state has
`version` set to `2` and includes `next_action` and `waiting_on`, each as exact
text or `null` for absence. Project rules and runtime controls govern dispatch.

Use `--require-readable-summary` for a current packet without scoped fields.
Validate historical handoffs without scoped fields or a status summary by
omitting these flags.
