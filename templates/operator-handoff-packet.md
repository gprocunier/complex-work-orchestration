# Operator Handoff Packet

Use this packet in the final TUI response for CWO closeout, sprint parking,
blocked work, pushed commits, or carry-forward handoff. Beads comments and repo
artifacts are not a substitute for this user-visible packet.

- Next action: `<specific work that can proceed now, or None>`
- Waiting on: `<affected work and specific dependency, or None>`
- Next executable Bead: `<bead-id or reason no Bead is ready>`
- Why it is next: `<priority, dependency, validation, or unblock>`
- Exact command/resume: `<copy-paste command>`
- Execution prompt: `<prompt to resume the next bounded lane>`
- What must NOT run yet: `<blocked, unsafe, unapproved, or out-of-scope work>`
- Commit/push status: `<commit, push, remote verification, or not requested>`
- Validation status: `<commands run, not run, or blocked>`
- Escalation rule: `<applicable project rule or how to follow up on the blocker>`

Record work that can proceed under **Next action** even when **Waiting on**
names a dependency for other work. Use `--require-scoped-continuation` to
validate both fields. If source-derived continuation state exists, pass
`--continuation-state <path>` to check both values against it. Provide that
state when both fields are `None` in a scoped packet. The JSON state has
`version` set to `2` and includes `next_action` and `waiting_on`, each as exact
text or `null` for absence. Project rules and runtime controls govern dispatch.

Validate historical handoffs without the scoped fields by omitting these flags.
