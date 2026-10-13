# Operator Handoff Packet

Use this packet in the final TUI response for CWO closeout, sprint parking,
blocked work, pushed commits, or carry-forward handoff. Beads comments and repo
artifacts are not a substitute for this user-visible packet.

- Next executable Bead: `<bead-id or none - stop condition met>`
- Why it is next: `<priority, dependency, validation, unblock, or stop condition>`
- Exact command/resume: `<copy-paste command>`
- Execution prompt: `<prompt to resume the next bounded lane>`
- What must NOT run yet: `<blocked, unsafe, unapproved, or out-of-scope work>`
- Commit/push status: `<commit, push, remote verification, or not requested>`
- Validation status: `<commands run, not run, or blocked>`
- Escalation rule: `<when to stop and ask the operator>`

For a current campaign with a terminal or protected sub-operation, also supply
the scoped continuation fields below and validate with
`--require-scoped-continuation`. They describe a decision; they do not grant
dispatch authority. When a source-derived continuation-state artifact exists,
also pass `--continuation-state <path>` to catch a false generic approval ask.
That artifact is a consistency input, not authority. Historical handoffs remain
readable without these fields.

- Stopped operation: `<exact child, cohort, path, or parent operation>`
- Stop scope: `<child, cohort, execution-path, complete-task, or publication>`
- Continuation disposition: `<continue-authorized, material-decision, or complete>`
- Already-authorized next action: `<exact action or none>`
- Authority delta required: `<specific new authority or none>`
