# Operator Handoff Packet

Use this packet in the final TUI response for CWO closeout, sprint parking,
blocked work, pushed commits, or carry-forward handoff. Beads comments and repo
artifacts are not a substitute for this user-visible packet.

- Recommended operator action: `<CONTINUE|EXECUTE|GO_REQUIRED|DECIDE|PIVOT|STOP>`
- Action to send: `<one exact user message appropriate to the selected action>`
- Next executable Bead: `<bead-id or none - stop condition met>`
- Why it is next: `<priority, dependency, validation, unblock, or stop condition>`
- What must NOT run yet: `<blocked, unsafe, unapproved, or out-of-scope work>`
- Commit/push status: `<commit, push, remote verification, or not requested>`
- Validation status: `<commands run, not run, or blocked>`
- Escalation rule: `<when to stop and ask the operator>`
