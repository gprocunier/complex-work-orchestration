# Disposable service configuration checker

This is a deliberately broken tutorial starter, not a production validator.
Run `python3 -m unittest -v` here; failures are expected initially.

Phase 1: `errors(config)` returns a list of messages, empty for valid input.
The root must be an object. The host must be nonempty text after trimming.
The port must be an integer (not a boolean) between 1 and 65535 inclusive.
Check host and port independently; missing both produces two messages.
Extra fields are ignored. Never connect to the named host.

Phase 2, in a fresh session: preserve that contract and add
`python3 checker.py service.json`. Print `valid` with exit 0 on success;
print errors with exit 1 for invalid config; print a readable message with
exit 2 for missing/unreadable files, malformed JSON, or wrong command usage.
Add subprocess tests for these cases. Do not install packages or use a network.

Keep `HANDOFF.md` and a local Beads work record describing what was checked,
the boolean-port decision, and the next dependency. Do not record credentials.
The [full walkthrough](https://gprocunier.github.io/complex-work-orchestration/get-started.html)
explains setup, continuation, diff inspection, and recovery.
