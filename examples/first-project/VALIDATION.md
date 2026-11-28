# First-project execution evidence

On October 15, 2026, the tutorial was exercised using an actual isolated CWO
installation and two separate fresh named-profile agent sessions, not a
reference-solution replay. The source baseline was `5b3c095` with the local
tutorial additions. No live user skill or global configuration was replaced.

Environment: Fedora Linux, Python 3.14.7, Git 2.55.0, Codex CLI 0.162.1, Beads
1.3.1 with embedded local Dolt. The source operator profile requested
`gpt-5.6-sol`; runtime metadata observed that exact model with `high` effort
inherited from the isolated configuration. A profile's requested model does not
establish availability on another account.

Observed sequence:

1. Installed the actual skill into a disposable Codex home. Installed and
   hash-verified the profile and launcher; installed/source content matched.
2. Created a new starter project, saved a disposable Git baseline, initialized
   Beads, and observed the intentional failing validator tests.
3. First fresh session repaired only the validator, recorded its accepted
   boolean-port decision, and created the CLI task with a validator dependency.
   Six original validator tests passed. No CLI was implemented in this phase.
4. A second fresh session read project files, HANDOFF.md and Beads, verified the
   accepted validator behavior before editing, then added the CLI and five
   subprocess tests. Independent execution passed all 11 project tests; valid,
   invalid and missing-file inputs returned 0, 1 and 2 respectively. Both tasks
   were completed with closure records.
5. Review strengthened the public starter's coverage (primitive roots,
   simultaneous invalid fields, whitespace and ignored extras). The final
   acceptance matrix was independently rerun against the live-produced utility,
   not merely the authored reference solution.

Limits: one configured Linux host and an authenticated existing account; not a
real-novice study, cross-platform test, worker qualification, throughput
benchmark, or cost-saving claim. Both sessions made multiple model/tool calls.
A rejected handoff patch occurred in the second session and was corrected
within that same scope before acceptance. Raw session logs and private paths
are deliberately not public documentation.

The starter/reference regression suite is independently repeatable with
`python3 -m unittest discover -s tests -p test_first_project.py -v`. This check
uses an authored solution and must not be described as repeating the live
two-session result. See the canonical [walkthrough](../../docs/get-started.html).

## Offline walkthrough rehearsal

On November 28, 2026, a fresh disposable project exercised the current
local workflow on Linux with Python 3.14.10, Git 2.56.1 and Beads 1.3.4
(embedded Dolt). The run used the authored reference solution in two phases
and reopened project files and task records at the handoff. The commands ran
in a network namespace without external access. The earlier October record
is the observed agent-session evidence.

| Step | Command and observed result |
| --- | --- |
| Create the starter and baseline | `python3 scripts/create_first_project.py PROJECT` created the project. The first `python3 -m unittest -v` ran 8 tests and exited 1 with `FAILED (failures=13, errors=7)`. The local `cwo-tutorial-start` tag recorded the untouched starter. |
| Initialize the local task database | `bd init --prefix cwo-demo --skip-agents --skip-hooks --sandbox` reported embedded Dolt. `bd ready --json --sandbox` returned `[]`. The setup produced no editor integrations or Git hooks. |
| Verify the validator phase | The authored validator passed all 8 starter tests. From the practice folder, the narrative helper posted `pending-acceptance` using its absolute script path. `bd where --json --sandbox` reported the practice project’s local `.beads` directory and embedded Dolt storage. `bd ready --json --sandbox` listed only the validator while both tasks were open. |
| Accept and resume | `bd close VALIDATOR_TASK_ID --reason "Accepted after reviewing the validator diff and passing tests" --sandbox` closed the validator only. `bd ready --json --sandbox` then listed the CLI task. The handoff and validator tests were checked again before the CLI edit. |
| Verify the CLI phase | `python3 -m unittest -v` passed 13 tests, including 5 subprocess checks. `python3 checker.py service.json` printed `valid` and exited 0. `invalid.json` reported `port must be an integer from 1 to 65535` and exited 1. `missing.json` exited 2. The original validator tests remained byte-for-byte unchanged. |
| Inspect the final record | `bd show CLI_TASK_ID --json --sandbox` showed the CLI open with its validator dependency. `bd comments CLI_TASK_ID --json --sandbox` included the `pending-acceptance` delivery. The validator’s recorded acceptance and the final `HANDOFF.md` remained available. |

For both deliveries, the practice project was the working directory.
The absolute path to `close_bead_with_summary.py` pointed into the CWO source
checkout. The helper used local Beads discovery and ran with
`--disposition pending-acceptance --meaningful --json` and the complete
narrative fields. Each result reported `closure_memory_quality` as
`complete`, `closed` as `false`, and empty missing-field and warning lists.
The saved comment text matched the returned summary for each open task.

Beads 1.3.4 enables editor integration and hooks during ordinary
initialization, so the walkthrough skips those steps.
