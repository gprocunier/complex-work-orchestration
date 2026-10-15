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

## Presentation update

The walkthrough is now split into preparation, installation, first task and
continuation pages. The observations above describe the earlier two-session run.
The split pages preserve its setup commands and accepted utility behavior; their
current navigation and rendering are checked separately. A new two-fresh-session
model execution of the split presentation has not yet been observed.
