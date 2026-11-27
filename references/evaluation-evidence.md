# Evaluation evidence

## Registered native single worker

The live qualification completed on November 24, 2026. Every required
behaviour passed across CWO v1.21.0 through v1.24.0 with Codex CLI 0.171.0.
The qualification record combines observations from those four releases and
counts 15 starts against a cap of 20.

- The worker produced the exact expected bytes, and the artifact validator
  accepted the output.
- An empty poll returned progress from the original child with zero bytes
  submitted or delivered to standard input. In a separate check, the poll
  refused the one byte submitted and delivered zero bytes.
- An attempted write outside the workspace was refused before a tool process
  started. The test file kept its device, inode and bytes.
- The signed step limit triggered closure and the full reservation charge.
  The qualification also verified turn archiving, exit and reaping of the
  original app server, and retirement of its receipt.

[Single-worker promotion](https://github.com/gprocunier/complex-work-orchestration/pull/149) · [Final qualification release](https://github.com/gprocunier/complex-work-orchestration/tree/v1.24.0)

## Contained worker pool

On November 26, 2026, the live pass record for CWO v1.45.0 reported all 13
required behaviours passed for the observed disposable two- and three-worker
cohorts. The campaign used 45 of 45 permitted starts in total, including two
calibration runs and four productive runs on the final roster.

| Area | Passing observations |
| --- | --- |
| Concurrency | Two-worker concurrency and three-worker concurrency |
| Containment | Named profile in effect, refusal to widen its permissions, read-only workspace, and provider-only network access |
| Login custody | Dedicated worker logins and login-path denial |
| Work and isolation | Registered writer, shared budget, cross-worker isolation and failure isolation |
| Lifecycle | Cleanup |

The login-path check verified the active named profile and the mounted
read-only deny rule. No login read was attempted. Tool declarations are
informational and cover the observed worker turns. Session metadata describes
dynamic registration. An empty list can mean an empty declaration or missing
telemetry. Other requests, retained context, deferred tools and unlisted workers
are outside that inventory.

[Historical qualification procedure](https://github.com/gprocunier/complex-work-orchestration/blob/v1.45.0/references/native-supervision-pools.md#contained-qualification-on-stock-codex) · [Qualification release](https://github.com/gprocunier/complex-work-orchestration/tree/v1.45.0)

## Architect prompt small check

On November 22, 2026, the architect prompt ran once on each of 12 fixed tasks
using a dispatch stand-in. Eleven passed under the original criteria. The
remaining task failed a hidden assertion that required wording absent from
the task. Its output passed the hidden tests when only that wording assertion
was relaxed. One passing task added an unrequested README note.

The check recorded 9.15 million raw tokens, including 8.03 million cached
input tokens, and 1.12 million uncached input plus output tokens. The nominal
cap was about 1 million tokens and left the accounting basis unspecified.
The results apply to those 12 fixed tasks.

[v1.5.0 changelog](https://github.com/gprocunier/complex-work-orchestration/blob/v1.5.0/CHANGELOG.md#150---2026-11-22)

## Architect real-use trial

On November 26, 2026, one registered worker used CWO v1.39.0 to deliver two
editorial examples in a single 604-byte file in the CWO repository. The
worker finished in 94 seconds with one tool call. The runtime recorded the
delivery, turn archive and process termination. The trial logging wrapper
stopped before CWO received the delegation command. The host issued the same
approved command, and the first CWO invocation delivered the candidate.

The candidate verifier returned valid with zero errors. A separate review
confirmed that the candidate added only the expected file, preserved the
source facts and ordering, and kept the shell command byte for byte. The
operator accepted the original delivery from a separate foreground terminal.
The host recorded acceptance and closure against the same candidate and
original dispatch. The closed task references that acceptance event.

The worker recorded 30,808 tokens. The architect session recorded 179,516
tokens, including preflight and the initial logging failure. The trial covers
one editorial task.

[Trial release](https://github.com/gprocunier/complex-work-orchestration/tree/v1.39.0) · [Manual acceptance procedure](https://github.com/gprocunier/complex-work-orchestration/pull/244)

## Retired three-arm study

The retired three-arm study never ran. Its frozen design and synthetic
rehearsal records remain available in the [study archive](../evaluation/history/README.md).
