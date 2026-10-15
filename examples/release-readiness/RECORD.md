# Release-readiness case: a JSON report without breaking the CLI

## Goal and result

Add an explicit machine-readable mode to the existing documentation-audit CLI,
while preserving human output, the `check()` list API and status meaning.
The local change added `--json`, then passed eleven focused tests. Its actual
successful report is saved in [report.json](report.json).

```sh
python3 scripts/check_documentation.py --json
# {"version": 1, "ok": true, "errors": []}
python3 -m unittest discover -s tests -p test_documentation_cli.py -v
```

Run from the supplied candidate checkout containing this change. At the October 15 observation, public main did not yet contain this candidate; inspecting the recorded run is separate from independently reproducing it. Use a checkout matching the source manifest. The [source snapshot manifest](SOURCE-SNAPSHOT.json) identifies the exact helper, tests and reproduction harness. This is a recorded local
maintenance task, not a published release or a canned decision-output script.

To repeat the observed encoding regression against the actual helper:

```sh
python3 examples/release-readiness/reproduce_encoding_case.py
```

This authored harness executes the real CLI in a temporary project under ASCII
stdout; it does not emit a prewritten decision or demonstrate orchestration.

## What independent review changed

The first isolated candidate passed eight tests, including an in-memory Unicode
check. The independent review identified an actual process-level counterexample:
a missing `café.md` link, UTF-8 source input and ASCII stdout. The candidate used
`ensure_ascii=False`, and actual reproduction raised `UnicodeEncodeError` instead
of emitting the report.

The lead accepted JSON's default escaping. It preserves the decoded diagnostic
without requiring stdout to encode every character. A forced-ASCII subprocess
regression now checks status 1, empty stderr and the original decoded filename.
Review also prompted exact Boolean/integer type assertions and real human-CLI
subprocess checks; equality with `True` alone would also accept the integer `1`.
The lead chose exact-only `--json` opt-in rather than argparse abbreviations.

Inspect the [implementation](../../scripts/check_documentation.py) and the
[independent acceptance checks in source](https://github.com/gprocunier/complex-work-orchestration/blob/main/tests/test_documentation_cli.py).

## Saved work and dependencies

The parent case was tracked before the prototype. Finer contract, implementation
and review records were added after initial prototype authoring, to gate accepted
integration. They are not evidence that no draft existed before those records.

| Actual local task | Accepted result |
| --- | --- |
| `complex-work-orchestration-jtz4.11.1` | Human output, list API, 0/1 validation status, usage status 2 and version-1 JSON shape |
| `complex-work-orchestration-jtz4.11.2` | Isolated implementation and actual subprocess checks; depends on the contract |
| `complex-work-orchestration-jtz4.11.3` | Independent review disposition, reproduced finding and corrected validation; depends on implementation |

CWO's contribution here was the bounded assignment, independent finding, saved
owner decision and prerequisite/evidence record. The standard-library CLI itself
does not perform orchestration. The owner implemented and integrated the change;
the specialist supplied read-only review rather than a writable patch.

## Acceptance and continuation

The corrected candidate passed eleven tests, including actual success/failure
reports, human-output compatibility, forced-ASCII Unicode, usage errors and exact
JSON types. The original validation logic and public list-of-errors API were
unchanged. `report.json` captures an actual CLI invocation, not prewritten output.

The [saved handoff](HANDOFF.md) records the source, accepted behavior and check commands. A fresh
agent continuation of this case has not yet been observed. The separate
[first-project run](../first-project/VALIDATION.md) supplies the earlier observed
two-session teaching example.

## Scope and limitations

Observed October 15, 2026 on one configured Linux host in an isolated complete
current-source copy, followed by integration of the accepted helper and tests.
This used independent internal specialist review, not productive native-worker
execution or native concurrency. Those routes were unavailable on the active
surface; no model substitution, weaker tool profile, live installation,
publication or deployment was used. Raw review/session records remain private.
