# Local CLI case handoff

Accepted result: opt-in version-1 JSON reporting, preserving the human success
line, ERROR prefixes, check() list API and 0/1 validation status; usage errors are
status 2. Default JSON escaping handles Unicode diagnostics on ASCII stdout.

Source at the October 15 observation: the supplied unpublished candidate snapshot, identified by the hashes below. See [SOURCE-SNAPSHOT.json](SOURCE-SNAPSHOT.json) for the exact source hashes and reproduction harness.
- Helper SHA256: `852c5c0236e80f25cd45accc3b9b1dcd245809097e6185c8915a44683d338238`
- Focused tests SHA256: `0c0a467373158ac320f0bd5cad3879c4fe88b3172cb3ffb0fecdeb6d020718d9`

Validation commands, from a checkout containing this change:

```sh
python3 -m unittest discover -s tests -p test_documentation_cli.py -v
python3 scripts/check_documentation.py --json
```

The corrected candidate passed eleven focused tests and an actual report run.
Rerun those commands before relying on the saved result. The initial eight-test
result missed a process encoding failure; independent review prompted a real
reproduction and regression, not a weakened Unicode requirement.

Actual local tasks: contract `complex-work-orchestration-jtz4.11.1`; implementation
`complex-work-orchestration-jtz4.11.2`; review disposition
`complex-work-orchestration-jtz4.11.3`. The local Beads database is not distributed
with the source; use the saved record for this case, and your own task IDs in
your project. The parent case existed before prototyping; finer records later
gated accepted integration.

Next action for this bounded CLI change: none — local acceptance complete.
Publication and any broader release action are separate decisions.
Fresh-agent continuation and productive native-worker execution were not observed
for this case. The specialist route was internal read-only review.
