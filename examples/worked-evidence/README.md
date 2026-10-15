# Inspectable evidence exercises

These are authored, deterministic fixtures, **not** measured CWO-agent runs or
actual reviewer transcripts. They exercise a genuinely contradictory pair of
retry proposals, local-file rollback after an intentionally simulated failed
health check, and source-note-to-decision traceability. Nothing accesses a live
service, changes infrastructure, or makes a model call.

From the CWO source checkout:

```bash
python3 examples/worked-evidence/run_examples.py --check
```

Expected: JSON containing a rejected two-effect POST retry, an accepted
single-effect POST, `rollback_verified: true`, and the research memo excluding
unsupported note N3. Generated lab files and memo are isolated in a temporary
directory and removed afterward; the output contains their meaningful content.
If an assertion fails, inspect the named exercise; do not run a production
rollout to make the demonstration pass.

The [worked examples guide](../../docs/use-cases.html) supplies initiating
prompts, scope, operator decisions, record excerpts, acceptance, recovery and
non-fit. The [first project](../first-project/) is the separate two-session live
agent exercise. Fixture checks are not integration qualification.
