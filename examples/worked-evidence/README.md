# Run three small evidence exercises

These are authored, deterministic fixtures, **not** measured CWO-agent runs or
actual reviewer transcripts. They show how a retry can create duplicate jobs, how to restore a local
configuration after a simulated failed health check, and how to exclude an
unsupported source claim from a decision memo. Nothing accesses a live
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

The [worked examples guide](../../docs/use-cases.html) explains each problem,
provides a starting prompt and shows what the result does—and does not—establish. The [first project](../first-project/) is the separate two-session live
agent exercise. Fixture checks are not integration qualification.
