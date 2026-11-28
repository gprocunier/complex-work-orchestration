# CI validation

Hosted CI runs four unit-test shards on each supported Python version, 3.12 and
3.14. The required `test` check passes only when every shard, both Codex
protocol checks and the entire `quality` job pass. The `quality` job checks
repository content, documentation, worked examples, types and coverage.
Separate jobs run the Debian filesystem gate, CodeQL and ShellCheck.
[CI workflow](https://github.com/gprocunier/complex-work-orchestration/blob/main/.github/workflows/ci.yml)

Run these commands from the root of a CWO source checkout. Install the pinned
development tools from `requirements-test.txt` into a virtual environment for
each Python version. CWO's installed Python runtime uses the standard library.

Run the unit shards under each interpreter. For one shard at a time, use the
command below, changing the index from `0` through `3`.

```bash
python scripts/run_parallel_unittest.py --workers 4 --verbose --shard-index 0 --shard-count 4
```

Use Python 3.12 to reproduce the type and coverage checks from the `quality`
job. The strict type check starts with eight annotated helpers. Add modules as
they pass strict checking.
[Type-check configuration](https://github.com/gprocunier/complex-work-orchestration/blob/main/tools/ci/mypy.ini)

```bash
python -m mypy --config-file tools/ci/mypy.ini
python -m coverage run --rcfile=tools/ci/coverage.ini -m unittest \
  tests.test_public_copy \
  tests.test_process_identity \
  tests.test_process_lifetime_numeric_inputs \
  tests.test_workspace_inert_inspection.PathContractTests
python -m coverage report --rcfile=tools/ci/coverage.ini
```

The coverage report measures statements and branches in the public-copy,
process-identity and path-contract helpers. It lists missing lines and fails
below the 89% combined floor. Raise the floor as verified coverage improves.
[Coverage configuration](https://github.com/gprocunier/complex-work-orchestration/blob/main/tools/ci/coverage.ini)
