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
Each isolated test worker can import `cwo_core` directly from the checkout.

```bash
python scripts/run_parallel_unittest.py --workers 4 --verbose --shard-index 0 --shard-count 4
```

The repository validator reads required documentation terms from
`tools/ci/required-documentation.json`. When changing a documented contract,
update the affected phrases in the same change.

Run `python scripts/check_code_health.py` to compare the checkout with
`policy/code-health-baseline.json`. It checks Ruff F and E9 diagnostics and
core-to-CLI imports. For code under `scripts/`, it also checks broad exception
handlers, cross-module imports of private names, function complexity, function
length and control nesting. It checks missing parameter and return annotations
in registered and offline scripts and their pool qualification helpers.

New functions may span up to 100 lines and nest up to five control suites before
the check reports new debt. Existing entries that exceed these limits cannot
grow. Run `python scripts/check_code_health.py refresh` after reducing debt.
The refresh lowers allowances to the observed counts, so CI rejects a return
of a diagnostic that has been cleared.
Record reviewed definition moves in `policy/code-health-moves.json`. Use
`refresh --admit REASON` after review when a change needs new debt.

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
