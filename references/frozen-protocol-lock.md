# Frozen protocol fidelity

Use a frozen protocol lock whenever a governing action brief or immutable
manifest prescribes an experiment controller, task family, candidate set,
scoring contract, budget, or decision rule. In this setting those fields are
scope boundaries, not summaries.

The lock prevents general steering such as “proceed,” “repair until complete,”
`full_auto`, or “step over blocking ceremony” from silently becoming authority
to replace a benchmark. Such steering may continue the locked run or authorize
a same-scope mechanical repair. It does not change the locked experiment.

## Artifacts

Create two JSON-compatible artifacts:

- `cwo-frozen-protocol-lock:v1`, validated by
  `schemas/frozen-protocol-lock.schema.json`; and
- `cwo-frozen-protocol-run:v1`, validated by
  `schemas/frozen-protocol-run.schema.json`.

Seal the lock with
`cwo_core.frozen_protocol.seal_frozen_protocol_lock()`. Bind at least the
governing prompt, controller, manifest, complete run contract, and decision-rule
digest. `scenario_count * len(arms)` must equal `initial_cells`.

The following run-contract fields are always immutable:

- controller and manifest;
- tasks and prompts;
- scoring and thresholds;
- aggregate budget; and
- decision rule.

The lock also prohibits benchmark, task-family, and controller substitution.
An explicitly authorized replacement still returns `new-protocol-required`; it
must receive a new protocol ID, lock, readiness evidence, and candidate-evidence
boundary instead of overwriting the old campaign.

## Execution bindings versus provenance

`governing_prompt` and `execution_bindings` are live fail-closed gates. Their
current files must match the frozen hashes before dispatch.

`authoring_provenance` records contextual evidence used while designing the
protocol. It is deliberately not a live execution gate. A later legitimate
revision to a report or analysis document does not damage an already-frozen
controller; the original digest remains available for provenance.

## Steering and same-scope repair

Classify steering as one of:

- `continue`: no locked field changes;
- `same-scope-repair`: no locked field changes and one typed mechanical repair;
  or
- `replace-protocol`: always requires a new protocol lock.

Typed same-scope repairs are restricted to derived-cache cleanup, permission
restoration, controller transport, and stale-verifier repair. A different task
family, scenario count, controller, scorer, threshold, prompt, budget, or
decision rule is never a same-scope repair.

Validate before every costly dispatch and again after steering, interruption,
or context compaction:

```bash
python3 scripts/validate_frozen_protocol.py \
  protocol-lock.json \
  --run-spec run-spec.json \
  --base-dir "$PWD"
```

Only `protocol-ready` permits the separate dispatch-readiness process to
continue. The lock is necessary evidence, not dispatch authority.

## Derived bytecode drift

Repository-wide `compileall` can create `__pycache__` beneath a sealed tree.
Inspect it without changing source files:

```bash
python3 scripts/validate_frozen_protocol.py \
  protocol-lock.json \
  --run-spec run-spec.json \
  --base-dir "$PWD" \
  --cache-root path/to/sealed
```

If the only drift is ordinary `*.pyc` files directly under ordinary
`__pycache__` directories, the operator may use
`--repair-derived-cache` only while the run spec declares a
`same-scope-repair` with repair class `mechanical-derived-cache`. The cleanup
refuses symlinks, nested directories,
mixed content, stray bytecode, and roots outside `--base-dir`. After cleanup,
all live execution hashes must still pass. Suspicious drift remains blocked.
