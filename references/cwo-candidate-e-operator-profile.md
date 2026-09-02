# Default Candidate E CWO operator profile

Candidate E remains the selected default architect contract. The interactive
profile preserves normal Codex tools and response formats while adding Candidate
E's acceptance, semantic-closure, projected-file, temporal-order, recovery,
quota, and frozen-protocol disciplines.

The terminal C/E/F qualification found no safety, completion, recovery, handoff,
or process advantage for any arm. E remains the default because it used the
fewest recorded tokens and least wall time across the final no-retry matrix.
Candidate C remains the compact opt-in alternative. This is a scoped repository
decision, not a universal ranking claim.

## Qualification and repair boundary

The exact prompt qualified by the final v5 matrix is archived at
`prompts/archive/cwo-sol-operator-e-v5-qualified.md`, SHA-256
`75b3bdf7624d7e3913f2879f4a20306c74805ad8409ce785597da67e1011c3f8`.
The active `prompts/cwo-sol-operator-e.md` is a post-v5 repair. It adds explicit
frozen-protocol fidelity after the operator incorrectly substituted a new
benchmark for an already-frozen controller under general continuation steering.

Deterministic regressions prove that the repaired profile and runtime lock now
reject benchmark, task-family, controller, and run-shape substitution; require a
new lock even for an explicitly authorized replacement; distinguish mutable
authoring provenance from execution bindings; and safely classify derived
`__pycache__` drift. No new model comparison has qualified the repaired prompt
bytes. The v5 result therefore explains why E was selected, while the archive
preserves exactly what v5 tested.

The production prompt deliberately excludes the qualification adapter's
tool-free rule, frozen inspection, campaign bindings, and exact JSON proposal
schema. Those remain task-specific controller contracts, not general operator
instructions.

When a governing brief or immutable manifest supplies an experiment protocol,
build and validate the lock described in
[`frozen-protocol-lock.md`](frozen-protocol-lock.md) before any costly dispatch.
Revalidate it after steering, interruption, or compaction. A
`new-protocol-required` result is a stop, not permission to substitute work.

## Install and verify

From this repository root:

```bash
python3 scripts/manage_instruction_profile.py install --profile operator-e
python3 scripts/manage_instruction_profile.py verify --profile operator-e
```

Installation creates the named Codex profile, a hash-bound prompt under
`$CODEX_HOME/prompts`, and the `cwo-codex` fresh-session launcher. It does not
edit `config.toml`, change ordinary Codex sessions, or alter the Candidate C
profile. Repository policy, schemas, hooks, and supervisors remain trusted CWO enforcement;
the prompt supplies behavioral judgment rather than authority.
The Candidate E profile intentionally does not set `model_reasoning_effort`.
It inherits the effort selected by the host or user so the profile cannot
silently override that choice. The Candidate C compatibility profile continues
to pin its historical `max` setting.
Drift causes install, verification, and removal to
fail closed unless the operator explicitly uses `--force` after inspection.

## Start a Candidate E session

Profile selection occurs only at the start of a new Codex session:

```bash
cwo-codex -C "$PWD"
```

The equivalent explicit command is:

```bash
codex --profile cwo-sol-operator-e -C "$PWD"
```

Resuming an older thread does not convert it to Candidate E. The next substantive
CWO task should serve as the adoption canary; record its outcome, interventions,
scope behavior, validation result, elapsed time, and token use without creating a
separate synthetic campaign.

The CWO skill default is Candidate E. It applies only to a fresh session
launched with this named profile; ordinary Codex sessions remain unchanged.

## Roll back

Immediate rollback is a fresh ordinary session:

```bash
codex -C "$PWD"
```

To remove the installed E profile and prompt:

```bash
python3 scripts/manage_instruction_profile.py remove --profile operator-e
```

Removal does not edit `config.toml` or remove the Candidate C profile. It also
removes the managed `cwo-codex` launcher when that launcher is unmodified.
