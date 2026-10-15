# CWO system prompt

CWO uses a system prompt optimized for complex project work rather than the
default OpenAI system prompt. It directs the lead to define acceptance criteria,
preserve project decisions, check evidence, coordinate bounded specialist work,
and leave a usable handoff. This describes its intended workflow, not a guarantee
of better results on every task.

For the complete setup and continuation journey, use
[Start Here](../docs/get-started.html). This reference owns prompt activation,
verification and removal, not a second beginner tutorial.

## Behavior and authority

The prompt preserves normal interactive tools and response formats while adding
acceptance closure, semantic checks, complete change transactions, temporal
ordering, recovery, quota and protocol discipline. Repository policy, schemas,
hooks and supervisors remain trusted CWO enforcement; the prompt supplies
behavioral judgment rather than authority. Text cannot establish a sandbox,
grant publication permission or qualify a worker runtime.

When a brief or immutable manifest supplies an experiment protocol, build and
validate the lock described in [frozen-protocol-lock.md](frozen-protocol-lock.md)
before costly dispatch. Revalidate after steering, interruption or compaction.
A `new-protocol-required` result stops that operation; it does not permit a
replacement experiment under the old evidence boundary.

## Install and verify

After installing the CWO skill, run from this repository root:

```bash
python3 scripts/manage_instruction_profile.py install --profile operator-e
python3 scripts/manage_instruction_profile.py verify --profile operator-e
```

The profile and source filenames are stable compatibility identifiers, not
choices between competing prompts. Installation creates the named Codex profile,
a hash-bound copy of `prompts/cwo-sol-operator-e.md` under `$CODEX_HOME/prompts`,
and the `cwo-codex` launcher. It does not edit `config.toml` or change ordinary
default-profile settings.

The profile does not set `model_reasoning_effort`. It inherits the effort
selected by the host or user. Verify the actual model and effort in the running
session; a config file alone is not runtime evidence. Drift causes installation,
verification and removal to fail closed. Inspect modified managed files before
deciding whether an explicit `--force` is appropriate.

## Start a fresh CWO session

Select the profile at the start of a new Codex session:

```bash
cwo-codex -C "$PWD"
```

The equivalent explicit command is:

```bash
codex --profile cwo-sol-operator-e -C "$PWD"
```

Resuming an older thread does not activate the named profile or provide
profile-selection evidence. Explicitly reading and following the source prompt
is a fallback for a thread that cannot restart, but it is not named-profile
activation. The installed CWO skill remains available in ordinary sessions until
disabled or removed; that is separate from selecting the system-prompt profile.

## Roll back

Leave the profiled session and start a fresh ordinary session:

```bash
codex -C "$PWD"
```

To remove the managed profile, prompt and unmodified launcher:

```bash
python3 scripts/manage_instruction_profile.py remove --profile operator-e
```

Removal does not edit `config.toml` or remove the CWO skill or other profiles.
Preserve unexpected local changes instead of forcing removal by default.
