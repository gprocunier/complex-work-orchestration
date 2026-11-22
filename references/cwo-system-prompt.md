# CWO system prompt

The opt-in CWO profile loads a system prompt optimized for complex project work
in place of the default OpenAI system prompt. It directs the lead to advance
authorized work, check the result against acceptance criteria, recover from
in-scope failures, and record the evidence and next action.

For the complete setup and continuation journey, use
[Start Here](../docs/get-started.html). This reference owns prompt activation,
verification and removal, not a second beginner tutorial.

## Behavior and authority

The prompt keeps the session interactive. The lead makes routine in-scope
decisions, checks changed behavior through its consumers, and proceeds with
independent work when a prerequisite is outstanding. Explicit operator
authorization applies when the intended effect exceeds the authority already
granted, such as a material scope change, additional paid work, external
disclosure, or publication.

Routing configuration determines the model used for each role. The lead and
architecture role is `sol`, `astra` handles stronger independent review or
unresolved architecture, `luna` handles primary worker tasks, and `terra`
handles documented worker escalations. Use the selected route's own authority,
suitability, evidence, and budget checks. The shipped source holds apply
independently of model selection for registered native worker, pool and campaign
execution, live activation preview, new worker-surface qualification, live
browser dispatch and sharing, and live local invocation.

Delivered work awaiting verified acceptance is recorded as `pending-acceptance`
and stays open. For successful closure, an embedding host uses the verified
library with current, single-use host acceptance, an adjudicator independent
of the executor, and every blocker and child closed in the registered database.
The library checks the original dispatch, exact requirement baseline and
candidate, reviewed observations, current policy, and required hold clearances.
It reserves the acceptance before its first Beads write. Failed writes and
reopened tasks leave the acceptance spent. The shipped review-host producer
remains under a source hold. Confirm closure from Beads readback and the host
report. See
[closure and acceptance](run-readiness.md#verified-closure-library).

Trusted CWO enforcement comes from the host and the checks on supported
effect paths. Validators, hooks and supervision helpers are cooperative
where a lead can bypass the helper or rewrite its inputs; supervision helpers
do not independently poll or interrupt workers. Configured host audit verification
checks retained history against its private head checkpoint and segment seals;
legacy diagnostic logs lack that checkpoint and cannot provide host authority.
A same-account writer can erase that state or rewrite and rehash the host chain
and checkpoint.
These records do not authenticate the operator or supply an external anchor.
The [claims register](claims-register.md) and
[threat model](security-threat-model.md) describe those boundaries.

The prompt guides the lead's behavior; it cannot establish a sandbox, grant
publication permission or qualify a worker runtime. Source inspection, fake-effect
tests, operating-system observations and live runtime qualification are separate
evidence classes; none implies the others.

When a brief or immutable manifest supplies an experiment protocol, build and
validate the lock described in [frozen-protocol-lock.md](frozen-protocol-lock.md)
before every candidate or model call. Revalidate after steering, interruption
or compaction.
A `new-protocol-required` result calls for explicitly authorized replacement
scope, a new lock, and a new evidence record.

## Install and verify

After installing the CWO skill, run from this repository root:

```bash
python3 scripts/manage_instruction_profile.py install --profile operator-e
python3 scripts/manage_instruction_profile.py verify --profile operator-e
```

Installation creates the named Codex profile, an exact copy of
`prompts/cwo-sol-operator-e.md` under `$CODEX_HOME/prompts`, and the `cwo-codex`
launcher. It does not edit `config.toml` or change ordinary default-profile
settings. The profile's `model` comes from the connected Codex architect
binding for `sol` in the
[execution environment policy](../policy/execution-environments.yaml).

The profile does not set `model_reasoning_effort`. It inherits the effort
selected by the host or user. Verification compares exact bytes and reports the
expected and actual SHA-256 for the profile, prompt, and launcher. Retain the
prompt hash with the session evidence, and verify the actual profile selection,
model, and effort from the running session.

When verification reports drift, inspect the affected files. To replace a
reviewed older installation, rerun installation with `--force` and verify again.

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
