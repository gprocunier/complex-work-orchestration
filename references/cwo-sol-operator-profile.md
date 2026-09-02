# Opt-in C Sol operator profile

Candidate C is the compact opt-in architect contract.
`cwo-sol-operator-experimental` is retained as the installed profile name for
compatibility. It replaces the model instruction file only when the profile is
selected at the start of a new Codex session.

The profile manager does not edit `config.toml`, so ordinary Codex sessions
launched without this named profile remain unchanged. CWO policy,
schemas, hooks, supervisors, disclosure gates, and other trusted enforcement
also remain in force; model instructions are behavioral guidance, not authority.

## Install

Run the manager from the root of this repository. To use a non-default Codex
home, export `CODEX_HOME` before running any command on this page.

```bash
python3 scripts/manage_instruction_profile.py install --profile operator
```

The command installs the C profile and its prompt without changing the
Candidate E `cwo-codex` launcher.
Successful JSON
output reports `"default_profile_changed": false`. If a managed file already
exists with different contents, the manager stops rather than overwriting it.
Inspect the file before deciding whether an explicit `--force` is appropriate.

## Verify

Verify the installed files against the repository sources before launch:

```bash
python3 scripts/manage_instruction_profile.py verify --profile operator
```

Success exits with status 0, reports `"ok": true`, and shows matching expected
and actual SHA-256 hashes for the profile and prompt. A missing or changed file
exits with status 2; do not launch the profile until that drift is understood.

## Launch a fresh session

Open a terminal in the workspace that Codex should operate on, then run:

```bash
codex --profile cwo-sol-operator-experimental -C "$PWD"
```

Profile selection happens when this new Codex session starts. Installing the
files does not switch an already-running session, and resuming an older session
does not turn it into an arm C trial. Use a new session for each trial and keep
the verification output with the trial record; model self-report is not proof
that the profile was selected.

## Roll back

First leave the profiled session. Starting a new ordinary session without the
named profile is the immediate behavioral rollback:

```bash
codex -C "$PWD"
```

To remove the opt-in profile files as well, return to the root of this
repository and run:

```bash
python3 scripts/manage_instruction_profile.py remove --profile operator
```

Removal reports the prompt and profile as `removed` or `absent` and again reports
`"default_profile_changed": false`. It refuses to delete a locally modified
managed file unless `--force` is supplied. Inspect and preserve unexpected
changes instead of forcing removal by default. It does not remove the Candidate
E `cwo-codex` launcher, rewrite `config.toml`, or weaken trusted CWO enforcement.
