# CWO architect prompt

The opt-in `architect` profile loads [the CWO architect prompt](../prompts/cwo-architect.md)
as replacement Codex base instructions in a fresh session. The architect defines
success, delegates through CWO, integrates results and leaves a handoff. Separate
review and CWO's verified-acceptance process handle acceptance.

## Behavior and authority

Continue independent work within the requested scope when a step is blocked.
Record the cause, follow the applicable runtime controls and present effects
reserved to the operator for their decision. No phrase grants or removes
authority. The [claims register](claims-register.md) and
[threat model](security-threat-model.md) describe the limits of CWO's controls.

For an experiment governed by a brief or immutable manifest, use the
[frozen protocol lock](frozen-protocol-lock.md) before costly dispatch.

## Install and verify

After [installing the CWO skill](../docs/install.html#install), use its installed
directory to install and verify the optional profile:

```bash
python3 scripts/manage_instruction_profile.py install --profile architect
python3 scripts/manage_instruction_profile.py verify --profile architect
```

Installation writes `cwo-architect.config.toml` with the single setting
`model_instructions_file`, a byte-for-byte copy of the prompt under
`$CODEX_HOME/prompts`, and the `cwo-codex` launcher. Verification checks the
managed files against their expected bytes. Inspect any reported differences
before forcing an overwrite or removal.

## Start a fresh CWO session

From your project, start a fresh session:

```bash
cwo-codex -C "$PWD"
```

The launcher reads model, reasoning effort and service tier from the Sol role
in [CWO's routing configuration](../policy/model-roles.yaml). To select the
same prompt with your own Codex settings, use:

```bash
codex --profile cwo-architect -C "$PWD"
```

Check the active settings in the new session. The profile is selected at
startup, so use a fresh conversation to activate it. An ordinary session can
use the installed CWO skill and its [practice walkthrough](../docs/first-project.html).

## Roll back

Start a fresh ordinary session with `codex -C "$PWD"`. To remove the managed
profile, prompt and launcher, run from the installed skill directory:

```bash
python3 scripts/manage_instruction_profile.py remove --profile architect
```

The skill remains available to ordinary sessions until disabled or removed.

## History

The overlay, Candidate C and both Candidate E prompts are archived under
[`prompts/archive/`](../prompts/archive/). Candidate E's guide and qualification
summary are in [`references/history/`](history/). The held three-arm study has a
frozen binding to `prompts/cwo-sol-operator-e.md`, which remains at that path
with its original bytes solely as a study input.
