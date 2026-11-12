# Codex hook enforcement disposition

Hook-based enforcement is **unsupported and ineligible** on the pinned Codex
versions (0.163.0 and 0.162.0). This disposition completes the investigation on
the pinned versions, not the feature.

## Status

**Enforcement mode: refused.** Advisory hooks are permitted only for context
injection (Beads lifecycle hooks) where the output is treated as context, not
authority.

## Facts (pinned versions 0.163.0 and 0.162.0)

Source inspection of the pinned Codex versions (source at `c1382380`) establishes:

1. **PreToolUse leaves should_block=false** on execution or JSON failures, so it
   fails the proposed sole-gate fail-closed requirement.

2. **Stdin skips PreToolUse**. The separate stdin approval flow is conditional
   through `item/commandExecution/requestApproval` with `kind: "writeStdin"`.
   Schema support for stdin callbacks does not establish that every stdin write
   triggers one.

3. **PermissionRequest with no decision falls through to the reviewer**; an
   allow decision can bypass that reviewer. This is not equivalent to PreToolUse
   behavior where `should_block=false` on failure.

These facts do not mean every hook failure directly approves an action, but they
do mean the mechanisms are not equivalent and cannot provide fail-closed
enforcement on the pinned versions.

## Enforcement ineligibility

A future enforcement mechanism needs exact source/binary/config proof for:

- crash, timeout, malformed output
- missing invocation
- overrides
- every claimed tool/input path

Only after new eligibility evidence and explicit version qualification may
host-bound enforcement be implemented. The unsupported disposition recorded here
does not authorize enforcement on any version.

## Current permitted use

**Advisory hooks only**:

- Beads lifecycle hooks (SessionStart, UserPromptSubmit, PreCompact, PostCompact)
  inject saved project context for the model.
- Hook output is treated as context, never as permission grants or enforcement
  decisions.
- `configure_codex_beads_hooks.py` manages these advisory hooks.

**Prohibited**:

- Enforcement-mode hook configuration where hook output grants or denies
  permissions.
- Permission-granting hooks.
- Hooks that bypass or invalidate other required controls.
- Relying on hook behavior for security boundaries.

## Policy enforcement

Unsupported versions refuse enforcement-mode configuration.
`validate_advisory_hook_configuration()` in
`scripts/cwo_core/codex_hook_enforcement.py` is the single validation path. The
hooks writer, `configure_codex_beads_hooks.py` (before rendering and before
applying) and the access profile registry all call it. It accepts only a
positive allowlist and refuses everything else:

| Event | Group matcher | Exact commands |
|---|---|---|
| SessionStart | `startup\|resume\|clear` | `bd codex-hook SessionStart`, `bd prime --memories-only --hook-json` |
| UserPromptSubmit | none | `bd codex-hook UserPromptSubmit` |
| PreCompact | `manual\|auto` | `bd codex-hook PreCompact` |
| PostCompact | `manual\|auto` | `bd codex-hook PostCompact` |

- Hook type must be `command`. Hook keys are limited to `type`, `command`,
  `statusMessage` (a string) and `visibilityHint` (`quiet` or `verbose`).
  Commands match exactly, so shell chains, comments and another event's
  argument are refused.
- PreToolUse and PermissionRequest are refused by name, before their contents
  are inspected, citing the pinned versions in `policy/codex-protocol-pins.yaml`.
- Malformed structure is refused: a non-object document, a non-object `hooks`,
  groups that are not a list, unknown keys, empty hook lists and duplicate JSON
  keys in the hooks file.
- Named permission-granting fields (for example `grant_permission`) are refused
  with that reason.
- Access profiles may not declare `enforcement_hooks`; any profile `hooks` value
  goes through the same validation.
- The writer refuses a group that mixes a managed Beads command with other
  entries, because replacing that group would remove the other entries.

## Future eligibility

Any future host-bound hook implementation requires new exact-version eligibility
and source/runtime evidence. The pinned unsupported disposition remains in force.

## References

- Protocol pins: `policy/codex-protocol-pins.yaml`
- Capability matrix: `references/codex-protocol-capability-matrix.md`
- Advisory hooks: `references/codex-beads-hooks.md`
