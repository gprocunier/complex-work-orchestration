# Codex protocol and capability matrix

This matrix records what the host contract can rely on for a specific Codex
executable, and what is still an open question. Facts are pinned in
`policy/codex-protocol-pins.yaml` and checked by `cwo_core.codex_protocol_pin`
against schema bundles generated offline: no model call, no network, no Codex
configuration. A different executable or bundle matches no pin, so evidence
qualified against one pin does not carry over to it.

## Pinned executables

| Version | Status | Executable SHA-256 | Stable bundle | Experimental bundle |
|---|---|---|---|---|
| 0.163.0 | current | `399ff69c431c066e40de318fba45c2b07f45a76b19939d247ee4828fc70c4215` | 318 files, `89fe2000…3fff09` | 452 files, `d25388c6…01ccff47` |
| 0.162.0 | historical | `50ed828f357c655a3c82054d346cab8434f24901f14ec19b8267571bdd008b38` | 317 files, `317dfbf9…041d2eb` | 447 files, `d906641e…a205242c` |

The policy file holds the full digests, the generation commands
(`codex app-server generate-json-schema --out DIR`, and the same with
`--experimental`) and the per-file manifests under
`tests/fixtures/codex-protocol/`. Generating the 0.163.0 bundles twice gave
identical bytes. Every fact below holds for both versions.

## Classification

- **source-supported (schema):** stated by the schema Codex generates from its
  source, and checked against the pinned bytes.
- **fake-tested:** a test changes one value at a time and the check fails.
- **source-cited, not re-verified:** the remediation package cites Codex source
  at `c1382380`; no source checkout is available offline, so it is not
  re-verified here.
- **live-untested:** needs a running app-server, an effective configuration or
  an OS boundary. None was used.

## Matrix

| Question | Finding | Classification |
|---|---|---|
| Executable identity | Version text and SHA-256 must both match a pin. | fake-tested |
| Schema drift | A missing, extra or changed file, or a changed bundle digest, is reported; symlinks in a bundle are refused. | fake-tested |
| Capability opt-in | The `permissions` selector, `additionalPermissions` and `availableDecisions` exist only with `--experimental`; a stable client never sees them. | source-supported (schema), fake-tested |
| Named profile selector | `thread/start.permissions` names a profile and "cannot be combined with `sandbox`". Mapping to `default_permissions`, compilation and effective roots are not in the schema. | selector: source-supported (schema); mapping: source-cited, not re-verified |
| Approval envelope | `reason` is optional explanatory text. No `retry_reason`, `retryReason`, `sandbox_permissions` or `sandboxPermissions` field exists on command, file-change, exec or apply-patch approvals, stable or experimental. Identical reason text therefore cannot authenticate a retry class. | source-supported (schema), fake-tested |
| One-action versus session approval | Command and file-change approvals accept `accept` (one action) and `acceptForSession` (session-scoped cache); commands also accept execpolicy and network-policy amendments. The command approval response, reached from the `item/commandExecution/requestApproval` server request, requires `decision`, and its union is exactly four string values (`accept`, `acceptForSession`, `decline`, `cancel`) and two closed amendment objects (`acceptWithExecpolicyAmendment` with a string array, `applyNetworkPolicyAmendment` with a network policy amendment). An added integer, untyped or unknown branch, or a removed branch, fails the fact. Checked separately for the stable and the experimental bundle. | source-supported (schema), fake-tested |
| Approval correlation | Command approval requests always carry `threadId`, `turnId` and `itemId`. | source-supported (schema), fake-tested |
| Typed responses | Every server-to-client request has a response schema in its bundle. | source-supported (schema), fake-tested |
| Server request set | Exactly ten stable requests (eleven with `--experimental`, adding `currentTime/read`), including `item/permissions/requestApproval`. No separate server request exists for stdin approval; the existing command approval request handles both command and writeStdin kinds. | source-supported (schema), fake-tested |
| Approval kind | Command approval requests carry a `kind` field: `command` (default) or `writeStdin`. Both kinds use the same `item/commandExecution/requestApproval` server request. The check follows that request's params reference and `properties.kind` through its `allOf` reference to `CommandExecutionApprovalKind`, and requires exactly these two values and the `command` default, in both the server request schema and the standalone params schema. | source-supported (schema), fake-tested |
| Approval callback correlation | `approvalId` distinguishes multiple approval callbacks for one item. Stdin approvals and zsh-exec-bridge subcommands use distinct callback ids; regular approvals set this to null. Multiple callbacks can belong to one parent `itemId`. Runtime callback coverage remains unverified. | source-supported (schema), fake-tested |
| Stdin approval bypass | That ordinary stdin input bypasses approval even under denied reads is the package's source citation. Schema support for stdin callbacks does not establish that every stdin write triggers one. | source-cited, not re-verified |
| Reviewer routing and caches | `approvalsReviewer` overrides where approvals are routed for a thread; `acceptForSession` populates a session-scoped cache. Rule-loading paths and inherited grants are not in the schema. | routing fields: source-supported (schema); loading and inheritance: source-cited, not re-verified |
| Effective configuration | `config/read`, `configRequirements/read` and `permissionProfile/list` can be called without a turn. `config/read` does not require `turnId` in its stable params schema. Whether config/read reports the effective execpolicy is not established; an empty local rule file does not establish an empty effective policy. The experimental `ClientRequest.json` is not vendored, so experimental client parameter requirements (including `config/read`) are not yet qualified. | methods and stable parameter requirements: source-supported (schema), fake-tested; effective policy: live-untested; experimental client params: not yet qualified |
| Retry refusal versus approved escalation | Ordinary non-network retry refusal under denied reads, and write widening under approved escalation, are source citations. Platform enforcement is not established by source. | source-cited, not re-verified; OS enforcement live-untested |
| `strictAutoReview` | A nonempty turn-grant latch that forces Guardian review, not a client callback; ineligible as the no-grants stdin fix. | source-cited, not re-verified |
| PreToolUse fallback | Does not meet the fail-closed requirement (should_block=false on execution/JSON failures), per the package's source citation; not generalized to other hooks. | source-cited, not re-verified |
| PermissionRequest vs PreToolUse | PermissionRequest with no decision falls through to the reviewer; an allow decision can bypass that reviewer. This is not equivalent to PreToolUse behavior where should_block=false on failure. Hook-based enforcement is unsupported on the pinned versions. | source-cited, not re-verified |
| `native_capability.py` unused reads | Five reads bound nothing: `tool_surface_id`, `canary_session_id` and `advertised_models` in the base-state helper, and two leftover state variables. Each field is bound elsewhere: by the evaluation's completeness check, the session-evidence digest, receipt validation (including the authority's session) and receipt application. The reads are removed. Issuance names each failed authority binding with the same reason as validation, and each issuance and validation binding is changed alone, to a valid value, in a test that asserts its specific refusal. | fake-tested (one bound value changed at a time) |

## Remaining empirical questions

These need a running app-server, a real configuration or an OS boundary, so
they stay unqualified until a later slice answers them without a paid call.
They affect the named-profile candidate in section 6 of the host architecture
and every profile that relies on approvals:

1. Whether `config/read` and `permissionProfile/list` report the effective
   execpolicy, managed constraints and helper-readable paths, and whether a
   named profile compiles without fallback or warnings.
2. The profile fixtures the work order requires: missing or unknown names, no
   experimental capability, mixed selector and sandbox fields, effective-policy
   drift, root-deny transformation and narrow-deny write widening.
3. Fixtures for permission hooks, absent stdin callbacks, stripped experimental
   fields, and the strict-review cases (empty grants, invalid session scope,
   nonempty turn grants forcing Guardian).
4. Re-verifying the source-cited rows against a pinned Codex source checkout.
