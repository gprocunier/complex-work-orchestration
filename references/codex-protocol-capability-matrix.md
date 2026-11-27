# Codex protocol and capability matrix

## Runtime protocol compatibility

Codex CLI 0.163.0 is the tested support floor. CWO also supports later releases
that provide the app-server methods, request fields, notifications and reply
shapes it uses. On startup CWO checks the installed executable's bounded,
offline schema exports in a disposable Codex home and names the capability on
refusal. A CLI version number alone never triggers a refusal.

The required CI check exercises this contract against 0.163.0 and 0.171.0. The
weekly workflow checks the current stable release. To run the same check with
the Codex CLI on `PATH`, use `python scripts/check_codex_protocol_capabilities.py`.
The command only exports schemas and checks their contents. Assessments of
worker identity, execution profiles and containment require their own evidence.

## Historical schema fixtures

`policy/codex-protocol-pins.yaml` and `cwo_core.codex_protocol_pin` identify and
verify the retained fixtures used for protocol comparisons. The policy's
`current` label identifies its reference fixture. Each measured executable or
bundle digest describes the recorded bytes and scope.

| Version | Fixture role | Observed executable SHA-256 | Stable bundle | Experimental bundle |
|---|---|---|---|---|
| 0.163.0 | reference | `399ff69c431c066e40de318fba45c2b07f45a76b19939d247ee4828fc70c4215` | 318 files, `89fe2000…3fff09` | 452 files, `d25388c6…01ccff47` |
| 0.162.0 | historical | `50ed828f357c655a3c82054d346cab8434f24901f14ec19b8267571bdd008b38` | 317 files, `317dfbf9…041d2eb` | 447 files, `d906641e…a205242c` |

The policy file holds the full digests, the generation commands
(`codex app-server generate-json-schema --out DIR`, and the same with
`--experimental`) and the per-file manifests under
`tests/fixtures/codex-protocol/`. Generating the 0.163.0 bundles twice gave
identical bytes. The historical schema findings below describe both fixtures.

## Selected qualification target

`policy/qualification-target.yaml` selects the **constrained-integrity** profile
and records **Codex CLI 0.163.0** as the minimum supported version.

The selected configuration is the native worker's `workspace-write` sandbox,
`approvalPolicy: never`, no network, and a bwrap host. Qualification must show
that the worker writes only its workspace, cannot change host records, policy
or receipts, and cannot retry or escalate without separate approval. These are
requirements for the selected target; effective configuration and enforcement
remain **unknown** for the full native worker route. The profile is selected
and unqualified. **Confidential** operation is **unsupported**: diagnostic read
denials do not establish a fully qualified native worker confidentiality boundary.

On 2026-11-14, no-model local observations confirmed the executable version,
executable hash and package-manifest hash of the standalone 0.163.0
`x86_64-unknown-linux-musl` package. The package entrypoint was `bin/codex` and
`codex-package.json` had SHA-256
`5fa8533bde21972564cbb2c665c99c6d6d0e92b625fa6f4fdf1354ac5fb71a78`.
Stable and experimental schema generation ran with empty `HOME` and `CODEX_HOME`
in bwrap with `--unshare-net`. Both complete bundle digests matched their
recorded fixtures. The observation covered identity and schema generation.

The machine-readable property matrix labels every row as **source-supported**,
**fake-tested**, **os-observed**, **unknown**, or **unsupported**, and links each
row to its evidence or stated limit. Source support can describe schema fields
or the host's requested configuration; fake tests establish check behavior.
Neither establishes platform enforcement. Unknown properties include effective
rules and grants, protected write roots, network denial, retries and escalation,
stdin gating, named-profile compilation, tool behavior and live model behavior.

`cwo_core.qualification_target.selected_target()` validates the document.
`target_for` checks the supplied profile and configuration descriptor. These
checks return policy metadata. The schema check addresses protocol compatibility,
and exact executable identity remains part of scoped worker or diagnostic
evidence. Existing live holds remain in force.

## Offline boundary diagnostics

`scripts/selected_native_containment.py` exercises a fixed catalogue through the
supplied executable's app-server `command/exec` API. It creates an independent
disposable repository, reads the effective configuration, and omits per-command
`sandboxPolicy` and `permissionProfile` overrides. It starts no thread, model
turn or live route, accepts no worker output and cannot promote an artifact.

The recorded 0.163.0 package diagnostics observed a useful shell command and
`git apply`, followed by prohibited effects through that same runner. The
app-server reported `workspace-write`, `never`, network off, an isolated user
configuration, an empty system configuration layer and no managed requirements.
Server diagnostic output during admission refuses the diagnostic. The wider
inventory of runtime grants, caches, hooks and helper paths remains unknown.

| Property | Disposition and scope |
| --- | --- |
| Filesystem and custody | Enforced in the fixed diagnostic and observed through real commands: controller records, host imports, policy and adapter paths are outside the worker mount view; executable, configuration, rules and independent Git metadata resist writes. A trusted gate checks effective mounts after filesystem setup and before the native command starts. Identity digests establish identity only. |
| Network and process access | The same command cannot reach matched live host TCP/Unix listeners, read host process memory, signal host processes or debug them. PID, user, mount and network namespace separation is observed independently. |
| Inherited access | A synthetic credential environment value and an inheritable descriptor are excluded. Host control sockets remain inaccessible. These bounded controls do not inventory every possible helper or credential source. |
| Finite input | The fixed command uses `streamStdin: false`. Nonempty polling refuses before RPC delivery; an empty poll observes useful output for the original connection-scoped process. Native model-tool `write_stdin` remains unknown. |
| Lifecycle | Original launcher and verified namespace pidfds bind each epoch. Actual controller death, detached descendants, watchdog death and deadline expiry stop the tested namespace. Restart uses a fresh owner; a stale receipt cannot terminate its successor. Private PID reuse has the two distinct scopes below; native model-worker and production recovery remain unperformed. |
| Primitive PID reuse | In the historical 2026-11-15 measurement, an original controller constructed after private namespace entry retained its atomic receipt and pidfd through controlled exit and external reaping. A fresh atomic sentinel received the exact reused numeric PID. The stale owner sent no signal or reap, the live sentinel heartbeat grew, and its fresh owner confirmed exit and reaping. This primitive control supplies no selected-executable evidence. |
| Exact diagnostic-launcher PID reuse | In the historical 2026-11-15 measurement, with the selected package and unchanged configuration, actual configuration reads and fixed no-model command/exec preceded reuse of the original launcher PID by a fresh fixed sentinel. The retained stale receipt/pidfd did not signal or reap that sentinel; live heartbeat growth and fresh cleanup were confirmed. This observes the diagnostic launcher, not a native model-worker/server/callback lifetime or production recovery. |
| Instructions | No prompt instruction establishes any diagnostic denial or custody property. Model compliance is not used as enforcement evidence. |
| Required unknowns | Model-turn builtin tools, their stdin and callbacks, ordinary retry versus approved escalation, complete effective grants/rules/helpers, native model-worker/server/callback PID reuse and production ownership/accounting/restart recovery keep the selected profile unqualified. Current local dependency and host fixtures do not establish those native properties. |
| Unsupported operation | Confidential workloads remain unsupported. The original named root-deny candidate is a different, unselected configuration and fails configuration parsing as described below. |

The 2026-11-15 PID-reuse measurements above are historical observations.
Current guard behavior is described below.

On 2026-11-16 the existing selected-launcher PID-reuse positive and five
matched package, scope and identity refusal controls passed all six tests
with zero skips under the unchanged package pin and configuration. This
offline rerun did not repeat the historical configuration RPC checks. It
does not qualify native model-worker/server/callback PID reuse or production
ownership/accounting/restart recovery, which remained unperformed in that
check. The later registered contained route has its own two- and three-worker
live record. [Native Supervision Pools](native-supervision-pools.md)

The current implementation uses disposable user, PID, mount and network
namespaces with private procfs. A single fixed bubblewrap
bootstrap directly enters the trusted driver without nested unshare. It mounts
the host root read-only, binds only the owned temporary root writable, and sets
nested diagnostic `TMPDIR` within that root. Private procfs and a tmpfs `/dev`
with six fixed device nodes avoid devpts and a second user namespace. Parent
checks join the handed-off self-pidfd, exact bubblewrap/driver executable
objects, original watchdog ancestry and private PID namespace before release.
The PID namespace's owning user namespace must equal the driver's user
namespace. Birth comparisons preserve PID, command name, parent and start ticks;
volatile scheduler state may change. Watchdog-death and rejected-helper controls
observe the fixed helper and driver exiting under the original bounded cleanup.
Received handles remain quarantined until all checks pass;
refusal closes an unverified handle without signaling its lifetime. The controller under test is constructed in a fresh
interpreter after namespace entry. Only the verified private `ns_last_pid` cursor
is written; no host-global process control changes. The trusted driver retains
namespace-local cursor capabilities while clearing inheritable and ambient
capabilities; exec children report zero effective, permitted, inheritable and
ambient capabilities and retain the original user/group identities. Unsupported
cursor access, aliased host procfs, bad handoffs or unexpected scope refuse.

The primitive test may report the exactly measured original cursor WRITE
permission denial as **unperformed** only after checking original source, security
and independent boundary receipts and all original cleanup results. This supplies
no useful PID-reuse or qualification credit. Unknown source, credential, lifetime,
identity, type or cleanup failures still fail. Supported targets must execute the
positive controls. The diagnostic-launcher case has its own applicability check.
The data fixture and unit controls establish no kernel permission
or cleanup.

External reaping of the original child does not repair its old controller's
accounting: its stale report remains conservatively `already-exited` with
`child_reaped: false`. The fresh owner's cleanup is checked independently. The
two observations are covered by
`PrivatePidReuseOSControlTests.test_actual_private_pid_reuse_preserves_the_fresh_lifetime`
and `SelectedNativeOSProbeTests.test_private_pid_reuse_repeats_the_exact_selected_launcher_scope`
in [the diagnostic tests](../tests/test_selected_native_containment.py).
Primitive results cannot substitute for the selected-launcher scope. Neither
scope authorizes model work, accepted output, confidential workloads or
production recovery.

The original named candidate was assessed separately with `untrusted` approvals,
the `user` reviewer, root deny, minimal runtime reads, isolated workspace writes
and network off. The selected executable rejected `approval_policy="untrusted"`
before profile compilation. No root-deny transformation, fallback behavior or
named enforcement follows from that refusal. A different approval setting would
be another configuration identity; it is not substituted for either candidate.

Supply the native executable explicitly to run the fixed diagnostics.

```sh
python scripts/selected_native_containment.py --codex /path/to/codex
CWO_QUALIFICATION_PACKAGE="$QUALIFICATION_PACKAGE" python -m unittest tests.test_selected_native_containment -q
```

The CLI also accepts a standalone package directory via `--package` and locates
its `bin/codex` entrypoint. Each new diagnostic records its own executable
identity. The dated package observations continue to describe that package.

The full test module includes both PID-reuse scopes. The fixed CLI catalogue
does not run PID reuse or accept an arbitrary command.

Tests without that package still exercise the actual outer OS mechanisms, but
give those controls no selected-executable credit. The machine-readable target
policy separates the original dated identity/schema observations from these
scoped diagnostics. Both retain `execution_authorized: false`.

## Protected serial pool integration

The [v1.46.0 serial pool fixtures](https://github.com/gprocunier/complex-work-orchestration/blob/v1.46.0/references/codex-protocol-capability-matrix.md#protected-serial-pool-integration)
exercised the original registered host, opaque authority, validators and ledger
for N=1/2/3 with fake OS/RPC. They recorded consent and signed adoption,
terminal persistence, charge retention and reconciliation refusals. The serial
execution and retry paths are retired. Signed readback uses the original
configuration and source image.

The public launcher remains an in-process host client. Local structural
validation grants no authority and makes no model call; trusted host validation
still applies the original authority checks without consuming an operation. Pool request capture accepts at
most 4 KiB through a pinned regular-file descriptor, refuses symlinks and special
files without waiting for a writer, and checks descriptor/path identity and size
around the read. Missing no-follow or nonblocking primitives refuse before open.
Request data cannot select factories, imports or credentials. Client exceptions
pass through without an implicit retry, budget expansion or privilege change.
These controls preserve the direct CLI's pre-import authority refusal; no live
pool qualification, activation or accepted delivery follows.

The registered model task preserves every admitted prompt, wrapper, attachment
and source, together with its permitted command, completion marker, outputs and
original acceptance criteria. The full execution manifest stays in protected
host records. Separate original-request and actual model-task digests bind the
factory, native control, adapter boundary and dispatch provenance. The model
task is rederived from the original admission and stays within its byte allowance;
original reservations and replay identity remain bound to the complete request.

Host-supplied model submissions and supported context RPCs, together with
registered finite tool replies, are prepared and screened at their final host
writers. Preparation binds the original structured payload to the exact JSON
bytes, and screening refusal preserves conservative charging and containment.
The original action failure remains primary through later cleanup and summary
errors, while independent cleanup facts are retained.
These source and fake-wire controls cover known host-supplied frames. Complete
server-loaded context, native builtin tools, provider behavior and helper paths
remain unqualified; no live model observation is inferred from these guards.

## Classification

- **source-supported (schema):** stated by the schema Codex generates from its
  source, and checked against the pinned bytes.
- **fake-tested:** a test changes one value at a time and the check fails.
- **source-cited, not re-verified:** the remediation package cites Codex source
  at `c1382380`; no source checkout is available offline, so it is not
  re-verified here.
- **live-untested:** needs a running app-server, an effective configuration or
  an OS boundary. The historical rows below make no runtime or OS claim; the
  selected target's later identity observations are scoped above.

## Matrix

These findings describe the 0.162.0 and 0.163.0 schema fixtures.

| Question | Finding | Classification |
|---|---|---|
| Historical executable identity | Version text and SHA-256 are both checked when verifying a match to recorded evidence. | fake-tested |
| Fixture integrity | A missing, extra or changed file, or a changed bundle digest, is reported. Symlinks in a fixture bundle are refused. | fake-tested |
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
