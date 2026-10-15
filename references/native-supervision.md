# Native supervision: current and historical contracts

Current operative routing is neutral-sized, qualified exact Luna first, with
Terra only for recorded nonfit or justified escalation. Spark/v2 examples below
are historical compatibility material: parseability is not fresh dispatch
authority. Current v3 routes require current qualification, source/context/scope,
candidate/attempt and budget bindings through precommit, packet and release.

Read-only semantic reviews require zero mutations and an enforced filesystem
and network boundary. Removing a patch tool or giving read-only instructions
is not sufficient. A valid realignment return is nonaccepted. Final transaction
validation and actual owned-resource closure outrank transport completion.

Explicit self-maintenance uses owner-issued in-process capabilities and truthful
maintenance-unbounded budget mode with bounded individual operations. Serialized
authority snapshots never authenticate themselves. Normal unauthorized requests
and finite budgets retain their ordinary behavior.

## Current host tool profiles

Tool policy version 2 explicitly binds the current core-resource profiles.
The mutating profile permits `apply_patch`, `exec_command`, `write_stdin`,
`list_mcp_resource_templates`, `list_mcp_resources`, and `read_mcp_resource`.
The read-only profile omits `apply_patch`. Resource tools require actual empty,
fully paginated MCP endpoint inventories before and after the owned thread;
endpoint/configuration changes invalidate dispatch. Do not relabel a larger
capture as an older three/two-tool profile. Version-1 profiles remain readable
and strict on their own hosts; they do not qualify this larger surface.

Packet producers can select these profiles with `--tool-profile` (or the
corresponding library argument). The same validated profile governs rendered
instructions and host enforcement. Removing a tool is never proof that shell
writes or network effects are prevented; retain the actual enforced sandbox.
Precommit/qualification turns remain no-tools regardless of operative profile.

## Historical supervision reference

# Native Worker Supervision

Native worker supervision is the connected CWO control path for delegated
operative work. The CWO lead remains the architect and final decision owner. A
fresh native `gpt-5.3-codex-spark` worker receives one bounded assignment, and
the trusted host monitors that assignment against its packet, model, tools,
budget, workspace, telemetry, and completion contract.

Every delegated native worker is supervised. Once CWO delegates to a native
worker, there is no unsupervised mode or opt-out. Multi-worker concurrency is
the experimental part, not supervision.

This reference covers the normal single-worker path. Concurrent pool operation
is documented in [Native Supervision Pools](native-supervision-pools.md).

## What Is Standard

One supervised worker is the default. The standard path requires:

- a Beads work item with closed scope and acceptance criteria;
- a semantic work estimate;
- a fresh Spark session with trusted model attestation;
- a version-2 native worker packet;
- an accepting precommit receipt;
- operative release evidence for the exact packet and work plan;
- the single-worker supervisor armed before task submission;
- one uninterrupted control turn for submission, receipt binding, and polling;
- bounded validation and lead adjudication before acceptance.

CWO does not silently replace Spark with another model. A model self-report is
not attestation. Missing trusted session metadata, wrong model identity, an
unavailable interrupt or close control, or an unusable telemetry stream stops
dispatch.

## Spark-First Operative Routing

Operative, critic, and peer-review routes are independent decisions. Critic,
contractor, and local-review configuration is evidence-only and never changes
the operative model. Each fresh operative segment resolves an
`operative_route` from trusted live capability evidence. Policy declarations or
a model name accepted by a CLI parser do not prove availability.

The exact availability vocabulary is `available`,
`verified-quota-exhausted`, `verified-capacity-unavailable`, `unknown`,
`model-mismatch`, `control-fault`, and `security-fault`. Only the two verified
quota/capacity states open the ordinary fallback-choice path. Unknown or
ambiguous telemetry, mismatch, control failure, contradictory validation,
security failure, or unattributed mutation stops rather than prompting for a
fallback.

The legacy `workerbee_planned_delegation.spark_dispatch` summary remains
readable for compatibility, but it is advisory and cannot prove availability
or authorize dispatch. Consumers must use `operative_route` and the normal
packet, precommit, release, and supervision gates.

Fallback candidates are the intersection of fresh live host evidence and the
environment's approved operative executors. They must retain repository read,
write, shell, exact-attestation, lifecycle-control, workspace, mutation, risk,
and policy authority. Review-only and external executors are excluded.

A separate strict `cwo-operative-fallback-fit` artifact binds the native work
estimate, Bead/wave/fresh-segment and work-lineage context, cache evidence,
per-model host evidence, aggregate budget, policy version/hash, classifications,
and candidate results by SHA-256. Predicted cache fit requires a hash-bound
context plan. Observed cache fit requires trusted same-lineage telemetry. Stale,
cross-lineage, missing, negative, malformed, or ratio-invalid evidence fails
closed.

The coach presents at most three eligible candidates plus **Wait for Spark**:
GPT-5.5 only for strategically valid substantial cache-heavy work, Terra for
non-Luna-shaped work, and Luna for deterministic narrow or repeatable work.
Luna remains the final live fallback for non-Luna work only with an explicit
degraded-task-fit warning and acknowledgement. Dispatch remains unauthorized
until the user explicitly selects a displayed model and a scope: current Bead,
current wave, or until Spark is restored. Version-2 selection provenance binds
the exact model/executor, reason, scope/expiry, timestamp, actor, capability,
work-estimate, fitness, policy, and candidate-evidence hashes.

The aggregate budget is copied across model changes and is never reset. Spark
is re-evaluated at every fresh segment. When it returns, a restoration-scoped
fallback expires and the new segment returns to Spark; an already-running work
unit never switches models. Route history appends quota, selection, and expiry
evidence without rewriting earlier events. Legacy explicit-fallback metadata
remains readable for inspection but must be migrated to the version-2 explicit
selection contract before dispatch.

## Before Dispatch

The precommit request happens before the candidate packet is allowed to become
operative. It contains the work-plan hash, task class, bounded primary outcome,
bounded acceptance checks, numeric complexity, aggregate allowance, and the
required p50/p90 estimate fields. The semantic text is single-line, size-limited,
and rejects absolute paths and code or command fragments. The request excludes
repository paths, code excerpts, commands, mutation instructions, and validation
commands while remaining self-contained enough for a truthful fit decision.

The precommit worker is supervised as a zero-tool fit request. An unexpected
tool call, model mismatch, workspace mutation, compaction, partial session
boundary, control loss, or invalid completion makes the receipt non-accepting.
An accepting receipt creates a version-2 commitment for the exact work plan.

That commitment is still not dispatch authority. The operative release gate
must bind the packet, work plan, precommit receipt, positive canary evidence,
requested model, and adjudication state. Changing the work plan requires a new
session, nonce, precommit prompt, and receipt.

The canonical packet and precommit commands are in
[Execution Environments](execution-environments.md#native-packet-and-live-supervisor).

## Live Control Turn

After the fresh worker passes trusted no-tools attestation, the host creates the
single-worker supervision state and arms it with a unique control-turn ID. The
following order is required:

```text
persist state
  -> arm supervisor
  -> send task
  -> bind submission ID
  -> check every second
  -> interrupt or observe clean completion
  -> finalize control receipts
  -> close worker
```

The first poll follows task submission without an assistant or model round-trip.
The same control-turn ID binds arming, the dispatch receipt, checks, interruption,
and finalization. A long passive wait is not a substitute for one-second checks.

The supervisor classifies trusted session events and compares observed activity
with the packet. It tracks tools, command evidence, reads, mutations, validation,
tokens, runtime, compaction, terminal state, and workspace drift. Advisory
worker prose never overrides those observations.

A check that returns exit code `2` means interrupt or control loss. The host
must interrupt the native worker, close it, and record the control receipts
before returning control to the architect. A clean completion records
`worker-completed` before close.

## Workspace Authority

The packet's `scope.workdir` is the authoritative working directory. The
worker may inherit another shell directory, but that inherited value cannot
widen mutation authority.

Before execution, CWO records a clean workspace baseline and resolves allowed
paths without following a symlinked authority boundary. During execution it
distinguishes expected mutations from unattributed or out-of-scope changes.
Incomplete comparison, unexpected untracked files, path aliasing, or mutation
outside the packet stops the attempt.

Mutable concurrent workers require separate clean worktrees with non-overlapping
integration targets. Read-only workers may share a clean worktree only when
every child declares no write or integration target.

## Failure And Recovery

The supervisor protects the task rather than trying to salvage every partial
result.

- **Model mismatch:** reject the session and its artifact.
- **Control loss or unsafe mutation:** interrupt, close, and quarantine the
  attempt.
- **Context compaction:** stop the session and require architect adjudication of
  any retained artifact.
- **Budget-only stop:** one fresh independent validation may assess the artifact;
  failure ends that path.
- **Healthy packet-contract failure:** the project manager may refine the packet
  once within the original scope and aggregate allowance.
- **Material replan:** checkpoint evidence in Beads and start a fresh worker.
  Do not resume the operative worker by default.
- **Retry:** only a policy-eligible failure may use the bounded retry contract.
  It shares the original budget and requires fresh attestation and exact
  evidence.

A worker return is evidence. The CWO lead decides whether it is retained,
corrected, quarantined, deferred, or accepted after validation. CWO does not
turn an interrupted artifact into implementation authority through an automatic
salvage chain.

## Multi-Worker Concurrency Tech Preview

Running multiple supervised native workers concurrently is experimental and
disabled by default. Supervision remains mandatory for every worker; only the
concurrent pool requires a separate opt-in.

| Capacity | Status | Additional requirements |
| --- | --- | --- |
| One worker | Standard default | Normal trusted single-worker controls |
| Two workers | Opt-in Tech Preview | Fresh same-host capability receipt and safe fixed cohort |
| Three workers | Opt-in Tech Preview | Same requirements; released and hard ceiling |
| Four or more | Blocked | Not represented by the operative contract |

A concurrent pool also requires deterministic admission, an economical and
schedulable cohort, immutable child bindings, isolated mutable worktrees or
strictly shared read-only topology, and an admission-bound version-2 launcher.
The pool does not make precommit, packet construction, critics, integration,
retry, replay, or publication concurrent.

Do not run several single-worker supervisors in parallel by hand. Serialized
contracts, hashes, receipts, proportionality assessments, and preflight results
are evidence; none of them can replace the one-use admission capability held by
the trusted process. Productive concurrent execution uses the admitted pool
launcher, `run_admitted_native_pool`, not direct `NativePoolCoordinator`
construction.

A protected pool fault interrupts affected admitted children and makes the pool
receipt non-accepting. An isolated child failure may allow healthy peers to
finish, but the pool remains partial and non-accepting. Leases remain blocking
until valid terminal evidence exists; dead-owner cleanup does not infer a safe
terminal.

See [Native Supervision Pools](native-supervision-pools.md) for topology,
admission, scheduling, inspection, lease, and rollback details.

## Separate Activation Preview

Exact server-side tool allowlisting is required for ordinary operative work.
The disabled `trusted-detect-and-contain` activation preview explores a weaker
boundary in which an unlisted built-in could act before detection. It is not the
normal N=1 path and is not equivalent to server-side prevention.

The preview accepts only the fixed `n1-read-only`, `n2-read-only`, and
`n1-mutable` profiles. A serialized override records risk intent but cannot
authorize dispatch. Live use requires an exact prepared plan, a signed and
unexpired operator approval, a permanent one-use claim, and explicit
`--enable-tech-preview`. Use `--dry-run` for non-consuming validation.

Live canary campaign artifacts prove a specific certification run. They do not
grant general authority, convert historical schemas into current dispatch
formats, or make a prior approval reusable.

## Operator Checks

Use these read-only interfaces to inspect normal supervision:

```bash
python3 scripts/supervise_native_worker.py --help
python3 scripts/check_native_worker_session.py --help
python3 scripts/supervise_native_pool.py --help
```

The public policy source is `policy/native-worker-execution.yaml`. Important
schemas include:

- `schemas/operative-routing-state.schema.json`
- `schemas/operative-fallback-fit.schema.json`
- `schemas/native-worker-packet.schema.json`
- `schemas/native-precommit-state.schema.json`
- `schemas/native-precommit-receipt.schema.json`
- `schemas/native-release-evidence.schema.json`
- `schemas/native-supervision-state.schema.json`
- `schemas/native-supervision-decision.schema.json`
- `schemas/native-supervision-pool-contract-v2.schema.json`
- `schemas/native-supervision-pool-receipt-v2.schema.json`

For exact single-worker commands and exit-code behavior, use
[Execution Environments](execution-environments.md). For pool operations, use
[Native Supervision Pools](native-supervision-pools.md). For recovery and
quarantine handling, use the [Incident Response Playbook](incident-response-playbook.md).
