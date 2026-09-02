# Native Worker Supervision

Native worker supervision is the connected CWO control path for delegated
operative work. Candidate E remains the architect and final decision owner. A
fresh native `gpt-5.3-codex-spark` worker receives one bounded assignment, and
the trusted host monitors that assignment against its packet, model, tools,
budget, workspace, telemetry, and completion contract.

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
- bounded validation and Candidate E adjudication before acceptance.

CWO does not silently replace Spark with another model. A model self-report is
not attestation. Missing trusted session metadata, wrong model identity, an
unavailable interrupt or close control, or an unusable telemetry stream stops
dispatch.

## Before Dispatch

The precommit request happens before the candidate packet is allowed to become
operative. It contains the work-plan hash, numeric complexity, aggregate
allowance, and the required p50/p90 estimate fields. It excludes repository
paths, code excerpts, commands, mutation instructions, and validation commands.

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

A worker return is evidence. Candidate E decides whether it is retained,
corrected, quarantined, deferred, or accepted after validation. CWO does not
turn an interrupted artifact into implementation authority through an automatic
salvage chain.

## Concurrent Supervision Tech Preview

Concurrent native supervision is experimental and disabled by default.

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
