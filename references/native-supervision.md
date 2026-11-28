# Native supervision: current and historical contracts

The registered single-worker route requires the original signed workflow,
explicit provider disclosure consent and separately supplied production
authentication. A trusted embedding host can send an eligible assignment on
this route and post its exact candidate for separate hand acceptance. The
lead-run supervision checks in this reference are advisory. See the
[registered production requirements](native-live-route-holds.md#standing-approved-delegation).

Single-worker execution is the default. A trusted controller can admit a fixed
group of two or three workers through the [registered contained pool](native-supervision-pools.md).
The controller requires exact approval and fresh callback calibration on the
same host.

For a new assignment, estimate the whole task before selecting a worker. Luna
is the first choice for focused native work. Sol handles escalation when the
attempt records a fit, risk or cost reason bound to its fit evidence.

For an assignment primarily about an interface, visual material or computer
use, set `work_kind` to `interface`, `visual` or `computer-use` in the version 2
native work estimate under `fit_inputs.work_estimate`. This classification
selects the Terra lane even when the task includes coding. Omit `work_kind`
for general coding or other work. Terra selection requires the explicit field;
task descriptions alone do not classify work.

A current launch must bind the exact selected model,
source revision and context, task scope, candidate and attempt identities, and
allowance through the fit check (`precommit`), scoped brief (`packet`) and exact
launch approval (`release evidence`).

`policy/model-roles.yaml` is the source for the current and previous model of
each role. The default selection uses `current`. Set a role's `selection` to
`latest-in-family` to resolve its newest visible model from the Codex catalog
at startup. The optional `pin` takes precedence over discovery. The selected
model stays fixed for that attempt. To roll back, select the explicit mode and
use the model recorded in `previous`.

The shipped worker policy records `gpt-6-luna` as its preferred model, matching
the shipped Luna role. Active routing resolves the role for each new attempt.
Older Spark-first records use the historical routing policy and its exact-model
rosters.

The shipped policy does not contain a `cyber_fallback` role. A user who chooses
to enable refusal recovery adds this entry under `roles` in their installed
`policy/model-roles.yaml`:

```json
"cyber_fallback": {
  "model": "gpt-6-sol",
  "previous": null,
  "required_access_program": "daybreakBlue",
  "codex_config": {"daybreak": true}
}
```

The model is configuration: change `model` (and record the old one in
`previous`) when the Daybreak Blue model changes. It must be an exact Sol-family
model ID and must differ from the `sol` role's model, so `daybreak=true` is never
combined with the ordinary sol model or any other family. Only a cyber-policy refusal triggers
recovery. Other refusals, errors and timeouts stop the task. Recovery makes one
attempt with the same packet. It carries the original reasoning effort capped at
`xhigh` and always uses the standard (`default`) service tier. A second refusal, or an
account without Daybreak Blue access, stops the task and records the blocker.
Each attempt is recorded with the refusal that triggered it and its outcome.

At startup, CWO reads the public Codex model catalog. The role is available only
when the exact model is selectable and its `availableAccessPrograms.cyber` list
contains `daybreakBlue`. A missing model, missing metadata or missing program is
reported as unavailable. It is not a policy-load error. CWO never combines
`daybreak=true` with another model.

Recovery also requires an explicit operator mark held by the protected authority
host, the same separate account that holds outbound approvals. Publish it as the
host account and keep the printed reference:

```bash
scripts/lead_authority_host.py publish security-work-mark < mark.json
```

Construct `AuthorityMarkStore(reference)` in the parent supervisor. The lead can
request the mark by reference but cannot create, widen or replace it. The
controller refuses a file-based `SecurityMarkStore` unless the caller passes
`allow_file_marks=True`, which is for fixtures and non-production use. The mark
document format is:

```json
{
  "version": 1,
  "marks": [
    {
      "scope": "work-item",
      "id": "project-task-id",
      "source": "user",
      "marked_by": "operator identity",
      "marked_at": "2026-11-23T09:00:00-05:00"
    }
  ]
}
```

`scope` may be `work-item` or `project`. A fixture file used with
`allow_file_marks=True` must be an absolute, non-symlink, owner-only regular
file, normally mode `0600`, and the parent passes all lead and worker write roots
to `SecurityMarkStore`. In either case the parent requests an opaque
mark handle for the exact work item and gives that handle to
`CyberFallbackController`. Plain JSON, a mark whose `source` is `lead` or
`worker`, a mark inside a supplied write root, a forged handle and a spent handle
are rejected. The recorded mark retains `marked_by`, `marked_at` and the digest of
the captured mark document.

After Part 1 reports a structured provider safety refusal, the parent controller
can consume the mark and make one fallback attempt. It sends the identical packet
bytes, carries reasoning effort capped at `xhigh` on the standard service tier, links the attempt to the
original with reason `cyber_refusal`, and charges the original aggregate budget
again. The audit record binds the original attempt, classification, mark, role
and packet digest. Unmarked work, unavailable access, any non-refusal failure or
a second refusal produces a terminal blocker without another launch. The lead's
model is not an input to this controller and never changes.

This is a parent integration contract. The default-off native route holds remain
in force, so adding the role or mark does not activate live dispatch.

The Spark/v2 examples below are retained to interpret historical artifacts. An
old packet passing its format check does not approve a new dispatch. Start with
the [current delegation guide](../docs/native-supervision.html) for the reader
procedure, then use this reference for the exact contracts.

Read-only semantic reviews require zero mutations and an enforced filesystem
and network boundary. Removing a patch tool or giving read-only instructions
is not sufficient. A valid realignment return is nonaccepted. Final transaction
validation and actual owned-resource closure outrank transport completion.

Explicit self-maintenance uses owner-issued in-process capabilities and truthful
maintenance-unbounded budget mode with bounded individual operations. Serialized
authority snapshots never authenticate themselves. Normal unauthorized requests
and finite budgets retain their ordinary behavior.

When a registered single-worker failure summary is available, it records
`terminal_blockers.provider-safety-policy-refusal` if the durable turn has
failed and its exact `turn/completed` notification carries `cyberPolicy` or
`misalignmentPolicyViolation` in `error.codexErrorInfo`. The report keeps the
original failure, charge and cleanup outcome. Missing, ambiguous and other
codes keep the ordinary failure classification. The blocker is terminal for
that attempt.

When that blocker belongs to marked work, the optional parent-side cyber fallback
contract above may consume it once. Reply wording never classifies a refusal and
cannot authorize the retry.

### Reasoning effort routing

The `sol` role in `policy/model-roles.yaml` supplies `reasoning_effort`
(`high`) and `escalation_reasoning_effort` (`xhigh`). The interactive lead
launch reads the default. Existing worker and reviewer controls govern which
routes can dispatch.

| Signal | Eligible role |
| --- | --- |
| The host has recorded a rejected return from a default-effort attempt on the same delivery | Worker or reviewer preparing a fresh attempt |
| Routing identifies security or containment work such as sandbox, network, credentials or approval controls | Worker or reviewer |
| A change classified high or critical needs independent review or adjudication | Reviewer or adjudicator |
| Architecture or planning work has wide consequences, such as a cross-cutting change or a public contract change | Worker or reviewer |

`route_work.py --json` reports the effort and reason for each Codex role.
For a fresh internal Codex dispatch preparation after an embedding host
records a rejection through `record_received_evaluation`, give
`dispatch_work.py --retry-dispatch` the original dispatch ID and its `--bead`,
submit the same task and use a new dispatch ID and current `--workload` for
an internal critic request. CWO checks the original request
digest, recorded effort, host-captured return receipt and evaluation. The
evaluation must reject the delivery on its merits and clear screening and
review holds. Preparation prints the Codex effort argument and records the
choice. The next attempt still needs its usual approval. Standing delegation uses the selected effort in the
signed worker configuration and records it with the worker dispatch. A recorded
Codex peer request supplies its effort argument and workload allowance to
the embedding host. Completion checks that effort against the original
session. [Dispatch readiness](run-readiness.md#dispatch-readiness)


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

The Spark recipes below describe the older path. Its lead-run supervision
checks are advisory.

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

This loop is cooperative. The lead runs each check and acts on its exit code;
no shipped component polls or interrupts the worker on its own, and nothing
stops a lead that skips a check.
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

Baselines are retrospective observations, not a write or network boundary.
Capture never runs `git status` or `git diff`, so repository-configured
monitors, hooks and filters do not run. It records HEAD and index manifests, an
inventory of every worktree entry with its type, mode and (for files) content
digest, ignored files included, and digests of Git metadata such as config and
the files it names, hooks and references. A change made and reverted between
two captures is not seen. A capped, unreadable, sparse or otherwise incomplete
capture cannot pass the mutation check, so large ignored trees (for example a
virtual environment inside the worktree) can make captures incomplete, as does
a `core.fsmonitor` hook program (only boolean values are supported, and with
Git 2.35, which resolves every non-empty value as a program, any non-empty
value).
Git never opens a file of the inspected workspace or its repository. Capture
copies the index and ignore files into a private scratch repository and runs
Git only there; config, HEAD, references and HEAD's tree are read without Git,
each object checked against its identifier, and nothing is fetched. Every
repository file read must be a regular file, and repositories whose config
names more files (includes, excludes or attributes files), split indexes,
chained symbolic references, alternate object stores, reftable references and
`core.worktree` are refused as unsupported. A writer still running during
capture can still change what the capture observes, so capture belongs after
the worker has stopped. Capture assumes that its own code, its execution
configuration and its private scratch directory (with the directories above
it) are not modified by untrusted processes while it runs. It is not a
confinement boundary against a process of the same user that can modify them,
and hostile concurrent workers need a separately qualified boundary.

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

## Multi-Worker Concurrency

| Capacity | Registered route | Requirements |
| --- | --- | --- |
| One worker | Single-worker execution | Original signed workflow, provider disclosure adoption and separate production authentication |
| Two workers | Contained pool | Exact approved cohort, separate configured logins and fresh same-host callback capability |
| Three workers | Contained pool | Same requirements and the current capacity ceiling |
| Four or more | Unavailable | The policy supports up to three workers |

A concurrent pool also requires deterministic admission, an economical and
schedulable cohort, immutable child bindings, isolated mutable worktrees or
strictly shared read-only topology, and an admission-bound version-2 launcher.
The pool does not make precommit, packet construction, critics, integration,
retry, replay, or publication concurrent.

Do not run several single-worker supervisors in parallel by hand. Serialized
contracts, hashes, receipts, proportionality assessments, and preflight results
are evidence; none of them can replace the one-use admission capability held by
the trusted process. The registered controller uses the admitted pool launcher,
`run_admitted_native_pool`, after approval and admission. A direct
`NativePoolCoordinator` instance carries no such authority.

A protected pool fault interrupts affected admitted children and makes the pool
receipt non-accepting. An isolated child failure may allow healthy peers to
finish, but the pool remains partial and non-accepting. Leases remain blocking
until valid terminal evidence exists; dead-owner cleanup does not infer a safe
terminal.

See [Native Supervision Pools](native-supervision-pools.md) for topology,
admission, scheduling, inspection, lease, and rollback details.

## Separate Activation Preview

Exact server-side tool allowlisting is required for ordinary operative work.
The offline `trusted-detect-and-contain` activation preview records risk intent
for a historical boundary in which an unlisted built-in could act before
detection.

The preview accepts only the fixed `n1-read-only`, `n2-read-only`, and
`n1-mutable` profiles. Use `--dry-run` for non-consuming validation of the
prepared plan and operator approval. Live execution is retired.
`--enable-tech-preview` refuses before input reads, claims or RPCs.
[Native Supervision Pools](native-supervision-pools.md#temporary-audited-tool-boundary).

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
