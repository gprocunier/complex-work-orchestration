# Native Supervision Pools

## What This Is

This reference is for operators deciding whether to use CWO's bounded native
worker supervision. Native supervision lets one trusted host control a fixed
cohort of one or two already-created native worker supervisors; it does not make
packet construction, precommit, critics, integration, retry, replay, or
publication concurrent.

Capacity one remains the default. Capacity two is an opt-in Tech Preview that
is experimental and disabled by default. It requires one fresh same-host
capability receipt, exactly two fixed workers, and either isolated mutable
worktrees or a shared read-only topology. Start with the reader-facing
[Native Supervision Tech Preview](https://gprocunier.github.io/complex-work-orchestration/workflows.html#native-supervision-tech-preview),
then review the [deferred hardening](#experimental-status-and-deferred-hardening)
before opting in.

The public contract is deliberately small:

- Capacity one is the default and preserves single-worker behavior.
- Capacity two requires `--enable-concurrency` and a fresh trusted adapter
  capability receipt from the same live host process.
- Capacity two is experimental and disabled by default. Operative release
  makes explicit opt-in available; it does not silently raise capacity.
- Capacity above two, threads, hot admission, replacement children, and a
  second coordinator are rejected.
- The cohort, worker sessions, nonces, control turns, state files, worktree
  identities, target paths, aggregate allowance, scheduler, and capability
  evidence are immutable after contract rendering.
- Capacity two is operative only when policy records `operative-authorized`
  with `cap_two_operative_release=true`. The marker is released only after the
  `complex-work-orchestration-18w.6` live campaign is accepted; structural
  support alone is not operative release.

## Trusted Live Canary Gate

The release canary is a separate, single-shot controller:
`scripts/run_native_pool_live_canaries.py`. It requires the immutable full-auto
authorization, the active outer authority, the exact predecessor authorization
and campaign manifest, an accepting independent Spark receipt, plus
independently adjudicated pre-mutation and pre-live Sol steering receipts. All
artifacts are private mode 0600. The launcher recomputes canonical receipt and
predecessor artifact hashes, binds predecessor identity, generation, and exact
candidate commit/tree, then rechecks their raw byte hashes immediately before
allocation. Each steering receipt is validated against trusted session JSONL,
consumed once under a private process lock, and cannot authorize repository
work by itself.

The public live launcher accepts only its current v11/v8/v6/v6 contract tuple;
historical tuples remain inspection-only and mixed tuples fail before
allocation. The accepted practical release used a fresh one-use, Bead-scoped
authority around the v8 renderer envelope and bound only the immediate
Generation-12 terminal-facts and containment roots. It did not make any prior
live authority reusable.

Generation 8 is represented by a dedicated quarantine predecessor leaf, never
by the accepting-session parser. The leaf requires its exact two-record archive
(`session_meta`, then `task_started`), zero trusted turn contexts, terminal
events, tools, certification, or model attestation, and its exact archive-only
six-event ledger. It reconstructs the sequence-4 failure ledger from the final
ledger's same identity, authority bindings, and first four entry payloads, then
requires the reconstructed raw, state, and head hashes to equal the failure
evidence. This proves containment only; it cannot supply trusted model evidence.

Calibration runs exactly `sleep 20`. App-server `inProgress` is only a hint:
the controller waits up to ten seconds for a complete current-turn
`turn_context` with the exact model and effort and an agent-origin
`commandExecution` that remains `inProgress` across two complete observations
at least one second apart. It polls no slower than 250 ms, excludes terminal,
failed, declined, rerouted, compacted, malformed, duplicate, truncated, or
rewritten telemetry, then immediately revalidates before interrupt. The same
turn must confirm interruption within five seconds.

Materialization evidence contains only identities, fresh nonces, timestamps,
status classes, record/item indices, counts, offsets, and domain-separated
hashes. Raw prompts, commands, output, responses, reasoning, content, paths,
and path hashes are forbidden. The authorization latch is mode 0600 and
monotonic. A protected fault durably changes `active` to `containment-only`
before returning; only interrupt, close, sanitized evidence, reserved steering,
Beads updates, local checkpoint, pickup, and handoff remain possible.

Callback observations are telemetry, not timing authority. A capacity-two
receipt separately binds the exact production envelope and policy digest, the
adapter implementation digest, fixed per-operation ceilings, and a 100 ms
scheduler ceiling. The frozen ceilings are 100 ms for arm, dispatch marking,
and finalize; 200 ms for check; and 250 ms for send-input, interrupt, and
close. Any observed value above its named ceiling rejects the capability.

Before every `thread/start` and `turn/start`, the live controller fsyncs a
two-phase intent to a private allocation ledger beside the final evidence.
Returned thread and turn identities are bound in separate events, and every
event is anchored into a separate locked CWO audit hash chain. The ledger uses
an owner-only directory and files, records exactly seven campaign roles, and
survives deletion of the disposable worktrees. An unresolved intent is
ambiguous allocation evidence and rejects the campaign.

The release campaign has exactly seven fresh turn starts: capability
interruption, two concurrent read-only workers, two concurrent disjoint mutable
workers in disposable worktrees, and an interrupted worker while its peer
completes. No turn is resumed or salvaged. The canary path requires
`cap_two_operative_release=false`; after its evidence is accepted, the release
sprint changes the policy pair together to `operative-authorized` and `true`.
Ordinary capacity-two rendering rejects the canary-gated pair and requires the
released pair.

## Experimental Status And Deferred Hardening

Capacity two is a practical experimental capability for a trusted same-user
control plane. It remains bounded to two fixed workers, explicit opt-in, one
connected host process, immutable admission, and isolated mutable worktrees or
strictly shared read-only topology.

The accepted campaign proved same-epoch application-level recovery for the
observed pre-attestation startup scaffold, with one guarded wire request, one
consumed retry token, unchanged identity and workspace, and the normal trusted
validators restored afterward. The following work is deliberately deferred and
tracked separately:

- transport-level exactly-once guarantees below the app-server API;
- atomic serialization with concurrent session-log ingestion;
- exhaustive rejection of every harmless unknown JSONL extension;
- recursive inclusion of the complete historical proof DAG in each campaign;
- broader optimization and refactoring beyond the fixed capacity-two path.

These limitations do not relax wrong-model, control-loss, mutation-attribution,
ambiguous-dispatch, terminal-boundary, or second-failure rejection.

## Topology

Every mutable child needs a distinct clean Git worktree and non-overlapping
integration target paths. The integration checkout is monitored and must remain
clean during worker execution. Two read-only children may share one clean
worktree only when both declare no write or integration target paths.

| Surface | Capacity one | Capacity two |
| --- | --- | --- |
| Fixed cohort | Required | Required, exactly two children |
| Mutable worker worktree | Isolated from integration | One distinct worktree per child |
| Shared read-only worktree | Allowed | Allowed only for two read-only children |
| Integration target paths | Scoped, non-symlinked | Scoped and non-overlapping |
| Adapter capability receipt | Must be absent | Fresh, exact, trusted, and same-host |
| Explicit opt-in | No | `--enable-concurrency` |
| Operative release | Existing single-worker policy | Requires `operative-authorized` and a true marker |

Physical device/inode identity, canonical-path hash, Git common-directory hash,
and a complete clean baseline are captured before the pool contract is sealed.
A symlinked root or target component, incomplete comparison, dirty integration
checkout, aliased mutable worktree, or attribution ambiguity fails closed.

## Lifecycle And Scheduling

The pool lifecycle is:

```text
created -> capability-validated -> admitting -> running -> draining
        -> interrupt-pending | completed | control-failed -> closed
```

Capacity-one pools skip `capability-validated`. Admission is sequential: a
child lease is acquired before that child's first adapter callback. Scheduling
uses earliest deadline with deterministic rotation for ties. `step()` invokes
at most one adapter callback and never sleeps; only the host's `run()` wrapper
sleeps. The v1 timing contract is exactly a 1000 ms poll interval with 1500 ms
lag tolerance. Capacity two also proves the non-preemptive worst-case response
bound:

```text
max_lifecycle_ms + 2 * certified_check_max_ms
  + certified_scheduler_overhead_max_ms <= 1000

250 + 2 * 200 + 100 = 750 <= 1000
```

Peer-deadline protection includes both the proposed operation ceiling and the
certified scheduler overhead. The first protected fault is latched before
interrupt and is hash-bound into pool state and receipt; later telemetry,
cleanup, or close failures can add reasons but cannot replace it. Exactly
missing or zero-byte telemetry after interrupt/close is represented only as a
quarantined, nonattesting, nonaccepting containment observation.

Each child reports cumulative usage. The coordinator rejects counter resets and
sums deltas into one aggregate hard allowance. Pool wall time, worker time, and
poll overhead are reported separately.

## Rendering A Contract

Start each ordinary worker supervisor first so its private state is in
`status=created`. Render each callback-free child control-turn contract, then
build a strict local render request using
`schemas/native-supervision-pool-render-request.schema.json`. The render request
contains local paths and identity fields, but never task text.

```bash
python3 scripts/supervise_native_pool.py render \
  --request /path/to/private/pool-render-request.json \
  --owner-pid HOST_PID \
  --output /path/to/private/pool-contract.json
```

For capacity two, the connected host supplies its fresh capability receipt and
opts in explicitly:

```bash
python3 scripts/supervise_native_pool.py render \
  --request /path/to/private/pool-render-request.json \
  --capability-receipt /path/to/private/adapter-capability.json \
  --enable-concurrency \
  --owner-pid HOST_PID \
  --output /path/to/private/pool-contract.json
```

`HOST_PID` is the long-running process that will own the coordinator. For
capacity two it must match the capability receipt's live process identity.
When rendering and execution happen in one Python host, call
`cwo_core.native_pool_config.build_pool_contract()` directly and omit
`owner_pid`; the current process is used for capacity one.

The connected native adapter callbacks cannot be serialized into a subprocess.
Execution therefore remains a host API:

```python
from cwo_core.native_pool import NativePoolCoordinator

coordinator = NativePoolCoordinator(
    contract,
    child_control_contracts,
    task_inputs,
    child_adapter_callbacks,
    pool_callbacks=trusted_pool_callbacks,
    lease_registry=lease_registry,
    capability_receipt=capability_receipt,
    state_file=pool_state_file,
    decision_file=pool_decision_file,
    control_file=pool_control_file,
)
receipt = coordinator.run()
```

The task inputs enter only this trusted in-process execution API. They are not
written to the pool contract, decisions, status report, control request, or
audit summary.

## Validate, Inspect, And Interrupt

Validate any strict pool artifact, optionally with its cross-binding contract
and state:

```bash
python3 scripts/supervise_native_pool.py validate \
  --artifact /path/to/private/pool-receipt.json \
  --contract /path/to/private/pool-contract.json \
  --state /path/to/private/pool-state.json
```

Status reports absolute configured, admitted, executing, awaiting-close, and
terminal worker counts. They include per-worker and aggregate usage, remaining
hard allowance, pool/worker/poll timing, lease lifecycle, dispositions, and
canonical artifact hashes. Auditing is opt-in for read-only status inspection
and requires a Bead identity:

```bash
python3 scripts/supervise_native_pool.py status \
  --contract /path/to/private/pool-contract.json \
  --state /path/to/private/pool-state.json \
  --receipt /path/to/private/pool-receipt.json \
  --audit-file /path/to/private/audit.jsonl \
  --bead-id PROJECT-BEAD
```

Request a pool-wide interrupt by writing the coordinator's configured control
file. The request is mode 0600, canonical-hash sealed, and bound to the exact
observed state sequence and hash:

```bash
python3 scripts/supervise_native_pool.py interrupt \
  --contract /path/to/private/pool-contract.json \
  --state /path/to/private/pool-state.json \
  --output /path/to/private/pool-control.json \
  --reason "operator requested bounded stop"
```

The coordinator consumes at most one control artifact. A valid request, an
invalid request, unsafe permissions, or a symlinked control file all cause
containment. Interrupt wins after it is requested, including after completion
was observed but before the terminal comparison and close completed. A closed
or control-failed pool cannot accept a new request.

## Failure And Lease Rules

Pool-wide protected failures include control loss, callback overrun, scheduler
lag beyond policy, aggregate allowance exhaustion, integration mutation,
shared-read-only mutation, unattributable workspace activity, state watermark
change, duplicate coordinator, and capability or topology mismatch. The pool
interrupts every affected admitted child and issues only a nonaccepting receipt.
An isolated child semantic failure may preserve an independently accepted peer,
but the pool receipt remains partial and nonaccepting.

Leases remain held until terminal workspace comparison succeeds. Ordinary
completion releases them only after a hash-valid completed or closed pool
state. Control failure leaves `release-pending`; missing terminal evidence leaves
`orphaned-active`. Cleanup never guesses:

```bash
python3 scripts/supervise_native_pool.py cleanup-leases \
  --registry /path/to/private/pool-leases.json \
  --terminal-state /path/to/private/pool-state.json
```

Cleanup changes a stale lease only when its recorded owner process is dead and
the supplied terminal state is valid and identity-bound. Otherwise the lease
continues to block overlapping work.

## Rollback

Rollback does not require deleting artifacts or weakening validation:

1. Stop admitting capacity-two cohorts.
2. Leave `default_max_active_workers=1`, set `status=canary-gated`, and set
   `cap_two_operative_release=false` in policy.
3. Interrupt any active pool through its bound control file.
4. Preserve nonaccepting receipts and release-pending leases for adjudication.
5. Run capacity one through the same coordinator, schemas, telemetry, and
   workspace checks.

Precommit, candidate packet construction, prompt rendering, retry, resume,
replay, outside critic review, integration, and publication stay single-flight
regardless of the pool capacity setting.
