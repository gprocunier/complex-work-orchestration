# Native Supervision Pools

Native supervision pools let one trusted host control a fixed cohort of one or
two already-created native worker supervisors. They add bounded concurrency to
the live supervision layer; they do not make packet construction, precommit,
critics, integration, retry, replay, or publication concurrent.

The public contract is deliberately small:

- Capacity one is the default and preserves single-worker behavior.
- Capacity two requires `--enable-concurrency` and a fresh trusted adapter
  capability receipt from the same live host process.
- Capacity above two, threads, hot admission, replacement children, and a
  second coordinator are rejected.
- The cohort, worker sessions, nonces, control turns, state files, worktree
  identities, target paths, aggregate allowance, scheduler, and capability
  evidence are immutable after contract rendering.
- Capacity two remains canary-gated until
  `complex-work-orchestration-18w.6` records successful live canaries and the
  policy release marker changes. Structural support is not operative release.

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
| Operative release | Existing single-worker policy | Canary-gated through 18w.6 |

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
lag tolerance. Capacity two also proves:

```text
2 * certified_check_max_ms + certified_scheduler_overhead_max_ms <= 1000
```

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
2. Leave `default_max_active_workers=1` and
   `cap_two_operative_release=false` in policy.
3. Interrupt any active pool through its bound control file.
4. Preserve nonaccepting receipts and release-pending leases for adjudication.
5. Run capacity one through the same coordinator, schemas, telemetry, and
   workspace checks.

Precommit, candidate packet construction, prompt rendering, retry, resume,
replay, outside critic review, integration, and publication stay single-flight
regardless of the pool capacity setting.
