# Native Supervision Pools

## What This Is

This reference is for operators deciding whether to use CWO's concurrent native
worker supervision. Start with [Native Worker Supervision](native-supervision.md)
for the normal single-worker path. A concurrent pool lets one trusted host control a fixed
cohort of already-created native worker supervisors within the policy ceiling;
it does not make
packet construction, precommit, critics, integration, retry, replay, or
publication concurrent.

Every delegated native worker is supervised; there is no unsupervised mode or
opt-out. One supervised worker remains the standard path. Running two or three
supervised native workers concurrently is an opt-in Tech Preview that is
experimental and disabled by default. It requires one fresh same-host capability
receipt, a fixed cohort, and either isolated mutable worktrees or a shared
read-only topology. The canonical policy releases the certified hard ceiling of
three; N>=4 remains blocked pending Phase 2 architecture and recertification.
Start with the reader-facing
[Native Supervision guide](https://gprocunier.github.io/complex-work-orchestration/native-supervision.html#concurrency-preview),
then review the [deferred hardening](#experimental-status-and-deferred-hardening)
before opting in.

The public contract is deliberately small:

- One worker is the default and preserves single-worker behavior.
- Every concurrent pool requires `--enable-concurrency` and a fresh trusted adapter
  capability receipt from the same live host process.
- The currently released and hard ceilings are both three. N>=4 is not
  represented by the current operative contract and is rejected.
- Capacity above the policy hard ceiling, capacity above the released ceiling,
  threads, hot admission, replacement children, and a second coordinator are
  rejected.
- The cohort, worker sessions, nonces, control turns, state files, worktree
  identities, target paths, aggregate allowance, scheduler, and capability
  evidence are immutable after contract rendering.
- The operative ceiling is read from
  `native_supervision_pool.capacity.released_max_active_workers`. Increasing it
  requires an explicit operator activation; structural support alone is not
  operative release.

See [Pool Capacity Naming Migration](native-pool-capacity-migration.md) for the
canonical field inventory and the bounded historical-read compatibility window.

## Temporary Audited Tool Boundary

Exact server-side tool enforcement remains the default for operative workers.
When the app server cannot prove that exact allowlist, an ordinary operative
launch still fails closed.

The repository contains a narrower `trusted-detect-and-contain` contract for a
separately activated Tech Preview. It accepts the explicit risk that
`unlisted-built-ins-may-act-before-detection`, so it is not equivalent to
server-side prevention. The serialized tool-enforcement override records the
candidate, campaign, outer authorization, maximum two-worker cohort, maximum
one mutation lane, and risk acknowledgement. Its self-hash proves only that
those fields have not changed; it is intent and audit evidence, never dispatch
authority.

Temporary activation requires an opaque
`VerifiedToolEnforcementActivation` minted by `OperatorApprovalVerifier` from a
signed, unexpired operator approval. The capability is bound to the exact
candidate, campaign, pool identity, fixed child cohort, worker counts, and risk
statement. Pool preflight rejects a missing, copied, serialized, expired,
replayed, or mismatched capability. The supported admitted launcher consumes
the capability before lease acquisition, so a later launch error cannot make
it reusable. If exact server allowlisting is available, the weaker mode is
rejected as unnecessary.

The trusted host constructs the verifier and keeps its verification key and
replay store outside the hostile worker process. A process that controls that
trust root is the operator control plane, not an untrusted activation caller;
expanding the threat model to a compromised host requires an external trust
anchor.

There is deliberately no JSON or command-line representation of activation
authority. `prepare_native_worker.py --tool-enforcement-override` may embed the
audit-only intent in a packet, but that packet is rejected by dispatchable
packet validation and cannot start the single-worker supervisor. Preflight
acceptance is evidence, not dispatch permission.

The disabled-by-default operator path is
`scripts/run_native_pool_activation_preview.py`. It accepts only three fixed
profiles: `n1-read-only`, `n2-read-only`, and `n1-mutable`. It has no arbitrary
prompt, model, tool, task, mutation-path, retry, resume, refill, or replacement
input. It also does not enter the historical
`run_native_pool_live_canaries.py` campaign workflow; its claim, ledger, and
result formats are separate.

Use an absolute owner-private control root outside a clean source repository:

```bash
python3 scripts/run_native_pool_activation_preview.py keygen \
  --control-root /absolute/private/activation-preview

python3 scripts/run_native_pool_activation_preview.py prepare \
  --control-root /absolute/private/activation-preview \
  --profile n1-read-only \
  --source-repo /absolute/clean/source-repository

python3 scripts/run_native_pool_activation_preview.py approve \
  --control-root /absolute/private/activation-preview \
  --prepared /absolute/private/activation-preview/runs/<activation-id>/prepared.json \
  --operator-id "<operator-id>" \
  --identity-source "<trusted-identity-source>" \
  --accept-risk unlisted-built-ins-may-act-before-detection

python3 scripts/run_native_pool_activation_preview.py run \
  --control-root /absolute/private/activation-preview \
  --prepared /absolute/private/activation-preview/runs/<activation-id>/prepared.json \
  --approval /absolute/private/activation-preview/runs/<activation-id>/approval.json \
  --operator-id "<operator-id>" \
  --identity-source "<trusted-identity-source>" \
  --dry-run
```

`--dry-run` verifies the clean commit/tree, signed approval, fixed cohort,
tool-boundary bindings, and offline admission without consuming the approval,
creating a permanent claim, or making an app-server RPC. Live execution remains
a separate operator decision: replace `--dry-run` with
`--enable-tech-preview` only for the exact prepared attempt.

The live path permanently claims the activation ID and campaign nonce before
approval verification, Beads claims, leases, or RPC. A bad, expired, mismatched,
or raced approval therefore burns that plan; prepare a new one instead of
retrying. Owner-private mode 0700 directories and mode 0600 key, plan, approval,
claim, ledger, and result artifacts are required. There is no retry, resume,
refill, replacement, or salvage path.

An activation now accepts only when every child produces its fixed profile's
exact ordered tool trace. The two read-only calls are `git rev-parse HEAD` then
`sha256sum data/shared.txt`; the mutable calls are the frozen `apply_patch`
payload then `git diff --check`. For an exec call, the only tolerated transport
shapes are the exact command alone, the exact command plus the task worktree,
or those two fields plus `login: false`. No other argument key is tolerated.

Every attempted call counts. A failed call followed by a successful retry is
an extra call, not a successful two-call trace. Reordered tools, wrong
arguments, wrong targets, unknown or contradictory results, missing result
pairing, and extra calls all make the pool and result non-accepting. Successful
`apply_patch` evidence additionally requires its same-call, same-turn
`patch_apply_end` event between the call and output. Only a durable successful
terminal event can finalize required trace cardinality; a projected completion
remains pending during the bounded observation window. A non-null
`task_complete.error` is failed terminal control loss, never a successful
completion missing its final token, required calls, or expected mutation. When
that durable terminal was already observed, containment archives it without
issuing a redundant interrupt RPC. If the terminal transition instead wins the
race with the sole interrupt request, the rejected request is adjudicated
against the trusted boundary once and is never retried.

The controller writes the privacy-safe ordered receipts to the private
`records/activation-tool-trace.json` artifact. After both that exact trace and
the raw pool receipt accept, it consumes each pool-authorized implementation
child Bead closure once, in task order, and reconciles the exact post-state. It
never closes the parent or publication Bead. There is no close retry, reopen,
or rollback: if an N=2 close fails after the first child closed, the first
closure remains, the second is left untouched, and the activation rejects.
`records/activation-bead-closure.json` records the outcome.

New live results use
`schemas/native-tool-activation-result-v2.schema.json`. An accepted v2 result
hash-binds both private artifacts through `tool_trace_sha256` and
`bead_closure_sha256`. The v1 result schema remains historical
inspection-only. A trace mismatch or closure failure cannot emit an accepted
v2 result.

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

New steering writes use `cwo-steering-receipt:v2` and
`schemas/native-steering-receipt-v2.schema.json`. The zero-tool critic prompt
must request canonical JSON with six separate sections: `operator_facts`,
`observed_evidence`, `model_interpretation`, `recommendation`,
`strongest_counterargument`, and `agent_authored_constraints`. It must state
that recommendations, confidence, interpretations, and agent-authored
constraints are advisory only. An operator fact is accepted only when its exact
provenance matches an opaque authority returned by the verified operator-fact
directive path and that directive's signed action hash binds the exact fact
statement; copying, reusing, or constructing a provenance-shaped dictionary is
not sufficient. V2 steering carries repository-policy authority capped at one
child. A critic recommendation can select only policy-bounded child
continuation paths; critic identity strings, prose, and confidence never mint
or widen authority. Every v2 outcome, including `go`, requires a hash-bound
architect `go` before consumption; a stop additionally requires its exact
resolution proof. A stop retry targets the receipt's exact Bead child.
Historical v1 receipts remain readable only when their
opinion hash is intact; they cannot produce stop metadata or be newly consumed.
Progress decisions use the same separation in
`native-progress-decision-v2.schema.json`; their worker-authored recommendation
cannot populate `operator_facts` or broaden the policy-derived child scope.

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
at least one second apart. Startup probes remain bounded by the 30-second
startup deadline and do not certify operative callback timing. After the first
complete exact observation, certified checks remain within 200 ms and polling
runs no slower than 250 ms through immediate pre-interrupt revalidation. The
controller excludes terminal, failed, declined, rerouted, compacted, malformed,
duplicate, truncated, or rewritten telemetry. The same turn must confirm
interruption within five seconds.

Materialization evidence contains only identities, fresh nonces, timestamps,
status classes, record/item indices, counts, offsets, and domain-separated
hashes. Raw prompts, commands, output, responses, reasoning, content, paths,
and path hashes are forbidden. The authorization latch is mode 0600 and
monotonic. A protected fault durably changes `active` to `containment-only`
before returning; only interrupt, close, sanitized evidence, reserved steering,
Beads updates, local checkpoint, pickup, and handoff remain possible.

Callback observations are telemetry, not timing authority. A concurrent-pool
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

The historical capacity-two release campaign has exactly seven fresh turn starts: capability
interruption, two concurrent read-only workers, two concurrent disjoint mutable
workers in disposable worktrees, and an interrupted worker while its peer
completes. No turn is resumed or salvaged. The canary path requires
the frozen `cap_two_operative_release=false` manifest field; after its evidence
was accepted, that historical release sprint changed its policy pair together.
This alias is inspection-only now. New policy and pool artifacts use the
generalized capacity fields.

## Experimental Status And Deferred Hardening

Concurrent capacity is a practical experimental capability for a trusted
same-user control plane. The released path remains bounded to three fixed
workers, explicit opt-in, one connected host process, immutable admission, and
isolated mutable worktrees or strictly shared read-only topology. Capacity
N>=4 remains non-operative.

The accepted campaign proved same-epoch application-level recovery for the
observed pre-attestation startup scaffold, with one guarded wire request, one
consumed retry token, unchanged identity and workspace, and the normal trusted
validators restored afterward. The following work is deliberately deferred and
tracked separately:

- transport-level exactly-once guarantees below the app-server API;
- atomic serialization with concurrent session-log ingestion;
- exhaustive rejection of every harmless unknown JSONL extension;
- recursive inclusion of the complete historical proof DAG in each campaign;
- broader optimization and refactoring beyond the currently released cohort.

These limitations do not relax wrong-model, control-loss, mutation-attribution,
ambiguous-dispatch, terminal-boundary, or second-failure rejection.

## Topology

Every mutable child needs a distinct clean Git worktree and non-overlapping
integration target paths. The integration checkout is monitored and must remain
clean during worker execution. Three read-only children may share one clean
worktree only when all declare no write or integration target paths.

| Surface | Single worker | Concurrent pool |
| --- | --- | --- |
| Fixed cohort | Required | Required; currently released up to three children |
| Mutable worker worktree | Isolated from integration | One distinct worktree per child |
| Shared read-only worktree | Allowed | Allowed only when every child is read-only |
| Integration target paths | Scoped, non-symlinked | Scoped and non-overlapping |
| Adapter capability receipt | Must be absent | Fresh, exact, trusted, and same-host |
| Explicit opt-in | No | `--enable-concurrency` |
| Operative release | Existing single-worker policy | Must not exceed `released_max_active_workers` |

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

Single-worker pools skip `capability-validated`. Admission is sequential: a
child lease is acquired before that child's first adapter callback. Scheduling
uses earliest deadline with deterministic rotation for ties. `step()` invokes
at most one adapter callback and never sleeps; only the host's `run()` wrapper
sleeps. New receipts use `timing.accounting_version=exclusive-v1` and expose
mutually exclusive nanosecond counters for adapter callbacks, non-callback
control-turn invocation, coordinator work, and declared wait time. Their sum
equals `pool_wall_seconds`; `poll_overhead_seconds` is the non-callback invoke
plus coordinator buckets, so callback and wait time are never included.
Coordinator time includes pool-owned evidence reads, workspace checks,
persistence, lease operations, and other external I/O. Historical receipts
with only the original four timing fields remain readable. Timing freezes at
the terminal state boundary. The v1 scheduling contract is exactly a 1000 ms
poll interval with 1500 ms lag tolerance. Concurrent admission uses the
requested N in the conservative non-preemptive worst-case response bound:

```text
max_lifecycle_ms + N * certified_check_max_ms
  + certified_scheduler_overhead_max_ms <= 1000

250 + 2 * 200 + 100 = 750 <= 1000
250 + 3 * 200 + 100 = 950 <= 1000  # released N=3
250 + 4 * 200 + 100 = 1150 > 1000  # rejected
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

## Proportionality Candidate Gate

`cwo_core.native_pool_proportionality.pool_proportionality_check()` is the
model-free economic gate between canonical Beads readiness and fixed-cohort
reservation. It accepts the exact P1-13A readiness snapshot and compatible
subsets plus the corresponding validated work estimates. P1-13A seals the
exact ordered cohort-membership commitments inside the snapshot, so a new
self-hashed subset assembled from otherwise valid candidates is rejected. The
assessment binds the readiness, estimate-set, policy, and cohort hashes and
remains `candidate-evidence-only`; it cannot claim work or authorize dispatch.

The provisional policy requires every child to have at least a five-minute p90
runtime and requires gross parallel savings to exceed twice total orchestration
overhead. The model includes a conservative or higher measured fixed cost,
per-worker admission and evidence ceremony, topology, mutation, integration,
and the exact N-worker schedulability demand. Literal-command work is never
pool-eligible. Capacity is only a ceiling: the selector chooses the largest
economical compatible subset, then the highest modeled net savings, then the
P1-13A ready rank and Bead ID.

An economic exception requires a fresh, exact, non-replayable operator approval
verified by `verify_proportionality_override()`; the resulting opaque capability
is atomically consumed by one assessment application. Serialized audit
provenance is not reusable authority, and structural, literal-command,
capacity, snapshot, or schedulability failures are nonwaivable. An accepted N=3
assessment under the current policy is marked `released-capacity`. The
historical `offline-unreleased-candidate` mode remains valid under a rollback
policy whose released ceiling is below the hard ceiling. P1-13B owns render
rejection and pool-contract storage: it must re-evaluate the exact readiness
and work-estimate inputs, then bind this assessment during reservation and
contract construction before the result can participate in productive
admission.

## Rendering A Contract

Start each ordinary worker supervisor first so its private state is in
`status=created`. Productive concurrent execution then uses the admission-bound
version-2 path. It revalidates the exact readiness snapshot, estimates,
proportionality assessment, fixed cohort, worktrees, capability evidence, and
leases before consuming a one-use `FixedCohortAdmissionCapability` in
`cwo_core.native_pool_admitted.run_admitted_native_pool()`.

The version-1 render request and direct coordinator surface remain available
for strict artifact validation and compatibility inspection. They are not the
admission-bound version-2 path. A version-2 admitted contract passed directly
to the coordinator is rejected with `admitted-pool-launcher-required`; a
serialized request, contract, receipt, hash, or preflight result cannot replace
the admission capability.

The callback-free rendering interface is:

```bash
python3 scripts/supervise_native_pool.py render \
  --request /path/to/private/pool-render-request.json \
  --owner-pid HOST_PID \
  --output /path/to/private/pool-contract.json
```

For a concurrent artifact, the connected host supplies its fresh capability
receipt and opts in explicitly:

```bash
python3 scripts/supervise_native_pool.py render \
  --request /path/to/private/pool-render-request.json \
  --capability-receipt /path/to/private/adapter-capability.json \
  --enable-concurrency \
  --owner-pid HOST_PID \
  --output /path/to/private/pool-contract.json
```

`HOST_PID` is the long-running process that owns admission and coordination. It
must match the capability receipt's live process identity.

The connected native adapter callbacks cannot be serialized into a subprocess.
Productive execution therefore remains a trusted host API rather than a CLI
that accepts serialized authority:

```python
from cwo_core.native_pool_admitted import run_admitted_native_pool

receipt = run_admitted_native_pool(
    reservation_receipt,
    admission_capability,
    contract,
    preflight_request,
    preflight_result,
    child_contracts,
    task_inputs,
    child_callbacks,
    claim_adapter=claim_adapter,
    live_revalidate=live_revalidate,
    pool_callbacks=pool_callbacks,
    lease_registry=lease_registry,
    capability_receipt=capability_receipt,
)
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

1. Stop admitting concurrent cohorts.
2. Leave `capacity.default_max_active_workers=1` and set
   `capacity.released_max_active_workers=1` in policy through the protected
   operator-approved policy path.
3. Interrupt any active pool through its bound control file.
4. Preserve nonaccepting receipts and release-pending leases for adjudication.
5. Run one worker through the same coordinator, schemas, telemetry, and
   workspace checks.

Precommit, candidate packet construction, prompt rendering, retry, resume,
replay, outside critic review, integration, and publication stay single-flight
regardless of the pool capacity setting.
