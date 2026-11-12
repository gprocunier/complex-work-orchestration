# Recorded independent peer review

`make_acceptance_decision`, `evaluate_return.py` and the qualified adjudication
broker require a version 2 peer-review record for `peer_review_status="passed"`:

```json
{
  "record_type": "cwo-peer-review",
  "version": 2,
  "reviewer_identity": {
    "provider": "openai",
    "model_family": "gpt",
    "model_id": "gpt-6-astra",
    "reasoning_effort": "max",
    "dispatch_id": "review-dispatch-id"
  },
  "return_sha256": "<64 lowercase hexadecimal characters>",
  "evaluation_sha256": "<64 lowercase hexadecimal characters>",
  "decision": "passed"
}
```

These are exact fields; missing or extra fields refuse. Version is integer `2`,
not a boolean. `peer_review_reviewer` is a separately supplied identity object
with exactly those five fields and must equal `reviewer_identity`. Each component
has 1..128 ASCII characters: an initial letter or digit followed by letters,
digits or `._:@/-`. Validation precedes evaluation and audit persistence.

Identity declarations do not prove dispatch. The evaluator resolves both dispatches
through the configured `HostRecordStore`. Content-addressed records live under the
host state root selected by `policy/workspace-host-state.json`, outside the source
worktree and every worker-writable binding. No CLI argument or worker return can
select that store. Each read verifies private descriptor-safe storage, the record
SHA-256, a matching `dispatch_prepared` event, the bounded existing audit chain and
its current-head checkpoint. Missing records/events, symlinks, wrong modes,
digest mismatches, chain breaks and exceeded bounds refuse.

A host dispatch record has `schema_version: 1`, `record_type: "dispatch"`,
`dispatch_id`, `dispatch_role`, `provider`, `model_family`, `model_id`,
`reasoning_effort`, `session_id`, and a packet or request digest. The executor
record has role `executor`; the reviewer record has role `peer-review` and an
exact `review_target` containing the executor `dispatch_id`, `return_sha256` and
`evaluation_sha256`. The executor identity comes from the dispatch referenced by
the host's received-return receipt for the exact evaluated bytes. An asserted
executor alias must agree with the recorded alias. When a host records an executor
alias, its provider is also checked against the executor/provider registries.

The reviewer declaration must match every recorded identity component. Both model
IDs and families must occur in `provider-registry.yaml`'s `review_models` table.
`provider` names the underlying vendor/family, rather than an access-channel key:
`internal_codex` and `openai_manual` both resolve to `openai`. A caller-written
dispatch sidecar or a declaration in the peer-review JSON establishes no authority.

Preparation may record an unknown runtime identity. A completed original host
can add one immutable observation linked to that preparation's content digest.
Known identity, request context and required-review metadata cannot change; an
observation can fill unknowns and add runtime completion facts. Readers select
that verified observation, and receipts must bind its exact record digest.
Deleting an anchored observation refuses instead of reviving a preparation-only
receipt.

The host intake records the exact executor return digest. For a structured peer
return it validates the identity and dispatched target, then records both the
raw-byte receipt and, when different, the canonical JSON receipt. The review contract requires the
canonical received-decision digest, so knowing a review dispatch ID cannot turn
an arbitrary submitted decision into a received review. Canonical peer-decision
JSON uses the same UTF-8, sorted-key, compact encoding shown below, without a
trailing newline.

Separation is evaluated in this order:

1. The same dispatch, session or model ID refuses. A different reasoning effort
   never makes the same model independent.
2. A different derived provider or registered model family is `cross-family`,
   the preferred separation.
3. Otherwise, the reviewer model must explicitly list the executor model in its
   `stronger_than` policy entry. This is `escalation`. No code ranks model names
   or reasoning efforts. Missing policy edges refuse.

Escalation is accepted when another family is unavailable. It is weaker than
cross-family review because both models share a provider and training lineage.
The evaluator records `peer_review_separation`: the level, executor identity,
both recorded session IDs and both source dispatch SHA-256 digests. Hold-clearance
records and persisted audit events retain this evidence. Human-readable CLI
reports also show the separation level. Audit sanitization validates the entire
bounded identity, record and separation metadata before appending anything.

`return_sha256` binds the exact evaluated UTF-8 text including whitespace and line
endings. The CLI decodes without newline conversion. `evaluation_sha256` binds
the **complete current pending evaluation**, with identical arguments except
`peer_review_status="pending"`, `peer_review_reviewer=None` and
`peer_review_record=None`. The canonical encoding is:

```python
json.dumps(pending, sort_keys=True, ensure_ascii=False,
           separators=(",", ":"), allow_nan=False).encode("utf-8")
```

Hash those bytes without a trailing newline.
`cwo_core.peer_review.pending_evaluation_sha256` implements this encoding. The
evaluator recomputes it before checking dispatch separation. Advisory decoration
is applied afterward. Any change to the return or evaluated metadata requires a
new matching review.

CLI inputs are:

```text
--dispatch-id executor-dispatch-id --peer-review-status passed
--peer-review-reviewer '<structured identity JSON>' --peer-review-record review.json
```

The broker's complete independently observed evaluation metadata includes the
identity object and review record. Its pinned control must observe matching
metadata; reevaluation resolves the host records again. The former
`--peer-review-dispatch-root` option and library argument are removed. Tests inject
an in-process test store; production has no caller-selected record-root seam.

A valid review clears only `peer-review-pending`,
`provider-conflict-peer-review-pending` and `risk-review-pending`. Quarantine,
tripwires, packet-only restrictions, rejection and all other independent holds
remain. The standalone risk helper retains review holds for a bare passed flag.
No review grants execution, activation, installation or closure.

Version 1 reviews and free-text reviewer identities remain historical artifacts.
They cannot clear current holds: reevaluate pending and obtain a version 2 review
using recorded dispatches. Old provider registries may omit `review_models` and
continue to support non-review operations; passed review then refuses closed.
The optional table is a closed-shape extension in both provider schema versions.

The host store prevents a sandboxed worker from writing its own provenance; the
N1 containment test exercises that boundary. Retained record changes, missing
chain events and broken digests/chains are detected and refused. This remains an
integrity-only chain: an unrestricted same-user process able to replace and
rehash the complete history is outside the trust boundary. There is no signature,
human signing step or immutable external anchor. Synthetic fixture identities
are recorded by the product writers in disposable stores, never live model calls.

CWO closure acceptance is written by the existing completed adjudication
control's `current()` observation through its internal `record_acceptance` path. The host reobserves the designated original completion,
checks the exact return and evaluation, and records its autonomous acceptance and
invocation receipt in this same chain. Closure recomputes the full and pending
evaluations from the recorded return, dispatch metadata and current policy before
checking every required hold clearance. Generic record persistence cannot replace
that acceptance receipt. Evidence or task holds without qualified clearance remain
held. `PRODUCTION_CLOSURE_AVAILABLE` stays `False`; this work restores no route.

Dispatch IDs remain single file components: `/` is refused in executor and reviewer
identities before audit persistence, matching the store reader and public schemas.

The public normalizer accepts only recorded manual executor (`manual_ui`)
dispatches. It refuses peer-review, N1, pool, HTTP and unknown host modes before
any receipt/output write, even if caller metadata claims manual mode. Original
host capture writes one `host-capture-v1` receipt whose raw digest and optional
canonical-decision digest refer to the same captured return. Exact byte replay
is idempotent; changed formatting is different bytes and cannot add a second
receipt. Actual raw bytes remain in the original immutable completion/artifact.
Old receipts without that capture provenance cannot grant peer-review authority;
obtain a fresh genuine review rather than relabeling historical evidence.
The [segmented audit history](host-audit-history.md) preserves every old anchor.
