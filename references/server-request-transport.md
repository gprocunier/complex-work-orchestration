# Server request transport boundaries

The [selected qualification target](codex-protocol-capability-matrix.md#selected-qualification-target)
uses Codex 0.163.0 with `workspace-write`, `approvalPolicy: never`, no network,
and a bwrap host. The profile remains unqualified. This selection does not
enable approval-dependent execution or change a live-route hold.

The shared `AppServer` implementation lives in
`scripts/cwo_core/supervision/transport/`; the former canary module still
exports the same objects. Its historical reader queues a message with both
`id` and `method` as a notification and sends no reply. That behavior remains
covered by compatibility tests. Notification history and unmatched responses
have no finite storage cap, and raw line intake has no frame-size cap. These
are open transport limits on this path. Request timeouts do not establish a
storage bound or supply a missing protocol response.

The separate registered reader in `scripts/registered_n1_factory.py` uses
`RegisteredServerRequests` for typed requests. Its registered configuration
requires an experimental named permission profile with `untrusted` approvals
and the `user` reviewer. It is a different configuration from the selected
qualification target. Its offline tests use a fake child with real protocol
pipes and consumer code; they do not establish Codex runtime or OS enforcement.

That registered consumer bounds frames, requests, pending decisions, item
contexts and reply deadlines. A separate decision thread allows terminal
events, EOF and deadline handling to continue while a decision is blocked.
Correlation includes connection epoch, typed request ID, thread, turn, item
and optional approval ID. Stale, duplicate, cross-turn and terminal requests
cannot supply an accepting reply. Reconnect requires a fresh factory and
epoch. Unknown methods receive a protocol error before bounded containment.

Command and file replies use `decision`; permission requests receive empty
`permissions`. File requests are declined because their parameters do not
provide authenticated changed-path evidence. Reason text supplies no rename
destination. Session decisions, rule amendments and permission grants are
unavailable through this consumer. Identical actions require fresh correlated
decisions. A failed approval path remains unavailable without fallback.

`tests/test_registered_transport_contract.py` checks actual registered-reader
replies for useful command acceptance, file refusal, permission refusal and
command cancellation against the pinned 0.163.0 stable and experimental
response schemas. The additional schemas match the existing complete bundle
manifests; no pin or historical contract hash changes. These are schema and
fake-child witnesses. Effective configuration, legacy transport limits and
physical containment still need qualification before stronger runtime claims.
