# Explicit host-record quarantine

Genuine host-record searches verify every anchored record and the complete audit
history. Unreferenced directory entries do not become records or authority and do
not block a bounded search. All entries still count toward the original record
and scan-byte limits. Selected digest lookups and acceptance verification remain
strict and read-only. Missing, tampered, wrong-type or unsafe referenced records
refuse; a caller-selected forged acceptance never triggers cleanup.

`configured_store().quarantine_unreferenced()` is the explicit maintenance API.
It uses only the workspace-configured store, outside worker-writable roots. It
does not accept a caller root, an approval record, an effect grant or a recovery
flag. Tests use private `HostRecordStore.for_tests` fixtures. Do not run maintenance
on an active installed store as part of an offline code check or rehearsal.

Before mutation, maintenance verifies all anchored records and known typed
record references, then preflights the complete orphan batch, manifest, journal
and audit capacity. Source files must be stable, owner-private 0600 regular
single-link files within the existing limits. Links, nonregular objects, changed
identities, capacity exhaustion or corrupt references refuse. Unknown contents
are opaque; they are not interpreted as permissions or authority.

An unsupported unreferenced entry refusal names that entry and a manual step.
For a regular file with the wrong mode, preserve it and restore owner-private
0600 permissions. Preserve a directory outside `records/` before removing its
entry; remove only an unsupported symlink, without following it. Maintenance
performs none of those manual changes automatically.

Known references include persisted peer-review separation dispatch digests in
hold clearances, evaluation/pending snapshots, and `return_evaluated` audit facts.
Only those defined containers and typed keys are inspected; arbitrary nested
hex strings and output hashes do not become host-record references. A missing
or unanchored nested dispatch refuses before any movement. Genuine nonpeer
snapshots may omit separation metadata or retain `None`.

Files are exclusively copied into a private `quarantine/tx-…/files` directory,
verified and fsynced before an identity-checked source unlink. Existing destination
bytes are never overwritten. This preserves source bytes and stat evidence; it
does not preserve the source inode. The immutable manifest binds the old audit
checkpoint and each source/destination. A separate bounded
`records.quarantine.json` journal records progress.
Its first publication and the audit rotation journal use a temporary file,
fsync and an atomic no-replace rename, so interruption during their first write
cannot publish a partial final journal or overwrite an existing claim. The
Linux no-replace primitive must be available; otherwise publication refuses.
Later updates replace only the transaction's already-verified journal.
An unreferenced temporary file retains its bytes for
inspection and does not become a record or a recovery instruction.

All orphans leave `records` before the original audit append/rotation machinery
records `host_records_quarantined`. Its retained transaction ID, manifest digest
and count are audit facts only. They are neither host-record anchors nor
acceptance, clearance, database-selection or closure receipts. Quarantined bytes
cannot be loaded as host records merely by possessing their digest.

While a journal is pending, ordinary readers refuse without writes and ordinary
record/audit writers refuse before rotation or record creation. Explicit
database initialization also checks the pending gate before its external identity
file and holds that same exclusive audit lock through the host-record commit.
Only a subsequent explicit maintenance call recovers it. A verified committed event retains the
quarantined bytes. A verified old checkpoint and exact planned pending-event
prefix allow rollback. Recovery verifies real sealed history and referenced
records before cleanup; an old prefix alone never permits truncating foreign
audit bytes. Partial copies/restores resume only their proven bytes. An uncertain
outcome preserves the journal and evidence and refuses.

When no quarantine transaction is already pending, explicit maintenance may
first recover a pending audit rotation while holding that same exclusive lock.
It verifies every anchored record and counts every directory entry and byte;
unrelated entries remain untouched until the subsequent quarantine transaction.
The existing exact old/new checkpoint and pending-record recovery checks remain
mandatory. Ordinary writers keep their strict inventory refusal, and recovery
of an already-pending quarantine still requires its exact planned rotation event.

Successful and rolled-back transactions retain their private manifest, copies
and outcome for custody. Repeating maintenance after success adds no second
completion when there are no orphans. Ordinary product writes remain strict
before maintenance and resume after it succeeds. There is no automatic pruning,
reader repair, ordinary-write autohealing, quota reset or fresh audit chain.
Existing audit/record limits and the integrity-only, same-user threat boundary
remain unchanged. Local component acceptance does not activate installed-store
maintenance, production closure, live/paid work or any held route.
