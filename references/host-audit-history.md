# Host audit history and recovery

Workspace policy selects `../.cwo-host-state/<package-name>/audit.jsonl`, relative
to the package root. For an installed skill, this is beside the installed skill
directory, under `.cwo-host-state/<package-name>/`. This replaces the old default
`.orchestration-audit/audit.jsonl`. No CLI flag or environment variable selects
host record authority. `CWO_AUDIT_FILE` is ignored by all default writers,
quota checks, matching, verification, telemetry import and status readers.
Explicit `--audit-file`/`--audit-log` custom logs remain diagnostic legacy
readers; they cannot stand in for the configured host chain.

## One chain, bounded segments

`audit.jsonl` is segment zero. Automatic rotation seals it and creates
`audit.segment-000001.jsonl`, followed by consecutive numbered segments. The
active file is selected by the private `audit.jsonl.head.json` checkpoint.
Sealed files are never appended again. Each seal contains the segment index,
exact byte count, event count, final event hash, previous segment's final event
hash and SHA-256 of its exact content. The first event in every later segment
links to the previous segment's final event hash. The checkpoint commits the
ordered seals, active segment index, global event count, active byte count and
current chain head. This is one audit chain, not independent per-file chains.

The original limits remain **16 MiB (16,777,216 bytes)** and **100,000 events per
segment**, including JSON encoding and newline bytes. A single event cannot
exceed the byte limit. History is explicitly bounded to **16 segments**,
**256 MiB (268,435,456 bytes)** and **1,600,000 events** in total. The checkpoint
has a separate 65,536-byte metadata bound. Record size, record count and record
scan bounds remain unchanged. Tests use smaller explicit limits to cross these
boundaries without stress runs.

Every authoritative read verifies the complete retained history through the
current checkpoint. Default event iteration, quota counting, matching, status
reporting and `verify_audit_log.py` use that same history. Rotation cannot reset
a quota, discard an old dispatch receipt or make an older acceptance unverifiable.
Missing, reordered or truncated segments, a changed seal/content digest, an event
hash or seam mismatch, and a missing or inconsistent checkpoint refuse closed.
All paths use owner-private descriptor traversal with no symlink following,
regular single-link files and the existing worker-root exclusion checks.

This is bounded retention, not unbounded archival. At any total-history bound,
preflight refuses before writing a record or event. There is no automatic
pruning or fresh-chain fallback: those would forget quota and provenance.
A future capacity or archival migration must preserve both. Copying only the
active JSONL file is not a backup; retain the entire private host state together.

## Rotation interruption

An exclusive product writer records a private `audit.rotation.json` write-ahead
journal before creating a new segment, then atomically commits its checkpoint.
Readers encountering a pending journal refuse without writes. The next product
writer automatically verifies and recovers the transaction under the same lock.
Before any cleanup, the complete bounded referenced-record inventory must pass
its private-file, digest, schema, type and anchor checks. If the exact old
checkpoint remains, its journal-proven pending byte prefix and pending record
must also verify. The host then durably records `rollback_ready` in that same
private journal before removing uncommitted artifacts. A cleanup crash can resume
completed deletions only with that proven ready marker; an initially missing
pending record refuses. If the exact new checkpoint and all its referenced
records verify, committed evidence is retained. Changed pending bytes,
unknown checkpoint outcomes or unavailable verification preserve all evidence
and refuse. No confirmation, signing step or recovery-enabling flag exists.

Interrupted ordinary appends retain their prior exact rollback/uncertainty rules.
Unrelated stray entries do not become records and do not block bounded genuine
lookup. Ordinary writes and rotation recovery remain strict; explicit journaled
maintenance is described in [host-record-quarantine.md](host-record-quarantine.md).
No reader or ordinary writer automatically quarantines unknown records. Do not
remove referenced records, seals or events to make a verifier pass. The chain is tamper-evident and
integrity-only; a same-user process rewriting every record and checkpoint remains
outside the threat boundary.
