# Changelog

## Unreleased

- Refuse unsupported disclosure formats, encodings and attachment declarations, and verify decoded fields and final serialized text before manual export, browser submission or local HTTP dispatch.

## 0.2.1 - 2026-11-14

- Added an optional repository hook to check commit messages and contributor identity.
- Added a release inventory rebind command that reports affected routes and refuses stale source spans.
- Tightened parallel test checks for missing results and incorrect case counts, with regression tests for failed groups and serial test isolation.
- Added a CI-parity release test environment covering checkout includes, relocated Python and four-CPU execution.
- Added explicit host selection and transport dry runs to the release gate dispatcher.
- Limited push-triggered CI to `main` and `v*` tags while preserving pull-request checks.
- Made polling-close test coverage deterministic while preserving admission and containment checks.

## 0.2.0 - 2026-11-11

### Highlights

- Successful delivery stays open as `pending-acceptance` until acceptance can be verified.
- Host audit history uses sealed segments, a retained head checkpoint and crash recovery.

### Disabled in this release

- Successful Bead closure is refused; use `--disposition pending-acceptance` for delivered work awaiting acceptance.
- Local HTTP dispatch (`dispatch_work.py --execute-local`), live browser dispatch and browser model confirmation refuse. Local envelope preparation and manual export remain available.
- The registered native single-worker route, concurrent pools, live campaigns and activation preview ship with default-off live holds. Offline validation and dry-run preparation remain available.
- Risk narrowing through `--risk-scope` or `--risk-evidence-dir` is refused.
- Stale-agent cleanup detects processes but cannot terminate them; termination requests report `termination-unavailable`. Registry pruning remains available.

### Changed

- Native routing policy v3 selects Luna first and requires a recorded reason for Terra escalation. Spark and v2 routing records are historical. Live holds still apply.
- Default audit consumers use `../.cwo-host-state/<workspace-name>/audit.jsonl`; `CWO_AUDIT_FILE` no longer redirects them. Explicit custom logs are diagnostic.
- Public return intake requires a recorded manual executor dispatch. Peer review requires a version 2 record bound to the dispatches and exact return/evaluation; self-review and same-session review refuse.
- Native RPC methods outside the containment allowlist recheck the single-worker hold. Campaign adapters default to the held campaign route when selection is omitted.
- The installer follows `policy/install-projection.yaml`, verifies a staged copy before activation, retains backups and supports `--uninstall`.
- Site code highlighting preserves named less-than entities.

### Added

- `setup_workspace_database.py` records the physical identity of an existing workspace database without invoking Beads.
- Installed-skill drift checks, schema validation for registered policies and change-focused code-health ratchets.
- A bounded release effect inventory with complete script byte/mode bindings, classified Python effect candidates, per-hit dispositions and guard-form checks. It runs during repository validation.
- A required Debian 13 filesystem release gate in CI, alongside separate Linux filesystem qualification.
- Method-group sharding for slow unittest modules, with isolated child processes, repeated fixtures, serial stateful tests and preserved diagnostic output.
- A claims register, threat model and host audit history reference.
- Codex app-server protocol schema pins for 0.162.0 and 0.163.0.

### Security

- Outbound screening inspects final serialized bytes and decoded views; return tripwires flag suspicious content for evaluation and adjudication.
- Audit verification checks retained digests, links, checkpoints and segment seals. Same-account rewriting remains possible; packet attestation is an unkeyed digest. See [the claims register](references/claims-register.md).

### Known limitations

- Checks are cooperative; CWO supplies no sandbox of its own.
- Tested on Linux with Python 3.12 and 3.14. Qualification of other platforms and interpreter versions is not established.
- Concurrent native work and new worker-surface qualification are unavailable in this release.

### Upgrading

- Reinstall with `scripts/install.sh` after reviewing the live holds. Caller-written approval files cannot replace host-owned records; default audit history now lives outside the package tree.
