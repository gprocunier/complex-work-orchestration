# Changelog

## Unreleased

- Centralize the pinned native worker model in
  `policy/native-worker-execution.yaml`: runtime helpers now read the pin
  through policy accessors, and the repository validator scans docs, schemas,
  policies, and scripts for stale or unauthorized worker-model pins.
- Enforce a trusted session-file invariant in native supervision: the live
  supervisor and retrospective session checker fail closed when the session
  JSONL is a symlink, wrongly owned, group/world-writable, or in an unsafe
  directory.
- Gate native dispatch and acceptance on supervision receipts:
  `prepare_native_worker.py render` requires an armed supervision state bound
  to the packet hash and control turn (`--preview-only` renders a watermarked
  non-dispatch copy), and `validate-return` requires a finalized supervision
  state unless a `--allow-unsupervised-return` waiver with a reason is
  recorded.
- Move architecture-critic trigger phrases into
  `policy/routing-policy.yaml` (`architecture_critic_triggers`) so routing
  opt-in phrases are operator-tunable policy instead of code; the validator
  checks the registry against the executor registry.
- Collapse sabotage thresholds to a single policy source
  (`contracting-controls.yaml` `sabotage_policy.thresholds`, effective values
  unchanged); shadow threshold blocks in acceptance-policy and
  peer-review-policy were removed and the validator rejects reintroduction.
- Add `scripts/render_control_effectiveness.py`: aggregates supervisor and
  return-evaluation audit events into proof-period rubric metrics
  (control-loss rate with a spurious-vs-substantive split, poll health,
  quarantine rates) with tuning hints for `poll_lag_tolerance_ms`.
- Document why live supervision polls in control turns (harness limitation,
  not preference) and the trusted session-file invariant in
  `references/execution-environments.md`.
- Restrict `--snippet-file` contractor-packet inputs to repository-safe files.
  Outside-repository absolute paths are now rejected; use a repo-local ignored
  work-packet file for external review snippets.
- Remove local ChatGPT browser config paths from dispatch summaries.
- Add explicit contractor-return prompt-injection sabotage detection.
- Add configurable Beads subprocess timeouts and direct-scaffold recovery
  guidance for partial graph creation.
- Serialize local audit hash-chain appends with POSIX file locking when
  available, with best-effort metadata on unsupported platforms.
- Expand explicit Claude/Gemini second-opinion and ChatGPT master-review
  routing phrases while preserving provider opt-in requirements.
