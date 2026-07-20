# Changelog

## Unreleased

- Centralize the pinned native worker model in
  `policy/native-worker-execution.yaml`: runtime helpers now read the pin
  through policy accessors, and the repository validator scans docs, schemas,
  policies, and scripts for stale or unauthorized worker-model pins.
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
- Release bounded two-worker native supervision pool. Capacity two requires
  explicit opt-in, a fresh capability receipt, and isolated or shared-read-only
  topology. It remains experimental and disabled by default.
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
