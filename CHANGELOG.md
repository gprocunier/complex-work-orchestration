# Changelog

## Unreleased

- Release bounded two-worker native supervision after the accepted seven-turn
  live campaign. Capacity two still requires explicit opt-in, a fresh trusted
  same-host capability receipt, aggregate budgets, and isolated or strictly
  shared-read-only topology. It remains experimental and disabled by default;
  all other orchestration surfaces remain single-flight.
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
