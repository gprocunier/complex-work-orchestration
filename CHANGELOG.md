# Changelog

## Unreleased

- Add a disabled-by-default, one-shot native tool-boundary activation preview
  for fixed N=1/N=2 read-only or N=1 mutable certification, with private signed
  approvals, permanent claims, a separate intent ledger, and no retry or
  resume path.
- Release bounded three-worker native supervision pool. Concurrent capacity
  requires explicit opt-in, a fresh capability receipt, and isolated or
  shared-read-only topology. It remains experimental and disabled by default;
  N>=4 remains blocked.
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
