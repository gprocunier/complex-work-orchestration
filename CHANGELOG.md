# Changelog

## Unreleased

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
