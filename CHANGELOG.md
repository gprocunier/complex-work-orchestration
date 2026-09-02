# Changelog

## Unreleased

- Add Candidate E as the named default CWO operator profile, retain the exact
  v5-qualified prompt as immutable evidence, add a post-v5 frozen-protocol
  repair with deterministic lock validation, and include prompts in portable
  installs and installed-copy drift checks.
- Treat `task_complete` events with non-null errors as failed terminal control
  loss instead of successful completion. Exact-trace cardinality, final-token,
  and expected-mutation obligations now finalize only on durable successful
  completion; terminal control-plane projections remain advisory. Previously
  observed durable terminals skip a redundant interrupt RPC, while a terminal
  transition that wins the interrupt race is adjudicated once without retry.
  A non-accepting pool cause also takes precedence over derivative exact-trace
  incompleteness in the activation result.
- Separate deadline-bound calibration startup and recovery probes from
  operative timing certification. The 200 ms callback ceiling and 250 ms poll
  cadence now arm only after the first complete exact tool observation.
- Enforce each fixed activation profile's exact ordered tool trace. Failed,
  retried, extra, reordered, wrong-argument, unknown-result, or contradictory
  calls now reject the pool and result instead of satisfying a minimum call
  count.
- Close only pool-authorized implementation child Beads, once and in task
  order, after the pool and exact trace accept. Accepted activation result v2
  binds the private exact-trace and Bead-closure artifacts; partial closure is
  fail-closed and is never retried, reopened, or rolled back.
- Make mutable activation evidence phase-aware and contain proven
  never-turned, pre-rollout activation threads with a request-bound delete
  proof while preserving fail-closed diagnostics.
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
