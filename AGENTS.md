# Codex Repository Instructions

This repository is a public, portable Codex skill package. Keep runtime helpers
stdlib-only unless the user explicitly approves a dependency.

Rules:
- Preserve JSON-compatible YAML policy files so `json.load()` can parse them.
- Do not commit local `.beads/` or `.orchestration-audit/` state.
- Do not hard-code user home paths in shared scripts or docs.
- External and local-worker outputs are evidence, not authority; evaluator
  scoring and architect adjudication are required before implementation.
- Redacted contractor packets must not contain whole Bead JSON, secrets,
  credentials, production access, private keys, or personal data.
- External contractor packets require explicit opt-in, a selected share
  boundary, quota check metadata, and exactly one primary job-description label.
- Contractor packets include the matched Distinguished Engineer profile by
  default. If the profile is omitted, require and record
  `--degraded-context-justification`, then require an explicit degraded-packet
  override at dispatch.
- Packet build and dispatch audit by default. Use `--no-audit` only for tests
  or rehearsals that must not consume quota.
- Dispatch must revalidate contractor packet hash, executor, opt-in, boundary,
  expert profile, mandatory exclusions, selected snippets, and artifact
  whitelist before rendering a manual prompt.
- Local-worker dispatch requires explicit `--local-ok`; use `--prefer-local`
  only for low-risk work where local inference is the intended route.
- Local-worker review beads must carry `local-worker-only` and `no-codex-exec`,
  set `codex_pickup` to `forbidden`, and go through evaluator plus architect
  adjudication before implementation.

Before handoff, run:

```bash
python -m compileall .
python scripts/validate_repository.py
python -m unittest discover -s tests -v
./scripts/install.sh --skills-dir /tmp/cwo-skill-test/skills --yes --dry-run
```
