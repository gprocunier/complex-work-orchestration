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

Before handoff, run:

```bash
python -m compileall .
python -m unittest discover -s tests -v
./scripts/install.sh --skills-dir /tmp/cwo-skill-test/skills --yes --dry-run
```
