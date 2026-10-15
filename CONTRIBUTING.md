# Maintaining CWO documentation

Start with [AGENTS.md](AGENTS.md) for repository rules. Runtime helpers remain
stdlib-only. Documentation or test dependencies must not become prerequisites
for using the installed skill.

## Content ownership

| Reader task | Canonical human guide | Implementation truth |
| --- | --- | --- |
| Install, verify, first task, continue, remove | `docs/get-started.html`, `install.html`, `first-project.html`, `continue-project.html`, `tutorial-recovery.html` | `scripts/install.sh`, `scripts/manage_instruction_profile.py`, installer/profile tests |
| Decide whether to adopt | `docs/index.html`, `docs/workflows.html` | Current skill plus policy and observed execution; compare native features against official vendor documentation |
| Reproduce an example | `docs/use-cases.html`, `examples/first-project/`, `examples/worked-evidence/` | Fixture scripts and tests; separately identified live-run evidence |
| Understand boundaries | `docs/explanation.html` | Access, executor, routing, and supervision contracts |
| Activate the default CWO system prompt | `references/cwo-system-prompt.md` | `scripts/manage_instruction_profile.py`, profile configuration, active prompt and profile tests |
| Find an exact control | `docs/reference.html`, linked `references/` Markdown | Policy, schemas, scripts, and current tests |
| Operate native delegation | Current overview in `references/native-supervision.md` | Active `task_selected_routing`; historical v2 material never grants v3 dispatch |

README is a compact front door, not a second installation manual. Other guides
summarize and link to the canonical sequence rather than copying it. Keep
behavioral details in their existing operator references. Do not rewrite
historical qualification evidence, agent instructions, policy prompts, or
archived examples merely to match current narrative language.

`scripts/generate_site.py` generates the shared shell and navigation while
preserving separately authored HTML page bodies. It is **not** a Markdown-to-site
pipeline. Change the appropriate body, then regenerate the shell. The site
validator imports the shell inventory; safety, privacy, source-link and reader
journey checks remain independently tested.

The shared shell also owns parent-navigation metadata. `docs/site.js` only sets
responsive defaults for native local-contents disclosures; navigation remains
usable without JavaScript. There are no remote scripts or assets. A bounded
`generate_site.py --write --pages PAGE...` updates explicit page shells; the
ordinary `--check` still checks the complete inventory.

## Diagram source and rendering

Author workflow diagrams in `docs/diagrams/flows.json`; the stdlib-only
`scripts/generate_diagrams.py --write` renders static SVG assets and updates the
marked figures in their HTML pages. Sequence geometry and the hook decision
layout live in that helper. Use real SVG nodes, arrowheads and decision branches,
not preformatted ASCII or CSS text-card grids. Existing Mermaid in Markdown
references remains valid diagram source.

Each diagram has wide and narrow SVG variants of the same graph, selected by a
native `<picture>` element, plus a visible text-equivalent caption. SVGs include
an accessible title and description; no JavaScript, remote renderer or external
font is required. Keep the JSON description complete enough to understand every
path without seeing the image. The generated-artifact check runs in CI and Pages.
Inspect full-size desktop and narrow screenshots after changing labels, node
sizes or routes; XML validity alone does not establish legibility.

## Evidence and maturity

For a changed material claim, record the user outcome, owning source/policy,
test or observed run, limitations, and documentation location in the work
artifact. Inspect final consumers, not only a matching schema or CLI flag.
Distinguish default, optional, preview, host-qualified, historical, illustrative,
and planned behavior. Prompt guidance is not deterministic enforcement.

Model identities change faster than reader tasks. Keep exact worker identifiers
in policy and executable reference; use roles in the narrative. Recheck primary
vendor sources before comparing agent features or documenting prerequisites.
Add deliberate exact source URLs to `SOURCE_LINK_PATTERNS` and source-blob
allowlists, with a positive and a lookalike/negative test. Do not disable link
restrictions to make a page pass.

## Validation

Use focused checks while authoring:

```bash
python3 scripts/generate_site.py --write
python3 scripts/generate_diagrams.py --write
python3 scripts/generate_site.py --check
python3 scripts/generate_diagrams.py --check
python3 scripts/validate_site.py
python3 scripts/validate_public_copy.py
python3 -m unittest discover -s tests -p 'test_*site.py' -v
python3 -m unittest discover -s tests -p test_first_project.py -v
python3 -m unittest discover -s tests -p test_worked_evidence.py -v
python3 scripts/check_documentation.py
git diff --check
```

Before handoff, run the broader checks in AGENTS.md and CI, using an isolated
test environment with `requirements-test.txt`. Stateful operations stay serial;
the prescribed test fanout does not authorize concurrent Beads/model dispatch.
Actually install into a disposable Codex home, verify the profile, execute both
tutorial phases in fresh sessions where authenticated access is available, and
record the real model/effort and any deviations. A reference-solution test or
installer dry run is not a live first-use result.

Preview at the GitHub Pages subpath, not just `/`:

```bash
python3 scripts/preview_site.py --port 8765
```

Open `http://127.0.0.1:8765/complex-work-orchestration/`. Inspect desktop and narrow
mobile, keyboard focus/skip link, heading order, navigation, code wrapping,
diagrams and text equivalents, zoom/reflow, retained routes and fragments.
Keep screenshots and a concise result record outside publishable content.
Limited automated checks do not establish accessibility conformance.

## URL and publication discipline

The primary labels changed, not their filenames: Start Here is
`get-started.html`, Examples is `use-cases.html`, Guides is `workflows.html`, and
Concepts is `explanation.html`. Preserve useful old fragments as meaningful
aliases and add new checks before moving/removing them. Advanced pages remain
reachable through Guides and Reference; history stays history.

Never publish raw session logs, credentials, private paths, internal work
packets, or mission-specific model allocations. Review sanitized evidence before
including it in public copy. Run publish sanitization before a formal push,
release, or tag. A passing local change set is not authorization to commit,
push, deploy, change remote metadata, or update someone's installed skill.
