# Execution Environments

This reference explains the v2 execution-environment abstraction. Codex remains
the best-tested connected execution environment, but CWO should not require the
Codex shell when an operator is working in a restricted or airgapped zone.

## Boundary

CWO owns governance:

- Beads work graph and closure memory
- prompt coach sizing
- share-boundary and local-worker opt-in
- contractor packet validation
- return normalization and evaluator scoring
- architect adjudication
- validation and publish gates

Execution harnesses run bounded assignments after CWO has rendered a prompt,
packet, or dispatch envelope. A harness return is evidence, not authority.

## Profiles

Execution profiles live in `policy/execution-environments.yaml`.

- `connected-codex`: current production-quality path. Codex owns architecture
  and integration; OpenShift AI vLLM, Claude, Gemini, or ChatGPT Pro lanes are
  optional evidence after opt-in.
- `connected-opencode-exemplar`: v2 proof point showing that CWO can render work
  to an open harness while retaining Beads, route, evaluation, and acceptance.
- `restricted-opencode-rhoai`: restricted-zone profile using OpenCode plus
  approved providers or local OpenShift AI vLLM.
- `airgapped-rhoai`: Codex CLI is not assumed available. Use local Beads,
  OpenCode or a manual operator shell, and OpenShift AI vLLM or another local
  OpenAI-compatible endpoint.

Harness capabilities live in `policy/harness-registry.yaml`.

## Why OpenCode First

OpenCode is the first open-source exemplar for v2 because it is terminal-first,
scriptable, provider-flexible, and supports local OpenAI-compatible endpoints.
The local CLI also supports non-interactive dispatch with `opencode run`,
`--format json`, `--file`, `--agent`, `--model`, `--variant`, and `--dir`.

The first adapter should render a harness dispatch artifact, not execute it by
default:

```bash
python3 scripts/render_harness_dispatch.py \
  --environment connected-opencode-exemplar \
  --harness opencode \
  --role worker \
  --agent cwo-review \
  --model rhoai/local-model \
  --json \
  "Review command examples for execution environment wording."
```

The JSON envelope follows `schemas/harness-dispatch-envelope.schema.json`. It
includes `envelope_version=1.0`, lifecycle state `rendered`, a prompt SHA-256,
execution environment, harness, role, capability requirements, timeout,
suggested command, and constraints. It must not include API keys, bearer tokens,
browser cookies, kubeconfigs, or other credential values.

## Harness Decision Matrix

| Harness | CWO fit | Initial decision |
| --- | --- | --- |
| Codex CLI | Best-tested connected architect and integration shell. | Keep as default connected adapter. |
| OpenCode | Non-interactive CLI, JSON output, agents, provider flexibility, local OpenAI-compatible support, permission controls. | First v2 open-source exemplar. |
| Hermes Agent | Persistent/self-hosted agent with provider routing and vLLM support. | Later candidate after memory-loop governance review. |
| Goose | CLI, desktop, API, MCP, ACP, recipes, many providers, local model support. | Strong second-wave candidate. |
| OpenHands | Powerful CLI/headless/containerized agent with LiteLLM and JSONL. | Later controlled-runtime candidate due runtime weight and approval risk. |
| Aider | Mature terminal pair-programming and OpenAI-compatible support. | Narrow coding helper adapter. |
| Cline | Strong IDE-local workflow and OpenAI-compatible configuration. | Human IDE workflow, not first scripted harness. |
| Pi | Minimal customizable harness with print/JSON/RPC/SDK modes. | Experimental; needs external sandbox and permission story. |

## Airgap Notes

In an airgapped zone, Codex CLI should not be treated as available. CWO still
has value if the local checkout includes the helper scripts, Beads is available,
and an approved open harness or manual operator shell can run the rendered
dispatch envelopes. OpenShift AI vLLM is the preferred local serving exemplar
because it can place model serving inside the controlled platform boundary, but
the generic OpenAI-compatible local profile remains available for other stacks.

## Lifecycle

CWO owns execution lifecycle state. A rendered harness dispatch starts at
`rendered` and can later move through `accepted`, `running`, `completed`,
`failed`, or `rejected` when a future adapter records those transitions. Until
that adapter exists, `scripts/render_harness_dispatch.py` only renders the
envelope and suggested command. Concurrent execution against the same Bead is
disabled by default unless a future profile explicitly allows it.

## Acceptance

Before promoting this beyond v2:

- `policy/harness-registry.yaml` and `policy/execution-environments.yaml`
  validate cleanly.
- `schemas/execution-environment.schema.json` and
  `schemas/harness-dispatch-envelope.schema.json` match runtime fields.
- `scripts/render_harness_dispatch.py` renders versioned OpenCode artifacts
  with lifecycle state and capability requirements, without executing them by
  default.
- Tests cover profile references, OpenCode exemplar assumptions, secret-free
  dispatch artifacts, and repository validation.
- Public docs explain Codex as a default environment, OpenCode as the v2
  exemplar, and OpenShift AI vLLM as the local serving exemplar without
  implying any external sharing in airgapped mode.
