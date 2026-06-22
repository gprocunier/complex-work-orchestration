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
Role-specific local model profiles live in `policy/model-profiles.yaml`, with
runtime shape described by `schemas/model-profile.schema.json`.

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
  --environment airgapped-rhoai \
  --role worker \
  --model-profile rhoai-worker-qwen2-5-coder-32b-fp8 \
  --json \
  "Review command examples for execution environment wording."
```

The JSON envelope follows `schemas/harness-dispatch-envelope.schema.json`. It
includes `envelope_version=1.0`, lifecycle state `rendered`, a prompt SHA-256,
execution environment, harness, role, capability requirements, timeout,
selected `model_profile`, sanitized `model_profile_details`, suggested command,
and constraints. It must not include API keys, bearer tokens, browser cookies,
kubeconfigs, or other credential values.

## Airgapped Model Matrix

The model-profile registry is RedHatAI-first because OpenShift AI vLLM is the
documented local serving exemplar. These profiles are high-confidence starting
points for airgapped GPU-backed operation, not promises of proprietary frontier
model parity. Endpoint model aliases such as `rhoai/architect` are operator
conventions; the backing Hugging Face model IDs remain recorded in
`policy/model-profiles.yaml`.

| CWO role | Connected default | Practical airgapped profile | Enterprise candidates | Confidence |
| --- | --- | --- | --- | --- |
| Architect | Codex 5.5 x-high architect | `rhoai-architect-mistral-small-4-119b-nvfp4` | `rhoai-architect-nemotron-3-ultra-550b-a55b-fp8`, `rhoai-architect-glm-5-2-fp8` | High after benchmark |
| Project manager | Codex PM or smaller coordination model | `rhoai-project-manager-qwen3-6-35b-a3b-nvfp4` | `rhoai-project-manager-qwen3-6-35b-a3b-nvfp4`, `rhoai-architect-glm-5-2-fp8` | High |
| Workerbee | Codex 5.3 Spark | `rhoai-worker-qwen2-5-coder-32b-fp8` | `rhoai-worker-qwen2-5-coder-32b-fp8`, `rhoai-architect-glm-5-2-fp8` for Beads-heavy reasoning packets | High |
| Review worker | Codex 5.3 Spark review-only subagent | `rhoai-reviewer-nemotron-3-nano-30b-fp8` | `rhoai-reviewer-llama-4-maverick-17b-128e-fp8`, `rhoai-architect-nemotron-3-ultra-550b-a55b-fp8` | Medium to high |
| Local secure reviewer | Local secure reviewer or Codex evaluator | `rhoai-secure-review-qwen3-6-35b-a3b-nvfp4` | `rhoai-architect-nemotron-3-ultra-550b-a55b-fp8` for high-stakes review | High after benchmark |
| Synthesis input | CWO-native synthesis plus architect adjudication | `rhoai-synthesis-qwen3-5-122b-a10b-nvfp4` | `rhoai-architect-nemotron-3-ultra-550b-a55b-fp8`, `rhoai-architect-glm-5-2-fp8` | High after benchmark |

The OpenCode path can therefore run without public frontier providers when the
selected execution environment binds architect, PM, worker, review,
local-secure-review, and synthesis roles to RHOAI vLLM profiles. CWO still owns
Beads memory, dispatch rendering, validation, return evaluation, synthesis
provenance, and architect adjudication.

### H200/CerIO Enterprise Candidates

For medium enterprise and larger disconnected work, the registry includes two
H200-class profiles that are deliberately marked as candidates:

- `rhoai-architect-nemotron-3-ultra-550b-a55b-fp8` uses
  `RedHatAI/NVIDIA-Nemotron-3-Ultra-550B-A55B-FP8-dynamic` for deep
  architecture, security/malpractice review, and synthesis.
- `rhoai-architect-glm-5-2-fp8` uses `zai-org/GLM-5.2-FP8` for long-context
  architecture, Beads-heavy briefing, PM summarization, and synthesis.
- `rhoai-reviewer-llama-4-maverick-17b-128e-fp8` uses
  `meta-llama/Llama-4-Maverick-17B-128E-Instruct-FP8` for multimodal or
  general review work. It is not the primary x-high architecture substitute.

The H200/CerIO test environment is an exemplar: a compact OpenShift cluster with
H200 GPUs, CerIO PCIe 5.0 fabric, same-root-complex GPU enumeration, adjacent
GPU-to-GPU paths, and an extra CPU hop. Other deployments can use the same
profiles, but they should not skip the benchmark gate.

Before promoting either H200 candidate, record evidence for:

- `nvidia-smi topo -m`
- `nvidia-smi topo -p2p w`
- CUDA `p2pBandwidthLatencyTest`
- NCCL `all_reduce_perf` for the intended 8-GPU or 16-GPU shape
- vLLM startup with exact model, context, parser, and tool-call flags
- `/v1/models` and `/v1/chat/completions` smoke tests
- representative CWO architect and synthesis packets
- evaluator scoring and architect adjudication

Use `airgapped-rhoai-h200-nemotron` or `airgapped-rhoai-h200-glm` only after
that benchmark gate is satisfied. Until then, keep `airgapped-rhoai` as the
reasonable practical default.

### Profile Resolution

`scripts/render_harness_dispatch.py` resolves the role binding first:

1. The execution environment chooses the bound harness and agent for the role.
2. A bound `model_profile` supplies the model alias and default variant.
3. `--model-profile` can choose another approved profile explicitly.
4. `--model` is an operator override and disables profile resolution.
5. `--model` and `--model-profile` are mutually exclusive.

Resolved model-profile dispatch is still render-only. It creates the prompt,
hash, suggested OpenCode command, and reviewable envelope; it does not call
OpenCode or the vLLM endpoint.

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
- `policy/model-profiles.yaml` records role substitution, public Hugging Face
  model IDs, confidence, deployment boundaries, and vLLM endpoint assumptions.
- `schemas/execution-environment.schema.json` and
  `schemas/harness-dispatch-envelope.schema.json` match runtime fields.
- `schemas/model-profile.schema.json` matches runtime model-profile fields.
- `scripts/render_harness_dispatch.py` renders versioned OpenCode artifacts
  with lifecycle state, capability requirements, model profile metadata, and no
  execution by default.
- Tests cover profile references, OpenCode exemplar assumptions, secret-free
  dispatch artifacts, and repository validation.
- Public docs explain Codex as a default environment, OpenCode as the v2
  exemplar, and OpenShift AI vLLM as the local serving exemplar without
  implying any external sharing in airgapped mode.
