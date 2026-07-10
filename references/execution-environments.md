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
Access profiles live in `policy/access-profiles.yaml`, with runtime shape
described by `schemas/access-profile.schema.json`. They classify how a role
reaches a model or tool: Codex shell, Codex review lane, external manual CLI,
ChatGPT browser review, generic local OpenAI-compatible endpoint, OpenShift AI
vLLM, GLM BF16, or human specialist.

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

Think of the three profile layers this way:

- Execution environment: which harness and executor owns each CWO role.
- Access profile: what kind of access the executor has, which env var names
  configure it, and whether it can read, write, use shell, use web, or share
  externally.
- Model profile: which approved model alias or Hugging Face model ID should
  serve a CWO role.

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
includes `envelope_version=1.0`, lifecycle state `rendered`, a prompt SHA-256
that must match the rendered prompt, execution environment, harness, role,
capability requirements, timeout, selected `model_profile`, sanitized
`model_profile_details`, selected `access_profile`, sanitized
`access_profile_details`, redacted access-profile readiness, shell-quoted
suggested command, and constraints. It
must not include API keys, bearer tokens, browser cookies, kubeconfigs, or other
credential values.

## Airgapped Model Matrix

The model-profile registry is RedHatAI-first because OpenShift AI vLLM is the
documented local serving exemplar. These profiles are high-confidence starting
points for airgapped GPU-backed operation, not promises of proprietary frontier
model parity. Endpoint model aliases such as `rhoai/architect` are operator
conventions; the backing Hugging Face model IDs remain recorded in
`policy/model-profiles.yaml`.

| CWO role | Connected default | Practical airgapped profile | Enterprise evaluation targets | Confidence |
| --- | --- | --- | --- | --- |
| Architect | Codex 5.6 Sol architect | `rhoai-architect-mistral-small-4-119b-nvfp4` | <ul><li><code>rhoai-architect-nemotron-3-ultra-550b-a55b-fp8</code></li><li><code>rhoai-architect-glm-5-2-fp8</code></li></ul> | High after benchmark |
| Project manager | Codex PM or smaller coordination model | `rhoai-project-manager-qwen3-6-35b-a3b-nvfp4` | <ul><li><code>rhoai-project-manager-qwen3-6-35b-a3b-nvfp4</code></li><li><code>rhoai-architect-glm-5-2-fp8</code> for summarization-heavy workloads</li></ul> | High |
| Workerbee | Codex 5.3 Spark | `rhoai-worker-qwen2-5-coder-32b-fp8` | <ul><li><code>rhoai-worker-qwen2-5-coder-32b-fp8</code></li><li><code>rhoai-architect-glm-5-2-fp8</code> for large reasoning packets</li></ul> | High |
| Review worker | Codex 5.3 Spark review-only subagent | `rhoai-reviewer-nemotron-3-nano-30b-fp8` | <ul><li><code>rhoai-reviewer-llama-4-maverick-17b-128e-fp8</code></li><li><code>rhoai-architect-nemotron-3-ultra-550b-a55b-fp8</code></li></ul> | Medium to high |
| Local secure reviewer | Local secure reviewer or Codex evaluator | `rhoai-secure-review-qwen3-6-35b-a3b-nvfp4` | <ul><li><code>rhoai-architect-nemotron-3-ultra-550b-a55b-fp8</code> for high-stakes local review</li></ul> | High after benchmark |
| Synthesis input | CWO-native synthesis plus architect adjudication | `rhoai-synthesis-qwen3-5-122b-a10b-nvfp4` | <ul><li><code>rhoai-architect-nemotron-3-ultra-550b-a55b-fp8</code></li><li><code>rhoai-architect-glm-5-2-fp8</code></li></ul> | High after benchmark |

The OpenCode path can therefore run without public frontier providers when the
selected execution environment binds architect, PM, worker, review,
local-secure-review, and synthesis roles to RHOAI vLLM profiles. CWO still owns
Beads memory, dispatch rendering, validation, return evaluation, synthesis
provenance, and architect adjudication.

### Connected GLM-Primary Bridge

The default connected Codex environment binds `frontier_architect` to
`codex-5.6-sol`. Keep `frontier_architect` as the stable role key in plans,
Beads metadata, and policy references.

`connected-codex-glm-primary` is the first-pass bridge for testing an
airgap-ready hierarchy without leaving the Codex shell. The main Codex thread is
the project manager and operator surface. GLM-5.2 BF16 Thinking is bound as the
primary architect through `rhoai_glm_primary_architect`.
Codex 5.6 Sol is represented by
`codex_architecture_critic` as the internal counter-review lane.

Select it explicitly:

```bash
python3 scripts/route_work.py \
  --execution-environment connected-codex-glm-primary \
  --model-synthesis \
  --requested-role architecture \
  "<task text>"
```

The environment selection is the local architect opt-in. It does not give GLM
shell, web, or repo-write authority. The Codex PM applies changes only after
GLM architect output, evaluator/synthesis evidence, and required adjudication
are recorded. Synthesis ownership moves from `frontier_architect` to the GLM
primary architect for this environment only; the default `connected-codex`
profile remains unchanged.

### Native-only Spark route

Spark dispatch is native-only. Use native subagents for Spark work and assert model
attestation from trusted control-plane/session metadata, never from model self-report.
Hard-stop if actual model attestation is missing or not `gpt-5.3-codex-spark`;
do not substitute Sol or another model.

### Enterprise Evaluation Targets

For medium enterprise and larger disconnected work, the registry includes two
large-cluster profiles that are deliberately marked as candidates:

- `rhoai-architect-nemotron-3-ultra-550b-a55b-fp8` uses
  `RedHatAI/NVIDIA-Nemotron-3-Ultra-550B-A55B-FP8-dynamic` for deep
  architecture, security/malpractice review, and synthesis.
- `rhoai-architect-glm-5-2-fp8` uses `zai-org/GLM-5.2-FP8` for long-context
  architecture, large work-graph briefings, PM summarization, and synthesis.
- `rhoai-architect-glm-5-2-bf16-thinking` uses the GLM-5.2 BF16 endpoint for
  thinking-enabled primary architecture tests and synthesis input.
- `rhoai-reviewer-llama-4-maverick-17b-128e-fp8` uses
  `meta-llama/Llama-4-Maverick-17B-128E-Instruct-FP8` for multimodal or
  general review work. It is not the primary x-high architecture substitute.

These candidates are deployment-neutral. Record the actual accelerator, fabric,
topology, vLLM flags, context window, smoke-test results, and representative CWO
packet results for the cluster being promoted. Do not turn one lab topology into
a public category name.

Before promoting either enterprise evaluation target, record evidence for:

- `nvidia-smi topo -m`
- `nvidia-smi topo -p2p w`
- CUDA `p2pBandwidthLatencyTest`
- NCCL `all_reduce_perf` for the intended 8-GPU or 16-GPU shape
- vLLM startup with exact model, context, parser, and tool-call flags
- `/v1/models` and `/v1/chat/completions` smoke tests
- representative CWO architect and synthesis packets
- evaluator scoring and architect adjudication

Use enterprise candidate environments only after that benchmark gate is
satisfied. Until then, keep `airgapped-rhoai` as the reasonable practical
default.

### Profile Resolution

`scripts/render_harness_dispatch.py` resolves the role binding first:

1. The execution environment chooses the bound harness and agent for the role.
2. A bound `model_profile` supplies the model alias and default variant.
3. The access profile records the access class and configured env var names.
4. `--model-profile` can choose another approved profile explicitly.
5. `--model` is an operator override and disables model-profile details for
   that dispatch, while the role's access profile still records the access path.
6. `--model` and `--model-profile` are mutually exclusive.

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
| OpenHands | CLI, headless, and containerized agent with LiteLLM and JSONL. | Later controlled-runtime candidate due runtime weight and approval risk. |
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
- `policy/access-profiles.yaml` records Codex, external, browser, local,
  RHOAI, GLM, and human access classes without credential values.
- `schemas/execution-environment.schema.json` and
  `schemas/harness-dispatch-envelope.schema.json` match runtime fields.
- `schemas/model-profile.schema.json` matches runtime model-profile fields.
- `schemas/access-profile.schema.json` matches runtime access-profile fields.
- `scripts/render_harness_dispatch.py` renders versioned OpenCode artifacts
  with lifecycle state, capability requirements, model profile metadata, and no
  execution by default.
- Tests cover profile references, OpenCode exemplar assumptions, secret-free
  dispatch artifacts, and repository validation.
- Public docs explain Codex as a default environment, OpenCode as the v2
  exemplar, and OpenShift AI vLLM as the local serving exemplar without
  implying any external sharing in airgapped mode.
