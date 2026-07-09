# Local Inference Operator Guide

This reference covers local OpenAI-compatible workers for
`complex-work-orchestration`, including OpenShift AI vLLM endpoints.

Local inference is not third-party contracting, but it is still contract-style
work. A local worker receives a bounded prompt envelope, returns evidence, and
cannot authorize implementation. Evaluator scoring and architect adjudication
remain required.

## In-Codex Invocation

The first-class path is a Codex prompt. Ask the prompt coach to size the work
and let it surface the local-worker opt-in question before any local dispatch
exists:

```text
/plan Use $complex-work-orchestration prompt coach:
OpenShift AI vLLM local review of README command examples.
```

After explicit opt-in, Codex may run the helper equivalent behind the scenes.
Use direct script execution only for advanced automation or troubleshooting:

```bash
python3 scripts/coach_prompt.py \
  --local-ok \
  --prefer-local \
  --local-profile openshift-ai-vllm \
  --requested-role documentation \
  "OpenShift AI vLLM local review of README command examples."
```

## Profiles

Registered local endpoint profiles still live in `policy/executor-registry.yaml`
for backward compatibility. Access-profile metadata lives in
`policy/access-profiles.yaml` and is emitted in route, local-dispatch, and
harness-dispatch artifacts.

- `generic-openai-compatible`: local endpoint configured with
  `CWO_LOCAL_OPENAI_BASE_URL`, `CWO_LOCAL_OPENAI_MODEL`, and optional
  `CWO_LOCAL_OPENAI_API_KEY`.
- `openshift-ai-vllm`: OpenShift AI vLLM endpoint configured with
  `CWO_OPENSHIFT_AI_VLLM_BASE_URL`, `CWO_OPENSHIFT_AI_VLLM_MODEL`, and optional
  `CWO_OPENSHIFT_AI_VLLM_API_KEY`.

GLM-5.2 BF16 thinking review is a named OpenShift AI vLLM lane, not a
separate endpoint class. The executor
`rhoai_glm_architecture_critic` uses the same local
profile but reads the GLM route and model from
`CWO_OPENSHIFT_AI_GLM_5_2_BF16_BASE_URL` and
`CWO_OPENSHIFT_AI_GLM_5_2_BF16_MODEL`, defaulting the model name to
`glm-5.2-bf16-128k`. Its model profile is
`rhoai-architect-glm-5-2-bf16-thinking`.

The same endpoint can be selected as an experimental primary architect through
`rhoai_glm_primary_architect` by choosing the
`connected-codex-glm-primary` execution environment. That path keeps the Codex
shell as project manager, moves Codex 5.5 x-high to an internal counter-review
lane, and still treats GLM as local read-only evidence until evaluator,
synthesis, and adjudication gates accept the work.

Execution environments can also bind role-specific model profiles from
`policy/model-profiles.yaml`. That registry is the model matrix for replacing
connected CWO roles with public Hugging Face models served through OpenShift AI
vLLM. The important distinction is:

- Executor profile: where the endpoint lives and which environment variables
  configure the call.
- Access profile: the access class for that executor, including allowed
  harnesses, outside-sharing posture, repo/tool authority, and the env var names
  CWO may mention.
- Model profile: which approved model alias or Hugging Face model ID should be
  used for a CWO role.

The access registry does not rename current operator env vars. It records names
such as `CWO_OPENSHIFT_AI_VLLM_BASE_URL`,
`CWO_OPENSHIFT_AI_VLLM_API_KEY`,
`CWO_OPENSHIFT_AI_GLM_5_2_BF16_BASE_URL`, and
`CWO_CHATGPT_BROWSER_CONFIG` so packets and status reports can show the access
path without printing values.

For example, `airgapped-rhoai` binds its worker role to
`rhoai-worker-qwen2-5-coder-32b-fp8`. Rendering a harness envelope resolves that
profile to the operator-owned model alias `rhoai/workerbee` and includes the
sanitized backing model metadata:

```bash
python3 scripts/render_harness_dispatch.py \
  --environment airgapped-rhoai \
  --role worker \
  --json \
  "Review command examples."
```

Use `--model-profile` only when the operator wants to pick a different approved
profile explicitly. Use `--model` only for an override that should disable
profile resolution for that dispatch.

### Enterprise Evaluation Targets

For disconnected medium enterprise work, keep `airgapped-rhoai` as the
reasonable practical default until the local serving stack proves a larger lane.
Enterprise-scale OpenShift AI clusters can benchmark two explicit candidates:

- the Nemotron enterprise candidate binds deep architecture, secure review, and
  synthesis lanes to `rhoai-architect-nemotron-3-ultra-550b-a55b-fp8`.
- the GLM enterprise candidate binds long-context architecture, PM
  summarization, and synthesis lanes to `rhoai-architect-glm-5-2-fp8`.
- the GLM BF16 thinking candidate binds architecture second-opinion and
  synthesis lanes to `rhoai-architect-glm-5-2-bf16-thinking`.

Both candidates require a benchmark gate before promotion: GPU topology, P2P,
NCCL collectives, exact vLLM startup flags, `/v1/models`,
`/v1/chat/completions`, representative CWO packets, evaluator scoring, and
architect adjudication. The benchmark gate is deliberately deployment-neutral:
record the actual accelerator, fabric, topology, vLLM flags, context window,
and smoke-test results for the cluster being promoted.
`rhoai-reviewer-llama-4-maverick-17b-128e-fp8`
is a multimodal/general review candidate when the harness and endpoint can
safely carry images or mixed-modal evidence; it is not the primary x-high
architect substitute.

Use the profile on route and dispatch commands:

```bash
python3 scripts/route_work.py \
  --local-ok \
  --prefer-local \
  --local-profile openshift-ai-vllm \
  --requested-role documentation \
  "Documentation review for the public README examples."
```

Use the experimental GLM-primary bridge when testing architecture substitution:

```bash
python3 scripts/route_work.py \
  --execution-environment connected-codex-glm-primary \
  --model-synthesis \
  --requested-role architecture \
  "Review the architect plan with GLM-5.2 as primary architect."
```

## Dispatch

`scripts/dispatch_work.py` prepares a `local_envelope` by default. It does not
call the endpoint unless `--execute-local` is set.

```bash
export CWO_OPENSHIFT_AI_VLLM_BASE_URL="https://vllm.example.internal"
export CWO_OPENSHIFT_AI_VLLM_MODEL="vllm-local"

python3 scripts/dispatch_work.py \
  --local-ok \
  --prefer-local \
  --local-profile openshift-ai-vllm \
  --dispatch-id dispatch-example \
  --bead example \
  --json \
  "Summarize docs-review risks."
```

To execute:

```bash
python3 scripts/dispatch_work.py \
  --local-ok \
  --prefer-local \
  --local-profile openshift-ai-vllm \
  --execute-local \
  "Summarize docs-review risks."
```

The envelope follows `schemas/local-dispatch-envelope.schema.json` and includes
the selected `access_profile`, sanitized `access_profile_details`, readiness
booleans for required and optional env var names, and only endpoint environment
variable names. It never includes API key values or endpoint URLs.

To inspect access readiness without dispatching:

```bash
python3 scripts/render_access_profile_status.py --profile rhoai-vllm
python3 scripts/render_access_profile_status.py --profile rhoai-vllm --require-configured
```

For GLM-5.2 BF16 thinking:

```bash
export CWO_OPENSHIFT_AI_GLM_5_2_BF16_BASE_URL="https://glm-route.example.internal"
export CWO_OPENSHIFT_AI_GLM_5_2_BF16_MODEL="glm-5.2-bf16-128k"

python3 scripts/dispatch_work.py \
  --local-ok \
  --local-profile openshift-ai-vllm \
  --requested-role architecture \
  --execute-local \
  "Use GLM-5.2 BF16 thinking as an independent architecture critic second opinion."
```

### GLM-5.2 BF16 thinking modes

Use request-side controls from the selected GLM executor:

- Concise verdict mode: keep `--local-thinking off` with `--local-max-tokens 512` to
  `1024`.
- Deep evidence mode: keep `--local-thinking on` with `--local-max-tokens 2048` to
  `4096` and `--local-timeout 600`.
- Full-patch review should be split into chunked passes (or review + finalizer) in the
  next sprint rather than a single unconstrained pass.

The executor defaults remain bounded request-side at `chat_template_kwargs.enable_thinking=true`
and `max_tokens=4096` so local endpoint defaults do not control safety-critical
token cap behavior.

For a render-only harness envelope under the GLM-primary bridge:

```bash
python3 scripts/render_harness_dispatch.py \
  --environment connected-codex-glm-primary \
  --role architect \
  --json \
  "Review the architecture plan as the GLM-5.2 primary architect."
```

The GLM executor sends `chat_template_kwargs.enable_thinking=true`. If the
endpoint returns thinking text in the message content, CWO strips that reasoning
from the usable response, records only hashes and character counts, and keeps
the final answer as evaluator input. Raw thinking must not be copied into
Beads, audit events, public docs, or synthesis artifacts.

## Endpoint Safety

`--execute-local` validates the endpoint immediately before dispatch. It accepts
only `http` or `https` base URLs with no embedded username or password. The host
must be a literal loopback/private address or resolve only to loopback, RFC1918
private, or RFC4193 local IPv6 addresses. DNS failures, public addresses, and
mixed private/public address sets fail before any POST is attempted.

Plain HTTP is allowed only for loopback endpoints. Private network endpoints
should use HTTPS. The dispatcher disables environment proxy use and rejects
redirects so a validated local endpoint cannot silently shift the request to a
different target.

OpenShift Route hostnames are allowed only when the selected executor profile or
`--local-allow-private-dns` opts in and every resolved address is loopback,
RFC1918 private, or RFC4193 local IPv6. For TLS, prefer normal trust-store
verification or set `CWO_OPENSHIFT_AI_VLLM_CA_BUNDLE` to a route CA bundle.
The GLM BF16 executor also supports the lab-only
`CWO_OPENSHIFT_AI_GLM_5_2_BF16_TLS_VERIFY=false` or `--local-insecure-tls`
escape hatch; audit metadata records that insecure verification was selected,
and other local executor profiles remain fail-closed unless they explicitly
allow it.

API-key values are never placed in the envelope. The API-key environment
variable name must be one of the local allowlist entries:

- `CWO_OPENSHIFT_AI_VLLM_API_KEY`
- `CWO_LOCAL_OPENAI_API_KEY`
- `LOCAL_OPENAI_API_KEY`
- `LOCAL_VLLM_API_KEY`
- `VLLM_API_KEY`

## Guardrails

Local worker and secure-review executors must set `codex_pickup=forbidden`.
They must not support web access, shell execution, or repo write. Secure
reviewers may read approved local repo context; normal local workers may not.

Local outputs must go through normalization and evaluation with the executor
identity preserved. For OpenShift AI vLLM, pass the executor key so the return
bundle and acceptance decision record `provider_key=openshift_ai_vllm`,
`provider_trust_tier=local-platform`, `local_profile=openshift-ai-vllm`,
`model_profile=<profile-key>`, and `provenance_class=local-worker` instead of
treating the return as unknown evidence:

```bash
python3 scripts/normalize_contractor_return.py --file local-return.md --executor openshift_ai_vllm_worker --output local-return-bundle.json
python3 scripts/evaluate_return.py --file local-return.md --executor openshift_ai_vllm_worker
```

The minimal fallback is `python3 scripts/evaluate_return.py --file local-return.md`,
but operator flows should prefer `--executor` or the equivalent
`--provider-key`, `--provider-trust-tier`, `--dispatch-mode`, and
`--local-profile` and `--model-profile` fields from the dispatch envelope.

Add `--peer-review-required` only when `route_work.py`, the Beads lane, or
the evaluator policy says that peer review is required for that return:

```bash
python3 scripts/evaluate_return.py --file local-return.md --executor openshift_ai_vllm_worker --peer-review-required
```

Review the evaluator fields before using any finding:

- `provider_key`
- `provider_trust_tier`
- `local_profile`
- `model_profile`
- `provenance_class`
- `sabotage_score`
- `malpractice_score`
- `peer_review_required`
- `peer_review_status`
- `human_adjudication_required`
- `recommended_disposition`

Quarantined, failed, or disputed local returns must not become implementation
dependencies until the architect adjudicates them.
