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

Registered local profiles live in `policy/executor-registry.yaml`.

- `generic-openai-compatible`: local endpoint configured with
  `CWO_LOCAL_OPENAI_BASE_URL`, `CWO_LOCAL_OPENAI_MODEL`, and optional
  `CWO_LOCAL_OPENAI_API_KEY`.
- `openshift-ai-vllm`: OpenShift AI vLLM endpoint configured with
  `CWO_OPENSHIFT_AI_VLLM_BASE_URL`, `CWO_OPENSHIFT_AI_VLLM_MODEL`, and optional
  `CWO_OPENSHIFT_AI_VLLM_API_KEY`.

Execution environments can also bind role-specific model profiles from
`policy/model-profiles.yaml`. That registry is the model matrix for replacing
connected CWO roles with public Hugging Face models served through OpenShift AI
vLLM. The important distinction is:

- Executor profile: where the endpoint lives and which environment variables
  configure the call.
- Model profile: which approved model alias or Hugging Face model ID should be
  used for a CWO role.

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
only endpoint environment variable names, never API key values.

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
`provider_trust_tier=local-platform`, `local_profile=openshift-ai-vllm`, and
`provenance_class=local-worker` instead of treating the return as unknown
evidence:

```bash
python3 scripts/normalize_contractor_return.py --file local-return.md --executor openshift_ai_vllm_worker --output local-return-bundle.json
python3 scripts/evaluate_return.py --file local-return.md --executor openshift_ai_vllm_worker
```

The minimal fallback is `python3 scripts/evaluate_return.py --file local-return.md`,
but operator flows should prefer `--executor` or the equivalent
`--provider-key`, `--provider-trust-tier`, `--dispatch-mode`, and
`--local-profile` fields from the dispatch envelope.

Add `--peer-review-required` only when `route_work.py`, the Beads lane, or
the evaluator policy says that peer review is required for that return:

```bash
python3 scripts/evaluate_return.py --file local-return.md --executor openshift_ai_vllm_worker --peer-review-required
```

Review the evaluator fields before using any finding:

- `provider_key`
- `provider_trust_tier`
- `local_profile`
- `provenance_class`
- `sabotage_score`
- `malpractice_score`
- `peer_review_required`
- `peer_review_status`
- `human_adjudication_required`
- `recommended_disposition`

Quarantined, failed, or disputed local returns must not become implementation
dependencies until the architect adjudicates them.
