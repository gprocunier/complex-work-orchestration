# Local Inference Operator Guide

This reference covers local OpenAI-compatible workers for
`complex-work-orchestration`, including OpenShift AI vLLM endpoints.

Local inference is not third-party contracting, but it is still contract-style
work. A local worker receives a bounded prompt envelope, returns evidence, and
cannot authorize implementation. Evaluator scoring and architect adjudication
remain required.

## Profiles

Registered local profiles live in `policy/executor-registry.yaml`.

- `generic-openai-compatible`: local endpoint configured with
  `CWO_LOCAL_OPENAI_BASE_URL`, `CWO_LOCAL_OPENAI_MODEL`, and optional
  `CWO_LOCAL_OPENAI_API_KEY`.
- `openshift-ai-vllm`: OpenShift AI vLLM endpoint configured with
  `CWO_OPENSHIFT_AI_VLLM_BASE_URL`, `CWO_OPENSHIFT_AI_VLLM_MODEL`, and optional
  `CWO_OPENSHIFT_AI_VLLM_API_KEY`.

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

## Guardrails

Local worker and secure-review executors must set `codex_pickup=forbidden`.
They must not support web access, shell execution, or repo write. Secure
reviewers may read approved local repo context; normal local workers may not.

Local outputs must go through:

```bash
python3 scripts/normalize_contractor_return.py --file local-return.md --output local-return-bundle.json
python3 scripts/evaluate_return.py --file local-return.md --peer-review-required
```

Review the evaluator fields before using any finding:

- `sabotage_score`
- `malpractice_score`
- `peer_review_required`
- `peer_review_status`
- `human_adjudication_required`
- `recommended_disposition`

Quarantined, failed, or disputed local returns must not become implementation
dependencies until the architect adjudicates them.
