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

The hardened 256K review lane is separate from that older profile. The executor
`rhoai_glm_hardened_architecture_critic` selects local profile
`openshift-ai-glm-256k`, access profile `rhoai-glm-bf16-256k`, and model
profile `rhoai-architect-glm-5-2-bf16-256k-thinking`. It reads its route from
`CWO_OPENSHIFT_AI_GLM_5_2_BF16_256K_BASE_URL`, requires the exact model
`glm-5.2-bf16-256k`, and preflights `/v1/models` immediately before posting to
`/v1/chat/completions`.

GLM-5.3 direct review uses the dedicated executor
`rhoai_glm_compact_architecture_critic`, local profile
`openshift-ai-glm-5-3-direct`, and access profile `rhoai-glm-5-3-direct`. It
reads `CWO_OPENSHIFT_AI_GLM_5_3_BASE_URL`, accepts either an origin URL or one
already ending in `/v1`, requires the exact advertised model
`glm-5.3-bf16`, and sends no API-key header. It is a compact second-opinion
critic, not a primary architect or implementation worker.

The same endpoint can be selected as an experimental primary architect through
`rhoai_glm_primary_architect` by choosing the
`connected-codex-glm-primary` execution environment. That path keeps the Codex
shell as project manager, moves Codex 5.6 Sol to an internal counter-review
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
`CWO_OPENSHIFT_AI_GLM_5_2_BF16_BASE_URL`,
`CWO_OPENSHIFT_AI_GLM_5_2_BF16_256K_BASE_URL`, and
`CWO_CHATGPT_BROWSER_CONFIG` so packets and status reports can show the access
path without printing values.

## Endpoint Configuration

Keep endpoint values in an operator-owned shell file outside the repository.
The access profile registry is policy only; it should contain environment
variable names, not URLs, API keys, tokens, or route-specific secrets.

```bash
mkdir -p ~/.config/cwo
chmod 700 ~/.config/cwo
$EDITOR ~/.config/cwo/vllm-endpoints.env
chmod 600 ~/.config/cwo/vllm-endpoints.env
```

Use stable model aliases where possible so CWO routing does not change when the
serving backend changes:

```bash
export CWO_OPENSHIFT_AI_VLLM_BASE_URL="https://vllm.example.internal"
export CWO_OPENSHIFT_AI_VLLM_MODEL="rhoai/workerbee"
export CWO_OPENSHIFT_AI_VLLM_API_KEY="..."

export CWO_OPENSHIFT_AI_GLM_5_2_BF16_BASE_URL="https://glm-route.example.internal"
export CWO_OPENSHIFT_AI_GLM_5_2_BF16_MODEL="glm-5.2-bf16-128k"

export CWO_OPENSHIFT_AI_GLM_5_2_BF16_256K_BASE_URL="https://glm-256k-route.example.internal"
export CWO_OPENSHIFT_AI_GLM_5_2_BF16_256K_MODEL="glm-5.2-bf16-256k"

export CWO_OPENSHIFT_AI_GLM_5_3_BASE_URL="https://glm-route.example.internal/v1"
export CWO_OPENSHIFT_AI_GLM_5_3_MODEL="glm-5.3-bf16"

# Optional for private route trust.
export CWO_OPENSHIFT_AI_VLLM_CA_BUNDLE="$HOME/.config/cwo/rhoai-ca.pem"

# Lab-only escape hatch when the endpoint route cannot be validated normally.
# export CWO_OPENSHIFT_AI_GLM_5_2_BF16_TLS_VERIFY=false
# export CWO_OPENSHIFT_AI_GLM_5_2_BF16_256K_TLS_VERIFY=false
# export CWO_OPENSHIFT_AI_GLM_5_3_TLS_VERIFY=false
```

Source the file before starting Codex or running CWO helpers:

```bash
source ~/.config/cwo/vllm-endpoints.env
```

Smoke-test the configuration in layers:

```bash
python3 scripts/render_access_profile_status.py --profile rhoai-vllm --require-configured
python3 scripts/render_access_profile_status.py --profile rhoai-glm-bf16 --require-configured
python3 scripts/render_access_profile_status.py --profile rhoai-glm-bf16-256k --require-configured
python3 scripts/render_access_profile_status.py --profile rhoai-glm-5-3-direct --require-configured

curl -sS "$CWO_OPENSHIFT_AI_VLLM_BASE_URL/v1/models" \
  -H "Authorization: Bearer $CWO_OPENSHIFT_AI_VLLM_API_KEY"

python3 scripts/dispatch_work.py \
  --local-ok \
  --prefer-local \
  --local-profile openshift-ai-vllm \
  --execute-local \
  "Return one sentence confirming the local endpoint is reachable."
```

The older `rhoai-glm-bf16` profile and the independently configured
`rhoai-glm-bf16-256k` profile remain `offline` by default. The 256K profile
still requires its dedicated base-URL environment variable. An operator must
verify the intended route and deliberately change its policy status before
normal execution. Any profile marked `offline` fails closed unless the
operator supplies the explicit offline waiver and reason.

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
python3 scripts/render_access_profile_status.py --profile rhoai-glm-bf16-256k --require-configured
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

After an operator verifies the route and marks the access profile available,
the hardened GLM-5.2 BF16 256K lane can be dispatched with:

```bash
python3 scripts/dispatch_work.py \
  --local-ok \
  --local-profile openshift-ai-glm-256k \
  --requested-role architecture \
  --execute-local \
  "Use exact GLM-5.2 BF16 256K thinking as an independent architecture critic second opinion."
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

### GLM-5.3 compact second-opinion mode

The GLM-5.3 lane addresses a failure mode observed with a monolithic review:
the model spent 10,000 to 12,000 output tokens drafting, the server did not make
the requested response schema visible to the model, and a larger repeat ended
in an HTTP 504. The repaired lane therefore puts a small JSON contract directly
in the system message, requests GLM-5.3's supported
`reasoning_effort=low`, caps the final return at three findings, and
deterministically renders a successful object into
the standard evaluator sections. The prospective `cwo-glm-critic-v2` contract
uses one 6,000-character final-object ceiling rather than prescribing how the
model must distribute that space across evidence fields. Historical v1 evidence
retains its original per-field limits and is never reinterpreted under v2.

V2 tells the normal-chat model to emit exactly eight top-level keys:
`verdict`, `summary`, `findings`, `alternatives`, `risks`, `confidence`,
`recommended_next_action`, and `escalation_needed`. `verdict` is `approve`,
`revise`, or `reject`; `confidence` is `high`, `medium`, or `low`. Each of one
to three findings has exactly four string keys: `severity`, `claim`,
`evidence`, and `repair`; severity is `critical`, `high`, `medium`, or `low`.
Evidence must include `Fact:` or `Inference:` as appropriate--there is no
separate inference field. Alternatives and risks are arrays of zero to two
non-empty strings.

Client validation still rejects every shape violation. Invalid v2 results may
carry only bounded generated diagnostics: JSON/container type, missing known
fields, unexpected-field count plus a digest, invalid enum or text type, and
list bounds. Unknown field names, values, excerpts, and reasoning are never
reported. Rejected final content is quarantined before both full and compact
projection, so diagnostics are operational evidence rather than a recoverable
review. Deterministic mocked tests check this client contract; they do not
establish GLM reliability on a live workload.
Current-host diagnostics show that the route advertises but
does not enforce native structured-output constraints; a later reasoning-aligned
constrained request returned HTTP 500. The dispatcher therefore does not submit
`structured_outputs` on this host. Re-enable it only after an isolated server
diagnostic proves enforcement. Independent validation
uses the semantic JSON contract and total-length ceiling rather than rejecting a
safe answer only because it contains harmless JSON whitespace or escapes.

Server logs later classified the single HTTP 500 as an xgrammar finite-state
machine rejection while advancing the grammar during generation. It was not a
GLM outage, compiler failure, parser assertion, OOM, engine death, Ray loss, or
pod restart. Consequently this profile fails closed if `response_format`,
`structured_outputs`, `guided_json`, `guided_regex`, `guided_grammar`, or any
equivalent grammar-constrained request option is configured. Normal chat output
is validated and quarantined client-side instead.

```bash
set -euo pipefail
dispatch_json=$(mktemp "${TMPDIR:-/tmp}/cwo-glm53-dispatch.XXXXXXXX.json")
return_file=$(mktemp "${TMPDIR:-/tmp}/cwo-glm53-return.XXXXXXXX.md")
trap 'rm -f "$dispatch_json" "$return_file" "$return_file.pending"' EXIT

python3 scripts/dispatch_work.py \
  --file critic-brief.md \
  --local-ok \
  --local-profile openshift-ai-glm-5-3-direct \
  --requested-role architecture \
  --execute-local \
  --local-result-view compact \
  --json > "$dispatch_json"

python3 - "$dispatch_json" "$return_file" <<'PY'
import json
import os
import sys
from pathlib import Path

artifact = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
response = artifact.get("local_response")
value = response.get("normalized_return") if isinstance(response, dict) else None
if not isinstance(value, str) or not value:
    raise SystemExit("GLM-5.3 did not produce an evaluator-ready return")
target = Path(sys.argv[2])
pending = target.with_name(target.name + ".pending")
pending.write_text(value, encoding="utf-8")
os.replace(pending, target)
PY

python3 scripts/evaluate_return.py \
  --file "$return_file" \
  --local-dispatch-result "$dispatch_json" \
  --peer-review-required \
  --json
```

Run the block as one shell transaction. A failed dispatch or extraction stops
before evaluation; the per-run temporary files are removed on exit. The
evaluator also requires an exact match to the dispatch's normalized-return
digest for v2, so a stale or substituted return cannot gain synthesis weight.

Prefer a configured `CWO_OPENSHIFT_AI_VLLM_CA_BUNDLE`. If the current lab route
still presents an untrusted chain, `--local-insecure-tls` is available only with
an explicit waiver reason and is recorded in dispatch telemetry. The no-auth
profile never reads the shared API-key variable.

GLM-5.3 has no non-thinking mode. Its chat template uses `reasoning_effort` and
always opens a reasoning segment, so this profile must not send the older
`enable_thinking=false` switch. That combination can leave the model reasoning
while disabling vLLM's extraction, leaking scratchpad text into `content`.
Instead the profile sends top-level `reasoning_effort=low` and keeps reasoning
extraction enabled. Separate reasoning is hashed and removed. For the known
leading-prompt case where only a closing `</think>` appears in generated text,
the client hashes the prefix as reasoning and validates only the final suffix.

Only an exact-model, `stop`-finished, tool-free final response matching
`cwo-glm-critic-v2` is usable. The request boundary revalidates the profile,
exact normal-chat option allowlist, contract, and no-auth mode immediately before
preflight. The client rejects duplicate JSON keys, non-finite values, invalid
Unicode, dangerous controls, and excessive nesting. Any unusable model-authored
final content is removed from both full and compact results and replaced by its
hash and character count. The validator retains a 6,000-character fail-closed
whole-final-text ceiling without the brittle v1 per-field distribution caps. The 8,192-token
request budget exists to leave room for low-effort reasoning and a bounded final
object. A length stop, 504,
reasoning-only return, or invalid contract ends that dispatch; never repeat or
resume it. Any separately admitted call must use a fresh dispatch and a
materially distinct question while preserving the failed evidence.

The dispatch command emits its audited JSON artifact and then exits nonzero when
an executed local response is unusable. Automation must check both the process
status and `local_response.usable_final_content`; an evaluator verdict never
overrides the dispatcher's final eligibility decision. Current limits bound the
model-visible final text, not the complete HTTP response body, so this profile
does not claim a separately calibrated wire-byte resource ceiling.

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
The GLM BF16 executors also support the lab-only
`CWO_OPENSHIFT_AI_GLM_5_2_BF16_TLS_VERIFY=false`,
`CWO_OPENSHIFT_AI_GLM_5_3_TLS_VERIFY=false`, or `--local-insecure-tls`
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

Prefer the complete dispatch result when it is available. Version-2 local
envelopes carry `expected_return_language: en`; the evaluator rejects a
version-2 envelope that omits or changes that contract. Version-1 envelopes
remain compatible and use the current English policy default:

```bash
python3 scripts/evaluate_return.py \
  --file local-return.md \
  --local-dispatch-result local-dispatch-result.json
```

The evaluator applies NFKC sabotage matching, Unicode-control checks,
mixed-script word detection, and prose-only language likelihood checks before a
local return can influence implementation. Review and quarantine findings still
require architect adjudication; they do not authorize automatic rejection or
follow-up work by themselves.

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
