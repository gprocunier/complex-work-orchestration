# Upgrading from 0.2.0-dev

Keep the old checkout and saved work packets while you set up the current skill.
The [installation guide](../docs/install.html#install) shows how to preview the
destination and verify the replacement.

## Which way to work

| Mode | When to use it |
| --- | --- |
| **Architect profile (`cwo-codex`)** | Coordinate delegated work across sessions. Workers make the code edits through CWO's tools, and a separate reviewer accepts the delivery. |
| **Plain Codex with the CWO skill** | Make a quick, hands-on repair in one sitting. The [practice walkthrough](../README.md#example-one-project-across-two-fresh-sessions) uses plain sessions for in-thread edits. |

The [installer](../docs/install.html#install) can set up and check the dedicated
worker login. Actual delegation uses the protected, signed single-worker
workflow. End-to-end dispatch from an ordinary architect session awaits the
protected standing-approval entry.

Set the architect launcher's model, reasoning effort and service tier under the
Sol role (`sol`) in [`policy/model-roles.yaml`](../policy/model-roles.yaml). Use the
same settings in plain Codex for a like-for-like comparison. Cyber fallback is opt-in.
Candidate E is retired.

Install the optional [architect profile](cwo-system-prompt.md) to use CWO's
replacement base instructions. Start a fresh session with `cwo-codex -C "$PWD"`.

## Dispatch and closure

| Review or work route | What is available now |
| --- | --- |
| Outside reviewers | With explicit opt-in, build and validate a contractor packet, export its manual prompt, then submit it yourself within the approved sharing boundary. Bring the return back for evaluation and adjudication. See [outside review](external-contracting.md). |
| Local vLLM reviewers | Prepare a local dispatch envelope or export a prompt. Live HTTP submission with `--execute-local` is held. See [local model preparation](local-inference.md#dispatch). |
| ChatGPT in Chrome | Use `@Chrome` from a Codex thread in the ChatGPT desktop app for [ChatGPT Pro reviews](chatgpt-pro-browser.md). You can [verify saved CDP return artifacts](private-browser-artifacts.md). |
| Codex work | Work in the lead session or use the [registered single-worker route](native-live-route-holds.md#registered-single-worker-production) with its original signed workflow, consent for the exact provider disclosure and a dedicated worker login. Raw native launch and concurrent v2 pools remain held. Direct v1 pool dispatch and the legacy campaign launcher are retired. |

Direct local model dispatch is planned for a future 1.x release.

The lead records delivery as `pending-acceptance` with the baseline and
candidate files. A reviewer working by hand runs `cwo.py accept-delivery` from
a separate foreground terminal with those files, the reviewed candidate
digest and a note. CWO checks the current requirement baseline and requires
closed blockers and children, then records acceptance and confirmed closure
in the host audit. The verified closure library serves embedding hosts with
original observations and single-use host acceptance from a separated
adjudicator. See [closing Beads](run-readiness.md#closing-beads).

## Re-create a custom reviewer profile

Keep custom entries in the source checkout you use to install CWO. Add the
example member below to `profiles` in `policy/model-profiles.yaml`, keeping
the existing entries and role matrix. It uses the same checkpoint as the
shipped Nemotron review profile with a team-specific served model alias. Set
the alias to the name your endpoint serves. The model profile selects the
model. Access and endpoint settings come from their existing registries.
[Model profile schema](../schemas/model-profiles.schema.json) · [Profile reference](local-inference.md#profiles)

```json
{
  "team-docs-review": {
    "display_name": "Team documentation review",
    "provider_key": "openshift_ai_vllm",
    "local_profile": "openshift-ai-vllm",
    "huggingface_model_id": "RedHatAI/NVIDIA-Nemotron-3-Nano-30B-A3B-FP8",
    "model_alias": "rhoai/team-docs-review",
    "publisher": "RedHatAI",
    "source_url": "https://huggingface.co/RedHatAI/NVIDIA-Nemotron-3-Nano-30B-A3B-FP8",
    "license": "nvidia-open-model-license",
    "artifact": "FP8 checkpoint",
    "quantization": "FP8",
    "vllm_compatible": true,
    "endpoint_path": "/v1/chat/completions",
    "recommended_roles": ["review_worker"],
    "substitute_confidence": "medium",
    "deployment_class": "RHOAI/vLLM endpoint",
    "deployment_tier": "team review candidate",
    "hardware_profile": "Verify GPU memory on the intended endpoint",
    "recommended_enterprise_scale": "Team documentation review",
    "benchmark_gate": ["Documentation review packet", "Evaluator acceptance"],
    "promotion_status": "candidate",
    "context_window": "Verify the deployed endpoint limit",
    "strengths": ["Focused documentation critique"],
    "limits": ["Review evidence only"]
  }
}
```

Inspect the resulting envelope from your source checkout. Rendering prepares
the request without running the harness or calling the model.

```bash
python3 scripts/render_harness_dispatch.py --environment airgapped-rhoai \
  --role review_worker --model-profile team-docs-review --json \
  "Review the changed README examples."
```

## Find the old audit and packets

The current log starts at `../.cwo-host-state/<package>/audit.jsonl` relative to
the package root. For a default install, that is
`$CODEX_HOME/skills/.cwo-host-state/complex-work-orchestration/audit.jsonl`,
with `CODEX_HOME` defaulting to `$HOME/.codex`. The first current-format write
starts a fresh chain when no chain exists. Keep the old
`.orchestration-audit/audit.jsonl` for reference. Old receipts and quota history
are excluded from the current chain. An existing current-format chain stays in
place. See [host audit history](host-audit-history.md).

On replacement, the installer moves the whole previous skill directory to
`skill-backups/complex-work-orchestration.prev.YYYYMMDD-HHMMSS.PID`
under the parent of the skills directory. With default paths this is
`$CODEX_HOME/skill-backups/`. The installer prints the exact backup path.
Look there for old logs or packets saved inside the previous skill. In a
separate checkout or project, check the original output path or its
`work-packets/` folder.
[Installer](../scripts/install.sh)

Read saved Markdown packets in a text viewer. Set `old_log` and `old_packet`
to the saved JSON Lines audit and JSON packet paths.

```bash
python3 -m json.tool --json-lines "$old_log"
python3 -m json.tool "$old_packet"
```
