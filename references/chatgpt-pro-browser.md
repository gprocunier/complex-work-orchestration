# ChatGPT Pro Browser Master Review

This is the durable operator runbook for the CWO ChatGPT Pro 5.5 Extended
Reasoning master-review lane. Use it when a user explicitly asks for ChatGPT
Pro, GPT-5.5, Extended Reasoning, or a ChatGPT master review of the final plan
or total work packet.

The lane is browser-mediated because ChatGPT Pro account state and model
selection live in the operator's browser session. Do not use OpenAI API calls,
Deep Research, Gemini, Opus, or an internal review as a silent substitute.

## Contract

- Executor: `chatgpt_pro_5_5_extended_reasoning_browser`
- Job label: `contract-jd-master-plan-review`
- Default share boundary: `redacted-packet`
- Evidence requirement: dispatch JSON with confirmed `model_attestation`, a
  ChatGPT share URL, ingested return markdown, return evaluation, and architect
  adjudication
- Blocking behavior: if the user explicitly requested this lane before
  implementation, stop before implementation unless the Pro lane succeeds or
  the operator records a waiver/downgrade in Beads

## Safe Browser Launch

Prefer the CWO launcher instead of executing Chrome directly from Codex. The
launcher starts Chrome through `systemd-run --user`, keeps the visible browser
outside the lifetime of the shell command, uses Wayland/Ozone flags, opens a
dedicated Chrome profile, and exposes only a localhost CDP port.

```bash
scripts/launch_chatgpt_cdp_chrome.sh --write-config
```

The default profile is:

```text
$HOME/.local/share/cwo/chatgpt-master-reviewer-profile
```

The default browser config is:

```text
$HOME/.config/cwo/chatgpt-browser.json
```

The config written by `--write-config` contains no credentials or browser
session material. It uses:

```json
{
  "connect_over_cdp_url": "http://127.0.0.1:9222",
  "model_label": "ChatGPT Pro 5.5",
  "reasoning_label": "Extended Reasoning",
  "require_model_confirmation": true,
  "max_prompt_chars": 50000,
  "local_clipboard_fallback": true,
  "selectors": {
    "model_label_confirmation_selector": "[data-testid='composer-intelligence-picker-content']",
    "reasoning_label_confirmation_selector": "[data-testid='composer-intelligence-picker-content']"
  }
}
```

The file must be mode `0600` and must live outside the repository. If the
ChatGPT UI changes, update only this local config.

Useful launcher commands:

```bash
scripts/launch_chatgpt_cdp_chrome.sh --status
scripts/launch_chatgpt_cdp_chrome.sh --replace --write-config
scripts/launch_chatgpt_cdp_chrome.sh --stop
```

Set `CWO_CHATGPT_BROWSER_CONFIG` only when using a non-default config path:

```bash
export CWO_CHATGPT_BROWSER_CONFIG="$HOME/.config/cwo/chatgpt-browser.json"
```

## Packet Size Rule

Do not send raw heavy Beads graphs, full comments, full audit dumps, or large
repo listings to the browser lane. Large contenteditable prompts can freeze the
visible ChatGPT tab before submission. The browser helper now rejects prompts
larger than `max_prompt_chars` before opening or touching the browser. Keep the
default limit at `50000` unless the operator deliberately raises it for a
tested profile.

Use a compact plan bundle in `work-packets/`:

```bash
mkdir -p work-packets
cp templates/master-review-plan-packet.md work-packets/master-review-plan.md
```

The plan bundle should contain:

- objective and acceptance criteria
- compact Beads graph summary, not full raw Beads JSON
- final execution or review plan
- concrete local evidence and validation results
- outside-return summaries and evaluator dispositions
- known risks, conflicts, open questions, and requested master-review focus

If a generated prompt is too large, build a smaller `--snippet-file` packet
rather than retrying the browser.

## Dispatch Flow

Build the packet from the compact plan bundle:

```bash
python3 scripts/build_contractor_packet.py \
  --bead <id> \
  --executor chatgpt_pro_5_5_extended_reasoning_browser \
  --share-boundary redacted-packet \
  --external-ok \
  --job-description contract-jd-master-plan-review \
  --snippet-file work-packets/master-review-plan.md \
  --attest-packet \
  --format json \
  --output work-packets/master-plan-review-packet.json
```

Dry run first. This verifies the prompt/config and reports `prompt_chars`
without submitting:

```bash
python3 scripts/chatgpt_browser_review.py \
  --packet work-packets/master-plan-review-packet.json \
  --dry-run \
  --json \
  > work-packets/master-plan-review-dry-run.json
```

Confirm model and effort before spending the Pro query:

```bash
python3 scripts/chatgpt_browser_review.py \
  --packet work-packets/master-plan-review-packet.json \
  --confirm-only \
  --json \
  > work-packets/master-plan-review-confirmation.json
```

Submit once the confirmation status is `model-confirmed` and the attestation
labels show `GPT-5.5` and `Extended`:

```bash
python3 scripts/chatgpt_browser_review.py \
  --packet work-packets/master-plan-review-packet.json \
  --json \
  > work-packets/master-plan-review-dispatch.json
```

Ingest the share return using the exact dispatch identity:

```bash
SHARE_URL="$(jq -r '.share_url' work-packets/master-plan-review-dispatch.json)"
DISPATCH_ID="$(jq -r '.dispatch_id' work-packets/master-plan-review-dispatch.json)"
PACKET_SHA256="$(jq -r '.packet_sha256' work-packets/master-plan-review-dispatch.json)"

python3 scripts/ingest_chatgpt_share_return.py \
  "$SHARE_URL" \
  --bead <id> \
  --dispatch-id "$DISPATCH_ID" \
  --packet-sha256 "$PACKET_SHA256" \
  --output work-packets/master-plan-review-return.md
```

Normalize/evaluate before using the return:

```bash
python3 scripts/normalize_contractor_return.py \
  --bead <id> \
  --dispatch-id "$DISPATCH_ID" \
  --packet-sha256 "$PACKET_SHA256" \
  --file work-packets/master-plan-review-return.md \
  --output work-packets/master-plan-review-return-bundle.json

python3 scripts/evaluate_return.py \
  --bead <id> \
  --file work-packets/master-plan-review-return.md \
  --workspace-mutation-report mutation-report.json \
  > work-packets/master-plan-review-evaluation.json
```

If the evaluator marks the return `salvage-only`, `run-peer-review`,
`quarantine`, or otherwise held, use it only as allowed by the evaluator and
record architect adjudication before changing implementation direction.

## Failure Handling

Before diagnosing a frozen visible browser, check whether CWO still owns a
browser unit or CDP port:

```bash
scripts/launch_chatgpt_cdp_chrome.sh --status
ss -ltnp 'sport = :9222' || true
pgrep -a -u "$USER" -f 'chatgpt_browser_review|remote-debugging-port=9222|cwo-chatgpt' || true
```

If the page froze before prompt submission and there is no share URL and no
response text, the audit layer treats it as a pre-submission browser failure
and does not consume the external-contractor quota. Record the failure in
Beads, shrink the packet, then retry. Do not repeatedly paste large prompts
into the same visible browser session.

If the browser is wedged:

1. Stop only the dedicated CWO unit if it is active:
   `scripts/launch_chatgpt_cdp_chrome.sh --stop`
2. Verify `9222` is clear.
3. Relaunch with `--replace --write-config`.
4. Re-run `--dry-run` and `--confirm-only` before dispatch.

Avoid killing or reloading unrelated user Chrome windows unless the operator
explicitly approves that loss of browser state.

## Security Boundaries

- CDP must stay on localhost.
- Never store Google credentials, cookies, session tokens, private packet text,
  or browser profile paths in Beads comments, public docs, audit logs, or
  contractor prompts.
- The ChatGPT share link is a return channel, not permission to widen the share
  boundary.
- Browser text without a valid share URL and confirmed model attestation is not
  accepted master-review evidence.

Last verified on Fedora 43 Wayland: July 5, 2026.
