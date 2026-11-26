# ChatGPT Pro review in desktop Chrome

Run the architect's Codex thread in the ChatGPT desktop app. The thread uses
`@Chrome` in the Chrome profile paired through the
[ChatGPT extension](https://chromewebstore.google.com/detail/chatgpt/hehggadaopoacecdllhhajmbjkdcmajg).
With the operator present and the review authorized, the thread prepares the
request, drives the browser and evaluates the reply without a manual transfer.
Browser access belongs to the desktop app session. Keep its private browser
connection inside the app.

1. [Build an approved browser reviewer packet](external-contracting.md#dispatch-flow)
   within the assignment's sharing boundary. From the CWO directory, use the
   same host audit store to prepare and inspect the screened request. Set
   `packet` to the original packet path. Create a private run directory that
   the desktop thread can write to and keep that review's files there.

   ```bash
   umask 077
   run_dir=$(mktemp -d)
   python3 scripts/cwo.py prepare-browser --packet "$packet" > "$run_dir/request.txt"
   ```

2. Use `@Chrome` to open a fresh ChatGPT chat in the paired Chrome profile.
   Select Pro and record the exact label shown in the model picker. With the
   operator present, send the screened request once, including its CWO request
   ID line. Read `request_id` from the posted user message.
3. Wait for the assistant to finish. Use `@Chrome` to read the visible message text
   of the completed reply and save the text as UTF-8 in `$run_dir/reply.txt`.
   Evaluate the file with the original packet, the posted `request_id` and
   the confirmed `model_label`. Save the evaluation in the same run directory.

   ```bash
   python3 scripts/cwo.py evaluate --contractor-packet "$packet" \
     --browser-reply "$run_dir/reply.txt" --request-id "$request_id" \
     --model-label "$model_label" --json > "$run_dir/evaluation.json"
   ```

CWO links the dispatch, private return and evaluator record in the host audit.
The evaluator reports the score and review status. The reply text stays in the
private artifact. For a candidate-bound packet, supply `--candidate` and
`--candidate-root` at evaluation. Complete any required peer review and
adjudication before using the findings. Share URL and HTML intake is retired.

If an assignment requires this reviewer and the route or required evidence is
unavailable, record the missing prerequisite and obtain the operator's decision
before dependent implementation. For saved CDP captures, see
[Private browser returns](private-browser-artifacts.md).

For a redacted rehearsal of a saved legacy browser configuration, use
`cwo browser-review --dry-run`. The command validates the packet and config
locally and logs the rehearsal by default. Calls without `--dry-run`, including
`--confirm-only`, refuse before loading the packet or config.
