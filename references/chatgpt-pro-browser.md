# ChatGPT Pro review in desktop Chrome

The desktop route is off by default pending an authorized live round trip that
brings a Pro reply back into CWO's evaluator. The workflow requires the operator
present in a ChatGPT desktop session paired with the target Chrome profile
through the [ChatGPT extension](https://chromewebstore.google.com/detail/chatgpt/hehggadaopoacecdllhhajmbjkdcmajg).
Use that desktop session for browser submission and capture. CWO's request
preparation and reply evaluation run locally.

1. [Build an approved browser reviewer packet](external-contracting.md#dispatch-flow)
   within the assignment's sharing boundary. From the CWO directory, use the
   same host audit store to prepare and inspect the screened request. Set
   `packet` to the original packet path and `request` to a new file in a
   private working directory.

   ```bash
   umask 077
   python3 scripts/cwo.py prepare-browser --packet "$packet" > "$request"
   ```

2. From a ChatGPT desktop thread, use `@Chrome` to open a fresh ChatGPT chat in
   the paired Chrome profile. Select Pro and confirm the label shown in the
   model picker. With the operator present, send the prepared text intact,
   including its CWO request ID line.
3. Read the request ID from the posted message and copy the reply from the
   same chat into a private text file. Evaluate it with the original packet,
   the observed request ID and the label the sender confirmed in the model
   picker. Set `reply`, `request_id` and `model_label` to those values.

   ```bash
   python3 scripts/cwo.py evaluate --contractor-packet "$packet" \
     --browser-reply "$reply" --request-id "$request_id" \
     --model-label "$model_label" --json
   ```

CWO links the dispatch, private return and evaluator record in the host audit.
The evaluator reports the score and review status. The reply text stays in the
private artifact. For a candidate-bound packet, supply `--candidate` and
`--candidate-root` at evaluation. Complete any required peer review and
adjudication before using the findings. Share-link ingestion remains held.

If an assignment requires this reviewer and the route or required evidence is
unavailable, record the missing prerequisite and obtain the operator's decision
before dependent implementation. For saved CDP captures, see
[Private browser returns](private-browser-artifacts.md).
