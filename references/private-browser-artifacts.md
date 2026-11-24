# Private browser returns

A complete private browser return binds the reviewed input to the packet,
frozen screened request, observed conversation and user/assistant messages, and
exact response bytes. Candidate reviews name the existing formal candidate
identity and verify its current repository contents. Other assignments identify
their packet inputs explicitly and make no candidate claim.

The private provenance record contains identities and digests. Response text
stays in its separate owner-only file. Publication uses the existing protected
directory, atomic no-overwrite writes and substitution checks. A partial capture
or a missing file is retained for diagnosis and cannot become a complete return.

Ingestion needs the current original packet, its saved packet-source digest and
the exact dispatch event hash returned with the private-artifact reference. The
event is read from the configured audit store and pins the raw provenance-file
digest before response content is read. Values copied from the artifact being
checked do not supply independent expectations. A changed packet, source,
candidate, request, conversation, message or response refuses.

For an artifact whose independent references are already available:

```bash
python scripts/ingest_chatgpt_share_return.py \
  --private-artifact private/review.provenance.json \
  --packet private/packet.json \
  --packet-source-sha256 "$PACKET_SOURCE_SHA256" \
  --capture-event "$CAPTURE_EVENT_HASH" \
  --output private/review-return.md --json
```

A candidate-bound packet also requires its private candidate record and current
repository through `--candidate` and `--candidate-root`. Full candidate and Bead
records are not disclosed in the packet. Default stdout is metadata, and refusal diagnostics omit response content.
The explicitly requested contractor-return file includes
the evidence text for normal evaluation. Extraction does not accept findings.
Older provenance versions remain historical records and cannot be upgraded into
a complete current chain by adding fields.

### Direct evaluation of an observed host dispatch

The trusted host can call `prepare_browser_packet_request` and then call
`record_dispatch()` on that prepared request before Send. The configured host
store records the packet source, request ID and screened preparation and Send
digests. The host supplies the actual model, effort and session when it records
the observed dispatch after capture. Evaluation verifies these prepared fields.

Use `cwo evaluate` to score the exact reply from an existing host-observed
browser dispatch. Supply the original packet and its independent capture
references.

```bash
python scripts/cwo.py evaluate \
  --private-artifact private/review.provenance.json \
  --contractor-packet private/packet.json \
  --packet-source-sha256 "$PACKET_SOURCE_SHA256" \
  --capture-event "$CAPTURE_EVENT_HASH" --json
```

The configured host audit store must contain the completed private capture.
The observed executor dispatch must bind that capture event and the exact
screened request digest. Evaluation records the exact response digest in the
host chain and applies the dispatch's review requirements. Its output contains
the score, review status and record reference.

Browser attestation flags report confirmation of configured UI labels. Exact
model and session identity come from the original host observation. Live Chrome
dispatch and qualification of a Pro response remain pending.

Private permissions and audit hashes provide local access hygiene and consistent
identity. They do not authenticate the provider or protect against another
process with the same user's access to both the artifacts and trusted audit
store. Keep the independently selected references outside the returned artifact.

Separate create-share authorization requires fresh consent from the original
registered parent. Consent binds its frozen source, candidate or packet inputs,
prepared request, intended purpose, document and conversation identity, complete
ordered history including the generated response, and exact final disclosure
bytes. Decoded conversation content and the final representation pass outbound
screening at consent and again before creation. Unknown coverage refuses.

Consent is an opaque, expiring object that can authorize only one original share
ticket. Its lifetime cannot exceed the original action timeout; an earlier
requested expiry still applies. Copies, foreign consent, replay and changed
source, options, document, conversation or content refuse before the next effect.
Sharing consumes a separate one-use execution admission within the original
aggregate budget. Configuration alone cannot grant consent.

Registered offline fixtures can declare complete coverage and exercise the
separate consumer for explicit plaintext disclosures. Unrepresented media,
attachments, embedded documents and rich markup refuse complete coverage.
Plaintext wrappers permit only pre-wrap whitespace formatting; additional inline
style properties refuse coverage.
The supported fixture boundary pins the original document
and its root, checks the current URL and exact disclosure, then clicks once in
one synchronous browser operation. It validates a result URL against an observed
document, conversation and action binding. A known stale result refuses before
creation. A wrong result discovered after creation leaves an unknown outcome
and conservative reservation accounting; it cannot undo that creation. No
legacy share, social or clipboard fallback follows a refusal.

Browser Send and sharing remain unavailable as live routes. Offline fixture
coverage does not establish complete coverage of a live UI, restore routes or
authorize live sharing.
