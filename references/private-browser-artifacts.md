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

Private permissions and audit hashes provide local access hygiene and consistent
identity. They do not authenticate the provider or protect against another
process with the same user's access to both the artifacts and trusted audit
store. Keep the independently selected references outside the returned artifact.

Separate create-share authorization binds the selected conversation, ordered
content, purpose and expiry. It consumes its own one-use execution admission;
configuration alone cannot authorize sharing. Browser Send and sharing remain
unavailable as live routes. Offline action checks do not restore them or qualify
live browser behavior.
