"""P0 host-pipeline fixtures: synthetic results, no model or Beads effects."""
import hashlib
from pathlib import Path
import uuid

from cwo_core.model_identities import resolve_model
from cwo_core.host_acceptance import HostAcceptancePipeline, HostAdjudicationDecision
from cwo_core.host_records import using_test_store


def provision_acceptance(store, *, bead_id, database_identity, delivery_context=None,
                        observation_sha256=None, adjudication_identity="default"):
    root = Path(__file__).resolve().parents[1]
    text = (root / "examples/sample-contractor-return.md").read_text(encoding="utf-8")
    dispatch_id = "EXAMPLE_ACCEPTANCE_" + uuid.uuid4().hex
    metadata = {} if delivery_context is None else {'source_context': {
        **delivery_context, 'dispatch_id': dispatch_id, 'packet_sha256': '1' * 64,
        'executor': 'codex_architecture_critic'}}
    if observation_sha256 is not None:
        metadata['source_context']['observation_sha256'] = observation_sha256
    store.write_dispatch(dispatch_id=dispatch_id, dispatch_role="executor", provider="openai",
        model_family="gpt", model_id=resolve_model("sol"), reasoning_effort="xhigh",
        session_id="EXAMPLE_EXECUTOR_SESSION", packet_sha256="1" * 64,
        bead_id=bead_id, executor="codex_architecture_critic", provider_key="internal_codex",
        evaluation_metadata=metadata)
    returned = hashlib.sha256(text.encode("utf-8")).hexdigest()
    store.write_return_received(dispatch_id, returned)
    if adjudication_identity == "default":
        adjudication_identity = dict(provider="openai", model_family="gpt", model_id=resolve_model("astra"),
            reasoning_effort="xhigh", dispatch_id="EXAMPLE_ADJUDICATION_" + uuid.uuid4().hex,
            session_id="EXAMPLE_ADJUDICATOR_SESSION")
    pipeline = HostAcceptancePipeline(lambda observed: HostAdjudicationDecision(
        "accepted", "EXAMPLE offline autonomous CWO acceptance", "EXAMPLE_HOST_CONTROL"), store=store,
        adjudication_identity=adjudication_identity)
    with using_test_store(store):
        record_id = pipeline.accept(text, bead_id=bead_id, dispatch_id=dispatch_id,
                                    database_identity=database_identity)
    accepted = store.get(record_id)
    return {"acceptance_record": record_id, "return_sha256": returned,
            "evaluation_sha256": accepted["evaluation_sha256"]}
