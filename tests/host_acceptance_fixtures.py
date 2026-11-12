"""P0 host-pipeline fixtures: synthetic results, no model or Beads effects."""
import hashlib
from pathlib import Path
import uuid

from cwo_core.host_acceptance import HostAcceptancePipeline, HostAdjudicationDecision
from cwo_core.host_records import using_test_store


def provision_acceptance(store, *, bead_id, database_identity):
    root = Path(__file__).resolve().parents[1]
    text = (root / "examples/sample-contractor-return.md").read_text(encoding="utf-8")
    dispatch_id = "EXAMPLE_ACCEPTANCE_" + uuid.uuid4().hex
    store.write_dispatch(dispatch_id=dispatch_id, dispatch_role="executor", provider="openai",
        model_family="gpt", model_id="gpt-6.1-sol", reasoning_effort="xhigh",
        session_id="EXAMPLE_EXECUTOR_SESSION", packet_sha256="1" * 64,
        bead_id=bead_id, executor="codex_architecture_critic", provider_key="internal_codex")
    returned = hashlib.sha256(text.encode("utf-8")).hexdigest()
    store.write_return_received(dispatch_id, returned)
    pipeline = HostAcceptancePipeline(lambda observed: HostAdjudicationDecision(
        "accepted", "EXAMPLE offline autonomous CWO acceptance", "EXAMPLE_HOST_CONTROL"), store=store)
    with using_test_store(store):
        record_id = pipeline.accept(text, bead_id=bead_id, dispatch_id=dispatch_id,
                                    database_identity=database_identity)
    accepted = store.get(record_id)
    return {"acceptance_record": record_id, "return_sha256": returned,
            "evaluation_sha256": accepted["evaluation_sha256"]}
