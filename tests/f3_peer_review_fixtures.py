"""Genuine host-written peer-review fixture history; no model invocation."""
import hashlib
import json
from pathlib import Path
import tempfile

from cwo_core.adjudication import dispatch_provenance
from cwo_core.host_return_intake import record_received_return
from cwo_core.host_records import HostRecordStore, using_test_store
from cwo_core.policy import load_policy
from cwo_core.returns import make_acceptance_decision
from cwo_core.peer_review import pending_evaluation_sha256


def review_binding(case, text, *, own_changes=None, review_changes=None,
                   record_executor_receipt=True, record_reviewer_receipt=True, **inputs):
    root = Path(case.enterContext(tempfile.TemporaryDirectory()))
    store = HostRecordStore.for_tests(root / "host")
    case.enterContext(using_test_store(store))
    case._host_review_store = store
    dispatch_id = inputs.get("dispatch_id") or "EXAMPLE_EXECUTOR_DISPATCH"
    executor = inputs.get("executor") or "codex_architecture_critic"
    vendor = dispatch_provenance({"record_type": "cwo-dispatch-record", "version": 1,
        "dispatch_id": dispatch_id, "executor": executor, "candidate": "EXAMPLE_OFFLINE_CANDIDATE",
        "return_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest()})["provider_family"]
    model_id, model = next(iter(load_policy("provider-registry")["review_models"][vendor].items()))
    own = dict(dispatch_id=dispatch_id, dispatch_role="executor", provider=vendor,
        model_family=model["model_family"], model_id=model_id, reasoning_effort="xhigh",
        session_id="EXAMPLE_EXECUTOR_SESSION", packet_sha256="1" * 64, executor=executor)
    own.update(own_changes or {})
    store.write_dispatch(**own)
    if record_executor_receipt:
        store.write_return_received(dispatch_id, hashlib.sha256(text.encode("utf-8")).hexdigest(),
                                    capture_provenance="host-capture-v1")
    context = {} if inputs.get("dispatch_id") else {"dispatch_id": dispatch_id}
    pending = make_acceptance_decision(text, peer_review_status="pending", **{**inputs, **context})
    review = dict(dispatch_id="EXAMPLE_REVIEW_DISPATCH", dispatch_role="peer-review", provider="openai",
        model_family="gpt", model_id="gpt-6-astra", reasoning_effort="max", session_id="EXAMPLE_REVIEW_SESSION",
        packet_sha256="2" * 64, executor="codex_architecture_critic",
        review_target={"dispatch_id": dispatch_id, "return_sha256": own_return(text),
                       "evaluation_sha256": pending_evaluation_sha256(pending)})
    review.update(review_changes or {})
    store.write_dispatch(**review)
    reviewer = {name: review[name] for name in ("provider", "model_family", "model_id", "reasoning_effort", "dispatch_id")}
    record = {"record_type": "cwo-peer-review", "version": 2, "reviewer_identity": reviewer.copy(),
        "decision": "passed", "return_sha256": own_return(text),
        "evaluation_sha256": pending_evaluation_sha256(pending)}
    if record_reviewer_receipt:
        if review_changes:
            # Deliberately inconsistent host fixture isolates the reader's target/role checks.
            store.write_return_received(review["dispatch_id"], pending_evaluation_sha256(record),
                                        capture_provenance="host-capture-v1")
        else:
            record_received_return(store, review["dispatch_id"], json.dumps(record).encode())
    return {**context, "peer_review_reviewer": reviewer, "peer_review_record": record}


def own_return(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
