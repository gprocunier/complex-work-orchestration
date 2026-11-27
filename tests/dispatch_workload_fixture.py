"""Synthetic planning input for a real rendered packet in no-model witnesses."""
import json

from cwo_core import work_sizing
from generate_manual_dispatch_prompt import render_packet_prompt
from tests.test_route_feasibility_preparation import bind, planner, record


def planned_export(packet, *, browser=False, prompt=None):
    route = record(tiny=True)
    route["parent_id"] = packet["bead_id"]
    node = route["nodes"][0]
    prompt = render_packet_prompt(packet) if prompt is None else prompt
    node.update(prompt=prompt.rstrip() if browser else prompt, wrappers=[], attachments=[], sources=[])
    transport = packet.get("executor_transport") or {}
    node["execution"].update(
        executor=packet["executor"], provider=packet["provider_key"],
        model=transport.get("model") or transport.get("default_model_label") or "EXAMPLE-Planned-Model",
        effort=transport.get("effort") or transport.get("default_reasoning_label") or "default",
    )
    source = node["estimate_source"]
    source.update(bead_id=route["parent_id"], requested_model=node["execution"]["model"], context_manifest=[])
    node["source_sha256"] = work_sizing.canonical_work_estimate_sha256(source)
    unit = work_sizing.evaluate_work_estimate(source, policy=route["policy"])
    node["unit_estimate"] = unit
    node["unit_sha256"] = work_sizing.canonical_work_estimate_sha256(unit)
    node["rendered_request"] = planner.render_request(node)
    return {"route_input": bind(route), "node_id": node["id"]}


def write_workload(path, packet, *, browser=False, prompt=None):
    path.write_text(json.dumps(planned_export(packet, browser=browser, prompt=prompt)), encoding="utf-8")
    return str(path)
