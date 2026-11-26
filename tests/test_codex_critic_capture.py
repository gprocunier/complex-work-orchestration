"""Offline witnesses for the original Codex critic and peer-review completion bridges."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.codex_critic_capture import (  # noqa: E402
    MAX_CODEX_CAPTURE_BYTES,
    prepare_codex_peer_review_request,
    record_codex_critic_completion,
    record_codex_peer_review_completion,
)
from cwo_core.errors import CWOPolicyError  # noqa: E402
from cwo_core.host_records import HostRecordStore, using_test_store  # noqa: E402
from cwo_core.host_return_intake import record_received_return  # noqa: E402
from cwo_core.model_identities import resolve_model  # noqa: E402
from cwo_core.peer_review import pending_evaluation_sha256  # noqa: E402
from cwo_core.policy import configured_gemini_critic  # noqa: E402
from cwo_core.returns import make_acceptance_decision  # noqa: E402


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def jsonl(rows):
    return b"".join(json.dumps(row, ensure_ascii=False).encode("utf-8") + b"\n" for row in rows)


def rollout_row(kind, **payload):
    return dict(type=kind, payload=payload)


def event(kind, **payload):
    return rollout_row("event_msg", type=kind, **payload)


def response(role, kind, text, **payload):
    return rollout_row("response_item", type="message", role=role,
                       content=[dict(type=kind, text=text)], **payload)


class OriginalCodexProcess:
    def __init__(self, root, request, final, *, session="019a0000-0000-7000-8000-000000000001", effort="xhigh"):
        self.session = session
        self.turn = "019a0000-0000-7000-8000-000000000009"
        self.request, self.final = request, final
        self.stdout = [dict(type="thread.started", thread_id=session), dict(type="turn.started"),
                       dict(type="item.completed", item=dict(type="reasoning", id="item_0", text="Summary")),
                       dict(type="item.completed", item=dict(type="agent_message", id="item_1", text=final)),
                       dict(type="turn.completed", usage=dict(input_tokens=20, output_tokens=10))]
        self.rollout = [
            rollout_row("session_meta", id=session, session_id=session, source="exec", model_provider="openai",
                        originator="codex_exec", thread_source="user", history_mode="paginated"),
            event("task_started", turn_id=self.turn, root_turn_id=self.turn),
            rollout_row("response_item", type="additional_tools", role="developer", tools=[]),
            response("developer", "input_text", "Runtime setup"),
            response("user", "input_text", "<environment_context>\n<shell>bash</shell>\n</environment_context>"),
            rollout_row("world_state"),
            rollout_row("turn_context", turn_id=self.turn, root_turn_id=self.turn, model=resolve_model("sol"),
                        effort=effort, sandbox_policy={"type": "read-only"}),
            event("thread_settings_applied", thread_id=session,
                  thread_settings=dict(model=resolve_model("sol"), model_provider_id="openai",
                                       reasoning_effort=effort, service_tier="default")),
            response("user", "input_text", request.decode("utf-8")),
            event("item_completed", thread_id=session, turn_id=self.turn,
                  item=dict(type="UserMessage", id="user", content=[dict(type="text", text=request.decode("utf-8"))])),
            rollout_row("response_item", type="reasoning", summary=[]),
            event("item_completed", thread_id=session, turn_id=self.turn,
                  item=dict(type="AgentMessage", id="final", phase="final_answer",
                            content=[dict(type="Text", text=final)])),
            response("assistant", "output_text", final, phase="final_answer"),
            event("task_complete", turn_id=self.turn, root_turn_id=self.turn, last_agent_message=final),
        ]
        self.home = root / "codex"
        self.path = self.home / "sessions" / "2026" / f"rollout-original-{session}.jsonl"
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def inputs(self, *, exit_code=0):
        self.path.write_bytes(jsonl(self.rollout))
        return dict(stdout=jsonl(self.stdout), codex_home=self.home, exit_code=exit_code)


class CodexCriticCaptureTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.store = HostRecordStore.for_tests(self.root / "host")
        self.enterContext(using_test_store(self.store))
        self.request = "Review exactly this question. Café.\n".encode()
        self.original = OriginalCodexProcess(self.root, self.request, "  exact return — café\r\n\n")
        self.prepared = self._prepare_critic("critic")

    def _prepare_critic(self, dispatch_id):
        return self.store.write_dispatch(dispatch_id=dispatch_id, dispatch_role="executor", provider="openai",
            model_family=None, model_id=None, reasoning_effort=None, session_id=None,
            request_sha256=sha(self.request), bead_id="test-critic", executor="codex_architecture_critic",
            provider_key="internal_codex", evaluation_metadata={"dispatch_mode": "main_thread_review",
                                                                "peer_review_required": False})

    def _finish_critic(self, *, dispatch_id="critic", request=None, **changes):
        return record_codex_critic_completion(self.store, dispatch_id,
            request=self.request if request is None else request, **{**self.original.inputs(), **changes})

    def test_preserves_exact_return_and_observed_dispatch_on_retry(self):
        result = self._finish_critic()
        self.assertEqual(result, self._finish_critic())
        self.assertEqual(result.final, self.original.final.encode())
        observed = self.store.require_dispatch("critic")
        self.assertEqual(observed["_record_sha256"], result.dispatch_record_sha256)
        self.assertEqual(observed["prepared_record_sha256"], self.prepared)
        self.assertEqual(observed["model_id"], resolve_model("sol"))
        self.assertEqual(observed["reasoning_effort"], "xhigh")
        self.assertEqual(observed["session_id"], self.original.session)
        self.assertEqual(self.store.require_return("critic", sha(result.final))["_record_sha256"],
                         result.return_record_sha256)
        self.assertEqual(self.store.get(result.return_record_sha256)["capture_provenance"], "host-capture-v1")

    def test_refuses_failed_or_missing_original_capture(self):
        wrong = [dict(exit_code=1), dict(exit_code=False), dict(stdout=b"{}\n"),
                 dict(stdout=jsonl(self.original.stdout)[:-1]),
                 dict(stdout=b"x" * (MAX_CODEX_CAPTURE_BYTES + 1)),
                 dict(codex_home=self.root / "ephemeral")]
        for override in wrong:
            with self.subTest(override=list(override)), self.assertRaises(CWOPolicyError):
                self._finish_critic(**override)
        duplicate = self.original.home / "archived_sessions" / self.original.path.name
        duplicate.parent.mkdir()
        duplicate.write_bytes(jsonl(self.original.rollout))
        with self.assertRaises(CWOPolicyError):
            self._finish_critic()
        self.assertEqual(self.store.require_dispatch("critic")["_record_sha256"], self.prepared)
        self.assertEqual(self.store.find("return-received"), [])

    def test_refuses_wrong_request_final_identity_and_activity(self):
        original = deepcopy(self.original.rollout)
        for index, change in (
            (0, dict(model_provider="other")), (0, dict(session_id=self.original.turn)),
            (1, dict(turn_id=self.original.session)), (6, dict(model=resolve_model("astra"))),
            (6, dict(effort="high")), (6, dict(service_tier="fast")),
            (6, dict(sandbox_policy={"type": "workspace-write"})),
            (7, dict(thread_settings=dict(service_tier="fast"))),
            (8, dict(content=[dict(type="input_text", text="a different request")])),
            (11, dict(item=dict(type="CommandExecution"))),
            (12, dict(content=[dict(type="output_text", text="a different final")])),
            (13, dict(last_agent_message="a different final")), (13, dict(error={"message": "failure"})),
        ):
            self.original.rollout = deepcopy(original)
            self.original.rollout[index]["payload"].update(change)
            with self.subTest(index=index, change=change), self.assertRaises(CWOPolicyError):
                self._finish_critic()
        for added in (event("model_reroute"), event("task_started", turn_id=self.original.turn),
                      rollout_row("response_item", type="function_call", name="read")):
            self.original.rollout = [*original[:-1], added, original[-1]]
            with self.subTest(added=added), self.assertRaises(CWOPolicyError):
                self._finish_critic()
        self.original.rollout = original
        with self.assertRaises(CWOPolicyError):
            self._finish_critic(request=b"wrong prepared request")
        self.assertEqual(self.store.find("return-received"), [])

    def test_allows_absent_tier_and_rejects_session_reuse(self):
        del self.original.rollout[7]["payload"]["thread_settings"]["service_tier"]
        self._finish_critic()
        self._prepare_critic("second")
        with self.assertRaises(CWOPolicyError):
            self._finish_critic(dispatch_id="second")

    def _gemini(self, *, session="gemini-session"):
        report = (ROOT / "examples" / "sample-contractor-return.md").read_bytes()
        metadata = dict(dispatch_mode="manual_ui", peer_review_required=True, share_boundary="redacted-packet",
                        job_description_label="contract-jd-architecture-reasoning", provider_conflict_domains=[])
        profile = configured_gemini_critic()
        prepared = self.store.write_dispatch(dispatch_id="gemini", dispatch_role="executor", provider="google",
            model_family=None, model_id=None, reasoning_effort=None, session_id=None,
            request_sha256=sha(b"gemini prompt"), bead_id="test-critic", executor="gemini_architecture_critic",
            provider_key="google_gemini_manual", evaluation_metadata=metadata)
        self.store.write_observed_dispatch("gemini", prepared_record_sha256=prepared,
            observation_sha256=sha(b"observed gemini"), provider="google", model_family="gemini",
            model_id=profile["model"], reasoning_effort=profile["effort"], session_id=session)
        record_received_return(self.store, "gemini", report)
        return report, metadata

    def _review(self, report):
        return prepare_codex_peer_review_request(self.store, "peer", target_dispatch_id="gemini", target_return=report)

    def test_peer_refuses_mismatched_target_before_writing_identity(self):
        report, _ = self._gemini()
        request = self._review(report)
        for raw in (report + b"\n", report.replace(b"\n", b"\r\n")):
            with self.subTest(raw_sha=sha(raw)), self.assertRaises(CWOPolicyError):
                self._review(raw)
        process = OriginalCodexProcess(self.root, request.request, "{}")
        with self.assertRaises(CWOPolicyError):
            record_codex_peer_review_completion(self.store, request, target_return=report, **process.inputs())
        self.assertEqual(self.store.find("dispatch", dispatch_id="peer"), [])

    def test_peer_reuses_evaluator_and_cannot_substitute_for_critic(self):
        report, metadata = self._gemini()
        request = self._review(report)
        reviewer = dict(provider="openai", model_family="gpt", model_id=resolve_model("sol"),
                        reasoning_effort="xhigh", dispatch_id="peer")
        accepted_inputs = dict(bead_id="test-critic", dispatch_id="gemini", executor="gemini_architecture_critic",
                               provider_key="google_gemini_manual", **metadata)
        pending = make_acceptance_decision(report.decode(), peer_review_status="pending", **accepted_inputs)
        decision = dict(record_type="cwo-peer-review", version=2, decision="passed", reviewer_identity=reviewer,
                        return_sha256=sha(report), evaluation_sha256=pending_evaluation_sha256(pending))
        process = OriginalCodexProcess(self.root, request.request, "\n" + json.dumps(decision, indent=2) + "\n")
        result = record_codex_peer_review_completion(self.store, request, target_return=report, **process.inputs())
        self.assertEqual(result.final, process.final.encode())
        self.assertEqual(result, record_codex_peer_review_completion(
            self.store, request, target_return=report, **process.inputs()))
        self.assertEqual(self.store.require_dispatch("peer")["review_target"],
                         dict(dispatch_id="gemini", return_sha256=sha(report),
                              evaluation_sha256=pending_evaluation_sha256(pending)))
        actual = make_acceptance_decision(report.decode(), peer_review_status="passed", peer_review_reviewer=reviewer,
                                          peer_review_record=decision, **accepted_inputs)
        self.assertEqual(actual["peer_review_separation"]["level"], "cross-family")
        self.assertFalse(set(actual["hold_reasons"]) & {"peer-review-pending", "provider-conflict-peer-review-pending"})
        with self.assertRaises(CWOPolicyError):
            self._finish_critic(dispatch_id="peer")


if __name__ == "__main__":
    unittest.main()
