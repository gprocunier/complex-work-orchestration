"""Offline tests for retained evidence from the contained pool qualification."""

from dataclasses import replace
from datetime import date, datetime
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from cwo_core.native_pool_qualification_evidence import (  # noqa: E402
    REQUIRED_BEHAVIORS,
    OutcomeObservation,
    WorkerToolObservation,
    build_pass_record,
    observe_worker_tools,
)
from cwo_core.native_session_boundary import capture_unique_boundary  # noqa: E402


TURN = "current-turn"
SESSION = "01a20784-b263-7bf1-ae6e-000000000000"
WRITER = "cwo_finite.finite_command"
DIGEST = "4" * 40


def _row(record_type, **payload):
    return {"type": record_type, "payload": payload}


def _event(kind, turn=TURN):
    return _row("event_msg", type=kind, turn_id=turn)


def _spec(name, kind="function", **details):
    return {"type": kind, "name": name, **details}


def _declared(*specs, role="developer", **fields):
    return _row("response_item", type="additional_tools", role=role, tools=list(specs), **fields)


def _world(*names, full=True, **fields):
    return _row("world_state", full=full, state={"top_level_tools": dict.fromkeys(names, DIGEST)}, **fields)


def _turn(*observations, turn=TURN):
    return [_event("task_started", turn), *observations, _row("turn_context", turn_id=turn),
            _event("task_complete", turn)]


def _session(*rows):
    namespace = _spec("cwo_finite", "namespace", tools=[_spec("finite_command")])
    return [_row("session_meta", id=SESSION, dynamic_tools=[namespace]), *rows]


def _all_passed():
    return {key: OutcomeObservation("passed", (2 if key == "n3_concurrency" else 1,))
            for key in REQUIRED_BEHAVIORS}


def _report(**overrides):
    inputs = {"cwo_version": "1.26.0", "minimum_codex_version": "0.163.0",
              "date": date(2026, 11, 24), "runs_consumed": 2, "run_cap": 20,
              "outcomes": {}, "worker_tools": {}}
    return build_pass_record(**(inputs | overrides))


class WorkerToolObservationTests(unittest.TestCase):
    def test_archived_shape_projects_direct_and_nested_names_without_request_content(self):
        # The stock 0.171 inert witness emits declaration items before the
        # world-state name map and exact turn context. No original text is needed.
        secret = "sensitive fixture request body"
        functions = _spec("functions", "namespace", tools=[
            _spec("exec", "custom", description=f"{secret}\n### `apply_patch`\n### `clock__curr_time`"),
            _spec("wait", parameters={"default": secret}),
        ])
        finite = _spec("cwo_finite", "namespace", tools=[_spec("finite_command", description=secret)])
        rows = _session(*_turn(
            _declared(functions, finite),
            _row("response_item", type="message", content=secret),
            _world("functions", "functions.exec", "functions.wait", "cwo_finite", WRITER),
        ))
        with TemporaryDirectory() as scratch:
            home = Path(scratch)
            store = home / "archived_sessions"
            store.mkdir()
            archive = store / f"rollout-{SESSION}.jsonl"
            archive.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
            _, _, original = capture_unique_boundary(home, SESSION)
            observation = observe_worker_tools(original, turn_id=TURN)
        self.assertEqual(observation.world_state_tools, (WRITER, "functions.exec", "functions.wait"))
        self.assertEqual(observation.additional_tools, observation.world_state_tools)
        self.assertEqual(observation.code_mode_tools, ("apply_patch", "clock__curr_time"))
        self.assertEqual(observation.registered_tools, (WRITER,))
        self.assertEqual(observation.unexpected, ("apply_patch", "clock__curr_time", "functions.exec", "functions.wait"))
        self.assertEqual(observation.limitations, ())
        serialized = json.dumps(_report(worker_tools={1: {1: observation}}))
        self.assertNotIn(secret, serialized)
        self.assertNotIn(DIGEST, serialized)
        self.assertNotIn(TURN, serialized)
        self.assertNotIn(SESSION, serialized)

    def test_registration_or_call_without_declarations_stays_unavailable(self):
        rows = _session(*_turn(_row("response_item", type="function_call", name="tool_called")))
        observation = observe_worker_tools(rows, turn_id=TURN)
        self.assertEqual(observation.world_state_tools, ())
        self.assertEqual(observation.additional_tools, ())
        self.assertEqual(observation.registered_tools, (WRITER,))
        self.assertEqual(observation.unexpected, ())
        self.assertIn("declarations-unavailable", observation.limitations)

    def test_exact_window_excludes_foreign_declarations(self):
        rows = _session(
            *_turn(_world("prior_turn_tool"), turn="prior"),
            *_turn(_world("first_tool"), _world("wrong_binding", turn_id="parallel"),
                   _world("later_tool", full=False), _declared(_spec("wrong_role"), role="user")),
            *_turn(_world("next_turn_tool"), turn="next"),
        )
        observation = observe_worker_tools(rows, turn_id=TURN)
        self.assertEqual(observation.world_state_tools, ("first_tool", "later_tool"))
        self.assertEqual(observation.unexpected, ("first_tool", "later_tool"))
        self.assertIn("declarations-incomplete", observation.limitations)

    def test_ambiguous_or_missing_turn_data_has_registration_only(self):
        valid = _turn(_world("would_be_exposed"))
        cases = {
            "missing start": valid[1:],
            "missing context": valid[:2] + valid[3:],
            "duplicate start": [_event("task_started"), *valid],
            "duplicate terminal": [*valid, _event("task_complete")],
            "interleaved start": [valid[0], _event("task_started", "another"), *valid[1:]],
            "interleaved context": [*valid[:-1], _row("turn_context", turn_id="another"), valid[-1]],
            "legacy context alias": [*valid[:2], _row("turn_context", turnId=TURN), valid[-1]],
        }
        for problem, records in cases.items():
            with self.subTest(problem=problem):
                observation = observe_worker_tools(_session(*records), turn_id=TURN)
                self.assertEqual(observation.registered_tools, (WRITER,))
                self.assertEqual(observation.world_state_tools, ())
                self.assertIn("turn-unbound", observation.limitations)

    def test_partial_turn_and_invalid_names_preserve_useful_observations(self):
        fake_token = "sk-proj-test-credential"
        wrapper = _spec("functions", "namespace", tools=[
            _spec("exec", "custom", description=f"### `{fake_token}`\n### `cwo_finite__finite_command`"),
        ])
        rows = _turn(_declared(wrapper, _spec("not/a/tool"), {"type": "web_search"}),
                     _world("functions.exec", fake_token, "z" * 97))[:-1]
        observation = observe_worker_tools(rows, turn_id=TURN)
        self.assertEqual(observation.additional_tools, ("functions.exec", "web_search"))
        self.assertEqual(observation.code_mode_tools, ("cwo_finite__finite_command",))
        self.assertEqual(observation.unexpected, ("functions.exec", "web_search"))
        self.assertIn("terminal-unavailable", observation.limitations)
        self.assertIn("registration-unavailable", observation.limitations)
        self.assertIn("declarations-incomplete", observation.limitations)
        self.assertNotIn(fake_token, json.dumps(_report(worker_tools={1: {1: observation}})))

    def test_long_catalog_remains_bounded_and_informational(self):
        names = tuple(f"unexpected_{i}" for i in range(400))
        observation = observe_worker_tools(_session(*_turn(_world(*names))), turn_id=TURN)
        self.assertTrue(observation.unexpected)
        self.assertLess(len(observation.world_state_tools), len(names))
        self.assertIn("declarations-incomplete", observation.limitations)
        result = _report(outcomes=_all_passed(), worker_tools={1: {1: observation}})
        self.assertEqual(result["outcome"], "passed")


class QualificationPassRecordTests(unittest.TestCase):
    def test_pass_record_has_fixed_identity_and_separate_worker_provenance(self):
        first = observe_worker_tools(_session(*_turn(_world(WRITER))), turn_id=TURN)
        second = observe_worker_tools(_session(*_turn(_world("apply_patch"))), turn_id=TURN)
        result = _report(outcomes=_all_passed(), worker_tools={2: {3: second}, 1: {1: first}})
        self.assertEqual(result["outcome"], "passed")
        self.assertEqual(result["qualification"], "contained-pool")
        expected = {"date": "2026-11-24", "cwo_version": "1.26.0", "minimum_codex_version": "0.163.0",
                    "model": "gpt-6.2-sol", "effort": "xhigh", "tier": "default", "runs_consumed": 2, "run_cap": 20}
        self.assertEqual({key: result[key] for key in expected}, expected)
        self.assertEqual([(row["run"], row["worker"]) for row in result["tool_lists"]], [(1, 1), (2, 3)])
        self.assertEqual(result["tool_lists"][0]["rollout.world_state.top_level_tools"], [WRITER])
        self.assertEqual(result["tool_lists"][1]["unexpected"], ["apply_patch"])
        self.assertEqual(result["behaviors"]["n3_concurrency"], {"outcome": "passed", "runs": [2]})

    def test_missing_readback_cannot_make_or_break_containment(self):
        absent = WorkerToolObservation()
        report = _report(outcomes=_all_passed(), worker_tools={1: {1: absent}})
        self.assertEqual(report["outcome"], "passed")
        self.assertTrue(report["tool_lists"][0]["limitations"])
        self.assertEqual(_report(outcomes=_all_passed())["outcome"], "passed")
        no_cleanup = _all_passed()
        del no_cleanup["cleanup"]
        self.assertEqual(_report(outcomes=no_cleanup)["outcome"], "incomplete")
        self.assertEqual(_report()["outcome"], "incomplete")
        self.assertEqual(_report(runs_consumed=0)["outcome"], "not-run")

    def test_failed_containment_behaviors_remain_separate(self):
        outcomes = _all_passed()
        for key in ("cross_worker_isolation", "provider_only_egress", "cleanup"):
            outcomes[key] = OutcomeObservation("failed", (1, 2))
        result = _report(outcomes=outcomes)
        self.assertEqual(result["outcome"], "failed")
        for key in ("cross_worker_isolation", "provider_only_egress", "cleanup"):
            self.assertEqual(result["behaviors"][key], {"outcome": "failed", "runs": [1, 2]})

    def test_stock_catalog_fallback_is_recorded_without_gating_containment(self):
        result = _report(outcomes=_all_passed(), catalog_modes={2: "stock-fallback", 1: "trimmed"})
        self.assertEqual(result["outcome"], "passed")
        self.assertEqual(result["model_catalog"], [{"run": 1, "mode": "trimmed"},
                                                   {"run": 2, "mode": "stock-fallback"}])

    def test_outcome_requires_started_reference_and_claim_exact_inputs(self):
        cases = (
            {"outcomes": {"cleanup": OutcomeObservation("passed")}},
            {"outcomes": {"cleanup": OutcomeObservation("passed", (3,))}},
            {"outcomes": {"cleanup": OutcomeObservation("not-run", (1,))}},
            {"outcomes": {"uncorroborated": OutcomeObservation("passed", (1,))}},
            {"outcomes": _all_passed() | {"n3_concurrency": OutcomeObservation("passed", (1,))}},
            {"worker_tools": {3: {1: WorkerToolObservation()}}},
            {"worker_tools": {1: {4: WorkerToolObservation()}}},
            {"catalog_modes": {1: "custom"}}, {"catalog_modes": {3: "trimmed"}},
            {"run_cap": 21}, {"runs_consumed": 21}, {"runs_consumed": True},
            {"date": datetime(2026, 11, 24)}, {"cwo_version": "1.26.0\nprivate"},
        )
        for overrides in cases:
            with self.subTest(overrides=overrides), self.assertRaises(ValueError):
                _report(**overrides)

    def test_record_only_retains_safe_values_even_for_prebuilt_observations(self):
        fabricated = replace(WorkerToolObservation(), additional_tools=("safe_tool", "secret payload"),
                             limitations=("path to sensitive file",))
        result = _report(worker_tools={1: {1: fabricated}})
        row = result["tool_lists"][0]
        self.assertEqual(row["rollout.additional_tools"], ["safe_tool"])
        self.assertNotIn("sensitive file", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
