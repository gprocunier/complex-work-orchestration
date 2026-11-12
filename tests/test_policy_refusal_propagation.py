"""Schema refusals survive advisory executor lookups at real consumers."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core import policy, returns, routing  # noqa: E402
from cwo_core.policy_schema import PolicySchemaError  # noqa: E402
from tests.test_policy_schema import malformed_policy  # noqa: E402


KEY = "gemini_manual_reviewer"
UNKNOWN = "offline-unknown-executor"


class PolicyRefusalPropagationTests(unittest.TestCase):
    def tearDown(self) -> None:
        policy.clear_policy_cache()

    def invalid_executor(self):
        return malformed_policy(
            "executor-registry",
            lambda document: document["executors"][KEY].update(external="false"),
        )

    def sample_return(self) -> str:
        return (ROOT / "examples" / "sample-contractor-return.md").read_text(encoding="utf-8")

    def assert_schema_refused(self, call: Callable[[], Any]) -> None:
        with self.assertRaises(PolicySchemaError) as raised:
            call()
        self.assertIn("policy/executor-registry.yaml", str(raised.exception))
        self.assertIn("external", str(raised.exception))
        self.assertIn("expected boolean, found string", str(raised.exception))

    def test_provenance_preserves_schema_refusal(self) -> None:
        with malformed_policy("executor-registry"):
            value = returns.return_provenance(executor=KEY)
            self.assertEqual(value["executor"], KEY)
            self.assertEqual(value["provider_family"], "google")
            self.assertEqual(value["provenance_warnings"], [])
        with self.invalid_executor():
            self.assert_schema_refused(lambda: returns.return_provenance(executor=KEY))

    def test_synthesis_default_preserves_schema_refusal(self) -> None:
        with malformed_policy("executor-registry"):
            self.assertEqual(returns.executor_default_synthesis_use(KEY), "salvage-only")
        with self.invalid_executor():
            self.assert_schema_refused(lambda: returns.executor_default_synthesis_use(KEY))

    def test_final_recommendation_cannot_lose_configured_restriction(self) -> None:
        kwargs = {
            "verdict": "accept",
            "recommended_disposition": "accept-findings",
            "evidence_quality_score": 100,
            "boundary_status": "clear",
            "executor": KEY,
            "provider_family": "openai",
            "hard_disqualifiers": [],
        }
        with malformed_policy("executor-registry"):
            self.assertEqual(returns.recommend_synthesis_use(**kwargs), "salvage-only")
        with self.invalid_executor():
            self.assert_schema_refused(lambda: returns.recommend_synthesis_use(**kwargs))

    def test_acceptance_entry_preserves_schema_refusal(self) -> None:
        text = self.sample_return()
        with malformed_policy("executor-registry"):
            decision = returns.make_acceptance_decision(text, executor=KEY)
            self.assertEqual(decision["executor"], KEY)
            self.assertEqual(decision["verdict"], "accept")
            self.assertEqual(decision["recommended_synthesis_use"], "salvage-only")
            self.assertIs(decision["execution_permitted"], False)
        with self.invalid_executor():
            self.assert_schema_refused(lambda: returns.make_acceptance_decision(text, executor=KEY))

    def test_normalization_preserves_schema_refusal(self) -> None:
        text = self.sample_return()
        with malformed_policy("executor-registry"):
            bundle = returns.normalize_contractor_return(text, executor=KEY)
            self.assertEqual(bundle["provider_family"], "google")
            self.assertEqual(bundle["executor"], KEY)
        with self.invalid_executor():
            self.assert_schema_refused(lambda: returns.normalize_contractor_return(text, executor=KEY))

    def test_routing_lookup_preserves_schema_refusal(self) -> None:
        with malformed_policy("executor-registry"):
            entry = routing.executor_registry_entry(KEY)
            self.assertEqual(entry["key"], KEY)
            self.assertIs(entry["external"], True)
            self.assertEqual(entry["default_synthesis_use"], "salvage-only")
        with self.invalid_executor():
            self.assert_schema_refused(lambda: routing.executor_registry_entry(KEY))

    def test_unknown_executor_fallback_remains_supported(self) -> None:
        with malformed_policy("executor-registry"):
            provenance = returns.return_provenance(executor=UNKNOWN)
            self.assertEqual(provenance["executor"], UNKNOWN)
            self.assertEqual(provenance["provenance_class"], "unknown")
            self.assertIn(
                "executor not found in executor registry",
                provenance["provenance_warnings"],
            )
            self.assertIsNone(returns.executor_default_synthesis_use(UNKNOWN))
            self.assertEqual(routing.executor_registry_entry(UNKNOWN), {})
            decision = returns.make_acceptance_decision(self.sample_return(), executor=UNKNOWN)
            self.assertEqual(decision["executor"], UNKNOWN)
            self.assertEqual(decision["recommended_synthesis_use"], "primary")

    def test_absent_executor_behavior_remains_supported(self) -> None:
        with malformed_policy("executor-registry"):
            self.assertIsNone(returns.executor_default_synthesis_use(None))
            self.assertEqual(routing.executor_registry_entry(None), {})
            provenance = returns.return_provenance(executor=None)
            self.assertIsNone(provenance["executor"])
            self.assertEqual(provenance["provenance_class"], "unknown")
            self.assertEqual(provenance["provenance_warnings"], [])

    def test_unknown_executor_does_not_hide_schema_refusal(self) -> None:
        with malformed_policy("executor-registry"):
            self.assertIsNone(returns.executor_default_synthesis_use(UNKNOWN))
        with self.invalid_executor():
            calls = (
                lambda: returns.return_provenance(executor=UNKNOWN),
                lambda: returns.executor_default_synthesis_use(UNKNOWN),
                lambda: routing.executor_registry_entry(UNKNOWN),
            )
            for index, call in enumerate(calls):
                with self.subTest(consumer=index):
                    self.assert_schema_refused(call)

    def test_alias_preserves_requested_and_canonical_identity(self) -> None:
        alias = "codex_5_6_sol_architect"
        with malformed_policy("executor-registry"):
            entry = routing.executor_registry_entry(alias)
            self.assertEqual(entry["key"], "frontier_architect")
            self.assertEqual(entry["requested_key"], alias)
            provenance = returns.return_provenance(executor=alias)
            self.assertEqual(provenance["executor"], alias)
            self.assertEqual(provenance["provider_key"], "internal_codex")
            self.assertIsNone(returns.executor_default_synthesis_use(alias))

    def test_local_completion_restriction_remains_effective(self) -> None:
        text = self.sample_return()
        key = "rhoai_glm_hardened_architecture_critic"
        with malformed_policy("executor-registry"):
            complete = returns.make_acceptance_decision(
                text, executor=key, local_completion_status="completed",
                local_usable_final_content=True,
            )
            self.assertEqual(complete["recommended_synthesis_use"], "primary")
            incomplete = returns.make_acceptance_decision(
                text, executor=key, local_completion_status="empty-final-content",
                local_usable_final_content=False,
            )
            self.assertEqual(incomplete["recommended_synthesis_use"], "salvage-only")
            self.assertIs(incomplete["human_adjudication_required"], True)



class PolicyLookupFailureCategoryTests(unittest.TestCase):
    def tearDown(self) -> None:
        policy.clear_policy_cache()

    def calls(self, key: str) -> tuple[Callable[[], Any], ...]:
        return (
            lambda: returns.return_provenance(executor=key),
            lambda: returns.executor_default_synthesis_use(key),
            lambda: routing.executor_registry_entry(key),
        )

    def assert_lookup_refusal(self, key: str) -> None:
        for call in self.calls(key):
            with self.subTest(call=call):
                policy.clear_policy_cache()
                with self.assertRaises(SystemExit) as raised:
                    call()
                self.assertNotIsInstance(raised.exception, policy.UnknownExecutorError)

    def test_only_unknown_executor_has_the_fallback_category(self) -> None:
        with malformed_policy("executor-registry"):
            with self.assertRaises(policy.UnknownExecutorError) as raised:
                policy.executor_config(UNKNOWN)
            self.assertIsInstance(raised.exception, SystemExit)
            self.assertIsNone(returns.executor_default_synthesis_use(UNKNOWN))
            self.assertEqual(routing.executor_registry_entry(UNKNOWN), {})

    def test_missing_registry_is_not_an_unknown_executor(self) -> None:
        with malformed_policy("executor-registry") as directory:
            self.assertEqual(returns.executor_default_synthesis_use(KEY), "salvage-only")
            (directory / "executor-registry.yaml").unlink()
            self.assert_lookup_refusal(KEY)

    def test_malformed_json_is_not_an_unknown_executor(self) -> None:
        with malformed_policy("executor-registry") as directory:
            self.assertEqual(returns.executor_default_synthesis_use(KEY), "salvage-only")
            (directory / "executor-registry.yaml").write_text("{", encoding="utf-8")
            self.assert_lookup_refusal(KEY)

    def test_alias_cycle_is_not_an_unknown_executor(self) -> None:
        with malformed_policy("executor-registry"):
            self.assertEqual(returns.executor_default_synthesis_use(KEY), "salvage-only")
        def cycle(document: dict[str, Any]) -> None:
            document["aliases"].update({"offline-cycle-a": "offline-cycle-b", "offline-cycle-b": "offline-cycle-a"})
        with malformed_policy("executor-registry", cycle):
            self.assert_lookup_refusal("offline-cycle-a")

    def test_dangling_alias_is_not_an_unknown_executor(self) -> None:
        with malformed_policy("executor-registry"):
            self.assertEqual(returns.executor_default_synthesis_use(KEY), "salvage-only")
        def dangling(document: dict[str, Any]) -> None:
            document["aliases"]["offline-dangling-alias"] = UNKNOWN
        with malformed_policy("executor-registry", dangling):
            self.assert_lookup_refusal("offline-dangling-alias")

if __name__ == "__main__":
    unittest.main()
