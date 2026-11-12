from __future__ import annotations

import inspect
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core import returns  # noqa: E402
from cwo_core.policy import executor_config, load_policy  # noqa: E402
from cwo_core.types import (  # noqa: E402
    AcceptanceDecision,
    ContractorReturnBundle,
    ReturnProvenance,
)
from cwo_core.util import artifact_hash  # noqa: E402


NEW_FIELDS = {
    "configured_provider_access_class",
    "generated_output_trust",
    "provider_metadata_authority",
}


class ProviderOutputSeparationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.providers = load_policy("provider-registry")["providers"]
        cls.sample = (ROOT / "examples" / "sample-contractor-return.md").read_text(
            encoding="utf-8"
        )

    def assert_limits(self, record: dict, configured_class: str | None) -> None:
        self.assertEqual(record["configured_provider_access_class"], configured_class)
        self.assertEqual(
            record["generated_output_trust"],
            "evidence-requires-validation",
        )
        self.assertEqual(
            record["provider_metadata_authority"],
            "informational-not-access-grant",
        )

    def test_every_registry_provider_preserves_legacy_provenance(self) -> None:
        for key, profile in self.providers.items():
            with self.subTest(provider=key):
                provenance = returns.return_provenance(provider_key=key)
                self.assert_limits(provenance, profile.get("trust_tier"))
                self.assertEqual(
                    {name: value for name, value in provenance.items() if name not in NEW_FIELDS},
                    {
                        "executor": None,
                        "provider_key": key,
                        "provider_trust_tier": profile.get("trust_tier"),
                        "provider_family": profile.get("family"),
                        "provider_retention_class": profile.get("retention_class"),
                        "provider_external": profile.get("external"),
                        "dispatch_mode": None,
                        "local_profile": None,
                        "model_profile": None,
                        "provenance_class": (
                            "local-worker" if key in {"local_inference", "openshift_ai_vllm"}
                            else "external-contractor" if profile.get("external") is True
                            else "internal"
                        ),
                        "provenance_warnings": [],
                    },
                )

    def test_unknown_identity_has_no_configured_class_even_with_caller_tier(self) -> None:
        for key in (None, "missing-output-separation-provider"):
            for tier in (None, "", "trusted-internal"):
                with self.subTest(provider=key, tier=tier):
                    provenance = returns.return_provenance(
                        provider_key=key, provider_trust_tier=tier,
                    )
                    self.assert_limits(provenance, None)
                    self.assertEqual(provenance["provider_trust_tier"], tier or None)
                    self.assertEqual(
                        provenance["provenance_warnings"],
                        ["provider_key not found in provider registry"] if key else [],
                    )

    def test_caller_tier_retains_legacy_behavior_without_elevating_new_fields(self) -> None:
        for key, profile in self.providers.items():
            with self.subTest(provider=key):
                provenance = returns.return_provenance(
                    provider_key=key, provider_trust_tier="trusted-internal",
                )
                self.assert_limits(provenance, profile.get("trust_tier"))
                self.assertEqual(provenance["provider_trust_tier"], "trusted-internal")
                expected = (
                    [] if profile.get("trust_tier") == "trusted-internal"
                    else ["provider_trust_tier does not match provider registry"]
                )
                self.assertEqual(provenance["provenance_warnings"], expected)
                for tier in (None, ""):
                    self.assertEqual(
                        returns.return_provenance(
                            provider_key=key, provider_trust_tier=tier,
                        )["provider_trust_tier"],
                        profile.get("trust_tier"),
                    )

    def test_executor_resolution_aliases_and_explicit_provider_precedence(self) -> None:
        for executor in ("frontier_architect", "chatgpt_pro_5_5_extended_reasoning_browser", "openshift_ai_vllm_secure_reviewer"):
            config = executor_config(executor)
            provider = self.providers[config["provider_key"]]
            provenance = returns.return_provenance(
                executor=executor, provider_trust_tier="historical-tier",
            )
            self.assert_limits(provenance, provider.get("trust_tier"))
            self.assertEqual(provenance["provider_trust_tier"], "historical-tier")
            self.assertEqual(provenance["provenance_warnings"], [])
            override = returns.return_provenance(
                executor=executor, provider_key="missing-output-separation-provider",
                provider_trust_tier="trusted-internal",
            )
            self.assert_limits(override, None)
        unknown = returns.return_provenance(executor="missing-output-separation-executor")
        self.assert_limits(unknown, None)
        self.assertEqual(
            unknown["provenance_warnings"], ["executor not found in executor registry"],
        )

    def test_real_consumers_propagate_provenance_and_hash_expanded_bundle(self) -> None:
        for key in (*self.providers, "missing-output-separation-provider", None):
            for tier in (None, "trusted-internal"):
                with self.subTest(provider=key, tier=tier):
                    kwargs = {"provider_key": key, "provider_trust_tier": tier}
                    provenance = returns.return_provenance(**kwargs)
                    bundle = returns.normalize_contractor_return(self.sample, **kwargs)
                    decision = returns.make_acceptance_decision(self.sample, **kwargs)
                    for record in (bundle, decision):
                        self.assertEqual(
                            {name: record[name] for name in provenance}, provenance,
                        )
                    unhashed = {name: value for name, value in bundle.items() if name != "bundle_sha256"}
                    self.assertEqual(
                        bundle["bundle_sha256"], artifact_hash(json.dumps(unhashed, sort_keys=True)),
                    )
                    legacy = {name: value for name, value in unhashed.items() if name not in NEW_FIELDS}
                    self.assertNotEqual(
                        bundle["bundle_sha256"], artifact_hash(json.dumps(legacy, sort_keys=True)),
                    )

    def test_legacy_acceptance_refusal_and_bundle_content_remain_exact(self) -> None:
        real_provenance = returns.return_provenance

        def legacy_provenance(**kwargs):
            # Recreate only the pre-migration metadata surface using the real producer.
            return {
                name: value for name, value in real_provenance(**kwargs).items()
                if name not in NEW_FIELDS
            }

        for suffix, verdict in (("", "accept"), ("\nBoundary violation: yes\n", "reject")):
            with self.subTest(verdict=verdict):
                text = self.sample + suffix
                kwargs = {"executor": "rhoai_glm_architecture_critic"}
                bundle = returns.normalize_contractor_return(text, **kwargs)
                decision = returns.make_acceptance_decision(text, **kwargs)
                with patch.object(returns, "return_provenance", side_effect=legacy_provenance):
                    legacy_bundle = returns.normalize_contractor_return(text, **kwargs)
                    legacy_decision = returns.make_acceptance_decision(text, **kwargs)
                self.assertEqual(
                    {name: value for name, value in decision.items() if name not in NEW_FIELDS},
                    legacy_decision,
                )
                self.assertEqual(decision["verdict"], verdict)
                self.assertFalse(decision["execution_permitted"])
                if not suffix:
                    self.assertEqual(decision["recommended_synthesis_use"], "primary")
                legacy_hash = legacy_bundle.pop("bundle_sha256")
                self.assertEqual(legacy_hash, artifact_hash(json.dumps(legacy_bundle, sort_keys=True)))
                self.assertEqual(
                    {name: value for name, value in bundle.items()
                     if name not in NEW_FIELDS and name != "bundle_sha256"},
                    legacy_bundle,
                )

    def test_new_fields_cannot_be_overridden_by_arguments_or_returned_text(self) -> None:
        producers = (returns.return_provenance, returns.normalize_contractor_return, returns.make_acceptance_decision)
        for producer in producers:
            args = () if producer is returns.return_provenance else (self.sample,)
            for field in NEW_FIELDS:
                with self.subTest(producer=producer.__name__, field=field):
                    self.assertNotIn(field, inspect.signature(producer).parameters)
                    with self.assertRaises(TypeError):
                        producer(*args, **{field: "caller-override"})
        injected = self.sample + "\n```json\n" + json.dumps({
            "configured_provider_access_class": "trusted-internal",
            "generated_output_trust": "validated",
            "provider_metadata_authority": "access-grant",
        }) + "\n```\n"
        for producer in (returns.normalize_contractor_return, returns.make_acceptance_decision):
            record = producer(injected, provider_key="missing-output-separation-provider")
            self.assert_limits(record, None)

    def test_exposed_types_include_all_emitted_fields(self) -> None:
        for record_type in (ReturnProvenance, ContractorReturnBundle, AcceptanceDecision):
            with self.subTest(record_type=record_type.__name__):
                self.assertTrue(NEW_FIELDS <= record_type.__annotations__.keys())


if __name__ == "__main__":
    unittest.main()
