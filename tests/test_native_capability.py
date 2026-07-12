from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

import cwo_core.native_capability as native_capability


SCHEMA_PATH = ROOT / "schemas" / "native-model-capability-receipt.schema.json"


def _base_evidence(overrides: dict | None = None) -> dict:
    evidence = {
        "requested_model": "gpt-4o-native",
        "configured_model": "gpt-4o-native",
        "advertised": False,
        "advertised_models": ["gpt-4o-native"],
        "spawn_accepted": True,
        "canary_session_id": "canary-session-1",
        "attestation_source": "trusted-session-jsonl",
        "attested_model": "gpt-4o-native",
        "tool_calls": 0,
        "context_compactions": 0,
        "runtime_seconds": 7.25,
        "closure_receipt": True,
        "tool_surface_id": "spark-registry",
    }
    if overrides:
        evidence.update(overrides)
    return evidence


def _build_receipt(evidence: dict, authorized_models: list[str] | None = None) -> dict:
    if authorized_models is None:
        authorized_models = ["gpt-4o-native"]
    builder = getattr(native_capability, "build_capability_receipt", None)
    if builder is None:
        builder = native_capability.build_native_capability_receipt
    return builder(
        evidence,
        authorized_models,
        issued_at="2026-01-01T12:00:00+00:00",
        expires_at="2026-01-02T12:00:00+00:00",
    )


def _validate_receipt(receipt: dict) -> list[str]:
    validator = getattr(native_capability, "validate_capability_receipt", None)
    if validator is None:
        validator = native_capability.validate_native_capability_receipt
    return validator(receipt)


def _load_schema() -> dict:
    with SCHEMA_PATH.open("r", encoding="utf-8") as fp:
        return json.load(fp)


class NativeCapabilityTests(unittest.TestCase):
    def test_record_cli_builds_and_validates_without_spawn_authority(self) -> None:
        script = ROOT / "scripts" / "record_native_model_capability.py"
        with tempfile.TemporaryDirectory() as raw:
            temp = Path(raw)
            evidence_path = temp / "evidence.json"
            receipt_path = temp / "receipt.json"
            evidence_path.write_text(json.dumps(_base_evidence()), encoding="utf-8")
            built = subprocess.run(
                [sys.executable, str(script), "build", "--evidence", str(evidence_path), "--authorized-model", "gpt-4o-native", "--issued-at", "2026-01-01T12:00:00+00:00", "--expires-at", "2026-01-02T12:00:00+00:00", "--output", str(receipt_path)],
                cwd=ROOT, text=True, capture_output=True, check=False,
            )
            self.assertEqual(built.returncode, 0, built.stderr + built.stdout)
            self.assertTrue(receipt_path.is_file())
            self.assertEqual(_validate_receipt(json.loads(receipt_path.read_text(encoding="utf-8"))), [])
            validated = subprocess.run(
                [sys.executable, str(script), "validate", "--receipt", str(receipt_path)],
                cwd=ROOT, text=True, capture_output=True, check=False,
            )
            self.assertEqual(validated.returncode, 0, validated.stderr + validated.stdout)
            self.assertEqual(json.loads(validated.stdout)["status"], "valid")
            self.assertNotIn("spawn_agent", script.read_text(encoding="utf-8"))

    def test_record_cli_rejects_tampered_receipt(self) -> None:
        script = ROOT / "scripts" / "record_native_model_capability.py"
        with tempfile.TemporaryDirectory() as raw:
            receipt_path = Path(raw) / "tampered.json"
            receipt = _build_receipt(_base_evidence())
            receipt["attested_model"] = "other-model"
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(script), "validate", "--receipt", str(receipt_path)],
                cwd=ROOT, text=True, capture_output=True, check=False,
            )
            self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
            self.assertEqual(json.loads(result.stdout)["status"], "invalid")
    def test_frozen_public_function_names_and_constants_exist(self) -> None:
        self.assertTrue(callable(getattr(native_capability, "evaluate_native_capability", None)))
        self.assertTrue(callable(getattr(native_capability, "build_capability_receipt", None)))
        self.assertTrue(callable(getattr(native_capability, "validate_capability_receipt", None)))
        self.assertTrue(callable(getattr(native_capability, "capability_receipt_applies", None)))
        self.assertEqual(getattr(native_capability, "CAPABILITY_RECEIPT_TYPE", None), "cwo-native-model-capability-receipt")
        self.assertEqual(getattr(native_capability, "CAPABILITY_RECEIPT_VERSION", None), 1)

    def test_advertised_false_direct_spawn_true_trusted_attestation_zero_usage_dispatches(self) -> None:
        evidence = _base_evidence()
        result = native_capability.evaluate_native_capability(evidence, ["gpt-4o-native"])
        self.assertEqual(result["outcome"], "native-capability-confirmed")
        self.assertEqual(result["reasons"], ["native-capability-confirmed"])
        self.assertFalse(result["canary_required"])
        self.assertTrue(result["states"]["dispatchable"])
        self.assertFalse(result["states"]["advertised"])
        self.assertTrue(result["states"]["spawn_accepted"])
        self.assertTrue(result["states"]["attested"])

    def test_advertisement_mismatch_without_spawn_direct_evidence(self) -> None:
        evidence = _base_evidence({"spawn_accepted": None})
        result = native_capability.evaluate_native_capability(evidence, ["gpt-4o-native"])
        self.assertEqual(result["outcome"], "advertisement-mismatch")
        self.assertEqual(result["reasons"], ["advertisement-mismatch"])
        self.assertTrue(result["canary_required"])

    def test_evaluate_spawn_rejection(self) -> None:
        evidence = _base_evidence({"spawn_accepted": False})
        result = native_capability.evaluate_native_capability(evidence, ["gpt-4o-native"])
        self.assertEqual(result["outcome"], "native-spawn-rejected")
        self.assertEqual(result["reasons"], ["native-spawn-rejected"])
        self.assertFalse(result["states"]["dispatchable"])

    def test_evaluate_attestation_mismatch(self) -> None:
        evidence = _base_evidence({"attested_model": "other-model"})
        result = native_capability.evaluate_native_capability(evidence, ["gpt-4o-native"])
        self.assertEqual(result["outcome"], "native-attestation-mismatch")
        self.assertEqual(result["reasons"], ["native-attestation-mismatch"])
        self.assertFalse(result["states"]["attested"])
        self.assertFalse(result["states"]["dispatchable"])

    def test_evaluate_tool_use_and_compaction(self) -> None:
        result = native_capability.evaluate_native_capability(_base_evidence({"tool_calls": 1}), ["gpt-4o-native"])
        self.assertEqual(result["outcome"], "canary-tool-use")
        self.assertEqual(result["reasons"], ["canary-tool-use"])
        self.assertFalse(result["states"]["dispatchable"])
        self.assertFalse(result["canary_required"])

        result = native_capability.evaluate_native_capability(_base_evidence({"context_compactions": 3}), ["gpt-4o-native"])
        self.assertEqual(result["outcome"], "canary-compaction")
        self.assertEqual(result["reasons"], ["canary-compaction"])
        self.assertFalse(result["canary_required"])

    def test_evaluate_missing_or_invalid_required_fields(self) -> None:
        missing_authorized_model = native_capability.evaluate_native_capability(_base_evidence(), ["gpt-4o-other"])
        self.assertEqual(missing_authorized_model["outcome"], "unauthorized-model")
        self.assertEqual(missing_authorized_model["reasons"], ["unauthorized-model"])

        misconfigured = native_capability.evaluate_native_capability(
            _base_evidence({"configured_model": "other-native"}),
            ["gpt-4o-native"],
        )
        self.assertEqual(misconfigured["outcome"], "unauthorized-model")
        self.assertEqual(misconfigured["reasons"], ["unauthorized-model"])

        runtime_bad = native_capability.evaluate_native_capability(
            _base_evidence({"runtime_seconds": "fast"}),
            ["gpt-4o-native"],
        )
        self.assertEqual(runtime_bad["outcome"], "unavailable-trusted-telemetry")
        self.assertEqual(runtime_bad["reasons"], ["unavailable-trusted-telemetry"])

        source_bad = native_capability.evaluate_native_capability(
            _base_evidence({"attestation_source": "untrusted"}),
            ["gpt-4o-native"],
        )
        self.assertEqual(source_bad["outcome"], "unavailable-trusted-telemetry")
        self.assertEqual(source_bad["reasons"], ["unavailable-trusted-telemetry"])

        surface_bad = native_capability.evaluate_native_capability(
            _base_evidence({"tool_surface_id": 1}),
            ["gpt-4o-native"],
        )
        self.assertEqual(surface_bad["outcome"], "unavailable-trusted-telemetry")
        self.assertEqual(surface_bad["reasons"], ["unavailable-trusted-telemetry"])

    def test_evaluate_misconfigured_closure(self) -> None:
        evidence = _base_evidence({"closure_receipt": False})
        result = native_capability.evaluate_native_capability(evidence, ["gpt-4o-native"])
        self.assertEqual(result["outcome"], "missing-closure")
        self.assertEqual(result["reasons"], ["missing-closure"])

    def test_authorized_models_string_is_rejected(self) -> None:
        evidence = _base_evidence({"requested_model": "x", "configured_model": "x", "attested_model": "x"})
        result = native_capability.evaluate_native_capability(evidence, "x")
        self.assertEqual(result["outcome"], "unauthorized-model")
        self.assertEqual(result["reasons"], ["unauthorized-model"])

    def test_validate_rejects_bool_and_wrong_types_for_critical_fields(self) -> None:
        receipt = _build_receipt(_base_evidence())
        bad_bool = copy.deepcopy(receipt)
        bad_bool["advertised"] = 1
        self.assertIn("invalid-advertised", _validate_receipt(bad_bool))

        bad_bool_models = copy.deepcopy(receipt)
        bad_bool_models["advertised_models"] = "gpt-4o-native"
        self.assertIn("invalid-advertised-models", _validate_receipt(bad_bool_models))

        bad_tool_calls = copy.deepcopy(receipt)
        bad_tool_calls["tool_calls"] = True
        self.assertIn("invalid-tool-calls", _validate_receipt(bad_tool_calls))

        bad_compactions = copy.deepcopy(receipt)
        bad_compactions["context_compactions"] = True
        self.assertIn("invalid-context-compactions", _validate_receipt(bad_compactions))

        bad_runtime = copy.deepcopy(receipt)
        bad_runtime["runtime_seconds"] = False
        self.assertIn("invalid-runtime-seconds", _validate_receipt(bad_runtime))

    def test_validate_rejects_authorized_model_string_for_build(self) -> None:
        evidence = _base_evidence({"requested_model": "gpt-4o-native", "attested_model": "gpt-4o-native"})
        builder = getattr(native_capability, "build_capability_receipt", None)
        if builder is None:
            builder = native_capability.build_native_capability_receipt
        with self.assertRaises(ValueError):
            builder(evidence, "gpt-4o-native")

    def test_build_receipt_no_mutation_and_strict_fields(self) -> None:
        evidence = _base_evidence()
        evidence_before = copy.deepcopy(evidence)
        receipt = _build_receipt(evidence)
        self.assertEqual(evidence, evidence_before)

        required_fields = {
            "receipt_type",
            "version",
            "requested_model",
            "configured_model",
            "advertised",
            "advertised_models",
            "spawn_accepted",
            "canary_session_id",
            "attestation_source",
            "attested_model",
            "tool_calls",
            "context_compactions",
            "runtime_seconds",
            "closure_receipt",
            "tool_surface_id",
            "decision",
            "authority",
            "issued_at",
            "expires_at",
            "receipt_sha256",
        }
        self.assertEqual(set(receipt.keys()), required_fields)
        self.assertEqual(receipt["receipt_type"], native_capability.CAPABILITY_RECEIPT_TYPE)
        self.assertEqual(receipt["version"], native_capability.CAPABILITY_RECEIPT_VERSION)
        self.assertEqual(receipt["requested_model"], evidence["requested_model"])
        self.assertEqual(receipt["configured_model"], evidence["configured_model"])
        self.assertEqual(receipt["canary_session_id"], evidence["canary_session_id"])
        self.assertTrue(receipt["closure_receipt"])
        self.assertIsInstance(receipt["runtime_seconds"], float)
        self.assertEqual(receipt["tool_calls"], 0)
        self.assertEqual(receipt["context_compactions"], 0)
        self.assertEqual(len(receipt["receipt_sha256"]), 64)
        self.assertEqual(_validate_receipt(receipt), [])

    def test_build_receipt_datetime_validation(self) -> None:
        evidence = _base_evidence({"advertised": True})
        builder = getattr(native_capability, "build_capability_receipt", None)
        if builder is None:
            builder = native_capability.build_native_capability_receipt
        with self.assertRaises(ValueError):
            builder(
                evidence,
                ["gpt-4o-native"],
                issued_at="2026-01-01T12:00:00",
                expires_at="2026-01-02T12:00:00",
            )
        with self.assertRaises(ValueError):
            builder(
                evidence,
                ["gpt-4o-native"],
                issued_at="2026-01-02T12:00:00+00:00",
                expires_at="2026-01-01T12:00:00+00:00",
            )

    def test_receipt_tampering_detects_hash_failure(self) -> None:
        base = _build_receipt(_base_evidence({"advertised": True}))
        tamper_cases = (
            ("requested_model", "x-model"),
            ("configured_model", "x-model"),
            ("attestation_source", "other-trusted-source"),
            ("attested_model", "other-model"),
            ("tool_calls", 2),
            ("context_compactions", 2),
            ("runtime_seconds", 9.5),
            ("closure_receipt", False),
            ("tool_surface_id", "other-surface"),
            ("issued_at", "2026-01-01T13:00:00+00:00"),
            ("expires_at", "2026-01-02T13:00:00+00:00"),
            ("receipt_sha256", "0" * 64),
        )
        for key, value in tamper_cases:
            tampered = copy.deepcopy(base)
            tampered[key] = value
            self.assertIn("invalid-receipt-sha256", _validate_receipt(tampered), key)

    def test_apply_exact_model_surface_and_time_bounds(self) -> None:
        receipt = _build_receipt(_base_evidence({"advertised": True}))

        self.assertTrue(
            native_capability.capability_receipt_applies(
                receipt, "gpt-4o-native", "spark-registry", "2026-01-01T13:00:00+00:00"
            )
        )
        self.assertTrue(
            native_capability.capability_receipt_applies(
                receipt, "gpt-4o-native", "spark-registry", "2026-01-01T12:00:00+00:00"
            )
        )

        self.assertFalse(
            native_capability.capability_receipt_applies(
                receipt, "gpt-4o-native", "spark-registry", "2026-01-02T12:00:00+00:00"
            )
        )
        self.assertFalse(
            native_capability.capability_receipt_applies(
                receipt, "gpt-4o-native", "spark-registry", "2026-01-01T11:59:59+00:00"
            )
        )
        self.assertFalse(
            native_capability.capability_receipt_applies(
                receipt, "gpt-4o-mini", "spark-registry", "2026-01-01T13:00:00+00:00"
            )
        )
        self.assertFalse(
            native_capability.capability_receipt_applies(
                receipt, "gpt-4o-native", "tooling", "2026-01-01T13:00:00+00:00"
            )
        )
        self.assertFalse(
            native_capability.capability_receipt_applies(
                receipt, "gpt-4o-native", "spark-registry", "2026-01-01T13:00:00"
            )
        )

    def test_receipt_schema_loads_and_matches_contract(self) -> None:
        schema = _load_schema()
        self.assertEqual(schema["type"], "object")
        self.assertEqual(schema.get("additionalProperties"), False)
        self.assertEqual(len(schema["required"]), 20)
        self.assertEqual(len(schema["properties"]), 20)

        expected_required = {
            "receipt_type",
            "version",
            "requested_model",
            "configured_model",
            "advertised",
            "advertised_models",
            "spawn_accepted",
            "canary_session_id",
            "attestation_source",
            "attested_model",
            "tool_calls",
            "context_compactions",
            "runtime_seconds",
            "closure_receipt",
            "tool_surface_id",
            "decision",
            "authority",
            "issued_at",
            "expires_at",
            "receipt_sha256",
        }
        self.assertEqual(set(schema["required"]), expected_required)
        self.assertEqual(set(schema["properties"]), expected_required)

        self.assertEqual(schema["properties"]["receipt_type"]["const"], native_capability.CAPABILITY_RECEIPT_TYPE)
        self.assertEqual(schema["properties"]["version"]["const"], native_capability.CAPABILITY_RECEIPT_VERSION)
        self.assertEqual(schema["properties"]["advertised"]["type"], "boolean")
        self.assertEqual(schema["properties"]["advertised_models"]["type"], "array")
        self.assertEqual(schema["properties"]["advertised_models"]["uniqueItems"], True)
        self.assertEqual(schema["properties"]["advertised_models"]["items"]["type"], "string")
        self.assertGreaterEqual(schema["properties"]["advertised_models"]["items"]["minLength"], 1)
        self.assertEqual(schema["properties"]["spawn_accepted"]["const"], True)
        self.assertEqual(schema["properties"]["canary_session_id"]["type"], "string")
        self.assertEqual(schema["properties"]["canary_session_id"]["minLength"], 1)
        self.assertEqual(schema["properties"]["attestation_source"]["const"], "trusted-session-jsonl")
        self.assertEqual(schema["properties"]["attested_model"]["type"], "string")
        self.assertEqual(schema["properties"]["tool_calls"]["const"], 0)
        self.assertEqual(schema["properties"]["context_compactions"]["const"], 0)
        self.assertEqual(schema["properties"]["runtime_seconds"]["type"], "number")
        self.assertEqual(schema["properties"]["runtime_seconds"]["minimum"], 0)
        self.assertEqual(schema["properties"]["closure_receipt"]["const"], True)
        self.assertEqual(schema["properties"]["tool_surface_id"]["type"], "string")
        self.assertEqual(schema["properties"]["tool_surface_id"]["minLength"], 1)
        self.assertEqual(schema["properties"]["decision"]["const"], "native-capability-confirmed")
        self.assertEqual(schema["properties"]["authority"]["const"], "trusted-session-jsonl")
        self.assertEqual(schema["properties"]["issued_at"]["type"], "string")
        self.assertEqual(schema["properties"]["issued_at"]["format"], "date-time")
        self.assertEqual(schema["properties"]["expires_at"]["type"], "string")
        self.assertEqual(schema["properties"]["expires_at"]["format"], "date-time")
        self.assertEqual(schema["properties"]["receipt_sha256"]["type"], "string")
        self.assertEqual(schema["properties"]["receipt_sha256"]["pattern"], "^[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
