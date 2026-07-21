from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path

from scripts.cwo_core.native_recovery_policy import (
    PROVISIONAL_ADMISSION_GRADE,
    RECOVERY_CLASS_MATRIX,
    RECOVERY_DECISION_FIELDS,
    RECOVERY_DECISION_SCHEMA,
    RECOVERY_SIGNAL_FIELDS,
    RecoveryPolicyError,
    build_recovery_audit_decision,
    classify_recovery_signals,
    validate_recovery_audit_decision,
)


COHORT_SHA256 = "a" * 64
CHILD_SHA256 = "b" * 64
EVIDENCE_SHA256 = "c" * 64
ROOT = Path(__file__).resolve().parents[1]
HAS_JSONSCHEMA = importlib.util.find_spec("jsonschema") is not None


def signals(*enabled: str) -> dict[str, bool]:
    value = {field: False for field in RECOVERY_SIGNAL_FIELDS}
    for field in enabled:
        value[field] = True
    return value


def decision(
    *enabled: str,
    replacement_count: int = 0,
    construction_attempt_count: int = 0,
) -> dict:
    return build_recovery_audit_decision(
        signals(*enabled),
        replacement_count=replacement_count,
        construction_attempt_count=construction_attempt_count,
        evidence_sha256=EVIDENCE_SHA256,
        fixed_cohort_sha256=COHORT_SHA256,
        admitted_bead_id="bead-fixed-1",
        admitted_child_sha256=CHILD_SHA256,
    )


class NativeRecoveryPolicyTests(unittest.TestCase):
    def test_all_six_classes_match_frozen_initial_matrix(self) -> None:
        cases = {
            "deterministic_construction_failure": (
                "deterministic-construction-failure",
                "reconstruct-same-admitted-bead",
                0,
                "child",
                "verified-project-manager",
            ),
            "pre_dispatch_transport_failure": (
                "pre-dispatch-transport-failure",
                "replace-same-admitted-bead",
                1,
                "child",
                "pm-controller-plus-supervisor-policy",
            ),
            "contained_semantic_no_op": (
                "contained-semantic-no-op",
                "replace-same-admitted-bead",
                1,
                "child",
                "pm-controller-plus-verified-containment",
            ),
            "individual_child_failure": (
                "individual-child-failure",
                "replace-same-admitted-bead",
                1,
                "child",
                "pm-controller-plus-verified-containment",
            ),
            "control_security_failure": (
                "control-security-failure",
                "stop-execution-path",
                0,
                "execution-path",
                "supervisor-policy",
            ),
            "contradictory_authority_changing_validation": (
                "contradictory-authority-changing-validation",
                "await-operator-input",
                0,
                "complete-task",
                "verified-operator-directive",
            ),
        }
        for signal, expected in cases.items():
            with self.subTest(signal=signal):
                result = decision(signal)
                self.assertEqual(
                    (
                        result["recovery_class"],
                        result["action"],
                        result["replacement_budget"],
                        result["stop_scope"],
                        result["required_authority"],
                    ),
                    expected,
                )
                self.assertEqual(
                    RECOVERY_CLASS_MATRIX[result["recovery_class"]]["initial_action"],
                    result["action"],
                )
                self.assertFalse(result["dispatch_authorized"])
                self.assertFalse(result["newly_ready_refill_allowed"])
                self.assertTrue(result["fixed_cohort_required"])
                self.assertEqual(result["admission_grade"], PROVISIONAL_ADMISSION_GRADE)
                self.assertEqual(validate_recovery_audit_decision(result), [])

    def test_recovery_class_matrix_is_deeply_immutable(self) -> None:
        with self.assertRaises(TypeError):
            RECOVERY_CLASS_MATRIX["control-security-failure"] = {}  # type: ignore[index]
        with self.assertRaises(TypeError):
            RECOVERY_CLASS_MATRIX["control-security-failure"][
                "initial_action"
            ] = "replace-same-admitted-bead"  # type: ignore[index]

        protected = decision(
            "failed_ambiguous_dispatch",
            "individual_child_failure",
        )
        self.assertEqual(protected["action"], "stop-execution-path")
        self.assertEqual(protected["stop_scope"], "execution-path")
        self.assertEqual(protected["required_authority"], "supervisor-policy")
        self.assertEqual(validate_recovery_audit_decision(protected), [])

    def test_replaceable_classes_use_exhausted_action_after_one_replacement(self) -> None:
        for signal in (
            "pre_dispatch_transport_failure",
            "contained_semantic_no_op",
            "individual_child_failure",
        ):
            with self.subTest(signal=signal):
                result = decision(signal, replacement_count=1)
                self.assertEqual(
                    result["action"], "return-same-admitted-bead-to-main-thread"
                )
                self.assertEqual(result["replacements_remaining"], 0)
                self.assertEqual(validate_recovery_audit_decision(result), [])

    def test_global_replacement_count_does_not_mask_a_later_protected_stop(self) -> None:
        for signal, expected_action in (
            ("control_security_failure", "stop-execution-path"),
            ("failed_ambiguous_dispatch", "stop-execution-path"),
            (
                "contradictory_authority_changing_validation",
                "await-operator-input",
            ),
        ):
            with self.subTest(signal=signal):
                result = decision(signal, replacement_count=1)
                self.assertEqual(result["action"], expected_action)
                self.assertEqual(result["replacements_remaining"], 0)
                self.assertEqual(validate_recovery_audit_decision(result), [])

    def test_construction_after_a_replacement_returns_same_bead_to_main_thread(self) -> None:
        result = decision(
            "deterministic_construction_failure", replacement_count=1
        )
        self.assertEqual(
            result["action"], "return-same-admitted-bead-to-main-thread"
        )
        self.assertEqual(result["replacements_remaining"], 0)

    def test_construction_attempt_is_independently_bounded(self) -> None:
        first = decision("deterministic_construction_failure")
        self.assertEqual(first["action"], "reconstruct-same-admitted-bead")
        self.assertEqual(first["construction_attempts_remaining"], 1)

        exhausted = decision(
            "deterministic_construction_failure",
            construction_attempt_count=1,
        )
        self.assertEqual(
            exhausted["action"], "return-same-admitted-bead-to-main-thread"
        )
        self.assertEqual(exhausted["construction_attempts_remaining"], 0)
        self.assertEqual(exhausted["replacement_count"], 0)

    def test_signal_key_order_does_not_change_decision_or_seal(self) -> None:
        ordered = signals("individual_child_failure", "contained_semantic_no_op")
        reversed_order = dict(reversed(list(ordered.items())))
        first = build_recovery_audit_decision(
            ordered,
            replacement_count=0,
            construction_attempt_count=0,
            evidence_sha256=EVIDENCE_SHA256,
            fixed_cohort_sha256=COHORT_SHA256,
            admitted_bead_id="bead-fixed-1",
            admitted_child_sha256=CHILD_SHA256,
        )
        second = build_recovery_audit_decision(
            reversed_order,
            replacement_count=0,
            construction_attempt_count=0,
            evidence_sha256=EVIDENCE_SHA256,
            fixed_cohort_sha256=COHORT_SHA256,
            admitted_bead_id="bead-fixed-1",
            admitted_child_sha256=CHILD_SHA256,
        )
        self.assertEqual(first, second)
        self.assertEqual(first["decision_sha256"], second["decision_sha256"])

    def test_exact_source_evidence_changes_decision_binding(self) -> None:
        first = decision("contained_semantic_no_op")
        second = build_recovery_audit_decision(
            signals("contained_semantic_no_op"),
            replacement_count=0,
            construction_attempt_count=0,
            evidence_sha256="d" * 64,
            fixed_cohort_sha256=COHORT_SHA256,
            admitted_bead_id="bead-fixed-1",
            admitted_child_sha256=CHILD_SHA256,
        )
        self.assertEqual(
            first["classification_evidence_sha256"],
            second["classification_evidence_sha256"],
        )
        self.assertNotEqual(first["evidence_sha256"], second["evidence_sha256"])
        self.assertNotEqual(first["decision_sha256"], second["decision_sha256"])

    def test_mixed_signal_precedence_is_highest_first(self) -> None:
        all_signals = signals(*RECOVERY_SIGNAL_FIELDS)
        self.assertEqual(
            classify_recovery_signals(all_signals),
            "contradictory-authority-changing-validation",
        )
        all_signals["contradictory_authority_changing_validation"] = False
        self.assertEqual(
            classify_recovery_signals(all_signals), "control-security-failure"
        )
        all_signals["failed_ambiguous_dispatch"] = False
        all_signals["control_security_failure"] = False
        self.assertEqual(
            classify_recovery_signals(all_signals), "individual-child-failure"
        )

    def test_failed_ambiguous_dominates_every_replaceable_or_reconstruct_signal(self) -> None:
        result = decision(
            "failed_ambiguous_dispatch",
            "individual_child_failure",
            "contained_semantic_no_op",
            "pre_dispatch_transport_failure",
            "deterministic_construction_failure",
        )
        self.assertEqual(result["recovery_class"], "control-security-failure")
        self.assertEqual(result["action"], "stop-execution-path")
        self.assertEqual(result["replacement_budget"], 0)
        self.assertFalse(result["dispatch_authorized"])

    def test_signal_shape_and_types_are_strict(self) -> None:
        malformed = [
            None,
            [],
            {field: False for field in RECOVERY_SIGNAL_FIELDS},
            {k: v for k, v in signals("control_security_failure").items() if k != "control_security_failure"},
            {**signals("control_security_failure"), "free_text_choice": True},
            {**signals("control_security_failure"), "control_security_failure": 1},
            {**signals("control_security_failure"), "control_security_failure": None},
        ]
        for value in malformed:
            with self.subTest(value=value):
                with self.assertRaises(RecoveryPolicyError):
                    classify_recovery_signals(value)

    def test_impossible_replacement_counts_fail_closed(self) -> None:
        for count in (-1, 2, True, 1.0, "1", None):
            with self.subTest(count=count):
                with self.assertRaises(RecoveryPolicyError):
                    decision("individual_child_failure", replacement_count=count)  # type: ignore[arg-type]

    def test_impossible_construction_attempt_counts_fail_closed(self) -> None:
        for count in (-1, 2, True, 1.0, "1", None):
            with self.subTest(count=count):
                with self.assertRaises(RecoveryPolicyError):
                    decision(
                        "deterministic_construction_failure",
                        construction_attempt_count=count,  # type: ignore[arg-type]
                    )

    def test_decision_contract_is_exact_and_hash_sealed(self) -> None:
        result = decision("contained_semantic_no_op")
        self.assertEqual(set(result), RECOVERY_DECISION_FIELDS)
        self.assertEqual(result["schema"], RECOVERY_DECISION_SCHEMA)
        for field, replacement in (
            ("action", "reconstruct-same-admitted-bead"),
            ("evidence_sha256", "d" * 64),
            ("classification_evidence_sha256", "e" * 64),
            ("fixed_cohort_sha256", "f" * 64),
            ("dispatch_authorized", True),
            ("newly_ready_refill_allowed", True),
            ("fixed_cohort_required", False),
            ("decision_sha256", "d" * 64),
        ):
            with self.subTest(field=field):
                tampered = copy.deepcopy(result)
                tampered[field] = replacement
                self.assertEqual(
                    validate_recovery_audit_decision(tampered),
                    ["recovery-decision-mismatch"],
                )
        unknown = copy.deepcopy(result)
        unknown["recommendation"] = "replace another ready issue"
        self.assertEqual(
            validate_recovery_audit_decision(unknown),
            ["recovery-decision-fields-invalid"],
        )

    def test_decision_validation_rejects_bool_integer_type_aliases(self) -> None:
        result = decision("contained_semantic_no_op")
        for field, replacement in (
            ("version", True),
            ("replacement_budget", True),
            ("replacement_count", False),
            ("replacements_remaining", True),
            ("construction_attempt_budget", False),
            ("construction_attempt_count", False),
            ("construction_attempts_remaining", False),
            ("dispatch_authorized", 0),
            ("newly_ready_refill_allowed", 0),
            ("fixed_cohort_required", 1),
        ):
            with self.subTest(field=field):
                tampered = copy.deepcopy(result)
                tampered[field] = replacement
                self.assertTrue(validate_recovery_audit_decision(tampered))

        class DictSubclass(dict):
            pass

        self.assertEqual(
            validate_recovery_audit_decision(DictSubclass(result)),
            ["recovery-decision-must-be-object"],
        )

    @unittest.skipUnless(HAS_JSONSCHEMA, "jsonschema is not installed")
    def test_decision_matches_strict_json_schema(self) -> None:
        import jsonschema

        schema = json.loads(
            (ROOT / "schemas/native-recovery-decision.schema.json").read_text(
                encoding="utf-8"
            )
        )
        for signal in RECOVERY_SIGNAL_FIELDS:
            with self.subTest(signal=signal):
                jsonschema.validate(decision(signal), schema)

        jsonschema.validate(
            decision(
                "deterministic_construction_failure",
                construction_attempt_count=1,
            ),
            schema,
        )
        jsonschema.validate(
            decision("control_security_failure", replacement_count=1),
            schema,
        )

    @unittest.skipUnless(HAS_JSONSCHEMA, "jsonschema is not installed")
    def test_schema_rejects_impossible_matrix_and_precedence_combinations(self) -> None:
        import jsonschema

        schema = json.loads(
            (ROOT / "schemas/native-recovery-decision.schema.json").read_text(
                encoding="utf-8"
            )
        )
        protected = decision("control_security_failure")
        for field, replacement in (
            ("action", "replace-same-admitted-bead"),
            ("recovery_class", "individual-child-failure"),
            ("replacement_budget", 1),
            ("replacements_remaining", 1),
            ("stop_scope", "child"),
            ("required_authority", "verified-project-manager"),
        ):
            with self.subTest(field=field):
                tampered = copy.deepcopy(protected)
                tampered[field] = replacement
                with self.assertRaises(jsonschema.ValidationError):
                    jsonschema.validate(tampered, schema)

        ambiguous = decision(
            "failed_ambiguous_dispatch",
            "individual_child_failure",
        )
        ambiguous.update(
            {
                "recovery_class": "individual-child-failure",
                "action": "replace-same-admitted-bead",
                "replacement_budget": 1,
                "replacements_remaining": 1,
                "stop_scope": "child",
                "required_authority": "pm-controller-plus-verified-containment",
            }
        )
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(ambiguous, schema)


if __name__ == "__main__":
    unittest.main()
