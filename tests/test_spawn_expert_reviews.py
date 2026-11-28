from __future__ import annotations

import sys
from unittest.mock import patch
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.routing import (  # noqa: E402
    classify_work,
    expert_review_labels,
    expert_review_metadata,
)
from spawn_expert_reviews import control_review_tasks, review_fields  # noqa: E402


class SpawnExpertReviewsTests(unittest.TestCase):
    def assert_native_fields(self, item: dict[str, object]) -> None:
        self.assertTrue(item.get("skills"))
        self.assertTrue(item.get("acceptance"))
        self.assertTrue(item.get("design"))
        self.assertTrue(item.get("notes"))

    def test_expert_review_fields_include_native_beads_contract(self) -> None:
        route = classify_work(
            "Security and documentation review for public contractor packet behavior.",
            requested_roles=["security", "documentation"],
        )
        expert = route["ranked_experts"][0]
        fields = review_fields(expert, route)
        self.assert_native_fields(fields)
        self.assertIn(expert["job_description_label"], fields["skills"])
        self.assertIn("Review is complete", fields["acceptance"])

    def test_spawn_and_direct_scaffold_write_the_same_review_body(self) -> None:
        import scaffold_workgraph
        import spawn_expert_reviews

        title = "Prepare public documentation and GitHub Pages."
        task = title + "\nReview input [target audience]: First-time queue operators"
        editor = "contract-jd-editorial-reasoning"
        bodies = []
        for cli, argv in (
            (spawn_expert_reviews, [task, "--top-n", "8"]),
            (scaffold_workgraph, ["--title", title, "--description", task]),
        ):
            with patch.object(sys, "argv", [cli.__file__, *argv]), \
                    patch.object(cli, "bind_project_beads"), \
                    patch.object(cli, "create_bead", return_value={"id": "bd-test", "title": "review"}) as create, \
                    patch.object(scaffold_workgraph, "try_dep"), patch("builtins.print"):
                cli.main()
            fields = next(call.kwargs for call in create.call_args_list if editor in call.kwargs["labels"])
            self.assertEqual(fields["metadata"]["persona_file"], "experts/editor.md")
            self.assertEqual(fields["metadata"]["review_input_status"], "blocked")
            self.assertIn("First-time queue operators", fields["description"])
            self.assertIn("docs and pages flow together", fields["acceptance"])
            bodies.append(fields["description"])
        self.assertEqual(bodies[0], bodies[1])

    def test_provider_conflict_adds_peer_and_sabotage_control_reviews(self) -> None:
        route = classify_work(
            "Claude Opus contractor return for model provider sabotage review.",
            external_ok=True,
            share_boundary="redacted-packet",
            requested_roles=["security"],
        )
        tasks = control_review_tasks("Expert review", route)
        labels = [set(task["labels"]) for task in tasks]
        self.assertTrue(any("contract-jd-peer-review" in item for item in labels))
        self.assertTrue(any("contract-jd-sabotage-review" in item for item in labels))
        self.assertTrue(all(task["metadata"]["codex_pickup"] == "forbidden" for task in tasks))
        sabotage = next(task for task in tasks if "contract-jd-sabotage-review" in task["labels"])
        self.assertIn("provider-conflict", sabotage["metadata"]["control_review_triggers"])
        self.assertEqual(sabotage["metadata"]["authority"], "advisory-evidence-only")
        self.assertIn("advisory evidence only", sabotage["description"])
        self.assertIn("architect adjudication remains final", sabotage["description"])
        for task in tasks:
            self.assert_native_fields(task)

    def test_work_rerouting_adds_sabotage_control_review_without_provider_conflict(self) -> None:
        route = classify_work(
            "Evaluate a contractor return for work_rerouting_or_subversion and objective dilution.",
            share_boundary="redacted-packet",
        )
        self.assertTrue(route["sabotage_review_required"])
        self.assertFalse(route["provider_conflict_detected"])

        tasks = control_review_tasks("Expert review", route)
        labels = [set(task["labels"]) for task in tasks]
        self.assertTrue(any("contract-jd-sabotage-review" in item for item in labels))
        self.assertTrue(all(task["metadata"]["codex_pickup"] == "forbidden" for task in tasks))
        sabotage = next(task for task in tasks if "contract-jd-sabotage-review" in task["labels"])
        self.assertEqual(sabotage["metadata"]["control_review_triggers"], ["work-rerouting-or-subversion"])
        self.assertEqual(sabotage["metadata"]["authority"], "advisory-evidence-only")

    def test_editor_review_fields_include_gate_contract(self) -> None:
        route = classify_work(
            "Create documentation plus GitHub Pages for a project using Diataxis and Red Hat UX.",
            file_paths=["docs/index.html", "README.md"],
        )
        editor = next(expert for expert in route["ranked_experts"] if expert["name"] == "editor")
        fields = review_fields(editor, route)
        labels = expert_review_labels(editor, route)
        metadata = expert_review_metadata(editor, route)

        self.assert_native_fields(fields)
        self.assertIn("contract-jd-editorial-reasoning", fields["skills"])
        self.assertIn("contract-jd-editorial-reasoning", labels)
        self.assertIn("pre-release", labels)
        self.assertIn("docs and pages flow together", fields["acceptance"])
        self.assertTrue(metadata["validation_gate_required"])
        self.assertEqual(metadata["gate_scope"], "public-docs-pages")


if __name__ == "__main__":
    unittest.main()
