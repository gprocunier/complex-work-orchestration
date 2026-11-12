from __future__ import annotations

import contextlib
import copy
import io
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import cwo_core.beads as beads  # noqa: E402
import scaffold_workgraph as graph  # noqa: E402


MAIN_OPTIONS = (
    (),
    ("--dry-run",),
    ("--dry-run", "--format", "cwo"),
    ("--dry-run", "--format", "beads-graph"),
    ("--dry-run", "--format", "markdown-workgraph"),
)


def example_item(lane: str, dependencies: list[object] | None = None) -> dict[str, object]:
    return {
        "title": f"EXAMPLE reliable work {lane}",
        "type": "task",
        "lane": lane,
        "labels": ["EXAMPLE_RELIABILITY"],
        "skills": ["EXAMPLE_VALIDATION"],
        "depends_on_lanes": list(dependencies or []),
        "acceptance": "EXAMPLE reliable result.",
        "design": "EXAMPLE bounded maintenance.",
        "notes": "EXAMPLE checks remain required.",
        "metadata": {"example_record": "EXAMPLE_CONTEXT"},
    }


def example_plan() -> list[dict[str, object]]:
    epic = example_item("EXAMPLE_EPIC")
    epic.pop("lane")
    epic["type"] = "epic"
    return [
        epic,
        example_item("EXAMPLE_FIRST", ["EXAMPLE_LAST"]),
        example_item("EXAMPLE_LAST"),
    ]


def observed_main(
    plan: object, options: tuple[str, ...] = (), *, dependency_error: Exception | None = None
):
    writes = []
    links = []
    output_text = io.StringIO()
    error_text = io.StringIO()
    failure = None

    def create(title: str, **fields: object) -> dict[str, str]:
        identifier = f"EXAMPLE_NODE_{len(writes):04d}"
        writes.append((identifier, title, fields))
        return {"id": identifier, "title": title}

    def link(blocked: str, blocker: str, *, dependency_type: str = "blocks") -> None:
        links.append((blocked, blocker, dependency_type))
        if dependency_error is not None:
            raise dependency_error

    with contextlib.ExitStack() as stack:
        stack.enter_context(patch.object(graph, "classify_work", return_value={}))
        stack.enter_context(patch.object(graph, "prompt_coach_level", return_value="EXAMPLE_LEVEL"))
        stack.enter_context(patch.object(graph, "prompt_coach_parallel_workerbee_signal", return_value={}))
        stack.enter_context(patch.object(graph, "planned_graph", return_value=plan))
        stack.enter_context(patch.object(graph, "create_bead", side_effect=create))
        stack.enter_context(patch.object(graph, "add_dependency", side_effect=link))
        stack.enter_context(patch.object(sys, "argv", ["scaffold_workgraph.py", "--title", "EXAMPLE_GRAPH", *options]))
        stack.enter_context(contextlib.redirect_stdout(output_text))
        stack.enter_context(contextlib.redirect_stderr(error_text))
        try:
            graph.main()
        except SystemExit as exc:
            failure = exc
    return failure, output_text.getvalue(), error_text.getvalue(), writes, links


class ExampleNonJsonValue:
    def __str__(self) -> str:
        return "EXAMPLE_NON_JSON_VALUE"


class CountingOutput(io.StringIO):
    def __init__(self) -> None:
        super().__init__()
        self.characters = 0
        self.trailing_newline = False

    def write(self, value: str) -> int:
        self.characters += len(value)
        self.trailing_newline = value.endswith("\n") if value else self.trailing_newline
        return len(value)


def observed_render(plan: object, options: tuple[str, ...], stream: io.StringIO):
    errors = io.StringIO()
    failure = None
    with contextlib.ExitStack() as stack:
        stack.enter_context(patch.object(graph, "classify_work", return_value={}))
        stack.enter_context(patch.object(graph, "prompt_coach_level", return_value="EXAMPLE_LEVEL"))
        stack.enter_context(patch.object(graph, "prompt_coach_parallel_workerbee_signal", return_value={}))
        stack.enter_context(patch.object(graph, "planned_graph", return_value=plan))
        created = stack.enter_context(
            patch.object(graph, "create_bead", return_value={"id": "EXAMPLE_NODE", "title": "EXAMPLE_RELIABLE_TITLE"})
        )
        linked = stack.enter_context(patch.object(graph, "add_dependency"))
        stack.enter_context(patch.object(sys, "argv", ["scaffold_workgraph.py", "--title", "EXAMPLE_GRAPH", *options]))
        stack.enter_context(contextlib.redirect_stdout(stream))
        stack.enter_context(contextlib.redirect_stderr(errors))
        try:
            graph.main()
        except SystemExit as exc:
            failure = exc
    return failure, stream.getvalue(), errors.getvalue(), created.call_args_list, linked.call_args_list


def native_deep_control():
    nested: object = "EXAMPLE_LEAF"
    for _ in range(10000):
        nested = [nested]
    try:
        serialized = json.dumps(nested, sort_keys=True)
    except RecursionError:
        return nested, None
    return nested, serialized


class ScaffoldRenderReportingTests(unittest.TestCase):
    def setUp(self) -> None:
        guard = patch.object(beads, "run_bd", side_effect=AssertionError("EXAMPLE unexpected Beads process"))
        guard.start()
        self.addCleanup(guard.stop)

    def assert_refused(self, result) -> None:
        failure, output_text, error_text, writes, links = result
        self.assertIsInstance(failure, SystemExit)
        self.assertTrue(bool(str(failure)), "EXAMPLE input refusal needs a clear reliability message.")
        self.assertTrue(output_text == "", "EXAMPLE invalid input produced output.")
        self.assertEqual(error_text, "")
        self.assertEqual((len(writes), len(links)), (0, 0))

    def assert_propagates(self, error, call) -> None:
        if isinstance(error, SystemExit):
            result = call()
            self.assertIs(result[0], error)
            self.assert_refused(result)
        else:
            with self.assertRaises(type(error)) as caught:
                call()
            self.assertIs(caught.exception, error)

    def test_selected_json_failures_are_reported_without_output_or_writes(self) -> None:
        for mode, field in (
            ("beads-graph", "skills"),
            ("cwo", "EXAMPLE_UNUSED_VALUE"),
        ):
            with self.subTest(mode=mode):
                plan = example_plan()
                marker = ExampleNonJsonValue()
                plan[2][field] = [marker] if field == "skills" else marker
                self.assert_refused(observed_main(plan, ("--dry-run", "--format", mode)))
                if mode == "beads-graph":
                    with self.assertRaisesRegex(ValueError, "invalid export metadata"):
                        graph.beads_graph_plan(plan)
                rendered = graph.markdown_workgraph_plan("EXAMPLE_GRAPH", plan)
                if mode == "beads-graph":
                    self.assertIn("EXAMPLE_NON_JSON_VALUE", rendered)
                else:
                    self.assertTrue(graph.beads_graph_plan(plan)["nodes"])

    def test_circular_json_failures_remain_scoped_to_consumed_values(self) -> None:
        value = []
        value.append(value)
        plan = example_plan()
        plan[2]["EXAMPLE_UNUSED_VALUE"] = value
        self.assert_refused(observed_main(plan, ("--dry-run", "--format", "cwo")))
        self.assertTrue(graph.beads_graph_plan(plan)["nodes"])
        graph.markdown_workgraph_plan("EXAMPLE_GRAPH", plan)
        for options in MAIN_OPTIONS:
            plan = example_plan()
            plan[2]["metadata"] = {"EXAMPLE_VALUE": value}
            self.assert_refused(observed_main(plan, options))

    def test_missing_standalone_title_keeps_beads_refusal_and_markdown_fallback(self) -> None:
        with self.assertRaisesRegex(ValueError, "must have a title"):
            graph.beads_graph_plan([{}])
        rendered = graph.markdown_workgraph_plan("EXAMPLE_GRAPH", [{}])
        self.assertIn("### epic: epic\n", rendered)

    def test_selected_renderer_input_errors_are_reported(self) -> None:
        for renderer in ("beads_graph_plan", "markdown_workgraph_plan"):
            for kind in (TypeError, ValueError):
                with self.subTest(renderer=renderer, error=kind.__name__):
                    mode = "beads-graph" if renderer == "beads_graph_plan" else "markdown-workgraph"
                    with patch.object(graph, renderer, side_effect=kind("EXAMPLE_RENDER_INPUT")):
                        self.assert_refused(observed_main(example_plan(), ("--dry-run", "--format", mode)))

    def test_native_deep_cli_serialization_preserves_interpreter_behavior(self) -> None:
        nested, serialized = native_deep_control()
        native_refuses = serialized is None
        self.assertIs(native_refuses, sys.version_info[:2] == (3, 12), "EXAMPLE native serialization control changed.")
        cases = [("EXAMPLE_UNUSED_VALUE", ("--dry-run", "--format", "cwo"))]
        cases.extend(("metadata", options) for options in MAIN_OPTIONS)
        for field, options in cases:
            with self.subTest(field=field, options=options):
                plan = example_plan()
                plan[2][field] = {"EXAMPLE_DEEP_VALUE": nested} if field == "metadata" else nested
                stream = CountingOutput()
                result = observed_render(plan, options, stream)
                if native_refuses:
                    self.assert_refused(result)
                    self.assertEqual(stream.characters, 0)
                else:
                    failure, _, errors, writes, links = result
                    self.assertIsNone(failure)
                    self.assertEqual(errors, "")
                    self.assertGreater(stream.characters, 0)
                    self.assertLess(stream.characters, 256 * 1024 * 1024)
                    self.assertTrue(stream.trailing_newline)
                    self.assertEqual(len(writes), 0 if options else len(plan))
                    self.assertEqual(len(links), 0 if options else 1)
                self.assertIs(plan[2][field]["EXAMPLE_DEEP_VALUE"] if field == "metadata" else plan[2][field], nested)

    def test_native_deep_standalone_projection_preserves_interpreter_behavior(self) -> None:
        nested, serialized = native_deep_control()
        self.assertIs(serialized is None, sys.version_info[:2] == (3, 12), "EXAMPLE native serialization control changed.")
        plan = example_plan()
        plan[2]["metadata"] = {"EXAMPLE_DEEP_VALUE": nested}
        if serialized is None:
            with self.assertRaisesRegex(ValueError, "invalid export metadata"):
                graph.beads_graph_plan(plan)
        else:
            projected = graph.beads_graph_plan(plan)["nodes"][2]["metadata"]["cwo_metadata_EXAMPLE_DEEP_VALUE"]
            self.assertTrue(projected == serialized, "EXAMPLE reliable deep metadata changed.")
        self.assertIs(plan[2]["metadata"]["EXAMPLE_DEEP_VALUE"], nested)

    def test_unrelated_renderer_failures_and_process_control_propagate(self) -> None:
        for renderer, mode in (
            ("beads_graph_plan", "beads-graph"),
            ("markdown_workgraph_plan", "markdown-workgraph"),
            ("string_metadata", "beads-graph"),
        ):
            for kind in (RuntimeError, RecursionError, KeyboardInterrupt, SystemExit):
                error = kind("EXAMPLE_RENDER_FAILURE")
                stream = io.StringIO()
                with patch.object(graph, renderer, side_effect=error):
                    self.assert_propagates(
                        error, lambda: observed_render(example_plan(), ("--dry-run", "--format", mode), stream)
                    )
                self.assertEqual(stream.getvalue(), "")

    def test_route_construction_errors_remain_outside_render_handlers(self) -> None:
        for kind in (TypeError, ValueError, RecursionError, RuntimeError, KeyboardInterrupt, SystemExit):
            error = kind("EXAMPLE_ROUTE_FAILURE")
            stream = io.StringIO()
            with patch.object(graph, "_normalize_workerbee_planned_delegation", side_effect=error):
                self.assert_propagates(
                    error, lambda: observed_render(example_plan(), ("--dry-run",), stream)
                )
            self.assertEqual(stream.getvalue(), "")

    def test_json_boundary_reports_input_errors_and_preserves_unrelated_failures(self) -> None:
        native_dumps = json.dumps
        for kind in (TypeError, ValueError, RecursionError, RuntimeError, KeyboardInterrupt, SystemExit):
            error = kind("EXAMPLE_SERIALIZATION_FAILURE")
            stream = io.StringIO()

            def serialize(value, **kwargs):
                if kwargs.get("indent") == 2:
                    raise error
                return native_dumps(value, **kwargs)

            with patch.object(graph.json, "dumps", side_effect=serialize):
                call = lambda: observed_render(example_plan(), ("--dry-run", "--format", "cwo"), stream)
                if kind in (TypeError, ValueError, RecursionError):
                    self.assert_refused(call())
                else:
                    self.assert_propagates(error, call)
            self.assertEqual(stream.getvalue(), "")

    def test_metadata_serialization_preserves_unrelated_failures(self) -> None:
        for consumer in (graph._validate_creation_fields, graph.beads_graph_plan):
            for kind in (RuntimeError, KeyboardInterrupt, SystemExit):
                error = kind("EXAMPLE_METADATA_FAILURE")
                with patch.object(graph.json, "dumps", side_effect=error):
                    with self.assertRaises(kind) as caught:
                        consumer(example_plan())
                self.assertIs(caught.exception, error)

    def test_output_stream_errors_remain_outside_render_handlers(self) -> None:
        for mode in ("cwo", "beads-graph", "markdown-workgraph"):
            for kind in (TypeError, ValueError, RecursionError, RuntimeError, KeyboardInterrupt, SystemExit, OSError):
                error = kind("EXAMPLE_OUTPUT_FAILURE")
                stream = io.StringIO()
                with patch.object(stream, "write", side_effect=error):
                    self.assert_propagates(
                        error, lambda: observed_render(example_plan(), ("--dry-run", "--format", mode), stream)
                    )
                self.assertEqual(stream.getvalue(), "")


class ScaffoldDependencyValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        guard = patch.object(beads, "run_bd", side_effect=AssertionError("unexpected Beads process"))
        guard.start()
        self.addCleanup(guard.stop)

    def test_main_closure_pressure_refuses_before_create_and_dependency(self) -> None:
        """A supplied valid plan isolates main's refusal before functioning fake writes."""
        failure, output_text, error_text, writes, links = observed_main(
            example_plan(), ("--closure-pressure-active",)
        )
        self.assertEqual((len(writes), len(links)), (0, 0))
        self.assertIsInstance(failure, SystemExit)
        self.assertEqual(failure.code, 2)
        self.assertIn("explicit-closure-disposition-required", error_text)
        self.assertEqual(output_text, "")

        failure, _output_text, error_text, writes, links = observed_main(
            example_plan(), ("--closure-pressure-active", "--closure-disposition", "correct")
        )
        self.assertEqual((len(writes), len(links)), (3, 1))
        self.assertEqual(links, [("EXAMPLE_NODE_0001", "EXAMPLE_NODE_0002", "blocks")])
        self.assertIsNone(failure)
        self.assertEqual(error_text, "")

    def assert_main_rejected(self, plan: object, message: str) -> None:
        for options in MAIN_OPTIONS:
            with self.subTest(options=options):
                failure, output_text, error_text, writes, links = observed_main(plan, options)
                self.assertIsInstance(failure, SystemExit)
                self.assertRegex(str(failure), message)
                self.assertEqual(output_text, "")
                self.assertEqual(error_text, "")
                self.assertEqual(len(writes), 0)
                self.assertEqual(len(links), 0)

    def assert_rejected(self, plan: object, message: str) -> None:
        before = copy.deepcopy(plan)
        for name, export in (
            ("beads", graph.beads_graph_plan),
            ("markdown", lambda value: graph.markdown_workgraph_plan("EXAMPLE_GRAPH", value)),
        ):
            with self.subTest(consumer=name), self.assertRaisesRegex(ValueError, message):
                export(plan)
        self.assert_main_rejected(plan, message)
        self.assertEqual(plan, before)

    def assert_created_consumers(self, plan, exported, output_text, writes, links) -> None:
        keys = [node["key"] for node in exported["nodes"]]
        self.assertEqual(len(writes), len(plan))
        identifiers = {key: write[0] for key, write in zip(keys, writes)}
        for index, (item, node, write) in enumerate(zip(plan, exported["nodes"], writes)):
            _, title, fields = write
            self.assertEqual(title, item["title"])
            self.assertEqual(node["title"], title)
            self.assertEqual(fields["priority"], node["priority"])
            self.assertEqual(fields["labels"], item["labels"])
            self.assertEqual(fields["skills"], item["skills"])
            self.assertEqual(fields["metadata"], item.get("metadata"))
            for name in ("acceptance", "design", "notes"):
                self.assertEqual(fields[name], str(item[name]))
            self.assertEqual(json.loads(node["metadata"]["cwo_skills"]), item["skills"])
            self.assertEqual(node["metadata"]["cwo_lane"], str(item.get("lane") or "epic"))
            self.assertEqual(json.loads(node["metadata"]["cwo_depends_on_lanes"]), item.get("depends_on_lanes", []))
            if index:
                self.assertEqual(node["parent_key"], "epic")
                self.assertEqual(fields["parent"], writes[0][0])
            else:
                self.assertNotIn("parent_key", node)
                self.assertEqual(fields["issue_type"], "epic")
        self.assertEqual(
            links,
            [(identifiers[edge["from_key"]], identifiers[edge["to_key"]], edge["type"]) for edge in exported["edges"]],
        )
        expected_output = f"Created epic: {writes[0][0]}\n"
        expected_output += "".join(f"Created task: {identifier} {title}\n" for identifier, title, _ in writes[1:])
        self.assertEqual(output_text, expected_output)

    def assert_valid_consumers(self, plan: list[dict[str, object]]) -> None:
        before = copy.deepcopy(plan)
        exported = graph.beads_graph_plan(plan)
        rendered = graph.markdown_workgraph_plan("EXAMPLE_GRAPH", plan)
        keys = [graph.item_key(item, index) for index, item in enumerate(plan)]
        self.assertEqual([node["key"] for node in exported["nodes"]], keys)
        headings = [line for line in rendered.splitlines() if line.startswith("### ")]
        self.assertEqual(len(headings), len(plan))
        for key, heading in zip(keys, headings):
            self.assertTrue(heading.startswith(f"### {key}: "))
        for options in MAIN_OPTIONS:
            with self.subTest(options=options):
                failure, output_text, error_text, writes, links = observed_main(plan, options)
                self.assertIsNone(failure)
                self.assertEqual(error_text, "")
                if options:
                    self.assertEqual(len(writes), 0)
                    self.assertEqual(len(links), 0)
                    if options[-1] == "markdown-workgraph":
                        self.assertEqual(output_text, rendered)
                    else:
                        context_record = exported if options[-1] == "beads-graph" else plan
                        self.assertEqual(output_text, json.dumps(context_record, indent=2, sort_keys=True) + "\n")
                    continue
                self.assert_created_consumers(plan, exported, output_text, writes, links)
        self.assertEqual(plan, before)

    def test_missing_references_and_duplicate_effective_keys_are_refused(self) -> None:
        for dependency in ("EXAMPLE_MISSING", {"key": "EXAMPLE_MISSING", "type": "related"}):
            plan = example_plan()
            plan[1]["depends_on_lanes"] = [dependency]
            self.assert_rejected(plan, "missing dependency reference")
        plan = example_plan()
        plan.append(copy.deepcopy(plan[1]))
        self.assert_rejected(plan, "duplicate node key")
        plan = example_plan()
        plan[2]["lane"] = "epic"
        self.assert_rejected(plan, "duplicate node key 'epic'")
        plan = example_plan()
        plan[1].pop("lane")
        plan[2]["lane"] = "item-1"
        self.assert_rejected(plan, "duplicate node key 'item-1'")

    def test_blocks_and_until_self_and_multi_node_cycles_are_refused(self) -> None:
        for dependency_type in ("blocks", "until"):
            plan = example_plan()
            plan[1]["depends_on_lanes"] = [{"lane": "EXAMPLE_FIRST", "type": dependency_type}]
            self.assert_rejected(plan, "readiness dependency cycle")
        for first_type, last_type in (("blocks", "blocks"), ("until", "until"), ("blocks", "until")):
            plan = example_plan()
            plan[1]["depends_on_lanes"] = [{"lane": "EXAMPLE_LAST", "type": first_type}]
            plan[2]["depends_on_lanes"] = [{"lane": "EXAMPLE_FIRST", "type": last_type}]
            self.assert_rejected(plan, "readiness dependency cycle")
        plan = example_plan()
        plan[0]["depends_on_lanes"] = ["EXAMPLE_FIRST"]
        plan[2]["depends_on_lanes"] = [{"key": "epic", "type": "until"}]
        self.assert_rejected(plan, "readiness dependency cycle")

    def test_invalid_field_shapes_and_dependency_types_are_refused(self) -> None:
        for field, value in (
            ("lane", []),
            ("labels", "EXAMPLE_INVALID"),
            ("labels", [3]),
            ("skills", None),
            ("depends_on_lanes", "EXAMPLE_LAST"),
            ("depends_on_lanes", {"lane": "EXAMPLE_LAST"}),
            ("depends_on_lanes", None),
        ):
            plan = example_plan()
            plan[2][field] = value
            self.assert_rejected(plan, "work graph")
        for dependency, message in (
            (None, "dependency entry"),
            (3, "dependency entry"),
            ("", "dependency lane"),
            ({"lane": "EXAMPLE_LAST", "type": "EXAMPLE_UNSUPPORTED"}, "dependency_type"),
        ):
            plan = example_plan()
            plan[1]["depends_on_lanes"] = [dependency]
            self.assert_rejected(plan, message)
        for plan in (None, {}, [None]):
            self.assert_rejected(plan, "work graph")

    def test_main_reports_missing_creation_fields_before_writes(self) -> None:
        for index in (0, 2):
            for field in ("labels", "skills", "acceptance", "design", "notes"):
                plan = example_plan()
                del plan[index][field]
                graph.beads_graph_plan(plan)
                graph.markdown_workgraph_plan("EXAMPLE_GRAPH", plan)
                self.assert_main_rejected(plan, f"missing creation field {field}")
        plan = example_plan()
        del plan[0]["metadata"]
        self.assert_main_rejected(plan, "missing creation field metadata")
        plan = example_plan()
        del plan[2]["title"]
        with self.assertRaisesRegex(ValueError, "must have a title"):
            graph.beads_graph_plan(plan)
        self.assertIn(
            "### EXAMPLE_LAST: EXAMPLE_LAST\n",
            graph.markdown_workgraph_plan("EXAMPLE_GRAPH", plan),
        )
        self.assert_main_rejected(plan, "text title")

    def test_forward_references_aliases_and_relationship_order_are_preserved(self) -> None:
        plan = example_plan()
        plan[0]["depends_on_lanes"] = [{"key": " EXAMPLE_FIRST ", "dependency_type": "VALIDATES"}]
        plan[1]["depends_on_lanes"] = [
            " EXAMPLE_LAST ",
            {"key": " EXAMPLE_LAST ", "dependency_type": " RELATES_TO "},
            {"lane": "EXAMPLE_LAST", "type": "UNTIL"},
        ]
        plan[2]["depends_on_lanes"] = [{"key": "EXAMPLE_FIRST", "type": "tracks"}]
        self.assertEqual(
            [(edge["from_key"], edge["to_key"], edge["type"]) for edge in graph.beads_graph_plan(plan)["edges"]],
            [
                ("epic", "EXAMPLE_FIRST", "validates"),
                ("EXAMPLE_FIRST", "EXAMPLE_LAST", "blocks"),
                ("EXAMPLE_FIRST", "EXAMPLE_LAST", "relates-to"),
                ("EXAMPLE_FIRST", "EXAMPLE_LAST", "until"),
                ("EXAMPLE_LAST", "EXAMPLE_FIRST", "tracks"),
            ],
        )
        self.assert_valid_consumers(plan)
        plan = example_plan()
        plan[2].pop("lane")
        plan[1]["depends_on_lanes"] = [{"key": " item-2 ", "dependency_type": "blocks"}]
        self.assert_valid_consumers(plan)

    def test_nonblocking_cycles_retain_every_supported_relationship_type(self) -> None:
        for dependency_type in (
            "related", "relates-to", "tracks", "validates", "parent-child",
            "discovered-from", "caused-by", "supersedes",
        ):
            plan = example_plan()
            plan[1]["depends_on_lanes"] = [{"lane": "EXAMPLE_LAST", "type": dependency_type}]
            plan[2]["depends_on_lanes"] = [
                {"lane": "EXAMPLE_FIRST", "type": dependency_type},
                {"key": "EXAMPLE_LAST", "type": dependency_type},
            ]
            exported = graph.beads_graph_plan(plan)
            self.assertEqual([edge["type"] for edge in exported["edges"]], [dependency_type] * 3)
            self.assert_valid_consumers(plan)

    def test_standalone_empty_exports_remain_available_and_main_refuses_empty_plan(self) -> None:
        self.assertEqual(graph.beads_graph_plan([]), {"nodes": [], "edges": []})
        rendered = graph.markdown_workgraph_plan("EXAMPLE_EMPTY", [])
        self.assertTrue(rendered.startswith("# EXAMPLE_EMPTY\n"))
        self.assertIn("## Work Items\n", rendered)
        self.assertNotIn("### ", rendered)
        self.assert_main_rejected([], "plan is empty")

    def test_real_full_and_tight_graphs_preserve_valid_consumer_outputs(self) -> None:
        for input_text, options in (
            ("Explain a small local project maintenance change.", {}),
            ("Create documentation plus GitHub Pages for a project.", {"file_paths": ["README.md"]}),
            ("RHACS policy review.", {"external_ok": True, "share_boundary": "redacted-packet"}),
            ("Review public docs and README guidance.", {"local_ok": True, "prefer_local": True, "file_paths": ["README.md"]}),
        ):
            route = graph.classify_work(input_text, **options)
            for size in ("full", "tight"):
                with self.subTest(input_text=input_text, size=size):
                    plan = graph.planned_graph("EXAMPLE_GRAPH", route, scaffold_size=size)
                    self.assert_valid_consumers(plan)

    def test_long_acyclic_chain_uses_iterative_validation(self) -> None:
        plan = example_plan()[:1]
        for index in range(4096):
            lane = f"EXAMPLE_CHAIN_{index:04d}"
            dependencies = [] if index == 0 else [f"EXAMPLE_CHAIN_{index - 1:04d}"]
            plan.append(example_item(lane, dependencies))
        self.assert_valid_consumers(plan)

    def test_observers_are_restored_after_valid_and_rejected_main_calls(self) -> None:
        before = (graph.create_bead, graph.add_dependency, graph.classify_work, graph.planned_graph, sys.argv, sys.stdout, sys.stderr, beads.run_bd)
        observed_main(example_plan())
        plan = example_plan()
        plan[1]["depends_on_lanes"] = ["EXAMPLE_MISSING"]
        observed_main(plan)
        after = (graph.create_bead, graph.add_dependency, graph.classify_work, graph.planned_graph, sys.argv, sys.stdout, sys.stderr, beads.run_bd)
        for original, restored in zip(before, after):
            self.assertIs(restored, original)

    def test_dependency_write_failure_keeps_partial_persistence_reporting(self) -> None:
        failure, output_text, error_text, writes, links = observed_main(
            example_plan(), dependency_error=RuntimeError("EXAMPLE_DEPENDENCY_WRITE_FAILURE")
        )
        self.assertIsInstance(failure, SystemExit)
        self.assertIn("could not add dependency", str(failure))
        self.assertEqual(len(writes), 3)
        self.assertEqual(len(links), 1)
        self.assertIn("Created epic: EXAMPLE_NODE_0000", output_text)
        self.assertIn("Partial Beads graph creation detected.", error_text)
        self.assertIn("EXAMPLE_NODE_0000", error_text)
        self.assertIn("EXAMPLE_DEPENDENCY_WRITE_FAILURE", error_text)

    def test_unrelated_failures_and_control_exceptions_are_not_relabelled(self) -> None:
        for error in (RuntimeError("EXAMPLE_PROCESS_FAILURE"), KeyboardInterrupt("EXAMPLE_STOP")):
            with patch.object(graph, "validate_workgraph_plan", side_effect=error), self.assertRaises(type(error)) as caught:
                observed_main(example_plan())
            self.assertIs(caught.exception, error)

    def test_standalone_export_control_preserves_defaults(self) -> None:
        plan = [
            {"title": "EXAMPLE_EPIC"},
            {"title": "EXAMPLE_TASK", "lane": "EXAMPLE_TASK", "depends_on_lanes": ["epic"]},
        ]
        before = copy.deepcopy(plan)
        exported = graph.beads_graph_plan(plan)
        self.assertEqual([node["key"] for node in exported["nodes"]], ["epic", "EXAMPLE_TASK"])
        self.assertEqual(exported["edges"], [
            {"from_key": "EXAMPLE_TASK", "to_key": "epic", "type": "blocks"},
        ])
        self.assertIn("### EXAMPLE_TASK: EXAMPLE_TASK", graph.markdown_workgraph_plan("EXAMPLE_GRAPH", plan))
        self.assertEqual(plan, before)

    def test_standalone_title_conversion_and_markdown_defaults_are_preserved(self) -> None:
        for title in (7, 0, None, False, {}, []):
            with self.subTest(title_type=type(title).__name__):
                plan = [{"title": title}]
                before = copy.deepcopy(plan)
                self.assertEqual(graph.beads_graph_plan(plan)["nodes"][0]["title"], str(title))
                rendered = graph.markdown_workgraph_plan("EXAMPLE_GRAPH", plan)
                self.assertIn(f"### epic: {title or 'epic'}\n", rendered)
                self.assertEqual(plan, before)

    def test_standalone_exports_ignore_unused_extensions_without_mutation(self) -> None:
        plain = example_plan()
        before = copy.deepcopy(plain)
        marker = object()
        extended = [dict(item, EXAMPLE_UNUSED_VALUE=marker) for item in plain]
        self.assertEqual(graph.beads_graph_plan(extended), graph.beads_graph_plan(plain))
        self.assertEqual(
            graph.markdown_workgraph_plan("EXAMPLE_GRAPH", extended),
            graph.markdown_workgraph_plan("EXAMPLE_GRAPH", plain),
        )
        self.assertEqual(plain, before)
        for item, expected in zip(extended, before):
            self.assertEqual(set(item), set(expected) | {"EXAMPLE_UNUSED_VALUE"})
            self.assertIs(item["EXAMPLE_UNUSED_VALUE"], marker)
            for field, value in expected.items():
                self.assertEqual(item[field], value)

    def test_consumed_metadata_is_checked_only_for_relevant_consumers(self) -> None:
        for metadata in (["EXAMPLE_INVALID"], {"example_field": {"EXAMPLE_INVALID"}}):
            plan = example_plan()
            rendered = graph.markdown_workgraph_plan("EXAMPLE_GRAPH", plan)
            plan[2]["metadata"] = metadata
            before = copy.deepcopy(plan)
            with self.assertRaisesRegex(ValueError, "work graph"):
                graph.beads_graph_plan(plan)
            self.assertEqual(graph.markdown_workgraph_plan("EXAMPLE_GRAPH", plan), rendered)
            self.assert_main_rejected(plan, "work graph")
            self.assertEqual(plan, before)

    def test_creation_title_validation_remains_scoped_to_creation(self) -> None:
        for title in ({}, 7):
            plan = example_plan()
            plan[2]["title"] = title
            self.assertEqual(graph.beads_graph_plan(plan)["nodes"][2]["title"], str(title))
            graph.markdown_workgraph_plan("EXAMPLE_GRAPH", plan)
            self.assert_main_rejected(plan, "text title")


if __name__ == "__main__":
    unittest.main()
