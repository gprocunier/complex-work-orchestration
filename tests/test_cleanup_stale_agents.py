from __future__ import annotations

import ast
import contextlib
import io
import json
import os
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import cleanup_stale_agents  # noqa: E402
from cleanup_stale_agents import agent_process_match, cleanup, is_agent_process, parse_process_line, ProcessInfo  # noqa: E402


class CleanupStaleAgentsTests(unittest.TestCase):
    def test_parse_process_line_handles_args_with_spaces(self) -> None:
        process = parse_process_line("123 1 3600 Sl+ node node /home/user/.local/bin/codex --yolo")
        self.assertIsNotNone(process)
        assert process is not None
        self.assertEqual(process.pid, 123)
        self.assertEqual(process.ppid, 1)
        self.assertEqual(process.elapsed_seconds, 3600)
        self.assertEqual(process.command, "node")
        self.assertEqual(process.args, "node /home/user/.local/bin/codex --yolo")
        self.assertTrue(is_agent_process(process))
        self.assertEqual(agent_process_match(process), "command:codex")

    def test_agent_process_matching_uses_tokens_not_substrings(self) -> None:
        false_positives = [
            ProcessInfo(1, 1, 3600, "S", "python", "python strategy.py", cwd=str(ROOT)),
            ProcessInfo(2, 1, 3600, "S", "my-codex-wrapper", "my-codex-wrapper", cwd=str(ROOT)),
            ProcessInfo(3, 1, 3600, "S", "node", "node /tmp/my-codex-wrapper --flag", cwd=str(ROOT)),
        ]
        for process in false_positives:
            with self.subTest(command=process.command_line):
                self.assertIsNone(agent_process_match(process))

        self.assertEqual(
            agent_process_match(ProcessInfo(4, 1, 3600, "S", "npx", "npx @openai/codex --help", cwd=str(ROOT))),
            "package:@openai/codex",
        )
        self.assertEqual(
            agent_process_match(
                ProcessInfo(5, 1, 3600, "S", "node", "node /home/user/.local/bin/codex --yolo", cwd=str(ROOT))
            ),
            "command:codex",
        )
        self.assertEqual(
            agent_process_match(ProcessInfo(6, 1, 3600, "S", "npx", "npx @openai/codex@latest", cwd=str(ROOT))),
            "package:@openai/codex",
        )
        self.assertEqual(
            agent_process_match(
                ProcessInfo(
                    7,
                    1,
                    3600,
                    "S",
                    "node",
                    "node /usr/lib/node_modules/@openai/codex/bin/codex.js",
                    cwd=str(ROOT),
                )
            ),
            "package:@openai/codex",
        )

    def stale(self, pid: int, command: str, args: str, cwd: str | None = None) -> ProcessInfo:
        return ProcessInfo(pid=pid, ppid=1, elapsed_seconds=7200, stat="S", command=command, args=args, cwd=cwd or str(ROOT))

    @contextlib.contextmanager
    def signal_spies(self):
        """Fail loudly if any signal primitive is reached."""
        with mock.patch.object(os, "kill") as kill, mock.patch.object(os, "killpg") as killpg, mock.patch.object(
            signal, "pidfd_send_signal", create=True
        ) as pidfd_send:
            yield (kill, killpg, pidfd_send)
        for spy in (kill, killpg, pidfd_send):
            self.assertEqual(spy.call_count, 0, f"signal primitive reached: {spy}")

    def write_registry(self, state_dir: Path, *records: object, raw_lines: tuple[str, ...] = ()) -> None:
        state_dir.mkdir(parents=True, exist_ok=True)
        lines = [json.dumps(record) for record in records] + list(raw_lines)
        (state_dir / "sessions.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")

    def run_cleanup(self, state_dir: Path, processes: list[ProcessInfo], **overrides: object) -> dict:
        options = dict(
            processes=processes,
            state_dir=state_dir,
            workspace_root=ROOT,
            stale_after_seconds=3600,
            protected_pids=set(),
            terminate_owned=False,
            terminate_unowned_codex=False,
            prune_state=True,
            dry_run=False,
            grace_seconds=0,
        )
        options.update(overrides)
        return cleanup(**options)

    def run_main(self, argv: list[str], processes: list[ProcessInfo]) -> tuple[int, dict]:
        stdout = io.StringIO()
        with mock.patch.object(cleanup_stale_agents, "discover_processes", return_value=processes), mock.patch.object(
            cleanup_stale_agents, "ancestor_pids", return_value=set()
        ), contextlib.redirect_stdout(stdout):
            code = cleanup_stale_agents.main(argv + ["--json"])
        return code, json.loads(stdout.getvalue())

    def test_default_invocation_is_detection_only_for_a_planted_registry_pid(self) -> None:
        planted = self.stale(100, "sleep", "sleep 3600")
        with tempfile.TemporaryDirectory() as tmpdir, self.signal_spies():
            state_dir = Path(tmpdir) / "state"
            self.write_registry(state_dir, {"pid": 100, "session_id": "planted"})
            code, result = self.run_main(["--state-dir", str(state_dir), "--workspace-root", str(ROOT)], [planted])
        self.assertEqual(code, 0)
        self.assertEqual(result["actions"], [{"action": "stale-owned-detected", "pid": 100, "command": "sleep 3600"}])
        self.assertEqual(result["termination"]["requested"], {"owned": False, "unowned": False})
        self.assertFalse(result["termination"]["available"])
        self.assertEqual(result["termination"]["signals_sent"], 0)

    def test_no_terminate_owned_alias_matches_the_default(self) -> None:
        planted = self.stale(101, "sleep", "sleep 3600")
        with tempfile.TemporaryDirectory() as tmpdir, self.signal_spies():
            state_dir = Path(tmpdir) / "state"
            self.write_registry(state_dir, {"pid": 101})
            default_code, default_result = self.run_main(["--state-dir", str(state_dir), "--dry-run"], [planted])
            alias_code, alias_result = self.run_main(["--state-dir", str(state_dir), "--dry-run", "--no-terminate-owned"], [planted])
        self.assertEqual((default_code, alias_code), (0, 0))
        self.assertEqual(default_result["actions"], alias_result["actions"])

    def test_explicit_owned_termination_request_reports_unavailable_without_signals(self) -> None:
        planted = self.stale(102, "sleep", "sleep 3600")
        with tempfile.TemporaryDirectory() as tmpdir, self.signal_spies():
            state_dir = Path(tmpdir) / "state"
            self.write_registry(state_dir, {"pid": 102, "session_id": "planted"})
            code, result = self.run_main(["--state-dir", str(state_dir), "--terminate-owned"], [planted])
            kept = (state_dir / "sessions.jsonl").read_text(encoding="utf-8")
        self.assertEqual(code, cleanup_stale_agents.TERMINATION_UNAVAILABLE_EXIT)
        self.assertEqual(
            result["actions"],
            [
                {
                    "action": "termination-unavailable",
                    "scope": "owned",
                    "reason": "no-trusted-ownership-producer",
                    "pid": 102,
                    "command": "sleep 3600",
                }
            ],
        )
        self.assertIn('"pid": 102', kept, "an unterminated record must not be pruned")

    def test_owned_termination_request_refuses_every_registry_shape(self) -> None:
        processes = [
            self.stale(200, "sleep", "sleep 3600"),
            self.stale(201, "python3", "python3 unrelated-script.py codex"),
            self.stale(202, "codex", "codex --yolo", cwd="/elsewhere"),
            self.stale(203, "codex", "codex exec"),
        ]
        with tempfile.TemporaryDirectory() as tmpdir, self.signal_spies():
            state_dir = Path(tmpdir) / "state"
            self.write_registry(
                state_dir,
                {"pid": 200},
                {"pid": 201, "start_time": None},
                {"pid": 202, "workspace": str(ROOT)},
                {"pid": 203, "boot_id": "x", "start_time": 1, "executable": "/usr/bin/codex", "workspace": str(ROOT)},
                {"pid": 203},
                raw_lines=("{not json",),
            )
            result = self.run_cleanup(state_dir, processes, terminate_owned=True)
        by_pid: dict[int, list[str]] = {}
        for action in result["actions"]:
            if "pid" in action:
                by_pid.setdefault(action["pid"], []).append(action["action"])
        self.assertEqual(set(by_pid), {200, 201, 202, 203})
        for pid, outcomes in by_pid.items():
            with self.subTest(pid=pid):
                self.assertEqual(set(outcomes), {"termination-unavailable"})
        self.assertIn({"action": "keep-invalid-record", "line_number": 6}, result["actions"])

    def test_protected_ancestor_is_protected_even_when_termination_is_requested(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, self.signal_spies():
            state_dir = Path(tmpdir) / "state"
            self.write_registry(state_dir, {"pid": 210, "session_id": "current-agent"})
            result = self.run_cleanup(
                state_dir,
                [self.stale(210, "codex", "codex --yolo")],
                protected_pids={210},
                terminate_owned=True,
                terminate_unowned_codex=True,
            )
        self.assertEqual(result["actions"], [{"action": "protect", "reason": "current-process-tree", "pid": 210}])

    def test_unowned_recognized_agent_is_an_observation_only(self) -> None:
        recognized = self.stale(300, "node", "node /home/user/.local/bin/codex --yolo")
        unrelated_with_token = self.stale(301, "python3", "python3 unrelated-script.py codex")
        with tempfile.TemporaryDirectory() as tmpdir, self.signal_spies():
            state_dir = Path(tmpdir) / "state"
            detected = self.run_cleanup(state_dir, [recognized, unrelated_with_token])
            requested = self.run_cleanup(state_dir, [recognized, unrelated_with_token], terminate_unowned_codex=True)
        self.assertEqual([a["action"] for a in detected["actions"]], ["stale-unowned-detected", "stale-unowned-detected"])
        # The recognizer cannot tell an agent from an argument named codex.
        self.assertEqual(agent_process_match(unrelated_with_token), "command:codex")
        for action in requested["actions"]:
            with self.subTest(pid=action["pid"]):
                self.assertEqual(action["action"], "termination-unavailable")
                self.assertEqual(action["reason"], "no-exact-target-authority")
                self.assertEqual(action["agent_match"], "command:codex")

    def test_unowned_termination_request_exits_unavailable(self) -> None:
        recognized = self.stale(310, "codex", "codex --yolo")
        with tempfile.TemporaryDirectory() as tmpdir, self.signal_spies():
            code, result = self.run_main(
                ["--state-dir", str(Path(tmpdir) / "state"), "--workspace-root", str(ROOT), "--terminate-unowned-codex"],
                [recognized],
            )
        self.assertEqual(code, cleanup_stale_agents.TERMINATION_UNAVAILABLE_EXIT)
        self.assertEqual(result["actions"][0]["action"], "termination-unavailable")
        self.assertEqual(result["termination"]["requested"], {"owned": False, "unowned": True})
        self.assertEqual(result["termination"]["reasons"], {"unowned": "no-exact-target-authority"})

    def test_every_case_is_signal_free_in_default_and_requested_modes(self) -> None:
        processes = [
            self.stale(500, "sleep", "sleep 3600"),
            self.stale(501, "python3", "python3 unrelated-script.py codex"),
            self.stale(502, "codex", "codex --yolo", cwd="/elsewhere"),
            self.stale(503, "codex", "codex exec"),
            self.stale(504, "codex", "codex --yolo"),
            # Unregistered and outside the workspace: never a candidate in any mode.
            self.stale(590, "codex", "codex --yolo", cwd="/elsewhere"),
        ]
        registry = (
            {"pid": 500},
            {"pid": 501, "start_time": None},
            {"pid": 502, "workspace": str(ROOT)},
            {"pid": 503},
            {"pid": 503, "session_id": "duplicate"},
            {"pid": 504},
        )
        for mode, overrides in (("default", {}), ("requested", {"terminate_owned": True, "terminate_unowned_codex": True})):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmpdir, self.signal_spies():
                state_dir = Path(tmpdir) / "state"
                self.write_registry(state_dir, *registry, raw_lines=("{not json",))
                before = (state_dir / "sessions.jsonl").read_text(encoding="utf-8")
                result = self.run_cleanup(state_dir, processes, protected_pids={504}, **overrides)
                kept = [json.loads(line) for line in (state_dir / "sessions.jsonl").read_text(encoding="utf-8").splitlines()]
                self.assertEqual(
                    sorted(record["pid"] for record in kept if "pid" in record),
                    [500, 501, 502, 503, 503, 504],
                    "every live record is retained",
                )
                self.assertIn("{not json", [record.get("raw") for record in kept], "the malformed line is retained")
                self.assertTrue(before)
                expected_owned = "termination-unavailable" if mode == "requested" else "stale-owned-detected"
                self.assertEqual(
                    sorted((action.get("pid", -1), action["action"]) for action in result["actions"]),
                    sorted(
                        [(-1, "keep-invalid-record")]
                        + [(pid, expected_owned) for pid in (500, 501, 502, 503, 503)]
                        + [(504, "protect")]
                    ),
                    "the complete action multiset, including both duplicate records; pid 590 never appears",
                )
                self.assertEqual(result["termination"]["signals_sent"], 0)

    def test_requested_termination_exits_unavailable_even_without_matches(self) -> None:
        fresh = ProcessInfo(pid=600, ppid=1, elapsed_seconds=10, stat="S", command="codex", args="codex", cwd=str(ROOT))
        protected = self.stale(601, "codex", "codex --yolo")
        outside = self.stale(602, "codex", "codex --yolo", cwd="/elsewhere")
        cases = (
            ("empty registry", ["--terminate-owned"], [], (), set(), {"owned": "no-trusted-ownership-producer"}),
            ("fresh only", ["--terminate-owned"], [fresh], ({"pid": 600},), set(), {"owned": "no-trusted-ownership-producer"}),
            ("protected only", ["--terminate-owned"], [protected], ({"pid": 601},), {601}, {"owned": "no-trusted-ownership-producer"}),
            ("outside workspace", ["--terminate-unowned-codex"], [outside], (), set(), {"unowned": "no-exact-target-authority"}),
            (
                "both scopes",
                ["--terminate-owned", "--terminate-unowned-codex"],
                [],
                (),
                set(),
                {"owned": "no-trusted-ownership-producer", "unowned": "no-exact-target-authority"},
            ),
        )
        for name, flags, processes, records, ancestors, reasons in cases:
            with self.subTest(case=name), tempfile.TemporaryDirectory() as tmpdir, self.signal_spies():
                state_dir = Path(tmpdir) / "state"
                if records:
                    self.write_registry(state_dir, *records)
                stdout = io.StringIO()
                with mock.patch.object(cleanup_stale_agents, "discover_processes", return_value=processes), mock.patch.object(
                    cleanup_stale_agents, "ancestor_pids", return_value=ancestors
                ), contextlib.redirect_stdout(stdout):
                    code = cleanup_stale_agents.main(["--state-dir", str(state_dir), "--workspace-root", str(ROOT), "--json", *flags])
                result = json.loads(stdout.getvalue())
                self.assertEqual(code, cleanup_stale_agents.TERMINATION_UNAVAILABLE_EXIT)
                self.assertEqual(result["termination"]["status"], "unavailable")
                self.assertEqual(result["termination"]["reasons"], reasons)

    def test_no_request_reports_not_requested_and_exits_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, self.signal_spies():
            code, result = self.run_main(["--state-dir", str(Path(tmpdir) / "state")], [])
        self.assertEqual(code, 0)
        self.assertEqual(result["termination"]["status"], "not-requested")
        self.assertEqual(result["termination"]["reasons"], {})

    def test_cwo_alias_propagates_unavailable_exit_status(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            completed = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "cwo.py"),
                    "cleanup-stale-agents",
                    "--terminate-owned",
                    "--json",
                    "--state-dir",
                    str(Path(tmpdir) / "state"),
                    "--workspace-root",
                    tmpdir,
                ],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
        self.assertEqual(completed.returncode, cleanup_stale_agents.TERMINATION_UNAVAILABLE_EXIT, completed.stderr)
        self.assertEqual(json.loads(completed.stdout)["termination"]["status"], "unavailable")

    def attribute_calls(self, module_path: str, names: set[str]) -> list[str]:
        tree = ast.parse(Path(module_path).read_text(encoding="utf-8"))
        return [
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in names
        ]

    def test_cleanup_never_calls_a_signal_primitive_directly(self) -> None:
        self.assertEqual(
            self.attribute_calls(cleanup_stale_agents.__file__, {"kill", "killpg", "pidfd_send_signal", "send_signal"}), []
        )
        self.assertFalse(hasattr(cleanup_stale_agents, "terminate_process"))

    def test_identity_module_signals_only_through_a_pidfd(self) -> None:
        import cwo_core.process_identity as process_identity

        self.assertEqual(self.attribute_calls(process_identity.__file__, {"kill", "killpg"}), [])
        self.assertEqual(self.attribute_calls(process_identity.__file__, {"pidfd_send_signal"}), ["pidfd_send_signal"])

    def test_dead_records_are_pruned(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, self.signal_spies():
            state_dir = Path(tmpdir) / "state"
            self.write_registry(state_dir, {"pid": 400, "session_id": "dead-agent"})
            result = self.run_cleanup(state_dir, [], terminate_owned=True)
            self.assertFalse((state_dir / "sessions.jsonl").exists())
        self.assertEqual(result["actions"][0]["action"], "prune-record")
        self.assertEqual(result["actions"][0]["reason"], "dead-process")


if __name__ == "__main__":
    unittest.main()
