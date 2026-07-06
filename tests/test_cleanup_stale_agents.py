from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

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

    def test_owned_stale_process_is_terminated_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state_dir = Path(tmpdir) / "state"
            state_dir.mkdir()
            (state_dir / "sessions.jsonl").write_text(
                json.dumps({"pid": 100, "session_id": "owned-agent"}) + "\n",
                encoding="utf-8",
            )
            result = cleanup(
                processes=[
                    ProcessInfo(
                        pid=100,
                        ppid=1,
                        elapsed_seconds=7200,
                        stat="Sl+",
                        command="codex",
                        args="codex --yolo",
                        cwd=str(ROOT),
                    )
                ],
                state_dir=state_dir,
                workspace_root=ROOT,
                stale_after_seconds=3600,
                protected_pids=set(),
                terminate_owned=True,
                terminate_unowned_codex=False,
                prune_state=True,
                dry_run=True,
                grace_seconds=0,
            )
        self.assertIn({"action": "would-terminate", "scope": "owned", "pid": 100, "command": "codex --yolo"}, result["actions"])

    def test_current_process_tree_is_protected_even_when_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state_dir = Path(tmpdir) / "state"
            state_dir.mkdir()
            (state_dir / "sessions.jsonl").write_text(
                json.dumps({"pid": 200, "session_id": "current-agent"}) + "\n",
                encoding="utf-8",
            )
            result = cleanup(
                processes=[
                    ProcessInfo(
                        pid=200,
                        ppid=1,
                        elapsed_seconds=7200,
                        stat="Sl+",
                        command="codex",
                        args="codex --yolo",
                        cwd=str(ROOT),
                    )
                ],
                state_dir=state_dir,
                workspace_root=ROOT,
                stale_after_seconds=3600,
                protected_pids={200},
                terminate_owned=True,
                terminate_unowned_codex=True,
                prune_state=True,
                dry_run=True,
                grace_seconds=0,
            )
        self.assertIn({"action": "protect", "reason": "current-process-tree", "pid": 200}, result["actions"])

    def test_unowned_stale_codex_process_requires_explicit_termination_flag(self) -> None:
        process = ProcessInfo(
            pid=300,
            ppid=1,
            elapsed_seconds=7200,
            stat="Sl+",
            command="node",
            args="node /home/user/.local/bin/codex --yolo",
            cwd=str(ROOT),
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            detected = cleanup(
                processes=[process],
                state_dir=Path(tmpdir) / "state",
                workspace_root=ROOT,
                stale_after_seconds=3600,
                protected_pids=set(),
                terminate_owned=True,
                terminate_unowned_codex=False,
                prune_state=True,
                dry_run=True,
                grace_seconds=0,
            )
            terminated = cleanup(
                processes=[process],
                state_dir=Path(tmpdir) / "state",
                workspace_root=ROOT,
                stale_after_seconds=3600,
                protected_pids=set(),
                terminate_owned=True,
                terminate_unowned_codex=True,
                prune_state=True,
                dry_run=True,
                grace_seconds=0,
            )
        self.assertEqual(detected["actions"][0]["action"], "stale-unowned-detected")
        self.assertEqual(detected["actions"][0]["agent_match"], "command:codex")
        self.assertEqual(terminated["actions"][0]["action"], "would-terminate")
        self.assertEqual(terminated["actions"][0]["scope"], "unowned")
        self.assertEqual(terminated["actions"][0]["agent_match"], "command:codex")

    def test_dead_records_are_pruned(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state_dir = Path(tmpdir) / "state"
            state_dir.mkdir()
            (state_dir / "sessions.jsonl").write_text(
                json.dumps({"pid": 400, "session_id": "dead-agent"}) + "\n",
                encoding="utf-8",
            )
            result = cleanup(
                processes=[],
                state_dir=state_dir,
                workspace_root=ROOT,
                stale_after_seconds=3600,
                protected_pids=set(),
                terminate_owned=True,
                terminate_unowned_codex=False,
                prune_state=True,
                dry_run=False,
                grace_seconds=0,
            )
            self.assertFalse((state_dir / "sessions.jsonl").exists())
        self.assertEqual(result["actions"][0]["action"], "prune-record")
        self.assertEqual(result["actions"][0]["reason"], "dead-process")


if __name__ == "__main__":
    unittest.main()
