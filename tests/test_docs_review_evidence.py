from __future__ import annotations

import re
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from site_code import CodeBlocks
from validate_site import validate_html


class ReviewEvidenceDocumentationTests(unittest.TestCase):
    def link_errors(self, url: str) -> list[str]:
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            path = Path(directory) / "explanation.html"
            path.write_text(
                '<html lang="en"><head><title>Test</title></head><body>'
                '<header></header><nav></nav><main><h1>Test</h1>'
                f'<a href="{url}">Source</a></main><footer></footer></body></html>'
            )
            return [e for e in validate_html(path) if "non-source external URL" in e]

    def test_primary_ecosystem_links_allow_exact_pages_and_fragments_only(self):
        urls = [
            "https://code.claude.com/docs/en/sub-agents",
            "https://code.claude.com/docs/en/agent-teams",
            "https://docs.opencode.ai/docs/providers/",
            "https://docs.opencode.ai/docs/permissions/",
            "https://docs.langchain.com/oss/python/langgraph/persistence",
            "https://docs.langchain.com/oss/python/langgraph/interrupts",
            "https://docs.crewai.com/en/concepts/flows",
            "https://openai.github.io/openai-agents-python/models/",
            "https://openai.github.io/openai-agents-python/guardrails/",
            "https://microsoft.github.io/autogen/stable/user-guide/agentchat-user-guide/tutorial/teams.html",
        ]
        for url in urls:
            with self.subTest(url=url):
                self.assertEqual(self.link_errors(url), [])
                self.assertEqual(self.link_errors(url + "#section"), [])
                self.assertTrue(self.link_errors(url + "extra"))
                self.assertTrue(self.link_errors(url.replace("https://", "https://lookalike.invalid/")))
                self.assertTrue(self.link_errors(url + "?redirect=elsewhere"))

    def test_component_source_links_are_pinned_to_exact_test_files(self):
        base = "https://github.com/gprocunier/complex-work-orchestration/blob/8e05b6cce4c4cf89325112f019fdd8c69a28ecff/"
        for path in ["tests/test_local_dispatch.py", "tests/test_model_synthesis.py", "tests/test_zero_trust_consensus.py"]:
            with self.subTest(path=path):
                self.assertEqual(self.link_errors(base + path + "#L78-L102"), [])
                self.assertTrue(self.link_errors(base + path + ".unrelated"))
                self.assertTrue(self.link_errors(base.replace("8e05b6cce4c4cf89325112f019fdd8c69a28ecff", "unknown") + path))

    def test_local_normalizer_and_evaluator_examples_match_real_cli_options(self):
        parser = CodeBlocks()
        parser.feed((ROOT / "docs/local-workers.html").read_text())
        commands = {}
        for _, text in parser.blocks:
            for name in ["normalize_contractor_return.py", "evaluate_return.py"]:
                if text.startswith("python3 scripts/" + name):
                    commands[name] = shlex.split(text.replace("\\\n", ""))
        self.assertEqual(len(commands), 2)
        for name, command in commands.items():
            with self.subTest(name=name):
                result = subprocess.run(
                    [sys.executable, "scripts/" + name, "--help"], cwd=ROOT,
                    capture_output=True, text=True, timeout=15, check=True,
                )
                allowed = set(re.findall(r"--[a-z][a-z0-9-]*", result.stdout))
                used = {arg for arg in command if arg.startswith("--")}
                self.assertLessEqual(used, allowed)
                self.assertEqual(command[command.index("--bead") + 1], "$TASK_ID")
                self.assertEqual(command[command.index("--file") + 1], "local-return.md")
        self.assertNotIn("--local-dispatch-result", commands["normalize_contractor_return.py"])
        evaluation = commands["evaluate_return.py"]
        self.assertEqual(evaluation[evaluation.index("--local-dispatch-result") + 1], "local-dispatch-result.json")


if __name__ == "__main__":
    unittest.main()
