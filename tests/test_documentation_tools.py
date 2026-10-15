from __future__ import annotations

from functools import partial
from http.server import ThreadingHTTPServer
import importlib.util
from pathlib import Path
import re
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DocumentationToolTests(unittest.TestCase):
    def test_maintained_links_and_legacy_routes(self):
        self.assertEqual(load("check_documentation").check(), [])

    def test_markdown_fragments_include_duplicate_and_explicit_ids(self):
        module = load("check_documentation")
        self.assertEqual(module.markdown_ids('# A: `test`\n## A: `test`\n<a id="old"></a>'),
                         {"a-test", "a-test-1", "old"})

    def test_direct_example_route_establishes_its_own_source_checkout(self):
        page = (ROOT / "docs/use-cases.html").read_text()
        section = page.split('<section id="run-fixtures">', 1)[1]
        self.assertIn("do not need Codex authentication, Beads", section)
        self.assertLess(section.index("git clone"), section.index("run_examples.py --check"))
        self.assertIn("cwo-example-source", section)

    def test_default_profile_is_not_confused_with_removing_skill(self):
        readme = " ".join((ROOT / "README.md").read_text().split())
        self.assertIn("CWO skill remains available in ordinary sessions until disabled or removed", readme)

    def test_current_docs_describe_the_default_optimized_cwo_system_prompt(self):
        for relative in ("README.md", "SKILL.md", "docs/index.html", "docs/explanation.html",
                         "references/cwo-system-prompt.md"):
            with self.subTest(path=relative):
                text = " ".join((ROOT / relative).read_text().split())
                self.assertIn("system prompt optimized for complex project work", text)
                self.assertIn("default OpenAI system prompt", text)

    def test_current_reader_docs_do_not_reintroduce_candidate_branding_or_links(self):
        paths = [ROOT / name for name in ("README.md", "SKILL.md", "CHANGELOG.md",
                 "references/cwo-system-prompt.md", "references/cwo-candidate-e-operator-profile.md",
                 "references/cwo-sol-operator-profile.md", "references/native-supervision.md")]
        paths.extend(sorted((ROOT / "docs").glob("*.html")))
        for path in paths:
            with self.subTest(path=path.relative_to(ROOT)):
                source = path.read_text()
                visible = " ".join(re.sub(r"<[^>]+>", "", source).split())
                self.assertNotRegex(visible, r"(?i)\bcandidate[ -]+[cef]\b")
                self.assertNotIn("post-v5", visible)
                self.assertNotIn("fewest recorded tokens", visible)
                self.assertNotIn("cwo-candidate-e-operator-profile.md", source)
                self.assertNotIn("candidate-e-qualification-summary.md", source)

    def test_legacy_profile_guide_keeps_its_links_without_current_candidate_branding(self):
        source = (ROOT / "references/cwo-candidate-e-operator-profile.md").read_text()
        self.assertIn("[CWO system prompt](cwo-system-prompt.md)", source)
        for identifier in ("candidate-e-baseline-operator-profile", "qualification-and-repair-boundary",
                           "install-and-verify", "start-a-candidate-e-session", "roll-back"):
            with self.subTest(fragment=identifier):
                self.assertIn(f'id="{identifier}"', source)

    def test_preview_serves_only_the_repository_subpath(self):
        preview = load("preview_site")
        server = ThreadingHTTPServer(("127.0.0.1", 0), partial(preview.PagesHandler, directory=str(preview.DOCS)))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = f"http://127.0.0.1:{server.server_port}"
            with urlopen(base + preview.PREFIX + "index.html", timeout=5) as response:
                self.assertEqual(response.status, 200)
                self.assertIn(b"<main", response.read())
            with urlopen(base + preview.PREFIX[:-1], timeout=5) as response:
                self.assertTrue(response.url.endswith(preview.PREFIX))
            for path in ["/", "/README.md", preview.PREFIX + "../README.md"]:
                with self.subTest(path=path), self.assertRaises(HTTPError) as caught:
                    urlopen(base + path, timeout=5)
                caught.exception.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        self.assertFalse(thread.is_alive())


if __name__ == "__main__":
    unittest.main()
