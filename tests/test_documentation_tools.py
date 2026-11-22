from __future__ import annotations

from functools import partial
import contextlib
import io
from http.server import ThreadingHTTPServer
import importlib.util
from pathlib import Path
import sys
import threading
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from site_code import without_token_spans


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
        page = without_token_spans((ROOT / "docs/use-cases.html").read_text())
        section = page.split('<section id="run-fixtures">', 1)[1]
        self.assertIn("do not need Codex authentication, Beads", section)
        self.assertLess(section.index("git clone"), section.index("run_examples.py --check"))
        self.assertIn("cwo-example-source", section)

    def test_default_profile_is_not_confused_with_removing_skill(self):
        readme = " ".join((ROOT / "README.md").read_text().split())
        self.assertIn("CWO skill remains available in ordinary sessions until disabled or removed", readme)

    def test_historical_profile_references_are_archived(self):
        references = ROOT / "references"
        for name in ("cwo-candidate-e-operator-profile.md", "candidate-e-qualification-summary.md"):
            with self.subTest(path=name):
                self.assertTrue((references / "history" / name).is_file())
                self.assertFalse((references / name).exists())

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

    def test_preview_main_binds_only_loopback_and_closes_the_server(self):
        preview = load("preview_site")
        for port, failure in ((8765, KeyboardInterrupt), (0, RuntimeError("EXAMPLE server failure"))):
            with self.subTest(port=port):
                server = Mock(server_port=port or 43210)
                server.serve_forever.side_effect = failure
                with patch.object(sys, "argv", ["preview_site.py", "--port", str(port)]), \
                        patch.object(preview, "ThreadingHTTPServer", return_value=server) as constructor, \
                        contextlib.redirect_stdout(io.StringIO()) as output:
                    if failure is KeyboardInterrupt:
                        preview.main()
                    else:
                        with self.assertRaisesRegex(RuntimeError, "EXAMPLE server failure"):
                            preview.main()
                self.assertEqual(constructor.call_count, 1)
                address, handler = constructor.call_args.args
                self.assertEqual(address, ("127.0.0.1", port))
                self.assertIs(handler.func, preview.PagesHandler)
                self.assertEqual(handler.keywords, {"directory": str(preview.DOCS)})
                server.serve_forever.assert_called_once_with()
                server.server_close.assert_called_once_with()
                self.assertIn(f"http://127.0.0.1:{server.server_port}{preview.PREFIX}", output.getvalue())


if __name__ == "__main__":
    unittest.main()
