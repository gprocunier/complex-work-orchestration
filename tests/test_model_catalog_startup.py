from __future__ import annotations

from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, call, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from cwo_core.model_catalog_startup import public_model_catalog
from cwo_core.model_identities import configure_model_catalog, resolve_model
from cwo_core.policy import load_policy
from model_catalog_startup import AppServerError, _CatalogServer, configure_cli_model_catalog


class ModelCatalogStartupTests(unittest.TestCase):
    def test_paginates_public_catalog_and_excludes_hidden_or_inexact_entries(self):
        luna = {"id": "gpt-9.8-luna", "model": "gpt-9.8-luna", "hidden": False,
                "availableAccessPrograms": {"cyber": ["daybreakBlue"]}}
        terra = {"id": "gpt-9.7-terra", "model": "gpt-9.7-terra", "hidden": False}
        request = Mock(side_effect=[
            ({"data": [luna, {"id": "gpt-reserve", "model": "gpt-reserve", "hidden": True}],
              "nextCursor": "page-2"}, 0),
            ({"data": [terra, {"id": "gpt-9.9-luna", "model": "different", "hidden": False}],
              "nextCursor": None}, 0),
        ])

        self.assertEqual(public_model_catalog(request), {"data": [luna, terra], "nextCursor": None})
        self.assertEqual(request.call_args_list, [
            call("model/list", {"includeHidden": False}),
            call("model/list", {"includeHidden": False, "cursor": "page-2"}),
        ])

    def test_missing_visibility_or_conflicting_duplicate_fails_closed(self):
        entry = {"id": "gpt-9.8-luna", "model": "gpt-9.8-luna"}
        for rows, reason in (
            ([entry], "invalid entry"),
            ([dict(entry, hidden=True), dict(entry, hidden=False)], "duplicate model ID"),
        ):
            with self.subTest(reason=reason), self.assertRaisesRegex(ValueError, reason):
                public_model_catalog(Mock(return_value=({"data": rows}, 0)))

    @patch("model_catalog_startup._CatalogServer")
    @patch("model_catalog_startup.requires_model_catalog", return_value=False)
    def test_explicit_selection_skips_codex(self, required, server):
        configure_cli_model_catalog(("luna",))
        required.assert_called_once_with(("luna",))
        server.assert_not_called()

    @patch("model_catalog_startup._CatalogServer")
    @patch("model_catalog_startup.shutil.which", return_value="/opt/codex/bin/codex")
    def test_startup_catalog_feeds_current_role_resolution(self, executable, server):
        policy = load_policy("model-roles")
        policy["roles"]["luna"]["selection"] = "latest-in-family"
        policy["roles"]["luna"].pop("pin", None)
        latest = "gpt-98-luna"
        server.return_value.request.return_value = ({"data": [
            {"id": latest, "model": latest, "hidden": False},
            {"id": "gpt-99-luna", "model": "gpt-99-luna", "hidden": True},
        ]}, 0)
        self.addCleanup(configure_model_catalog, None)

        with patch("cwo_core.policy.load_policy", return_value=policy):
            configure_cli_model_catalog(("luna",))
            self.assertEqual(resolve_model("luna"), latest)

        server.return_value.request.assert_called_once_with("model/list", {"includeHidden": False}, timeout=5)
        server.return_value.close.assert_called_once_with()

    @patch("model_catalog_startup.configure_model_catalog")
    @patch("model_catalog_startup._CatalogServer")
    @patch("model_catalog_startup.shutil.which", return_value="/opt/codex/bin/codex")
    @patch("model_catalog_startup.requires_model_catalog", return_value=True)
    def test_malformed_list_reaps_catalog_server_before_failing(self, required, executable, server, configure):
        server.return_value.request.return_value = ({"data": None}, 0)

        with self.assertRaisesRegex(SystemExit, "response has no data array"):
            configure_cli_model_catalog(("luna",), codex_home=Path("/tmp/catalog-test"))

        server.return_value.close.assert_called_once_with()
        configure.assert_not_called()

    def test_refuses_thread_writes_and_hidden_queries_at_the_transport_boundary(self):
        server = _CatalogServer.__new__(_CatalogServer)
        with self.assertRaisesRegex(AppServerError, "method-refused"):
            server._write_payload({"method": "thread/start"}, method="thread/start", timeout=1)
        with self.assertRaisesRegex(AppServerError, "visibility-refused"):
            server._write_payload({"method": "model/list", "params": {"includeHidden": True}},
                                  method="model/list", timeout=1)


if __name__ == "__main__":
    unittest.main()
