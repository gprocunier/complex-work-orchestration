"""The archived fixed pool campaign has no current launcher or host."""

from importlib.util import find_spec
from pathlib import Path
import sys
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from cwo_core import native_live_availability as availability


class RetiredPoolQualificationTests(unittest.TestCase):
    def test_fixed_campaign_entrypoints_and_modules_are_absent(self):
        for name in (
            "prepare_native_pool_qualification",
            "run_native_pool_qualification",
            "registered_pool_qualification_host",
            "cwo_core.native_pool_qualification_budget",
            "cwo_core.native_pool_qualification_fixtures",
        ):
            with self.subTest(module=name):
                self.assertFalse((SCRIPTS / (name.replace(".", "/") + ".py")).exists())
                self.assertIsNone(find_spec(name))
        self.assertFalse(hasattr(availability, "require_pool_qualification"))
        self.assertFalse(hasattr(availability, "POOL_QUALIFICATION_AVAILABLE"))
