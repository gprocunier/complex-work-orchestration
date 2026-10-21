import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("worked_evidence", ROOT / "examples/worked-evidence/run_examples.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class WorkedEvidenceTests(unittest.TestCase):
    def test_conflict_has_decisive_counterexample(self):
        result = module.review_example()
        self.assertEqual(result["rejected_post"]["effects"], 2)
        self.assertEqual(result["accepted_post"]["effects"], 1)
        self.assertEqual(result["accepted_get"]["effects"], 0)

    def test_lab_restores_and_research_excludes_unmeasured_claim(self):
        result = module.run()
        self.assertTrue(result["lab"]["rollback_verified"])
        self.assertEqual(result["lab"]["production_mutations"], 0)
        self.assertEqual(result["lab"]["network_requests"], 0)
        self.assertEqual(result["research"]["rejected_unsupported_claims"], ["N3"])
        self.assertIn("N1, N2", result["research"]["memo"])
        self.assertIn("no measurement", result["research"]["memo"])


if __name__ == "__main__":
    unittest.main()
