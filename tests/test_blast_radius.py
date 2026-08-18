import unittest

from hydrashield.graph import InMemoryGraph
from hydrashield.service import HydraShieldService, seed_six_minute_demo


class BlastRadiusTest(unittest.TestCase):
    def setUp(self):
        self.graph = InMemoryGraph()
        self.advisory_id = seed_six_minute_demo(self.graph)
        self.result = HydraShieldService(self.graph).analyze(self.advisory_id)

    def test_finds_complete_blast_radius(self):
        summary = self.result["summary"]
        self.assertEqual(summary["applications_exposed"], 6)
        self.assertEqual(summary["production_exposed"], 4)
        self.assertEqual(summary["direct_exposure"], 1)
        self.assertEqual(summary["transitive_exposure"], 5)
        self.assertEqual(summary["evidence_paths"], 6)
        self.assertEqual(summary["confidence"], "verified")

    def test_paths_are_explainable(self):
        checkout = next(item for item in self.result["exposures"] if item["application"]["id"] == "checkout-api")
        names = [node["name"] for node in checkout["paths"][0]["packages"]]
        self.assertEqual(names, ["checkout-sdk", "request-helper", "package-x"])

    def test_greedy_remediation_covers_shared_routes(self):
        remediations = self.result["remediations"]
        selected = {item["package"]["name"] for item in remediations}
        self.assertIn("telemetry-core", selected)
        self.assertIn("theme-loader", selected)
        self.assertEqual(sum(item["paths_removed"] for item in remediations), 6)
        self.assertLess(len(remediations), 6)

    def test_unknown_advisory_abstains_by_error(self):
        with self.assertRaises(KeyError):
            HydraShieldService(self.graph).analyze("UNKNOWN")


if __name__ == "__main__":
    unittest.main()

