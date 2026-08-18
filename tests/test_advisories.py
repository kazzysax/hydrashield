import json
import unittest
from pathlib import Path

from hydrashield.advisories import ingest_osv_advisory
from hydrashield.graph import InMemoryGraph
from hydrashield.models import PackageVersion


ROOT = Path(__file__).resolve().parents[1]


class OSVIngestionTest(unittest.TestCase):
    def test_ingests_exact_affected_version(self):
        graph = InMemoryGraph()
        graph.add_package(PackageVersion("npm:package-x@3.2.1", "package-x", "3.2.1"))
        payload = json.loads((ROOT / "fixtures/sample-osv.json").read_text())
        advisory = ingest_osv_advisory(graph, payload)
        self.assertEqual(advisory.id, "GHSA-HYDRA-2026-0001")
        self.assertEqual(advisory.severity, "critical")
        self.assertEqual(graph.affected[advisory.id], {"npm:package-x@3.2.1"})

    def test_refuses_unexpanded_range(self):
        payload = {"id": "ADV", "affected": [{"package": {"ecosystem": "npm", "name": "x"}, "ranges": []}]}
        with self.assertRaisesRegex(ValueError, "expanded versions"):
            ingest_osv_advisory(InMemoryGraph(), payload)


if __name__ == "__main__":
    unittest.main()
