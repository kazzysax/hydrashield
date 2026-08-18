import json
import unittest
from pathlib import Path

from hydrashield.graph import InMemoryGraph
from hydrashield.ingest import ingest_package_lock
from hydrashield.models import Advisory, Application


ROOT = Path(__file__).resolve().parents[1]


class PackageLockIngestionTest(unittest.TestCase):
    def test_ingests_direct_and_transitive_dependencies(self):
        graph = InMemoryGraph()
        lockfile = json.loads((ROOT / "fixtures/sample-package-lock.json").read_text())
        result = ingest_package_lock(
            graph,
            Application("checkout", "Checkout", "production", "acme/checkout"),
            lockfile,
        )
        graph.add_advisory(
            Advisory("ADV-1", "package-x", ("3.2.1",), "critical", "test", "2026-08-18T09:00:00Z"),
            ["npm:package-x@3.2.1"],
        )

        self.assertEqual(result.package_versions, 3)
        self.assertEqual(result.dependency_edges, 2)
        self.assertEqual(result.direct_dependencies, 1)
        paths = graph.evidence_paths("ADV-1")
        self.assertEqual(len(paths), 1)
        self.assertEqual([node.name for node in paths[0].packages], ["checkout-sdk", "request-helper", "package-x"])

    def test_rejects_old_lockfile_shape(self):
        with self.assertRaisesRegex(ValueError, "lockfileVersion 2 or 3"):
            ingest_package_lock(InMemoryGraph(), Application("a", "A"), {"dependencies": {}})


if __name__ == "__main__":
    unittest.main()

