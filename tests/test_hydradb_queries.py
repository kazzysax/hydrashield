import unittest

from hydrashield.hydradb import HydraDBGraph


class RecordingHydraDB(HydraDBGraph):
    def __init__(self):
        super().__init__("http://example.invalid")
        self.queries = []

    def _query(self, query):
        self.queries.append(query)
        return []


class HydraDBQueryTest(unittest.TestCase):
    def test_evidence_is_computed_with_hydradb_traversals(self):
        graph = RecordingHydraDB()
        graph.evidence_paths("ADV-1", max_depth=3)
        self.assertEqual(len(graph.queries), 4)
        self.assertIn("[:DEPENDS_ON]", graph.queries[2])
        self.assertIn("(app:Application)-[:DECLARES]", graph.queries[0])
        self.assertIn("(adv:Advisory", graph.queries[0])


if __name__ == "__main__":
    unittest.main()

