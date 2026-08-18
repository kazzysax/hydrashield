#!/usr/bin/env python3
from __future__ import annotations

import json
import statistics
import time

from hydrashield.graph import InMemoryGraph
from hydrashield.service import HydraShieldService, seed_six_minute_demo


def main() -> None:
    graph = InMemoryGraph()
    advisory_id = seed_six_minute_demo(graph)
    service = HydraShieldService(graph)
    expected = {"checkout-api", "admin-console", "campaign-worker", "analytics-api", "docs-site", "legacy-webhook"}
    timings = []
    result = None
    for _ in range(250):
        start = time.perf_counter()
        result = service.analyze(advisory_id)
        timings.append((time.perf_counter() - start) * 1000)
    actual = {item["application"]["id"] for item in result["exposures"]}
    precision = len(actual & expected) / len(actual) if actual else 0
    recall = len(actual & expected) / len(expected)
    report = {
        "scenario": "six-minute-compromise",
        "expected_applications": len(expected),
        "returned_applications": len(actual),
        "precision": precision,
        "recall": recall,
        "p50_ms": statistics.median(timings),
        "p95_ms": sorted(timings)[int(len(timings) * .95) - 1],
        "runs": len(timings),
    }
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if precision == recall == 1.0 else 1)


if __name__ == "__main__":
    main()

