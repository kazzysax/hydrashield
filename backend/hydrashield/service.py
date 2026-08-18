from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict
from typing import Any

from .graph import GraphStore
from .models import Advisory, Application, ApplicationExposure, PackageVersion


class HydraShieldService:
    def __init__(self, graph: GraphStore):
        self.graph = graph

    def analyze(self, advisory_id: str, max_depth: int = 12) -> dict[str, Any]:
        advisory = self.graph.get_advisory(advisory_id)
        if advisory is None:
            raise KeyError(f"Unknown advisory: {advisory_id}")

        paths = self.graph.evidence_paths(advisory_id, max_depth=max_depth)
        grouped: dict[str, ApplicationExposure] = {}
        for path in paths:
            exposure = grouped.setdefault(path.application.id, ApplicationExposure(path.application))
            exposure.paths.append(path)

        exposures = sorted(
            grouped.values(),
            key=lambda item: (
                item.application.environment != "production",
                item.shortest_depth,
                item.application.name,
            ),
        )
        production = [item for item in exposures if item.application.environment == "production"]
        direct = [item for item in exposures if item.direct]
        remediations = self._greedy_remediation(paths)
        confidence = "verified" if paths else "insufficient_evidence"

        return {
            "advisory": asdict(advisory),
            "summary": {
                "status": "critical" if production else "contained",
                "confidence": confidence,
                "applications_exposed": len(exposures),
                "production_exposed": len(production),
                "direct_exposure": len(direct),
                "transitive_exposure": len(exposures) - len(direct),
                "evidence_paths": len(paths),
                "recommended_upgrades": len(remediations),
            },
            "exposures": [item.to_dict() for item in exposures],
            "remediations": remediations,
            "graph_counts": self.graph.counts(),
        }

    @staticmethod
    def _greedy_remediation(paths: list) -> list[dict[str, Any]]:
        remaining = set(range(len(paths)))
        coverage: dict[str, set[int]] = defaultdict(set)
        candidates_by_id: dict[str, PackageVersion] = {}
        for index, path in enumerate(paths):
            if not path.packages:
                continue
            # Any non-compromised package on the path can be upgraded or
            # overridden to cut that route. A direct path falls back to the
            # compromised package itself.
            candidates = path.packages[:-1] or path.packages
            for package in candidates:
                coverage[package.id].add(index)
                candidates_by_id[package.id] = package

        recommendations: list[dict[str, Any]] = []
        while remaining:
            candidates = [
                (len(indexes & remaining), package_id)
                for package_id, indexes in coverage.items()
                if indexes & remaining
            ]
            if not candidates:
                break
            removed_count, selected = max(candidates, key=lambda item: (item[0], item[1]))
            package = candidates_by_id[selected]
            affected_apps = sorted(
                {paths[index].application.name for index in coverage[selected] & remaining}
            )
            recommendations.append(
                {
                    "package": asdict(package),
                    "action": f"Upgrade or override {package.name}",
                    "paths_removed": removed_count,
                    "applications": affected_apps,
                    "priority": len(recommendations) + 1,
                }
            )
            remaining -= coverage[selected]
        return recommendations


def seed_six_minute_demo(graph: GraphStore) -> str:
    graph.reset()
    applications = [
        Application("checkout-api", "Checkout API", "production", "acme/checkout-api", "critical"),
        Application("admin-console", "Admin Console", "production", "acme/admin-console", "high"),
        Application("campaign-worker", "Campaign Worker", "staging", "acme/campaign-worker", "medium"),
        Application("analytics-api", "Analytics API", "production", "acme/analytics-api", "high"),
        Application("docs-site", "Documentation Site", "development", "acme/docs-site", "low"),
        Application("legacy-webhook", "Legacy Webhook", "production", "acme/legacy-webhook", "high"),
    ]
    packages = [
        PackageVersion("npm:checkout-sdk@4.1.0", "checkout-sdk", "4.1.0"),
        PackageVersion("npm:request-helper@2.7.0", "request-helper", "2.7.0"),
        PackageVersion("npm:ui-platform@8.4.0", "ui-platform", "8.4.0"),
        PackageVersion("npm:theme-loader@3.0.2", "theme-loader", "3.0.2"),
        PackageVersion("npm:campaign-kit@5.2.0", "campaign-kit", "5.2.0"),
        PackageVersion("npm:telemetry-core@6.0.0", "telemetry-core", "6.0.0"),
        PackageVersion("npm:analytics-kit@7.3.1", "analytics-kit", "7.3.1"),
        PackageVersion("npm:package-x@3.2.1", "package-x", "3.2.1"),
        PackageVersion("npm:markdown-renderer@2.1.0", "markdown-renderer", "2.1.0"),
    ]
    for application in applications:
        graph.add_application(application)
    for package in packages:
        graph.add_package(package)

    declarations = {
        "checkout-api": "npm:checkout-sdk@4.1.0",
        "admin-console": "npm:ui-platform@8.4.0",
        "campaign-worker": "npm:campaign-kit@5.2.0",
        "analytics-api": "npm:analytics-kit@7.3.1",
        "docs-site": "npm:markdown-renderer@2.1.0",
        "legacy-webhook": "npm:package-x@3.2.1",
    }
    for app_id, package_identifier in declarations.items():
        graph.declare_dependency(app_id, package_identifier)

    for parent, child in [
        ("npm:checkout-sdk@4.1.0", "npm:request-helper@2.7.0"),
        ("npm:request-helper@2.7.0", "npm:package-x@3.2.1"),
        ("npm:ui-platform@8.4.0", "npm:theme-loader@3.0.2"),
        ("npm:theme-loader@3.0.2", "npm:package-x@3.2.1"),
        ("npm:campaign-kit@5.2.0", "npm:telemetry-core@6.0.0"),
        ("npm:telemetry-core@6.0.0", "npm:package-x@3.2.1"),
        ("npm:analytics-kit@7.3.1", "npm:telemetry-core@6.0.0"),
        ("npm:markdown-renderer@2.1.0", "npm:theme-loader@3.0.2"),
    ]:
        graph.add_dependency(parent, child)

    advisory = Advisory(
        "GHSA-HYDRA-2026-0001",
        "package-x",
        ("3.2.1",),
        "critical",
        "Credential exfiltration through a compromised post-install hook",
        "2026-08-18T09:00:00Z",
        "https://osv.dev/",
    )
    graph.add_advisory(advisory, ["npm:package-x@3.2.1"])
    return advisory.id
