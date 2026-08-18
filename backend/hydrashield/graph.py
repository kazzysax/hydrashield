from __future__ import annotations

from collections import defaultdict
from typing import Protocol

from .models import Advisory, Application, EvidencePath, PackageVersion


class GraphStore(Protocol):
    def reset(self) -> None: ...
    def add_application(self, application: Application) -> None: ...
    def add_package(self, package: PackageVersion) -> None: ...
    def add_dependency(self, parent_id: str, child_id: str) -> None: ...
    def declare_dependency(self, application_id: str, package_id: str) -> None: ...
    def add_advisory(self, advisory: Advisory, affected_package_ids: list[str]) -> None: ...
    def get_advisory(self, advisory_id: str) -> Advisory | None: ...
    def evidence_paths(self, advisory_id: str, max_depth: int = 12) -> list[EvidencePath]: ...
    def counts(self) -> dict[str, int]: ...


class InMemoryGraph:
    """Deterministic graph adapter used for tests and the zero-setup preview."""

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self.applications: dict[str, Application] = {}
        self.packages: dict[str, PackageVersion] = {}
        self.dependencies: dict[str, set[str]] = defaultdict(set)
        self.declarations: dict[str, set[str]] = defaultdict(set)
        self.advisories: dict[str, Advisory] = {}
        self.affected: dict[str, set[str]] = defaultdict(set)

    def add_application(self, application: Application) -> None:
        self.applications[application.id] = application

    def add_package(self, package: PackageVersion) -> None:
        self.packages[package.id] = package

    def add_dependency(self, parent_id: str, child_id: str) -> None:
        if parent_id != child_id:
            self.dependencies[parent_id].add(child_id)

    def declare_dependency(self, application_id: str, package_id: str) -> None:
        self.declarations[application_id].add(package_id)

    def add_advisory(self, advisory: Advisory, affected_package_ids: list[str]) -> None:
        self.advisories[advisory.id] = advisory
        self.affected[advisory.id].update(affected_package_ids)

    def get_advisory(self, advisory_id: str) -> Advisory | None:
        return self.advisories.get(advisory_id)

    def evidence_paths(self, advisory_id: str, max_depth: int = 12) -> list[EvidencePath]:
        targets = self.affected.get(advisory_id, set())
        results: list[EvidencePath] = []
        for app_id, roots in sorted(self.declarations.items()):
            application = self.applications[app_id]
            for root_id in sorted(roots):
                stack: list[tuple[str, tuple[str, ...]]] = [(root_id, (root_id,))]
                while stack:
                    current, path = stack.pop()
                    if current in targets:
                        results.append(
                            EvidencePath(
                                application=application,
                                packages=tuple(self.packages[item] for item in path),
                                advisory_id=advisory_id,
                            )
                        )
                        continue
                    if len(path) - 1 >= max_depth:
                        continue
                    for child in sorted(self.dependencies.get(current, set()), reverse=True):
                        if child not in path:
                            stack.append((child, path + (child,)))
        return results

    def counts(self) -> dict[str, int]:
        return {
            "applications": len(self.applications),
            "package_versions": len(self.packages),
            "dependency_edges": sum(map(len, self.dependencies.values())),
            "advisories": len(self.advisories),
        }

