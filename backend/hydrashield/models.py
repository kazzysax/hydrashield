from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class Application:
    id: str
    name: str
    environment: str = "production"
    repository: str = ""
    criticality: str = "medium"


@dataclass(frozen=True)
class PackageVersion:
    id: str
    name: str
    version: str
    ecosystem: str = "npm"


@dataclass(frozen=True)
class Advisory:
    id: str
    package_name: str
    affected_versions: tuple[str, ...]
    severity: str
    summary: str
    published_at: str
    source_url: str = ""


@dataclass(frozen=True)
class EvidencePath:
    application: Application
    packages: tuple[PackageVersion, ...]
    advisory_id: str

    @property
    def direct(self) -> bool:
        return len(self.packages) == 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "application": asdict(self.application),
            "packages": [asdict(package) for package in self.packages],
            "advisory_id": self.advisory_id,
            "direct": self.direct,
            "depth": max(0, len(self.packages) - 1),
        }


@dataclass
class ApplicationExposure:
    application: Application
    paths: list[EvidencePath] = field(default_factory=list)

    @property
    def shortest_depth(self) -> int:
        return min((len(path.packages) - 1 for path in self.paths), default=0)

    @property
    def direct(self) -> bool:
        return any(path.direct for path in self.paths)

    def to_dict(self) -> dict[str, Any]:
        return {
            "application": asdict(self.application),
            "direct": self.direct,
            "shortest_depth": self.shortest_depth,
            "path_count": len(self.paths),
            "paths": [path.to_dict() for path in self.paths],
        }

