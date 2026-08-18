from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from .graph import GraphStore
from .models import Application, PackageVersion


@dataclass(frozen=True)
class IngestionResult:
    application_id: str
    package_versions: int
    dependency_edges: int
    direct_dependencies: int
    lockfile_sha256: str


def package_id(name: str, version: str, ecosystem: str = "npm") -> str:
    return f"{ecosystem}:{name}@{version}"


def _package_name(path: str, record: dict[str, Any]) -> str:
    if record.get("name"):
        return str(record["name"])
    marker = "node_modules/"
    tail = path.rsplit(marker, 1)[-1]
    return tail


def _resolve_dependency_path(parent_path: str, dependency_name: str, installed: set[str]) -> str | None:
    current = parent_path
    if current and "/node_modules/" not in current:
        current = ""
    while True:
        base = current.rsplit("/node_modules/", 1)[0] if "/node_modules/" in current else ""
        candidate = f"{base + '/' if base else ''}node_modules/{dependency_name}"
        if candidate in installed:
            return candidate
        if not base:
            break
        current = base
    fallback = f"node_modules/{dependency_name}"
    return fallback if fallback in installed else None


def ingest_package_lock(
    graph: GraphStore,
    application: Application,
    lockfile: dict[str, Any],
) -> IngestionResult:
    packages = lockfile.get("packages")
    if not isinstance(packages, dict) or "" not in packages:
        raise ValueError("package-lock.json must use lockfileVersion 2 or 3 and include packages['']")

    graph.add_application(application)
    path_to_id: dict[str, str] = {}
    installed_paths = {path for path in packages if path}

    for path, record in sorted(packages.items()):
        if not path or not isinstance(record, dict) or not record.get("version"):
            continue
        name = _package_name(path, record)
        version = str(record["version"])
        identifier = package_id(name, version)
        path_to_id[path] = identifier
        graph.add_package(PackageVersion(identifier, name, version))

    root_record = packages.get("", {})
    direct_names = set(root_record.get("dependencies", {})) | set(root_record.get("optionalDependencies", {}))
    direct_count = 0
    for dependency_name in sorted(direct_names):
        resolved_path = _resolve_dependency_path("", dependency_name, installed_paths)
        if resolved_path and resolved_path in path_to_id:
            graph.declare_dependency(application.id, path_to_id[resolved_path])
            direct_count += 1

    edges: set[tuple[str, str]] = set()
    for path, record in sorted(packages.items()):
        if not path or path not in path_to_id or not isinstance(record, dict):
            continue
        dependency_names = set(record.get("dependencies", {})) | set(record.get("optionalDependencies", {}))
        for dependency_name in sorted(dependency_names):
            resolved_path = _resolve_dependency_path(path, dependency_name, installed_paths)
            if resolved_path and resolved_path in path_to_id:
                edge = (path_to_id[path], path_to_id[resolved_path])
                if edge not in edges:
                    graph.add_dependency(*edge)
                    edges.add(edge)

    raw = json.dumps(lockfile, sort_keys=True, separators=(",", ":")).encode()
    return IngestionResult(
        application_id=application.id,
        package_versions=len(set(path_to_id.values())),
        dependency_edges=len(edges),
        direct_dependencies=direct_count,
        lockfile_sha256=hashlib.sha256(raw).hexdigest(),
    )

