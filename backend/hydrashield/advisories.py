from __future__ import annotations

from typing import Any

from .graph import GraphStore
from .ingest import package_id
from .models import Advisory


def ingest_osv_advisory(graph: GraphStore, payload: dict[str, Any]) -> Advisory:
    """Ingest exact versions from an OSV-format advisory.

    OSV ranges without an expanded ``versions`` list are intentionally not
    guessed. This keeps the trusted MVP exact; semver range expansion belongs
    in an ecosystem-aware preprocessing step.
    """
    advisory_id = str(payload["id"])
    summary = str(payload.get("summary") or payload.get("details") or "No summary provided")
    published_at = str(payload.get("published", ""))
    severity_entries = payload.get("severity", [])
    severity = str(payload.get("database_specific", {}).get("severity", "critical")).lower()
    if severity_entries and not payload.get("database_specific", {}).get("severity"):
        severity = "high"

    package_name = ""
    versions: set[str] = set()
    package_ids: set[str] = set()
    for affected in payload.get("affected", []):
        package = affected.get("package", {})
        ecosystem = str(package.get("ecosystem", "npm")).lower()
        name = str(package.get("name", ""))
        if not name:
            continue
        package_name = package_name or name
        for version in affected.get("versions", []):
            value = str(version)
            versions.add(value)
            package_ids.add(package_id(name, value, ecosystem))

    if not package_name or not versions:
        raise ValueError("OSV advisory must include an affected package and an expanded versions list")

    references = payload.get("references", [])
    source_url = str(references[0].get("url", "")) if references else ""
    advisory = Advisory(
        advisory_id,
        package_name,
        tuple(sorted(versions)),
        severity,
        summary,
        published_at,
        source_url,
    )
    graph.add_advisory(advisory, sorted(package_ids))
    return advisory

