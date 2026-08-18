from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import asdict
from typing import Any

from .models import Advisory, Application, EvidencePath, PackageVersion


def _literal(value: Any) -> str:
    """Encode a primitive as an OpenCypher literal."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return "'" + str(value).replace("\\", "\\\\").replace("'", "\\'") + "'"


def _props(data: dict[str, Any]) -> str:
    return "{" + ", ".join(f"{key}: {_literal(value)}" for key, value in data.items()) + "}"


def _unwrap(value: Any) -> Any:
    if isinstance(value, dict) and "value" in value and "type" in value:
        return _unwrap(value["value"])
    if isinstance(value, dict):
        return {key: _unwrap(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_unwrap(item) for item in value]
    return value


class HydraDBError(RuntimeError):
    pass


class HydraDBGraph:
    """HydraDB OSS adapter using its authenticated HTTPS/OpenCypher endpoint.

    The adapter intentionally issues graph mutations and traversals directly.
    HydraDB is therefore the authoritative data and reasoning layer, not a
    decorative integration around an in-process dependency engine.
    """

    def __init__(
        self,
        base_url: str | None = None,
        token: str | None = None,
        graph: str | None = None,
        namespace: str | None = None,
        cell: str | None = None,
    ) -> None:
        self.base_url = (base_url or os.getenv("HYDRADB_URL", "http://127.0.0.1:8443")).rstrip("/")
        self.token = token or os.getenv("HYDRADB_TOKEN", "local-development-token-32-bytes")
        self.graph = graph or os.getenv("HYDRADB_GRAPH", "default")
        self.namespace = namespace or os.getenv("HYDRADB_NAMESPACE", "default")
        self.cell = cell or os.getenv("HYDRADB_CELL", "cell-0")
        self._advisory_cache: dict[str, Advisory] = {}

    def _query(self, query: str) -> list[dict[str, Any]]:
        request = urllib.request.Request(
            f"{self.base_url}/v1/graphs/{self.graph}/query",
            data=json.dumps({"cell_id": self.cell, "query": query}).encode(),
            headers={
                "Authorization": f"Bearer {self.token}",
                "X-Graph-Namespace": self.namespace,
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                payload = json.loads(response.read().decode() or "{}")
        except urllib.error.HTTPError as error:
            detail = error.read().decode(errors="replace")
            raise HydraDBError(f"HydraDB query failed ({error.code}): {detail}") from error
        except urllib.error.URLError as error:
            raise HydraDBError(f"Cannot reach HydraDB at {self.base_url}: {error.reason}") from error

        unwrapped = _unwrap(payload)
        for key in ("rows", "results", "data"):
            value = unwrapped.get(key) if isinstance(unwrapped, dict) else None
            if isinstance(value, list):
                return [row if isinstance(row, dict) else {"value": row} for row in value]
            if isinstance(value, dict):
                for nested in ("rows", "results"):
                    if isinstance(value.get(nested), list):
                        return value[nested]
        return []

    def reset(self) -> None:
        # HydraShield uses a fresh competition/demo graph. MATCH/DETACH DELETE is
        # attempted for repeatable local demos; a first run naturally has no data.
        try:
            self._query("MATCH (n) DETACH DELETE n")
        except HydraDBError:
            pass
        self._advisory_cache.clear()

    def _exists(self, query: str) -> bool:
        rows = self._query(query)
        return bool(rows and int(rows[0].get("total", 0)) > 0)

    def add_application(self, application: Application) -> None:
        if not self._exists(
            "MATCH (n:Application {id: " + _literal(application.id) + "}) RETURN count(n) AS total"
        ):
            self._query(f"CREATE (:Application {_props(asdict(application))})")

    def add_package(self, package: PackageVersion) -> None:
        if not self._exists(
            "MATCH (n:PackageVersion {id: " + _literal(package.id) + "}) RETURN count(n) AS total"
        ):
            self._query(f"CREATE (:PackageVersion {_props(asdict(package))})")

    def add_dependency(self, parent_id: str, child_id: str) -> None:
        exists = self._exists(
            "MATCH (a:PackageVersion {id: " + _literal(parent_id) + "})"
            "-[r:DEPENDS_ON]->(b:PackageVersion {id: " + _literal(child_id) + "}) "
            "RETURN count(r) AS total"
        )
        if not exists:
            self._query(
                "MATCH (a:PackageVersion {id: " + _literal(parent_id) + "}), "
                "(b:PackageVersion {id: " + _literal(child_id) + "}) "
                "CREATE (a)-[:DEPENDS_ON]->(b)"
            )

    def declare_dependency(self, application_id: str, package_id: str) -> None:
        exists = self._exists(
            "MATCH (a:Application {id: " + _literal(application_id) + "})"
            "-[r:DECLARES]->(p:PackageVersion {id: " + _literal(package_id) + "}) "
            "RETURN count(r) AS total"
        )
        if not exists:
            self._query(
                "MATCH (a:Application {id: " + _literal(application_id) + "}), "
                "(p:PackageVersion {id: " + _literal(package_id) + "}) "
                "CREATE (a)-[:DECLARES]->(p)"
            )

    def add_advisory(self, advisory: Advisory, affected_package_ids: list[str]) -> None:
        values = asdict(advisory)
        values["affected_versions"] = ",".join(advisory.affected_versions)
        if not self._exists(
            "MATCH (n:Advisory {id: " + _literal(advisory.id) + "}) RETURN count(n) AS total"
        ):
            self._query(f"CREATE (:Advisory {_props(values)})")
        for package_id in affected_package_ids:
            exists = self._exists(
                "MATCH (a:Advisory {id: " + _literal(advisory.id) + "})"
                "-[r:AFFECTS]->(p:PackageVersion {id: " + _literal(package_id) + "}) "
                "RETURN count(r) AS total"
            )
            if not exists:
                self._query(
                    "MATCH (a:Advisory {id: " + _literal(advisory.id) + "}), "
                    "(p:PackageVersion {id: " + _literal(package_id) + "}) "
                    "CREATE (a)-[:AFFECTS]->(p)"
                )
        self._advisory_cache[advisory.id] = advisory

    def get_advisory(self, advisory_id: str) -> Advisory | None:
        cached = self._advisory_cache.get(advisory_id)
        if cached:
            return cached
        rows = self._query(
            "MATCH (a:Advisory {id: " + _literal(advisory_id) + "}) RETURN "
            "a.id AS id, a.package_name AS package_name, "
            "a.affected_versions AS affected_versions, a.severity AS severity, "
            "a.summary AS summary, a.published_at AS published_at, a.source_url AS source_url"
        )
        if not rows:
            return None
        row = rows[0]
        advisory = Advisory(
            str(row["id"]),
            str(row["package_name"]),
            tuple(str(row["affected_versions"]).split(",")),
            str(row["severity"]),
            str(row["summary"]),
            str(row["published_at"]),
            str(row.get("source_url", "")),
        )
        self._advisory_cache[advisory.id] = advisory
        return advisory

    def evidence_paths(self, advisory_id: str, max_depth: int = 12) -> list[EvidencePath]:
        """Return exact fixed-depth paths.

        Fixed-depth MATCH queries keep the transport payload scalar and easy to
        audit while still executing every traversal inside HydraDB. The query
        set covers direct dependencies (depth 0) through max_depth.
        """
        paths: list[EvidencePath] = []
        seen: set[tuple[str, tuple[str, ...]]] = set()
        for depth in range(max_depth + 1):
            nodes = [f"n{index}" for index in range(depth + 1)]
            chain = ""
            if depth:
                chain = "".join(f"-[:DEPENDS_ON]->({node}:PackageVersion)" for node in nodes[1:])
            match = (
                "MATCH (adv:Advisory {id: " + _literal(advisory_id) + "})-[:AFFECTS]->(bad:PackageVersion) "
                "MATCH (app:Application)-[:DECLARES]->(n0:PackageVersion)" + chain + " "
                f"WHERE {nodes[-1]}.id = bad.id RETURN "
                "app.id AS app_id, app.name AS app_name, app.environment AS environment, "
                "app.repository AS repository, app.criticality AS criticality, "
                + ", ".join(
                    f"{node}.id AS p{index}_id, {node}.name AS p{index}_name, {node}.version AS p{index}_version"
                    for index, node in enumerate(nodes)
                )
            )
            for row in self._query(match):
                package_nodes = tuple(
                    PackageVersion(
                        str(row[f"p{index}_id"]),
                        str(row[f"p{index}_name"]),
                        str(row[f"p{index}_version"]),
                    )
                    for index in range(depth + 1)
                )
                key = (str(row["app_id"]), tuple(node.id for node in package_nodes))
                if key in seen:
                    continue
                seen.add(key)
                paths.append(
                    EvidencePath(
                        Application(
                            str(row["app_id"]),
                            str(row["app_name"]),
                            str(row.get("environment", "production")),
                            str(row.get("repository", "")),
                            str(row.get("criticality", "medium")),
                        ),
                        package_nodes,
                        advisory_id,
                    )
                )
        return paths

    def counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        queries = {
            "applications": "MATCH (n:Application) RETURN count(n) AS total",
            "package_versions": "MATCH (n:PackageVersion) RETURN count(n) AS total",
            "dependency_edges": "MATCH (:PackageVersion)-[r:DEPENDS_ON]->(:PackageVersion) RETURN count(r) AS total",
            "advisories": "MATCH (n:Advisory) RETURN count(n) AS total",
        }
        for key, query in queries.items():
            rows = self._query(query)
            counts[key] = int(rows[0].get("total", 0)) if rows else 0
        return counts
