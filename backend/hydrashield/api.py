from __future__ import annotations

import argparse
import json
import mimetypes
import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .graph import InMemoryGraph
from .hydradb import HydraDBError, HydraDBGraph
from .models import Application
from .ingest import ingest_package_lock
from .advisories import ingest_osv_advisory
from .service import HydraShieldService, seed_six_minute_demo


def build_graph():
    backend = os.getenv("HYDRASHIELD_GRAPH_BACKEND", "memory").lower()
    if backend == "hydradb":
        return HydraDBGraph()
    if backend == "memory":
        return InMemoryGraph()
    raise ValueError(f"Unsupported graph backend: {backend}")


class HydraShieldHandler(BaseHTTPRequestHandler):
    graph = build_graph()
    service = HydraShieldService(graph)
    default_advisory = "GHSA-HYDRA-2026-0001"
    web_root = Path(os.getenv("HYDRASHIELD_WEB_ROOT", Path(__file__).resolve().parents[2] / "web"))

    def log_message(self, fmt: str, *args) -> None:
        print(f"[hydrashield] {self.address_string()} - {fmt % args}")

    def _json(self, payload, status: int = 200) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        size = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(size) or b"{}")

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        try:
            if parsed.path == "/api/health":
                self._json({"status": "ok", "backend": type(self.graph).__name__})
                return
            if parsed.path == "/api/overview":
                query = parse_qs(parsed.query)
                advisory_id = query.get("advisory_id", [self.default_advisory])[0]
                self._json(self.service.analyze(advisory_id))
                return
            self._serve_static(parsed.path)
        except KeyError as error:
            self._json({"error": str(error)}, HTTPStatus.NOT_FOUND)
        except (ValueError, json.JSONDecodeError) as error:
            self._json({"error": str(error)}, HTTPStatus.BAD_REQUEST)
        except HydraDBError as error:
            self._json({"error": str(error), "backend": "HydraDB"}, HTTPStatus.BAD_GATEWAY)
        except Exception as error:  # pragma: no cover - final server boundary
            self._json({"error": str(error)}, HTTPStatus.INTERNAL_SERVER_ERROR)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        try:
            if parsed.path == "/api/demo/reset":
                self.default_advisory = seed_six_minute_demo(self.graph)
                self._json(self.service.analyze(self.default_advisory), HTTPStatus.CREATED)
                return
            if parsed.path == "/api/ingest/package-lock":
                payload = self._read_json()
                app_payload = payload.get("application", {})
                application = Application(
                    str(app_payload["id"]),
                    str(app_payload["name"]),
                    str(app_payload.get("environment", "production")),
                    str(app_payload.get("repository", "")),
                    str(app_payload.get("criticality", "medium")),
                )
                result = ingest_package_lock(self.graph, application, payload["lockfile"])
                self._json(result.__dict__, HTTPStatus.CREATED)
                return
            if parsed.path == "/api/ingest/osv":
                advisory = ingest_osv_advisory(self.graph, self._read_json())
                self.default_advisory = advisory.id
                self._json({"advisory_id": advisory.id, "affected_versions": list(advisory.affected_versions)}, HTTPStatus.CREATED)
                return
            self._json({"error": "Not found"}, HTTPStatus.NOT_FOUND)
        except (KeyError, ValueError, json.JSONDecodeError) as error:
            self._json({"error": str(error)}, HTTPStatus.BAD_REQUEST)
        except HydraDBError as error:
            self._json({"error": str(error), "backend": "HydraDB"}, HTTPStatus.BAD_GATEWAY)

    def _serve_static(self, path: str) -> None:
        relative = "index.html" if path in ("", "/") else path.lstrip("/")
        candidate = (self.web_root / relative).resolve()
        if self.web_root.resolve() not in candidate.parents and candidate != self.web_root.resolve():
            self._json({"error": "Not found"}, HTTPStatus.NOT_FOUND)
            return
        if not candidate.is_file():
            candidate = self.web_root / "index.html"
        body = candidate.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", mimetypes.guess_type(candidate.name)[0] or "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    parser = argparse.ArgumentParser(description="HydraShield local application")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=int(os.getenv("HYDRASHIELD_PORT", "8080")))
    parser.add_argument("--demo", action="store_true", help="Seed the six-minute compromise scenario")
    args = parser.parse_args()
    if args.demo:
        HydraShieldHandler.default_advisory = seed_six_minute_demo(HydraShieldHandler.graph)
    server = ThreadingHTTPServer((args.host, args.port), HydraShieldHandler)
    print(f"HydraShield running at http://{args.host}:{args.port}")
    print(f"Graph backend: {type(HydraShieldHandler.graph).__name__}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
