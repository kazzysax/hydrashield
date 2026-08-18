#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_root"

cleanup() {
  docker compose logs --no-color > /tmp/hydrashield-docker-boot.log 2>&1 || true
  docker compose down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

for command_name in docker curl python3; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "required command is unavailable: $command_name" >&2
    exit 2
  fi
done

if ! docker compose version >/dev/null 2>&1; then
  echo "Docker Compose v2 is required" >&2
  exit 2
fi

mkdir -p hydradb-data/store hydradb-data/cache
printf '%s\n' 'local-development-token-32-bytes' > hydradb-data/auth-token

export UID="$(id -u)"
export GID="$(id -g)"

docker compose pull hydradb
docker compose build app
docker compose up -d hydradb

hydra_ready=false
for _ in $(seq 1 60); do
  if curl -fsS http://127.0.0.1:9090/readyz >/dev/null 2>&1; then
    hydra_ready=true
    break
  fi
  sleep 2
done
if [ "$hydra_ready" != true ]; then
  echo "HydraDB did not become ready within 120 seconds" >&2
  docker compose logs --no-color hydradb >&2 || true
  exit 1
fi

docker compose up -d app

app_ready=false
for _ in $(seq 1 60); do
  if curl -fsS http://127.0.0.1:8080/api/health > /tmp/hydrashield-health.json 2>/dev/null; then
    app_ready=true
    break
  fi
  sleep 2
done
if [ "$app_ready" != true ]; then
  echo "HydraShield did not become ready within 120 seconds" >&2
  docker compose logs --no-color app >&2 || true
  exit 1
fi

python3 - <<'PY'
import json
import urllib.request

def get(path):
    with urllib.request.urlopen(f"http://127.0.0.1:8080{path}", timeout=10) as response:
        return json.load(response)

health = get("/api/health")
if health.get("backend") != "HydraDBGraph":
    raise SystemExit(f"wrong graph backend: {health}")

overview = get("/api/overview")
summary = overview.get("summary", {})
expected = {
    "applications_exposed": 6,
    "production_exposed": 4,
    "direct_exposure": 1,
    "transitive_exposure": 5,
    "evidence_paths": 6,
}
for key, value in expected.items():
    if summary.get(key) != value:
        raise SystemExit(f"unexpected {key}: wanted {value}, got {summary.get(key)}")

counts = overview.get("graph_counts", {})
if counts.get("applications") != 6 or counts.get("advisories") != 1:
    raise SystemExit(f"HydraDB round-trip counts failed: {counts}")

print(json.dumps({
    "status": "docker-boot-test-passed",
    "backend": health["backend"],
    "summary": summary,
    "graph_counts": counts,
}, indent=2))
PY

