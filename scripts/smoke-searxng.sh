#!/usr/bin/env bash
# scripts/smoke-searxng.sh — bring up the test SearXNG fixture and
# probe its /healthz. Used for spot-checking the docker-compose
# wiring without running the full pytest suite.

set -euo pipefail
ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

if ! command -v docker >/dev/null; then
    echo "docker not on PATH; install Docker Desktop or docker-ce" >&2
    exit 1
fi

echo "==> bringing up docker-compose.searxng-test.yml…"
docker compose -f docker-compose.searxng-test.yml up -d

echo
echo "==> waiting for SearXNG to answer on :8888 (up to 30s)"
for i in $(seq 1 30); do
    if curl -fsS --max-time 1 http://127.0.0.1:8888/healthz >/dev/null 2>&1; then
        echo "OK after ${i}s"
        curl -fsS http://127.0.0.1:8888/healthz
        echo
        break
    fi
    sleep 1
    if [ "$i" = 30 ]; then
        echo "timed out" >&2
        docker compose -f docker-compose.searxng-test.yml logs --tail 30
        exit 1
    fi
done

echo
echo "==> sample query"
curl -fsS "http://127.0.0.1:8888/search?q=test&format=json&engines=duckduckgo,brave" \
    | python3 -m json.tool | head -20

echo
echo "stop with: docker compose -f docker-compose.searxng-test.yml down"
