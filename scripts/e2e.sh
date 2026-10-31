#!/usr/bin/env bash
#
# e2e.sh — test the whole security chain: the production Caddy with the guard
# snippets from deploy/auth.caddy, the gateway image built from this
# repository, and an app that echoes what it receives. See e2e/chain_test.go.
#
# Needs Docker with Compose v2 and Go. Run from anywhere:  scripts/e2e.sh
# Leaves nothing behind; on failure it prints the gateway's and Caddy's logs.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PROJECT=vpsauth-e2e
export E2E_PORT="${E2E_PORT:-18443}"
export E2E_ADDR="127.0.0.1:$E2E_PORT"
export E2E_COMPOSE="docker compose -p $PROJECT -f $ROOT/e2e/compose.yml"
export E2E_CA="$ROOT/e2e/.root.crt"
# Fresh keys for every run; they never leave the test stack.
E2E_SESSION_SECRET="$(openssl rand -hex 32)"
E2E_DATA_KEY="$(openssl rand -hex 32)"
export E2E_SESSION_SECRET E2E_DATA_KEY

cleanup() {
  status=$?
  if [ "$status" != 0 ]; then
    echo "--- gateway log ---" >&2
    $E2E_COMPOSE logs --no-color auth >&2 || true
    echo "--- caddy log ---" >&2
    $E2E_COMPOSE logs --no-color caddy >&2 || true
  fi
  $E2E_COMPOSE down -v --remove-orphans >/dev/null 2>&1 || true
  rm -f "$E2E_CA"
  exit "$status"
}
trap cleanup EXIT

$E2E_COMPOSE down -v --remove-orphans >/dev/null 2>&1 || true
$E2E_COMPOSE up -d --build --wait

# Caddy makes its local CA when it first issues a certificate; ask for one,
# then copy the root out so the test can verify TLS rather than skip it.
for _ in $(seq 1 30); do
  curl -sk -o /dev/null --resolve "auth.e2e.test:$E2E_PORT:127.0.0.1" "https://auth.e2e.test:$E2E_PORT/healthz" && break
  sleep 1
done
$E2E_COMPOSE cp caddy:/data/caddy/pki/authorities/local/root.crt "$E2E_CA"

go test -tags e2e -count=1 -v ./e2e/
