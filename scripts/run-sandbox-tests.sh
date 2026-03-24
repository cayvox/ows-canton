#!/usr/bin/env bash
set -euo pipefail

# ── Canton Sandbox Integration Test Runner ──────────────────────────
#
# Starts a Canton Sandbox in Docker, waits for it to be ready,
# runs the integration tests, then tears down the container.
#
# Usage:
#   ./scripts/run-sandbox-tests.sh
#
# Requirements:
#   - Docker
#   - Canton 3.4+ image (JSON Ledger API v2)
#     Set CANTON_IMAGE to override the default image.
#
# Note: Canton 2.x (digitalasset/canton-open-source:latest) uses gRPC
# only. The JSON API v2 endpoints (/v2/...) require Canton 3.4+.
# When a public Canton 3.4+ Docker image becomes available, update
# CANTON_IMAGE below.

CANTON_IMAGE="${CANTON_IMAGE:-digitalasset/canton-open-source:latest}"
CONTAINER_NAME="ows-canton-sandbox-test"
LEDGER_PORT=7575
ADMIN_PORT=7576
CONFIG_PATH="$(cd "$(dirname "$0")/.." && pwd)/ows-canton/tests/fixtures/canton_sandbox.conf"
MAX_WAIT_SECONDS=120

cleanup() {
    echo "Stopping Canton Sandbox..."
    docker rm -f "$CONTAINER_NAME" 2>/dev/null || true
}
trap cleanup EXIT

echo "=== OWS Canton Integration Tests ==="
echo "Image:  $CANTON_IMAGE"
echo "Config: $CONFIG_PATH"
echo ""

# ── 1. Start Canton Sandbox ─────────────────────────────────────────

echo "Starting Canton Sandbox..."
docker rm -f "$CONTAINER_NAME" 2>/dev/null || true
docker run -d \
    --name "$CONTAINER_NAME" \
    -p "${LEDGER_PORT}:${LEDGER_PORT}" \
    -p "${ADMIN_PORT}:${ADMIN_PORT}" \
    -v "${CONFIG_PATH}:/canton/config.conf:ro" \
    "$CANTON_IMAGE" \
    daemon --auto-connect-local -c /canton/config.conf

# ── 2. Wait for Canton to be ready ──────────────────────────────────

echo "Waiting for Canton Sandbox to be ready..."
elapsed=0
while [ "$elapsed" -lt "$MAX_WAIT_SECONDS" ]; do
    # Try JSON API health endpoint (Canton 3.4+)
    if curl -sf "http://localhost:${LEDGER_PORT}/health" >/dev/null 2>&1; then
        echo "Canton Sandbox ready (JSON API) after ${elapsed}s"
        break
    fi

    # Try gRPC health via HTTP/2 (Canton 2.x)
    if curl -sf --http2-prior-knowledge "http://localhost:${LEDGER_PORT}/" >/dev/null 2>&1; then
        echo ""
        echo "WARNING: Canton is responding with gRPC (Canton 2.x detected)."
        echo "         The JSON Ledger API v2 requires Canton 3.4+."
        echo "         Integration tests targeting /v2/... endpoints will fail."
        echo "         Set CANTON_IMAGE to a Canton 3.4+ image and retry."
        echo ""
        break
    fi

    sleep 3
    elapsed=$((elapsed + 3))
done

if [ "$elapsed" -ge "$MAX_WAIT_SECONDS" ]; then
    echo "TIMEOUT: Canton did not start within ${MAX_WAIT_SECONDS}s"
    echo "Container logs:"
    docker logs "$CONTAINER_NAME" 2>&1 | tail -30
    exit 1
fi

# ── 3. Run integration tests ───────────────────────────────────────

echo ""
echo "Running integration tests..."
echo ""

cd "$(dirname "$0")/.."
cargo test -p ows-canton --features integration-tests -- --test-threads=1 2>&1
TEST_EXIT=$?

echo ""
if [ "$TEST_EXIT" -eq 0 ]; then
    echo "=== All integration tests passed ==="
else
    echo "=== Some integration tests failed (exit code: $TEST_EXIT) ==="
fi

exit "$TEST_EXIT"
