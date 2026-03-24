#!/usr/bin/env bash
set -euo pipefail

# ── Canton Sandbox Integration Test Runner ──────────────────────────
#
# Starts the Canton Sandbox using the DAML SDK, waits for it to be ready,
# runs the integration tests, then shuts down the sandbox.
#
# Usage:
#   ./scripts/run-sandbox-tests.sh
#
# Requirements:
#   - Java 17+ (set JAVA_HOME if needed)
#   - DAML SDK 3.4+ with Canton jar
#     Default: ~/.daml/sdk/3.4.10/canton/canton.jar
#     Override: CANTON_JAR=/path/to/canton.jar
#
# The Canton sandbox HTTP JSON API (Ledger API v2) runs on port 6864.
# Integration tests connect to http://localhost:6864.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Canton jar location
CANTON_JAR="${CANTON_JAR:-$HOME/.daml/sdk/3.4.10/canton/canton.jar}"
JSON_API_PORT="${JSON_API_PORT:-6864}"
GRPC_API_PORT="${GRPC_API_PORT:-6865}"
MAX_WAIT_SECONDS="${MAX_WAIT_SECONDS:-60}"
SANDBOX_PID=""

# Java home detection
if [ -z "${JAVA_HOME:-}" ]; then
    # Try common locations
    for dir in \
        "$HOME/sdk/java/jdk-17.0.18+8/Contents/Home" \
        "/Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home" \
        "/usr/lib/jvm/java-17-openjdk-amd64"; do
        if [ -d "$dir" ]; then
            export JAVA_HOME="$dir"
            break
        fi
    done
fi

if [ -n "${JAVA_HOME:-}" ]; then
    export PATH="$JAVA_HOME/bin:$PATH"
fi

cleanup() {
    if [ -n "$SANDBOX_PID" ] && kill -0 "$SANDBOX_PID" 2>/dev/null; then
        echo ""
        echo "Stopping Canton Sandbox (PID $SANDBOX_PID)..."
        kill "$SANDBOX_PID" 2>/dev/null || true
        wait "$SANDBOX_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo "=== OWS Canton Integration Tests ==="
echo "Canton jar:    $CANTON_JAR"
echo "JSON API port: $JSON_API_PORT"
echo ""

# ── 0. Verify requirements ──────────────────────────────────────────

if ! command -v java >/dev/null 2>&1; then
    echo "ERROR: Java not found. Set JAVA_HOME or install Java 17+."
    exit 1
fi

if [ ! -f "$CANTON_JAR" ]; then
    echo "ERROR: Canton jar not found at $CANTON_JAR"
    echo "       Install DAML SDK 3.4+ or set CANTON_JAR=/path/to/canton.jar"
    exit 1
fi

# ── 1. Start Canton Sandbox ─────────────────────────────────────────

# Check if something is already running on the port
if curl -sf "http://localhost:${JSON_API_PORT}/v2/version" >/dev/null 2>&1; then
    echo "Canton Sandbox already running on port ${JSON_API_PORT} — skipping start"
    SANDBOX_PID=""
else
    echo "Starting Canton Sandbox..."
    java -jar "$CANTON_JAR" sandbox \
        --json-api-port "$JSON_API_PORT" \
        --ledger-api-port "$GRPC_API_PORT" \
        --no-tty \
        > /tmp/canton_sandbox_test.log 2>&1 &
    SANDBOX_PID=$!
    echo "Canton Sandbox PID: $SANDBOX_PID"
fi

# ── 2. Wait for Canton to be ready ──────────────────────────────────

echo "Waiting for Canton Sandbox to be ready on port ${JSON_API_PORT}..."
elapsed=0
while [ "$elapsed" -lt "$MAX_WAIT_SECONDS" ]; do
    if curl -sf "http://localhost:${JSON_API_PORT}/v2/version" >/dev/null 2>&1; then
        echo "Canton Sandbox ready after ${elapsed}s"
        break
    fi

    # Check if canton process died
    if [ -n "$SANDBOX_PID" ] && ! kill -0 "$SANDBOX_PID" 2>/dev/null; then
        echo "ERROR: Canton Sandbox process died. Last log output:"
        tail -30 /tmp/canton_sandbox_test.log 2>/dev/null || true
        exit 1
    fi

    sleep 2
    elapsed=$((elapsed + 2))
done

if [ "$elapsed" -ge "$MAX_WAIT_SECONDS" ]; then
    echo "TIMEOUT: Canton Sandbox did not start within ${MAX_WAIT_SECONDS}s"
    echo "Log output:"
    tail -30 /tmp/canton_sandbox_test.log 2>/dev/null || true
    exit 1
fi

# Confirm the API is responding correctly
VERSION=$(curl -s "http://localhost:${JSON_API_PORT}/v2/version" | python3 -c "import sys,json; print(json.load(sys.stdin).get('version', 'unknown'))" 2>/dev/null || echo "unknown")
echo "Canton version: $VERSION"
echo ""

# ── 3. Run integration tests ───────────────────────────────────────

echo "Running integration tests..."
echo ""

cd "$REPO_ROOT"
cargo test -p ows-canton --features integration-tests -- --test-threads=1 2>&1
TEST_EXIT=$?

echo ""
if [ "$TEST_EXIT" -eq 0 ]; then
    echo "=== All integration tests passed ==="
else
    echo "=== Some integration tests failed (exit code: $TEST_EXIT) ==="
fi

exit "$TEST_EXIT"
