#!/bin/bash
# ─────────────────────────────────────────────────────
#  amalgame-net-http — Test Runner
#  Usage: ./tests/run_tests.sh [path-to-amc]
# ─────────────────────────────────────────────────────
set -e

PKG_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TESTS_DIR="$PKG_DIR/tests"

# Resolve `amc`.
AMC=""
if [ -n "$1" ]; then
    AMC="$1"
elif [ -x "./amc" ]; then
    AMC="$(pwd)/amc"
elif command -v amc >/dev/null 2>&1; then
    AMC="$(command -v amc)"
elif [ -x "$PKG_DIR/../Amalgame/amc" ]; then
    AMC="$PKG_DIR/../Amalgame/amc"
elif [ -x "$HOME/.local/bin/amc" ]; then
    AMC="$HOME/.local/bin/amc"
elif [ -x "$HOME/.amalgame/bin/amc" ]; then
    AMC="$HOME/.amalgame/bin/amc"
fi

if [ -z "$AMC" ] || [ ! -x "$AMC" ]; then
    echo "error: amc binary not found"
    echo "  pass an explicit path:  ./tests/run_tests.sh /path/to/amc"
    exit 2
fi
echo "Using amc: $AMC"

BUILD_DIR=$(mktemp -d -t amalgame-net-http-XXXXXX)
trap 'rm -rf "$BUILD_DIR"; [ -n "$SERVER_PID" ] && kill $SERVER_PID 2>/dev/null' EXIT

# Resolve the runtime headers dir (need it for gcc -I).
RUNTIME_DIR=""
if [ -d "$PKG_DIR/../Amalgame/runtime" ]; then
    RUNTIME_DIR="$PKG_DIR/../Amalgame/runtime"
elif [ -d "$HOME/.amalgame/runtime" ]; then
    RUNTIME_DIR="$HOME/.amalgame/runtime"
fi
if [ -z "$RUNTIME_DIR" ]; then
    echo "error: Amalgame runtime headers not found (need <runtime/Amalgame_*.h>)"
    exit 2
fi

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

cd "$PKG_DIR"

# ── Build facade.o once ───────────────────────────────────────────
echo -e "\n── Building facade.o ──"
"$AMC" --lib -o "$BUILD_DIR/facade" facade.am 2>&1 | tail -2
gcc -O2 -Iruntime -I"$RUNTIME_DIR" -c "$BUILD_DIR/facade.c" -o "$BUILD_DIR/facade.o" 2>&1 | head -5
if [ ! -s "$BUILD_DIR/facade.o" ]; then
    echo -e "${RED}FAIL${NC} (facade compile)"
    exit 1
fi
echo -e "${GREEN}facade.o ready${NC}"

# Helper to build a test binary linking against facade.o.
build_test() {
    local src="$1"
    local out="$2"
    "$AMC" -o "$out" "$src" --external facade.am 2>&1 | tail -2
    gcc -O2 -Iruntime -I"$RUNTIME_DIR" "$out.c" "$BUILD_DIR/facade.o" \
        -lgc -lm -lcurl -lz -o "$out" 2>&1 | head -5
    [ -x "$out" ]
}

# ── Parser unit tests (no sockets) ────────────────────────────────
echo -e "\n── Parser unit tests ──"
if build_test tests/parser_test.am "$BUILD_DIR/parser_test"; then
    "$BUILD_DIR/parser_test"
else
    echo -e "${RED}FAIL${NC} (parser test build)"
    exit 1
fi

# ── End-to-end (server + client as separate processes) ────────────
echo -e "\n── End-to-end test (server + client) ──"
build_test tests/server_test.am "$BUILD_DIR/server_test" || { echo "server build failed"; exit 1; }
build_test tests/client_test.am "$BUILD_DIR/client_test" || { echo "client build failed"; exit 1; }

"$BUILD_DIR/server_test" &
SERVER_PID=$!
sleep 0.3
"$BUILD_DIR/client_test"
wait $SERVER_PID 2>/dev/null || true
SERVER_PID=""

echo -e "\n${GREEN}All tests completed${NC}"
