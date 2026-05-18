#!/bin/bash
# ─────────────────────────────────────────────────────
#  amalgame-net-http — Test Runner
#  Usage: ./tests/run_tests.sh [path-to-amc]
# ─────────────────────────────────────────────────────
set -e

PKG_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TESTS_DIR="$PKG_DIR/tests"

# Resolve `amc` — explicit arg wins, else $PATH, sibling Amalgame
# checkout, then the user's amalgame bin dir.
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
trap 'rm -rf "$BUILD_DIR"' EXIT

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

run_test() {
    local name="$1"
    local file="$2"
    echo -e "\n── $name ──"
    cd "$PKG_DIR"
    "$AMC" -o "$BUILD_DIR/$(basename "${file%.am}")" "$file" "$PKG_DIR/facade.am" 2>&1 | tail -3
    local out="$BUILD_DIR/$(basename "${file%.am}")"
    if [ ! -x "$out" ]; then
        echo -e "${RED}FAIL${NC} (amc build failed)"
        return 1
    fi
    "$out"
}

run_test "Parser unit tests" tests/parser_test.am
run_test "End-to-end (server + client)" tests/e2e_test.am

echo -e "\n${GREEN}All tests completed${NC}"
