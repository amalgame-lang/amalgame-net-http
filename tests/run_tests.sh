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
if [ -n "$AMC_RUNTIME" ] && [ -d "$AMC_RUNTIME" ]; then
    RUNTIME_DIR="$AMC_RUNTIME"
elif [ -d "$PKG_DIR/../Amalgame/runtime" ]; then
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

# v0.4.6: facade.am split across multiple source files (cookie,
# http_request, http_response, http_parser, http_server, http_client).
# Order matches amalgame.toml's `sources = [...]` for cross-file refs.
NETHTTP_SOURCES="facade.am cookie.am http_request.am http_response.am http_parser.am http_server.am http_client.am"
NETHTTP_EXTERNAL_FLAGS=""
for src in $NETHTTP_SOURCES; do
    NETHTTP_EXTERNAL_FLAGS="$NETHTTP_EXTERNAL_FLAGS --external $src"
done

# ── Build facade.o once ───────────────────────────────────────────
echo -e "\n── Building facade.o ──"
"$AMC" --lib -o "$BUILD_DIR/facade" $NETHTTP_SOURCES 2>&1 | tail -2
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
    "$AMC" -o "$out" "$src" $NETHTTP_EXTERNAL_FLAGS 2>&1 | tail -2
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

# ── HttpServerConfig C smoke (no sockets, no AM) ──────────────────
# The class is a C-struct backed by stdlib.functions; testing it
# from AM requires the full `amc package add` flow (the manifest
# registers the class + functions, which --external doesn't). A
# direct C smoke against the runtime header is the right scope
# here — consumers (amalgame-web's RateLimit etc.) exercise the
# AM-facing surface once installed.
echo -e "\n── HttpServerConfig C smoke ──"
cat > "$BUILD_DIR/cfg_smoke.c" <<'EOF'
#include "Amalgame_Net_Http.h"
#include <stdio.h>
int main(void) {
    GC_INIT();
    AmalgameNetHttpServerConfig* c = Amalgame_Net_Http_HttpServerConfig_Default();
    int ok_default = (Amalgame_Net_Http_HttpServerConfig_HeaderTimeoutSec(c) == 0
                   && Amalgame_Net_Http_HttpServerConfig_BodyTimeoutSec(c)   == 0
                   && Amalgame_Net_Http_HttpServerConfig_MaxBodyBytes(c)     == 0);
    Amalgame_Net_Http_HttpServerConfig_WithHeaderTimeoutSec(c, 5);
    Amalgame_Net_Http_HttpServerConfig_WithBodyTimeoutSec(c, 30);
    Amalgame_Net_Http_HttpServerConfig_WithMaxBodyBytes(c, 1048576);
    Amalgame_Net_Http_HttpServerConfig_WithListenBacklog(c, 128);
    int ok_set = (Amalgame_Net_Http_HttpServerConfig_HeaderTimeoutSec(c) == 5
               && Amalgame_Net_Http_HttpServerConfig_BodyTimeoutSec(c)   == 30
               && Amalgame_Net_Http_HttpServerConfig_MaxBodyBytes(c)     == 1048576
               && Amalgame_Net_Http_HttpServerConfig_ListenBacklog(c)    == 128);
    /* ApplyToFd on -1 must be a quiet no-op (defensive null/bad-fd path). */
    Amalgame_Net_Http_HttpServerConfig_ApplyToFd(-1, c);
    Amalgame_Net_Http_HttpServerConfig_ApplyToFd(0, NULL);
    printf("default_zero: %d\n", ok_default);
    printf("builder_roundtrip: %d\n", ok_set);
    return 0;
}
EOF
gcc -O2 -Iruntime -I"$RUNTIME_DIR" "$BUILD_DIR/cfg_smoke.c" \
    -lgc -o "$BUILD_DIR/cfg_smoke" 2>&1 | head -5
if [ ! -x "$BUILD_DIR/cfg_smoke" ]; then
    echo -e "${RED}FAIL${NC} (HttpServerConfig smoke build)"
    exit 1
fi
CFG_OUT=$("$BUILD_DIR/cfg_smoke")
echo "$CFG_OUT"
if echo "$CFG_OUT" | grep -q "default_zero: 1" && \
   echo "$CFG_OUT" | grep -q "builder_roundtrip: 1"; then
    echo -e "${GREEN}PASS${NC} (HttpServerConfig default + builders + ApplyToFd no-op)"
else
    echo -e "${RED}FAIL${NC} (HttpServerConfig smoke output unexpected)"
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

# ── h2c smoke (HTTP/2 cleartext via nghttp2, v0.2+) ──────────────
# Mirrors amalgame-tls's smoke pattern: the AM-level e2e would need
# the package-loader to register itself (chicken-and-egg), so we
# verify the runtime header builds + nghttp2 links from a small C
# program. The full AM-level path is exercised by user code in
# downstream demos / amalgame-web.
echo -e "\n── h2c smoke (header + nghttp2 link) ──"
cat > "$BUILD_DIR/h2c_smoke.c" <<EOF
#include "Amalgame_Net_Http.h"
#include <stdio.h>
int main(void) {
    GC_INIT();
    i64 avail = Amalgame_Net_Http_H2_Available();
    AmalgameH2Server* srv = Amalgame_Net_Http_H2Server_Listen(0, 0);
    int listening = Amalgame_Net_Http_H2Server_IsListening(srv);
    Amalgame_Net_Http_H2Server_Close(srv);
    printf("H2_Available: %lld\n", (long long)avail);
    printf("H2Server_Listen(0) ok: %d\n", listening);
    return 0;
}
EOF
gcc -O2 -Iruntime -I"$RUNTIME_DIR" "$BUILD_DIR/h2c_smoke.c" \
    -lnghttp2 -lgc -o "$BUILD_DIR/h2c_smoke" 2>&1 | head -5
if [ ! -x "$BUILD_DIR/h2c_smoke" ]; then
    echo -e "${RED}FAIL${NC} (h2c smoke build)"
    exit 1
fi
SMOKE_OUT=$("$BUILD_DIR/h2c_smoke")
echo "$SMOKE_OUT"
if echo "$SMOKE_OUT" | grep -q "H2_Available: 1" && \
   echo "$SMOKE_OUT" | grep -q "H2Server_Listen(0) ok: 1"; then
    echo -e "${GREEN}PASS${NC} (nghttp2 detected + linked, H2Server listens)"
else
    echo -e "${RED}FAIL${NC} (nghttp2 not detected at compile time)"
    exit 1
fi

echo -e "\n${GREEN}All tests completed${NC}"
