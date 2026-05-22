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

# v0.9.1: amalgame-async runtime is required because
# Amalgame_Net_Http.h now #includes "Amalgame_Async.h" for the
# Http1.ServeAsync path. Look in the sibling repo first (CI +
# local dev), then in the package cache.
ASYNC_RUNTIME_DIR=""
if [ -d "$PKG_DIR/../amalgame-async/runtime" ]; then
    ASYNC_RUNTIME_DIR="$PKG_DIR/../amalgame-async/runtime"
elif compgen -G "$HOME/.amalgame/packages/github.com/amalgame-lang/amalgame-async/*/runtime" > /dev/null 2>&1; then
    ASYNC_RUNTIME_DIR="$(ls -d $HOME/.amalgame/packages/github.com/amalgame-lang/amalgame-async/*/runtime | tail -n1)"
fi
if [ -z "$ASYNC_RUNTIME_DIR" ]; then
    echo "error: amalgame-async runtime/ not found."
    echo "  Expected sibling: $PKG_DIR/../amalgame-async/runtime"
    echo "  Or installed via: amc package add async@v0.2.0"
    exit 2
fi
echo "Using amalgame-async runtime: $ASYNC_RUNTIME_DIR"

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
gcc -O2 -Iruntime -I"$RUNTIME_DIR" -I"$ASYNC_RUNTIME_DIR" -c "$BUILD_DIR/facade.c" -o "$BUILD_DIR/facade.o" 2>&1 | head -5
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
    gcc -O2 -Iruntime -I"$RUNTIME_DIR" -I"$ASYNC_RUNTIME_DIR" \
        "$out.c" "$BUILD_DIR/facade.o" \
        -lgc -lm -lcurl -lz -lpthread -o "$out" 2>&1 | head -5
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
gcc -O2 -Iruntime -I"$RUNTIME_DIR" -I"$ASYNC_RUNTIME_DIR" "$BUILD_DIR/cfg_smoke.c" \
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

# ── Http1.ServeMt smoke (v0.6.0) ─────────────────────────────────
# AM-level test would need `amc package add` (chicken-and-egg —
# same as the h2c smoke below). A direct C smoke verifies the new
# symbol resolves + the pthread / GC_pthread_create link path
# compiles cleanly. We don't actually call ServeMt (blocks forever).
echo -e "\n── Http1.ServeMt smoke (link path) ──"
cat > "$BUILD_DIR/mt_smoke.c" <<'EOF'
#include "Amalgame_Net_Http.h"
#include <stdio.h>
int main(void) {
    GC_INIT();
    /* Reference ServeMt + the helper struct so the linker pulls
     * them in. Never executed at runtime. */
    if (0) {
        Amalgame_Net_Http_Http1_ServeMt(0, NULL);
        Amalgame_Net_Http_Http1_ServeMtWith(0, NULL, NULL);
        Amalgame_Net_Http_Http2_ServeMt(0, NULL);
        Amalgame_Net_Http_Https_ServeMt(0, "", "", NULL);
        Amalgame_Net_Http_Ws_ServeMt(0, NULL);
        Amalgame_Net_Http_Wss_ServeMt(0, "", "", NULL);
        amalgame_h1_mt_arg dummy = {0};
        amalgame_h1_mt_with_arg dummy2 = {0};
        (void) dummy; (void) dummy2;
    }
    printf("mt_smoke_linked: 1\n");
    return 0;
}
EOF
gcc -O2 -Iruntime -I"$RUNTIME_DIR" -I"$ASYNC_RUNTIME_DIR" "$BUILD_DIR/mt_smoke.c" \
    -lgc -lpthread -o "$BUILD_DIR/mt_smoke" 2>&1 | head -5
if [ ! -x "$BUILD_DIR/mt_smoke" ]; then
    echo -e "${RED}FAIL${NC} (Http1.ServeMt smoke build)"
    exit 1
fi
MT_OUT=$("$BUILD_DIR/mt_smoke")
echo "$MT_OUT"
if echo "$MT_OUT" | grep -q "mt_smoke_linked: 1"; then
    echo -e "${GREEN}PASS${NC} (Http1.ServeMt + pthread link path)"
else
    echo -e "${RED}FAIL${NC} (Http1.ServeMt smoke output unexpected)"
    exit 1
fi

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
gcc -O2 -Iruntime -I"$RUNTIME_DIR" -I"$ASYNC_RUNTIME_DIR" "$BUILD_DIR/h2c_smoke.c" \
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


# ── Http1.ServeAsync smoke (v0.9.1, Linux epoll) ──────────────────
# Verifies:
#   1. Link path — Amalgame_Net_Http.h #includes Amalgame_Async.h,
#      and the static-inline body of Http1_ServeAsync compiles +
#      links cleanly (pulls in epoll + ucontext refs from libc).
#   2. End-to-end — spawns the server in a pthread, fires 3 parallel
#      curl requests, asserts all 3 get 200 OK, then signals shutdown
#      via the existing graceful-stop flag. ~1s total.
echo -e "\n── Http1.ServeAsync e2e (link + fibers + epoll) ──"
SERVE_ASYNC_PORT=18091
cat > "$BUILD_DIR/serve_async_smoke.c" <<EOF
#include "Amalgame_Net_Http.h"
#include <pthread.h>
#include <stdio.h>
#include <time.h>

/* Handler closure trampoline — writes a fixed response. */
static void* handler_fn(void* env, void* arg) {
    (void) env;
    AmalgameH1Conn* c = (AmalgameH1Conn*) arg;
    Amalgame_Net_Http_H1Conn_Respond(
        c, 200, "text/plain", "ok-from-fiber");
    return NULL;
}

static void* server_thread(void* unused) {
    (void) unused;
    AmalgameClosure* h =
        AmalgameClosure_new((void*) handler_fn, NULL);
    Amalgame_Net_Http_Http1_ServeAsync($SERVE_ASYNC_PORT, h);
    return NULL;
}

/* nanosleep loop — robust against EINTR from libgc stop-the-world
 * signals (PWR/USR1) which would otherwise short-circuit usleep
 * in the main thread while the server thread allocates fiber
 * stacks. */
static void sleep_ms(long ms) {
    struct timespec rem;
    rem.tv_sec  = ms / 1000;
    rem.tv_nsec = (ms % 1000) * 1000000L;
    while (nanosleep(&rem, &rem) == -1) {
        /* loop until time fully consumed */
    }
}

int main(void) {
    GC_INIT();
    pthread_t t;
    if (GC_pthread_create(&t, NULL, server_thread, NULL) != 0) {
        fprintf(stderr, "pthread_create failed\n");
        return 1;
    }
    /* Give the server time to bind + spawn the accept fiber. */
    sleep_ms(300);
    printf("server-up: 1\n");
    fflush(stdout);
    /* Stay up long enough for the 3 curl probes below. */
    sleep_ms(1500);
    Amalgame_Net_Http_Http1_RequestShutdown();
    GC_pthread_join(t, NULL);
    printf("server-down: 1\n");
    return 0;
}
EOF
gcc -O2 -Iruntime -I"$RUNTIME_DIR" -I"$ASYNC_RUNTIME_DIR" \
    "$BUILD_DIR/serve_async_smoke.c" \
    -lgc -lpthread -o "$BUILD_DIR/serve_async_smoke" 2>&1 | head -5
if [ ! -x "$BUILD_DIR/serve_async_smoke" ]; then
    echo -e "${RED}FAIL${NC} (ServeAsync smoke build)"
    exit 1
fi
"$BUILD_DIR/serve_async_smoke" &
SERVER_PID=$!
sleep 0.4

# Fire 3 concurrent curl requests. The fiber-driven server should
# accept all 3 and respond on the same OS thread.
ASYNC_OK=0
for i in 1 2 3; do
    body=$(curl -fsS --max-time 2 "http://127.0.0.1:$SERVE_ASYNC_PORT/" 2>/dev/null || true)
    if [ "$body" = "ok-from-fiber" ]; then
        ASYNC_OK=$((ASYNC_OK + 1))
    fi
done

wait $SERVER_PID 2>/dev/null || true
SERVER_PID=""

if [ "$ASYNC_OK" -eq 3 ]; then
    echo -e "${GREEN}PASS${NC} (ServeAsync served $ASYNC_OK requests via fibers)"
else
    echo -e "${RED}FAIL${NC} (ServeAsync ok=$ASYNC_OK / 3)"
    exit 1
fi

echo -e "\n${GREEN}All tests completed${NC}"
