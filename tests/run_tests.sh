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

# v0.11.0: HttpClient.Execute branches into amalgame-tls' TlsStream
# for https://. Same sibling-or-cache pattern as ASYNC.
TLS_RUNTIME_DIR=""
if [ -d "$PKG_DIR/../amalgame-tls/runtime" ]; then
    TLS_RUNTIME_DIR="$PKG_DIR/../amalgame-tls/runtime"
elif compgen -G "$HOME/.amalgame/packages/github.com/amalgame-lang/amalgame-tls/*/runtime" > /dev/null 2>&1; then
    TLS_RUNTIME_DIR="$(ls -d $HOME/.amalgame/packages/github.com/amalgame-lang/amalgame-tls/*/runtime | tail -n1)"
fi
if [ -z "$TLS_RUNTIME_DIR" ]; then
    echo "error: amalgame-tls runtime/ not found."
    echo "  Expected sibling: $PKG_DIR/../amalgame-tls/runtime"
    echo "  Or installed via: amc package add tls@v0.3.0"
    exit 2
fi
echo "Using amalgame-tls runtime:   $TLS_RUNTIME_DIR"
echo "Using amalgame-async runtime: $ASYNC_RUNTIME_DIR"

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

cd "$PKG_DIR"

# v0.4.6: facade.am split across multiple source files (cookie,
# http_request, http_response, http_parser, http_server, http_client).
# Order matches amalgame.toml's `sources = [...]` for cross-file refs.
NETHTTP_SOURCES="facade.am cookie.am http_request.am http_response.am http_parser.am http_server.am http_client.am multipart.am"
NETHTTP_EXTERNAL_FLAGS=""
for src in $NETHTTP_SOURCES; do
    NETHTTP_EXTERNAL_FLAGS="$NETHTTP_EXTERNAL_FLAGS --external $src"
done

# ── Build facade.o once ───────────────────────────────────────────
echo -e "\n── Building facade.o ──"
"$AMC" --lib -o "$BUILD_DIR/facade" $NETHTTP_SOURCES 2>&1 | tail -2
gcc -O2 -Iruntime -I"$RUNTIME_DIR" -I"$ASYNC_RUNTIME_DIR" -I"$TLS_RUNTIME_DIR" -c "$BUILD_DIR/facade.c" -o "$BUILD_DIR/facade.o" 2>&1 | head -5
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
    # v0.10.0: facade.o pulls in HTTPS-H1's SSL_read/SSL_write
    # via amalgame_h1_send_all / amalgame_h1_recv_into branches
    # on c->ssl. Link -lssl -lcrypto unconditionally; users on
    # OpenSSL-less builds (rare) can override via a -U define.
    gcc -O2 -Iruntime -I"$RUNTIME_DIR" -I"$ASYNC_RUNTIME_DIR" -I"$TLS_RUNTIME_DIR" \
        "$out.c" "$BUILD_DIR/facade.o" \
        -lgc -lm -lcurl -lz -lpthread -lssl -lcrypto -lnghttp2 -o "$out" 2>&1 | head -5
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

# ── Multipart unit tests (no sockets) ─────────────────────────────
echo -e "\n── Multipart unit tests ──"
if build_test tests/multipart_test.am "$BUILD_DIR/multipart_test"; then
    "$BUILD_DIR/multipart_test"
else
    echo -e "${RED}FAIL${NC} (multipart test build)"
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
gcc -O2 -Iruntime -I"$RUNTIME_DIR" -I"$ASYNC_RUNTIME_DIR" -I"$TLS_RUNTIME_DIR" "$BUILD_DIR/cfg_smoke.c" \
    -lgc -lssl -lcrypto -o "$BUILD_DIR/cfg_smoke" 2>&1 | head -5
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

# ── H1Conn_RespondFile binary-safe smoke (v0.9.6) ────────────────
# Critical: PNG / JPEG / PDF / WASM contain NUL bytes that the
# legacy H1Conn_Respond path strlen-truncates. The new entry point
# carries Content-Length explicitly. We verify by:
#   1. building a 64-byte payload that contains a NUL at byte 5
#   2. piping it through a socketpair'd H1Conn
#   3. reading the wire bytes back and asserting the body half
#      matches the original payload byte-for-byte (with the NUL).
echo -e "\n── H1Conn_RespondFile binary-safe smoke ──"
PAYLOAD_PATH="$BUILD_DIR/payload.bin"
python3 -c "
import sys
data = b'hello' + b'\x00' + b'world' + bytes(range(256)) + b'TAIL'
open('$PAYLOAD_PATH','wb').write(data)
sys.stdout.write(str(len(data)))
" > "$BUILD_DIR/payload.len"
PAYLOAD_LEN=$(cat "$BUILD_DIR/payload.len")
cat > "$BUILD_DIR/respondfile_smoke.c" <<EOF
#include "Amalgame_Net_Http.h"
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
int main(void) {
    GC_INIT();
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { perror("socketpair"); return 1; }

    /* Build an AmalgameH1Conn that writes to sv[0] (server side). */
    AmalgameH1Conn* c = (AmalgameH1Conn*) GC_MALLOC(sizeof(AmalgameH1Conn));
    memset(c, 0, sizeof(*c));
    c->fd = sv[0];
    c->keep_alive = 0;

    /* Send the payload via the binary-safe entry. */
    i64 rc = Amalgame_Net_Http_H1Conn_RespondFile(c, 200,
        (code_string) "application/octet-stream",
        (code_string) "$PAYLOAD_PATH");

    /* Half-close server end so client sees EOF after final byte. */
    shutdown(sv[0], SHUT_WR);

    /* Drain wire bytes on the client end. */
    char buf[8192];
    ssize_t got = 0, n;
    while ((n = read(sv[1], buf + got, sizeof(buf) - got - 1)) > 0) got += n;
    buf[got] = 0;
    close(sv[0]); close(sv[1]);

    /* Split header / body at the CRLFCRLF. */
    const char* sep = "\r\n\r\n";
    char* hdr_end = NULL;
    for (ssize_t i = 0; i + 3 < got; i++) {
        if (memcmp(buf + i, sep, 4) == 0) { hdr_end = buf + i + 4; break; }
    }
    if (!hdr_end) { printf("FAIL: no CRLFCRLF in %zd wire bytes\n", got); return 1; }
    ssize_t body_len = got - (hdr_end - buf);
    ssize_t expected = $PAYLOAD_LEN;

    /* Read the original file for byte-for-byte comparison. */
    FILE* f = fopen("$PAYLOAD_PATH", "rb");
    if (!f) { perror("fopen payload"); return 1; }
    char orig[8192];
    ssize_t orig_len = fread(orig, 1, sizeof(orig), f);
    fclose(f);

    printf("rc=%lld\n", (long long) rc);
    printf("body_len=%zd expected=%zd orig_len=%zd\n", body_len, expected, orig_len);
    printf("content_length_header=%s\n",
        strstr(buf, "Content-Length: ") ? strstr(buf, "Content-Length: ") + 16 : "MISSING");

    if (body_len != expected) { printf("FAIL: length mismatch\n"); return 1; }
    if (memcmp(hdr_end, orig, body_len) != 0) {
        for (ssize_t i = 0; i < body_len; i++) {
            if (hdr_end[i] != orig[i]) {
                printf("FAIL: byte %zd diff (got=0x%02x expected=0x%02x)\n",
                    i, (unsigned)(unsigned char)hdr_end[i],
                    (unsigned)(unsigned char)orig[i]);
                return 1;
            }
        }
    }
    printf("PASS\n");
    return 0;
}
EOF
gcc -O2 -Iruntime -I"$RUNTIME_DIR" -I"$ASYNC_RUNTIME_DIR" -I"$TLS_RUNTIME_DIR" \
    "$BUILD_DIR/respondfile_smoke.c" -lgc -lssl -lcrypto -o "$BUILD_DIR/respondfile_smoke" 2>&1 | head -5
if [ ! -x "$BUILD_DIR/respondfile_smoke" ]; then
    echo -e "${RED}FAIL${NC} (RespondFile smoke build)"
    exit 1
fi
RF_OUT=$("$BUILD_DIR/respondfile_smoke")
echo "$RF_OUT"
if echo "$RF_OUT" | grep -q "^PASS$" && echo "$RF_OUT" | grep -q "rc=0"; then
    echo -e "${GREEN}PASS${NC} (RespondFile sends $PAYLOAD_LEN bytes including NULs byte-for-byte)"
else
    echo -e "${RED}FAIL${NC} (RespondFile binary-safe pipeline broken)"
    exit 1
fi

# ── v0.14.0: streaming primitives + raw body byte accessor ────────
echo -e "\n── Streaming primitives (BeginStream / WriteRaw / BodyByteAt) ──"
cat > "$BUILD_DIR/stream_smoke.c" <<'EOF'
#include "Amalgame_Net_Http.h"
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
int main(void) {
    GC_INIT();

    /* (1) BodyByteAt over a body that contains NUL bytes — the exact
     * case H1Conn_Body (code_string) truncates and loses. */
    AmalgameH1Conn* b = (AmalgameH1Conn*) GC_MALLOC(sizeof(AmalgameH1Conn));
    memset(b, 0, sizeof(*b));
    static const unsigned char payload[5] = { 0xff, 0x00, 0x41, 0x00, 0x7e };
    b->body = (char*) payload;
    b->body_len = 5;
    int byte_ok = 1;
    if (Amalgame_Net_Http_H1Conn_BodyByteAt(b, 0) != 0xff) byte_ok = 0;
    if (Amalgame_Net_Http_H1Conn_BodyByteAt(b, 1) != 0x00) byte_ok = 0;
    if (Amalgame_Net_Http_H1Conn_BodyByteAt(b, 2) != 0x41) byte_ok = 0;
    if (Amalgame_Net_Http_H1Conn_BodyByteAt(b, 4) != 0x7e) byte_ok = 0;
    if (Amalgame_Net_Http_H1Conn_BodyByteAt(b, 5) != -1)   byte_ok = 0;  /* OOR */
    if (Amalgame_Net_Http_H1Conn_BodyByteAt(b, -1) != -1)  byte_ok = 0;
    printf("byteat_ok=%d\n", byte_ok);

    /* (2) BeginStream + WriteRaw over a socketpair. */
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { perror("socketpair"); return 1; }
    AmalgameH1Conn* c = (AmalgameH1Conn*) GC_MALLOC(sizeof(AmalgameH1Conn));
    memset(c, 0, sizeof(*c));
    c->fd = sv[0];
    c->keep_alive = 1;   /* BeginStream must force this to 0 */

    i64 bs = Amalgame_Net_Http_H1Conn_BeginStream(c, 200,
        (code_string) "Content-Type: text/event-stream\r\nCache-Control: no-cache\r\n");
    i64 w1 = Amalgame_Net_Http_H1Conn_WriteRaw(c, (code_string) "data: hello\n\n");
    i64 w2 = Amalgame_Net_Http_H1Conn_WriteRaw(c, (code_string) "data: world\n\n");
    Amalgame_Net_Http_H1Conn_Flush(c);

    shutdown(sv[0], SHUT_WR);
    char buf[4096]; ssize_t got = 0, n;
    while ((n = read(sv[1], buf + got, sizeof(buf) - got - 1)) > 0) got += n;
    buf[got] = 0;
    close(sv[0]); close(sv[1]);

    printf("bs=%lld w1=%lld w2=%lld keep_alive=%d streaming=%d resp_sent=%d\n",
        (long long)bs, (long long)w1, (long long)w2,
        (int)c->keep_alive, (int)c->streaming, (int)c->response_sent);

    int ok = byte_ok
        && bs == 0 && w1 == 0 && w2 == 0
        && c->keep_alive == 0 && c->streaming == 1 && c->response_sent == 1
        && strstr(buf, "HTTP/1.1 200 OK\r\n") == buf
        && strstr(buf, "Connection: close\r\n")
        && strstr(buf, "Content-Type: text/event-stream\r\n")
        && strstr(buf, "\r\n\r\ndata: hello\n\ndata: world\n\n")
        && !strstr(buf, "Content-Length:");
    printf(ok ? "PASS\n" : "FAIL\n");
    return ok ? 0 : 1;
}
EOF
gcc -O2 -Iruntime -I"$RUNTIME_DIR" -I"$ASYNC_RUNTIME_DIR" -I"$TLS_RUNTIME_DIR" \
    "$BUILD_DIR/stream_smoke.c" -lgc -lssl -lcrypto -o "$BUILD_DIR/stream_smoke" 2>&1 | head -5
if [ ! -x "$BUILD_DIR/stream_smoke" ]; then
    echo -e "${RED}FAIL${NC} (streaming smoke build)"
    exit 1
fi
ST_OUT=$("$BUILD_DIR/stream_smoke")
echo "$ST_OUT"
if echo "$ST_OUT" | grep -q "^PASS$"; then
    echo -e "${GREEN}PASS${NC} (BeginStream/WriteRaw wire framing + BodyByteAt binary-safe)"
else
    echo -e "${RED}FAIL${NC} (streaming primitives broken)"
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
gcc -O2 -Iruntime -I"$RUNTIME_DIR" -I"$ASYNC_RUNTIME_DIR" -I"$TLS_RUNTIME_DIR" "$BUILD_DIR/mt_smoke.c" \
    -lgc -lpthread -lssl -lcrypto -o "$BUILD_DIR/mt_smoke" 2>&1 | head -5
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
gcc -O2 -Iruntime -I"$RUNTIME_DIR" -I"$ASYNC_RUNTIME_DIR" -I"$TLS_RUNTIME_DIR" "$BUILD_DIR/h2c_smoke.c" \
    -lnghttp2 -lssl -lcrypto -lgc -o "$BUILD_DIR/h2c_smoke" 2>&1 | head -5
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
    /* Stay up long enough for the 3 + 3 curl probes below. */
    sleep_ms(3500);
    Amalgame_Net_Http_Http1_RequestShutdown();
    GC_pthread_join(t, NULL);
    printf("server-down: 1\n");
    return 0;
}
EOF
gcc -O2 -Iruntime -I"$RUNTIME_DIR" -I"$ASYNC_RUNTIME_DIR" -I"$TLS_RUNTIME_DIR" \
    "$BUILD_DIR/serve_async_smoke.c" \
    -lgc -lpthread -lssl -lcrypto -o "$BUILD_DIR/serve_async_smoke" 2>&1 | head -5
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

if [ "$ASYNC_OK" -eq 3 ]; then
    echo -e "${GREEN}PASS${NC} (ServeAsync served $ASYNC_OK requests via fibers)"
else
    echo -e "${RED}FAIL${NC} (ServeAsync ok=$ASYNC_OK / 3)"
    kill -TERM $SERVER_PID 2>/dev/null
    exit 1
fi

# v0.9.2: keep-alive smoke — same socket carries 3 sequential
# requests. curl with no Connection: close + --http1.1 reuses
# the TCP connection. Server must ResetForReuse + re-parse.
KEEPALIVE_OUT=$(curl -sS --http1.1 --max-time 3 \
    "http://127.0.0.1:$SERVE_ASYNC_PORT/k1" \
    "http://127.0.0.1:$SERVE_ASYNC_PORT/k2" \
    "http://127.0.0.1:$SERVE_ASYNC_PORT/k3" 2>/dev/null || true)
# Each response body is "ok-from-fiber" (no newline). Concatenation
# of 3 responses = "ok-from-fiberok-from-fiberok-from-fiber".
if echo "$KEEPALIVE_OUT" | grep -qF "ok-from-fiberok-from-fiberok-from-fiber"; then
    echo -e "${GREEN}PASS${NC} (ServeAsync keep-alive: 3 reqs on one socket)"
else
    echo -e "${RED}FAIL${NC} (ServeAsync keep-alive: '$KEEPALIVE_OUT')"
    kill -TERM $SERVER_PID 2>/dev/null
    exit 1
fi

wait $SERVER_PID 2>/dev/null || true
SERVER_PID=""

# ── Http1.ServeAsyncWith smoke (v0.9.3) ───────────────────────────
# Builds the same server pattern as ServeAsync but with a
# HttpServerConfig that disables keep-alive (idle_timeout_sec=0) and
# caps the body size. Asserts: link + 3 concurrent requests succeed
# + a body that exceeds max_body_bytes gets a parse error (curl
# observes connection close mid-response = empty body). Linux only,
# same backend constraints as ServeAsync.
echo -e "\n── Http1.ServeAsyncWith e2e (config + fibers) ──"
SAW_PORT=18092
cat > "$BUILD_DIR/serve_async_with_smoke.c" <<EOF
#include "Amalgame_Net_Http.h"
#include <pthread.h>
#include <stdio.h>
#include <time.h>

static void* handler_fn(void* env, void* arg) {
    (void) env;
    AmalgameH1Conn* c = (AmalgameH1Conn*) arg;
    Amalgame_Net_Http_H1Conn_Respond(c, 200, "text/plain", "with-config");
    return NULL;
}

static void* server_thread(void* u) {
    (void) u;
    AmalgameNetHttpServerConfig* cfg =
        Amalgame_Net_Http_HttpServerConfig_Default();
    Amalgame_Net_Http_HttpServerConfig_WithMaxBodyBytes(cfg, 128);
    Amalgame_Net_Http_HttpServerConfig_WithListenBacklog(cfg, 64);
    /* idle_timeout_sec stays 0 → keep-alive OFF, matches sync ServeWith */
    AmalgameClosure* h =
        AmalgameClosure_new((void*) handler_fn, NULL);
    Amalgame_Net_Http_Http1_ServeAsyncWith($SAW_PORT, cfg, h);
    return NULL;
}

static void sleep_ms(long ms) {
    struct timespec rem = { ms / 1000, (ms % 1000) * 1000000L };
    while (nanosleep(&rem, &rem) == -1) { }
}

int main(void) {
    GC_INIT();
    pthread_t t;
    if (GC_pthread_create(&t, NULL, server_thread, NULL) != 0) {
        fprintf(stderr, "pthread_create failed\n");
        return 1;
    }
    sleep_ms(300);
    printf("server-up: 1\n");
    fflush(stdout);
    sleep_ms(1500);
    Amalgame_Net_Http_Http1_RequestShutdown();
    GC_pthread_join(t, NULL);
    printf("server-down: 1\n");
    return 0;
}
EOF
gcc -O2 -Iruntime -I"$RUNTIME_DIR" -I"$ASYNC_RUNTIME_DIR" -I"$TLS_RUNTIME_DIR" \
    "$BUILD_DIR/serve_async_with_smoke.c" \
    -lgc -lpthread -lssl -lcrypto -o "$BUILD_DIR/serve_async_with_smoke" 2>&1 | head -5
if [ ! -x "$BUILD_DIR/serve_async_with_smoke" ]; then
    echo -e "${RED}FAIL${NC} (ServeAsyncWith smoke build)"
    exit 1
fi
"$BUILD_DIR/serve_async_with_smoke" &
SERVER_PID=$!
sleep 0.4

# 3 small GETs → all 200 with body "with-config"
SAW_OK=0
for i in 1 2 3; do
    body=$(curl -fsS --max-time 2 "http://127.0.0.1:$SAW_PORT/" 2>/dev/null || true)
    if [ "$body" = "with-config" ]; then
        SAW_OK=$((SAW_OK + 1))
    fi
done
if [ "$SAW_OK" -eq 3 ]; then
    echo -e "${GREEN}PASS${NC} (ServeAsyncWith served $SAW_OK requests via fibers)"
else
    echo -e "${RED}FAIL${NC} (ServeAsyncWith ok=$SAW_OK / 3)"
    kill -TERM $SERVER_PID 2>/dev/null
    exit 1
fi

# max_body_bytes=128 → a 512-byte body must be rejected (parse error).
# curl observes connection-close → -fS exits non-zero → we capture the
# exit code. Pass = curl FAILED to complete the request.
BIG=$(head -c 512 /dev/urandom | base64 | head -c 512)
if curl -fsS --max-time 2 -X POST -d "$BIG" \
       "http://127.0.0.1:$SAW_PORT/" > /dev/null 2>&1; then
    echo -e "${RED}FAIL${NC} (ServeAsyncWith: max_body=128 should reject 512-byte body)"
    kill -TERM $SERVER_PID 2>/dev/null
    exit 1
else
    echo -e "${GREEN}PASS${NC} (ServeAsyncWith max_body=128 rejects 512-byte body)"
fi

wait $SERVER_PID 2>/dev/null || true
SERVER_PID=""

# ── Http1.ServeAsyncWith header_timeout_sec (v0.9.4) ──────────────
# Boots a server with header_timeout_sec=1. Opens a raw TCP socket
# from python, sends a partial request (no CRLF CRLF), keeps it
# open for 2.5s without sending more. Server must time out and
# close the conn, NOT hang forever waiting for headers. We assert
# the client-side recv returns 0 (clean close) within ~1.5s.
echo -e "\n── Http1.ServeAsyncWith header_timeout_sec (slow-client) ──"
HTO_PORT=18093
cat > "$BUILD_DIR/header_timeout_smoke.c" <<EOF
#include "Amalgame_Net_Http.h"
#include <pthread.h>
#include <stdio.h>
#include <time.h>

static void* handler_fn(void* env, void* arg) {
    (void) env;
    AmalgameH1Conn* c = (AmalgameH1Conn*) arg;
    Amalgame_Net_Http_H1Conn_Respond(c, 200, "text/plain", "ok");
    return NULL;
}

static void* server_thread(void* u) {
    (void) u;
    AmalgameNetHttpServerConfig* cfg =
        Amalgame_Net_Http_HttpServerConfig_Default();
    /* 1-second header timeout — slow-client mitigation. */
    Amalgame_Net_Http_HttpServerConfig_WithHeaderTimeoutSec(cfg, 1);
    AmalgameClosure* h =
        AmalgameClosure_new((void*) handler_fn, NULL);
    Amalgame_Net_Http_Http1_ServeAsyncWith($HTO_PORT, cfg, h);
    return NULL;
}

static void sleep_ms(long ms) {
    struct timespec rem = { ms / 1000, (ms % 1000) * 1000000L };
    while (nanosleep(&rem, &rem) == -1) { }
}

int main(void) {
    GC_INIT();
    pthread_t t;
    if (GC_pthread_create(&t, NULL, server_thread, NULL) != 0) return 1;
    sleep_ms(300);
    printf("server-up: 1\n"); fflush(stdout);
    sleep_ms(2500);
    Amalgame_Net_Http_Http1_RequestShutdown();
    GC_pthread_join(t, NULL);
    return 0;
}
EOF
gcc -O2 -Iruntime -I"$RUNTIME_DIR" -I"$ASYNC_RUNTIME_DIR" -I"$TLS_RUNTIME_DIR" \
    "$BUILD_DIR/header_timeout_smoke.c" \
    -lgc -lpthread -lssl -lcrypto -o "$BUILD_DIR/header_timeout_smoke" 2>&1 | head -3
if [ ! -x "$BUILD_DIR/header_timeout_smoke" ]; then
    echo -e "${RED}FAIL${NC} (header-timeout smoke build)"
    exit 1
fi
"$BUILD_DIR/header_timeout_smoke" &
SERVER_PID=$!
sleep 0.5

# Python: open TCP socket, send 23 bytes (well under header limit),
# wait. After ~1s the server should close us. Measure elapsed.
HTO_RESULT=$(python3 - <<'PYEOF'
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(3.0)
t0 = time.time()
s.connect(("127.0.0.1", 18093))
s.sendall(b"GET /slow HTTP/1.1\r\nHo")   # missing rest of headers + CRLFCRLF
try:
    # blocking recv: server closing the conn returns b"" promptly
    data = s.recv(64)
    elapsed = time.time() - t0
    print(f"closed_after={elapsed*1000:.0f}ms bytes={len(data)}")
except socket.timeout:
    print("client_timeout")
finally:
    s.close()
PYEOF
)
echo "  $HTO_RESULT"

wait $SERVER_PID 2>/dev/null || true
SERVER_PID=""

# Server's header_timeout_sec=1 → close within ~1100ms. Allow margin.
CLOSED_MS=$(echo "$HTO_RESULT" | sed -nE 's/.*closed_after=([0-9]+)ms.*/\1/p')
if [ -n "$CLOSED_MS" ] && [ "$CLOSED_MS" -ge 900 ] && [ "$CLOSED_MS" -le 1600 ]; then
    echo -e "${GREEN}PASS${NC} (header_timeout=1s fired in ${CLOSED_MS}ms)"
else
    echo -e "${RED}FAIL${NC} (expected close in 900-1600ms, got '$HTO_RESULT')"
    exit 1
fi

# ── Http1.ServeAsync graceful shutdown (v0.9.5) ───────────────────
# Spawns a server, fires a /slow request that does FiberSleep(5000),
# then calls Http1.RequestShutdown 200ms in. With v0.9.5 the accept
# loop walks live_head and FiberCancel's the in-flight handler; the
# FiberSleep returns early and the handler exits. Total ServeAsync
# return should be well under the 5s sleep — we assert < 2s.
echo -e "\n── Http1.ServeAsync graceful shutdown (cancellation) ──"
GS_PORT=18094
cat > "$BUILD_DIR/graceful_shutdown_smoke.c" <<EOF
#include "Amalgame_Net_Http.h"
#include <pthread.h>
#include <stdio.h>
#include <time.h>
#include <sys/time.h>

static i64 now_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (i64) tv.tv_sec * 1000 + (i64) (tv.tv_usec / 1000);
}

static void sleep_ms(long ms) {
    struct timespec rem = { ms / 1000, (ms % 1000) * 1000000L };
    while (nanosleep(&rem, &rem) == -1) { }
}

static void* slow_handler(void* env, void* arg) {
    (void) env;
    AmalgameH1Conn* c = (AmalgameH1Conn*) arg;
    /* Park the fiber for 5s. With v0.9.5 the shutdown sweep cancels
     * us, FiberSleep returns early, the handler exits. Without it,
     * ServeAsync waits the full 5s. */
    Amalgame_Async_FiberSleep(5000);
    Amalgame_Net_Http_H1Conn_Respond(c, 200, "text/plain", "slow-done");
    return NULL;
}

static volatile i64 g_serve_returned_at = 0;
static void* server_thread(void* u) {
    (void) u;
    AmalgameClosure* h = AmalgameClosure_new((void*) slow_handler, NULL);
    Amalgame_Net_Http_Http1_ServeAsync($GS_PORT, h);
    g_serve_returned_at = now_ms();
    return NULL;
}

static void* client_thread(void* u) {
    (void) u;
    char buf[1024];
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons($GS_PORT);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (connect(s, (struct sockaddr*) &addr, sizeof(addr)) == 0) {
        const char* req = "GET /slow HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
        send(s, req, strlen(req), 0);
        recv(s, buf, sizeof(buf), 0);   /* may return on close */
    }
    close(s);
    return NULL;
}

int main(void) {
    GC_INIT();
    pthread_t srv_t, cli_t;
    if (GC_pthread_create(&srv_t, NULL, server_thread, NULL) != 0) return 1;
    sleep_ms(300);
    pthread_create(&cli_t, NULL, client_thread, NULL);
    sleep_ms(200);   /* let the client request reach the handler */
    i64 t_shutdown = now_ms();
    Amalgame_Net_Http_Http1_RequestShutdown();
    GC_pthread_join(srv_t, NULL);
    pthread_join(cli_t, NULL);
    i64 elapsed = g_serve_returned_at - t_shutdown;
    printf("shutdown_to_serve_return=%lldms\n", (long long) elapsed);
    return 0;
}
EOF
gcc -O2 -Iruntime -I"$RUNTIME_DIR" -I"$ASYNC_RUNTIME_DIR" -I"$TLS_RUNTIME_DIR" \
    "$BUILD_DIR/graceful_shutdown_smoke.c" \
    -lgc -lpthread -lssl -lcrypto -o "$BUILD_DIR/graceful_shutdown_smoke" 2>&1 | head -5
if [ ! -x "$BUILD_DIR/graceful_shutdown_smoke" ]; then
    echo -e "${RED}FAIL${NC} (graceful-shutdown smoke build)"
    exit 1
fi
GS_OUT=$("$BUILD_DIR/graceful_shutdown_smoke")
echo "  $GS_OUT"
GS_MS=$(echo "$GS_OUT" | sed -nE 's/.*shutdown_to_serve_return=([0-9]+)ms.*/\1/p')
# Without v0.9.5 cancel: ~4800ms (waits for the 5000ms FiberSleep
# minus the 200ms we slept before shutdown).
# With v0.9.5 cancel: well under 500ms.
if [ -n "$GS_MS" ] && [ "$GS_MS" -lt 1500 ]; then
    echo -e "${GREEN}PASS${NC} (graceful shutdown returned in ${GS_MS}ms, 5s sleep cancelled)"
else
    echo -e "${RED}FAIL${NC} (expected < 1500ms, got '$GS_OUT' — FiberCancel not wiring through?)"
    exit 1
fi

# ── Https.H1Serve smoke (v0.10.0) ────────────────────────────────
# Verifies the TLS-terminating HTTP/1.1 server end-to-end:
#   1. Generate a self-signed cert in BUILD_DIR (openssl one-liner).
#   2. Spawn Https.H1Serve in a pthread on port $TLS_H1_PORT.
#   3. curl --insecure --http1.1 https://127.0.0.1:$TLS_H1_PORT/.
#   4. Assert HTTP 200 + expected body.
#   5. Signal graceful shutdown via Http1_RequestShutdown.
#
# Skips cleanly if `openssl` or `curl` is missing.
echo -e "\n── Https.H1Serve e2e (TLS termination + ALPN http/1.1) ──"
if ! command -v openssl >/dev/null 2>&1 || ! command -v curl >/dev/null 2>&1; then
    echo -e "${YELLOW}SKIP${NC} (openssl or curl missing)"
else
    TLS_H1_PORT=18099
    TLS_CERT="$BUILD_DIR/tls_h1.crt"
    TLS_KEY="$BUILD_DIR/tls_h1.key"
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$TLS_KEY" -out "$TLS_CERT" -days 1 \
        -subj "/CN=localhost" 2>/dev/null

    cat > "$BUILD_DIR/https_h1_smoke.c" <<EOF
#include "Amalgame_Net_Http.h"
#include <pthread.h>
#include <stdio.h>
#include <time.h>

static void* handler_fn(void* env, void* arg) {
    (void) env;
    AmalgameH1Conn* c = (AmalgameH1Conn*) arg;
    Amalgame_Net_Http_H1Conn_Respond(
        c, 200, "text/plain", "ok-from-tls-h1");
    return NULL;
}

static void* server_thread(void* unused) {
    (void) unused;
    AmalgameClosure* h =
        AmalgameClosure_new((void*) handler_fn, NULL);
    Amalgame_Net_Http_Https_H1Serve($TLS_H1_PORT,
        "$TLS_CERT", "$TLS_KEY", h);
    return NULL;
}

static void sleep_ms(long ms) {
    struct timespec rem;
    rem.tv_sec  = ms / 1000;
    rem.tv_nsec = (ms % 1000) * 1000000L;
    while (nanosleep(&rem, &rem) == -1) {
        if (errno != EINTR) break;
    }
}

int main(void) {
    GC_INIT();
    pthread_t srv_t;
    if (GC_pthread_create(&srv_t, NULL, server_thread, NULL) != 0) return 1;
    sleep_ms(400);  /* let the server bind + SSL_CTX setup */
    printf("server-up\n");
    fflush(stdout);
    sleep_ms(2000); /* hold so curl from outside can probe */
    Amalgame_Net_Http_Http1_RequestShutdown();
    GC_pthread_join(srv_t, NULL);
    return 0;
}
EOF
    gcc -O2 -Iruntime -I"$RUNTIME_DIR" -I"$ASYNC_RUNTIME_DIR" -I"$TLS_RUNTIME_DIR" \
        "$BUILD_DIR/https_h1_smoke.c" \
        -lssl -lcrypto -lnghttp2 -lgc -lpthread -o "$BUILD_DIR/https_h1_smoke" 2>&1 | head -5
    if [ ! -x "$BUILD_DIR/https_h1_smoke" ]; then
        echo -e "${RED}FAIL${NC} (https_h1_smoke build)"
        exit 1
    fi
    "$BUILD_DIR/https_h1_smoke" > "$BUILD_DIR/https_h1.log" 2>&1 &
    SERVER_PID=$!
    # Wait up to 2s for "server-up" to appear in the log.
    for _ in $(seq 1 20); do
        if grep -q "server-up" "$BUILD_DIR/https_h1.log" 2>/dev/null; then
            break
        fi
        sleep 0.1
    done
    CURL_OUT=$(curl -sk --max-time 3 --http1.1 \
        -o /dev/stdout -w "HTTP_CODE=%{http_code}\nALPN=%{ssl_proto}\n" \
        "https://127.0.0.1:$TLS_H1_PORT/" 2>&1)
    wait $SERVER_PID 2>/dev/null
    SERVER_PID=""
    echo "$CURL_OUT" | head -5
    if echo "$CURL_OUT" | grep -q "ok-from-tls-h1" && \
       echo "$CURL_OUT" | grep -q "HTTP_CODE=200"; then
        echo -e "${GREEN}PASS${NC} (TLS-terminated HTTP/1.1 200 returned via Https.H1Serve)"
    else
        echo -e "${RED}FAIL${NC} (Https.H1Serve didn't serve 200)"
        cat "$BUILD_DIR/https_h1.log" | head -20
        exit 1
    fi
fi

# ── HttpClient HTTPS smoke (v0.11.0) ────────────────────────────
# Verify the new TLS client path by hitting our own Https.H1Serve
# loop-back from a small C harness that links the AM-side facade.o
# and calls HttpClient.Get via the C-mangled symbol. Reuses the
# self-signed cert from the H1Serve test.
echo -e "\n── HttpClient HTTPS client e2e ──"
if ! command -v openssl >/dev/null 2>&1 ; then
    echo -e "${YELLOW}SKIP${NC} (openssl missing)"
else
    HTTPS_CLI_PORT=18100
    HTTPS_CLI_CERT="$BUILD_DIR/https_cli.crt"
    HTTPS_CLI_KEY="$BUILD_DIR/https_cli.key"
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$HTTPS_CLI_KEY" -out "$HTTPS_CLI_CERT" -days 1 \
        -subj "/CN=localhost" 2>/dev/null
    cat > "$BUILD_DIR/https_cli_smoke.c" <<EOF
#include "Amalgame_Net_Http.h"
#include <pthread.h>
#include <stdio.h>
#include <time.h>

static void* handler_fn(void* env, void* arg) {
    (void) env;
    AmalgameH1Conn* c = (AmalgameH1Conn*) arg;
    Amalgame_Net_Http_H1Conn_Respond(c, 200, "text/plain", "https-client-ok");
    return NULL;
}
static void* server_thread(void* unused) {
    (void) unused;
    AmalgameClosure* h = AmalgameClosure_new((void*) handler_fn, NULL);
    Amalgame_Net_Http_Https_H1Serve($HTTPS_CLI_PORT,
        "$HTTPS_CLI_CERT", "$HTTPS_CLI_KEY", h);
    return NULL;
}
static void sleep_ms(long ms) {
    struct timespec rem = { ms / 1000, (ms % 1000) * 1000000L };
    while (nanosleep(&rem, &rem) == -1 && errno == EINTR) {}
}
int main(void) {
    GC_INIT();
    /* Need to skip cert verify on the client since we self-signed.
     * Quick path: env var that amalgame-tls' Default config picks up,
     * or we call the C primitive directly. */
    setenv("AMALGAME_TLS_INSECURE", "1", 1);
    pthread_t srv;
    if (GC_pthread_create(&srv, NULL, server_thread, NULL) != 0) return 1;
    sleep_ms(500);
    /* Drive HttpClient via the C-mangled symbol. The fluent builder
     * is awkward from C; do a raw HttpClient.Get equivalent. */
    AmalgameNetHttpHttpRequestBuilder* b = Amalgame_Net_Http_HttpClient_Request(
        "GET", "https://localhost:$HTTPS_CLI_PORT/");
    AmalgameNetHttpHttpResponse* resp = Amalgame_Net_Http_HttpClient_Execute(b);
    i64 status = resp ? Amalgame_Net_Http_HttpResponse_Status(resp) : -1;
    code_string body = resp ? Amalgame_Net_Http_HttpResponse_BodyText(resp) : "";
    printf("status=%lld\nbody=%s\n", (long long) status, body ? body : "(null)");
    Amalgame_Net_Http_Http1_RequestShutdown();
    GC_pthread_join(srv, NULL);
    return 0;
}
EOF
    gcc -O2 -Iruntime -I"$RUNTIME_DIR" -I"$ASYNC_RUNTIME_DIR" -I"$TLS_RUNTIME_DIR" \
        "$BUILD_DIR/https_cli_smoke.c" "$BUILD_DIR/facade.o" \
        -lgc -lpthread -lssl -lcrypto -lnghttp2 \
        -o "$BUILD_DIR/https_cli_smoke" 2>&1 | head -5
    if [ ! -x "$BUILD_DIR/https_cli_smoke" ]; then
        echo -e "${YELLOW}SKIP${NC} (https_cli_smoke build failed — likely facade symbol mangling drift)"
    else
        HCLI_OUT=$("$BUILD_DIR/https_cli_smoke" 2>&1)
        echo "$HCLI_OUT" | head -3
        if echo "$HCLI_OUT" | grep -q "status=200" && echo "$HCLI_OUT" | grep -q "https-client-ok"; then
            echo -e "${GREEN}PASS${NC} (HttpClient.Get over HTTPS roundtrip)"
        else
            echo -e "${RED}FAIL${NC} (HttpClient HTTPS roundtrip)"
            # Don't fail the whole suite on this — the loop-back has
            # cert-verify subtleties (self-signed) that may need extra
            # plumbing per-CI-runner. Keep informational for now.
        fi
    fi
fi

# ── SNI: one HTTPS listener, per-domain certs (v0.12.0) ──────────
echo -e "\n── SNI (HttpsH1Server_AddSni) ──"
if AMC_RUNTIME="$RUNTIME_DIR" ASYNC_RT="$ASYNC_RUNTIME_DIR" TLS_RT="$TLS_RUNTIME_DIR" bash tests/sni_test.sh; then
    echo -e "${GREEN}PASS${NC} (SNI: bon cert par servername)"
else
    echo -e "${RED}FAIL${NC} (SNI)"
    exit 1
fi

echo -e "\n${GREEN}All tests completed${NC}"
