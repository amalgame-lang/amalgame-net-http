#!/usr/bin/env bash
# tls_idle_timeout_test.sh — the HTTPS keep-alive idle timeout must fire.
# Before v0.29.8 a blocking SSL_read that hit SO_RCVTIMEO came back as
# SSL_ERROR_WANT_READ (errno EAGAIN) and was retried for ever, and a GC
# signal (EINTR) re-armed the full timeout : an idle keep-alive client held
# its ServePool worker until it hung up, and `workers` idle connections
# froze the server. Here a thread allocates and collects in a loop while a
# client makes two requests on one connection, then stays silent : the
# server must close it after the idle timeout, not later.
set -euo pipefail
cd "$(dirname "$0")/.."

RT="${AMC_RUNTIME:-$HOME/.local/share/amalgame/runtime}"
ASYNC_RT="${ASYNC_RT:-$(ls -d "$HOME/.amalgame/packages/github.com/amalgame-lang/amalgame-async"/*/runtime 2>/dev/null | sort -V | tail -1)}"
TLS_RT="${TLS_RT:-$(ls -d "$HOME/.amalgame/packages/github.com/amalgame-lang/amalgame-tls"/*/runtime 2>/dev/null | sort -V | tail -1)}"
[ -d "$RT" ] || { echo "AMC_RUNTIME introuvable"; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo "[SKIP] openssl CLI absent"; exit 0; }

IDLE=2
B="$(mktemp -d)"; trap 'rm -rf "$B"; [ -n "${SRVPID:-}" ] && kill "$SRVPID" 2>/dev/null || true' EXIT
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -keyout "$B/k.pem" -out "$B/c.pem" \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" >/dev/null 2>&1

PORT=18448
cat > "$B/srv.c" <<EOF
#include "Amalgame_Net_Http.h"
#include <stdio.h>
#include <unistd.h>
static void* churn(void* p) {
    (void)p;
    for (;;) {
        for (int i = 0; i < 2000; i++) { volatile char* x = (char*) GC_MALLOC(256); x[0] = 1; }
        GC_gcollect();
        usleep(2000);
    }
    return NULL;
}
static void* handler(void* env, void* conn) {
    (void)env;
    Amalgame_Net_Http_H1Conn_Respond((AmalgameH1Conn*) conn, 200, "text/plain", "ok");
    return NULL;
}
int main(void){
    GC_INIT();
    SSL_library_init(); SSL_load_error_strings(); OpenSSL_add_all_algorithms();
    AmalgameHttpsH1Server* s = Amalgame_Net_Http_HttpsH1Server_Listen(
        $PORT, "$B/c.pem", "$B/k.pem", 0);
    if (!s || !Amalgame_Net_Http_HttpsH1Server_IsListening(s)) {
        fprintf(stderr, "listen failed\n"); return 2;
    }
    pthread_t t; GC_pthread_create(&t, NULL, churn, NULL);
    printf("ready\n"); fflush(stdout);
    Amalgame_Net_Http_HttpsH1Server_ServePool(s, AmalgameClosure_new((void*) handler, NULL), $IDLE, 4);
    return 0;
}
EOF

# Client : two requests on ONE connection (keep-alive still works), then
# silence ; prints how long the server took to close (ms). Its own 20 s
# read timeout bounds the test when the server never closes.
cat > "$B/cli.c" <<EOF
#include <openssl/ssl.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
static long long now_ms(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (long long) t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
static int get(SSL* s) {
    static const char req[] = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    if (SSL_write(s, req, (int) sizeof(req) - 1) <= 0) return 0;
    char buf[4096]; int got = 0;
    while (got < (int) sizeof(buf) - 1) {
        int r = SSL_read(s, buf + got, (int) sizeof(buf) - 1 - got);
        if (r <= 0) return 0;
        got += r; buf[got] = 0;
        if (strstr(buf, "\r\n\r\nok")) return 1;
    }
    return 0;
}
int main(void) {
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a; memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET; a.sin_port = htons($PORT); a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr*) &a, sizeof(a)) != 0) { puts("connect"); return 2; }
    struct timeval tv = { 20, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    SSL* s = SSL_new(ctx); SSL_set_fd(s, fd); SSL_set_tlsext_host_name(s, "localhost");
    if (SSL_connect(s) != 1) { puts("handshake"); return 2; }
    if (!get(s)) { puts("request 1"); return 2; }
    sleep(1);
    if (!get(s)) { puts("request 2 (keep-alive)"); return 2; }
    long long t0 = now_ms();
    char b[256];
    while (SSL_read(s, b, sizeof(b)) > 0) {}
    printf("%lld\n", now_ms() - t0);
    return 0;
}
EOF

if ! gcc -O2 -Iruntime -I"$RT" -I"$ASYNC_RT" -I"$TLS_RT" \
    "$B/srv.c" -lssl -lcrypto -lgc -lnghttp2 -lpthread -o "$B/srv" 2>"$B/gcc.log" \
   || ! gcc -O2 "$B/cli.c" -lssl -lcrypto -o "$B/cli" 2>>"$B/gcc.log"; then
    echo "[FAIL] build du test:"; head -10 "$B/gcc.log"; exit 1
fi

"$B/srv" > "$B/srv.out" 2>/dev/null &
SRVPID=$!
for _ in $(seq 1 50); do grep -q ready "$B/srv.out" 2>/dev/null && break; sleep 0.1; done

out="$("$B/cli")" || { echo "[FAIL] client : $out"; exit 1; }
echo "connexion inactive fermée par le serveur après ${out} ms (délai d'inactivité : ${IDLE} s), keep-alive servi"
if [ "$out" -ge $((IDLE * 1000 - 200)) ] && [ "$out" -le $((IDLE * 1000 + 1500)) ]; then
    echo "[PASS] le délai d'inactivité HTTPS est tenu malgré les signaux du collecteur"
else
    echo "[FAIL] attendu ~$((IDLE * 1000)) ms"; exit 1
fi
