#!/usr/bin/env bash
# gc_signal_test.sh — the HTTPS handshake must survive the collector.
# bdwgc stops the world by signalling every thread. A read on a socket
# that carries SO_RCVTIMEO (the 10 s handshake ceiling) is never restarted
# after a signal (signal(7)) : before v0.29.7 SSL_accept gave up with
# SSL_ERROR_WANT_READ and the client saw a reset handshake (curl 35/56).
# Here a thread allocates and collects in a loop (what any busy app does
# beside its server, only harder) while curl makes N requests : every one
# must be answered.
set -euo pipefail
cd "$(dirname "$0")/.."

RT="${AMC_RUNTIME:-$HOME/.local/share/amalgame/runtime}"
ASYNC_RT="${ASYNC_RT:-$(ls -d "$HOME/.amalgame/packages/github.com/amalgame-lang/amalgame-async"/*/runtime 2>/dev/null | sort -V | tail -1)}"
TLS_RT="${TLS_RT:-$(ls -d "$HOME/.amalgame/packages/github.com/amalgame-lang/amalgame-tls"/*/runtime 2>/dev/null | sort -V | tail -1)}"
[ -d "$RT" ] || { echo "AMC_RUNTIME introuvable"; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo "[SKIP] openssl CLI absent"; exit 0; }
command -v curl >/dev/null 2>&1 || { echo "[SKIP] curl absent"; exit 0; }

N=${N:-200}
B="$(mktemp -d)"; trap 'rm -rf "$B"; [ -n "${SRVPID:-}" ] && kill "$SRVPID" 2>/dev/null || true' EXIT
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -keyout "$B/k.pem" -out "$B/c.pem" \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" >/dev/null 2>&1

PORT=18447
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
    static const char ok[] = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
    for (;;) {
        AmalgameH1Conn* c = Amalgame_Net_Http_HttpsH1Server_AcceptParsed(s);
        if (!c) continue;
        SSL_write(c->ssl, ok, (int) sizeof(ok) - 1);
        Amalgame_Net_Http_H1Conn_Close(c);
    }
    return 0;
}
EOF

if ! gcc -O2 -Iruntime -I"$RT" -I"$ASYNC_RT" -I"$TLS_RT" \
    "$B/srv.c" -lssl -lcrypto -lgc -lnghttp2 -lpthread -o "$B/srv" 2>"$B/gcc.log"; then
    echo "[FAIL] build du serveur de test:"; head -10 "$B/gcc.log"; exit 1
fi

"$B/srv" > "$B/srv.out" 2>/dev/null &
SRVPID=$!
for _ in $(seq 1 50); do grep -q ready "$B/srv.out" 2>/dev/null && break; sleep 0.1; done

bad=0
for _ in $(seq 1 "$N"); do
    r=$(curl -s --max-time 10 --cacert "$B/c.pem" "https://localhost:$PORT/" || true)
    [ "$r" = ok ] || bad=$((bad + 1))
done
echo "$((N - bad))/$N requêtes HTTPS servies pendant que le collecteur tourne en boucle"
[ "$bad" -eq 0 ] && echo "[PASS] la poignée de main TLS survit aux signaux du collecteur" \
                 || { echo "[FAIL] $bad poignée(s) de main interrompue(s) par un signal (EINTR)"; exit 1; }
