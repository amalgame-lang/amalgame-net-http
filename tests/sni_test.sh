#!/usr/bin/env bash
# sni_test.sh — vérifie que HttpsH1Server_AddSni présente le BON cert
# selon le SNI du client. Génère 2 certs auto-signés (deux domaines
# bidons), lance un mini serveur C qui Listen + AddSni les deux, puis
# interroge avec `openssl s_client -servername` et compare le CN
# présenté. Pas de dépendance réseau externe (tout sur 127.0.0.1).
set -euo pipefail
cd "$(dirname "$0")/.."

# Runtime dirs. run_tests.sh passes ASYNC_RT / TLS_RT (resolved from
# env vars or sibling repos — the CI has no ~/.amalgame cache). Fall
# back to the local package cache for standalone runs.
RT="${AMC_RUNTIME:-$HOME/.local/share/amalgame/runtime}"
ASYNC_RT="${ASYNC_RT:-$(ls -d "$HOME/.amalgame/packages/github.com/amalgame-lang/amalgame-async"/*/runtime 2>/dev/null | sort -V | tail -1)}"
TLS_RT="${TLS_RT:-$(ls -d "$HOME/.amalgame/packages/github.com/amalgame-lang/amalgame-tls"/*/runtime 2>/dev/null | sort -V | tail -1)}"
[ -d "$RT" ] || { echo "AMC_RUNTIME introuvable"; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo "[SKIP] openssl CLI absent"; exit 0; }

B="$(mktemp -d)"; trap 'rm -rf "$B"; [ -n "${SRVPID:-}" ] && kill "$SRVPID" 2>/dev/null || true' EXIT

# A throwaway CA, then a leaf per domain signed by it. The served cert
# file for alpha is a FULLCHAIN (leaf + CA) so we can also check that
# the server sends the whole chain (use_certificate_chain_file), not
# just the leaf — that was the v0.12.1 INCOMPLETE_CHAIN fix.
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -keyout "$B/ca.key" -out "$B/ca.crt" -subj "/CN=Test Intermediate CA" >/dev/null 2>&1
for d in alpha.test beta.test; do
    openssl req -newkey rsa:2048 -nodes -keyout "$B/$d.key" -out "$B/$d.csr" \
        -subj "/CN=$d" >/dev/null 2>&1
    openssl x509 -req -in "$B/$d.csr" -CA "$B/ca.crt" -CAkey "$B/ca.key" \
        -CAcreateserial -days 1 -out "$B/$d.leaf.crt" >/dev/null 2>&1
    # fullchain = leaf + CA (intermediate)
    cat "$B/$d.leaf.crt" "$B/ca.crt" > "$B/$d.crt"
done

PORT=18443
cat > "$B/srv.c" <<EOF
#include "Amalgame_Net_Http.h"
#include <stdio.h>
#include <unistd.h>
int main(void){
    GC_INIT();
    SSL_library_init(); SSL_load_error_strings(); OpenSSL_add_all_algorithms();
    AmalgameHttpsH1Server* s = Amalgame_Net_Http_HttpsH1Server_Listen(
        $PORT, "$B/alpha.test.crt", "$B/alpha.test.key", 0);  /* default = alpha */
    if (!s || !Amalgame_Net_Http_HttpsH1Server_IsListening(s)) {
        fprintf(stderr, "listen failed\n"); return 2;
    }
    Amalgame_Net_Http_HttpsH1Server_AddSni(s, "beta.test",
        "$B/beta.test.crt", "$B/beta.test.key");
    printf("ready\n"); fflush(stdout);
    /* AcceptParsed: handshake + parse (covers the v0.12.1 parse fix —
     * Accept alone leaves Method/Path/headers empty). The test makes a
     * few probing connections; some send no request (s_client) so we
     * tolerate NULL and just keep accepting. */
    for (int i = 0; i < 6; i++) {
        AmalgameH1Conn* c = Amalgame_Net_Http_HttpsH1Server_AcceptParsed(s);
        (void)c;
    }
    return 0;
}
EOF

if ! gcc -O2 -Iruntime -I"$RT" -I"$ASYNC_RT" -I"$TLS_RT" \
    "$B/srv.c" -lssl -lcrypto -lgc -lnghttp2 -lpthread -o "$B/srv" 2>"$B/gcc.log"; then
    echo "[FAIL] build du serveur SNI de test:"; head -10 "$B/gcc.log"; exit 1
fi

"$B/srv" > "$B/srv.out" 2>/dev/null &
SRVPID=$!
# attendre "ready"
for _ in $(seq 1 50); do grep -q ready "$B/srv.out" 2>/dev/null && break; sleep 0.1; done

cn_for() {  # $1 = servername
    echo | openssl s_client -connect 127.0.0.1:$PORT -servername "$1" 2>/dev/null \
        | openssl x509 -noout -subject 2>/dev/null
}

A="$(cn_for alpha.test)"
Bsub="$(cn_for beta.test)"
echo "alpha.test → $A"
echo "beta.test  → $Bsub"

fail=0
echo "$A"    | grep -q "alpha.test" || { echo "[FAIL] alpha.test n'a pas reçu le cert alpha"; fail=1; }
echo "$Bsub" | grep -q "beta.test"  || { echo "[FAIL] beta.test n'a pas reçu le cert beta (SNI cassé)"; fail=1; }

# Chaîne complète : le serveur doit renvoyer leaf + CA (>= 2 certs),
# sinon les clients/proxies stricts rejettent (INCOMPLETE_CHAIN).
NCERTS="$(echo | openssl s_client -connect 127.0.0.1:$PORT -servername alpha.test -showcerts 2>/dev/null | grep -c 'BEGIN CERTIFICATE')"
echo "alpha.test → $NCERTS cert(s) servis"
[ "${NCERTS:-0}" -ge 2 ] || { echo "[FAIL] chaîne incomplète (leaf seul) — use_certificate_chain_file ?"; fail=1; }

[ "$fail" -eq 0 ] && echo "[PASS] SNI + chaîne complète" || { echo "FAIL (SNI/chain)"; exit 1; }
