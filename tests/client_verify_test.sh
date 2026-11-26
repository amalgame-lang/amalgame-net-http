#!/usr/bin/env bash
# client_verify_test.sh — HttpClient over HTTPS, certificate verification ON.
#
# Before v0.29.9 the client checked that the server's certificate chained
# to a trusted CA, but not that it was issued for the host it called : any
# valid certificate (for another name) was accepted, so anyone on the path
# could impersonate the server and read the request (an API key, a
# password). A server that went silent hung the caller for ever (HTTPS had
# no timeout), and a read cut by a GC signal or by the timeout ended the
# loop as if the response were complete.
#
# Here, with a throwaway CA trusted through SSL_CERT_FILE (no
# AMALGAME_TLS_INSECURE) :
#   1. the right name           → 200
#   2. a valid cert, wrong name → refused (Status 0)
#   3. an IP literal : SAN IP   → 200 ; SAN DNS only → refused
#   4. a silent server, HTTP and HTTPS, Timeout(1500) → "timeout" in < 5 s
#   5. 40 HTTPS requests while a thread allocates and collects (GC signals)
#      → 40 complete bodies
#
# The client is tests/client_verify.am, built by amc against this package's
# sources and linked with FACADE_O (built by run_tests.sh). OLD_DIR +
# OLD_FACADE_O, when given (an older checkout and its facade.o), run the
# wrong-name case on that version as a witness : it must accept it.
set -euo pipefail
cd "$(dirname "$0")/.."
PKG="$(pwd)"

AMC="${AMC:-$(command -v amc)}"
RT="${AMC_RUNTIME:-$HOME/.local/share/amalgame/runtime}"
ASYNC_RT="${ASYNC_RT:-$(ls -d "$HOME/.amalgame/packages/github.com/amalgame-lang/amalgame-async"/*/runtime 2>/dev/null | sort -V | tail -1)}"
TLS_RT="${TLS_RT:-$(ls -d "$HOME/.amalgame/packages/github.com/amalgame-lang/amalgame-tls"/*/runtime 2>/dev/null | sort -V | tail -1)}"
[ -d "$RT" ] || { echo "AMC_RUNTIME introuvable"; exit 1; }
[ -x "$AMC" ] || { echo "amc introuvable"; exit 1; }
[ -s "${FACADE_O:-}" ] || { echo "FACADE_O introuvable"; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo "[SKIP] openssl CLI absent"; exit 0; }
command -v python3 >/dev/null 2>&1 || { echo "[SKIP] python3 absent"; exit 0; }

B="$(mktemp -d)"
PIDS=""
trap 'for p in $PIDS; do kill "$p" 2>/dev/null || true; done; rm -rf "$B"' EXIT

# A CA, and leaves it signs : the right name, another name, an IP.
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -keyout "$B/ca.key" -out "$B/ca.crt" \
    -subj "/CN=Test CA" >/dev/null 2>&1
leaf() {  # name san
    openssl req -newkey rsa:2048 -nodes -keyout "$B/$1.key" -out "$B/$1.csr" -subj "/CN=$1" >/dev/null 2>&1
    printf "subjectAltName=%s\n" "$2" > "$B/$1.ext"
    openssl x509 -req -in "$B/$1.csr" -CA "$B/ca.crt" -CAkey "$B/ca.key" -CAcreateserial \
        -days 1 -extfile "$B/$1.ext" -out "$B/$1.crt" >/dev/null 2>&1
}
leaf localhost "DNS:localhost"
leaf alpha.test "DNS:alpha.test"
leaf ip "IP:127.0.0.1"
export SSL_CERT_FILE="$B/ca.crt"
unset AMALGAME_TLS_INSECURE || true

serve() {  # port cert
    openssl s_server -quiet -www -accept "$1" -cert "$B/$2.crt" -key "$B/$2.key" >/dev/null 2>&1 &
    PIDS="$PIDS $!"
}
serve 18461 localhost
serve 18462 alpha.test
serve 18463 ip
# Silent servers : accept, never answer (plain ; and TLS, after the handshake).
python3 - 18464 <<'PY' >/dev/null 2>&1 &
import socket, sys
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1]))); s.listen(8)
held = []
while True:
    c, _ = s.accept(); held.append(c)
PY
PIDS="$PIDS $!"
sleep 60 | openssl s_server -quiet -accept 18465 -cert "$B/localhost.crt" -key "$B/localhost.key" >/dev/null 2>&1 &
PIDS="$PIDS $!"
sleep 1

SRC="facade.am cookie.am http_request.am http_response.am http_parser.am http_server.am http_client.am multipart.am sse.am"
build() {  # pkgdir facade.o test.am out
    local ext=""
    for s in $SRC; do ext="$ext --external $1/$s"; done
    "$AMC" -o "$4" "$3" $ext > "$B/amc.log" 2>&1 || { tail -5 "$B/amc.log"; return 1; }
    gcc -O2 -I"$1/runtime" -I"$RT" -I"$ASYNC_RT" -I"$TLS_RT" "$4.c" "$2" \
        -lgc -lm -lpthread -lssl -lcrypto -lnghttp2 -lcurl -lz -o "$4" > "$B/cc.log" 2>&1 \
        || { grep -E "error" "$B/cc.log" | head -10; return 1; }
}
build "$PKG" "$FACADE_O" "$PKG/tests/client_verify.am" "$B/cli"

run() {  # bin url timeout count churn
    CV_URL="$2" CV_TIMEOUT="$3" CV_COUNT="$4" CV_CHURN="$5" "$1"
}
FAILS=0
check() {  # label expect-regex output
    if echo "$3" | grep -Eq "$2"; then echo "[PASS] $1"; else echo "[FAIL] $1 : $3"; FAILS=$((FAILS+1)); fi
}

out=$(run "$B/cli" https://localhost:18461/ 5000 1 0)
check "1. bon nom (localhost) : accepté" "^status=200 .*complete=1" "$out"
out=$(run "$B/cli" https://localhost:18462/ 5000 1 0)
check "2. certificat valide d'un autre nom (alpha.test) : refusé" "^status=0 .*certificate not valid for localhost" "$out"
out=$(run "$B/cli" https://127.0.0.1:18463/ 5000 1 0)
check "3a. adresse IP, certificat IP:127.0.0.1 : accepté" "^status=200 .*complete=1" "$out"
out=$(run "$B/cli" https://127.0.0.1:18461/ 5000 1 0)
check "3b. adresse IP, certificat DNS:localhost seulement : refusé" "^status=0 " "$out"
out=$(run "$B/cli" http://127.0.0.1:18464/ 1500 1 0)
ms=$(echo "$out" | sed -n 's/.*ms=\([0-9]*\).*/\1/p')
check "4a. serveur HTTP muet : « timeout » en ${ms} ms" "^status=0 .*text=timeout" "$out"
[ "${ms:-99999}" -lt 5000 ] || { echo "[FAIL] 4a. trop long : ${ms} ms"; FAILS=$((FAILS+1)); }
out=$(run "$B/cli" https://localhost:18465/ 1500 1 0)
ms=$(echo "$out" | sed -n 's/.*ms=\([0-9]*\).*/\1/p')
check "4b. serveur HTTPS muet : « timeout » en ${ms} ms" "^status=0 .*text=timeout" "$out"
[ "${ms:-99999}" -lt 5000 ] || { echo "[FAIL] 4b. trop long : ${ms} ms"; FAILS=$((FAILS+1)); }
out=$(run "$B/cli" https://localhost:18461/ 10000 40 1)
ok=$(echo "$out" | grep -c "^status=200 .*complete=1" || true)
if [ "$ok" = 40 ]; then echo "[PASS] 5. 40 requêtes HTTPS sous les signaux du collecteur : 40/40 complètes"
else echo "[FAIL] 5. sous les signaux du collecteur : $ok/40 complètes"; echo "$out" | grep -v "complete=1" | head -3; FAILS=$((FAILS+1)); fi

if [ -n "${OLD_DIR:-}" ] && [ -s "${OLD_FACADE_O:-}" ]; then
    # The older client has no Timeout() nor Proxy() : the witness drops them.
    sed -e 's/\.Timeout(timeoutMs)//' -e '/b\.Proxy(proxy)/d' "$PKG/tests/client_verify.am" > "$B/client_old.am"
    if build "$OLD_DIR" "$OLD_FACADE_O" "$B/client_old.am" "$B/cli_old"; then
        out=$(run "$B/cli_old" https://localhost:18462/ 5000 1 0 2>&1 || true)
        echo "[TÉMOIN] version précédente, certificat valide d'un autre nom : $out"
    fi
fi

[ "$FAILS" = 0 ]
