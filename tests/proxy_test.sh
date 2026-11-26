#!/usr/bin/env bash
# proxy_test.sh — HttpClient through an HTTP proxy (v0.30.0).
#
# A test proxy (Python) relays CONNECT tunnels and absolute-form requests,
# logs what it is asked and what it relays ; it can require Basic
# credentials, or try to read the traffic by terminating TLS itself with a
# certificate valid for another name. A throwaway CA is trusted through
# SSL_CERT_FILE. Checks
#   1. HTTPS_PROXY : https:// goes through a CONNECT tunnel, 200, whole body
#   2. the proxy relays only ciphertext (no "GET /" in what it carried)
#   3. Proxy(url) on the request, without the environment
#   4. a proxy asking for credentials : 407 reported without them ; with
#      "http://user:password@host:port" the tunnel opens
#   5. a proxy that terminates TLS (certificate valid, for another name) :
#      refused — the server is checked end to end
#   6. NO_PROXY=localhost : direct
#   7. HTTP_PROXY for http:// : absolute-form request line
#   8. Proxy("none") : direct, whatever the environment says
#   9. an unsupported proxy (socks5://) is said, not ignored
# Needs FACADE_O (facade.o of this package, built by run_tests.sh).
set -euo pipefail
cd "$(dirname "$0")/.."
PKG="$(pwd)"
AMC="${AMC:-$(command -v amc)}"
RT="${AMC_RUNTIME:-$HOME/.local/share/amalgame/runtime}"
ASYNC_RT="${ASYNC_RT:-$(ls -d "$HOME/.amalgame/packages/github.com/amalgame-lang/amalgame-async"/*/runtime 2>/dev/null | sort -V | tail -1)}"
TLS_RT="${TLS_RT:-$(ls -d "$HOME/.amalgame/packages/github.com/amalgame-lang/amalgame-tls"/*/runtime 2>/dev/null | sort -V | tail -1)}"
[ -s "${FACADE_O:-}" ] || { echo "FACADE_O introuvable"; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo "[SKIP] openssl absent"; exit 0; }
command -v python3 >/dev/null 2>&1 || { echo "[SKIP] python3 absent"; exit 0; }

B="$(mktemp -d)"; PIDS=""
trap 'for p in $PIDS; do kill "$p" 2>/dev/null || true; done; rm -rf "$B"' EXIT
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -keyout "$B/ca.key" -out "$B/ca.crt" -subj "/CN=Test CA" >/dev/null 2>&1
leaf() {
    openssl req -newkey rsa:2048 -nodes -keyout "$B/$1.key" -out "$B/$1.csr" -subj "/CN=$1" >/dev/null 2>&1
    printf "subjectAltName=%s\n" "$2" > "$B/$1.ext"
    openssl x509 -req -in "$B/$1.csr" -CA "$B/ca.crt" -CAkey "$B/ca.key" -CAcreateserial -days 1 -extfile "$B/$1.ext" -out "$B/$1.crt" >/dev/null 2>&1
}
leaf localhost "DNS:localhost"
leaf other "DNS:proxy.other.test"
export SSL_CERT_FILE="$B/ca.crt"
unset HTTPS_PROXY https_proxy HTTP_PROXY http_proxy NO_PROXY no_proxy || true

cat > "$B/proxy.py" <<'PY'
import socket, ssl, sys, threading, base64
port, log, mode = int(sys.argv[1]), sys.argv[2], sys.argv[3]
cert, key = (sys.argv[4], sys.argv[5]) if len(sys.argv) > 5 else (None, None)
lock = threading.Lock()
def note(s):
    with lock:
        open(log, "a", encoding="utf-8").write(s + "\n")
def carry(a, b, tag):
    try:
        while True:
            d = a.recv(65536)
            if not d: break
            if tag:
                with lock: open(log + ".bytes", "ab").write(d)
            b.sendall(d)
    except Exception: pass
    finally:
        for s in (a, b):
            try: s.shutdown(socket.SHUT_RDWR)
            except Exception: pass
def head(c):
    h = b""
    while b"\r\n\r\n" not in h:
        d = c.recv(1)
        if not d: break
        h += d
    return h.decode(errors="replace")
def serve(c):
    try:
        h = head(c); line = h.split("\r\n")[0]; note(line)
        auth = [l for l in h.split("\r\n") if l.lower().startswith("proxy-authorization:")]
        if mode == "auth":
            want = "Basic " + base64.b64encode(b"kairos:s3cret").decode()
            if not auth or auth[0].split(":", 1)[1].strip() != want:
                c.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"t\"\r\nContent-Length: 0\r\n\r\n"); c.close(); return
            note("auth ok")
        meth, target = line.split(" ")[0], line.split(" ")[1]
        if meth == "CONNECT":
            host, p = target.rsplit(":", 1)
            if mode == "mitm":
                c.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(cert, key)
                t = ctx.wrap_socket(c, server_side=True)
                note("mitm read: " + t.recv(4096).decode(errors="replace").split("\r\n")[0])
                t.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nMITM"); t.close(); return
            u = socket.create_connection((host, int(p)))
            c.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            threading.Thread(target=carry, args=(u, c, False), daemon=True).start()
            carry(c, u, True)
        else:   # absolute form : http://host:port/path
            rest = target.split("://", 1)[1]; hp, _, path = rest.partition("/")
            host, p = hp.rsplit(":", 1)
            u = socket.create_connection((host, int(p)))
            lines = h.split("\r\n"); lines[0] = "%s /%s %s" % (meth, path, line.split(" ")[2])
            u.sendall("\r\n".join(l for l in lines if not l.lower().startswith("proxy-authorization:")).encode())
            threading.Thread(target=carry, args=(u, c, False), daemon=True).start()
            carry(c, u, False)
    except Exception as e:
        note("error " + repr(e))
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port)); s.listen(16)
while True:
    c, _ = s.accept(); threading.Thread(target=serve, args=(c,), daemon=True).start()
PY
python3 "$B/proxy.py" 18491 "$B/relay.log" relay >/dev/null 2>&1 & PIDS="$PIDS $!"
python3 "$B/proxy.py" 18492 "$B/auth.log" auth >/dev/null 2>&1 & PIDS="$PIDS $!"
python3 "$B/proxy.py" 18493 "$B/mitm.log" mitm "$B/other.crt" "$B/other.key" >/dev/null 2>&1 & PIDS="$PIDS $!"
openssl s_server -quiet -www -accept 18494 -cert "$B/localhost.crt" -key "$B/localhost.key" >/dev/null 2>&1 & PIDS="$PIDS $!"
mkdir -p "$B/www" && echo "proxied-ok" > "$B/www/index.html"
( cd "$B/www" && python3 -m http.server 18495 --bind 127.0.0.1 >/dev/null 2>&1 ) & PIDS="$PIDS $!"
sleep 1

SRC="facade.am cookie.am http_request.am http_response.am http_parser.am http_server.am http_client.am multipart.am sse.am"
ext=""; for s in $SRC; do ext="$ext --external $PKG/$s"; done
"$AMC" -o "$B/cli" "$PKG/tests/client_verify.am" $ext > "$B/amc.log" 2>&1 || { tail -5 "$B/amc.log"; exit 1; }
gcc -O2 -I"$PKG/runtime" -I"$RT" -I"$ASYNC_RT" -I"$TLS_RT" "$B/cli.c" "$FACADE_O" \
    -lgc -lm -lpthread -lssl -lcrypto -lnghttp2 -lcurl -lz -o "$B/cli" > "$B/cc.log" 2>&1 || { grep error "$B/cc.log" | head; exit 1; }

FAILS=0
check() { if [ "$1" = 0 ]; then echo "[PASS] $2"; else echo "[FAIL] $2"; FAILS=$((FAILS+1)); fi; }
lines() { [ -f "$1" ] && grep -c . "$1" || echo 0; }
HTTPS=https://localhost:18494/

o=$(HTTPS_PROXY=http://127.0.0.1:18491 CV_URL=$HTTPS "$B/cli")
check $(echo "$o" | grep -q "^status=200 .*complete=1" && grep -q "^CONNECT localhost:18494 " "$B/relay.log"; echo $?) "1. HTTPS_PROXY : tunnel CONNECT localhost:18494, 200, réponse complète"
check $( [ -s "$B/relay.log.bytes" ] && ! grep -aq "GET /" "$B/relay.log.bytes"; echo $?) "2. le proxy n'a relayé que du chiffré ($(stat -c %s "$B/relay.log.bytes") octets, aucun « GET / » lisible)"
n0=$(lines "$B/relay.log")
o=$(CV_PROXY=http://127.0.0.1:18491 CV_URL=$HTTPS "$B/cli")
check $(echo "$o" | grep -q "^status=200" && [ "$(lines "$B/relay.log")" -gt "$n0" ]; echo $?) "3. Proxy(url) sur la requête, sans variable d'environnement"
o1=$(HTTPS_PROXY=http://127.0.0.1:18492 CV_URL=$HTTPS "$B/cli")
o2=$(HTTPS_PROXY=http://kairos:s3cret@127.0.0.1:18492 CV_URL=$HTTPS "$B/cli")
check $(echo "$o1" | grep -q "proxy refused the tunnel (407)" && echo "$o2" | grep -q "^status=200" && grep -q "auth ok" "$B/auth.log"; echo $?) "4. proxy à identifiants : 407 dit sans eux ; http://kairos:…@hôte:port ouvre le tunnel"
o=$(HTTPS_PROXY=http://127.0.0.1:18493 CV_URL=$HTTPS "$B/cli")
check $(echo "$o" | grep -q "^status=0 .*certificate not valid for localhost" && ! grep -q "mitm read" "$B/mitm.log" 2>/dev/null; echo $?) "5. proxy qui déchiffre (certificat valide d'un autre nom) : refusé, il ne lit rien"
n0=$(lines "$B/relay.log")
o=$(HTTPS_PROXY=http://127.0.0.1:18491 NO_PROXY=example.com,localhost CV_URL=$HTTPS "$B/cli")
check $(echo "$o" | grep -q "^status=200" && [ "$(lines "$B/relay.log")" = "$n0" ]; echo $?) "6. NO_PROXY=localhost : direct"
o=$(HTTP_PROXY=http://127.0.0.1:18491 CV_URL=http://127.0.0.1:18495/ "$B/cli")
check $(echo "$o" | grep -q "^status=200" && grep -q "^GET http://127.0.0.1:18495/ HTTP/1.1" "$B/relay.log"; echo $?) "7. HTTP_PROXY pour http:// : requête en forme absolue"
n0=$(lines "$B/relay.log")
o=$(HTTPS_PROXY=http://127.0.0.1:18491 CV_PROXY=none CV_URL=$HTTPS "$B/cli")
check $(echo "$o" | grep -q "^status=200" && [ "$(lines "$B/relay.log")" = "$n0" ]; echo $?) "8. Proxy(\"none\") : direct malgré l'environnement"
o=$(HTTPS_PROXY=socks5://127.0.0.1:1080 CV_URL=$HTTPS "$B/cli")
check $(echo "$o" | grep -q "^status=0 .*socks5 not supported"; echo $?) "9. proxy non pris en charge (socks5://) : dit, pas ignoré"
[ "$FAILS" = 0 ]
