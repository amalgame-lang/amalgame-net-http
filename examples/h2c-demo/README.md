# h2c-demo

Minimal HTTP/2 cleartext (h2c) server using `amalgame-net-http v0.2`.

Three routes:

| Route       | Method | Response                                      |
|-------------|--------|-----------------------------------------------|
| `/`         | GET    | HTML page (200)                               |
| `/api/info` | GET    | JSON payload (200)                            |
| `/echo`     | POST   | echoes method/path/body length and body (200) |
| anything else | any  | `404 Not Found`                               |

## Build & run

Requires:

- `amc` ≥ v0.8.34
- `libnghttp2-dev` (Ubuntu/Debian) or `nghttp2` (Homebrew)
- `amalgame-net-http v0.2.0` installed (`amc package add net-http@v0.2.0`)

Project skeleton:

```text
h2c-demo/
├── amalgame.toml   # declares net-http v0.2.0 dependency
├── amalgame.lock   # locked rev for reproducible builds
└── server.am
```

```bash
amc build server.am
./server
```

## Verify with curl

```bash
curl --http2-prior-knowledge -i http://localhost:3000/
curl --http2-prior-knowledge -i http://localhost:3000/api/info
curl --http2-prior-knowledge -d 'ping pong' http://localhost:3000/echo
```

The status line on every response is `HTTP/2 200` — real h2 framing
served from pure-Amalgame request handlers, with nghttp2 doing the
HEADERS / DATA framing on the wire.

## What's NOT in v0.2

- **TLS + ALPN h2.** v0.2 is plain TCP (h2c). Browsers won't speak
  h2 over cleartext; use `curl --http2-prior-knowledge`, h2 test
  tooling, or a TLS-terminating reverse proxy. Native HTTPS+ALPN
  ships in v0.2.x.
- **Stream multiplexing on the AM side.** The connection runs full
  H2 multiplexing internally, but the AM facade serializes requests
  through `H2Conn.NextRequest`. Heavy concurrent streams are still
  handled correctly — they're just processed one at a time.
- **Binary request bodies with embedded NULs.** Bodies surface as
  `code_string`; use `H2Conn.BodyLen` for the true length.
