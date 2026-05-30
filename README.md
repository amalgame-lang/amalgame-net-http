# amalgame-net-http

HTTP/1.1 client + server primitives for [Amalgame](https://github.com/amalgame-lang/Amalgame). Pure-Amalgame parser, socket I/O via [`amalgame-net`](https://github.com/amalgame-lang/Amalgame), HTTPS via [`amalgame-tls`](https://github.com/amalgame-lang/amalgame-tls).

This is the middle layer of the Amalgame web stack:

```
amalgame-tls          (OpenSSL binding — TLS 1.2/1.3)
   └── amalgame-net-http   (HTTP/1.1 + HTTP/2 — this package)
          └── amalgame-web    (Mosaic framework)
```

## Install

```bash
amc package add tls         # required for HTTPS
amc package add net-http
```

No system dependencies beyond what `amalgame-tls` already requires (OpenSSL dev headers).

## API at a glance

### Server

```amalgame
import Amalgame.Net.Http

public class Program {
    public static void Main(string[] args) {
        let srv = HttpServer.Listen(":3000", null)   // null = no TLS
        srv.Serve(fn(req) {
            if (req.Path == "/") {
                return HttpResponse.New().Html("<h1>Hello!</h1>")
            }
            if (req.Path == "/api/echo" && req.Method == "POST") {
                return HttpResponse.New().Json(req.BodyText())
            }
            return HttpResponse.New().Status(404).Text("Not found")
        })
    }
}
```

### HTTPS server (HTTP/1.1 over TLS, since v0.10.0)

```amalgame
import Amalgame.Net.Http

// Hand the cert + key paths to Https.H1Serve — it opens an OpenSSL
// context with ALPN http/1.1, terminates TLS in-process, parses each
// request as HTTP/1.1, and invokes your handler with an H1Conn whose
// .ssl is set (recv/send dispatch through SSL_read/write).
let handler = (conn: int) {
    let req = HttpRequest.FromH1Conn(conn)
    let resp = HttpResponse.New().Text("Hello over HTTPS")
    resp.WriteToH1Conn(conn)
}
Https.H1Serve(443, "/etc/letsencrypt/live/example.com/fullchain.pem",
                   "/etc/letsencrypt/live/example.com/privkey.pem",
                   handler)
```

The multi-thread variant (`Https.H1ServeMt`) accepts the same args
and spawns one pthread per accepted TLS connection.

Pair this with [`amalgame-tls`](https://github.com/amalgame-lang/amalgame-tls)
(`AcmeNative.EnsureCert` + `AutoRenewTimer`) for a fully in-process
HTTPS deployment — no reverse proxy needed.

The older `Https.Serve` (HTTP/2-only, requires the client to negotiate
h2 via ALPN) is still available for browsers that prefer h2.

### Client

```amalgame
let resp: HttpResponse = HttpClient.Get("http://example.com/")
Console.WriteLine("Status: " + String_FromInt(resp.StatusCode))
Console.WriteLine("Body:   " + resp.BodyText)

let post: HttpResponse = HttpClient.Post(
    "http://api.example.com/users",
    "{\"name\":\"Alice\"}",
    "application/json")

// Fluent builder for complex requests.
let custom = HttpClient.Request("PATCH", "http://api.example.com/users/42")
    .Header("Authorization", "Bearer ...")
    .BodyJson("{\"name\":\"Bob\"}")
    .Send()
```

## Classes

| Class | Purpose |
|---|---|
| `HttpRequest` | Parsed incoming request: Method, Path, Headers, Query, Body, helpers (Form, Cookie) |
| `HttpResponse` | Outgoing response builder (Status, Header, Text, Json, Html, Redirect, SetCookie) |
| `Cookie` | Cookie struct + serialization to `Set-Cookie:` header |
| `HttpServer` | Listen + accept loop with handler dispatch (TLS-aware) |
| `HttpClient` | `Get` / `Post` / `Request` builder |
| `HttpRequestBuilder` | Fluent client request builder |
| `HttpParser` | Static parser entry points (used internally by server + client) |

## What's in v0.1

- ✅ HTTP/1.1 request + response parsing (pure AM)
- ✅ Body parsing helpers: `Form()`, urlencoded, plain text
- ✅ Query string parsing, urldecode
- ✅ Cookie parsing + serialization
- ✅ Server: listen, accept, single-request-per-connection
- ✅ Client: GET, POST, fluent builder
- ✅ **CRLF injection guard** (v0.4.2): `HttpResponse.Header(name, value)`
  silently drops any value containing `\r` or `\n` (HTTP-response-
  splitting prevention). Power users can bypass with
  `HeaderUnsafe(name, value)` for trusted internal values.
- ✅ **HttpServerConfig** (v0.4.3): per-server tunables for the
  HTTP/1.1 server. `Http1.ServeWith(port, config, handler)` applies
  the configured `SO_RCVTIMEO` / `SO_SNDTIMEO` to every accepted
  connection (Slowloris guard). Builder + getter pattern (C-struct
  backed, like `TlsConfig`).
- ✅ **All four ServeWith variants** (v0.4.4):
  `Http2.ServeWith(port, config, handler)`,
  `Https.ServeWith(port, cert, key, config, handler)`,
  `Ws.ServeWith(port, config, handler)`,
  `Wss.ServeWith(port, cert, key, config, handler)`. Same socket-
  timeout wiring per accepted connection. **Caveat for Ws/Wss**:
  `SO_RCVTIMEO` persists for the connection lifetime — fine for the
  upgrade handshake, wrong for long-lived frame loops. Handlers
  that intend long idle waits should clear/raise the timeout
  themselves (or wait for v0.4.5's post-upgrade clearing).
- ✅ **HttpServerConfig size limits wired** (v0.4.5): the H1 parser
  now reads `max_body_bytes` / `max_header_bytes` / `max_url_bytes`
  from the per-conn config (stashed by `Http1.ServeWith`). Zero in
  any field = fall back to the library default (current
  `AMALGAME_H1_MAX_BODY` etc.). Over-limit requests close the
  connection with a parse error.
- ✅ **HTTP/1.1 keep-alive** (v0.5.0): when
  `HttpServerConfig.idle_timeout_sec > 0`, `Http1.ServeWith` keeps
  the TCP connection open across requests (HTTP/1.1 default; respects
  `Connection: close` / `Connection: keep-alive` headers).
  `SO_RCVTIMEO` is swapped to the `idle_timeout_sec` value between
  requests so a stale client gets cleaned up after that interval.
  `Http1.Serve` (no config) keeps the legacy one-request-per-conn
  behavior — opt-in via `Http1.ServeWith` + non-zero `idle_timeout_sec`.

## Fiber-driven HTTP/1.1 server — `Http1.ServeAsync` (v0.9.1)

One OS thread, thousands of concurrent slow connections. Each
accepted connection runs in an [`amalgame-async`](https://github.com/amalgame-lang/amalgame-async)
fiber; `recv` / `send` park the fiber on `EAGAIN` via epoll instead
of blocking the OS thread. The handler signature is identical to
`Http1.Serve` — drop-in replacement for the I/O-bound case.

```amalgame
import Amalgame.Net.Http

let handler = (conn: H1Conn) => {
    if (conn.Path == "/slow") {
        // Pretend this is a downstream HTTP / DB / file
        // operation. With ServeAsync this fiber parks and the
        // scheduler advances another concurrent connection;
        // with Serve / ServeMt the OS thread blocks.
        Async.FiberSleep(2000)
    }
    conn.Respond(200, "text/plain", "hello")
    return 0
}
Http1.ServeAsync(8080, handler)
```

| | `Http1.Serve` | `Http1.ServeMt` | `Http1.ServeAsync` |
|---|---|---|---|
| Concurrency | serial | 1 thread / conn | 1 thread, N fibers |
| Memory per conn | n/a | ~8 MB pthread stack | ~64 KB fiber stack |
| Best for | dev / smoke | CPU-bound handlers | **I/O-bound handlers** |
| Platform | all | all | **Linux only (epoll)** |

### Benchmark — 100 ms I/O-bound handler

asyncio HTTP client opening N concurrent connections against a
server whose handler sleeps 100 ms (simulating downstream DB /
HTTP / file I/O). Linux x86_64, 2 cores, 4 GB RAM, gcc -O2, default
listen backlog. RSS sampled every 10 ms during the burst; peak
captured.

| N    | ServeMt           | ServeAsync       |
|------|-------------------|------------------|
| 100  | 1152 ms · 100/100 · 2.5 MB | **123 ms** · 100/100 · 9.8 MB |
| 500  | 2071 ms · 500/500 · 3.7 MB | **1374 ms** · 500/500 · 37 MB |
| 1000 | 2932 ms · 1000/1000 · 6.2 MB | **1628 ms** · 1000/1000 · 71 MB |
| 2000 | 31220 ms · **1665/2000** ⚠ | **1453 ms** · **2000/2000** ✅ |

Takeaways:
- **Throughput:** ServeAsync is 1.5× to 9× faster across the range, single-threaded.
- **Reliability under load:** At N=2000 ServeMt drops 16% of requests and the survivors take 31 s; ServeAsync handles 100% in 1.45 s.
- **Memory shape:** ServeMt's pthread stacks are 8 MB but lazy-mapped — RSS stays small as long as handlers don't touch much stack. ServeAsync's GC-allocated 64 KB stacks are eagerly resident, so RSS scales with concurrency (~70 KB / connection) but is bounded and predictable.
- **Crossover** where ServeMt collapses: somewhere between 1000 and 2000 concurrent connections on this hardware. Limit is pthread setup + kernel scheduler contention, not memory.

Bench script available at `bench/` for reproduction.

`kqueue` (BSD + macOS) backend is planned for `amalgame-async`
v0.2.1, then `Http1.ServeAsync` will work cross-platform.
Windows IOCP after `amalgame-async` v0.3.

**Not yet in v0.9.4:**
- Async H2 / Https / Ws / Wss variants (gated on amalgame-tls
  fiber-aware I/O)

### v0.9.5 — graceful shutdown cancels in-flight fibers

`Http1.ServeAsync` (and `ServeAsyncWith`) now tracks every accepted
connection's fiber in a doubly-linked list rooted on the accept-loop
context. When `amalgame_net_http_stopping` flips (SIGTERM / SIGINT
/ `Http1.RequestShutdown`), the accept loop walks that list and
calls `Async.FiberCancel` on each fiber so handlers parked on
`recv` / `send` / `FiberSleep` wake immediately rather than waiting
out the configured timeouts.

```
shutdown_to_serve_return=0ms     // v0.9.5
                       =4800ms   // v0.9.4 (waits for FiberSleep 5000)
```

A live regression test in `tests/run_tests.sh` (`Http1.ServeAsync
graceful shutdown`) spawns a server, fires one /slow request whose
handler calls `Async.FiberSleep(5000)`, then calls
`Http1.RequestShutdown` 200 ms later. With v0.9.5 + amalgame-async
v0.2.2 the server returns in **0-1 ms** (5/5 runs). Without
cancellation, it would block for the full 5 s.

Requires `amalgame-async >= 0.2.2`.

### v0.9.4 — per-phase async timeouts

`header_timeout_sec` and `body_timeout_sec` are now threaded into
the fiber-driven recv loops. Slow-client mitigation works the
same way as on sync `ServeWith`:

```amalgame
let cfg = HttpServerConfig.Default()
    .WithHeaderTimeoutSec(5)   // 5s to finish request line + headers
    .WithBodyTimeoutSec(30)    // 30s to finish the body once Content-Length is known
    .WithIdleTimeoutSec(15)    // 15s idle between keep-alive requests
Http1.ServeAsyncWith(8080, cfg, handler)
```

When the WaitFd timeout fires, `recv` returns `-1` with
`errno = ETIMEDOUT`, the parser returns `-1`, and the per-conn
fiber closes the socket. No SO_RCVTIMEO is applied (that would
conflict with the fiber's own WaitFd). 0 = library default
(currently 30 s).

### ServeAsyncWith (v0.9.3) — fiber I/O + HttpServerConfig

```amalgame
let cfg = HttpServerConfig.Default()
    .WithMaxBodyBytes(2 * 1024 * 1024)   // 2 MB
    .WithIdleTimeoutSec(15)              // HTTP/1.1 keep-alive on
    .WithListenBacklog(256)

Http1.ServeAsyncWith(8080, cfg, handler)
```

Drop-in replacement for `Http1.ServeAsync` with a per-conn config. Keep-alive policy mirrors the sync `ServeWith`: enabled iff `idle_timeout_sec > 0`, off otherwise (close per-request). The async path manages its own EAGAIN-driven WaitFd timeouts, so `SO_RCVTIMEO` / `SO_SNDTIMEO` are **not** applied — sub-30 s slow-client mitigation lands in v0.9.4 as proper per-phase WaitFd timeouts.

### Keep-alive (v0.9.2)

Each `ServeAsync` fiber now loops: `parse_request → handler →
ResetForReuse → parse next` while the request's `Connection`
header allows it (RFC 7230 defaults: HTTP/1.1 keep-alive unless
`Connection: close`, HTTP/1.0 close unless `Connection: keep-alive`).
The next parse re-uses the existing fiber + socket, so a 100-request
benchmark with `--http1.1` keep-alive amortises the TCP setup +
fiber spawn across all 100 requests.

## Low-level async I/O — drive H1 manually (v0.9.0)

`H1Server_RawFd(srv)` and `H1Conn_RawFd(conn)` expose the
underlying socket fds so user code can park fibers on them
with [`amalgame-async`](https://github.com/amalgame-lang/amalgame-async)
≥ v0.2.0 (Linux epoll backend). This lets a single OS thread
handle thousands of concurrent connections without
thread-per-connection overhead — the sweet spot for I/O-bound
handlers (downstream HTTP, DB queries, file writes).

```amalgame
import Amalgame.Net.Http
import Amalgame.Async

let srv = Http1.H1Server_Listen(8080, 0)
let listenFd: int = Http1.H1Server_RawFd(srv)
Async.MakeNonBlocking(listenFd)

let acceptLoop = (_x: int) => {
    while (true) {
        // park until a connection arrives
        let ok: bool = Async.WaitFdReadable(listenFd, -1)
        if (!ok) { break }
        let conn = Http1.H1Server_Accept(srv)
        if (conn == null) { continue }
        let connFd: int = Http1.H1Conn_RawFd(conn)
        Async.MakeNonBlocking(connFd)
        // spawn a fiber to handle this connection
        Async.FiberSpawn((fd: int) => {
            // ... non-blocking recv + WaitFdReadable loop here,
            // then parse, dispatch handler, write response
            return 0
        }, connFd)
    }
    return 0
}
Async.FiberSpawn(acceptLoop, 0)
Async.SchedulerRun()
```

**A first-class `Http1.ServeAsync(port, handler)`** that does
this dance internally — accept loop + non-blocking parse +
async-aware respond, all running inside the scheduler — is
planned for v0.9.1. v0.9.0 ships the **enablers only** so user
code can experiment with the API surface before we lock in the
high-level entry point.

## What's NOT in v0.1 (deferred to v0.1.x)

- HTTP/2 via nghttp2 (the runtime header stub is in place for the binding)
- HTTPS in `HttpClient.Execute` (the TCP path works, TLS path waits for amalgame-tls integration)
- Keep-alive (each connection currently handles one request)
- Streaming body / chunked transfer encoding
- Multipart form parsing
- Pre-built worker pool (currently single-threaded accept loop)

These are all planned for v0.1.x releases ahead of `amalgame-web v0.1`.

## Test

```bash
./tests/run_tests.sh /path/to/amc
```

## License

Apache-2.0. See [LICENSE](./LICENSE).
