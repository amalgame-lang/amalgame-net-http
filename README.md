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

### HTTPS server (via amalgame-tls)

```amalgame
import Amalgame.Net.Http
import Amalgame.Tls

let tlsCfg = TlsConfig.Default()
    .WithCertFile("cert.pem", "key.pem")
    .WithAlpn("http/1.1")
let tlsCtx = TlsContext.Server(tlsCfg)

let srv = HttpServer.Listen(":443", tlsCtx)
srv.Serve(fn(req) {
    return HttpResponse.New().Text("Hello over HTTPS")
})
```

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

## Async I/O — drive H1 with `amalgame-async` fibers (v0.9.0)

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
