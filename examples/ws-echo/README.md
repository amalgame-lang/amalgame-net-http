# WebSocket echo demo

Tiny end-to-end test of `amalgame-net-http v0.4`'s `Ws.Serve` —
a WS server that echoes every text message it receives.

## Run

```bash
cd examples/ws-echo
amc package add net-http@v0.4.0   # populates amalgame.lock next to amalgame.toml
amc build server.am
./server                           # listens on ws://localhost:8080
```

The `amc package add` call must run **inside this directory** — it
writes `amalgame.lock` here. If you skip it (or run it from a
different cwd) the resolver won't find the `net-http` dep and the
build dies with `Unknown symbol 'WsConn'`.

Open [`client.html`](client.html) in your browser (just
double-click the file; no HTTP server needed since the JS connects
directly to `ws://localhost:8080`).

Type a message in the input box, hit Enter. You'll see:
- `→ your message` (sent)
- `← echo @ your message` (server reply)

The server logs each connection / disconnection / message in the
terminal.

## What v0.4 ships

- RFC 6455 handshake (`Sec-WebSocket-Key` → `Sec-WebSocket-Accept`)
- Text frames in / out
- PING auto-replied with PONG
- CLOSE handled gracefully
- 1 MB max payload per frame
- Plain `ws://` only (`wss://` over TLS in v0.4.x)
