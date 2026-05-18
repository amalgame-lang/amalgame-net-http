/*
 * Amalgame.Net.Http — HTTP/1.1 client + server primitives.
 * Copyright (c) 2026 Bastien MOUGET
 * Licensed under the Apache License, Version 2.0.
 * https://github.com/amalgame-lang/amalgame-net-http
 *
 * v0.1: pure-Amalgame HTTP/1.1 implementation lives in `facade.am`.
 * This header is intentionally a thin stub — the package manifest
 * still requires it, but no native symbols ship in v0.1.
 *
 * v0.1.x will add the nghttp2 binding here for HTTP/2 frame parsing:
 *   - nghttp2_session_client_new / _server_new
 *   - frame send / recv callbacks bridged to amalgame-tls TlsStream
 *   - stream multiplexing
 *
 * The AM-level API (HttpRequest / HttpResponse / HttpServer /
 * HttpClient) stays identical between HTTP/1.1 and HTTP/2 — the
 * server inspects the negotiated ALPN protocol on the TLS handshake
 * and dispatches to the right parser internally.
 */

#ifndef AMALGAME_NET_HTTP_H
#define AMALGAME_NET_HTTP_H

#include "_runtime.h"

/* No native symbols in v0.1 — every class is implemented in the
 * facade. The forward decls below exist only so any future
 * `@c {}` block inside the facade can refer to them by name without
 * having to redeclare the struct. */

/* Reserved for nghttp2 binding (v0.1.x) — placeholders only. */
typedef struct AmalgameHttp2Session AmalgameHttp2Session;

#endif /* AMALGAME_NET_HTTP_H */
