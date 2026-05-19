/*
 * Amalgame.Net.Http — HTTP/1.1 + HTTP/2 primitives.
 * Copyright (c) 2026 Bastien MOUGET
 * Licensed under the Apache License, Version 2.0.
 * https://github.com/amalgame-lang/amalgame-net-http
 *
 * v0.1: pure-Amalgame HTTP/1.1 lives in `facade.am`.
 * v0.2: nghttp2 server binding (h2c — HTTP/2 cleartext) here.
 *
 * Scope of v0.2:
 *   - Server-side HTTP/2 over plain TCP (h2c). Used by clients that
 *     speak HTTP/2 with prior knowledge (`curl --http2-prior-knowledge`,
 *     gRPC servers behind a TLS-terminating proxy, h2 tests).
 *   - TLS+ALPN integration is deferred to v0.2.x — the nghttp2
 *     session itself is already wrapped here, so adding the TLS
 *     bytes-in/bytes-out shim later is straightforward.
 *
 * Architecture (h2c):
 *
 *     conn = AmalgameH2Conn_NewFromFd(fd)
 *     while ((sid = AmalgameH2Conn_NextRequest(conn)) > 0) {
 *         method = AmalgameH2Conn_Method(conn)
 *         path   = AmalgameH2Conn_Path(conn)
 *         body   = AmalgameH2Conn_Body(conn)
 *         // … build a response in AM …
 *         AmalgameH2Conn_Respond(conn, status, content_type, body)
 *     }
 *     AmalgameH2Conn_Close(conn)
 *
 * Internally NextRequest drives nghttp2_session_send (flush queued
 * frames) and nghttp2_session_mem_recv (consume incoming bytes from
 * the TCP socket). It returns when a request reaches END_STREAM.
 *
 * Stub fallback: when nghttp2 headers are absent at compile time,
 * all H2 entry points return error sentinels — AM code can detect
 * via Available() == 0 and refuse to serve H2.
 */

#ifndef AMALGAME_NET_HTTP_H
#define AMALGAME_NET_HTTP_H

#include "_runtime.h"
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>

/* nghttp2 header probe — multi-OS, mirrors the OpenSSL pattern in
 * amalgame-tls. macOS gets a Homebrew path fallback. */
#if defined(__has_include)
#  if __has_include(<nghttp2/nghttp2.h>)
#    define AMALGAME_HAS_NGHTTP2 1
#    include <nghttp2/nghttp2.h>
#  elif defined(__APPLE__) && __has_include("/opt/homebrew/include/nghttp2/nghttp2.h")
#    define AMALGAME_HAS_NGHTTP2 1
#    include "/opt/homebrew/include/nghttp2/nghttp2.h"
#  endif
#endif

/* ────────────────────────────────────────────────────────────────
 * AmalgameH2Conn — one h2c connection.
 * ──────────────────────────────────────────────────────────────── */

#define AMALGAME_H2_MAX_HEADERS 64
#define AMALGAME_H2_RECV_BUF    16384

typedef struct AmalgameH2Header {
    char* name;
    char* value;
} AmalgameH2Header;

typedef struct AmalgameH2Conn {
    int       fd;
#ifdef AMALGAME_HAS_NGHTTP2
    nghttp2_session* session;
#else
    void*     session;
#endif
    /* Current pending request — single-stream-at-a-time on the AM
     * side (h2's stream multiplexing is real, but we serialize at
     * the API boundary for v0.2 simplicity). */
    int32_t   current_stream;
    int32_t   request_ready;
    int32_t   want_close;

    char*     method;       /* :method */
    char*     path;         /* :path */
    char*     authority;    /* :authority */
    char*     scheme;       /* :scheme */

    AmalgameH2Header headers[AMALGAME_H2_MAX_HEADERS];
    int32_t   header_count;

    char*     body;         /* request body — growable, NUL-terminated */
    int32_t   body_len;
    int32_t   body_cap;

    /* Pending response — kept here so the data_source callback can
     * stream it out (nghttp2 may chunk DATA frames). */
    char*     resp_body;
    int32_t   resp_body_len;
    int32_t   resp_body_off;
} AmalgameH2Conn;

typedef struct AmalgameH2Server {
    int       fd;
    int32_t   listening;
    i64       port;
} AmalgameH2Server;

/* ────────────────────────────────────────────────────────────────
 * Real nghttp2 implementation — only compiled if headers found.
 * ──────────────────────────────────────────────────────────────── */

#ifdef AMALGAME_HAS_NGHTTP2

/* ── nghttp2 callbacks ────────────────────────────────── */

static ssize_t amalgame_h2_send_cb(nghttp2_session* sess, const uint8_t* data,
                                    size_t len, int flags, void* user) {
    (void)sess; (void)flags;
    AmalgameH2Conn* c = (AmalgameH2Conn*)user;
    if (!c || c->fd < 0) return NGHTTP2_ERR_CALLBACK_FAILURE;
    ssize_t total = 0;
    while ((size_t)total < len) {
        ssize_t n = send(c->fd, data + total, len - total, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return total > 0 ? total : NGHTTP2_ERR_WOULDBLOCK;
            }
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        if (n == 0) return NGHTTP2_ERR_CALLBACK_FAILURE;
        total += n;
    }
    return total;
}

static int amalgame_h2_on_begin_headers_cb(nghttp2_session* sess,
                                            const nghttp2_frame* frame,
                                            void* user) {
    (void)sess;
    AmalgameH2Conn* c = (AmalgameH2Conn*)user;
    if (frame->hd.type != NGHTTP2_HEADERS) return 0;
    if (frame->headers.cat != NGHTTP2_HCAT_REQUEST) return 0;
    c->current_stream = frame->hd.stream_id;
    c->header_count = 0;
    c->method = NULL; c->path = NULL;
    c->authority = NULL; c->scheme = NULL;
    c->body_len = 0;
    c->request_ready = 0;
    return 0;
}

static char* amalgame_h2_dup(const uint8_t* s, size_t n) {
    char* p = (char*)GC_MALLOC_ATOMIC(n + 1);
    if (n > 0) memcpy(p, s, n);
    p[n] = 0;
    return p;
}

static int amalgame_h2_on_header_cb(nghttp2_session* sess,
                                     const nghttp2_frame* frame,
                                     const uint8_t* name, size_t namelen,
                                     const uint8_t* value, size_t valuelen,
                                     uint8_t flags, void* user) {
    (void)sess; (void)flags;
    AmalgameH2Conn* c = (AmalgameH2Conn*)user;
    if (frame->hd.type != NGHTTP2_HEADERS) return 0;
    if (frame->headers.cat != NGHTTP2_HCAT_REQUEST) return 0;

    if (namelen > 0 && name[0] == ':') {
        if (namelen == 7 && memcmp(name, ":method", 7) == 0) {
            c->method = amalgame_h2_dup(value, valuelen);
        } else if (namelen == 5 && memcmp(name, ":path", 5) == 0) {
            c->path = amalgame_h2_dup(value, valuelen);
        } else if (namelen == 10 && memcmp(name, ":authority", 10) == 0) {
            c->authority = amalgame_h2_dup(value, valuelen);
        } else if (namelen == 7 && memcmp(name, ":scheme", 7) == 0) {
            c->scheme = amalgame_h2_dup(value, valuelen);
        }
        return 0;
    }
    if (c->header_count < AMALGAME_H2_MAX_HEADERS) {
        c->headers[c->header_count].name  = amalgame_h2_dup(name, namelen);
        c->headers[c->header_count].value = amalgame_h2_dup(value, valuelen);
        c->header_count++;
    }
    return 0;
}

static int amalgame_h2_on_data_chunk_cb(nghttp2_session* sess, uint8_t flags,
                                         int32_t stream_id,
                                         const uint8_t* data, size_t len,
                                         void* user) {
    (void)sess; (void)flags; (void)stream_id;
    AmalgameH2Conn* c = (AmalgameH2Conn*)user;
    if (c->body_len + (int32_t)len + 1 > c->body_cap) {
        int32_t newcap = c->body_cap ? c->body_cap * 2 : 1024;
        while (newcap < c->body_len + (int32_t)len + 1) newcap *= 2;
        char* nb = (char*)GC_MALLOC_ATOMIC(newcap);
        if (c->body_len > 0) memcpy(nb, c->body, c->body_len);
        c->body = nb;
        c->body_cap = newcap;
    }
    memcpy(c->body + c->body_len, data, len);
    c->body_len += (int32_t)len;
    c->body[c->body_len] = 0;
    return 0;
}

static int amalgame_h2_on_frame_recv_cb(nghttp2_session* sess,
                                         const nghttp2_frame* frame,
                                         void* user) {
    (void)sess;
    AmalgameH2Conn* c = (AmalgameH2Conn*)user;
    if ((frame->hd.flags & NGHTTP2_FLAG_END_STREAM) &&
        (frame->hd.type == NGHTTP2_HEADERS ||
         frame->hd.type == NGHTTP2_DATA)) {
        c->request_ready = 1;
    }
    return 0;
}

static int amalgame_h2_on_stream_close_cb(nghttp2_session* sess,
                                           int32_t stream_id,
                                           uint32_t error_code, void* user) {
    (void)sess; (void)stream_id; (void)error_code; (void)user;
    return 0;
}

/* Response body data source — feeds DATA frames from c->resp_body. */
static ssize_t amalgame_h2_data_source_cb(nghttp2_session* sess,
                                           int32_t stream_id,
                                           uint8_t* buf, size_t length,
                                           uint32_t* data_flags,
                                           nghttp2_data_source* source,
                                           void* user) {
    (void)sess; (void)stream_id; (void)source;
    AmalgameH2Conn* c = (AmalgameH2Conn*)user;
    int32_t remaining = c->resp_body_len - c->resp_body_off;
    if (remaining <= 0) {
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
        return 0;
    }
    size_t copy = (size_t)remaining < length ? (size_t)remaining : length;
    memcpy(buf, c->resp_body + c->resp_body_off, copy);
    c->resp_body_off += (int32_t)copy;
    if (c->resp_body_off >= c->resp_body_len) {
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    }
    return (ssize_t)copy;
}

/* ── Public API (real path) ───────────────────────────── */

static inline AmalgameH2Conn* Amalgame_Net_Http_H2Conn_NewFromFd(i64 fd) {
    if (fd < 0) return NULL;
    AmalgameH2Conn* c = (AmalgameH2Conn*)GC_MALLOC(sizeof(AmalgameH2Conn));
    memset(c, 0, sizeof(*c));
    c->fd = (int)fd;
    c->current_stream = 0;

    nghttp2_session_callbacks* cbs = NULL;
    if (nghttp2_session_callbacks_new(&cbs) != 0) return NULL;
    nghttp2_session_callbacks_set_send_callback(cbs, amalgame_h2_send_cb);
    nghttp2_session_callbacks_set_on_begin_headers_callback(cbs, amalgame_h2_on_begin_headers_cb);
    nghttp2_session_callbacks_set_on_header_callback(cbs, amalgame_h2_on_header_cb);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs, amalgame_h2_on_data_chunk_cb);
    nghttp2_session_callbacks_set_on_frame_recv_callback(cbs, amalgame_h2_on_frame_recv_cb);
    nghttp2_session_callbacks_set_on_stream_close_callback(cbs, amalgame_h2_on_stream_close_cb);

    if (nghttp2_session_server_new(&c->session, cbs, c) != 0) {
        nghttp2_session_callbacks_del(cbs);
        return NULL;
    }
    nghttp2_session_callbacks_del(cbs);

    nghttp2_settings_entry iv[1] = {
        { NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100 }
    };
    nghttp2_submit_settings(c->session, NGHTTP2_FLAG_NONE, iv, 1);

    return c;
}

/* Blocks until one request is complete. Returns the stream_id (>0)
 * on success, 0 on clean close, -1 on error. */
static inline i64 Amalgame_Net_Http_H2Conn_NextRequest(AmalgameH2Conn* c) {
    if (!c || !c->session) return -1;
    unsigned char recv_buf[AMALGAME_H2_RECV_BUF];

    c->request_ready = 0;
    while (!c->request_ready && !c->want_close) {
        int rv = nghttp2_session_send(c->session);
        if (rv != 0) return -1;

        ssize_t n = recv(c->fd, recv_buf, sizeof(recv_buf), 0);
        if (n == 0) return 0;          /* peer closed cleanly */
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        ssize_t consumed = nghttp2_session_mem_recv(c->session, recv_buf,
                                                     (size_t)n);
        if (consumed < 0) return -1;
    }
    return c->request_ready ? (i64)c->current_stream : 0;
}

/* Getters — return null-terminated C strings; "" when absent so AM
 * code doesn't need null-guards. NOTE: body may contain embedded NUL
 * for binary uploads — use BodyLen() to be safe with binary. */
static inline code_string Amalgame_Net_Http_H2Conn_Method(AmalgameH2Conn* c) {
    return (c && c->method) ? c->method : "";
}
static inline code_string Amalgame_Net_Http_H2Conn_Path(AmalgameH2Conn* c) {
    return (c && c->path) ? c->path : "";
}
static inline code_string Amalgame_Net_Http_H2Conn_Authority(AmalgameH2Conn* c) {
    return (c && c->authority) ? c->authority : "";
}
static inline code_string Amalgame_Net_Http_H2Conn_Header(AmalgameH2Conn* c,
                                                           code_string name) {
    if (!c || !name) return "";
    size_t nlen = strlen(name);
    for (int i = 0; i < c->header_count; i++) {
        if (strlen(c->headers[i].name) == nlen &&
            memcmp(c->headers[i].name, name, nlen) == 0) {
            return c->headers[i].value;
        }
    }
    return "";
}
static inline code_string Amalgame_Net_Http_H2Conn_Body(AmalgameH2Conn* c) {
    return (c && c->body) ? c->body : "";
}
static inline i64 Amalgame_Net_Http_H2Conn_BodyLen(AmalgameH2Conn* c) {
    return (c && c->body) ? (i64)c->body_len : 0;
}

/* Submit response. content_type may be "" (defaults to text/plain). */
static inline void Amalgame_Net_Http_H2Conn_Respond(AmalgameH2Conn* c,
                                                     i64 status,
                                                     code_string content_type,
                                                     code_string body) {
    if (!c || !c->session) return;

    size_t blen = body ? strlen(body) : 0;
    char* bb = (char*)GC_MALLOC_ATOMIC(blen + 1);
    if (blen > 0) memcpy(bb, body, blen);
    bb[blen] = 0;
    c->resp_body = bb;
    c->resp_body_len = (int32_t)blen;
    c->resp_body_off = 0;

    char status_buf[8];
    snprintf(status_buf, sizeof(status_buf), "%lld", (long long)status);

    char clen_buf[32];
    snprintf(clen_buf, sizeof(clen_buf), "%d", c->resp_body_len);

    const char* ct = (content_type && content_type[0])
                     ? content_type
                     : "text/plain; charset=utf-8";

    nghttp2_nv hdrs[3] = {
        { (uint8_t*)":status",        (uint8_t*)status_buf,
          7, strlen(status_buf), NGHTTP2_NV_FLAG_NONE },
        { (uint8_t*)"content-type",   (uint8_t*)ct,
          12, strlen(ct), NGHTTP2_NV_FLAG_NONE },
        { (uint8_t*)"content-length", (uint8_t*)clen_buf,
          14, strlen(clen_buf), NGHTTP2_NV_FLAG_NONE },
    };

    nghttp2_data_provider dp;
    dp.source.ptr = c;
    dp.read_callback = amalgame_h2_data_source_cb;

    nghttp2_submit_response(c->session, c->current_stream, hdrs, 3, &dp);
    nghttp2_session_send(c->session);
}

static inline void Amalgame_Net_Http_H2Conn_Close(AmalgameH2Conn* c) {
    if (!c) return;
    if (c->session) {
        nghttp2_session_terminate_session(c->session, NGHTTP2_NO_ERROR);
        nghttp2_session_send(c->session);
        nghttp2_session_del(c->session);
        c->session = NULL;
    }
    if (c->fd >= 0) {
        close(c->fd);
        c->fd = -1;
    }
    c->want_close = 1;
}

/* ── H2Server — minimal TCP listener for h2c ───────────── */

static inline AmalgameH2Server* Amalgame_Net_Http_H2Server_Listen(i64 port) {
    AmalgameH2Server* s =
        (AmalgameH2Server*)GC_MALLOC(sizeof(AmalgameH2Server));
    s->fd = -1; s->listening = 0; s->port = port;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return s;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)port);
    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0 ||
        listen(fd, 64) < 0) {
        close(fd);
        return s;
    }
    s->fd = fd;
    s->listening = 1;
    return s;
}

static inline code_bool Amalgame_Net_Http_H2Server_IsListening(
        AmalgameH2Server* s) {
    return s && s->listening ? 1 : 0;
}

/* Accept the next connection and wrap it in an H2Conn. Returns NULL
 * on accept failure. */
static inline AmalgameH2Conn* Amalgame_Net_Http_H2Server_Accept(
        AmalgameH2Server* s) {
    if (!s || !s->listening || s->fd < 0) return NULL;
    struct sockaddr_in addr; socklen_t alen = sizeof(addr);
    int cfd = accept(s->fd, (struct sockaddr*)&addr, &alen);
    if (cfd < 0) return NULL;
    return Amalgame_Net_Http_H2Conn_NewFromFd((i64)cfd);
}

static inline void Amalgame_Net_Http_H2Server_Close(AmalgameH2Server* s) {
    if (!s) return;
    if (s->fd >= 0) close(s->fd);
    s->fd = -1; s->listening = 0;
}

/* ── High-level entry point: Http2.Serve(port, handler) ──────────
 * Listens on `port`, accepts connections, drives the H2 protocol,
 * and invokes `handler(conn)` once per request. The handler is
 * expected to call H2Conn.Respond() before returning. Returns:
 *   0  on clean shutdown (currently unreachable — runs forever)
 *  -1  invalid handler
 *  -2  listen() failed (port already in use, EACCES, …)
 */
static inline i64 Amalgame_Net_Http_Http2_Serve(i64 port,
                                                 AmalgameClosure* handler) {
    if (!handler) {
        fprintf(stderr, "Http2.Serve: handler is NULL\n");
        return -1;
    }
    AmalgameH2Server* srv = Amalgame_Net_Http_H2Server_Listen(port);
    if (!srv || !srv->listening) {
        fprintf(stderr, "Http2.Serve: failed to listen on :%lld (%s)\n",
                (long long)port, strerror(errno));
        return -2;
    }
    fprintf(stdout, "Http2.Serve: listening on :%lld (h2c)\n", (long long)port);
    fflush(stdout);
    while (srv->listening) {
        AmalgameH2Conn* conn = Amalgame_Net_Http_H2Server_Accept(srv);
        if (!conn) continue;
        for (;;) {
            i64 sid = Amalgame_Net_Http_H2Conn_NextRequest(conn);
            if (sid <= 0) break;
            AmalgameClosure_call1(handler, (void*)conn);
        }
        Amalgame_Net_Http_H2Conn_Close(conn);
    }
    Amalgame_Net_Http_H2Server_Close(srv);
    return 0;
}

#else  /* !AMALGAME_HAS_NGHTTP2 — stub fallback */

static inline AmalgameH2Conn* Amalgame_Net_Http_H2Conn_NewFromFd(i64 fd) {
    (void)fd; return NULL;
}
static inline i64 Amalgame_Net_Http_H2Conn_NextRequest(AmalgameH2Conn* c) {
    (void)c; return -1;
}
static inline code_string Amalgame_Net_Http_H2Conn_Method(AmalgameH2Conn* c) {
    (void)c; return "";
}
static inline code_string Amalgame_Net_Http_H2Conn_Path(AmalgameH2Conn* c) {
    (void)c; return "";
}
static inline code_string Amalgame_Net_Http_H2Conn_Authority(AmalgameH2Conn* c) {
    (void)c; return "";
}
static inline code_string Amalgame_Net_Http_H2Conn_Header(AmalgameH2Conn* c,
                                                           code_string n) {
    (void)c; (void)n; return "";
}
static inline code_string Amalgame_Net_Http_H2Conn_Body(AmalgameH2Conn* c) {
    (void)c; return "";
}
static inline i64 Amalgame_Net_Http_H2Conn_BodyLen(AmalgameH2Conn* c) {
    (void)c; return 0;
}
static inline void Amalgame_Net_Http_H2Conn_Respond(AmalgameH2Conn* c,
                                                     i64 s, code_string ct,
                                                     code_string b) {
    (void)c; (void)s; (void)ct; (void)b;
}
static inline void Amalgame_Net_Http_H2Conn_Close(AmalgameH2Conn* c) {
    (void)c;
}
static inline AmalgameH2Server* Amalgame_Net_Http_H2Server_Listen(i64 p) {
    (void)p; return NULL;
}
static inline code_bool Amalgame_Net_Http_H2Server_IsListening(
        AmalgameH2Server* s) { (void)s; return 0; }
static inline AmalgameH2Conn* Amalgame_Net_Http_H2Server_Accept(
        AmalgameH2Server* s) { (void)s; return NULL; }
static inline void Amalgame_Net_Http_H2Server_Close(AmalgameH2Server* s) {
    (void)s;
}
static inline i64 Amalgame_Net_Http_Http2_Serve(i64 port,
                                                 AmalgameClosure* handler) {
    (void)port; (void)handler; return -1;
}

#endif /* AMALGAME_HAS_NGHTTP2 */

static inline i64 Amalgame_Net_Http_H2_Available(void) {
#ifdef AMALGAME_HAS_NGHTTP2
    return 1;
#else
    return 0;
#endif
}

/* ────────────────────────────────────────────────────────────────
 * HTTP/1.1 server (v0.2.1+) — browser-friendly counterpart to the
 * h2c server above. Same handler closure shape:
 *
 *     Http1.Serve(port, conn => {
 *         let path   = H1Conn.Path(conn)
 *         let method = H1Conn.Method(conn)
 *         H1Conn.Respond(conn, 200, "text/plain", "hi")
 *         return 0
 *     })
 *
 * Scope of v0.2.1:
 *   - One request per connection (no keep-alive; Connection: close).
 *   - Up to AMALGAME_H1_MAX_HEADERS headers per request.
 *   - Header lookup is case-insensitive (stored lowercased).
 *   - Body buffer capped at AMALGAME_H1_MAX_BODY bytes.
 *   - No multipart / chunked encoding parsing (read whole body
 *     into RAM by Content-Length).
 *
 * Designed for the Mosaic demo and small services. For heavy
 * throughput, sit it behind nginx / caddy.
 * ──────────────────────────────────────────────────────────────── */

#define AMALGAME_H1_MAX_HEADERS 64
#define AMALGAME_H1_RECV_BUF    65536
#define AMALGAME_H1_MAX_BODY    (8 * 1024 * 1024)

typedef struct AmalgameH1Header {
    char* name;   /* lowercased for case-insensitive lookup */
    char* value;
} AmalgameH1Header;

typedef struct AmalgameH1Conn {
    int       fd;
    char*     method;        /* "GET" / "POST" / ... */
    char*     path;          /* "/users/42" (query stripped) */
    char*     raw_target;    /* "/users/42?x=1" (with query) */
    char*     version;       /* "HTTP/1.1" */
    char*     body;
    int32_t   body_len;
    AmalgameH1Header headers[AMALGAME_H1_MAX_HEADERS];
    int32_t   header_count;
    int32_t   response_sent;
} AmalgameH1Conn;

typedef struct AmalgameH1Server {
    int       fd;
    int32_t   listening;
    i64       port;
} AmalgameH1Server;

/* ── parse one HTTP/1.1 request off the wire ─────────────────────
 * Returns 1 on success, 0 on clean peer close, -1 on parse error.
 * Caller owns the conn struct; we fill in method/path/headers/body. */
static int amalgame_h1_parse_request(AmalgameH1Conn* c) {
    char* buf = (char*)GC_MALLOC_ATOMIC(AMALGAME_H1_RECV_BUF + 1);
    int total = 0;
    char* eoh = NULL;
    while (total < AMALGAME_H1_RECV_BUF) {
        ssize_t n = recv(c->fd, buf + total, AMALGAME_H1_RECV_BUF - total, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) {
            if (total == 0) return 0;
            return -1;  /* connection closed mid-request */
        }
        total += (int)n;
        buf[total] = 0;
        eoh = strstr(buf, "\r\n\r\n");
        if (eoh) break;
    }
    if (!eoh) return -1;          /* request line + headers > 64 KB */
    int headers_len = (int)(eoh - buf);

    /* ── Request line: METHOD SP TARGET SP HTTP/1.1 CRLF ──────── */
    char* sp1 = (char*)memchr(buf, ' ', headers_len);
    if (!sp1) return -1;
    char* sp2 = (char*)memchr(sp1 + 1, ' ', headers_len - (int)(sp1 - buf) - 1);
    if (!sp2) return -1;
    char* eol = strstr(sp2 + 1, "\r\n");
    if (!eol || eol > eoh) return -1;

    int meth_len = (int)(sp1 - buf);
    int targ_len = (int)(sp2 - sp1 - 1);
    int vers_len = (int)(eol - sp2 - 1);

    c->method = (char*)GC_MALLOC_ATOMIC(meth_len + 1);
    memcpy(c->method, buf, meth_len);
    c->method[meth_len] = 0;

    c->raw_target = (char*)GC_MALLOC_ATOMIC(targ_len + 1);
    memcpy(c->raw_target, sp1 + 1, targ_len);
    c->raw_target[targ_len] = 0;

    char* q = strchr(c->raw_target, '?');
    if (q) {
        int path_len = (int)(q - c->raw_target);
        c->path = (char*)GC_MALLOC_ATOMIC(path_len + 1);
        memcpy(c->path, c->raw_target, path_len);
        c->path[path_len] = 0;
    } else {
        c->path = c->raw_target;
    }

    c->version = (char*)GC_MALLOC_ATOMIC(vers_len + 1);
    memcpy(c->version, sp2 + 1, vers_len);
    c->version[vers_len] = 0;

    /* ── Headers ───────────────────────────────────────────────── */
    c->header_count = 0;
    char* line = eol + 2;
    while (line < eoh && c->header_count < AMALGAME_H1_MAX_HEADERS) {
        char* eol2 = strstr(line, "\r\n");
        if (!eol2 || eol2 > eoh) break;
        char* colon = (char*)memchr(line, ':', eol2 - line);
        if (colon) {
            int name_len = (int)(colon - line);
            const char* vp = colon + 1;
            while (vp < eol2 && (*vp == ' ' || *vp == '\t')) vp++;
            int val_len = (int)(eol2 - vp);

            char* name = (char*)GC_MALLOC_ATOMIC(name_len + 1);
            for (int i = 0; i < name_len; i++) {
                char ch = line[i];
                if (ch >= 'A' && ch <= 'Z') ch += 32;
                name[i] = ch;
            }
            name[name_len] = 0;
            char* val = (char*)GC_MALLOC_ATOMIC(val_len + 1);
            if (val_len > 0) memcpy(val, vp, val_len);
            val[val_len] = 0;

            c->headers[c->header_count].name  = name;
            c->headers[c->header_count].value = val;
            c->header_count++;
        }
        line = eol2 + 2;
    }

    /* ── Body — only if Content-Length present ─────────────────── */
    int content_length = 0;
    for (int i = 0; i < c->header_count; i++) {
        if (strcmp(c->headers[i].name, "content-length") == 0) {
            content_length = atoi(c->headers[i].value);
            break;
        }
    }
    if (content_length > AMALGAME_H1_MAX_BODY) return -1;

    if (content_length > 0) {
        c->body = (char*)GC_MALLOC_ATOMIC(content_length + 1);
        int body_in_buf = total - (headers_len + 4);
        if (body_in_buf > 0) {
            int copy = body_in_buf > content_length ? content_length : body_in_buf;
            memcpy(c->body, eoh + 4, copy);
            c->body_len = copy;
        }
        while (c->body_len < content_length) {
            ssize_t n = recv(c->fd, c->body + c->body_len,
                             content_length - c->body_len, 0);
            if (n <= 0) {
                if (n < 0 && errno == EINTR) continue;
                return -1;
            }
            c->body_len += (int32_t)n;
        }
        c->body[c->body_len] = 0;
    } else {
        c->body = "";
        c->body_len = 0;
    }
    return 1;
}

/* ── H1Server — TCP listener ─────────────────────────────────────*/

static inline AmalgameH1Server* Amalgame_Net_Http_H1Server_Listen(i64 port) {
    AmalgameH1Server* s =
        (AmalgameH1Server*)GC_MALLOC(sizeof(AmalgameH1Server));
    s->fd = -1; s->listening = 0; s->port = port;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return s;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)port);
    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0 ||
        listen(fd, 64) < 0) {
        close(fd);
        return s;
    }
    s->fd = fd;
    s->listening = 1;
    return s;
}

static inline code_bool Amalgame_Net_Http_H1Server_IsListening(
        AmalgameH1Server* s) {
    return s && s->listening ? 1 : 0;
}

static inline AmalgameH1Conn* Amalgame_Net_Http_H1Server_Accept(
        AmalgameH1Server* s) {
    if (!s || !s->listening || s->fd < 0) return NULL;
    struct sockaddr_in addr; socklen_t alen = sizeof(addr);
    int cfd = accept(s->fd, (struct sockaddr*)&addr, &alen);
    if (cfd < 0) return NULL;
    AmalgameH1Conn* c =
        (AmalgameH1Conn*)GC_MALLOC(sizeof(AmalgameH1Conn));
    memset(c, 0, sizeof(*c));
    c->fd = cfd;
    return c;
}

static inline void Amalgame_Net_Http_H1Server_Close(AmalgameH1Server* s) {
    if (!s) return;
    if (s->fd >= 0) close(s->fd);
    s->fd = -1; s->listening = 0;
}

/* ── H1Conn — request accessors + response writer ────────────────*/

static inline code_string Amalgame_Net_Http_H1Conn_Method(AmalgameH1Conn* c) {
    return (c && c->method) ? c->method : "";
}
static inline code_string Amalgame_Net_Http_H1Conn_Path(AmalgameH1Conn* c) {
    return (c && c->path) ? c->path : "";
}
static inline code_string Amalgame_Net_Http_H1Conn_RawTarget(AmalgameH1Conn* c) {
    return (c && c->raw_target) ? c->raw_target : "";
}
static inline code_string Amalgame_Net_Http_H1Conn_Header(AmalgameH1Conn* c,
                                                          code_string name) {
    if (!c || !name) return "";
    /* Compare case-insensitively (stored lowercased). */
    size_t nlen = strlen(name);
    char* needle = (char*)GC_MALLOC_ATOMIC(nlen + 1);
    for (size_t i = 0; i < nlen; i++) {
        char ch = name[i];
        if (ch >= 'A' && ch <= 'Z') ch += 32;
        needle[i] = ch;
    }
    needle[nlen] = 0;
    for (int i = 0; i < c->header_count; i++) {
        if (strcmp(c->headers[i].name, needle) == 0) {
            return c->headers[i].value;
        }
    }
    return "";
}
static inline code_string Amalgame_Net_Http_H1Conn_Body(AmalgameH1Conn* c) {
    return (c && c->body) ? c->body : "";
}
static inline i64 Amalgame_Net_Http_H1Conn_BodyLen(AmalgameH1Conn* c) {
    return (c && c->body) ? (i64)c->body_len : 0;
}

static inline void Amalgame_Net_Http_H1Conn_Respond(AmalgameH1Conn* c,
                                                     i64 status,
                                                     code_string ct,
                                                     code_string body) {
    if (!c || c->fd < 0 || c->response_sent) return;

    /* Minimal reason-phrase table — RFC 7231 + a few common
     * extensions. Anything not listed gets "OK" as a safe default. */
    const char* reason = "OK";
    switch ((int)status) {
        case 100: reason = "Continue"; break;
        case 200: reason = "OK"; break;
        case 201: reason = "Created"; break;
        case 202: reason = "Accepted"; break;
        case 204: reason = "No Content"; break;
        case 301: reason = "Moved Permanently"; break;
        case 302: reason = "Found"; break;
        case 303: reason = "See Other"; break;
        case 304: reason = "Not Modified"; break;
        case 307: reason = "Temporary Redirect"; break;
        case 308: reason = "Permanent Redirect"; break;
        case 400: reason = "Bad Request"; break;
        case 401: reason = "Unauthorized"; break;
        case 403: reason = "Forbidden"; break;
        case 404: reason = "Not Found"; break;
        case 405: reason = "Method Not Allowed"; break;
        case 409: reason = "Conflict"; break;
        case 410: reason = "Gone"; break;
        case 413: reason = "Payload Too Large"; break;
        case 415: reason = "Unsupported Media Type"; break;
        case 422: reason = "Unprocessable Content"; break;
        case 429: reason = "Too Many Requests"; break;
        case 500: reason = "Internal Server Error"; break;
        case 501: reason = "Not Implemented"; break;
        case 502: reason = "Bad Gateway"; break;
        case 503: reason = "Service Unavailable"; break;
        case 504: reason = "Gateway Timeout"; break;
    }

    size_t blen = body ? strlen(body) : 0;
    const char* ctype = (ct && ct[0]) ? ct : "text/plain; charset=utf-8";

    char header[1024];
    int header_len = snprintf(header, sizeof(header),
        "HTTP/1.1 %lld %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n",
        (long long)status, reason, ctype, blen);

    if (header_len > 0) {
        ssize_t w = send(c->fd, header, (size_t)header_len, 0);
        (void)w;
        if (blen > 0) {
            w = send(c->fd, body, blen, 0);
            (void)w;
        }
    }
    c->response_sent = 1;
}

static inline void Amalgame_Net_Http_H1Conn_Close(AmalgameH1Conn* c) {
    if (!c) return;
    if (c->fd >= 0) {
        close(c->fd);
        c->fd = -1;
    }
}

/* ── Http1.Serve(port, handler) — high-level entry point ─────────
 * Same shape as Http2.Serve: one handler closure called once per
 * request with the H1Conn pointer. Returns:
 *    0  clean shutdown (unreachable currently — loops forever)
 *   -1  handler is NULL
 *   -2  listen() failed (port in use, EACCES, …)
 */
static inline i64 Amalgame_Net_Http_Http1_Serve(i64 port,
                                                AmalgameClosure* handler) {
    if (!handler) {
        fprintf(stderr, "Http1.Serve: handler is NULL\n");
        return -1;
    }
    AmalgameH1Server* srv = Amalgame_Net_Http_H1Server_Listen(port);
    if (!srv || !srv->listening) {
        fprintf(stderr, "Http1.Serve: failed to listen on :%lld (%s)\n",
                (long long)port, strerror(errno));
        return -2;
    }
    fprintf(stdout, "Http1.Serve: listening on :%lld (HTTP/1.1)\n",
            (long long)port);
    fflush(stdout);

    while (srv->listening) {
        AmalgameH1Conn* conn = Amalgame_Net_Http_H1Server_Accept(srv);
        if (!conn) continue;
        if (amalgame_h1_parse_request(conn) > 0) {
            AmalgameClosure_call1(handler, (void*)conn);
        }
        Amalgame_Net_Http_H1Conn_Close(conn);
    }
    Amalgame_Net_Http_H1Server_Close(srv);
    return 0;
}

#endif /* AMALGAME_NET_HTTP_H */
