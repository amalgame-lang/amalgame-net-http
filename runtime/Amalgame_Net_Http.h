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
    if (!handler) return -1;
    AmalgameH2Server* srv = Amalgame_Net_Http_H2Server_Listen(port);
    if (!srv || !srv->listening) return -2;
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

#endif /* AMALGAME_NET_HTTP_H */
