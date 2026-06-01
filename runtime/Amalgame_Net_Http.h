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
#include <signal.h>     /* v0.8.0: graceful SIGTERM/SIGINT shutdown */
#include <fcntl.h>
/* v0.9.1: Http1.ServeAsync uses amalgame-async for I/O parking.
 * Declared as a [dependencies] entry in amalgame.toml so users
 * of net-http v0.9.1+ automatically pick up async v0.2.0+. */
#include "Amalgame_Async.h"
/* v0.6.0: pthread for Http1.ServeMt — one worker thread per accepted
 * connection. GC_pthread_create wraps pthread_create with the bdwgc
 * thread-registration dance so locals on the worker stack stay
 * scannable; without it, GC can free live objects mid-request.
 *
 * The bdwgc threading helpers are only declared in <gc.h> when
 * GC_THREADS is defined BEFORE the first include. _runtime.h pulls
 * gc.h in transparently without that define, which locks the
 * prototypes out via the header guard. Forward-declare what we
 * need so the wrapper compiles cleanly regardless of include
 * order — same pattern as amalgame-threading. Symbols come from
 * the system libgc.so at link time. */
#include <pthread.h>
extern int GC_pthread_create(pthread_t* new_thread,
                              const pthread_attr_t* attr,
                              void* (*start_routine)(void*),
                              void* arg);

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

/* OpenSSL probe (v0.3+) — needed for the HTTPS server path. If
 * present, `Https.Serve` is enabled. If absent, the HTTPS entry
 * point returns -3 and stderr explains how to install OpenSSL
 * devel. mirrors amalgame-tls's pattern. */
#if defined(__has_include)
#  if __has_include(<openssl/ssl.h>)
#    define AMALGAME_HAS_OPENSSL 1
#    include <openssl/ssl.h>
#    include <openssl/err.h>
#  elif defined(__APPLE__) && __has_include("/opt/homebrew/opt/openssl@3/include/openssl/ssl.h")
#    define AMALGAME_HAS_OPENSSL 1
#    include "/opt/homebrew/opt/openssl@3/include/openssl/ssl.h"
#    include "/opt/homebrew/opt/openssl@3/include/openssl/err.h"
#  endif
#endif

/* ────────────────────────────────────────────────────────────────
 * Graceful shutdown (v0.8.0).
 *
 * Pre-v0.8.0 every Serve* path looped on accept() forever — the
 * only way out was SIGKILL, which dropped in-flight HTTP requests
 * and (worse) every connected WebSocket.  The Mosaic v0.5+ worker
 * supervisor needs SIGTERM to mean "stop accepting new conns but
 * keep serving the in-flight ones until they close or a grace
 * timeout fires", so the supervisor can fade an old worker out
 * after spawning a fresh one.
 *
 * Mechanism:
 *   - A global `volatile sig_atomic_t` flag flipped by the SIGTERM /
 *     SIGINT signal handler.
 *   - A small static registry (`amalgame_listen_fds`) of every
 *     listening fd currently held by Serve*.  The signal handler
 *     shutdown(2)'s each one — accept() then returns -1 with
 *     EINVAL and the loop bails out.
 *   - Each Serve* checks the flag before each iteration so a
 *     SIGTERM arriving between accept()s exits the loop without
 *     waiting for one more connection.
 *
 * The handler stays installed for the lifetime of the process —
 * idempotent install (`InstallShutdownSignals`) lets multiple
 * Serve* calls share the same flag without re-installing.
 *
 * SO_REUSEPORT (linked feature): every listener now sets
 * SO_REUSEPORT alongside SO_REUSEADDR so the supervisor can
 * spawn a fresh worker on the same port BEFORE the old one
 * stops accepting.  Both workers' listeners are valid for an
 * overlap window; the kernel load-balances incoming SYNs across
 * them.  On platforms without SO_REUSEPORT (rare these days —
 * Linux ≥ 3.9, all BSDs, macOS 10.7+) the setsockopt is a
 * silent no-op via the #ifdef.
 * ──────────────────────────────────────────────────────────────── */

static volatile sig_atomic_t amalgame_net_http_stopping = 0;

#define AMALGAME_NH_MAX_LISTEN_FDS 8
static int amalgame_net_http_listen_fds[AMALGAME_NH_MAX_LISTEN_FDS];
static int amalgame_net_http_listen_fd_count = 0;

static void amalgame_net_http_sig_handler(int sig) {
    (void) sig;
    amalgame_net_http_stopping = 1;
    /* Unblock every blocking accept() by shutting down the listen
     * sockets.  shutdown(SHUT_RD) is the canonical way — close()
     * inside a signal handler is technically allowed but races with
     * the accept loop's bookkeeping.  shutdown is signal-safe and
     * causes accept() to return -1 with EINVAL or EBADF. */
    for (int i = 0; i < amalgame_net_http_listen_fd_count; i++) {
        int fd = amalgame_net_http_listen_fds[i];
        if (fd >= 0) {
            shutdown(fd, SHUT_RDWR);
        }
    }
}

static void amalgame_net_http_register_listen_fd(int fd) {
    if (fd < 0) return;
    if (amalgame_net_http_listen_fd_count >= AMALGAME_NH_MAX_LISTEN_FDS) {
        /* Quietly drop excess registrations — eight concurrent
         * listeners is more than any realistic app needs. */
        return;
    }
    amalgame_net_http_listen_fds[amalgame_net_http_listen_fd_count++] = fd;
}

static void amalgame_net_http_unregister_listen_fd(int fd) {
    if (fd < 0) return;
    for (int i = 0; i < amalgame_net_http_listen_fd_count; i++) {
        if (amalgame_net_http_listen_fds[i] == fd) {
            amalgame_net_http_listen_fds[i] =
                amalgame_net_http_listen_fds[--amalgame_net_http_listen_fd_count];
            return;
        }
    }
}

/* Install the SIGTERM + SIGINT handler.  Idempotent — calling
 * this from every Serve* entry point is cheap and means the
 * application doesn't have to remember to opt in. */
static inline void Amalgame_Net_Http_InstallShutdownSignals(void) {
    static int installed = 0;
    if (installed) return;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = amalgame_net_http_sig_handler;
    sa.sa_flags   = SA_RESTART;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);
    /* SIGPIPE: writes to a half-closed socket would otherwise kill
     * the worker mid-handler.  We want EPIPE from write() instead. */
    signal(SIGPIPE, SIG_IGN);
    installed = 1;
}

/* Returns true (1) once a SIGTERM/SIGINT has been observed.  Serve*
 * loops poll this before each accept() iteration. */
static inline code_bool Amalgame_Net_Http_IsStopping(void) {
    return amalgame_net_http_stopping ? 1 : 0;
}

/* Programmatic shutdown — flips the same flag as the signal
 * handler.  Useful for tests + apps that drive their own lifecycle. */
static inline void Amalgame_Net_Http_RequestShutdown(void) {
    amalgame_net_http_sig_handler(0);
}

/* AM-facing aliases under Http1.{InstallShutdownSignals, IsStopping,
 * RequestShutdown}.  All Serve* paths share the same signal handler +
 * stopping flag, so the choice of Http1 as the namespace is arbitrary
 * — it's just the most idiomatic place for `mosaic dev`-style apps. */
static inline void Amalgame_Net_Http_Http1_InstallShutdownSignals(void) {
    Amalgame_Net_Http_InstallShutdownSignals();
}
static inline code_bool Amalgame_Net_Http_Http1_IsStopping(void) {
    return Amalgame_Net_Http_IsStopping();
}
static inline void Amalgame_Net_Http_Http1_RequestShutdown(void) {
    Amalgame_Net_Http_RequestShutdown();
}

/* SO_REUSEPORT helper — silent no-op on platforms that don't
 * have it (which is essentially nothing built in the last
 * decade).  Called next to every SO_REUSEADDR. */
static inline void amalgame_net_http_set_reuseport(int fd) {
#ifdef SO_REUSEPORT
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
#else
    (void) fd;
#endif
}

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
#ifdef AMALGAME_HAS_OPENSSL
    SSL*      ssl;            /* HTTPS path: non-NULL → use TLS I/O */
#else
    void*     ssl;
#endif
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
    if (!c) return NGHTTP2_ERR_CALLBACK_FAILURE;
#ifdef AMALGAME_HAS_OPENSSL
    /* HTTPS path: TLS-wrapped — write via SSL. SSL_write either
     * succeeds with N > 0 bytes (≤ len, partial allowed) or fails
     * (negative). Loop until len bytes are written or fatal error. */
    if (c->ssl) {
        ssize_t total = 0;
        while ((size_t)total < len) {
            int n = SSL_write(c->ssl, data + total, (int)(len - total));
            if (n > 0) { total += n; continue; }
            int err = SSL_get_error(c->ssl, n);
            if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
                return total > 0 ? total : NGHTTP2_ERR_WOULDBLOCK;
            }
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        return total;
    }
#endif
    /* h2c path: raw TCP fd. */
    if (c->fd < 0) return NGHTTP2_ERR_CALLBACK_FAILURE;
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

        ssize_t n;
#ifdef AMALGAME_HAS_OPENSSL
        if (c->ssl) {
            int r = SSL_read(c->ssl, recv_buf, sizeof(recv_buf));
            if (r > 0) {
                n = r;
            } else {
                int err = SSL_get_error(c->ssl, r);
                if (err == SSL_ERROR_ZERO_RETURN) return 0;
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) continue;
                return -1;
            }
        } else
#endif
        {
            n = recv(c->fd, recv_buf, sizeof(recv_buf), 0);
            if (n == 0) return 0;          /* peer closed cleanly */
            if (n < 0) {
                if (errno == EINTR) continue;
                return -1;
            }
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
#ifdef AMALGAME_HAS_OPENSSL
    if (c->ssl) {
        SSL_shutdown(c->ssl);
        SSL_free(c->ssl);
        c->ssl = NULL;
    }
#endif
    if (c->fd >= 0) {
        close(c->fd);
        c->fd = -1;
    }
    c->want_close = 1;
}

/* ── H2Server — minimal TCP listener for h2c ───────────── */

static inline AmalgameH2Server* Amalgame_Net_Http_H2Server_Listen(i64 port, i64 backlog) {
    AmalgameH2Server* s =
        (AmalgameH2Server*)GC_MALLOC(sizeof(AmalgameH2Server));
    s->fd = -1; s->listening = 0; s->port = port;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return s;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    amalgame_net_http_set_reuseport(fd);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)port);
    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0 ||
        listen(fd, (backlog > 0 ? (int)backlog : 64)) < 0) {
        close(fd);
        return s;
    }
    s->fd = fd;
    s->listening = 1;
    Amalgame_Net_Http_InstallShutdownSignals();
    amalgame_net_http_register_listen_fd(s->fd);
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
    amalgame_net_http_unregister_listen_fd(s->fd);
    if (s->fd >= 0) close(s->fd);
    s->fd = -1; s->listening = 0;
}

/* ── HttpServerConfig — server-side tunables (v0.4.3+) ────────────
 * Snapshot of the per-server config, applied at accept time.
 *
 * Wired today:
 *   header_timeout_sec, body_timeout_sec — SO_RCVTIMEO / SO_SNDTIMEO
 *     on every accepted fd. Slowloris guard. v0.4.3 wired Http1; v0.4.4
 *     extends to Http2 / Https / Ws / Wss via the *.ServeWith variants.
 *
 * Field present, pending v0.4.5 wiring:
 *   max_body_bytes, max_header_bytes, max_url_bytes — currently the
 *     parser uses compile-time constants (AMALGAME_H1_MAX_BODY etc.).
 *     The struct fields are accepted so the [limits] TOML schema is
 *     stable; switching the parser to read these is a follow-up patch.
 *   idle_timeout_sec — needs HTTP keep-alive support (today we
 *     close after one request).
 *   listen_backlog — needs to be threaded through *Server_Listen
 *     (today hardcoded 64). Trivial follow-up.
 *
 * Zero on any field = "library default" (current hardcoded value).
 * The struct is opaque to callers; use the New + With* helpers.
 *
 * Declared early in the file so every Serve variant can reference
 * it (the actual parser-side wiring still lives in the H1 block
 * below).
 */
typedef struct AmalgameNetHttpServerConfig {
    int listen_backlog;
    int header_timeout_sec;
    int body_timeout_sec;
    int idle_timeout_sec;
    i64 max_body_bytes;
    i64 max_header_bytes;
    i64 max_url_bytes;
    /* v0.7.1 — TLS knobs honored by Https.*, Wss.*, Http2.Serve (HTTPS path).
     * Zero/empty = library default (TLS 1.2+, ALPN "h2"). */
    int tls_min_version;   /* 12 = TLS 1.2 (default), 13 = TLS 1.3 */
    code_string tls_alpn;  /* comma-separated, e.g. "h2,http/1.1". NULL = "h2" only. */
} AmalgameNetHttpServerConfig;

/* Allocate a zeroed config (so every field defaults to "library
 * default" via 0). Caller fills in non-zero values via the With*
 * helpers. */
static inline AmalgameNetHttpServerConfig* Amalgame_Net_Http_HttpServerConfig_Default(void) {
    AmalgameNetHttpServerConfig* c =
        (AmalgameNetHttpServerConfig*)GC_MALLOC(sizeof(*c));
    memset(c, 0, sizeof(*c));
    return c;
}

static inline AmalgameNetHttpServerConfig* Amalgame_Net_Http_HttpServerConfig_WithHeaderTimeoutSec(
        AmalgameNetHttpServerConfig* c, i64 s) {
    if (c) c->header_timeout_sec = (int)s;
    return c;
}
static inline AmalgameNetHttpServerConfig* Amalgame_Net_Http_HttpServerConfig_WithBodyTimeoutSec(
        AmalgameNetHttpServerConfig* c, i64 s) {
    if (c) c->body_timeout_sec = (int)s;
    return c;
}
static inline AmalgameNetHttpServerConfig* Amalgame_Net_Http_HttpServerConfig_WithIdleTimeoutSec(
        AmalgameNetHttpServerConfig* c, i64 s) {
    if (c) c->idle_timeout_sec = (int)s;
    return c;
}
static inline AmalgameNetHttpServerConfig* Amalgame_Net_Http_HttpServerConfig_WithMaxBodyBytes(
        AmalgameNetHttpServerConfig* c, i64 b) {
    if (c) c->max_body_bytes = b;
    return c;
}
static inline AmalgameNetHttpServerConfig* Amalgame_Net_Http_HttpServerConfig_WithMaxHeaderBytes(
        AmalgameNetHttpServerConfig* c, i64 b) {
    if (c) c->max_header_bytes = b;
    return c;
}
static inline AmalgameNetHttpServerConfig* Amalgame_Net_Http_HttpServerConfig_WithMaxUrlBytes(
        AmalgameNetHttpServerConfig* c, i64 b) {
    if (c) c->max_url_bytes = b;
    return c;
}
static inline AmalgameNetHttpServerConfig* Amalgame_Net_Http_HttpServerConfig_WithListenBacklog(
        AmalgameNetHttpServerConfig* c, i64 b) {
    if (c) c->listen_backlog = (int)b;
    return c;
}
/* v0.7.1 — TLS knobs. Honored by HttpsServer_Listen (Https.Serve*,
 * Wss.Serve*, Http2.Serve when HTTPS-mode).
 * min_version: 12 = TLS 1.2 (default), 13 = TLS 1.3. Any other value
 * resets to the library default.
 * alpn: comma-separated wire-format string ("h2,http/1.1"). NULL/""
 * reverts to "h2" only (legacy default). */
static inline AmalgameNetHttpServerConfig* Amalgame_Net_Http_HttpServerConfig_WithTlsMinVersion(
        AmalgameNetHttpServerConfig* c, i64 v) {
    if (c) c->tls_min_version = (int)v;
    return c;
}
static inline AmalgameNetHttpServerConfig* Amalgame_Net_Http_HttpServerConfig_WithTlsAlpn(
        AmalgameNetHttpServerConfig* c, code_string a) {
    if (c) c->tls_alpn = a;
    return c;
}

/* Per-field getters — needed so AM-side FromMap can compose a config
 * by chained With* calls returning the (single) shared instance.
 * Reading non-zero fields lets callers introspect before they call
 * ServeWith. */
static inline i64 Amalgame_Net_Http_HttpServerConfig_HeaderTimeoutSec(AmalgameNetHttpServerConfig* c) { return c ? c->header_timeout_sec : 0; }
static inline i64 Amalgame_Net_Http_HttpServerConfig_BodyTimeoutSec(AmalgameNetHttpServerConfig* c)   { return c ? c->body_timeout_sec   : 0; }
static inline i64 Amalgame_Net_Http_HttpServerConfig_IdleTimeoutSec(AmalgameNetHttpServerConfig* c)   { return c ? c->idle_timeout_sec   : 0; }
static inline i64 Amalgame_Net_Http_HttpServerConfig_MaxBodyBytes(AmalgameNetHttpServerConfig* c)     { return c ? c->max_body_bytes     : 0; }
static inline i64 Amalgame_Net_Http_HttpServerConfig_MaxHeaderBytes(AmalgameNetHttpServerConfig* c)   { return c ? c->max_header_bytes   : 0; }
static inline i64 Amalgame_Net_Http_HttpServerConfig_MaxUrlBytes(AmalgameNetHttpServerConfig* c)      { return c ? c->max_url_bytes      : 0; }
static inline i64 Amalgame_Net_Http_HttpServerConfig_ListenBacklog(AmalgameNetHttpServerConfig* c)    { return c ? c->listen_backlog     : 0; }
static inline i64 Amalgame_Net_Http_HttpServerConfig_TlsMinVersion(AmalgameNetHttpServerConfig* c)    { return c ? c->tls_min_version    : 0; }
static inline code_string Amalgame_Net_Http_HttpServerConfig_TlsAlpn(AmalgameNetHttpServerConfig* c)  { return (c && c->tls_alpn) ? c->tls_alpn : ""; }

/* Apply the wired-today knobs (SO_RCVTIMEO / SO_SNDTIMEO) to a
 * connected fd. Quiet no-op when `config` is NULL or both timeout
 * fields are 0 (= no timeout, current default behavior). Uses the
 * larger of header/body timeouts as a single deadline — v0.5.x will
 * switch to a poll-based loop with phase-specific deadlines. */
static inline void Amalgame_Net_Http_HttpServerConfig_ApplyToFd(
        int fd, AmalgameNetHttpServerConfig* config) {
    if (!config || fd < 0) return;
    int t = config->body_timeout_sec;
    if (config->header_timeout_sec > t) t = config->header_timeout_sec;
    if (t > 0) {
        struct timeval tv;
        tv.tv_sec  = t;
        tv.tv_usec = 0;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    }
}

/* Reset SO_RCVTIMEO / SO_SNDTIMEO to 0 (= no timeout). Used by
 * Ws.ServeWith / Wss.ServeWith after the upgrade handshake completes,
 * so the long-lived frame loop doesn't inherit the handshake-phase
 * deadline. Safe to call on any fd; no-op on fd < 0. */
static inline void Amalgame_Net_Http_HttpServerConfig_ClearTimeoutsOnFd(int fd) {
    if (fd < 0) return;
    struct timeval tv;
    tv.tv_sec  = 0;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
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
    AmalgameH2Server* srv = Amalgame_Net_Http_H2Server_Listen(port, 0);
    if (!srv || !srv->listening) {
        fprintf(stderr, "Http2.Serve: failed to listen on :%lld (%s)\n",
                (long long)port, strerror(errno));
        return -2;
    }
    fprintf(stdout, "Http2.Serve: listening on :%lld (h2c)\n", (long long)port);
    fflush(stdout);
    while (srv->listening && !amalgame_net_http_stopping) {
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

/* ── Http2.ServeMt(port, handler) — multi-thread h2c (v0.7.0) ──
 * Same pattern as Http1.ServeMt: thread-per-connection,
 * GC_pthread_create, detached, run the per-conn request loop
 * (h2 multiplexes streams over one conn, so one thread drives
 * one nghttp2 session). */
typedef struct {
    AmalgameH2Conn*  conn;
    AmalgameClosure* handler;
} amalgame_h2_mt_arg;

static void* amalgame_h2_mt_worker(void* p) {
    amalgame_h2_mt_arg* a = (amalgame_h2_mt_arg*) p;
    for (;;) {
        i64 sid = Amalgame_Net_Http_H2Conn_NextRequest(a->conn);
        if (sid <= 0) break;
        AmalgameClosure_call1(a->handler, (void*) a->conn);
    }
    Amalgame_Net_Http_H2Conn_Close(a->conn);
    return NULL;
}

static inline i64 Amalgame_Net_Http_Http2_ServeMt(i64 port,
                                                   AmalgameClosure* handler) {
    if (!handler) {
        fprintf(stderr, "Http2.ServeMt: handler is NULL\n");
        return -1;
    }
    AmalgameH2Server* srv = Amalgame_Net_Http_H2Server_Listen(port, 0);
    if (!srv || !srv->listening) {
        fprintf(stderr, "Http2.ServeMt: failed to listen on :%lld (%s)\n",
                (long long)port, strerror(errno));
        return -2;
    }
    fprintf(stdout, "Http2.ServeMt: listening on :%lld (h2c, multi-thread)\n",
            (long long)port);
    fflush(stdout);
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    while (srv->listening && !amalgame_net_http_stopping) {
        AmalgameH2Conn* conn = Amalgame_Net_Http_H2Server_Accept(srv);
        if (!conn) continue;
        amalgame_h2_mt_arg* a = (amalgame_h2_mt_arg*) GC_MALLOC(sizeof(*a));
        a->conn = conn; a->handler = handler;
        pthread_t t;
        int rc = GC_pthread_create(&t, &attr, amalgame_h2_mt_worker, a);
        if (rc != 0) {
            fprintf(stderr, "Http2.ServeMt: thread create failed (%s), inline\n",
                    strerror(rc));
            amalgame_h2_mt_worker(a);
        }
    }
    pthread_attr_destroy(&attr);
    Amalgame_Net_Http_H2Server_Close(srv);
    return 0;
}

/* ── Http2.ServeWith(port, config, handler) — Http2.Serve + config ─
 * Same as Http2.Serve plus HttpServerConfig applied to every
 * accepted connection (SO_RCVTIMEO / SO_SNDTIMEO from
 * header_timeout_sec / body_timeout_sec). H2 multiplexes many
 * streams over one connection, so a single deadline applies to
 * the whole conn — for finer control wait for v0.4.5's per-frame
 * deadlines. */
static inline i64 Amalgame_Net_Http_Http2_ServeWith(
        i64 port,
        AmalgameNetHttpServerConfig* config,
        AmalgameClosure* handler) {
    if (!handler) {
        fprintf(stderr, "Http2.ServeWith: handler is NULL\n");
        return -1;
    }
    AmalgameH2Server* srv = Amalgame_Net_Http_H2Server_Listen(port, config ? config->listen_backlog : 0);
    if (!srv || !srv->listening) {
        fprintf(stderr, "Http2.ServeWith: failed to listen on :%lld (%s)\n",
                (long long)port, strerror(errno));
        return -2;
    }
    fprintf(stdout, "Http2.ServeWith: listening on :%lld (h2c, config-aware)\n",
            (long long)port);
    fflush(stdout);
    while (srv->listening && !amalgame_net_http_stopping) {
        AmalgameH2Conn* conn = Amalgame_Net_Http_H2Server_Accept(srv);
        if (!conn) continue;
        Amalgame_Net_Http_HttpServerConfig_ApplyToFd(conn->fd, config);
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

/* ────────────────────────────────────────────────────────────────
 * HTTPS server with ALPN h2 (v0.3+)
 *
 * Opens a TCP listener, then for each accepted connection:
 *   1. Wraps it in a TLS session (OpenSSL SSL_new + SSL_accept)
 *   2. Negotiates ALPN — advertise only "h2" so browsers that
 *      offer both end up on H2; clients that can't speak h2 are
 *      rejected during handshake (refused TLS_ALPN_NEGOTIATION)
 *   3. Drives the H2 protocol over the TLS stream (the existing
 *      H2Conn code, with the ssl field set so send/recv route
 *      through SSL_write / SSL_read instead of raw TCP)
 *
 * Cert + key are loaded from PEM files at listen time. For dev,
 * a self-signed cert is plenty (browser shows a warning the first
 * time, then remembers). For prod, pair with amalgame-tls v0.2's
 * planned ACME client to provision real certs automatically.
 *
 * Scope of v0.3:
 *   - TLS 1.2+ via SSL_CTX_set_min_proto_version
 *   - ALPN h2 ONLY (no http/1.1 fallback yet — v0.3.x)
 *   - One concurrent connection at a time (no threading)
 *   - SNI not enforced (single cert per listener)
 *   - libnghttp2 + libssl + libcrypto at link time
 *
 * Public API:
 *   Https.Serve(port, certFile, keyFile, handler)
 *     returns 0 / -1 / -2 / -3 (see Http2.Serve for codes)
 *     returns -3 when OpenSSL not compiled in
 *     returns -4 on TLS setup failure (bad cert/key file, etc.)
 * ──────────────────────────────────────────────────────────────── */

#ifdef AMALGAME_HAS_OPENSSL

typedef struct AmalgameHttpsServer {
    int       fd;
    int32_t   listening;
    i64       port;
    SSL_CTX*  ssl_ctx;
} AmalgameHttpsServer;

/* ALPN selection callback — server side. nghttp2 ships a helper
 * (nghttp2_select_next_protocol) that handles the wire format
 * (length-prefixed names), but reimplementing the trivial "h2 in,
 * h2 out" case keeps us decoupled from nghttp2 ALPN helpers. */
static int amalgame_https_alpn_select_cb(SSL* ssl,
        const unsigned char** out, unsigned char* outlen,
        const unsigned char* in, unsigned int inlen, void* arg) {
    (void)ssl; (void)arg;
    /* Walk the wire-format ALPN list: 1-byte length + name, repeated. */
    for (unsigned int i = 0; i < inlen; ) {
        unsigned int plen = in[i];
        if (i + 1 + plen > inlen) break;
        if (plen == 2 && in[i+1] == 'h' && in[i+2] == '2') {
            *out    = &in[i+1];
            *outlen = 2;
            return SSL_TLSEXT_ERR_OK;
        }
        i += 1 + plen;
    }
    /* No "h2" in client's offer → reject (TLS handshake fails). */
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

/* v0.7.1 — variant that honors HttpServerConfig.tls_min_version
 * (and accepts tls_alpn but stores-only — http/1.1 fallback is a
 * v0.7.2+ change). The legacy 4-arg signature delegates here with
 * cfg=NULL. */
static inline AmalgameHttpsServer* Amalgame_Net_Http_HttpsServer_ListenEx(
        i64 port, code_string cert_file, code_string key_file, i64 backlog,
        AmalgameNetHttpServerConfig* cfg) {
    AmalgameHttpsServer* s =
        (AmalgameHttpsServer*)GC_MALLOC(sizeof(AmalgameHttpsServer));
    memset(s, 0, sizeof(*s));
    s->port = port; s->fd = -1;

    /* TCP listener (same as H2Server_Listen). */
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return s;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    amalgame_net_http_set_reuseport(fd);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)port);
    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0 ||
        listen(fd, (backlog > 0 ? (int)backlog : 64)) < 0) {
        close(fd); return s;
    }
    s->fd = fd;

    /* SSL_CTX with cert + key. */
    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) { close(fd); s->fd = -1; return s; }
    /* TLS min version. cfg = NULL or tls_min_version not in {12,13}
     * → keep the v0.7.0 default (TLS 1.2+). 12 = TLS 1.2, 13 = TLS 1.3. */
    int min_ver = TLS1_2_VERSION;
    if (cfg) {
        if (cfg->tls_min_version == 13) min_ver = TLS1_3_VERSION;
        else if (cfg->tls_min_version == 12) min_ver = TLS1_2_VERSION;
    }
    SSL_CTX_set_min_proto_version(ctx, min_ver);
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file (ctx, key_file,  SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        close(fd); s->fd = -1;
        return s;
    }
    if (SSL_CTX_check_private_key(ctx) != 1) {
        fprintf(stderr, "Https.Serve: cert/key mismatch\n");
        SSL_CTX_free(ctx);
        close(fd); s->fd = -1;
        return s;
    }
    /* ALPN: today h2 only is implemented end-to-end. The cfg->tls_alpn
     * field is honored at the parse level (stored in the config and
     * passed through) but the select callback hardcodes h2 — when
     * cfg->tls_alpn says something else, log a one-line warning so
     * users notice the config knob isn't fully wired yet. Removing
     * the warning is the deliverable for v0.7.2's http/1.1 fallback. */
    if (cfg && cfg->tls_alpn && cfg->tls_alpn[0]
        && strcmp(cfg->tls_alpn, "h2") != 0) {
        fprintf(stderr,
            "Https.Listen: tls_alpn = %s requested, but only \"h2\" is "
            "wired end-to-end in v0.7.x; using h2.\n", cfg->tls_alpn);
    }
    SSL_CTX_set_alpn_select_cb(ctx, amalgame_https_alpn_select_cb, NULL);

    s->ssl_ctx = ctx;
    s->listening = 1;
    Amalgame_Net_Http_InstallShutdownSignals();
    amalgame_net_http_register_listen_fd(s->fd);
    return s;
}

/* Legacy 4-arg signature — kept for v0.7.0 callers. Delegates to
 * the Ex variant with cfg = NULL, so TLS 1.2+ / "h2" defaults stand. */
static inline AmalgameHttpsServer* Amalgame_Net_Http_HttpsServer_Listen(
        i64 port, code_string cert_file, code_string key_file, i64 backlog) {
    return Amalgame_Net_Http_HttpsServer_ListenEx(
        port, cert_file, key_file, backlog, NULL);
}

static inline AmalgameH2Conn* Amalgame_Net_Http_HttpsServer_Accept(
        AmalgameHttpsServer* s) {
    if (!s || !s->listening || s->fd < 0) return NULL;
    struct sockaddr_in addr; socklen_t alen = sizeof(addr);
    int cfd = accept(s->fd, (struct sockaddr*)&addr, &alen);
    if (cfd < 0) return NULL;

    SSL* ssl = SSL_new(s->ssl_ctx);
    if (!ssl) { close(cfd); return NULL; }
    SSL_set_fd(ssl, cfd);
    int rv = SSL_accept(ssl);
    if (rv != 1) {
        int err = SSL_get_error(ssl, rv);
        fprintf(stderr, "Https.Serve: TLS handshake failed (SSL err %d)\n", err);
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(cfd);
        return NULL;
    }

    /* Verify ALPN negotiated h2 — if not, our select_cb rejected,
     * we shouldn't be here, but belt-and-braces. */
    const unsigned char* alpn = NULL; unsigned int alen2 = 0;
    SSL_get0_alpn_selected(ssl, &alpn, &alen2);
    if (alen2 != 2 || alpn[0] != 'h' || alpn[1] != '2') {
        fprintf(stderr, "Https.Serve: client didn't negotiate h2\n");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(cfd);
        return NULL;
    }

    /* Wrap in an H2Conn with the ssl field set — send/recv now
     * dispatch through SSL_write / SSL_read automatically. */
    AmalgameH2Conn* c = Amalgame_Net_Http_H2Conn_NewFromFd((i64)cfd);
    if (!c) {
        SSL_shutdown(ssl); SSL_free(ssl); close(cfd);
        return NULL;
    }
    c->ssl = ssl;
    return c;
}

static inline void Amalgame_Net_Http_HttpsServer_Close(AmalgameHttpsServer* s) {
    if (!s) return;
    amalgame_net_http_unregister_listen_fd(s->fd);
    if (s->fd >= 0) close(s->fd);
    if (s->ssl_ctx) SSL_CTX_free(s->ssl_ctx);
    s->fd = -1; s->ssl_ctx = NULL; s->listening = 0;
}

static inline code_bool Amalgame_Net_Http_HttpsServer_IsListening(
        AmalgameHttpsServer* s) {
    return s && s->listening ? 1 : 0;
}

/* High-level entry point. Same closure shape as Http2.Serve —
 * handler is called once per request with an H2Conn pointer. */
static inline i64 Amalgame_Net_Http_Https_Serve(i64 port,
                                                 code_string cert_file,
                                                 code_string key_file,
                                                 AmalgameClosure* handler) {
    if (!handler) {
        fprintf(stderr, "Https.Serve: handler is NULL\n");
        return -1;
    }
    if (!cert_file || !cert_file[0] || !key_file || !key_file[0]) {
        fprintf(stderr, "Https.Serve: certFile and keyFile required\n");
        return -4;
    }
    /* OpenSSL global init — idempotent. */
    static int ssl_initialised = 0;
    if (!ssl_initialised) {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
        ssl_initialised = 1;
    }

    AmalgameHttpsServer* srv = Amalgame_Net_Http_HttpsServer_Listen(
        port, cert_file, key_file, 0);
    if (!srv || !srv->listening) {
        fprintf(stderr, "Https.Serve: failed to listen on :%lld (%s)\n",
                (long long)port, strerror(errno));
        return -2;
    }
    fprintf(stdout, "Https.Serve: listening on :%lld (HTTPS, ALPN h2)\n",
            (long long)port);
    fflush(stdout);

    while (srv->listening && !amalgame_net_http_stopping) {
        AmalgameH2Conn* conn = Amalgame_Net_Http_HttpsServer_Accept(srv);
        if (!conn) continue;
        for (;;) {
            i64 sid = Amalgame_Net_Http_H2Conn_NextRequest(conn);
            if (sid <= 0) break;
            AmalgameClosure_call1(handler, (void*)conn);
        }
        Amalgame_Net_Http_H2Conn_Close(conn);
    }
    Amalgame_Net_Http_HttpsServer_Close(srv);
    return 0;
}

/* ── Https.ServeMt(port, cert, key, handler) — multi-thread (v0.7.0) ─
 * Same pattern as Http2.ServeMt: thread per accepted TLS conn,
 * drives the h2 stream loop inside the worker. The TLS handshake
 * happens in HttpsServer_Accept, so each worker enters with an
 * upgraded H2Conn ready to serve streams. */
static inline i64 Amalgame_Net_Http_Https_ServeMt(i64 port,
        code_string cert_file, code_string key_file,
        AmalgameClosure* handler) {
    if (!handler) {
        fprintf(stderr, "Https.ServeMt: handler is NULL\n");
        return -1;
    }
    if (!cert_file || !cert_file[0] || !key_file || !key_file[0]) {
        fprintf(stderr, "Https.ServeMt: certFile and keyFile required\n");
        return -4;
    }
    static int ssl_initialised = 0;
    if (!ssl_initialised) {
        SSL_library_init(); SSL_load_error_strings(); OpenSSL_add_all_algorithms();
        ssl_initialised = 1;
    }
    AmalgameHttpsServer* srv = Amalgame_Net_Http_HttpsServer_Listen(
        port, cert_file, key_file, 0);
    if (!srv || !srv->listening) {
        fprintf(stderr, "Https.ServeMt: failed to listen on :%lld (%s)\n",
                (long long)port, strerror(errno));
        return -2;
    }
    fprintf(stdout, "Https.ServeMt: listening on :%lld (HTTPS h2, multi-thread)\n",
            (long long)port);
    fflush(stdout);
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    while (srv->listening && !amalgame_net_http_stopping) {
        AmalgameH2Conn* conn = Amalgame_Net_Http_HttpsServer_Accept(srv);
        if (!conn) continue;
        amalgame_h2_mt_arg* a = (amalgame_h2_mt_arg*) GC_MALLOC(sizeof(*a));
        a->conn = conn; a->handler = handler;
        pthread_t t;
        int rc = GC_pthread_create(&t, &attr, amalgame_h2_mt_worker, a);
        if (rc != 0) {
            fprintf(stderr, "Https.ServeMt: thread create failed (%s), inline\n",
                    strerror(rc));
            amalgame_h2_mt_worker(a);
        }
    }
    pthread_attr_destroy(&attr);
    Amalgame_Net_Http_HttpsServer_Close(srv);
    return 0;
}

/* ── Https.ServeWith(port, cert, key, config, handler) ─────────────
 * Https.Serve + HttpServerConfig applied post-accept. Same single-
 * deadline-per-conn caveat as Http2.ServeWith (H2 stream multiplexing).
 */
static inline i64 Amalgame_Net_Http_Https_ServeWith(
        i64 port,
        code_string cert_file,
        code_string key_file,
        AmalgameNetHttpServerConfig* config,
        AmalgameClosure* handler) {
    if (!handler) {
        fprintf(stderr, "Https.ServeWith: handler is NULL\n");
        return -1;
    }
    if (!cert_file || !cert_file[0] || !key_file || !key_file[0]) {
        fprintf(stderr, "Https.ServeWith: certFile and keyFile required\n");
        return -4;
    }
    static int ssl_initialised = 0;
    if (!ssl_initialised) {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
        ssl_initialised = 1;
    }
    AmalgameHttpsServer* srv = Amalgame_Net_Http_HttpsServer_ListenEx(
        port, cert_file, key_file,
        config ? config->listen_backlog : 0, config);
    if (!srv || !srv->listening) {
        fprintf(stderr, "Https.ServeWith: failed to listen on :%lld (%s)\n",
                (long long)port, strerror(errno));
        return -2;
    }
    fprintf(stdout, "Https.ServeWith: listening on :%lld (HTTPS+ALPN, config-aware)\n",
            (long long)port);
    fflush(stdout);
    while (srv->listening && !amalgame_net_http_stopping) {
        AmalgameH2Conn* conn = Amalgame_Net_Http_HttpsServer_Accept(srv);
        if (!conn) continue;
        Amalgame_Net_Http_HttpServerConfig_ApplyToFd(conn->fd, config);
        for (;;) {
            i64 sid = Amalgame_Net_Http_H2Conn_NextRequest(conn);
            if (sid <= 0) break;
            AmalgameClosure_call1(handler, (void*)conn);
        }
        Amalgame_Net_Http_H2Conn_Close(conn);
    }
    Amalgame_Net_Http_HttpsServer_Close(srv);
    return 0;
}

#else  /* !AMALGAME_HAS_OPENSSL — HTTPS stubs */

typedef struct AmalgameHttpsServer AmalgameHttpsServer;

static inline AmalgameHttpsServer* Amalgame_Net_Http_HttpsServer_Listen(
        i64 p, code_string c, code_string k, i64 b) {
    (void)p;(void)c;(void)k;(void)b; return NULL; }
static inline AmalgameH2Conn* Amalgame_Net_Http_HttpsServer_Accept(
        AmalgameHttpsServer* s) { (void)s; return NULL; }
static inline void Amalgame_Net_Http_HttpsServer_Close(AmalgameHttpsServer* s) {
    (void)s;
}
static inline code_bool Amalgame_Net_Http_HttpsServer_IsListening(
        AmalgameHttpsServer* s) { (void)s; return 0; }
static inline i64 Amalgame_Net_Http_Https_Serve(i64 port,
        code_string cert, code_string key, AmalgameClosure* h) {
    (void)port; (void)cert; (void)key; (void)h;
    fprintf(stderr,
        "Https.Serve: built without OpenSSL — install libssl-dev "
        "and rebuild this package (rm -rf the cache for net-http "
        "before re-running mosaic build).\n");
    return -3;
}
static inline i64 Amalgame_Net_Http_Https_ServeWith(i64 port,
        code_string cert, code_string key,
        AmalgameNetHttpServerConfig* cfg, AmalgameClosure* h) {
    (void)port; (void)cert; (void)key; (void)cfg; (void)h;
    fprintf(stderr, "Https.ServeWith: built without OpenSSL.\n");
    return -3;
}

/* v0.10.0 HttpsH1Server stubs live with the active definitions
 * later in the file (paired with #if AMALGAME_HAS_OPENSSL after
 * the AmalgameH1Conn struct), so nothing to declare here. */

#endif /* AMALGAME_HAS_OPENSSL */

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
static inline AmalgameH2Server* Amalgame_Net_Http_H2Server_Listen(i64 p, i64 b) {
    (void)b;
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
static inline i64 Amalgame_Net_Http_Http2_ServeWith(i64 port,
        AmalgameNetHttpServerConfig* cfg, AmalgameClosure* h) {
    (void)port; (void)cfg; (void)h; return -1;
}
static inline i64 Amalgame_Net_Http_Http2_ServeMt(i64 port,
        AmalgameClosure* h) {
    (void)port; (void)h; return -1;
}
typedef struct AmalgameHttpsServer AmalgameHttpsServer;
static inline AmalgameHttpsServer* Amalgame_Net_Http_HttpsServer_Listen(
        i64 p, code_string c, code_string k, i64 b) {
    (void)p;(void)c;(void)k;(void)b; return NULL; }
static inline AmalgameH2Conn* Amalgame_Net_Http_HttpsServer_Accept(
        AmalgameHttpsServer* s) { (void)s; return NULL; }
static inline void Amalgame_Net_Http_HttpsServer_Close(AmalgameHttpsServer* s) {
    (void)s;
}
static inline code_bool Amalgame_Net_Http_HttpsServer_IsListening(
        AmalgameHttpsServer* s) { (void)s; return 0; }
static inline i64 Amalgame_Net_Http_Https_Serve(i64 port,
        code_string cert, code_string key, AmalgameClosure* h) {
    (void)port; (void)cert; (void)key; (void)h;
    return -1;
}
static inline i64 Amalgame_Net_Http_Https_ServeWith(i64 port,
        code_string cert, code_string key,
        AmalgameNetHttpServerConfig* cfg, AmalgameClosure* h) {
    (void)port; (void)cert; (void)key; (void)cfg; (void)h;
    return -1;
}
static inline i64 Amalgame_Net_Http_Https_ServeMt(i64 port,
        code_string cert, code_string key, AmalgameClosure* h) {
    (void)port; (void)cert; (void)key; (void)h; return -1;
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
    /* v0.4.5: per-conn config snapshot. NULL = library defaults
     * (current AMALGAME_H1_MAX_* constants). Set by Http1.ServeWith
     * after accept; the parser then honors non-zero size-limit
     * fields. The struct itself is forward-declared near the top
     * of the file (it precedes the H2 / Https / Ws / Wss Serve
     * variants that also consume it). */
    AmalgameNetHttpServerConfig* config;
    /* v0.5.0: keep-alive flag, set by the dispatch loop based on
     * the request's `Connection` header + the protocol version.
     * When non-zero, Respond omits the hardcoded `Connection: close`
     * header so the client keeps the TCP connection open for the
     * next request. */
    int32_t   keep_alive;
    /* v0.7.0: client peer address captured at accept time, formatted
     * "ip:port" (e.g. "192.0.2.1:54321") for IPv4. Empty string when
     * the accept call failed to capture it. Read by middlewares that
     * key off the client IP — primarily RateLimit "ip" strategy. */
    char      remote_addr[64];
    /* v0.9.1: when set, recv/send loops MSG_DONTWAIT and park the
     * fiber via Amalgame_Async_WaitFd* on EAGAIN. Set by
     * Http1.ServeAsync after accept; zero in every other code path
     * so the synchronous Serve/ServeWith/ServeMt variants stay
     * blocking exactly like before. */
    int32_t   async_io;
    /* v0.9.5: live-fiber tracking for graceful shutdown. The accept
     * loop owns a doubly-linked list of in-flight conns; on SIGTERM
     * it walks the list and FiberCancel's each fiber so parked
     * handlers wake promptly instead of blocking on their configured
     * read/idle timeouts. NULL outside the async path. */
    AmalgameFiber*           async_fiber;
    struct AmalgameH1Conn*   async_next;
    struct AmalgameH1Conn*   async_prev;
    /* v0.10.0: TLS termination. When non-NULL, recv/send dispatch
     * through SSL_read / SSL_write instead of the bare fd. Set by
     * HttpsH1Server_Accept after a successful SSL handshake; NULL
     * for plain Http1.Serve/ServeMt/ServeAsync conns. */
    SSL*                     ssl;
} AmalgameH1Conn;

typedef struct AmalgameH1Server {
    int       fd;
    int32_t   listening;
    i64       port;
} AmalgameH1Server;

/* ── async-aware recv / send helpers (v0.9.1) ───────────────────
 * Branch on c->async_io: synchronous path uses blocking recv/send
 * exactly like before; async path uses MSG_DONTWAIT and parks the
 * fiber via Amalgame_Async_WaitFd* on EAGAIN. EINTR is retried
 * silently in both modes. Default timeouts mirror typical
 * reverse-proxy values (30 s read, 10 s write). v0.9.4 lets the
 * caller override the per-phase read timeout via
 * `amalgame_h1_recv_into(..., timeout_ms)`; the parser uses
 * config->header_timeout_sec for the header loop and
 * config->body_timeout_sec for the body loop (both in seconds,
 * 0 = library default). */
#define AMALGAME_H1_ASYNC_READ_TIMEOUT_MS  30000
#define AMALGAME_H1_ASYNC_WRITE_TIMEOUT_MS 10000

/* Pick the per-phase WaitFd timeout. Returns ms. Config in seconds;
 * 0 = use the library default. */
static inline i64 amalgame_h1_async_header_timeout_ms(AmalgameH1Conn* c) {
    if (c->config && c->config->header_timeout_sec > 0)
        return (i64) c->config->header_timeout_sec * 1000;
    return AMALGAME_H1_ASYNC_READ_TIMEOUT_MS;
}
static inline i64 amalgame_h1_async_body_timeout_ms(AmalgameH1Conn* c) {
    if (c->config && c->config->body_timeout_sec > 0)
        return (i64) c->config->body_timeout_sec * 1000;
    return AMALGAME_H1_ASYNC_READ_TIMEOUT_MS;
}

static ssize_t amalgame_h1_recv_into(AmalgameH1Conn* c, void* buf, size_t n,
                                     i64 timeout_ms) {
    /* v0.10.0: TLS branch. SSL_read fully drains its own internal
     * record buffer before pulling from the socket, so the EAGAIN
     * loop is at the SSL layer (WANT_READ/WANT_WRITE) rather than
     * recv(). Map both to the standard async-park / blocking-retry
     * pattern. The plain-text path below stays bit-identical to
     * v0.9.x. */
    if (c->ssl) {
        while (1) {
            int r = SSL_read(c->ssl, buf, (int) n);
            if (r > 0) return (ssize_t) r;
            int err = SSL_get_error(c->ssl, r);
            if (err == SSL_ERROR_ZERO_RETURN) return 0;  /* clean close */
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                if (c->async_io) {
                    code_bool ok = (err == SSL_ERROR_WANT_WRITE)
                        ? Amalgame_Async_WaitFdWritable((i64) c->fd, timeout_ms)
                        : Amalgame_Async_WaitFdReadable((i64) c->fd, timeout_ms);
                    if (!ok) { errno = ETIMEDOUT; return -1; }
                    continue;
                }
                /* Blocking SSL — OpenSSL handles waits internally;
                 * a WANT_* from a blocking BIO is unusual. Retry. */
                continue;
            }
            if (err == SSL_ERROR_SYSCALL && errno == EINTR) continue;
            return -1;
        }
    }
    int flags = c->async_io ? MSG_DONTWAIT : 0;
    while (1) {
        ssize_t r = recv(c->fd, buf, n, flags);
        if (r >= 0) return r;
        if (errno == EINTR) continue;
        if (c->async_io && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            code_bool ok = Amalgame_Async_WaitFdReadable(
                (i64) c->fd, timeout_ms);
            if (!ok) { errno = ETIMEDOUT; return -1; }
            continue;
        }
        return -1;
    }
}

static int amalgame_h1_send_all(AmalgameH1Conn* c, const void* buf, size_t n) {
    const char* p = (const char*) buf;
    size_t left = n;
    /* v0.10.0: TLS branch — mirror of the recv path. SSL_write drains
     * into the SSL record buffer; partial writes manifest as WANT_*
     * rather than short returns, so the loop pattern is the same. */
    if (c->ssl) {
        while (left > 0) {
            int w = SSL_write(c->ssl, p, (int) left);
            if (w > 0) {
                p    += w;
                left -= (size_t) w;
                continue;
            }
            int err = SSL_get_error(c->ssl, w);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                if (c->async_io) {
                    code_bool ok = (err == SSL_ERROR_WANT_READ)
                        ? Amalgame_Async_WaitFdReadable((i64) c->fd, AMALGAME_H1_ASYNC_WRITE_TIMEOUT_MS)
                        : Amalgame_Async_WaitFdWritable((i64) c->fd, AMALGAME_H1_ASYNC_WRITE_TIMEOUT_MS);
                    if (!ok) { errno = ETIMEDOUT; return -1; }
                    continue;
                }
                continue;
            }
            if (err == SSL_ERROR_SYSCALL && errno == EINTR) continue;
            return -1;
        }
        return 0;
    }
    int flags = c->async_io ? MSG_DONTWAIT : 0;
    while (left > 0) {
        ssize_t w = send(c->fd, p, left, flags);
        if (w > 0) {
            p += w;
            left -= (size_t) w;
            continue;
        }
        if (w < 0 && errno == EINTR) continue;
        if (c->async_io && w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            code_bool ok = Amalgame_Async_WaitFdWritable(
                (i64) c->fd, AMALGAME_H1_ASYNC_WRITE_TIMEOUT_MS);
            if (!ok) { errno = ETIMEDOUT; return -1; }
            continue;
        }
        return -1;
    }
    return 0;
}

/* ── parse one HTTP/1.1 request off the wire ─────────────────────
 * Returns 1 on success, 0 on clean peer close, -1 on parse error.
 * Caller owns the conn struct; we fill in method/path/headers/body. */
static int amalgame_h1_parse_request(AmalgameH1Conn* c) {
    char* buf = (char*)GC_MALLOC_ATOMIC(AMALGAME_H1_RECV_BUF + 1);
    int total = 0;
    char* eoh = NULL;
    i64 hdr_to_ms = amalgame_h1_async_header_timeout_ms(c);
    while (total < AMALGAME_H1_RECV_BUF) {
        ssize_t n = amalgame_h1_recv_into(c, buf + total,
                                          AMALGAME_H1_RECV_BUF - total,
                                          hdr_to_ms);
        if (n < 0) return -1;
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

    /* Per-conn header-block cap. Zero in config = use the library
     * default (currently bounded only by AMALGAME_H1_RECV_BUF). */
    if (c->config && c->config->max_header_bytes > 0
        && headers_len > c->config->max_header_bytes) {
        return -1;
    }

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

    /* Per-conn URL cap. Same fallback rule. */
    if (c->config && c->config->max_url_bytes > 0
        && targ_len > c->config->max_url_bytes) {
        return -1;
    }

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
    /* Body-size cap. Per-conn config (set by Http1.ServeWith)
     * overrides the compile-time constant. Zero in config = use
     * the library default (current behavior). */
    int max_body = AMALGAME_H1_MAX_BODY;
    if (c->config && c->config->max_body_bytes > 0) {
        max_body = (int)c->config->max_body_bytes;
    }
    if (content_length > max_body) return -1;

    if (content_length > 0) {
        c->body = (char*)GC_MALLOC_ATOMIC(content_length + 1);
        int body_in_buf = total - (headers_len + 4);
        if (body_in_buf > 0) {
            int copy = body_in_buf > content_length ? content_length : body_in_buf;
            memcpy(c->body, eoh + 4, copy);
            c->body_len = copy;
        }
        i64 body_to_ms = amalgame_h1_async_body_timeout_ms(c);
        while (c->body_len < content_length) {
            ssize_t n = amalgame_h1_recv_into(c, c->body + c->body_len,
                                              content_length - c->body_len,
                                              body_to_ms);
            if (n <= 0) return -1;
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

static inline AmalgameH1Server* Amalgame_Net_Http_H1Server_Listen(i64 port, i64 backlog) {
    AmalgameH1Server* s =
        (AmalgameH1Server*)GC_MALLOC(sizeof(AmalgameH1Server));
    s->fd = -1; s->listening = 0; s->port = port;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return s;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    amalgame_net_http_set_reuseport(fd);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)port);
    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0 ||
        listen(fd, (backlog > 0 ? (int)backlog : 64)) < 0) {
        close(fd);
        return s;
    }
    s->fd = fd;
    s->listening = 1;
    Amalgame_Net_Http_InstallShutdownSignals();
    amalgame_net_http_register_listen_fd(s->fd);
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
    /* v0.7.0: capture peer "ip:port" into a stack-NUL-terminated
     * buffer. inet_ntoa is fine for IPv4 (sockaddr_in); a v0.8.x
     * extension can switch to inet_ntop for IPv6 once sockaddr_in6
     * is plumbed through the rest of the server stack. */
    snprintf(c->remote_addr, sizeof(c->remote_addr),
             "%s:%u", inet_ntoa(addr.sin_addr),
             (unsigned) ntohs(addr.sin_port));
    return c;
}

static inline void Amalgame_Net_Http_H1Server_Close(AmalgameH1Server* s) {
    if (!s) return;
    amalgame_net_http_unregister_listen_fd(s->fd);
    if (s->fd >= 0) close(s->fd);
    s->fd = -1; s->listening = 0;
}

/* ── Async-friendly accessor (v0.9.0) ───────────────────────────
 * Returns the underlying listen socket fd. Lets user code drive an
 * async-aware accept loop with `Amalgame.Async.WaitFdReadable +
 * accept4(O_NONBLOCK)`. -1 when the server failed to bind. */
static inline i64 Amalgame_Net_Http_H1Server_RawFd(AmalgameH1Server* s) {
    return s ? (i64) s->fd : -1;
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

    /* Connection header: explicit "close" unless the conn is in
     * keep-alive mode (v0.5.0). The dispatch loop sets keep_alive=1
     * after parsing a request whose `Connection` header allows
     * reuse (HTTP/1.1 default = keep-alive; HTTP/1.0 default = close). */
    const char* conn_hdr = c->keep_alive ? "keep-alive" : "close";
    char header[1024];
    int header_len = snprintf(header, sizeof(header),
        "HTTP/1.1 %lld %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: %s\r\n"
        "\r\n",
        (long long)status, reason, ctype, blen, conn_hdr);

    if (header_len > 0) {
        /* v0.9.1: send_all loops on partial writes and parks the
         * fiber via WaitFdWritable on EAGAIN when c->async_io. The
         * synchronous path collapses to a plain blocking send(). */
        if (amalgame_h1_send_all(c, header, (size_t)header_len) == 0
            && blen > 0) {
            amalgame_h1_send_all(c, body, blen);
        }
    }
    c->response_sent = 1;
}

/* v0.11.1: respond with a caller-supplied header block.
 *
 * H1Conn_Respond hard-codes the header set (Content-Type / Length /
 * Connection) — fine for a 200 with text, useless for redirects
 * (Location), cookies (Set-Cookie), CSP/CORS, cache-control, …
 * Callers needing arbitrary headers (HttpResponse.Render via the
 * AM Headers map) build a `headers_block` string of the form
 *
 *   "Content-Type: text/html\r\n"
 *   "Location: https://...\r\n"
 *   "Set-Cookie: sid=abc; HttpOnly\r\n"
 *
 * — i.e. each header line terminated with CRLF, NO trailing empty
 * line. This function emits the status-line, adds Content-Length
 * and Connection (still authoritative — caller MUST NOT include
 * those in headers_block), appends the caller's block, the
 * end-of-headers blank line, and the body.
 *
 * `headers_block` may be NULL or "" — equivalent to calling
 * H1Conn_Respond with ct="text/plain; charset=utf-8".
 */
static inline void Amalgame_Net_Http_H1Conn_RespondFull(AmalgameH1Conn* c,
                                                         i64 status,
                                                         code_string headers_block,
                                                         code_string body) {
    if (!c || c->fd < 0 || c->response_sent) return;

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
    const char* conn_hdr = c->keep_alive ? "keep-alive" : "close";

    /* Status line + Content-Length + Connection (caller-managed
     * headers come after). Buffer is generous — 256 bytes covers
     * any reason phrase + framing headers. */
    char start[256];
    int start_len = snprintf(start, sizeof(start),
        "HTTP/1.1 %lld %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: %s\r\n",
        (long long)status, reason, blen, conn_hdr);
    if (start_len <= 0 || start_len >= (int)sizeof(start)) {
        c->response_sent = 1;
        return;
    }

    if (amalgame_h1_send_all(c, start, (size_t)start_len) != 0) {
        c->response_sent = 1;
        return;
    }
    if (headers_block && headers_block[0]) {
        size_t hlen = strlen(headers_block);
        if (amalgame_h1_send_all(c, headers_block, hlen) != 0) {
            c->response_sent = 1;
            return;
        }
    }
    /* End of headers */
    if (amalgame_h1_send_all(c, "\r\n", 2) != 0) {
        c->response_sent = 1;
        return;
    }
    if (blen > 0) {
        amalgame_h1_send_all(c, body, blen);
    }
    c->response_sent = 1;
}

/* v0.9.6: binary-safe response variants.
 *
 * H1Conn_Respond uses strlen(body) for Content-Length — fine for
 * text, broken for assets that contain NUL bytes (PNG, JPEG, PDF,
 * WASM, …). These two siblings carry the length explicitly:
 *
 *   H1Conn_RespondBytes — body is (ptr, len), already in memory.
 *                         Used when the AM caller has the bytes
 *                         (e.g. dynamically generated image).
 *
 *   H1Conn_RespondFile  — body is a filesystem path; we fopen("rb"),
 *                         GC_MALLOC the bytes, send with explicit
 *                         Content-Length. The static-file
 *                         middleware in amalgame-web is the prime
 *                         consumer. Returns 0 on success, -1 on
 *                         file open/read failure (so the caller
 *                         can fall back to a 500 response).
 *
 * Both share the reason-phrase table + Connection header logic
 * with H1Conn_Respond. Factored through a static helper to avoid
 * triplicating ~30 lines.
 */
static inline int amalgame_h1_send_response(AmalgameH1Conn* c,
                                             i64 status,
                                             const char* ct,
                                             const char* body,
                                             size_t blen) {
    if (!c || c->fd < 0 || c->response_sent) return -1;

    const char* reason = "OK";
    switch ((int)status) {
        case 100: reason = "Continue"; break;
        case 200: reason = "OK"; break;
        case 201: reason = "Created"; break;
        case 202: reason = "Accepted"; break;
        case 204: reason = "No Content"; break;
        case 206: reason = "Partial Content"; break;
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
        case 416: reason = "Range Not Satisfiable"; break;
        case 422: reason = "Unprocessable Content"; break;
        case 429: reason = "Too Many Requests"; break;
        case 500: reason = "Internal Server Error"; break;
        case 501: reason = "Not Implemented"; break;
        case 502: reason = "Bad Gateway"; break;
        case 503: reason = "Service Unavailable"; break;
        case 504: reason = "Gateway Timeout"; break;
    }

    const char* ctype = (ct && ct[0]) ? ct : "application/octet-stream";
    const char* conn_hdr = c->keep_alive ? "keep-alive" : "close";
    char header[1024];
    int header_len = snprintf(header, sizeof(header),
        "HTTP/1.1 %lld %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: %s\r\n"
        "\r\n",
        (long long)status, reason, ctype, blen, conn_hdr);

    int rc = -1;
    if (header_len > 0
        && amalgame_h1_send_all(c, header, (size_t)header_len) == 0) {
        if (blen > 0) {
            rc = amalgame_h1_send_all(c, body, blen);
        } else {
            rc = 0;
        }
    }
    c->response_sent = 1;
    return rc;
}

static inline void Amalgame_Net_Http_H1Conn_RespondBytes(AmalgameH1Conn* c,
                                                          i64 status,
                                                          code_string ct,
                                                          i64 body_ptr,
                                                          i64 body_len) {
    const char* body = (const char*)(uintptr_t) body_ptr;
    size_t blen = (body_len > 0) ? (size_t) body_len : 0;
    amalgame_h1_send_response(c, status, ct, body, blen);
}

static inline i64 Amalgame_Net_Http_H1Conn_RespondFile(AmalgameH1Conn* c,
                                                       i64 status,
                                                       code_string ct,
                                                       code_string path) {
    if (!c || !path) return -1;
    FILE* f = fopen(path, "rb");
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return -1; }
    rewind(f);
    char* buf = (char*) GC_MALLOC_ATOMIC((size_t) sz + 1);
    if (!buf) { fclose(f); return -1; }
    size_t got = fread(buf, 1, (size_t) sz, f);
    fclose(f);
    if (got != (size_t) sz) return -1;
    buf[got] = 0;  /* defensive — NUL after payload so a stray strlen
                    * on the buffer stops at sz, not past the heap end */
    int rc = amalgame_h1_send_response(c, status, ct, buf, (size_t) sz);
    return rc == 0 ? 0 : -1;
}

static inline void Amalgame_Net_Http_H1Conn_Close(AmalgameH1Conn* c) {
    if (!c) return;
    /* v0.10.0: TLS shutdown before the bare fd close so the peer
     * gets a clean close-notify alert. SSL_shutdown is best-effort —
     * we don't reblock waiting for the peer's response (matches the
     * existing H2/Https path). */
    if (c->ssl) {
        SSL_shutdown(c->ssl);
        SSL_free(c->ssl);
        c->ssl = NULL;
    }
    if (c->fd >= 0) {
        close(c->fd);
        c->fd = -1;
    }
}

/* ── Async-friendly accessor (v0.9.0) ───────────────────────────
 * Returns the underlying connection socket fd. Lets user code
 * park the fiber via `Amalgame.Async.WaitFdReadable(fd, ms)` /
 * `WaitFdWritable(...)` between non-blocking `recv` / `send`
 * iterations. -1 if the connection has been closed. */
static inline i64 Amalgame_Net_Http_H1Conn_RawFd(AmalgameH1Conn* c) {
    return c ? (i64) c->fd : -1;
}

/* ── Keep-alive helpers (v0.5.0) ─────────────────────────────────
 * Used by the Http1.ServeWith dispatch loop to read the next
 * request off the same TCP connection. AM-side users who write
 * their own accept loop can call these too.
 */

/* Clear per-request state on a conn so the next parse can reuse
 * the struct. Keeps fd, config and keep_alive intact. */
static inline void Amalgame_Net_Http_H1Conn_ResetForReuse(AmalgameH1Conn* c) {
    if (!c) return;
    c->method        = NULL;
    c->path          = NULL;
    c->raw_target    = NULL;
    c->version       = NULL;
    c->body          = NULL;
    c->body_len      = 0;
    c->header_count  = 0;
    c->response_sent = 0;
    /* fd / config / keep_alive are intentionally preserved. */
}

/* Tiny case-insensitive substring search — strcasestr is glibc-only
 * and we don't want to taint the whole header with _GNU_SOURCE. */
static inline int amalgame_substr_ci(const char* hay, const char* needle) {
    if (!hay || !needle || !needle[0]) return 0;
    size_t nlen = strlen(needle);
    for (const char* p = hay; *p; p++) {
        size_t i = 0;
        while (i < nlen && p[i]) {
            char a = p[i];
            char b = needle[i];
            if (a >= 'A' && a <= 'Z') a = (char)(a + 32);
            if (b >= 'A' && b <= 'Z') b = (char)(b + 32);
            if (a != b) break;
            i++;
        }
        if (i == nlen) return 1;
    }
    return 0;
}

/* Decide whether the just-parsed request asks to keep the connection
 * open. RFC 7230 defaults: HTTP/1.1 → keep-alive unless `Connection: close`
 * was sent; HTTP/1.0 → close unless `Connection: keep-alive` was sent.
 * The parser lowercases header names + values are stored verbatim. */
static inline int amalgame_h1_request_keep_alive(AmalgameH1Conn* c) {
    if (!c || !c->version) return 0;
    int is_http11 = (strcmp(c->version, "HTTP/1.1") == 0);
    int default_keep = is_http11 ? 1 : 0;
    for (int i = 0; i < c->header_count; i++) {
        if (strcmp(c->headers[i].name, "connection") == 0) {
            const char* v = c->headers[i].value ? c->headers[i].value : "";
            if (amalgame_substr_ci(v, "close")) return 0;
            if (amalgame_substr_ci(v, "keep-alive")) return 1;
            return default_keep;
        }
    }
    return default_keep;
}

/* ── Http1.Serve(port, handler) — high-level entry point ─────────
 * Same shape as Http2.Serve: one handler closure called once per
 * request with the H1Conn pointer. Returns:
 *    0  clean shutdown (unreachable currently — loops forever)
 *   -1  handler is NULL
 *   -2  listen() failed (port in use, EACCES, …)
 *
 * For tunable behavior (Slowloris timeouts, size limits) see
 * Http1.ServeWith below.
 */

#ifdef AMALGAME_HAS_OPENSSL

/* ══════════════════════════════════════════════════════════════════
 *  HTTPS-over-HTTP/1.1 (v0.10.0) — TLS-terminating H1 server
 * ══════════════════════════════════════════════════════════════════
 *
 * Sibling of Https.Serve (ALPN h2) shipped in v0.3. The v0.3
 * server terminates TLS and dispatches HTTP/2 — fine for h2
 * origins but leaves the (much larger) HTTP/1.1 routing surface
 * (amalgame-web's WebApp + Mosaic, Pollen Manager, every existing
 * handler in user code) unable to terminate TLS on its own.
 * Production deployments had to front the HTTP/1.1 server with
 * nginx or Caddy doing TLS termination.
 *
 * v0.10.0 adds a parallel TLS-terminating server that speaks
 * HTTP/1.1 directly:
 *
 *   - HttpsH1Server_Listen → AmalgameHttpsH1Server*
 *   - HttpsH1Server_Accept → AmalgameH1Conn*  (with ssl != NULL)
 *   - HttpsH1Server_Close  → void
 *   - Https.H1Serve(port, cert, key, handler)            single-thread
 *   - Https.H1ServeMt(port, cert, key, handler)          thread-per-conn
 *
 * The returned H1Conn has its `ssl` field set; the recv/send helpers
 * upstream already branch on that, so user code (HttpRequest.FromH1Conn,
 * HttpResponse.WriteToH1Conn) is bit-identical between plaintext and
 * TLS — the only difference is which Listen call you make.
 *
 * ALPN policy: advertise "http/1.1" only. Browsers happy. Pure-h2-only
 * clients (rare in 2026) get rejected at handshake. Clients that
 * don't offer ALPN at all (legacy curl --http1.1) are also accepted —
 * OpenSSL's select_cb isn't invoked when the client doesn't request
 * ALPN, and we don't insist on it. */

/* SNI: up to this many per-domain certs in addition to the default. */
#ifndef AMALGAME_HTTPS_SNI_MAX
#define AMALGAME_HTTPS_SNI_MAX 16
#endif

typedef struct AmalgameHttpsH1Server {
    int       fd;
    int32_t   listening;
    i64       port;
    SSL_CTX*  ssl_ctx;                 /* default ctx (fallback / no-SNI) */
    /* SNI table: client servername → ctx. The default ctx above is used
     * when the SNI name matches none of these (or no SNI sent). */
    int       sni_count;
    char*     sni_names[AMALGAME_HTTPS_SNI_MAX];
    SSL_CTX*  sni_ctxs[AMALGAME_HTTPS_SNI_MAX];
} AmalgameHttpsH1Server;

/* servername callback: pick the matching per-domain SSL_CTX at handshake
 * time. arg = the AmalgameHttpsH1Server*. Case-insensitive exact match;
 * falls through to the default ctx (already set on the SSL) otherwise. */
static int amalgame_https_h1_sni_cb(SSL* ssl, int* al, void* arg) {
    (void)al;
    AmalgameHttpsH1Server* s = (AmalgameHttpsH1Server*) arg;
    if (!s || s->sni_count <= 0) return SSL_TLSEXT_ERR_OK;
    const char* name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (!name) return SSL_TLSEXT_ERR_OK;
    for (int i = 0; i < s->sni_count; i++) {
        if (s->sni_names[i] && strcasecmp(s->sni_names[i], name) == 0) {
            SSL_set_SSL_CTX(ssl, s->sni_ctxs[i]);
            return SSL_TLSEXT_ERR_OK;
        }
    }
    return SSL_TLSEXT_ERR_OK;   /* unknown host → default cert */
}

/* Build a server-side SSL_CTX from a cert+key PEM pair. Returns NULL on
 * error (caller logs). Shared by the plain and SNI listen paths. */
static SSL_CTX* amalgame_https_h1_make_ctx(code_string cert_file,
                                           code_string key_file) {
    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) return NULL;
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file (ctx, key_file,  SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_check_private_key(ctx) != 1) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}

static int amalgame_https_h1_alpn_select_cb(SSL* ssl,
        const unsigned char** out, unsigned char* outlen,
        const unsigned char* in, unsigned int inlen, void* arg) {
    (void)ssl; (void)arg;
    for (unsigned int i = 0; i < inlen; ) {
        unsigned int plen = in[i];
        if (i + 1 + plen > inlen) break;
        if (plen == 8
            && in[i+1] == 'h' && in[i+2] == 't' && in[i+3] == 't'
            && in[i+4] == 'p' && in[i+5] == '/' && in[i+6] == '1'
            && in[i+7] == '.' && in[i+8] == '1') {
            *out    = &in[i+1];
            *outlen = 8;
            return SSL_TLSEXT_ERR_OK;
        }
        i += 1 + plen;
    }
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

static inline AmalgameHttpsH1Server* Amalgame_Net_Http_HttpsH1Server_Listen(
        i64 port, code_string cert_file, code_string key_file, i64 backlog) {
    AmalgameHttpsH1Server* s =
        (AmalgameHttpsH1Server*) GC_MALLOC(sizeof(AmalgameHttpsH1Server));
    memset(s, 0, sizeof(*s));
    s->port = port; s->fd = -1;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return s;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    amalgame_net_http_set_reuseport(fd);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons((uint16_t)port);
    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0 ||
        listen(fd, (backlog > 0 ? (int)backlog : 64)) < 0) {
        close(fd); return s;
    }
    s->fd = fd;

    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) { close(fd); s->fd = -1; return s; }
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file (ctx, key_file,  SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_check_private_key(ctx) != 1) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx); close(fd); s->fd = -1; return s;
    }
    SSL_CTX_set_alpn_select_cb(ctx, amalgame_https_h1_alpn_select_cb, NULL);
    /* Arm SNI on the default ctx: at handshake the callback may swap in
     * a per-domain ctx added via HttpsH1Server_AddSni. With no AddSni
     * calls (sni_count == 0) the callback is a no-op and this stays a
     * plain single-cert listener — fully backwards compatible. */
    SSL_CTX_set_tlsext_servername_callback(ctx, amalgame_https_h1_sni_cb);
    SSL_CTX_set_tlsext_servername_arg(ctx, s);
    s->ssl_ctx   = ctx;
    s->sni_count = 0;
    s->listening = 1;
    Amalgame_Net_Http_InstallShutdownSignals();
    amalgame_net_http_register_listen_fd(s->fd);
    return s;
}

/* Register an additional cert/key for a specific servername (SNI).
 * Call after HttpsH1Server_Listen, before accepting. Returns 1 on
 * success, 0 on error (bad cert/key, table full, server not listening).
 *
 * AM: public static bool HttpsH1Server_AddSni(AmalgameHttpsH1Server* s,
 *                          string name, string certFile, string keyFile)
 */
static inline code_bool Amalgame_Net_Http_HttpsH1Server_AddSni(
        AmalgameHttpsH1Server* s, code_string name,
        code_string cert_file, code_string key_file) {
    if (!s || !s->listening) return 0;
    if (s->sni_count >= AMALGAME_HTTPS_SNI_MAX) {
        fprintf(stderr, "HttpsH1Server_AddSni: SNI table full (max %d)\n",
                AMALGAME_HTTPS_SNI_MAX);
        return 0;
    }
    if (!name || !name[0] || !cert_file || !cert_file[0]
        || !key_file || !key_file[0]) return 0;
    SSL_CTX* c = amalgame_https_h1_make_ctx(cert_file, key_file);
    if (!c) {
        fprintf(stderr, "HttpsH1Server_AddSni: bad cert/key for %s\n", name);
        return 0;
    }
    SSL_CTX_set_alpn_select_cb(c, amalgame_https_h1_alpn_select_cb, NULL);
    int n = s->sni_count;
    size_t nl = strlen(name);
    s->sni_names[n] = (char*) GC_MALLOC_ATOMIC(nl + 1);
    memcpy(s->sni_names[n], name, nl + 1);
    s->sni_ctxs[n]  = c;
    s->sni_count    = n + 1;
    return 1;
}

static inline AmalgameH1Conn* Amalgame_Net_Http_HttpsH1Server_Accept(
        AmalgameHttpsH1Server* s) {
    if (!s || !s->listening || s->fd < 0) return NULL;
    struct sockaddr_in addr; socklen_t alen = sizeof(addr);
    int cfd = accept(s->fd, (struct sockaddr*)&addr, &alen);
    if (cfd < 0) return NULL;
    SSL* ssl = SSL_new(s->ssl_ctx);
    if (!ssl) { close(cfd); return NULL; }
    SSL_set_fd(ssl, cfd);
    int rv = SSL_accept(ssl);
    if (rv != 1) {
        int err = SSL_get_error(ssl, rv);
        fprintf(stderr, "Https.H1Serve: TLS handshake failed (SSL err %d)\n", err);
        ERR_print_errors_fp(stderr);
        SSL_free(ssl); close(cfd);
        return NULL;
    }
    const unsigned char* alpn = NULL; unsigned int alen2 = 0;
    SSL_get0_alpn_selected(ssl, &alpn, &alen2);
    if (alen2 != 0 && (alen2 != 8 || memcmp(alpn, "http/1.1", 8) != 0)) {
        fprintf(stderr, "Https.H1Serve: client picked non-h1 ALPN\n");
        SSL_shutdown(ssl); SSL_free(ssl); close(cfd);
        return NULL;
    }
    AmalgameH1Conn* c = (AmalgameH1Conn*) GC_MALLOC(sizeof(AmalgameH1Conn));
    memset(c, 0, sizeof(*c));
    c->fd  = cfd;
    c->ssl = ssl;
    char ipbuf[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &addr.sin_addr, ipbuf, sizeof(ipbuf))) {
        snprintf(c->remote_addr, sizeof(c->remote_addr),
                 "%s:%u", ipbuf, (unsigned) ntohs(addr.sin_port));
    }
    return c;
}

static inline void Amalgame_Net_Http_HttpsH1Server_Close(AmalgameHttpsH1Server* s) {
    if (!s) return;
    amalgame_net_http_unregister_listen_fd(s->fd);
    if (s->fd >= 0) close(s->fd);
    if (s->ssl_ctx) SSL_CTX_free(s->ssl_ctx);
    s->fd = -1; s->ssl_ctx = NULL; s->listening = 0;
}

static inline code_bool Amalgame_Net_Http_HttpsH1Server_IsListening(
        AmalgameHttpsH1Server* s) {
    return s && s->listening ? 1 : 0;
}

static inline i64 Amalgame_Net_Http_HttpsH1Server_RawFd(AmalgameHttpsH1Server* s) {
    return s ? (i64) s->fd : -1;
}

static inline i64 Amalgame_Net_Http_Https_H1Serve(i64 port,
        code_string cert_file, code_string key_file,
        AmalgameClosure* handler) {
    if (!handler) {
        fprintf(stderr, "Https.H1Serve: handler is NULL\n");
        return -1;
    }
    if (!cert_file || !cert_file[0] || !key_file || !key_file[0]) {
        fprintf(stderr, "Https.H1Serve: certFile and keyFile required\n");
        return -4;
    }
    static int ssl_initialised = 0;
    if (!ssl_initialised) {
        SSL_library_init(); SSL_load_error_strings(); OpenSSL_add_all_algorithms();
        ssl_initialised = 1;
    }
    AmalgameHttpsH1Server* srv = Amalgame_Net_Http_HttpsH1Server_Listen(
        port, cert_file, key_file, 0);
    if (!srv || !srv->listening) {
        fprintf(stderr, "Https.H1Serve: failed to listen on :%lld (%s)\n",
                (long long)port, strerror(errno));
        return -2;
    }
    fprintf(stdout, "Https.H1Serve: listening on :%lld (HTTPS, ALPN http/1.1)\n",
            (long long)port);
    fflush(stdout);
    while (srv->listening && !amalgame_net_http_stopping) {
        AmalgameH1Conn* conn = Amalgame_Net_Http_HttpsH1Server_Accept(srv);
        if (!conn) {
            if (amalgame_net_http_stopping) break;
            continue;
        }
        if (amalgame_h1_parse_request(conn) > 0) {
            AmalgameClosure_call1(handler, (void*)conn);
        }
        Amalgame_Net_Http_H1Conn_Close(conn);
    }
    Amalgame_Net_Http_HttpsH1Server_Close(srv);
    if (amalgame_net_http_stopping) {
        fprintf(stdout, "Https.H1Serve: graceful shutdown — stopped accepting\n");
        fflush(stdout);
    }
    return 0;
}

typedef struct amalgame_https_h1_mt_arg {
    AmalgameH1Conn*   conn;
    AmalgameClosure*  handler;
} amalgame_https_h1_mt_arg;

static void* amalgame_https_h1_mt_worker(void* p) {
    amalgame_https_h1_mt_arg* a = (amalgame_https_h1_mt_arg*) p;
    if (amalgame_h1_parse_request(a->conn) > 0) {
        AmalgameClosure_call1(a->handler, (void*)a->conn);
    }
    Amalgame_Net_Http_H1Conn_Close(a->conn);
    return NULL;
}

static inline i64 Amalgame_Net_Http_Https_H1ServeMt(i64 port,
        code_string cert_file, code_string key_file,
        AmalgameClosure* handler) {
    if (!handler) {
        fprintf(stderr, "Https.H1ServeMt: handler is NULL\n");
        return -1;
    }
    if (!cert_file || !cert_file[0] || !key_file || !key_file[0]) {
        fprintf(stderr, "Https.H1ServeMt: certFile and keyFile required\n");
        return -4;
    }
    static int ssl_initialised = 0;
    if (!ssl_initialised) {
        SSL_library_init(); SSL_load_error_strings(); OpenSSL_add_all_algorithms();
        ssl_initialised = 1;
    }
    AmalgameHttpsH1Server* srv = Amalgame_Net_Http_HttpsH1Server_Listen(
        port, cert_file, key_file, 0);
    if (!srv || !srv->listening) {
        fprintf(stderr, "Https.H1ServeMt: failed to listen on :%lld (%s)\n",
                (long long)port, strerror(errno));
        return -2;
    }
    fprintf(stdout, "Https.H1ServeMt: listening on :%lld (HTTPS h1, multi-thread)\n",
            (long long)port);
    fflush(stdout);
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    while (srv->listening && !amalgame_net_http_stopping) {
        AmalgameH1Conn* conn = Amalgame_Net_Http_HttpsH1Server_Accept(srv);
        if (!conn) {
            if (amalgame_net_http_stopping) break;
            continue;
        }
        amalgame_https_h1_mt_arg* a =
            (amalgame_https_h1_mt_arg*) GC_MALLOC(sizeof(*a));
        a->conn = conn; a->handler = handler;
        pthread_t t;
        int rc = GC_pthread_create(&t, &attr, amalgame_https_h1_mt_worker, a);
        if (rc != 0) {
            fprintf(stderr, "Https.H1ServeMt: thread create failed (%s), inline\n",
                    strerror(rc));
            amalgame_https_h1_mt_worker(a);
        }
    }
    pthread_attr_destroy(&attr);
    Amalgame_Net_Http_HttpsH1Server_Close(srv);
    return 0;
}

#else  /* !AMALGAME_HAS_OPENSSL — HTTPS-H1 stubs */

typedef struct AmalgameHttpsH1Server AmalgameHttpsH1Server;
static inline AmalgameHttpsH1Server* Amalgame_Net_Http_HttpsH1Server_Listen(
        i64 p, code_string c, code_string k, i64 b) {
    (void)p;(void)c;(void)k;(void)b; return NULL; }
static inline AmalgameH1Conn* Amalgame_Net_Http_HttpsH1Server_Accept(
        AmalgameHttpsH1Server* s) { (void)s; return NULL; }
static inline code_bool Amalgame_Net_Http_HttpsH1Server_AddSni(
        AmalgameHttpsH1Server* s, code_string n, code_string c, code_string k) {
    (void)s;(void)n;(void)c;(void)k; return 0; }
static inline void Amalgame_Net_Http_HttpsH1Server_Close(AmalgameHttpsH1Server* s) {
    (void)s; }
static inline code_bool Amalgame_Net_Http_HttpsH1Server_IsListening(
        AmalgameHttpsH1Server* s) { (void)s; return 0; }
static inline i64 Amalgame_Net_Http_HttpsH1Server_RawFd(AmalgameHttpsH1Server* s) {
    (void)s; return -1; }
static inline i64 Amalgame_Net_Http_Https_H1Serve(i64 port,
        code_string cert, code_string key, AmalgameClosure* h) {
    (void)port; (void)cert; (void)key; (void)h;
    fprintf(stderr,
        "Https.H1Serve: built without OpenSSL — install libssl-dev "
        "and rebuild this package.\n");
    return -3;
}
static inline i64 Amalgame_Net_Http_Https_H1ServeMt(i64 port,
        code_string cert, code_string key, AmalgameClosure* h) {
    (void)port; (void)cert; (void)key; (void)h;
    fprintf(stderr, "Https.H1ServeMt: built without OpenSSL.\n");
    return -3;
}

#endif /* AMALGAME_HAS_OPENSSL */

static inline i64 Amalgame_Net_Http_Http1_Serve(i64 port,
                                                AmalgameClosure* handler) {
    if (!handler) {
        fprintf(stderr, "Http1.Serve: handler is NULL\n");
        return -1;
    }
    AmalgameH1Server* srv = Amalgame_Net_Http_H1Server_Listen(port, 0);
    if (!srv || !srv->listening) {
        fprintf(stderr, "Http1.Serve: failed to listen on :%lld (%s)\n",
                (long long)port, strerror(errno));
        return -2;
    }
    /* v0.8.0: H1Server_Listen already installed SIGTERM/SIGINT
     * handlers + registered srv->fd with the listen-fd registry.
     * The accept loop below polls amalgame_net_http_stopping so
     * SIGTERM unblocks accept() via shutdown(2). */
    fprintf(stdout, "Http1.Serve: listening on :%lld (HTTP/1.1)\n",
            (long long)port);
    fflush(stdout);

    while (srv->listening && !amalgame_net_http_stopping) {
        AmalgameH1Conn* conn = Amalgame_Net_Http_H1Server_Accept(srv);
        if (!conn) {
            if (amalgame_net_http_stopping) break;
            continue;
        }
        if (amalgame_h1_parse_request(conn) > 0) {
            AmalgameClosure_call1(handler, (void*)conn);
        }
        Amalgame_Net_Http_H1Conn_Close(conn);
    }
    amalgame_net_http_unregister_listen_fd(srv->fd);
    Amalgame_Net_Http_H1Server_Close(srv);
    if (amalgame_net_http_stopping) {
        fprintf(stdout, "Http1.Serve: graceful shutdown — stopped accepting\n");
        fflush(stdout);
    }
    return 0;
}

/* ══════════════════════════════════════════════════════════════════
 *  Http1.ServeAsync(port, handler) — fiber-driven HTTP/1.1 server
 * ══════════════════════════════════════════════════════════════════
 * v0.9.1. Same handler shape as Http1.Serve but runs every connection
 * inside an `amalgame-async` fiber. The OS thread is never blocked on
 * recv / send — when those syscalls return EAGAIN, the fiber parks
 * on epoll and the scheduler advances another fiber meanwhile. Each
 * connection costs a 64 KB fiber stack (vs an 8 MB pthread stack in
 * ServeMt), so several thousand concurrent slow connections fit
 * comfortably in one process.
 *
 * Caller MUST be on Linux (epoll-only in amalgame-async v0.2). On
 * other platforms the WaitFd* calls fall back to "always 0" and the
 * loop spins — guard with `#ifdef __linux__` in user code if you
 * care about portability today (kqueue/IOCP backends planned for
 * v0.3 of amalgame-async).
 *
 * Per-connection lifecycle:
 *   1. Accept loop fiber WaitFdReadable's on the listen fd
 *   2. accept4(... SOCK_NONBLOCK) yields a fresh non-blocking conn fd
 *   3. A new fiber is spawned with the conn — it parses the request
 *      (parse_request now checks c->async_io and parks on EAGAIN),
 *      dispatches the user handler, sends the response via
 *      send_all (also async-aware), and closes the socket.
 *   4. Scheduler pumps until amalgame_net_http_stopping flips
 *      (SIGTERM/SIGINT) or the listen socket dies.
 *
 * Not yet supported:
 *   - HTTP/1.1 keep-alive across multiple requests (close per-conn,
 *     same as Serve/ServeMt today). Wait for v0.9.2.
 *   - HttpServerConfig knobs (timeouts / size limits). v0.9.2 adds
 *     ServeAsyncWith.
 *   - Multi-thread × scheduler (M:N). amalgame-async v0.4 needed.
 */

typedef struct {
    AmalgameH1Server*            srv;
    AmalgameClosure*             handler;
    /* v0.9.3: optional per-conn config — NULL for ServeAsync, set
     * by ServeAsyncWith. The parser honors max_*_bytes via
     * conn->config; keep-alive on the async path follows the
     * sync ServeWith convention (idle_timeout_sec > 0 enables). */
    AmalgameNetHttpServerConfig* config;
    /* v0.9.5: head of a doubly-linked list of in-flight conns. The
     * accept loop walks this on SIGTERM-driven exit and calls
     * Amalgame_Async_FiberCancel on each conn's fiber so handlers
     * parked on recv/send wake immediately rather than waiting out
     * their (potentially long) read timeout. */
    AmalgameH1Conn*              live_head;
} amalgame_h1_async_ctx;

/* v0.9.5: doubly-linked-list helpers for the live-conn registry.
 * Single-threaded by construction — only ever touched from inside
 * the accept loop fiber's stack (spawn, accept-loop sweep) and the
 * per-conn fiber's stack (entry registration, exit splice-out).
 * Both run on the same OS thread under the cooperative scheduler,
 * so no locking is needed. */
static inline void amalgame_h1_async_track(amalgame_h1_async_ctx* ctx,
                                           AmalgameH1Conn* c) {
    c->async_next = ctx->live_head;
    c->async_prev = NULL;
    if (ctx->live_head) ctx->live_head->async_prev = c;
    ctx->live_head = c;
}
static inline void amalgame_h1_async_untrack(amalgame_h1_async_ctx* ctx,
                                             AmalgameH1Conn* c) {
    if (c->async_prev) c->async_prev->async_next = c->async_next;
    if (c->async_next) c->async_next->async_prev = c->async_prev;
    if (ctx->live_head == c) ctx->live_head = c->async_next;
    c->async_next = c->async_prev = NULL;
}

static void* amalgame_h1_async_conn_fn(void* env, void* arg) {
    amalgame_h1_async_ctx* ctx = (amalgame_h1_async_ctx*) env;
    AmalgameH1Conn* conn = (AmalgameH1Conn*) arg;
    conn->config = ctx->config;
    /* v0.9.5: register the current fiber + splice the conn into the
     * live list. _amasync_sched.current is set by amalgame-async to
     * the per-conn fiber AmalgameFiber* — the accept loop's
     * shutdown sweep calls FiberCancel on it. */
    conn->async_fiber = _amasync_sched.current;
    amalgame_h1_async_track(ctx, conn);
    /* Keep-alive policy:
     *   - ServeAsync (config == NULL): always on (RFC 7230 default).
     *   - ServeAsyncWith: only if idle_timeout_sec > 0, mirroring
     *     ServeWith's sync-path semantics so configurations are
     *     portable between Serve / ServeWith / ServeAsync /
     *     ServeAsyncWith.
     * No SO_RCVTIMEO/SO_SNDTIMEO setup — the async helpers
     * (amalgame_h1_recv_into / send_all) drive their own
     * WaitFd timeouts. */
    int keep_alive_enabled =
        ctx->config ? (ctx->config->idle_timeout_sec > 0) : 1;
    while (1) {
        int p = amalgame_h1_parse_request(conn);
        if (p <= 0) break;
        conn->keep_alive =
            keep_alive_enabled ? amalgame_h1_request_keep_alive(conn) : 0;
        AmalgameClosure_call1(ctx->handler, (void*) conn);
        if (!conn->keep_alive) break;
        /* ResetForReuse preserves fd + config + keep_alive — size
         * limits apply to every request on the connection. */
        Amalgame_Net_Http_H1Conn_ResetForReuse(conn);
    }
    /* v0.9.5: splice this conn out of the live registry BEFORE we
     * close the socket. After this point the shutdown sweep won't
     * try to cancel us. */
    amalgame_h1_async_untrack(ctx, conn);
    conn->async_fiber = NULL;
    Amalgame_Net_Http_H1Conn_Close(conn);
    return NULL;
}

static void* amalgame_h1_async_accept_fn(void* env, void* arg) {
    (void) arg;
    amalgame_h1_async_ctx* ctx = (amalgame_h1_async_ctx*) env;
    AmalgameClosure* per_conn = AmalgameClosure_new(
        (void*) amalgame_h1_async_conn_fn, ctx);

    while (ctx->srv->listening && !amalgame_net_http_stopping) {
        /* 1s poll so we re-check the stopping flag without needing
         * a separate wakeup channel. WaitFdReadable returns 0 on
         * timeout — that's fine, the outer loop re-evaluates. */
        code_bool ready = Amalgame_Async_WaitFdReadable(
            (i64) ctx->srv->fd, 1000);
        if (!ready) continue;

        struct sockaddr_in addr;
        socklen_t alen = sizeof(addr);
        /* accept4 needs _GNU_SOURCE; we plain-accept + fcntl-after
         * so the build doesn't depend on per-file feature macros.
         * The two syscalls are cheap; the bench cost is in the
         * handler, not in the accept setup. */
        int cfd = accept(ctx->srv->fd, (struct sockaddr*)&addr, &alen);
        if (cfd >= 0) {
            int fl = fcntl(cfd, F_GETFL, 0);
            if (fl >= 0) fcntl(cfd, F_SETFL, fl | O_NONBLOCK);
            /* Best-effort O_CLOEXEC — descriptors leaking into
             * accidental fork+exec is a portability nit, not a
             * correctness bug. */
            int fdfl = fcntl(cfd, F_GETFD, 0);
            if (fdfl >= 0) fcntl(cfd, F_SETFD, fdfl | FD_CLOEXEC);
        }
        if (cfd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
            if (amalgame_net_http_stopping) break;
            continue;
        }

        AmalgameH1Conn* c =
            (AmalgameH1Conn*) GC_MALLOC(sizeof(AmalgameH1Conn));
        memset(c, 0, sizeof(*c));
        c->fd = cfd;
        c->async_io = 1;
        snprintf(c->remote_addr, sizeof(c->remote_addr),
                 "%s:%u", inet_ntoa(addr.sin_addr),
                 (unsigned) ntohs(addr.sin_port));

        /* FiberSpawn passes arg as i64 — round-trip the conn pointer
         * through (i64)(intptr_t) to preserve all bits. */
        Amalgame_Async_FiberSpawn(per_conn, (i64)(intptr_t) c);
    }

    /* v0.9.5: graceful shutdown sweep. The accept loop is exiting
     * (typically because amalgame_net_http_stopping just flipped via
     * SIGTERM/SIGINT or Http1.RequestShutdown). Walk the live-conn
     * list and FiberCancel each so handlers parked on recv/send wake
     * promptly, return their sentinel error, and let SchedulerRun
     * drain to completion without waiting out the configured
     * header/body/idle timeouts.
     *
     * Per-conn fibers self-untrack on exit, so by the time
     * SchedulerRun returns, live_head is NULL again. The list mutates
     * during this walk (cancellation eventually runs the fiber's
     * cleanup which calls amalgame_h1_async_untrack) but it's safe:
     * we save `next` before calling FiberCancel, and the cancelled
     * fiber doesn't actually run until after this accept fiber yields. */
    for (AmalgameH1Conn* c = ctx->live_head; c; ) {
        AmalgameH1Conn* next = c->async_next;
        if (c->async_fiber) {
            Amalgame_Async_FiberCancel(c->async_fiber);
        }
        c = next;
    }
    return NULL;
}

/* Internal worker used by both Http1.ServeAsync and
 * Http1.ServeAsyncWith. `name` only affects log lines. */
static inline i64 amalgame_h1_serve_async_impl(
        const char* name,
        i64 port,
        AmalgameNetHttpServerConfig* config,
        AmalgameClosure* handler) {
    if (!handler) {
        fprintf(stderr, "%s: handler is NULL\n", name);
        return -1;
    }
    AmalgameH1Server* srv = Amalgame_Net_Http_H1Server_Listen(
        port, config ? config->listen_backlog : 0);
    if (!srv || !srv->listening) {
        fprintf(stderr, "%s: failed to listen on :%lld (%s)\n",
                name, (long long) port, strerror(errno));
        return -2;
    }
    if (!Amalgame_Async_MakeNonBlocking((i64) srv->fd)) {
        fprintf(stderr, "%s: MakeNonBlocking on listen fd failed\n", name);
        amalgame_net_http_unregister_listen_fd(srv->fd);
        Amalgame_Net_Http_H1Server_Close(srv);
        return -3;
    }

    if (config) {
        fprintf(stdout, "%s: listening on :%lld (HTTP/1.1, fibers, max_body=%lld, idle_timeout=%lds)\n",
                name, (long long) port,
                (long long) config->max_body_bytes,
                (long) config->idle_timeout_sec);
    } else {
        fprintf(stdout, "%s: listening on :%lld (HTTP/1.1, fibers)\n",
                name, (long long) port);
    }
    fflush(stdout);

    amalgame_h1_async_ctx* ctx =
        (amalgame_h1_async_ctx*) GC_MALLOC(sizeof(amalgame_h1_async_ctx));
    ctx->srv     = srv;
    ctx->handler = handler;
    ctx->config  = config;

    AmalgameClosure* accept_loop = AmalgameClosure_new(
        (void*) amalgame_h1_async_accept_fn, ctx);
    Amalgame_Async_FiberSpawn(accept_loop, 0);
    Amalgame_Async_SchedulerRun();

    amalgame_net_http_unregister_listen_fd(srv->fd);
    Amalgame_Net_Http_H1Server_Close(srv);
    if (amalgame_net_http_stopping) {
        fprintf(stdout, "%s: graceful shutdown\n", name);
        fflush(stdout);
    }
    return 0;
}

static inline i64 Amalgame_Net_Http_Http1_ServeAsync(i64 port,
                                                     AmalgameClosure* handler) {
    return amalgame_h1_serve_async_impl("Http1.ServeAsync", port, NULL, handler);
}

/* Http1.ServeAsyncWith(port, config, handler) — fiber-driven HTTP/1.1
 * server with per-conn `HttpServerConfig`. Same handler shape as
 * ServeAsync. The config drives:
 *   - listen_backlog (default 64 if 0)
 *   - max_body_bytes / max_header_bytes / max_url_bytes (parser caps;
 *     0 = library default)
 *   - idle_timeout_sec — non-zero enables HTTP/1.1 keep-alive
 *     across requests on the same connection. 0 = close per request
 *     (matches Serve / ServeMt). The async path manages its own
 *     EAGAIN-driven WaitFd timeouts so SO_RCVTIMEO is *not* applied
 *     (that flag would compete with the fiber's WaitFd).
 *
 * v0.9.3 caveat: header_timeout_sec / body_timeout_sec are NOT yet
 * threaded through the async recv helpers — they still use the
 * compile-time AMALGAME_H1_ASYNC_READ_TIMEOUT_MS default (30s). A
 * future version will pipe the per-phase timeouts to
 * amalgame_h1_recv_into so slow-client mitigation matches the sync
 * path exactly.
 */
static inline i64 Amalgame_Net_Http_Http1_ServeAsyncWith(
        i64 port,
        AmalgameNetHttpServerConfig* config,
        AmalgameClosure* handler) {
    return amalgame_h1_serve_async_impl(
        "Http1.ServeAsyncWith", port, config, handler);
}

/* ── Http1.ServeMt(port, handler) — multi-threaded variant ──────
 * v0.6.0. Same handler signature as Http1.Serve, but each accepted
 * connection runs in its own worker thread. The accept loop never
 * blocks on a slow handler — throughput scales with cores + handler
 * latency, not just with handler latency.
 *
 * Threading model: thread-per-connection, fire-and-forget. Each
 * worker is detached at creation, so we don't pin its TID; when it
 * returns, pthread cleans up the stack and bdwgc collects any
 * leftover heap reachable from it.
 *
 * GC safety: GC_pthread_create registers the new thread with bdwgc
 * BEFORE handler-supplied code starts running, so the conn + arg
 * buffer + any AM heap touched by the handler stay scannable. Don't
 * swap GC_pthread_create for raw pthread_create — it would race the
 * collector and produce sporadic free-of-live crashes.
 *
 * On pthread_create failure (EAGAIN — out of resources) we fall back
 * to running the handler inline, so the server keeps serving even
 * under thread-exhaustion conditions. Slower but stays up.
 *
 * Use cases: any request that does I/O (DB, downstream HTTP, file
 * write) — those are the ones that benefit from not blocking the
 * accept loop. Pure-compute handlers see little benefit and pay the
 * pthread_create cost (~20µs on Linux).
 *
 * Caveats:
 *   - Per-thread stack ≈ 8MB on Linux (default pthread). With
 *     thousands of concurrent connections, RSS climbs. v2 can swap
 *     to a bounded thread-pool + queue.
 *   - The handler MUST be thread-safe: any state it touches via
 *     closure capture is shared across workers. Use a Mutex
 *     (amalgame-threading v0.1+) around mutable shared state.
 *   - keep-alive: ResetForReuse + a per-connection request loop
 *     could be added in a future version; today, each worker
 *     handles exactly one request then closes.
 */
typedef struct {
    AmalgameH1Conn*  conn;
    AmalgameClosure* handler;
} amalgame_h1_mt_arg;

static void* amalgame_h1_mt_worker(void* p) {
    amalgame_h1_mt_arg* a = (amalgame_h1_mt_arg*) p;
    if (amalgame_h1_parse_request(a->conn) > 0) {
        AmalgameClosure_call1(a->handler, (void*)a->conn);
    }
    Amalgame_Net_Http_H1Conn_Close(a->conn);
    return NULL;
}

static inline i64 Amalgame_Net_Http_Http1_ServeMt(i64 port,
                                                  AmalgameClosure* handler) {
    if (!handler) {
        fprintf(stderr, "Http1.ServeMt: handler is NULL\n");
        return -1;
    }
    AmalgameH1Server* srv = Amalgame_Net_Http_H1Server_Listen(port, 0);
    if (!srv || !srv->listening) {
        fprintf(stderr, "Http1.ServeMt: failed to listen on :%lld (%s)\n",
                (long long)port, strerror(errno));
        return -2;
    }
    fprintf(stdout, "Http1.ServeMt: listening on :%lld (HTTP/1.1, multi-thread)\n",
            (long long)port);
    fflush(stdout);

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    while (srv->listening && !amalgame_net_http_stopping) {
        AmalgameH1Conn* conn = Amalgame_Net_Http_H1Server_Accept(srv);
        if (!conn) continue;
        amalgame_h1_mt_arg* a =
            (amalgame_h1_mt_arg*) GC_MALLOC(sizeof(*a));
        a->conn    = conn;
        a->handler = handler;
        pthread_t t;
        int rc = GC_pthread_create(&t, &attr, amalgame_h1_mt_worker, a);
        if (rc != 0) {
            /* EAGAIN typically — out of thread resources. Degrade
             * gracefully by running the handler inline rather than
             * dropping the connection. */
            fprintf(stderr, "Http1.ServeMt: GC_pthread_create failed (%s), running inline\n",
                    strerror(rc));
            amalgame_h1_mt_worker(a);
        }
    }
    pthread_attr_destroy(&attr);
    Amalgame_Net_Http_H1Server_Close(srv);
    return 0;
}

/* ── Http1.ServeMtWith(port, config, handler) — multi-thread + config ─
 * v0.6.1. The full-featured server: multi-thread accept (from
 * ServeMt) + per-connection request loop + HttpServerConfig
 * (timeouts + size limits + idle_timeout keep-alive) merged into
 * one entry point. This is what production Mosaic apps should
 * call — everything from v0.4.3 + v0.5.0 + v0.6.0 wired together.
 *
 * Per-connection request loop (mirrors Http1.ServeWith v0.5.0):
 *   parse request → call handler → if keep-alive, ResetForReuse
 *   and parse the next request off the same TCP connection.
 *   SO_RCVTIMEO bounds the idle wait; recv() returns EAGAIN past
 *   the deadline and parse_request returns -1, breaking the loop.
 *
 * Threading model + GC safety unchanged from ServeMt — see the
 * comment block on Http1.ServeMt above. The same caveats apply
 * (per-thread stack ~8MB, handler must be thread-safe).
 */
typedef struct {
    AmalgameH1Conn*               conn;
    AmalgameClosure*              handler;
    AmalgameNetHttpServerConfig*  config;
} amalgame_h1_mt_with_arg;

static void* amalgame_h1_mt_with_worker(void* p) {
    amalgame_h1_mt_with_arg* a = (amalgame_h1_mt_with_arg*) p;
    /* Stash the config so the parser honors size limits. */
    a->conn->config = a->config;
    Amalgame_Net_Http_HttpServerConfig_ApplyToFd(a->conn->fd, a->config);

    int keep_alive_enabled = a->config ? (a->config->idle_timeout_sec > 0) : 0;
    while (1) {
        int parsed = amalgame_h1_parse_request(a->conn);
        if (parsed <= 0) break;
        a->conn->keep_alive = keep_alive_enabled
            ? amalgame_h1_request_keep_alive(a->conn) : 0;
        AmalgameClosure_call1(a->handler, (void*)a->conn);
        if (!a->conn->keep_alive) break;
        /* Switch SO_RCVTIMEO to idle_timeout for the wait on the
         * next request. */
        if (a->config && a->config->idle_timeout_sec > 0) {
            struct timeval tv;
            tv.tv_sec  = a->config->idle_timeout_sec;
            tv.tv_usec = 0;
            setsockopt(a->conn->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        }
        Amalgame_Net_Http_H1Conn_ResetForReuse(a->conn);
    }
    Amalgame_Net_Http_H1Conn_Close(a->conn);
    return NULL;
}

static inline i64 Amalgame_Net_Http_Http1_ServeMtWith(i64 port,
        AmalgameNetHttpServerConfig* config, AmalgameClosure* handler) {
    if (!handler) {
        fprintf(stderr, "Http1.ServeMtWith: handler is NULL\n");
        return -1;
    }
    AmalgameH1Server* srv = Amalgame_Net_Http_H1Server_Listen(
        port, config ? config->listen_backlog : 0);
    if (!srv || !srv->listening) {
        fprintf(stderr, "Http1.ServeMtWith: failed to listen on :%lld (%s)\n",
                (long long)port, strerror(errno));
        return -2;
    }
    int t = config ? config->header_timeout_sec : 0;
    if (config && config->body_timeout_sec > t) t = config->body_timeout_sec;
    int ka = config ? config->idle_timeout_sec : 0;
    fprintf(stdout, "Http1.ServeMtWith: listening on :%lld (HTTP/1.1, multi-thread, timeout=%ds, keep-alive=%ds)\n",
            (long long)port, t, ka);
    fflush(stdout);

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    while (srv->listening && !amalgame_net_http_stopping) {
        AmalgameH1Conn* conn = Amalgame_Net_Http_H1Server_Accept(srv);
        if (!conn) continue;
        amalgame_h1_mt_with_arg* a =
            (amalgame_h1_mt_with_arg*) GC_MALLOC(sizeof(*a));
        a->conn    = conn;
        a->handler = handler;
        a->config  = config;
        pthread_t th;
        int rc = GC_pthread_create(&th, &attr, amalgame_h1_mt_with_worker, a);
        if (rc != 0) {
            fprintf(stderr, "Http1.ServeMtWith: GC_pthread_create failed (%s), running inline\n",
                    strerror(rc));
            amalgame_h1_mt_with_worker(a);
        }
    }
    pthread_attr_destroy(&attr);
    Amalgame_Net_Http_H1Server_Close(srv);
    return 0;
}

/* ── Http1.ServeWith(port, config, handler) — Http1.Serve + config ─
 * Same shape as Http1.Serve but applies HttpServerConfig to every
 * accepted connection. Today that means setting SO_RCVTIMEO /
 * SO_SNDTIMEO from config.header_timeout_sec / body_timeout_sec —
 * the Slowloris guard. Size-limit fields are accepted in the
 * config struct (and TOML schema) but the parser still uses
 * compile-time constants; switching is a v0.4.4 follow-up.
 */
static inline i64 Amalgame_Net_Http_Http1_ServeWith(
        i64 port,
        AmalgameNetHttpServerConfig* config,
        AmalgameClosure* handler) {
    if (!handler) {
        fprintf(stderr, "Http1.ServeWith: handler is NULL\n");
        return -1;
    }
    AmalgameH1Server* srv = Amalgame_Net_Http_H1Server_Listen(port, config ? config->listen_backlog : 0);
    if (!srv || !srv->listening) {
        fprintf(stderr, "Http1.ServeWith: failed to listen on :%lld (%s)\n",
                (long long)port, strerror(errno));
        return -2;
    }
    int t = config ? config->header_timeout_sec : 0;
    if (config && config->body_timeout_sec > t) t = config->body_timeout_sec;
    fprintf(stdout, "Http1.ServeWith: listening on :%lld (HTTP/1.1, timeout=%ds)\n",
            (long long)port, t);
    fflush(stdout);

    while (srv->listening && !amalgame_net_http_stopping) {
        AmalgameH1Conn* conn = Amalgame_Net_Http_H1Server_Accept(srv);
        if (!conn) continue;
        /* Stash the config on the conn so the parser can honor
         * max_body_bytes / max_header_bytes / max_url_bytes
         * (v0.4.5). ApplyToFd does the socket-timeout half of the
         * config (v0.4.3). */
        conn->config = config;
        Amalgame_Net_Http_HttpServerConfig_ApplyToFd(conn->fd, config);

        /* v0.5.0 — keep-alive inner loop. Each iteration parses one
         * request and runs the handler. If the request asks to keep
         * the connection open (HTTP/1.1 default OR `Connection: keep-alive`)
         * AND the configured `idle_timeout_sec` is non-zero, we reset
         * the conn and parse the next request off the same TCP
         * connection. SO_RCVTIMEO (already applied above) bounds the
         * idle wait — recv() returns EAGAIN past the deadline and
         * the next parse_request returns -1, which breaks the loop.
         *
         * Set idle_timeout_sec=0 to disable keep-alive entirely
         * (legacy one-request-per-conn behavior). */
        int keep_alive_enabled = config ? (config->idle_timeout_sec > 0) : 0;
        while (1) {
            int parsed = amalgame_h1_parse_request(conn);
            if (parsed <= 0) break;
            conn->keep_alive = keep_alive_enabled ? amalgame_h1_request_keep_alive(conn) : 0;
            AmalgameClosure_call1(handler, (void*)conn);
            if (!conn->keep_alive) break;
            /* Honor the configured idle timeout for the next-request
             * wait. If idle_timeout differs from body/header timeout,
             * swap to the dedicated value here. */
            if (config && config->idle_timeout_sec > 0) {
                struct timeval tv;
                tv.tv_sec  = config->idle_timeout_sec;
                tv.tv_usec = 0;
                setsockopt(conn->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            }
            Amalgame_Net_Http_H1Conn_ResetForReuse(conn);
        }
        Amalgame_Net_Http_H1Conn_Close(conn);
    }
    Amalgame_Net_Http_H1Server_Close(srv);
    return 0;
}

/* ────────────────────────────────────────────────────────────────
 * WebSocket server (v0.4+, RFC 6455)
 *
 * `Ws.Serve(port, handler)` opens a TCP listener, accepts one
 * connection at a time, performs the HTTP/1.1 → WebSocket upgrade
 * handshake (Sec-WebSocket-Key → Sec-WebSocket-Accept via SHA-1 +
 * base64), then hands the connection to the user's closure.
 *
 * Handler API:
 *
 *     let handler = conn => {
 *         while (!WsConn.IsClosed(conn)) {
 *             let msg: string = WsConn.ReceiveText(conn)
 *             if (String_Length(msg) == 0) { break }
 *             WsConn.SendText(conn, "echo: " + msg)
 *         }
 *         return 0
 *     }
 *     Ws.Serve(8080, handler)
 *
 * Scope of v0.4.0:
 *   - Text + binary frames (opcodes 0x1 / 0x2).
 *   - PING / PONG handled transparently (server replies to PING).
 *   - CLOSE handled (handler's ReceiveText returns "").
 *   - Fragmentation NOT supported yet — multi-fragment messages
 *     get rejected (most browsers/libs send single-fragment for
 *     small messages).
 *   - Payload capped at AMALGAME_WS_MAX_PAYLOAD (1 MB by default).
 *   - One connection at a time (no threading).
 *
 * Requires OpenSSL (SHA1 + base64) — uses the same probe as the
 * HTTPS server. Without OpenSSL, Ws.Serve returns -3.
 *
 * v0.4.x will add Wss.Serve (TLS-wrapped) for wss:// URLs from
 * HTTPS pages.
 * ──────────────────────────────────────────────────────────────── */

#ifdef AMALGAME_HAS_OPENSSL

#define AMALGAME_WS_MAX_PAYLOAD (1024 * 1024)

typedef struct AmalgameWsServer {
    int       fd;
    int32_t   listening;
    i64       port;
} AmalgameWsServer;

typedef struct AmalgameWsConn {
    int       fd;
    int32_t   closed;
    SSL*      ssl;        /* non-NULL on the wss:// path (v0.4.1+) */
} AmalgameWsConn;

/* ── Server lifecycle ──────────────────────────────────────────── */

static inline AmalgameWsServer* Amalgame_Net_Http_WsServer_Listen(i64 port, i64 backlog) {
    AmalgameWsServer* s = (AmalgameWsServer*)GC_MALLOC(sizeof(*s));
    s->fd = -1; s->listening = 0; s->port = port;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return s;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    amalgame_net_http_set_reuseport(fd);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)port);
    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0 ||
        listen(fd, (backlog > 0 ? (int)backlog : 64)) < 0) {
        close(fd);
        return s;
    }
    s->fd = fd; s->listening = 1;
    Amalgame_Net_Http_InstallShutdownSignals();
    amalgame_net_http_register_listen_fd(s->fd);
    return s;
}

static inline code_bool Amalgame_Net_Http_WsServer_IsListening(
        AmalgameWsServer* s) {
    return s && s->listening ? 1 : 0;
}

static inline void Amalgame_Net_Http_WsServer_Close(AmalgameWsServer* s) {
    if (!s) return;
    amalgame_net_http_unregister_listen_fd(s->fd);
    if (s->fd >= 0) close(s->fd);
    s->fd = -1; s->listening = 0;
}

/* ── Handshake helper: base64(SHA1(key + magic)) ───────────────── */

#define AMALGAME_WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

static int amalgame_ws_compute_accept(const char* key_b64, size_t key_len,
                                       char* out, size_t out_cap) {
    /* concat key + GUID, SHA1, base64 — output is always 28 chars
     * + NUL (SHA1 is 20 bytes → base64 = ⌈20/3⌉*4 = 28). */
    char concat[256];
    if (key_len > 128) return -1;
    memcpy(concat, key_b64, key_len);
    memcpy(concat + key_len, AMALGAME_WS_GUID, 36);
    unsigned char digest[20];
    SHA1((unsigned char*)concat, key_len + 36, digest);
    int n = EVP_EncodeBlock((unsigned char*)out, digest, 20);
    if (n < 0 || (size_t)n + 1 > out_cap) return -1;
    out[n] = 0;
    return n;
}

/* ── Frame helpers ────────────────────────────────────────────── */
/* Read N bytes. When `ssl` is non-NULL, route through SSL_read
 * (wss:// path); otherwise raw recv() on `fd`. Returns 0 on
 * success, -1 on error/EOF. */
static int amalgame_ws_read_full(int fd, SSL* ssl, void* buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r;
        if (ssl) {
            int rr = SSL_read(ssl, (char*)buf + got, (int)(n - got));
            if (rr > 0) {
                r = rr;
            } else {
                int err = SSL_get_error(ssl, rr);
                if (err == SSL_ERROR_ZERO_RETURN) return -1;
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) continue;
                return -1;
            }
        } else {
            r = recv(fd, (char*)buf + got, n - got, 0);
            if (r < 0) {
                if (errno == EINTR) continue;
                return -1;
            }
            if (r == 0) return -1;
        }
        got += (size_t)r;
    }
    return 0;
}

/* Write N bytes. When `ssl` is non-NULL, route through SSL_write. */
static int amalgame_ws_write_full(int fd, SSL* ssl, const void* buf, size_t n) {
    size_t sent = 0;
    while (sent < n) {
        ssize_t w;
        if (ssl) {
            int ww = SSL_write(ssl, (const char*)buf + sent, (int)(n - sent));
            if (ww > 0) {
                w = ww;
            } else {
                int err = SSL_get_error(ssl, ww);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) continue;
                return -1;
            }
        } else {
            w = send(fd, (const char*)buf + sent, n - sent, 0);
            if (w < 0) {
                if (errno == EINTR) continue;
                return -1;
            }
            if (w == 0) return -1;
        }
        sent += (size_t)w;
    }
    return 0;
}

/* Send a server-to-client frame. opcode 0x1=text, 0x2=binary,
 * 0x8=close, 0x9=ping, 0xA=pong. MASK=0 (server doesn't mask). */
static int amalgame_ws_send_frame(int fd, SSL* ssl, int opcode,
                                    const char* payload, size_t plen) {
    unsigned char hdr[10];
    int hlen;
    hdr[0] = 0x80 | (opcode & 0x0F);   /* FIN=1, opcode */
    if (plen < 126) {
        hdr[1] = (unsigned char)plen;
        hlen = 2;
    } else if (plen <= 0xFFFF) {
        hdr[1] = 126;
        hdr[2] = (unsigned char)(plen >> 8);
        hdr[3] = (unsigned char)(plen & 0xFF);
        hlen = 4;
    } else {
        hdr[1] = 127;
        uint64_t pl = plen;
        for (int i = 0; i < 8; i++) hdr[2 + i] = (unsigned char)(pl >> ((7 - i) * 8));
        hlen = 10;
    }
    if (amalgame_ws_write_full(fd, ssl, hdr, hlen) < 0) return -1;
    if (plen > 0 && amalgame_ws_write_full(fd, ssl, payload, plen) < 0) return -1;
    return 0;
}

/* Receive next client-to-server frame. Allocates payload into
 * *out (GC), sets *out_len, *opcode_out. Returns 0 on success,
 * -1 on protocol error / EOF. PING is replied with PONG
 * transparently and we loop until a non-PING frame arrives. */
static int amalgame_ws_recv_frame(int fd, SSL* ssl, char** out, size_t* out_len,
                                    int* opcode_out) {
    for (;;) {
        unsigned char hdr[2];
        if (amalgame_ws_read_full(fd, ssl, hdr, 2) < 0) return -1;
        int fin    = (hdr[0] & 0x80) >> 7;
        int opcode = hdr[0] & 0x0F;
        int masked = (hdr[1] & 0x80) >> 7;
        uint64_t plen = hdr[1] & 0x7F;
        if (plen == 126) {
            unsigned char ext[2];
            if (amalgame_ws_read_full(fd, ssl, ext, 2) < 0) return -1;
            plen = ((uint64_t)ext[0] << 8) | ext[1];
        } else if (plen == 127) {
            unsigned char ext[8];
            if (amalgame_ws_read_full(fd, ssl, ext, 8) < 0) return -1;
            plen = 0;
            for (int i = 0; i < 8; i++) plen = (plen << 8) | ext[i];
        }
        if (plen > AMALGAME_WS_MAX_PAYLOAD) return -1;
        unsigned char mask[4] = {0};
        if (masked) {
            if (amalgame_ws_read_full(fd, ssl, mask, 4) < 0) return -1;
        }
        char* buf = (char*)GC_MALLOC_ATOMIC((size_t)plen + 1);
        if (plen > 0 && amalgame_ws_read_full(fd, ssl, buf, (size_t)plen) < 0) return -1;
        if (masked) {
            for (uint64_t i = 0; i < plen; i++) buf[i] ^= mask[i & 3];
        }
        buf[plen] = 0;

        if (opcode == 0x9) {
            /* PING — auto-respond with PONG. */
            amalgame_ws_send_frame(fd, ssl, 0xA, buf, (size_t)plen);
            continue;
        }
        if (opcode == 0xA) {
            /* PONG — ignore. */
            continue;
        }
        /* CLOSE (0x8), TEXT (0x1), BINARY (0x2), continuation (0x0) — surface. */
        if (!fin) return -1;  /* fragmentation: reject for v0.4.0 */
        *out = buf;
        *out_len = (size_t)plen;
        *opcode_out = opcode;
        return 0;
    }
}

/* ── Public WsConn accessors / actions ─────────────────────────── */

/* Receive next text message. Returns "" on close or error
 * (handler should break out of its loop in that case). */
static inline code_string Amalgame_Net_Http_WsConn_ReceiveText(
        AmalgameWsConn* c) {
    if (!c || c->closed || c->fd < 0) return "";
    char* buf = NULL;
    size_t blen = 0;
    int op = 0;
    if (amalgame_ws_recv_frame(c->fd, c->ssl, &buf, &blen, &op) < 0) {
        c->closed = 1;
        return "";
    }
    if (op == 0x8) {                   /* CLOSE */
        amalgame_ws_send_frame(c->fd, c->ssl, 0x8, "", 0);
        c->closed = 1;
        return "";
    }
    if (op != 0x1) {                   /* not text — drop */
        return "";
    }
    return buf;
}

static inline code_bool Amalgame_Net_Http_WsConn_SendText(
        AmalgameWsConn* c, code_string msg) {
    if (!c || c->closed || c->fd < 0 || !msg) return 0;
    size_t mlen = strlen(msg);
    if (amalgame_ws_send_frame(c->fd, c->ssl, 0x1, msg, mlen) < 0) {
        c->closed = 1;
        return 0;
    }
    return 1;
}

static inline code_bool Amalgame_Net_Http_WsConn_IsClosed(
        AmalgameWsConn* c) {
    return c && c->closed ? 1 : 0;
}

static inline void Amalgame_Net_Http_WsConn_Close(AmalgameWsConn* c) {
    if (!c) return;
    if (!c->closed && c->fd >= 0) {
        amalgame_ws_send_frame(c->fd, c->ssl, 0x8, "", 0);
    }
    if (c->ssl) {
        SSL_shutdown(c->ssl);
        SSL_free(c->ssl);
        c->ssl = NULL;
    }
    if (c->fd >= 0) close(c->fd);
    c->fd = -1; c->closed = 1;
}

/* ── Upgrade handshake + accept ─────────────────────────────────── */

/* Read a CRLF-terminated header line. Reads one byte at a time so
 * we stop exactly at the end of the line — leftover bytes (the WS
 * frames that may follow the empty line) stay buffered in the
 * socket / SSL session for the frame parser to pick up. Returns
 * the line length excl. CRLF, 0 on empty line, -1 on error/EOF. */
static int amalgame_ws_read_header_line(int fd, SSL* ssl,
                                         char* buf, size_t cap) {
    size_t i = 0;
    char prev = 0;
    while (i < cap - 1) {
        char c;
        if (ssl) {
            int r = SSL_read(ssl, &c, 1);
            if (r != 1) return -1;
        } else {
            ssize_t r = recv(fd, &c, 1, 0);
            if (r != 1) return -1;
        }
        buf[i++] = c;
        if (prev == '\r' && c == '\n') {
            buf[i - 2] = 0;
            return (int)(i - 2);
        }
        prev = c;
    }
    return -1;
}

/* Run the WebSocket upgrade handshake on a connected (and, if TLS,
 * post-handshake) socket. Returns a fresh AmalgameWsConn on success,
 * NULL on protocol error (closes the fd in that case). */
static inline AmalgameWsConn* amalgame_ws_do_upgrade(int cfd, SSL* ssl) {
    char key[256] = {0};
    int seen_upgrade = 0;
    char line[1024];
    int rv;
    rv = amalgame_ws_read_header_line(cfd, ssl, line, sizeof(line));
    if (rv <= 0) goto fail;
    while ((rv = amalgame_ws_read_header_line(cfd, ssl, line, sizeof(line))) > 0) {
        if (strncasecmp(line, "Sec-WebSocket-Key:", 18) == 0) {
            const char* v = line + 18;
            while (*v == ' ' || *v == '\t') v++;
            strncpy(key, v, sizeof(key) - 1);
        } else if (strncasecmp(line, "Upgrade:", 8) == 0) {
            const char* p = line;
            while (*p) {
                if ((p[0] == 'w' || p[0] == 'W') &&
                    strncasecmp(p, "websocket", 9) == 0) {
                    seen_upgrade = 1; break;
                }
                p++;
            }
        }
    }
    if (rv < 0) goto fail;
    if (!seen_upgrade || !key[0]) {
        const char* bad = "HTTP/1.1 400 Bad Request\r\n"
                          "Content-Length: 0\r\nConnection: close\r\n\r\n";
        amalgame_ws_write_full(cfd, ssl, bad, strlen(bad));
        goto fail;
    }

    char accept_b64[40];
    int alen2 = amalgame_ws_compute_accept(key, strlen(key),
                                            accept_b64, sizeof(accept_b64));
    if (alen2 < 0) goto fail;

    char resp[512];
    int rlen = snprintf(resp, sizeof(resp),
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\n\r\n", accept_b64);
    if (amalgame_ws_write_full(cfd, ssl, resp, rlen) < 0) goto fail;

    AmalgameWsConn* c = (AmalgameWsConn*)GC_MALLOC(sizeof(*c));
    c->fd = cfd; c->closed = 0; c->ssl = ssl;
    return c;

fail:
    if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
    close(cfd);
    return NULL;
}

/* Accept one connection + perform WS handshake (raw ws://). */
static inline AmalgameWsConn* Amalgame_Net_Http_WsServer_Accept(
        AmalgameWsServer* s) {
    if (!s || !s->listening || s->fd < 0) return NULL;
    struct sockaddr_in addr; socklen_t alen = sizeof(addr);
    int cfd = accept(s->fd, (struct sockaddr*)&addr, &alen);
    if (cfd < 0) return NULL;
    return amalgame_ws_do_upgrade(cfd, NULL);
}

/* ── High-level entry point: Ws.Serve(port, handler) ────────────── */

static inline i64 Amalgame_Net_Http_Ws_Serve(i64 port,
                                              AmalgameClosure* handler) {
    if (!handler) {
        fprintf(stderr, "Ws.Serve: handler is NULL\n");
        return -1;
    }
    AmalgameWsServer* srv = Amalgame_Net_Http_WsServer_Listen(port, 0);
    if (!srv || !srv->listening) {
        fprintf(stderr, "Ws.Serve: failed to listen on :%lld (%s)\n",
                (long long)port, strerror(errno));
        return -2;
    }
    fprintf(stdout, "Ws.Serve: listening on :%lld (WebSocket)\n",
            (long long)port);
    fflush(stdout);
    while (srv->listening && !amalgame_net_http_stopping) {
        AmalgameWsConn* conn = Amalgame_Net_Http_WsServer_Accept(srv);
        if (!conn) continue;
        AmalgameClosure_call1(handler, (void*)conn);
        Amalgame_Net_Http_WsConn_Close(conn);
    }
    Amalgame_Net_Http_WsServer_Close(srv);
    return 0;
}

/* ── Ws.ServeMt(port, handler) — multi-thread WebSocket (v0.7.0) ──
 * Each upgraded WsConn gets its own worker thread for the frame
 * loop. Critical for fan-out scenarios — chat / notifications /
 * presence — where one slow client must not block the others.
 * Same GC-safe thread-per-conn pattern as Http1.ServeMt; the
 * handler stays alive in its worker for the connection's lifetime
 * (i.e. until the user closure returns or the client disconnects). */
typedef struct {
    AmalgameWsConn*  conn;
    AmalgameClosure* handler;
} amalgame_ws_mt_arg;

static void* amalgame_ws_mt_worker(void* p) {
    amalgame_ws_mt_arg* a = (amalgame_ws_mt_arg*) p;
    AmalgameClosure_call1(a->handler, (void*) a->conn);
    Amalgame_Net_Http_WsConn_Close(a->conn);
    return NULL;
}

static inline i64 Amalgame_Net_Http_Ws_ServeMt(i64 port,
                                                AmalgameClosure* handler) {
    if (!handler) {
        fprintf(stderr, "Ws.ServeMt: handler is NULL\n");
        return -1;
    }
    AmalgameWsServer* srv = Amalgame_Net_Http_WsServer_Listen(port, 0);
    if (!srv || !srv->listening) {
        fprintf(stderr, "Ws.ServeMt: failed to listen on :%lld (%s)\n",
                (long long)port, strerror(errno));
        return -2;
    }
    fprintf(stdout, "Ws.ServeMt: listening on :%lld (WebSocket, multi-thread)\n",
            (long long)port);
    fflush(stdout);
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    while (srv->listening && !amalgame_net_http_stopping) {
        AmalgameWsConn* conn = Amalgame_Net_Http_WsServer_Accept(srv);
        if (!conn) continue;
        amalgame_ws_mt_arg* a = (amalgame_ws_mt_arg*) GC_MALLOC(sizeof(*a));
        a->conn = conn; a->handler = handler;
        pthread_t t;
        int rc = GC_pthread_create(&t, &attr, amalgame_ws_mt_worker, a);
        if (rc != 0) {
            fprintf(stderr, "Ws.ServeMt: thread create failed (%s), inline\n",
                    strerror(rc));
            amalgame_ws_mt_worker(a);
        }
    }
    pthread_attr_destroy(&attr);
    Amalgame_Net_Http_WsServer_Close(srv);
    return 0;
}

/* ── Ws.ServeWith(port, config, handler) ──────────────────────────
 * Ws.Serve + HttpServerConfig with the timeout dance done RIGHT
 * (v0.4.8): we accept the raw TCP socket ourselves, apply the
 * configured timeout BEFORE the upgrade handshake (so a slow client
 * can't hold the half-upgraded connection open), then CLEAR the
 * timeout after the upgrade succeeds so the long-lived frame loop
 * isn't subject to the handshake-phase deadline.
 *
 * Older v0.4.4–v0.4.7 versions of this function applied the
 * timeout AFTER WsServer_Accept (which does the upgrade
 * internally), which had the opposite of the intended effect:
 * upgrade unprotected, frame loop forcibly cut. This fixes that.
 *
 * WsServer_Accept stays available for users who want a one-shot
 * accept-and-upgrade with no timeout management. */
static inline i64 Amalgame_Net_Http_Ws_ServeWith(
        i64 port,
        AmalgameNetHttpServerConfig* config,
        AmalgameClosure* handler) {
    if (!handler) {
        fprintf(stderr, "Ws.ServeWith: handler is NULL\n");
        return -1;
    }
    AmalgameWsServer* srv = Amalgame_Net_Http_WsServer_Listen(port, config ? config->listen_backlog : 0);
    if (!srv || !srv->listening) {
        fprintf(stderr, "Ws.ServeWith: failed to listen on :%lld (%s)\n",
                (long long)port, strerror(errno));
        return -2;
    }
    fprintf(stdout, "Ws.ServeWith: listening on :%lld (WebSocket, timeout-protected upgrade)\n",
            (long long)port);
    fflush(stdout);
    while (srv->listening && !amalgame_net_http_stopping) {
        /* Manual accept-then-upgrade so we can bracket the upgrade
         * with timeout-apply / timeout-clear. */
        struct sockaddr_in addr; socklen_t alen = sizeof(addr);
        int cfd = accept(srv->fd, (struct sockaddr*)&addr, &alen);
        if (cfd < 0) continue;
        Amalgame_Net_Http_HttpServerConfig_ApplyToFd(cfd, config);
        AmalgameWsConn* conn = amalgame_ws_do_upgrade(cfd, NULL);
        if (!conn) continue;
        Amalgame_Net_Http_HttpServerConfig_ClearTimeoutsOnFd(conn->fd);
        AmalgameClosure_call1(handler, (void*)conn);
        Amalgame_Net_Http_WsConn_Close(conn);
    }
    Amalgame_Net_Http_WsServer_Close(srv);
    return 0;
}

/* ────────────────────────────────────────────────────────────────
 * WssServer — wss:// (TLS-wrapped WebSocket), v0.4.1+
 *
 * Same shape as `WsServer` plus an SSL_CTX. For each accepted TCP
 * connection we SSL_accept, then run the WebSocket upgrade
 * handshake over SSL_read/SSL_write, and hand back a WsConn whose
 * `ssl` field is set — all subsequent frame I/O routes through
 * SSL_read/SSL_write transparently (same code path as ws://, the
 * helpers branch on conn->ssl).
 *
 *     Wss.Serve(443, "cert.pem", "key.pem", handler)
 *
 * Browsers reach this endpoint with `new WebSocket("wss://host/")`
 * which is the only allowed form when the page is loaded over
 * HTTPS (mixed-content rules forbid plain ws://).
 *
 * Same constraints as the Ws server (no fragmentation, 1 MB payload
 * cap) + the constraints of the Https server (one cert per
 * listener, TLS 1.2+).
 * ──────────────────────────────────────────────────────────────── */

typedef struct AmalgameWssServer {
    int       fd;
    int32_t   listening;
    i64       port;
    SSL_CTX*  ssl_ctx;
} AmalgameWssServer;

/* v0.7.1 — variant that honors HttpServerConfig.tls_min_version.
 * Legacy 4-arg signature delegates to this with cfg=NULL. */
static inline AmalgameWssServer* Amalgame_Net_Http_WssServer_ListenEx(
        i64 port, code_string cert_file, code_string key_file, i64 backlog,
        AmalgameNetHttpServerConfig* cfg) {
    AmalgameWssServer* s =
        (AmalgameWssServer*)GC_MALLOC(sizeof(AmalgameWssServer));
    memset(s, 0, sizeof(*s));
    s->port = port; s->fd = -1;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return s;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    amalgame_net_http_set_reuseport(fd);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)port);
    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0 ||
        listen(fd, (backlog > 0 ? (int)backlog : 64)) < 0) {
        close(fd); return s;
    }
    s->fd = fd;

    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) { close(fd); s->fd = -1; return s; }
    int min_ver = TLS1_2_VERSION;
    if (cfg) {
        if (cfg->tls_min_version == 13) min_ver = TLS1_3_VERSION;
        else if (cfg->tls_min_version == 12) min_ver = TLS1_2_VERSION;
    }
    SSL_CTX_set_min_proto_version(ctx, min_ver);
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file (ctx, key_file,  SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        close(fd); s->fd = -1;
        return s;
    }
    if (SSL_CTX_check_private_key(ctx) != 1) {
        fprintf(stderr, "Wss.Serve: cert/key mismatch\n");
        SSL_CTX_free(ctx);
        close(fd); s->fd = -1;
        return s;
    }
    s->ssl_ctx = ctx;
    s->listening = 1;
    Amalgame_Net_Http_InstallShutdownSignals();
    amalgame_net_http_register_listen_fd(s->fd);
    return s;
}

/* Legacy 4-arg signature. */
static inline AmalgameWssServer* Amalgame_Net_Http_WssServer_Listen(
        i64 port, code_string cert_file, code_string key_file, i64 backlog) {
    return Amalgame_Net_Http_WssServer_ListenEx(port, cert_file, key_file,
                                                 backlog, NULL);
}

static inline code_bool Amalgame_Net_Http_WssServer_IsListening(
        AmalgameWssServer* s) {
    return s && s->listening ? 1 : 0;
}

static inline AmalgameWsConn* Amalgame_Net_Http_WssServer_Accept(
        AmalgameWssServer* s) {
    if (!s || !s->listening || s->fd < 0) return NULL;
    struct sockaddr_in addr; socklen_t alen = sizeof(addr);
    int cfd = accept(s->fd, (struct sockaddr*)&addr, &alen);
    if (cfd < 0) return NULL;

    SSL* ssl = SSL_new(s->ssl_ctx);
    if (!ssl) { close(cfd); return NULL; }
    SSL_set_fd(ssl, cfd);
    int rv = SSL_accept(ssl);
    if (rv != 1) {
        fprintf(stderr, "Wss.Serve: TLS handshake failed\n");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(cfd);
        return NULL;
    }
    return amalgame_ws_do_upgrade(cfd, ssl);
}

static inline void Amalgame_Net_Http_WssServer_Close(AmalgameWssServer* s) {
    if (!s) return;
    amalgame_net_http_unregister_listen_fd(s->fd);
    if (s->fd >= 0) close(s->fd);
    if (s->ssl_ctx) SSL_CTX_free(s->ssl_ctx);
    s->fd = -1; s->ssl_ctx = NULL; s->listening = 0;
}

static inline i64 Amalgame_Net_Http_Wss_Serve(i64 port,
                                               code_string cert_file,
                                               code_string key_file,
                                               AmalgameClosure* handler) {
    if (!handler) {
        fprintf(stderr, "Wss.Serve: handler is NULL\n");
        return -1;
    }
    if (!cert_file || !cert_file[0] || !key_file || !key_file[0]) {
        fprintf(stderr, "Wss.Serve: certFile and keyFile required\n");
        return -4;
    }
    static int ssl_initialised = 0;
    if (!ssl_initialised) {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
        ssl_initialised = 1;
    }
    AmalgameWssServer* srv = Amalgame_Net_Http_WssServer_Listen(
        port, cert_file, key_file, 0);
    if (!srv || !srv->listening) {
        fprintf(stderr, "Wss.Serve: failed to listen on :%lld (%s)\n",
                (long long)port, strerror(errno));
        return -2;
    }
    fprintf(stdout, "Wss.Serve: listening on :%lld (wss://)\n",
            (long long)port);
    fflush(stdout);
    while (srv->listening && !amalgame_net_http_stopping) {
        AmalgameWsConn* conn = Amalgame_Net_Http_WssServer_Accept(srv);
        if (!conn) continue;
        AmalgameClosure_call1(handler, (void*)conn);
        Amalgame_Net_Http_WsConn_Close(conn);
    }
    Amalgame_Net_Http_WssServer_Close(srv);
    return 0;
}

/* ── Wss.ServeMt(port, cert, key, handler) — multi-thread (v0.7.0) ─
 * wss:// equivalent of Ws.ServeMt: thread per accepted TLS+upgrade
 * WebSocket conn, drives the frame loop inside the worker. */
static inline i64 Amalgame_Net_Http_Wss_ServeMt(i64 port,
        code_string cert_file, code_string key_file,
        AmalgameClosure* handler) {
    if (!handler) {
        fprintf(stderr, "Wss.ServeMt: handler is NULL\n");
        return -1;
    }
    if (!cert_file || !cert_file[0] || !key_file || !key_file[0]) {
        fprintf(stderr, "Wss.ServeMt: certFile and keyFile required\n");
        return -4;
    }
    static int ssl_initialised = 0;
    if (!ssl_initialised) {
        SSL_library_init(); SSL_load_error_strings(); OpenSSL_add_all_algorithms();
        ssl_initialised = 1;
    }
    AmalgameWssServer* srv = Amalgame_Net_Http_WssServer_Listen(
        port, cert_file, key_file, 0);
    if (!srv || !srv->listening) {
        fprintf(stderr, "Wss.ServeMt: failed to listen on :%lld (%s)\n",
                (long long)port, strerror(errno));
        return -2;
    }
    fprintf(stdout, "Wss.ServeMt: listening on :%lld (wss://, multi-thread)\n",
            (long long)port);
    fflush(stdout);
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    while (srv->listening && !amalgame_net_http_stopping) {
        AmalgameWsConn* conn = Amalgame_Net_Http_WssServer_Accept(srv);
        if (!conn) continue;
        amalgame_ws_mt_arg* a = (amalgame_ws_mt_arg*) GC_MALLOC(sizeof(*a));
        a->conn = conn; a->handler = handler;
        pthread_t t;
        int rc = GC_pthread_create(&t, &attr, amalgame_ws_mt_worker, a);
        if (rc != 0) {
            fprintf(stderr, "Wss.ServeMt: thread create failed (%s), inline\n",
                    strerror(rc));
            amalgame_ws_mt_worker(a);
        }
    }
    pthread_attr_destroy(&attr);
    Amalgame_Net_Http_WssServer_Close(srv);
    return 0;
}

/* ── Wss.ServeWith(port, cert, key, config, handler) ──────────────
 * Wss.Serve + HttpServerConfig with the same timeout dance as
 * Ws.ServeWith (v0.4.8): apply timeout before SSL_accept + upgrade,
 * clear timeout before the long-lived frame loop. */
static inline i64 Amalgame_Net_Http_Wss_ServeWith(
        i64 port,
        code_string cert_file,
        code_string key_file,
        AmalgameNetHttpServerConfig* config,
        AmalgameClosure* handler) {
    if (!handler) {
        fprintf(stderr, "Wss.ServeWith: handler is NULL\n");
        return -1;
    }
    if (!cert_file || !cert_file[0] || !key_file || !key_file[0]) {
        fprintf(stderr, "Wss.ServeWith: certFile and keyFile required\n");
        return -4;
    }
    static int ssl_initialised = 0;
    if (!ssl_initialised) {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
        ssl_initialised = 1;
    }
    AmalgameWssServer* srv = Amalgame_Net_Http_WssServer_ListenEx(
        port, cert_file, key_file,
        config ? config->listen_backlog : 0, config);
    if (!srv || !srv->listening) {
        fprintf(stderr, "Wss.ServeWith: failed to listen on :%lld (%s)\n",
                (long long)port, strerror(errno));
        return -2;
    }
    fprintf(stdout, "Wss.ServeWith: listening on :%lld (wss://, timeout-protected upgrade)\n",
            (long long)port);
    fflush(stdout);
    while (srv->listening && !amalgame_net_http_stopping) {
        /* Manual accept → SSL_accept → upgrade → clear-timeout
         * sequence so the timeout brackets the slow phases (raw
         * accept, TLS handshake, HTTP upgrade) but doesn't bleed
         * into the WebSocket frame loop. */
        struct sockaddr_in addr; socklen_t alen = sizeof(addr);
        int cfd = accept(srv->fd, (struct sockaddr*)&addr, &alen);
        if (cfd < 0) continue;
        Amalgame_Net_Http_HttpServerConfig_ApplyToFd(cfd, config);
        SSL* ssl = SSL_new(srv->ssl_ctx);
        if (!ssl) { close(cfd); continue; }
        SSL_set_fd(ssl, cfd);
        int rv = SSL_accept(ssl);
        if (rv != 1) {
            fprintf(stderr, "Wss.ServeWith: TLS handshake failed\n");
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(cfd);
            continue;
        }
        AmalgameWsConn* conn = amalgame_ws_do_upgrade(cfd, ssl);
        if (!conn) continue;
        Amalgame_Net_Http_HttpServerConfig_ClearTimeoutsOnFd(conn->fd);
        AmalgameClosure_call1(handler, (void*)conn);
        Amalgame_Net_Http_WsConn_Close(conn);
    }
    Amalgame_Net_Http_WssServer_Close(srv);
    return 0;
}

#else  /* !AMALGAME_HAS_OPENSSL — WebSocket needs SHA1+base64 */

typedef struct AmalgameWsServer AmalgameWsServer;
typedef struct AmalgameWsConn   AmalgameWsConn;
static inline AmalgameWsServer* Amalgame_Net_Http_WsServer_Listen(i64 p, i64 b) {
    (void)b;
    (void)p; return NULL;
}
static inline code_bool Amalgame_Net_Http_WsServer_IsListening(
        AmalgameWsServer* s) { (void)s; return 0; }
static inline AmalgameWsConn* Amalgame_Net_Http_WsServer_Accept(
        AmalgameWsServer* s) { (void)s; return NULL; }
static inline void Amalgame_Net_Http_WsServer_Close(AmalgameWsServer* s) {
    (void)s;
}
static inline code_string Amalgame_Net_Http_WsConn_ReceiveText(
        AmalgameWsConn* c) { (void)c; return ""; }
static inline code_bool Amalgame_Net_Http_WsConn_SendText(
        AmalgameWsConn* c, code_string m) { (void)c; (void)m; return 0; }
static inline code_bool Amalgame_Net_Http_WsConn_IsClosed(
        AmalgameWsConn* c) { (void)c; return 1; }
static inline void Amalgame_Net_Http_WsConn_Close(AmalgameWsConn* c) {
    (void)c;
}
static inline i64 Amalgame_Net_Http_Ws_Serve(i64 port,
        AmalgameClosure* h) {
    (void)port; (void)h;
    fprintf(stderr, "Ws.Serve: built without OpenSSL — SHA1+base64 needed for the upgrade handshake.\n");
    return -3;
}
static inline i64 Amalgame_Net_Http_Ws_ServeWith(i64 port,
        AmalgameNetHttpServerConfig* cfg, AmalgameClosure* h) {
    (void)port; (void)cfg; (void)h;
    fprintf(stderr, "Ws.ServeWith: built without OpenSSL.\n");
    return -3;
}
static inline i64 Amalgame_Net_Http_Ws_ServeMt(i64 port,
        AmalgameClosure* h) {
    (void)port; (void)h;
    fprintf(stderr, "Ws.ServeMt: built without OpenSSL.\n");
    return -3;
}
typedef struct AmalgameWssServer AmalgameWssServer;
static inline AmalgameWssServer* Amalgame_Net_Http_WssServer_Listen(
        i64 p, code_string c, code_string k, i64 b) {
    (void)p;(void)c;(void)k;(void)b; return NULL; }
static inline code_bool Amalgame_Net_Http_WssServer_IsListening(
        AmalgameWssServer* s) { (void)s; return 0; }
static inline AmalgameWsConn* Amalgame_Net_Http_WssServer_Accept(
        AmalgameWssServer* s) { (void)s; return NULL; }
static inline void Amalgame_Net_Http_WssServer_Close(AmalgameWssServer* s) {
    (void)s;
}
static inline i64 Amalgame_Net_Http_Wss_Serve(i64 port,
        code_string cert, code_string key, AmalgameClosure* h) {
    (void)port; (void)cert; (void)key; (void)h;
    fprintf(stderr, "Wss.Serve: built without OpenSSL.\n");
    return -3;
}
static inline i64 Amalgame_Net_Http_Wss_ServeWith(i64 port,
        code_string cert, code_string key,
        AmalgameNetHttpServerConfig* cfg, AmalgameClosure* h) {
    (void)port; (void)cert; (void)key; (void)cfg; (void)h;
    fprintf(stderr, "Wss.ServeWith: built without OpenSSL.\n");
    return -3;
}
static inline i64 Amalgame_Net_Http_Wss_ServeMt(i64 port,
        code_string cert, code_string key, AmalgameClosure* h) {
    (void)port; (void)cert; (void)key; (void)h;
    fprintf(stderr, "Wss.ServeMt: built without OpenSSL.\n");
    return -3;
}

#endif /* AMALGAME_HAS_OPENSSL */

#endif /* AMALGAME_NET_HTTP_H */
