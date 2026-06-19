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
#ifdef _WIN32
  /* Windows: the BSD-socket API lives in Winsock2. ws2tcpip.h adds
   * getaddrinfo + socklen_t. The POSIX→Winsock shim (wrappers + macro
   * aliases) is installed further down, AFTER the nghttp2/openssl
   * probes, so it can't disturb those system headers. */
  #ifndef WIN32_LEAN_AND_MEAN
  #  define WIN32_LEAN_AND_MEAN
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <windows.h>
  #include <errno.h>
  #include <stdio.h>
  #include <signal.h>     /* v0.8.0: graceful shutdown (SIGINT/SIGTERM) */
#else
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <netdb.h>        /* v0.23.0: getaddrinfo for the H2 client dial */
  #include <unistd.h>
  #include <errno.h>
  #include <stdio.h>
  #include <signal.h>       /* v0.8.0: graceful SIGTERM/SIGINT shutdown */
  #include <fcntl.h>
#endif
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

#if defined(_WIN32) && !defined(AMALGAME_WIN_SOCK_SHIM)
#define AMALGAME_WIN_SOCK_SHIM 1
/* ── POSIX-socket → Winsock2 compatibility shim (Windows only) ──────
 * Shared across the Amalgame networking packages (net-http, tls): the
 * AMALGAME_WIN_SOCK_SHIM guard makes the first-included header define it
 * and the others reuse it, so a TU pulling several net headers has one
 * copy of the wrappers and one set of aliases.
 *
 * The BSD-socket code is written for POSIX. On Windows the calls exist
 * in Winsock2 under the same names, but: errors land in WSAGetLastError()
 * (not errno), close() must be closesocket(), and non-blocking is
 * ioctlsocket(FIONBIO) (not fcntl). We wrap each socket call so it sets
 * `errno` from a translated WSA error, then alias the POSIX names to the
 * wrappers — so all the errno/EAGAIN/EWOULDBLOCK handling works unchanged.
 * Wrappers are defined BEFORE the macros so their bodies bind to the
 * genuine Winsock functions. Placed AFTER each header's openssl/nghttp2
 * probes, so the macros never rewrite a system header. */
static inline int amsock_wsa2errno(int w) {
    switch (w) {
        case WSAEWOULDBLOCK:  return EWOULDBLOCK;
        case WSAEINPROGRESS:  return EINPROGRESS;
        case WSAEINTR:        return EINTR;
        case WSAECONNRESET:   return ECONNRESET;
        case WSAECONNABORTED: return ECONNABORTED;
        case WSAENOTCONN:     return ENOTCONN;
        case WSAETIMEDOUT:    return ETIMEDOUT;
        case WSAEADDRINUSE:   return EADDRINUSE;
        case WSAEINVAL:       return EINVAL;
        case WSAEMFILE:       return EMFILE;
        case WSAENOBUFS:      return ENOBUFS;
        case 0:               return 0;
        default:              return EIO;
    }
}
static inline void amsock_wsa_init(void) {
    static volatile LONG done = 0;
    if (InterlockedCompareExchange(&done, 1, 0) == 0) {
        WSADATA wsa; (void) WSAStartup(MAKEWORD(2, 2), &wsa);
    }
}
/* Run WSAStartup at load time so getaddrinfo()/socket() are usable
 * before the first explicit call, on any thread. */
__attribute__((constructor))
static void amsock_wsa_ctor(void) { amsock_wsa_init(); }

static inline int amsock_socket(int d, int t, int p) {
    SOCKET s = socket(d, t, p);
    if (s == INVALID_SOCKET) { errno = amsock_wsa2errno(WSAGetLastError()); return -1; }
    return (int) s;
}
static inline int amsock_accept(int s, struct sockaddr* a, socklen_t* l) {
    SOCKET c = accept((SOCKET) s, a, l);
    if (c == INVALID_SOCKET) { errno = amsock_wsa2errno(WSAGetLastError()); return -1; }
    return (int) c;
}
static inline int amsock_bind(int s, const struct sockaddr* a, socklen_t l) {
    if (bind((SOCKET) s, a, l) == SOCKET_ERROR) { errno = amsock_wsa2errno(WSAGetLastError()); return -1; }
    return 0;
}
static inline int amsock_listen(int s, int b) {
    if (listen((SOCKET) s, b) == SOCKET_ERROR) { errno = amsock_wsa2errno(WSAGetLastError()); return -1; }
    return 0;
}
static inline int amsock_connect(int s, const struct sockaddr* a, socklen_t l) {
    if (connect((SOCKET) s, a, l) == SOCKET_ERROR) { errno = amsock_wsa2errno(WSAGetLastError()); return -1; }
    return 0;
}
static inline int amsock_setsockopt(int s, int lv, int o, const void* v, socklen_t l) {
    if (setsockopt((SOCKET) s, lv, o, (const char*) v, l) == SOCKET_ERROR) { errno = amsock_wsa2errno(WSAGetLastError()); return -1; }
    return 0;
}
static inline int amsock_getsockopt(int s, int lv, int o, void* v, socklen_t* l) {
    if (getsockopt((SOCKET) s, lv, o, (char*) v, l) == SOCKET_ERROR) { errno = amsock_wsa2errno(WSAGetLastError()); return -1; }
    return 0;
}
static inline int amsock_recv(int s, void* b, size_t n, int f) {
    int r = recv((SOCKET) s, (char*) b, (int) n, f);
    if (r == SOCKET_ERROR) { errno = amsock_wsa2errno(WSAGetLastError()); return -1; }
    return r;
}
static inline int amsock_send(int s, const void* b, size_t n, int f) {
    int r = send((SOCKET) s, (const char*) b, (int) n, f);
    if (r == SOCKET_ERROR) { errno = amsock_wsa2errno(WSAGetLastError()); return -1; }
    return r;
}
static inline int amsock_shutdown(int s, int how) {
    return shutdown((SOCKET) s, how);
}
static inline int amsock_close(int fd) {
    return closesocket((SOCKET) fd);   /* every close() in this header is a socket */
}
static inline int amsock_set_nonblock(int fd) {
    u_long m = 1; return ioctlsocket((SOCKET) fd, FIONBIO, &m);
}

#define socket(d, t, p)          amsock_socket((d), (t), (p))
#define accept(s, a, l)          amsock_accept((s), (a), (l))
#define bind(s, a, l)            amsock_bind((s), (a), (l))
#define listen(s, b)             amsock_listen((s), (b))
#define connect(s, a, l)         amsock_connect((s), (a), (l))
#define setsockopt(s, lv, o, v, l) amsock_setsockopt((s), (lv), (o), (v), (l))
#define getsockopt(s, lv, o, v, l) amsock_getsockopt((s), (lv), (o), (v), (l))
#define recv(s, b, n, f)         amsock_recv((s), (b), (n), (f))
#define send(s, b, n, f)         amsock_send((s), (b), (n), (f))
#define shutdown(s, h)           amsock_shutdown((s), (h))
#define close(fd)                amsock_close(fd)

#ifndef SHUT_RD
#  define SHUT_RD   SD_RECEIVE
#  define SHUT_WR   SD_SEND
#  define SHUT_RDWR SD_BOTH
#endif
#ifndef MSG_DONTWAIT
#  define MSG_DONTWAIT 0   /* emulated via a non-blocking socket on Windows */
#endif
#ifndef MSG_NOSIGNAL
#  define MSG_NOSIGNAL 0   /* no SIGPIPE on Windows */
#endif
#endif /* _WIN32 */

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

/* ── Connection-level cap (v0.20.0) ────────────────────────────────
 * A process-wide ceiling on concurrently-served connections, across all
 * multi-thread accept loops. Defends against connection exhaustion /
 * slowloris-at-the-connection-level (which per-request rate limiting
 * doesn't see) and bounds worker-thread RSS. 0 = unlimited (default).
 * Opt in with Http.SetMaxConnections(n); accept loops call conn_admit()
 * and each worker calls conn_release() exactly once on exit. */
static long amalgame_net_http_active_conns = 0;
static long amalgame_net_http_max_conns    = 0;   /* 0 = unlimited */
/* Process-global request-body cap (bytes). 0 = use the compile-time
 * AMALGAME_H1_MAX_BODY default. Set via Http1.SetMaxBodyBytes(n); applies
 * to every accept loop (HTTP/1.1, HTTPS-H1) regardless of per-conn config,
 * so a server (e.g. a WebDAV NAS) can lift the 8 MiB default without
 * threading an HttpServerConfig through ServeHttps.
 *
 * WEAK + external linkage (not `static`): this header is inlined into many
 * translation units (the caller's main, plus every package archive — incl.
 * amalgame-web's MosaicServer, which is where the HTTPS accept loop + parser
 * actually run). A `static` global would give each TU its own copy, so a
 * SetMaxBodyBytes() call from the app's TU would never reach the parser
 * running inside the web archive. A weak definition collapses to a single
 * shared instance at link time, so the setter and the reader agree. */
long amalgame_net_http_max_body __attribute__((weak)) = 0;   /* 0 = library default */

/* Request-body spooling (v0.28.0). When a request's Content-Length is >=
 * the threshold (and threshold > 0), the H1 parser streams the body straight
 * to a temp file in the spool dir instead of buffering it in RAM — so peak
 * RAM stays flat (~64 KiB) regardless of upload size. The handler reads the
 * path via H1Conn.BodyFile / HttpRequest.BodyFile and typically rename()s it
 * into place (atomic on the same volume). Weak + external linkage for the
 * same cross-TU reason as amalgame_net_http_max_body. */
long  amalgame_net_http_body_spool_threshold __attribute__((weak)) = 0;   /* 0 = never spool */
char* amalgame_net_http_body_spool_dir       __attribute__((weak)) = 0;   /* NULL = /tmp */

static inline void Amalgame_Net_Http_Http1_SetMaxConnections(i64 n) {
    amalgame_net_http_max_conns = (long) n;
}
static inline void Amalgame_Net_Http_Http1_SetMaxBodyBytes(i64 n) {
    amalgame_net_http_max_body = (long) n;
}
static inline void Amalgame_Net_Http_Http1_SetBodySpoolThreshold(i64 n) {
    amalgame_net_http_body_spool_threshold = (long) n;
}
static inline void Amalgame_Net_Http_Http1_SetBodySpoolDir(code_string dir) {
    /* Copy so the caller's AM string can't be GC'd out from under us. */
    if (!dir) { amalgame_net_http_body_spool_dir = 0; return; }
    size_t n = strlen(dir);
    char* p = (char*) malloc(n + 1);
    if (!p) return;
    memcpy(p, dir, n + 1);
    amalgame_net_http_body_spool_dir = p;
}
static inline i64 Amalgame_Net_Http_Http1_ActiveConnections(void) {
    return (i64) __sync_add_and_fetch(&amalgame_net_http_active_conns, 0);
}
/* Reserve a slot for one new connection. Returns 1 if admitted (counter
 * incremented), 0 if at capacity (caller must close the fd). */
static inline int amalgame_net_http_conn_admit(void) {
    long max = amalgame_net_http_max_conns;
    long cur = __sync_add_and_fetch(&amalgame_net_http_active_conns, 1);
    if (max > 0 && cur > max) {
        __sync_sub_and_fetch(&amalgame_net_http_active_conns, 1);
        return 0;
    }
    return 1;
}
static inline void amalgame_net_http_conn_release(void) {
    __sync_sub_and_fetch(&amalgame_net_http_active_conns, 1);
}

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
#ifdef _WIN32
    /* Windows has no sigaction/SIGPIPE. The CRT's signal() handles
     * SIGINT (Ctrl-C) and SIGTERM; that's enough for the graceful-stop
     * flag. Half-closed-socket writes return WSAECONNRESET rather than
     * raising a signal, so there's nothing to ignore. */
    signal(SIGINT,  amalgame_net_http_sig_handler);
    signal(SIGTERM, amalgame_net_http_sig_handler);
#else
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = amalgame_net_http_sig_handler;
    sa.sa_flags   = SA_RESTART;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);
    /* SIGPIPE: writes to a half-closed socket would otherwise kill
     * the worker mid-handler.  We want EPIPE from write() instead. */
    signal(SIGPIPE, SIG_IGN);
#endif
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

/* Dual-stack listener (v0.21.0). An AF_INET6 socket with IPV6_V6ONLY=0
 * accepts BOTH IPv6 and IPv4 clients (the latter arrive as v4-mapped
 * ::ffff:a.b.c.d). Falls back to a plain AF_INET socket when IPv6 is
 * unavailable on the host (so behaviour never regresses). Returns a
 * bound + listening fd with SO_REUSEADDR (+ SO_REUSEPORT), or -1. */
static inline int amalgame_net_http_listen_dual(i64 port, i64 backlog) {
    int blog = (backlog > 0 ? (int)backlog : 64);
    int one = 1;
    int fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (fd >= 0) {
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        amalgame_net_http_set_reuseport(fd);
        int zero = 0;                       /* accept IPv4 on this v6 socket */
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof(zero));
        struct sockaddr_in6 a6;
        memset(&a6, 0, sizeof(a6));
        a6.sin6_family = AF_INET6;
        a6.sin6_addr   = in6addr_any;
        a6.sin6_port   = htons((uint16_t)port);
        if (bind(fd, (struct sockaddr*)&a6, sizeof(a6)) == 0 &&
            listen(fd, blog) == 0) {
            return fd;
        }
        close(fd);
    }
    /* Fallback: IPv4-only. */
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    amalgame_net_http_set_reuseport(fd);
    struct sockaddr_in a4;
    memset(&a4, 0, sizeof(a4));
    a4.sin_family      = AF_INET;
    a4.sin_addr.s_addr = INADDR_ANY;
    a4.sin_port        = htons((uint16_t)port);
    if (bind(fd, (struct sockaddr*)&a4, sizeof(a4)) < 0 ||
        listen(fd, blog) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* Format an accepted peer as "ip:port". A v4-mapped IPv6 address
 * (::ffff:a.b.c.d), which is how an IPv4 client appears on a dual-stack
 * socket, is rendered as plain "a.b.c.d" so RemoteAddr stays IPv4 for
 * IPv4 clients — preserving rate-limit keys, Host-guard and access-log
 * semantics across the dual-stack switch. (v0.21.0) */
static inline void amalgame_net_http_peer_str(
        struct sockaddr_storage* ss, char* out, size_t outn) {
    char ip[64]; ip[0] = '\0'; unsigned pport = 0;
    if (ss->ss_family == AF_INET6) {
        struct sockaddr_in6* s6 = (struct sockaddr_in6*)ss;
        pport = ntohs(s6->sin6_port);
        if (IN6_IS_ADDR_V4MAPPED(&s6->sin6_addr)) {
            struct in_addr a4;
            memcpy(&a4, &s6->sin6_addr.s6_addr[12], 4);
            inet_ntop(AF_INET, &a4, ip, sizeof(ip));
        } else {
            inet_ntop(AF_INET6, &s6->sin6_addr, ip, sizeof(ip));
        }
    } else if (ss->ss_family == AF_INET) {
        struct sockaddr_in* s4 = (struct sockaddr_in*)ss;
        pport = ntohs(s4->sin_port);
        inet_ntop(AF_INET, &s4->sin_addr, ip, sizeof(ip));
    }
    snprintf(out, outn, "%s:%u", ip, pport);
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

    /* gRPC response mode (v0.22.0): when grpc_mode != 0 the data source
     * callback closes the DATA without END_STREAM and submits the
     * grpc-status / grpc-message HTTP/2 *trailers* (mandatory for gRPC). */
    int32_t   grpc_mode;
    int32_t   grpc_status;
    char*     grpc_message;
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

/* gRPC data source (v0.22.0): identical streaming of resp_body, but at
 * EOF it does NOT end the stream — it sets NGHTTP2_DATA_FLAG_NO_END_STREAM
 * and submits the trailing HEADERS (grpc-status / grpc-message), which
 * is how gRPC signals the call result. Per the nghttp2 contract,
 * nghttp2_submit_trailer is called from inside this callback when
 * NO_END_STREAM is set. */
static ssize_t amalgame_h2_grpc_data_cb(nghttp2_session* sess,
                                        int32_t stream_id,
                                        uint8_t* buf, size_t length,
                                        uint32_t* data_flags,
                                        nghttp2_data_source* source,
                                        void* user) {
    (void)source;
    AmalgameH2Conn* c = (AmalgameH2Conn*)user;
    int32_t remaining = c->resp_body_len - c->resp_body_off;
    if (remaining > 0) {
        size_t copy = (size_t)remaining < length ? (size_t)remaining : length;
        memcpy(buf, c->resp_body + c->resp_body_off, copy);
        c->resp_body_off += (int32_t)copy;
        return (ssize_t)copy;
    }
    /* All body bytes sent — emit the gRPC trailers and end the stream. */
    *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    *data_flags |= NGHTTP2_DATA_FLAG_NO_END_STREAM;
    char st[12];
    snprintf(st, sizeof(st), "%d", c->grpc_status);
    const char* gm = c->grpc_message ? c->grpc_message : "";
    nghttp2_nv tr[2] = {
        { (uint8_t*)"grpc-status",  (uint8_t*)st,
          11, strlen(st), NGHTTP2_NV_FLAG_NONE },
        { (uint8_t*)"grpc-message", (uint8_t*)gm,
          12, strlen(gm), NGHTTP2_NV_FLAG_NONE },
    };
    nghttp2_submit_trailer(sess, stream_id, tr, 2);
    return 0;
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
/* Binary-safe single-byte request-body access (v0.22.0): the body
 * buffer may contain embedded NUL bytes (protobuf / gRPC / binary
 * uploads), which H2Conn_Body's NUL-terminated string view truncates.
 * Returns the byte at index i (0..255), or -1 out of range. */
static inline i64 Amalgame_Net_Http_H2Conn_BodyByteAt(AmalgameH2Conn* c, i64 i) {
    if (!c || !c->body || i < 0 || i >= (i64)c->body_len) return -1;
    return (i64)(unsigned char)c->body[i];
}

/* Submit a gRPC response (v0.22.0): :status 200 + content-type
 * application/grpc, a binary-safe body taken from an AmalgameList<int>
 * of bytes, and the grpc-status / grpc-message HTTP/2 trailers (emitted
 * by amalgame_h2_grpc_data_cb once the body is flushed). This is what
 * makes the stack able to serve real gRPC — H2Conn_Respond can express
 * neither trailers nor a binary body. */
static inline void Amalgame_Net_Http_H2Conn_RespondGrpc(AmalgameH2Conn* c,
                                                        AmalgameList* body,
                                                        i64 grpc_status,
                                                        code_string grpc_message) {
    if (!c || !c->session) return;
    int n = body ? AmalgameList_count(body) : 0;
    if (n < 0) n = 0;
    char* bb = (char*)GC_MALLOC_ATOMIC((size_t)(n > 0 ? n : 1));
    for (int i = 0; i < n; i++) {
        unsigned int b = (unsigned int)(intptr_t) AmalgameList_get(body, i);
        bb[i] = (char)(b & 0xFFu);
    }
    c->resp_body = bb;
    c->resp_body_len = (int32_t)n;
    c->resp_body_off = 0;
    c->grpc_mode = 1;
    c->grpc_status = (int32_t)grpc_status;
    if (grpc_message && grpc_message[0]) {
        size_t ml = strlen(grpc_message);
        char* m = (char*)GC_MALLOC_ATOMIC(ml + 1);
        memcpy(m, grpc_message, ml + 1);
        c->grpc_message = m;
    } else {
        c->grpc_message = NULL;
    }

    nghttp2_nv hdrs[2] = {
        { (uint8_t*)":status",      (uint8_t*)"200",
          7, 3, NGHTTP2_NV_FLAG_NONE },
        { (uint8_t*)"content-type", (uint8_t*)"application/grpc",
          12, 16, NGHTTP2_NV_FLAG_NONE },
    };
    nghttp2_data_provider dp;
    dp.source.ptr = c;
    dp.read_callback = amalgame_h2_grpc_data_cb;
    nghttp2_submit_response(c->session, c->current_stream, hdrs, 2, &dp);
    nghttp2_session_send(c->session);
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

/* ────────────────────────────────────────────────────────────────
 * AmalgameH2Client — synchronous HTTP/2 (h2c) client (v0.23.0).
 * Mirror of the server path: one unary request/response per call, with
 * binary-safe body collection and grpc-status/grpc-message trailer
 * capture — enough to drive a gRPC client (amalgame-net-grpc).
 * ──────────────────────────────────────────────────────────────── */

typedef struct AmalgameH2Client {
    int fd;
#ifdef AMALGAME_HAS_OPENSSL
    SSL*     ssl;            /* v0.24.0: non-NULL → TLS (h2) client */
    SSL_CTX* ssl_ctx;
#else
    void*    ssl;
    void*    ssl_ctx;
#endif
    nghttp2_session* session;
    const unsigned char* req_body; size_t req_len, req_off;   /* request body source */
    int32_t  resp_status;
    char*    resp_body; int32_t resp_body_len; int32_t resp_body_cap;
    char     resp_content_type[128];
    char     resp_grpc_status[16];
    char     resp_grpc_message[256];
    int32_t  done;
} AmalgameH2Client;

static void amalgame_h2c_append(AmalgameH2Client* c, const uint8_t* d, size_t n) {
    if ((int)(c->resp_body_len + (int)n) > c->resp_body_cap) {
        int nc = c->resp_body_cap > 0 ? c->resp_body_cap * 2 : 1024;
        while (nc < c->resp_body_len + (int)n) nc *= 2;
        char* nb = (char*) GC_MALLOC_ATOMIC((size_t) nc);
        if (c->resp_body_len > 0) memcpy(nb, c->resp_body, (size_t) c->resp_body_len);
        c->resp_body = nb; c->resp_body_cap = nc;
    }
    memcpy(c->resp_body + c->resp_body_len, d, n);
    c->resp_body_len += (int) n;
}

static int amalgame_h2c_on_header(nghttp2_session* s, const nghttp2_frame* f,
                                  const uint8_t* name, size_t nl,
                                  const uint8_t* val, size_t vl,
                                  uint8_t flags, void* user) {
    (void) s; (void) f; (void) flags;
    AmalgameH2Client* c = (AmalgameH2Client*) user;
    if (nl == 7 && memcmp(name, ":status", 7) == 0) {
        char b[8]; size_t k = vl < 7 ? vl : 7; memcpy(b, val, k); b[k] = 0;
        c->resp_status = atoi(b);
    } else if (nl == 12 && memcmp(name, "content-type", 12) == 0) {
        size_t k = vl < sizeof(c->resp_content_type) - 1 ? vl : sizeof(c->resp_content_type) - 1;
        memcpy(c->resp_content_type, val, k); c->resp_content_type[k] = 0;
    } else if (nl == 11 && memcmp(name, "grpc-status", 11) == 0) {
        size_t k = vl < sizeof(c->resp_grpc_status) - 1 ? vl : sizeof(c->resp_grpc_status) - 1;
        memcpy(c->resp_grpc_status, val, k); c->resp_grpc_status[k] = 0;
    } else if (nl == 12 && memcmp(name, "grpc-message", 12) == 0) {
        size_t k = vl < sizeof(c->resp_grpc_message) - 1 ? vl : sizeof(c->resp_grpc_message) - 1;
        memcpy(c->resp_grpc_message, val, k); c->resp_grpc_message[k] = 0;
    }
    return 0;
}
static int amalgame_h2c_on_data(nghttp2_session* s, uint8_t flags, int32_t sid,
                                const uint8_t* data, size_t len, void* user) {
    (void) s; (void) flags; (void) sid;
    amalgame_h2c_append((AmalgameH2Client*) user, data, len);
    return 0;
}
static int amalgame_h2c_on_close(nghttp2_session* s, int32_t sid, uint32_t ec, void* user) {
    (void) s; (void) sid; (void) ec;
    ((AmalgameH2Client*) user)->done = 1;
    return 0;
}
static ssize_t amalgame_h2c_req_read(nghttp2_session* s, int32_t sid, uint8_t* buf,
                                     size_t length, uint32_t* data_flags,
                                     nghttp2_data_source* src, void* user) {
    (void) s; (void) sid; (void) src; (void) user;
    AmalgameH2Client* c = (AmalgameH2Client*) ((nghttp2_data_source*) src)->ptr;
    size_t rem = c->req_len - c->req_off;
    size_t cp = rem < length ? rem : length;
    if (cp > 0) { memcpy(buf, c->req_body + c->req_off, cp); c->req_off += cp; }
    if (c->req_off >= c->req_len) *data_flags |= NGHTTP2_DATA_FLAG_EOF;   /* END_STREAM */
    return (ssize_t) cp;
}

static int amalgame_h2c_dial(const char* host, int port) {
    char ps[16]; snprintf(ps, sizeof(ps), "%d", port);
    struct addrinfo hints; memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* res = NULL;
    if (getaddrinfo(host, ps, &hints, &res) != 0 || !res) return -1;
    int fd = -1;
    for (struct addrinfo* ai = res; ai; ai = ai->ai_next) {
        fd = (int) socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

/* Connect to an h2c server. Returns a client handle (check
 * H2Client_IsConnected) — never NULL so AM stays null-guard-free. */
static inline AmalgameH2Client* Amalgame_Net_Http_H2Client_ConnectH2c(code_string host, i64 port) {
    AmalgameH2Client* c = (AmalgameH2Client*) GC_MALLOC(sizeof(AmalgameH2Client));
    memset(c, 0, sizeof(*c));
    c->fd = -1; c->resp_status = -1; c->resp_grpc_status[0] = 0;
    int fd = amalgame_h2c_dial(host ? host : "", (int) port);
    if (fd < 0) return c;
    struct timeval to; to.tv_sec = 30; to.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &to, sizeof(to));
    nghttp2_session_callbacks* cb;
    nghttp2_session_callbacks_new(&cb);
    nghttp2_session_callbacks_set_on_header_callback(cb, amalgame_h2c_on_header);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cb, amalgame_h2c_on_data);
    nghttp2_session_callbacks_set_on_stream_close_callback(cb, amalgame_h2c_on_close);
    nghttp2_session_client_new(&c->session, cb, c);
    nghttp2_session_callbacks_del(cb);
    nghttp2_settings_entry iv[1] = { { NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100 } };
    nghttp2_submit_settings(c->session, NGHTTP2_FLAG_NONE, iv, 1);
    c->fd = fd;
    return c;
}

/* Connect over TLS (ALPN h2). `insecure != 0` skips certificate +
 * hostname verification (self-signed / dev). Otherwise the system trust
 * store is used and the hostname is checked. (v0.24.0) */
static inline AmalgameH2Client* Amalgame_Net_Http_H2Client_ConnectTls(
        code_string host, i64 port, i64 insecure) {
    AmalgameH2Client* c = (AmalgameH2Client*) GC_MALLOC(sizeof(AmalgameH2Client));
    memset(c, 0, sizeof(*c));
    c->fd = -1; c->resp_status = -1; c->resp_grpc_status[0] = 0;
#ifdef AMALGAME_HAS_OPENSSL
    int fd = amalgame_h2c_dial(host ? host : "", (int) port);
    if (fd < 0) return c;
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { close(fd); return c; }
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    if (insecure) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    } else {
        SSL_CTX_set_default_verify_paths(ctx);
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    }
    SSL* ssl = SSL_new(ctx);
    if (!ssl) { SSL_CTX_free(ctx); close(fd); return c; }
    SSL_set_fd(ssl, fd);
    if (host && host[0]) {
        SSL_set_tlsext_host_name(ssl, host);                 /* SNI */
        if (!insecure) {
            X509_VERIFY_PARAM* vp = SSL_get0_param(ssl);
            X509_VERIFY_PARAM_set1_host(vp, host, 0);
        }
    }
    /* ALPN: advertise just h2 (required for gRPC over TLS). */
    static const unsigned char alpn_h2[] = { 2, 'h', '2' };
    SSL_set_alpn_protos(ssl, alpn_h2, sizeof(alpn_h2));
    if (SSL_connect(ssl) != 1) {
        if (getenv("AMALGAME_TLS_DEBUG")) ERR_print_errors_fp(stderr);
        ERR_clear_error(); SSL_free(ssl); SSL_CTX_free(ctx); close(fd); return c;
    }
    c->ssl = ssl; c->ssl_ctx = ctx;
    nghttp2_session_callbacks* cb;
    nghttp2_session_callbacks_new(&cb);
    nghttp2_session_callbacks_set_on_header_callback(cb, amalgame_h2c_on_header);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cb, amalgame_h2c_on_data);
    nghttp2_session_callbacks_set_on_stream_close_callback(cb, amalgame_h2c_on_close);
    nghttp2_session_client_new(&c->session, cb, c);
    nghttp2_session_callbacks_del(cb);
    nghttp2_settings_entry iv[1] = { { NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100 } };
    nghttp2_submit_settings(c->session, NGHTTP2_FLAG_NONE, iv, 1);
    c->fd = fd;
#else
    (void) host; (void) port; (void) insecure;
#endif
    return c;
}

static inline code_bool Amalgame_Net_Http_H2Client_IsConnected(AmalgameH2Client* c) {
    return (c && c->fd >= 0 && c->session) ? 1 : 0;
}

/* One unary request: POST `path` with content-type + `te: trailers` and
 * a binary-safe body (from a List<int>); drives the session until the
 * stream closes; collects status + body + grpc trailers. Returns the
 * HTTP :status (or -1 on transport error). */
static inline i64 Amalgame_Net_Http_H2Client_Unary(AmalgameH2Client* c, code_string path,
                                                   AmalgameList* body, code_string content_type) {
    if (!c || c->fd < 0 || !c->session) return -1;
    int n = body ? AmalgameList_count(body) : 0; if (n < 0) n = 0;
    unsigned char* rb = (unsigned char*) GC_MALLOC_ATOMIC((size_t)(n > 0 ? n : 1));
    for (int i = 0; i < n; i++) {
        unsigned int b = (unsigned int)(intptr_t) AmalgameList_get(body, i);
        rb[i] = (unsigned char)(b & 0xFFu);
    }
    c->req_body = rb; c->req_len = (size_t) n; c->req_off = 0;
    c->done = 0; c->resp_body_len = 0; c->resp_status = -1;
    c->resp_grpc_status[0] = 0; c->resp_grpc_message[0] = 0; c->resp_content_type[0] = 0;

    const char* ct = (content_type && content_type[0]) ? content_type : "application/grpc";
    const char* p  = (path && path[0]) ? path : "/";
    nghttp2_data_provider dp; dp.source.ptr = c; dp.read_callback = amalgame_h2c_req_read;
    nghttp2_nv hdrs[6] = {
        { (uint8_t*)":method",      (uint8_t*)"POST", 7, 4, NGHTTP2_NV_FLAG_NONE },
        { (uint8_t*)":scheme",      (uint8_t*)"http", 7, 4, NGHTTP2_NV_FLAG_NONE },
        { (uint8_t*)":path",        (uint8_t*)p, 5, strlen(p), NGHTTP2_NV_FLAG_NONE },
        { (uint8_t*)":authority",   (uint8_t*)"localhost", 10, 9, NGHTTP2_NV_FLAG_NONE },
        { (uint8_t*)"te",           (uint8_t*)"trailers", 2, 8, NGHTTP2_NV_FLAG_NONE },
        { (uint8_t*)"content-type", (uint8_t*)ct, 12, strlen(ct), NGHTTP2_NV_FLAG_NONE },
    };
    nghttp2_submit_request(c->session, NULL, hdrs, 6, &dp, NULL);

    unsigned char buf[16384];
    int guard = 0;
    while (!c->done && guard++ < 1000000) {
        const uint8_t* out; ssize_t ol;
        while ((ol = nghttp2_session_mem_send(c->session, &out)) > 0) {
            ssize_t off = 0;
            while (off < ol) {
                ssize_t w;
#ifdef AMALGAME_HAS_OPENSSL
                if (c->ssl) w = SSL_write(c->ssl, out + off, (int)(ol - off));
                else
#endif
                    w = send(c->fd, out + off, (size_t)(ol - off), 0);
                if (w <= 0) { c->done = 1; break; }
                off += w;
            }
        }
        if (c->done) break;
        ssize_t r;
#ifdef AMALGAME_HAS_OPENSSL
        if (c->ssl) r = SSL_read(c->ssl, buf, sizeof(buf));
        else
#endif
            r = recv(c->fd, buf, sizeof(buf), 0);
        if (r <= 0) break;
        if (nghttp2_session_mem_recv(c->session, buf, (size_t) r) < 0) break;
    }
    return (i64) c->resp_status;
}
static inline i64 Amalgame_Net_Http_H2Client_Status(AmalgameH2Client* c) {
    return c ? (i64) c->resp_status : -1;
}
static inline i64 Amalgame_Net_Http_H2Client_BodyLen(AmalgameH2Client* c) {
    return (c && c->resp_body) ? (i64) c->resp_body_len : 0;
}
static inline i64 Amalgame_Net_Http_H2Client_BodyByteAt(AmalgameH2Client* c, i64 i) {
    if (!c || !c->resp_body || i < 0 || i >= (i64) c->resp_body_len) return -1;
    return (i64)(unsigned char) c->resp_body[i];
}
/* gRPC status from the trailer, or -1 if none was sent. */
static inline i64 Amalgame_Net_Http_H2Client_GrpcStatus(AmalgameH2Client* c) {
    return (c && c->resp_grpc_status[0]) ? (i64) atoi(c->resp_grpc_status) : -1;
}
static inline code_string Amalgame_Net_Http_H2Client_GrpcMessage(AmalgameH2Client* c) {
    return (c && c->resp_grpc_message[0]) ? c->resp_grpc_message : "";
}
static inline code_string Amalgame_Net_Http_H2Client_ContentType(AmalgameH2Client* c) {
    return (c && c->resp_content_type[0]) ? c->resp_content_type : "";
}
static inline void Amalgame_Net_Http_H2Client_Close(AmalgameH2Client* c) {
    if (!c) return;
    if (c->session) { nghttp2_session_del(c->session); c->session = NULL; }
#ifdef AMALGAME_HAS_OPENSSL
    if (c->ssl) { SSL_shutdown(c->ssl); SSL_free(c->ssl); c->ssl = NULL; }
    if (c->ssl_ctx) { SSL_CTX_free(c->ssl_ctx); c->ssl_ctx = NULL; }
#endif
    if (c->fd >= 0) { close(c->fd); c->fd = -1; }
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

#endif /* AMALGAME_HAS_NGHTTP2 — the HttpServerConfig section below is
        * protocol-agnostic (HTTP/1 uses it too) and MUST be defined
        * whether or not nghttp2 is present. Without this split it lived
        * inside the nghttp2 block, so a build without nghttp2 (e.g.
        * Windows) left AmalgameNetHttpServerConfig undefined and every
        * H1/stub reference to it failed. Reopened after the section. */

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

#ifdef AMALGAME_HAS_NGHTTP2  /* reopen — HTTP/2 code resumes (needs nghttp2) */

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
    amalgame_net_http_conn_release();
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
        /* Connection cap: reject (close) when at capacity. */
        if (!amalgame_net_http_conn_admit()) {
            Amalgame_Net_Http_H2Conn_Close(conn);
            continue;
        }
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
    if (SSL_CTX_use_certificate_chain_file(ctx, cert_file) <= 0 ||
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
        /* Routine on a public :443 (scanners, old clients) — silent unless
         * AMALGAME_TLS_DEBUG. Clear the OpenSSL error queue. */
        if (getenv("AMALGAME_TLS_DEBUG")) {
            int err = SSL_get_error(ssl, rv);
            fprintf(stderr, "Https.Serve: TLS handshake failed (SSL err %d)\n", err);
            ERR_print_errors_fp(stderr);
        }
        ERR_clear_error();
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
        /* Connection cap: reject (close) when at capacity. */
        if (!amalgame_net_http_conn_admit()) {
            Amalgame_Net_Http_H2Conn_Close(conn);
            continue;
        }
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
static inline i64 Amalgame_Net_Http_H2Conn_BodyByteAt(AmalgameH2Conn* c, i64 i) {
    (void)c; (void)i; return -1;
}
static inline void Amalgame_Net_Http_H2Conn_Respond(AmalgameH2Conn* c,
                                                     i64 s, code_string ct,
                                                     code_string b) {
    (void)c; (void)s; (void)ct; (void)b;
}
static inline void Amalgame_Net_Http_H2Conn_RespondGrpc(AmalgameH2Conn* c,
                                                        AmalgameList* body,
                                                        i64 gs, code_string gm) {
    (void)c; (void)body; (void)gs; (void)gm;
}
static inline void Amalgame_Net_Http_H2Conn_Close(AmalgameH2Conn* c) {
    (void)c;
}
/* H2Client stubs (no nghttp2). */
typedef struct AmalgameH2Client { int fd; } AmalgameH2Client;
static inline AmalgameH2Client* Amalgame_Net_Http_H2Client_ConnectH2c(code_string h, i64 p) {
    (void)h; (void)p; return NULL;
}
static inline AmalgameH2Client* Amalgame_Net_Http_H2Client_ConnectTls(code_string h, i64 p, i64 ins) {
    (void)h; (void)p; (void)ins; return NULL;
}
static inline code_bool Amalgame_Net_Http_H2Client_IsConnected(AmalgameH2Client* c) { (void)c; return 0; }
static inline i64 Amalgame_Net_Http_H2Client_Unary(AmalgameH2Client* c, code_string path,
                                                   AmalgameList* body, code_string ct) {
    (void)c; (void)path; (void)body; (void)ct; return -1;
}
static inline i64 Amalgame_Net_Http_H2Client_Status(AmalgameH2Client* c) { (void)c; return -1; }
static inline i64 Amalgame_Net_Http_H2Client_BodyLen(AmalgameH2Client* c) { (void)c; return 0; }
static inline i64 Amalgame_Net_Http_H2Client_BodyByteAt(AmalgameH2Client* c, i64 i) { (void)c; (void)i; return -1; }
static inline i64 Amalgame_Net_Http_H2Client_GrpcStatus(AmalgameH2Client* c) { (void)c; return -1; }
static inline code_string Amalgame_Net_Http_H2Client_GrpcMessage(AmalgameH2Client* c) { (void)c; return ""; }
static inline code_string Amalgame_Net_Http_H2Client_ContentType(AmalgameH2Client* c) { (void)c; return ""; }
static inline void Amalgame_Net_Http_H2Client_Close(AmalgameH2Client* c) { (void)c; }
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
    /* v0.28.0: when the body was spooled to disk (Content-Length >=
     * spool threshold), this holds the temp-file path and `body` is the
     * empty string. NULL/empty = body is in RAM at `body`. */
    char*     body_file;
    int64_t   body_file_len;
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
    /* v0.14.0: open-ended streaming response (SSE / long-poll). Set by
     * H1Conn_BeginStream, which also forces keep_alive=0 so the
     * keep-alive request loop breaks + closes after the handler
     * returns (framing is Connection: close — the response ends when
     * the socket closes). Cleared by ResetForReuse for completeness. */
    int32_t                  streaming;
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
/* Request-framing safety (anti request-smuggling). Returns 1 if the parsed
 * header set is unambiguously framable, 0 if it must be rejected. Pulled
 * out of amalgame_h1_parse_request so it can be unit-tested. RFC 7230
 * §3.3.3:
 *   - Content-Length AND Transfer-Encoding together → reject (CL.TE/TE.CL).
 *   - Any Transfer-Encoding on a request → reject (this server doesn't
 *     decode chunked request bodies; honoring CL/0 would leave the chunk
 *     framing on the wire and desync the next request).
 *   - Conflicting duplicate Content-Length → reject (CL.CL).
 *   - Non-numeric Content-Length → reject (atoi() would mis-frame). */
static inline int amalgame_h1_framing_ok(const AmalgameH1Header* headers, int count) {
    int cl_count = 0, te_count = 0;
    const char* cl_val = NULL;
    for (int i = 0; i < count; i++) {
        if (strcmp(headers[i].name, "content-length") == 0) {
            if (cl_count > 0 && cl_val && strcmp(cl_val, headers[i].value) != 0) return 0;
            cl_val = headers[i].value;
            cl_count++;
        } else if (strcmp(headers[i].name, "transfer-encoding") == 0) {
            te_count++;
        }
    }
    if (te_count > 0 && cl_count > 0) return 0;
    if (te_count > 0) return 0;
    if (cl_val) {
        if (cl_val[0] == '\0') return 0;
        for (const char* p = cl_val; *p; p++) {
            if (*p < '0' || *p > '9') return 0;
        }
    }
    return 1;
}

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

    /* Strict request line: reject empty method / target / version. This
     * catches double-space request lines ("GET  /x HTTP/1.1" → empty
     * target) that strict proxies and this server could frame
     * differently — a request-line desync vector. */
    if (meth_len == 0 || targ_len == 0 || vers_len == 0) return -1;

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

    /* ── Anti-smuggling header validation (RFC 7230 §3.3.3) ─────── */
    if (!amalgame_h1_framing_ok(c->headers, c->header_count)) return -1;

    /* ── Body — only if Content-Length present ─────────────────── */
    long content_length = 0;
    for (int i = 0; i < c->header_count; i++) {
        if (strcmp(c->headers[i].name, "content-length") == 0) {
            content_length = atoll(c->headers[i].value);
            break;
        }
    }
    if (content_length < 0) return -1;

    /* ── Large-body spooling (v0.28.0) ─────────────────────────────
     * When SetBodySpoolThreshold(n>0) is set and Content-Length >= n,
     * stream the body straight to a temp file in the spool dir instead
     * of buffering it in RAM — peak RAM stays ~64 KiB regardless of
     * upload size. The handler reads the path via H1Conn.BodyFile and
     * owns it (rename into place / delete). The in-RAM max_body cap does
     * NOT apply here (the body never sits in RAM); size is bounded by
     * disk + the handler. */
    if (amalgame_net_http_body_spool_threshold > 0 &&
        content_length >= amalgame_net_http_body_spool_threshold) {
        const char* sdir = amalgame_net_http_body_spool_dir
                         ? amalgame_net_http_body_spool_dir : "/tmp";
        char tmpl[4096];
        snprintf(tmpl, sizeof(tmpl), "%s/amh1body-XXXXXX", sdir);
        int tfd = mkstemp(tmpl);
        if (tfd < 0) return -1;
        FILE* tf = fdopen(tfd, "wb");
        if (!tf) { close(tfd); unlink(tmpl); return -1; }
        long written = 0;
        /* bytes already pulled past the headers by the initial recv */
        int body_in_buf = total - (headers_len + 4);
        if (body_in_buf > 0) {
            long copy = (long)body_in_buf > content_length
                      ? content_length : (long)body_in_buf;
            if (copy > 0 &&
                fwrite(eoh + 4, 1, (size_t)copy, tf) != (size_t)copy) {
                fclose(tf); unlink(tmpl); return -1;
            }
            written = copy;
        }
        i64 body_to_ms = amalgame_h1_async_body_timeout_ms(c);
        char sbuf[65536];
        while (written < content_length) {
            long want = content_length - written;
            if (want > (long)sizeof(sbuf)) want = (long)sizeof(sbuf);
            ssize_t rn = amalgame_h1_recv_into(c, sbuf, (size_t)want, body_to_ms);
            if (rn <= 0) { fclose(tf); unlink(tmpl); return -1; }
            if (fwrite(sbuf, 1, (size_t)rn, tf) != (size_t)rn) {
                fclose(tf); unlink(tmpl); return -1;
            }
            written += rn;
        }
        if (fclose(tf) != 0) { unlink(tmpl); return -1; }
        char* bf = (char*) GC_MALLOC_ATOMIC(strlen(tmpl) + 1);
        strcpy(bf, tmpl);
        c->body_file     = bf;
        c->body_file_len = written;
        c->body          = "";
        c->body_len      = 0;
        return 1;
    }

    /* In-RAM body cap. Precedence: per-conn config (Http1.ServeWith) >
     * process-global (Http1.SetMaxBodyBytes) > compile-time constant.
     * Zero at a level = fall through to the next. */
    int max_body = AMALGAME_H1_MAX_BODY;
    if (amalgame_net_http_max_body > 0) {
        max_body = (int)amalgame_net_http_max_body;
    }
    if (c->config && c->config->max_body_bytes > 0) {
        max_body = (int)c->config->max_body_bytes;
    }
    if (content_length > (long)max_body) return -1;

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

    /* v0.21.0: dual-stack (IPv6 + IPv4) listener; IPv4-only fallback. */
    int fd = amalgame_net_http_listen_dual(port, backlog);
    if (fd < 0) return s;
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
    struct sockaddr_storage ss; socklen_t alen = sizeof(ss);
    int cfd = accept(s->fd, (struct sockaddr*)&ss, &alen);
    if (cfd < 0) return NULL;
    AmalgameH1Conn* c =
        (AmalgameH1Conn*)GC_MALLOC(sizeof(AmalgameH1Conn));
    memset(c, 0, sizeof(*c));
    c->fd = cfd;
    /* v0.21.0: capture peer "ip:port"; v4-mapped IPv6 (an IPv4 client on
     * the dual-stack socket) is normalized back to plain IPv4 so
     * RemoteAddr semantics are unchanged for IPv4 clients. */
    amalgame_net_http_peer_str(&ss, c->remote_addr, sizeof(c->remote_addr));
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
/* Peer "ip:port" captured at accept time. Lets AM read the client IP
 * (e.g. for geoip) without an @c cast into the struct. */
static inline code_string Amalgame_Net_Http_H1Conn_RemoteAddr(AmalgameH1Conn* c) {
    return (c && c->remote_addr[0]) ? c->remote_addr : "";
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
/* v0.28.0: path of the temp file the body was spooled to (large uploads),
 * or "" when the body is in RAM at `body`. The handler owns the file: move
 * it into place (rename) or delete it. */
static inline code_string Amalgame_Net_Http_H1Conn_BodyFile(AmalgameH1Conn* c) {
    return (c && c->body_file) ? c->body_file : "";
}
/* v0.14.0: raw body byte at index i (0..BodyLen-1), as an i64 0..255;
 * -1 when out of range or no body. H1Conn_Body returns a char* that AM
 * treats as a NUL-terminated code_string — it truncates at the first
 * NUL, which is fatal for binary uploads (PNG/PDF/…). The multipart
 * parser walks the raw buffer with this accessor and slices each part
 * into a List<int>, sidestepping the truncation entirely. */
static inline i64 Amalgame_Net_Http_H1Conn_BodyByteAt(AmalgameH1Conn* c, i64 i) {
    if (!c || !c->body) return -1;
    if (i < 0 || i >= (i64)c->body_len) return -1;
    return (i64)(unsigned char)c->body[i];
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

/* Reason phrase for a status code — shared by the v0.14.1 caller-header
 * binary path. Mirrors amalgame_h1_send_response's table. */
static inline const char* amalgame_h1_reason_phrase(i64 status) {
    switch ((int)status) {
        case 100: return "Continue";
        case 200: return "OK";
        case 201: return "Created";
        case 202: return "Accepted";
        case 204: return "No Content";
        case 206: return "Partial Content";
        case 301: return "Moved Permanently";
        case 302: return "Found";
        case 303: return "See Other";
        case 304: return "Not Modified";
        case 307: return "Temporary Redirect";
        case 308: return "Permanent Redirect";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 409: return "Conflict";
        case 410: return "Gone";
        case 413: return "Payload Too Large";
        case 415: return "Unsupported Media Type";
        case 416: return "Range Not Satisfiable";
        case 422: return "Unprocessable Content";
        case 429: return "Too Many Requests";
        case 500: return "Internal Server Error";
        case 501: return "Not Implemented";
        case 502: return "Bad Gateway";
        case 503: return "Service Unavailable";
        case 504: return "Gateway Timeout";
    }
    return "OK";
}

/* v0.14.1: binary body (ptr,len) WITH a caller-supplied header block —
 * the binary-safe sibling of RespondFull. Lets HttpResponse ship a
 * gzip-compressed or otherwise-binary body while keeping its custom
 * headers (Content-Encoding, CSP, Set-Cookie, …). headers_block is the
 * RespondFull shape: "Name: Value\r\n" lines, NO trailing blank line,
 * and MUST NOT carry Content-Length / Connection (added here). */
static inline void Amalgame_Net_Http_H1Conn_RespondBytesFull(AmalgameH1Conn* c,
                                                              i64 status,
                                                              code_string headers_block,
                                                              i64 body_ptr,
                                                              i64 body_len) {
    if (!c || c->fd < 0 || c->response_sent) return;
    const char* body = (const char*)(uintptr_t) body_ptr;
    size_t blen = (body_len > 0) ? (size_t) body_len : 0;
    const char* reason = amalgame_h1_reason_phrase(status);
    const char* conn_hdr = c->keep_alive ? "keep-alive" : "close";
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
        c->response_sent = 1; return;
    }
    if (headers_block && headers_block[0]) {
        if (amalgame_h1_send_all(c, headers_block, strlen(headers_block)) != 0) {
            c->response_sent = 1; return;
        }
    }
    if (amalgame_h1_send_all(c, "\r\n", 2) != 0) {
        c->response_sent = 1; return;
    }
    if (blen > 0) { amalgame_h1_send_all(c, body, blen); }
    c->response_sent = 1;
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

/* v0.15.0: serve a byte range [off, off+len) of a file with a caller
 * header block (Content-Range / ETag / Last-Modified / Accept-Ranges).
 * `status` is normally 206. `len <= 0` means "to end of file". Returns
 * 0 on success, -1 on file open/read error, -2 if the range is
 * unsatisfiable (off past EOF — caller should answer 416). */
static inline i64 Amalgame_Net_Http_H1Conn_RespondFileRange(AmalgameH1Conn* c,
        i64 status, code_string headers_block, code_string path,
        i64 off, i64 len) {
    if (!c || c->fd < 0 || c->response_sent || !path) return -1;
    FILE* f = fopen(path, "rb");
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return -1; }
    if (off < 0 || off >= (i64) sz) { fclose(f); return -2; }
    i64 maxlen = (i64) sz - off;
    i64 n = (len > 0 && len < maxlen) ? len : maxlen;
    if (fseek(f, (long) off, SEEK_SET) != 0) { fclose(f); return -1; }
    char* buf = (char*) GC_MALLOC_ATOMIC((size_t) n + 1);
    if (!buf) { fclose(f); return -1; }
    size_t got = fread(buf, 1, (size_t) n, f);
    fclose(f);
    if (got != (size_t) n) return -1;
    buf[got] = 0;
    const char* reason = amalgame_h1_reason_phrase(status);
    const char* conn_hdr = c->keep_alive ? "keep-alive" : "close";
    char start[256];
    int start_len = snprintf(start, sizeof(start),
        "HTTP/1.1 %lld %s\r\n"
        "Content-Length: %lld\r\n"
        "Connection: %s\r\n",
        (long long)status, reason, (long long) n, conn_hdr);
    if (start_len <= 0 || start_len >= (int)sizeof(start)) { c->response_sent = 1; return -1; }
    if (amalgame_h1_send_all(c, start, (size_t)start_len) != 0) { c->response_sent = 1; return -1; }
    if (headers_block && headers_block[0]) {
        if (amalgame_h1_send_all(c, headers_block, strlen(headers_block)) != 0) { c->response_sent = 1; return -1; }
    }
    if (amalgame_h1_send_all(c, "\r\n", 2) != 0) { c->response_sent = 1; return -1; }
    if (n > 0) { amalgame_h1_send_all(c, buf, (size_t) n); }
    c->response_sent = 1;
    return 0;
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

/* ── v0.14.0: response streaming primitives (SSE / long-poll) ───────
 * The normal model is parse → handler → return one HttpResponse →
 * close. That can't stream: Server-Sent Events / long-poll need the
 * handler to hold the connection and push frames over time. These let
 * an AM handler open an open-ended response and write until the peer
 * disconnects:
 *
 *   H1Conn_BeginStream(c, status, headers_block)
 *       Emit the status line + caller headers + end-of-headers blank
 *       line, with NO Content-Length. Framing is `Connection: close`
 *       (forced): the response ends when the server closes the socket.
 *       Sets response_sent (the dispatch loop won't double-respond)
 *       and keep_alive=0 (every keep-alive loop re-reads conn->keep_alive
 *       after the handler returns → breaks → closes). Returns 0 / -1.
 *
 *   H1Conn_WriteRaw(c, buf) / WriteRawBytes(c, ptr, len)
 *       Push a frame. 0 on success, -1 if the peer is gone (send_all →
 *       EPIPE; SIGPIPE already ignored). The AM SSE loop stops on -1.
 *
 *   H1Conn_Flush(c)
 *       No-op on the blocking path (send() already flushed); present
 *       for API symmetry and a future buffered/async hook.
 *
 * headers_block is the RespondFull shape: each line CRLF-terminated, NO
 * trailing blank line, and MUST NOT carry Content-Length or Connection
 * (managed here). NULL / "" is allowed. */
static inline i64 Amalgame_Net_Http_H1Conn_BeginStream(AmalgameH1Conn* c,
                                                        i64 status,
                                                        code_string headers_block) {
    if (!c || c->fd < 0 || c->response_sent) return -1;
    const char* reason = "OK";
    switch ((int)status) {
        case 200: reason = "OK"; break;
        case 201: reason = "Created"; break;
        case 202: reason = "Accepted"; break;
        /* streaming responses are virtually always 200 — keep it tiny */
    }
    c->keep_alive = 0;   /* stream ends on close → never reuse this conn */
    c->streaming  = 1;
    char start[256];
    int start_len = snprintf(start, sizeof(start),
        "HTTP/1.1 %lld %s\r\n"
        "Connection: close\r\n",
        (long long)status, reason);
    if (start_len <= 0 || start_len >= (int)sizeof(start)) {
        c->response_sent = 1;
        return -1;
    }
    if (amalgame_h1_send_all(c, start, (size_t)start_len) != 0) {
        c->response_sent = 1;
        return -1;
    }
    if (headers_block && headers_block[0]) {
        if (amalgame_h1_send_all(c, headers_block, strlen(headers_block)) != 0) {
            c->response_sent = 1;
            return -1;
        }
    }
    if (amalgame_h1_send_all(c, "\r\n", 2) != 0) {
        c->response_sent = 1;
        return -1;
    }
    c->response_sent = 1;
    return 0;
}

static inline i64 Amalgame_Net_Http_H1Conn_WriteRaw(AmalgameH1Conn* c,
                                                     code_string buf) {
    if (!c || c->fd < 0 || !buf) return -1;
    size_t n = strlen(buf);
    if (n == 0) return 0;
    return amalgame_h1_send_all(c, buf, n) == 0 ? 0 : -1;
}

static inline i64 Amalgame_Net_Http_H1Conn_WriteRawBytes(AmalgameH1Conn* c,
                                                          i64 ptr, i64 len) {
    if (!c || c->fd < 0) return -1;
    if (len <= 0) return 0;
    const char* p = (const char*)(uintptr_t) ptr;
    if (!p) return -1;
    return amalgame_h1_send_all(c, p, (size_t) len) == 0 ? 0 : -1;
}

static inline i64 Amalgame_Net_Http_H1Conn_Flush(AmalgameH1Conn* c) {
    (void) c;
    return 0;
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
    c->streaming     = 0;
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
    if (SSL_CTX_use_certificate_chain_file(ctx, cert_file) <= 0 ||
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

    /* v0.21.0: dual-stack (IPv6 + IPv4) listener; IPv4-only fallback. */
    int fd = amalgame_net_http_listen_dual(port, backlog);
    if (fd < 0) return s;
    s->fd = fd;

    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) { close(fd); s->fd = -1; return s; }
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    if (SSL_CTX_use_certificate_chain_file(ctx, cert_file) <= 0 ||
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
    struct sockaddr_storage addr; socklen_t alen = sizeof(addr);
    int cfd = accept(s->fd, (struct sockaddr*)&addr, &alen);
    if (cfd < 0) return NULL;
    /* Bound the TLS handshake with a recv/send timeout. SSL_accept runs
     * inline in the accept loop; without this a slow or malicious client
     * (port scanners that open a connection and send nothing, or the
     * "https proxy request" probes that hit :443) blocks SSL_accept
     * forever — and since it's reading the *client* socket, shutting down
     * the listen fd on SIGINT can't wake it, so the whole server hangs on
     * Ctrl-C. A 15 s ceiling makes the loop return to its IsStopping()
     * check and doubles as slowloris hardening. Cleared (0 = no timeout)
     * after a successful handshake so keep-alive reads aren't affected. */
    struct timeval hs_to; hs_to.tv_sec = 15; hs_to.tv_usec = 0;
    setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &hs_to, sizeof(hs_to));
    setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &hs_to, sizeof(hs_to));
    SSL* ssl = SSL_new(s->ssl_ctx);
    if (!ssl) { close(cfd); return NULL; }
    SSL_set_fd(ssl, cfd);
    int rv = SSL_accept(ssl);
    if (rv != 1) {
        /* Failed handshakes are ROUTINE on a public :443 — port scanners,
         * old/SSLv3 clients, plain-HTTP-to-HTTPS mistakes, slowloris cut at
         * the recv timeout. Logging each (with the OpenSSL error dump) just
         * spams stderr. Stay silent by default like nginx/apache; opt in to
         * the diagnostic via AMALGAME_TLS_DEBUG. Clear the error queue so a
         * stale entry can't leak into a later SSL op. */
        if (getenv("AMALGAME_TLS_DEBUG")) {
            int err = SSL_get_error(ssl, rv);
            fprintf(stderr, "Https.H1Serve: TLS handshake failed (SSL err %d)\n", err);
            ERR_print_errors_fp(stderr);
        }
        ERR_clear_error();
        SSL_free(ssl); close(cfd);
        return NULL;
    }
    const unsigned char* alpn = NULL; unsigned int alen2 = 0;
    SSL_get0_alpn_selected(ssl, &alpn, &alen2);
    if (alen2 != 0 && (alen2 != 8 || memcmp(alpn, "http/1.1", 8) != 0)) {
        if (getenv("AMALGAME_TLS_DEBUG")) {
            fprintf(stderr, "Https.H1Serve: client picked non-h1 ALPN\n");
        }
        ERR_clear_error();
        SSL_shutdown(ssl); SSL_free(ssl); close(cfd);
        return NULL;
    }
    /* Handshake done — clear the timeout so keep-alive idle waits aren't
     * cut short (ServeConnOn drives its own idle deadline). */
    struct timeval no_to; no_to.tv_sec = 0; no_to.tv_usec = 0;
    setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &no_to, sizeof(no_to));
    setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &no_to, sizeof(no_to));
    AmalgameH1Conn* c = (AmalgameH1Conn*) GC_MALLOC(sizeof(AmalgameH1Conn));
    memset(c, 0, sizeof(*c));
    c->fd  = cfd;
    c->ssl = ssl;
    /* v0.21.0: dual-stack peer; v4-mapped IPv6 normalized back to IPv4. */
    amalgame_net_http_peer_str(&addr, c->remote_addr, sizeof(c->remote_addr));
    return c;
}

/* Accept + parse the HTTP request in one call. HttpsH1Server_Accept only
 * does the TLS handshake (Https_H1Serve parses afterwards); a custom
 * accept loop in user code needs the request parsed too, or Method /
 * Path / Header(...) come back empty. Returns a conn with headers
 * populated, or NULL on handshake/parse failure or a closed listener.
 *
 * AM: public static AmalgameH1Conn* HttpsH1Server_AcceptParsed(server)
 */
static inline AmalgameH1Conn* Amalgame_Net_Http_HttpsH1Server_AcceptParsed(
        AmalgameHttpsH1Server* s) {
    AmalgameH1Conn* c = Amalgame_Net_Http_HttpsH1Server_Accept(s);
    if (!c) return NULL;
    if (amalgame_h1_parse_request(c) <= 0) {
        Amalgame_Net_Http_H1Conn_Close(c);
        return NULL;
    }
    return c;
}

/* HTTPS keep-alive: accept ONE TLS connection (handshake), then loop
 * parse→handler→ResetForReuse on the SAME connection while the client
 * keeps it open (HTTP/1.1 default unless Connection: close). One TLS
 * handshake serves every request of a page (page + favicon + assets),
 * instead of a fresh handshake per asset. `idle_timeout_sec` bounds the
 * wait for the next request (SO_RCVTIMEO on the fd → recv EAGAIN →
 * parse returns -1 → loop ends). Custom accept loops (e.g. a SNI multi-
 * site dispatcher) call this per accepted connection, ideally in a
 * worker thread so handshakes of distinct clients run in parallel.
 *
 * Returns 0 always (the per-connection lifecycle is fully handled:
 * handshake, request loop, close). Returns -1 only if the handshake
 * failed (nothing to serve).
 *
 * AM: public static int HttpsH1Server_ServeConn(server, handler, idleSec)
 */
static inline i64 Amalgame_Net_Http_HttpsH1Server_ServeConnOn(
        AmalgameH1Conn* conn, AmalgameClosure* handler, i64 idle_timeout_sec);

static inline i64 Amalgame_Net_Http_HttpsH1Server_ServeConn(
        AmalgameHttpsH1Server* s, AmalgameClosure* handler, i64 idle_timeout_sec) {
    if (!handler) return -1;
    AmalgameH1Conn* conn = Amalgame_Net_Http_HttpsH1Server_Accept(s);  /* TLS handshake */
    if (!conn) return -1;
    return Amalgame_Net_Http_HttpsH1Server_ServeConnOn(conn, handler, idle_timeout_sec);
}

/* Same keep-alive request loop as ServeConn, but on a connection the
 * caller has ALREADY accepted (TLS handshake done). Lets a custom loop
 * accept in the main thread (serial, cheap) and hand each conn to a
 * worker thread for the request loop — bounded concurrency, no
 * thread-spawn storm. Takes ownership of conn (closes it at the end).
 *
 * AM: public static int HttpsH1Server_ServeConnOn(conn, handler, idleSec)
 */
static inline i64 Amalgame_Net_Http_HttpsH1Server_ServeConnOn(
        AmalgameH1Conn* conn, AmalgameClosure* handler, i64 idle_timeout_sec) {
    if (!conn) return -1;
    if (!handler) { Amalgame_Net_Http_H1Conn_Close(conn); return -1; }
    int keep_alive_enabled = idle_timeout_sec > 0 ? 1 : 0;
    /* Bound the idle wait between requests. */
    if (keep_alive_enabled) {
        struct timeval tv;
        tv.tv_sec  = (time_t) idle_timeout_sec;
        tv.tv_usec = 0;
        setsockopt(conn->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }
    while (1) {
        int parsed = amalgame_h1_parse_request(conn);
        if (parsed <= 0) break;
        conn->keep_alive = keep_alive_enabled ? amalgame_h1_request_keep_alive(conn) : 0;
        AmalgameClosure_call1(handler, (void*) conn);
        if (!conn->keep_alive) break;
        Amalgame_Net_Http_H1Conn_ResetForReuse(conn);
    }
    Amalgame_Net_Http_H1Conn_Close(conn);
    return 0;
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
    amalgame_net_http_conn_release();
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
        /* Connection cap: reject (close) when at capacity. */
        if (!amalgame_net_http_conn_admit()) {
            Amalgame_Net_Http_H1Conn_Close(conn);
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

        struct sockaddr_storage addr;
        socklen_t alen = sizeof(addr);
        /* accept4 needs _GNU_SOURCE; we plain-accept + fcntl-after
         * so the build doesn't depend on per-file feature macros.
         * The two syscalls are cheap; the bench cost is in the
         * handler, not in the accept setup. */
        int cfd = accept(ctx->srv->fd, (struct sockaddr*)&addr, &alen);
        if (cfd >= 0) {
#ifdef _WIN32
            /* ioctlsocket(FIONBIO) is the Winsock non-blocking switch;
             * there's no CLOEXEC concept (no fork+exec). */
            amsock_set_nonblock(cfd);
#else
            int fl = fcntl(cfd, F_GETFL, 0);
            if (fl >= 0) fcntl(cfd, F_SETFL, fl | O_NONBLOCK);
            /* Best-effort O_CLOEXEC — descriptors leaking into
             * accidental fork+exec is a portability nit, not a
             * correctness bug. */
            int fdfl = fcntl(cfd, F_GETFD, 0);
            if (fdfl >= 0) fcntl(cfd, F_SETFD, fdfl | FD_CLOEXEC);
#endif
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
        /* v0.21.0: dual-stack peer; v4-mapped IPv6 normalized to IPv4. */
        amalgame_net_http_peer_str(&addr, c->remote_addr, sizeof(c->remote_addr));

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
    amalgame_net_http_conn_release();
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
        /* Connection cap: reject (close) when at capacity. */
        if (!amalgame_net_http_conn_admit()) {
            Amalgame_Net_Http_H1Conn_Close(conn);
            continue;
        }
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
    amalgame_net_http_conn_release();
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
        /* Connection cap: reject (close) when at capacity. */
        if (!amalgame_net_http_conn_admit()) {
            Amalgame_Net_Http_H1Conn_Close(conn);
            continue;
        }
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
    SSL*      ssl;            /* non-NULL on the wss:// path (v0.4.1+) */
    char      subprotocol[128]; /* v0.17.0: negotiated Sec-WebSocket-Protocol, "" if none */
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
/* v0.17.0: pick the first client-offered subprotocol that the server
 * supports. Both args are comma-separated, case-insensitive token
 * lists. Writes the match into `out` and returns 1; 0 if none. */
static inline int amalgame_ws_pick_subprotocol(const char* offered,
        const char* server_csv, char* out, size_t outsz) {
    if (!offered || !offered[0] || !server_csv || !server_csv[0]) return 0;
    const char* o = offered;
    while (*o) {
        while (*o == ' ' || *o == ',' || *o == '\t') o++;
        const char* start = o;
        while (*o && *o != ',') o++;
        const char* end = o;
        while (end > start && (end[-1] == ' ' || end[-1] == '\t')) end--;
        size_t tlen = (size_t)(end - start);
        if (tlen > 0) {
            const char* s = server_csv;
            while (*s) {
                while (*s == ' ' || *s == ',' || *s == '\t') s++;
                const char* ss = s;
                while (*s && *s != ',') s++;
                const char* se = s;
                while (se > ss && (se[-1] == ' ' || se[-1] == '\t')) se--;
                size_t slen = (size_t)(se - ss);
                if (slen == tlen && strncasecmp(start, ss, tlen) == 0) {
                    if (tlen >= outsz) tlen = outsz - 1;
                    memcpy(out, start, tlen);
                    out[tlen] = 0;
                    return 1;
                }
            }
        }
    }
    return 0;
}

/* Upgrade with optional server subprotocol set (CSV). When the client
 * offers a Sec-WebSocket-Protocol the server supports, the first match
 * is echoed in the 101 and stored on the conn; otherwise the header is
 * omitted (RFC 6455 — do NOT fail the handshake). */
/* Exact-match origin allow-list check (case-insensitive). Returns 1 iff
 * `origin` equals one of the comma-separated entries in `csv` (surrounding
 * spaces ignored). An empty/absent Origin never matches a non-empty list.
 * Used to defend the WebSocket handshake against Cross-Site WebSocket
 * Hijacking — browsers always send a truthful Origin a cross-site page
 * cannot forge. */
static inline int amalgame_ws_origin_allowed(const char* origin, const char* csv) {
    if (!origin || !origin[0] || !csv) return 0;
    size_t olen = strlen(origin);
    const char* p = csv;
    while (*p) {
        while (*p == ' ' || *p == ',') p++;
        const char* start = p;
        while (*p && *p != ',') p++;
        int len = (int)(p - start);
        while (len > 0 && start[len - 1] == ' ') len--;
        if (len > 0 && (size_t)len == olen &&
            strncasecmp(origin, start, (size_t)len) == 0) {
            return 1;
        }
    }
    return 0;
}

static inline AmalgameWsConn* amalgame_ws_do_upgrade_ex(int cfd, SSL* ssl,
        const char* server_protos, const char* allowed_origins) {
    char key[256] = {0};
    char offered[256] = {0};
    char origin[256] = {0};
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
        } else if (strncasecmp(line, "Sec-WebSocket-Protocol:", 23) == 0) {
            const char* v = line + 23;
            while (*v == ' ' || *v == '\t') v++;
            strncpy(offered, v, sizeof(offered) - 1);
        } else if (strncasecmp(line, "Origin:", 7) == 0) {
            const char* v = line + 7;
            while (*v == ' ' || *v == '\t') v++;
            strncpy(origin, v, sizeof(origin) - 1);
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

    /* Origin allow-list (anti Cross-Site WebSocket Hijacking). Only
     * enforced when the caller configured a non-empty list. The browser
     * sends a truthful Origin that a malicious cross-site page cannot
     * forge, so an off-list (or absent) Origin → 403, no upgrade. */
    if (allowed_origins && allowed_origins[0] &&
        !amalgame_ws_origin_allowed(origin, allowed_origins)) {
        const char* forbidden = "HTTP/1.1 403 Forbidden\r\n"
                                "Content-Length: 0\r\nConnection: close\r\n\r\n";
        amalgame_ws_write_full(cfd, ssl, forbidden, strlen(forbidden));
        goto fail;
    }

    char accept_b64[40];
    int alen2 = amalgame_ws_compute_accept(key, strlen(key),
                                            accept_b64, sizeof(accept_b64));
    if (alen2 < 0) goto fail;

    char chosen[128] = {0};
    int have_proto = 0;
    if (server_protos && server_protos[0] && offered[0]) {
        have_proto = amalgame_ws_pick_subprotocol(offered, server_protos,
                                                   chosen, sizeof(chosen));
    }

    char resp[640];
    int rlen;
    if (have_proto) {
        rlen = snprintf(resp, sizeof(resp),
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\nConnection: Upgrade\r\n"
            "Sec-WebSocket-Accept: %s\r\n"
            "Sec-WebSocket-Protocol: %s\r\n\r\n", accept_b64, chosen);
    } else {
        rlen = snprintf(resp, sizeof(resp),
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\nConnection: Upgrade\r\n"
            "Sec-WebSocket-Accept: %s\r\n\r\n", accept_b64);
    }
    if (amalgame_ws_write_full(cfd, ssl, resp, rlen) < 0) goto fail;

    AmalgameWsConn* c = (AmalgameWsConn*)GC_MALLOC(sizeof(*c));
    c->fd = cfd; c->closed = 0; c->ssl = ssl; c->subprotocol[0] = 0;
    if (have_proto) { strncpy(c->subprotocol, chosen, sizeof(c->subprotocol) - 1); }
    return c;

fail:
    if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
    close(cfd);
    return NULL;
}

/* Legacy entry — no subprotocol negotiation, no origin restriction. */
static inline AmalgameWsConn* amalgame_ws_do_upgrade(int cfd, SSL* ssl) {
    return amalgame_ws_do_upgrade_ex(cfd, ssl, NULL, NULL);
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

/* v0.17.0: negotiated WebSocket subprotocol ("" if none). */
static inline code_string Amalgame_Net_Http_WsConn_Subprotocol(
        AmalgameWsConn* c) {
    return (c && c->subprotocol[0]) ? (code_string) c->subprotocol : "";
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

/* v0.17.0: Ws.ServeWithProtocols(port, csv, handler) — single-thread
 * WebSocket with subprotocol negotiation. `protocols` is a CSV of the
 * subprotocols the server supports; the handshake echoes the first the
 * client offers (read back via WsConn.Subprotocol). Delegates to
 * Ws.Serve semantics otherwise. */
static inline i64 Amalgame_Net_Http_Ws_ServeWithProtocols(i64 port,
        code_string protocols, AmalgameClosure* handler) {
    if (!handler) {
        fprintf(stderr, "Ws.ServeWithProtocols: handler is NULL\n");
        return -1;
    }
    AmalgameWsServer* srv = Amalgame_Net_Http_WsServer_Listen(port, 0);
    if (!srv || !srv->listening) {
        fprintf(stderr, "Ws.ServeWithProtocols: failed to listen on :%lld (%s)\n",
                (long long)port, strerror(errno));
        return -2;
    }
    fprintf(stdout, "Ws.ServeWithProtocols: listening on :%lld (WebSocket)\n",
            (long long)port);
    fflush(stdout);
    while (srv->listening && !amalgame_net_http_stopping) {
        struct sockaddr_in addr; socklen_t alen = sizeof(addr);
        int cfd = accept(srv->fd, (struct sockaddr*)&addr, &alen);
        if (cfd < 0) continue;
        AmalgameWsConn* conn = amalgame_ws_do_upgrade_ex(cfd, NULL, protocols, NULL);
        if (!conn) continue;
        AmalgameClosure_call1(handler, (void*)conn);
        Amalgame_Net_Http_WsConn_Close(conn);
    }
    Amalgame_Net_Http_WsServer_Close(srv);
    return 0;
}

/* v0.18.0: Ws.ServeWithOrigins(port, csv, handler) — single-thread
 * WebSocket that rejects (403) any handshake whose Origin header is not in
 * the comma-separated allow-list. Defense against Cross-Site WebSocket
 * Hijacking (CSWSH): unlike fetch/XHR, the WS handshake is not gated by
 * the browser's CORS check, so a cross-site page can open a socket to an
 * authenticated endpoint — but it cannot forge the Origin the browser
 * stamps, which this list verifies. Pass exact origins
 * ("https://app.example.com,https://admin.example.com"). */
static inline i64 Amalgame_Net_Http_Ws_ServeWithOrigins(i64 port,
        code_string origins, AmalgameClosure* handler) {
    if (!handler) {
        fprintf(stderr, "Ws.ServeWithOrigins: handler is NULL\n");
        return -1;
    }
    AmalgameWsServer* srv = Amalgame_Net_Http_WsServer_Listen(port, 0);
    if (!srv || !srv->listening) {
        fprintf(stderr, "Ws.ServeWithOrigins: failed to listen on :%lld (%s)\n",
                (long long)port, strerror(errno));
        return -2;
    }
    fprintf(stdout, "Ws.ServeWithOrigins: listening on :%lld (WebSocket)\n",
            (long long)port);
    fflush(stdout);
    while (srv->listening && !amalgame_net_http_stopping) {
        struct sockaddr_in addr; socklen_t alen = sizeof(addr);
        int cfd = accept(srv->fd, (struct sockaddr*)&addr, &alen);
        if (cfd < 0) continue;
        AmalgameWsConn* conn = amalgame_ws_do_upgrade_ex(cfd, NULL, NULL, origins);
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
    if (SSL_CTX_use_certificate_chain_file(ctx, cert_file) <= 0 ||
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
