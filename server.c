/* server.c - single-threaded select-based HTTPS server using ossl.h
 *
 * Architecture:
 *   - Non-blocking listening socket
 *   - select() on listen_fd + all active client fds (read-ready only)
 *   - SSL_accept blocks internally (poll) — handshake is fast (< 200ms)
 *   - SSL_read / SSL_write are non-blocking — multiplexed via select()
 *   - Uses SSL_get_error() to distinguish WANT_READ from real errors
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include "ossl.h"

static volatile int keep_running = 1;

static void srv_signal_handler(int sig) {
    (void)sig;
    keep_running = 0;
}

static int srv_setup_signals(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = srv_signal_handler;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGINT,  &sa, NULL) != 0) return -1;
    if (sigaction(SIGTERM, &sa, NULL) != 0) return -1;
    signal(SIGPIPE, SIG_IGN);
    return 0;
}

enum {
    CONN_FREE = 0,
    CONN_ACCEPTING,   /* SSL_accept in progress (not used — handshake is blocking) */
    CONN_READING,     /* waiting for HTTP request */
    CONN_WRITING,     /* sending HTTP response */
    CONN_CLOSING      /* SSL_shutdown done, fd to be closed */
};

#define MAX_CONN 256

typedef struct {
    int fd;
    SSL *ssl;
    int state;
    char rbuf[8192];
    int  rlen;
    char wbuf[4096];
    int  wlen;
    int  woff;
} conn_t;

static conn_t conns[MAX_CONN];

static int conn_add(int fd, SSL *ssl) {
    for (int i = 0; i < MAX_CONN; i++) {
        if (conns[i].state == CONN_FREE) {
            conns[i].fd    = fd;
            conns[i].ssl   = ssl;
            conns[i].state = CONN_READING;
            conns[i].rlen  = 0;
            conns[i].wlen  = 0;
            conns[i].woff  = 0;
            return 0;
        }
    }
    return -1; /* too many connections */
}

static void conn_remove(int idx) {
    SSL_shutdown(conns[idx].ssl);
    SSL_free(conns[idx].ssl);
    close(conns[idx].fd);
    memset(&conns[idx], 0, sizeof(conn_t));
}

/* Try to read an HTTP request line. Returns 1 when ready to respond. */
static int conn_try_read(conn_t *c) {
    while (c->rlen < (int)sizeof(c->rbuf) - 1) {
        int n = SSL_read(c->ssl, c->rbuf + c->rlen, 1);
        if (n <= 0) {
            int err = SSL_get_error(c->ssl, n);
            if (err == SSL_ERROR_WANT_READ) return 0; /* try again later */
            return -1; /* error or EOF */
        }
        if (c->rbuf[c->rlen] == '\n') {
            /* Found end of request line */
            if (c->rlen > 0 && c->rbuf[c->rlen-1] == '\r')
                c->rbuf[c->rlen-1] = '\0';
            else
                c->rbuf[c->rlen] = '\0';
            return 1;
        }
        c->rlen++;
    }
    return -1; /* line too long */
}

/* Skip remaining HTTP headers. Returns 1 when headers end. */
static int conn_skip_headers(conn_t *c) {
    char prev = 0;
    for (;;) {
        char ch;
        int n = SSL_read(c->ssl, &ch, 1);
        if (n <= 0) {
            int err = SSL_get_error(c->ssl, n);
            if (err == SSL_ERROR_WANT_READ) return 0;
            return -1;
        }
        if (ch == '\n') {
            if (prev == '\n' || (prev == '\r')) return 1; /* empty line */
        }
        prev = ch;
    }
}

/* Build the HTTP response */
static void conn_build_response(conn_t *c) {
    const char *body = "Hello, World!";
    int body_len = (int)strlen(body);
    c->wlen = snprintf(c->wbuf, sizeof(c->wbuf),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        body_len, body);
    c->woff = 0;
    c->state = CONN_WRITING;
}

int main(int argc, char *argv[]) {
    int port = 8443;
    if (argc >= 2) {
        port = atoi(argv[1]);
        if (port <= 0 || port > 65535) {
            fprintf(stderr, "Invalid port: %s\n", argv[1]);
            return 1;
        }
    }

    if (srv_setup_signals() != 0) {
        fprintf(stderr, "Failed to setup signals\n");
        return 1;
    }

    /* Create non-blocking listening socket */
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) { perror("socket"); return 1; }
    fcntl(listen_fd, F_SETFL, fcntl(listen_fd, F_GETFL, 0) | O_NONBLOCK);

    { int opt = 1; setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)); }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((unsigned short)port);

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("bind"); close(listen_fd); return 1;
    }
    if (listen(listen_fd, SOMAXCONN) != 0) {
        perror("listen"); close(listen_fd); return 1;
    }

    /* Pre-load SSL context (shared across connections) */
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) { fprintf(stderr, "SSL_CTX_new failed\n"); close(listen_fd); return 1; }
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "Failed to load cert/key\n");
        SSL_CTX_free(ctx); close(listen_fd); return 1;
    }

    printf("HTTPS server listening on port %d (single-threaded select)\n", port);
    printf("Test with: ./test https://localhost:%d/\n", port);

    /* --- Main event loop --- */
    while (keep_running) {
        fd_set rfds, wfds;
        FD_ZERO(&rfds);
        FD_ZERO(&wfds);
        FD_SET(listen_fd, &rfds);
        int maxfd = listen_fd;

        for (int i = 0; i < MAX_CONN; i++) {
            if (conns[i].state == CONN_FREE || conns[i].state == CONN_CLOSING)
                continue;
            if (conns[i].state == CONN_READING)
                FD_SET(conns[i].fd, &rfds);
            else if (conns[i].state == CONN_WRITING)
                FD_SET(conns[i].fd, &wfds);
            if (conns[i].fd > maxfd) maxfd = conns[i].fd;
        }

        struct timeval tv;
        tv.tv_sec  = 1;
        tv.tv_usec = 0;

        int r = select(maxfd + 1, &rfds, &wfds, NULL, &tv);
        if (r < 0) {
            if (errno == EINTR) continue;
            perror("select"); break;
        }
        if (r == 0) { /* timeout */ continue; }

        /* New connections */
        if (FD_ISSET(listen_fd, &rfds)) {
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            int fd = accept(listen_fd, (struct sockaddr *)&client_addr, &client_len);
            if (fd >= 0) {
                fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
                SSL *ssl = SSL_new(ctx);
                if (!ssl) { close(fd); continue; }
                SSL_set_fd(ssl, fd);

                /* Handshake — blocking via internal poll() */
                if (SSL_accept(ssl) != 1) {
                    fprintf(stderr, "SSL_accept failed\n");
                    SSL_free(ssl); close(fd);
                    continue;
                }
                printf("Accepted connection (fd=%d)\n", fd);
                if (conn_add(fd, ssl) != 0) {
                    fprintf(stderr, "Too many connections\n");
                    SSL_shutdown(ssl); SSL_free(ssl); close(fd);
                }
            }
        }

        /* Existing connections */
        for (int i = 0; i < MAX_CONN; i++) {
            if (conns[i].state == CONN_FREE || conns[i].state == CONN_CLOSING)
                continue;

            if (conns[i].state == CONN_READING && FD_ISSET(conns[i].fd, &rfds)) {
                if (!conns[i].rlen) {
                    /* First read — get the request line */
                    int ret = conn_try_read(&conns[i]);
                    if (ret < 0) { conn_remove(i); continue; }
                    if (ret == 0) continue; /* WANT_READ — try again later */
                    /* Got request line — now skip headers */
                    conns[i].rlen = 9999; /* marker: reading headers */
                }

                if (conns[i].rlen == 9999) {
                    int ret = conn_skip_headers(&conns[i]);
                    if (ret < 0) { conn_remove(i); continue; }
                    if (ret == 0) continue;
                    /* Headers done — build and send response */
                    printf("Request: %s\n", conns[i].rbuf);
                    conn_build_response(&conns[i]);
                    /* Fall through to writing */
                }
            }

            if (conns[i].state == CONN_WRITING && FD_ISSET(conns[i].fd, &wfds)) {
                int n = SSL_write(conns[i].ssl,
                                  conns[i].wbuf + conns[i].woff,
                                  conns[i].wlen - conns[i].woff);
                if (n <= 0) {
                    int err = SSL_get_error(conns[i].ssl, n);
                    if (err == SSL_ERROR_WANT_WRITE) continue;
                    conn_remove(i);
                    continue;
                }
                conns[i].woff += n;
                if (conns[i].woff >= conns[i].wlen) {
                    printf("Response sent (%d bytes)\n", conns[i].wlen);
                    conn_remove(i);
                }
            }
        }
    }

    printf("\nShutting down...\n");

    /* Cleanup */
    for (int i = 0; i < MAX_CONN; i++)
        if (conns[i].state != CONN_FREE)
            conn_remove(i);

    close(listen_fd);
    SSL_CTX_free(ctx);
    return 0;
}