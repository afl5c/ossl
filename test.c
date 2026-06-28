/* test.c - uses ossl.h to make HTTP/HTTPS requests to argv[1] */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib,"ws2_32.lib")
typedef SOCKET test_sock_t;
#define TEST_INVALID_SOCKET INVALID_SOCKET
#define TEST_CLOSE_SOCKET(s) closesocket(s)
#define TEST_READ(fd,buf,len) recv((fd),(char*)(buf),(len),0)
#define TEST_WRITE(fd,buf,len) send((fd),(const char*)(buf),(len),0)
#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
typedef int test_sock_t;
#define TEST_INVALID_SOCKET (-1)
#define TEST_CLOSE_SOCKET(s) close(s)
#define TEST_READ(fd,buf,len) read((fd),(buf),(len))
#define TEST_WRITE(fd,buf,len) write((fd),(buf),(len))
#endif
#include "ossl.h"

static int test_init(void) {
#ifdef _WIN32
    WSADATA w;
    return WSAStartup(MAKEWORD(2,2), &w) ? -1 : 0;
#else
    return 0;
#endif
}

static void test_cleanup(void) {
#ifdef _WIN32
    WSACleanup();
#endif
}

/* Extract scheme, host, port, path from a URL. Returns 0 on success. */
static int parse_url(const char *url, char **scheme, char **host, int *port, char **path) {
    const char *p = url;
    const char *scheme_end = NULL;
    const char *host_start = NULL;
    const char *port_start = NULL;

    /* Find scheme */
    if (strncmp(p, "http://", 7) == 0) {
        *scheme = strdup("http");
        *port = 80;
        scheme_end = p + 7;
    } else if (strncmp(p, "https://", 8) == 0) {
        *scheme = strdup("https");
        *port = 443;
        scheme_end = p + 8;
    } else {
        /* Default to http */
        *scheme = strdup("http");
        *port = 80;
        scheme_end = p;
    }
    if (!*scheme) return -1;

    host_start = scheme_end;

    /* Find end of host part (next '/' or ':' or end) */
    const char *h_end = host_start;
    while (*h_end && *h_end != '/' && *h_end != ':') h_end++;
    const char *host_end = h_end; /* save before port parsing moves h_end */

    /* Check for port */
    if (*h_end == ':') {
        port_start = h_end + 1;
        const char *p_end = port_start;
        while (*p_end && *p_end >= '0' && *p_end <= '9') p_end++;
        if (p_end > port_start) {
            char port_str[16];
            size_t len = (size_t)(p_end - port_start);
            if (len >= sizeof(port_str)) len = sizeof(port_str) - 1;
            memcpy(port_str, port_start, len);
            port_str[len] = '\0';
            *port = atoi(port_str);
        }
        h_end = p_end;
    }

    size_t host_len = (size_t)(host_end - host_start);
    *host = (char*)malloc(host_len + 1);
    if (!*host) { free(*scheme); return -1; }
    memcpy(*host, host_start, host_len);
    (*host)[host_len] = '\0';

    /* Path */
    if (*h_end == '/') {
        *path = strdup(h_end);
    } else {
        *path = strdup("/");
    }
    if (!*path) { free(*scheme); free(*host); return -1; }

    return 0;
}

/* Send all data from buffer */
static int send_all(test_sock_t fd, const void *buf, size_t len) {
    const char *p = (const char*)buf;
    while (len > 0) {
        int n = (int)TEST_WRITE(fd, p, len);
        if (n <= 0) return -1;
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

/* Read data until connection close (or until we have something). Returns bytes read. */
static int recv_until_close(test_sock_t fd, void *buf, size_t bufsize) {
    size_t total = 0;
    while (total < bufsize) {
        int n = (int)TEST_READ(fd, (char*)buf + total, bufsize - total);
        if (n <= 0) break;
        total += (size_t)n;
    }
    return (int)total;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <url>\n", argv[0]);
        return 1;
    }

    if (test_init() != 0) {
        fprintf(stderr, "Failed to initialize network\n");
        return 1;
    }

    const char *url = argv[1];
    char *scheme = NULL, *host = NULL, *path = NULL;
    int port;

    if (parse_url(url, &scheme, &host, &port, &path) != 0) {
        fprintf(stderr, "Failed to parse URL\n");
        test_cleanup();
        return 1;
    }

    int use_ssl = (strcmp(scheme, "https") == 0);

    /* Resolve hostname */
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int gai_err = getaddrinfo(host, port_str, &hints, &res);
    if (gai_err != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(gai_err));
        free(scheme); free(host); free(path);
        test_cleanup();
        return 1;
    }

    /* Create socket and connect */
    test_sock_t fd = TEST_INVALID_SOCKET;
    struct addrinfo *rp;
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd == TEST_INVALID_SOCKET) continue;
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0)
            break;
        TEST_CLOSE_SOCKET(fd);
        fd = TEST_INVALID_SOCKET;
    }
    freeaddrinfo(res);

    if (fd == TEST_INVALID_SOCKET) {
        fprintf(stderr, "Failed to connect to %s:%d\n", host, port);
        free(scheme); free(host); free(path);
        test_cleanup();
        return 1;
    }

    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;

    if (use_ssl) {
        ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) {
            fprintf(stderr, "SSL_CTX_new failed\n");
            TEST_CLOSE_SOCKET(fd);
            free(scheme); free(host); free(path);
            test_cleanup();
            return 1;
        }
        SSL_CTX_set_default_verify_paths(ctx);
        ssl = SSL_new(ctx);
        if (!ssl) {
            fprintf(stderr, "SSL_new failed\n");
            SSL_CTX_free(ctx);
            TEST_CLOSE_SOCKET(fd);
            free(scheme); free(host); free(path);
            test_cleanup();
            return 1;
        }
        SSL_set_fd(ssl, (int)fd);
        /* Set SNI */
        SSL_set_tlsext_host_name(ssl, host);
        if (SSL_connect(ssl) != 1) {
            fprintf(stderr, "SSL_connect failed\n");
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            TEST_CLOSE_SOCKET(fd);
            free(scheme); free(host); free(path);
            test_cleanup();
            return 1;
        }
        /* Validate and print root CA */
        X509* cert = SSL_get_peer_certificate(ssl);
        if (cert) {
            long verify_result = SSL_get_verify_result(ssl);

            if (verify_result == X509_V_OK) {
                STACK_OF(X509)* chain = SSL_get_peer_cert_chain(ssl);
                if (chain && sk_X509_num(chain) > 0) {
                    X509* root = sk_X509_value(chain, sk_X509_num(chain) - 1);

                    if (root) {
                        BIO* mem = BIO_new(BIO_s_mem());
                        if (mem) {
                            X509_NAME_print_ex(mem, X509_get_subject_name(root), 0, XN_FLAG_ONELINE);

                            char* data = NULL;
                            long len = BIO_get_mem_data(mem, &data);

                            if (data && len > 0) {
                                printf("Root CA Subject: %.*s\n", (int)len, data);
                            }

                            BIO_free(mem);
                        }
                    }
                } else {
                    printf("Valid (but could not extract root CA)\n");
                }
            } else {
                printf("Invalid\n");
            }

            X509_free(cert);
        } else {
            printf("Invalid (no peer certificate)\n");
        }
    }

    /* Build HTTP GET request */
    char request[4096];
    int reqlen = snprintf(request, sizeof(request),
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Connection: close\r\n"
        "\r\n",
        path, host);

    if (use_ssl) {
        if (SSL_write(ssl, request, reqlen) <= 0) {
            fprintf(stderr, "SSL_write failed\n");
            if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
            if (ctx) SSL_CTX_free(ctx);
            TEST_CLOSE_SOCKET(fd);
            free(scheme); free(host); free(path);
            test_cleanup();
            return 1;
        }
    } else {
        if (send_all(fd, request, (size_t)reqlen) != 0) {
            fprintf(stderr, "send_all failed\n");
            TEST_CLOSE_SOCKET(fd);
            free(scheme); free(host); free(path);
            test_cleanup();
            return 1;
        }
    }

    /* Read response — stream in 4096-byte chunks to stdout */
    char buf[4096];
    int total_read = 0;
    int n;
    if (use_ssl) {
        while ((n = SSL_read(ssl, buf, (int)sizeof(buf))) > 0) {
            fwrite(buf, 1, (size_t)n, stdout);
            total_read += n;
        }
    } else {
        n = recv_until_close(fd, buf, sizeof(buf));
        if (n > 0) { fwrite(buf, 1, (size_t)n, stdout); total_read = n; }
    }

    if (total_read == 0) {
        fprintf(stderr, "No response received\n");
    }

    /* Cleanup */
    if (use_ssl) {
        if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
        if (ctx) SSL_CTX_free(ctx);
    }
    TEST_CLOSE_SOCKET(fd);
    free(scheme); free(host); free(path);
    test_cleanup();

    return 0;
}
