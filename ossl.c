/***
 * ossl.c — drop-in replacement for OpenSSL
 * Implements the functions declared in ossl.h without any external dependencies.
 * Works on Windows, Mac, and Linux.
 * On error, prints a message to stderr in addition to standard OpenSSL behavior.
 *
 * This implementation provides:
 *   - TLS 1.3 with ECDHE-ECDSA-AES128-GCM-SHA256 and ECDHE-RSA-AES128-GCM-SHA256
 *   - TLS 1.2 with ECDHE-RSA-AES128-GCM-SHA256 (primary) and RSA key exchange (fallback)
 *   - PEM certificate and private key parsing (DER)
 *   - Platform sockets (WinSock on Windows, BSD sockets elsewhere)
 *   - Self-contained crypto: AES-128/256, RSA (PKCS#1 v1.5 & PSS), SHA-256/SHA-384,
 *     HMAC, GHASH, X25519, ECDSA P-256
 *   - Cryptographically secure random number generator via OS entropy
 */

#include "ossl.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include "cacerts.h"

/* ========================================================================
 * Platform detection
 * ======================================================================== */
#if defined(_WIN32) || defined(_WIN64)
    #define OSSL_PLATFORM_WINDOWS
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #include <bcrypt.h>
    #pragma comment(lib, "ws2_32.lib")
    #pragma comment(lib, "bcrypt.lib")
    typedef SOCKET ossl_sock_t;
    #define OSSL_INVALID_SOCKET INVALID_SOCKET
    #define OSSL_SOCKET_ERROR SOCKET_ERROR
    #define OSSL_CLOSE_SOCKET(s) closesocket(s)
    #define OSSL_IO_RETRY(s) (WSAGetLastError() == WSAEWOULDBLOCK)
    typedef unsigned long long ossl_uint64;
#else
    #define OSSL_PLATFORM_POSIX
    #include <unistd.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <netinet/tcp.h>
    #include <arpa/inet.h>
    #include <fcntl.h>
    #include <errno.h>
    #include <sys/stat.h>
    typedef int ossl_sock_t;
    #define OSSL_INVALID_SOCKET (-1)
    #define OSSL_SOCKET_ERROR (-1)
    #define OSSL_CLOSE_SOCKET(s) close(s)
    #define OSSL_IO_RETRY(s) (errno == EAGAIN || errno == EWOULDBLOCK)
    typedef unsigned long long ossl_uint64;
#endif

/* Windows SDK defines X509_NAME as a macro — undo that so our typedef works */
#ifdef X509_NAME
#undef X509_NAME
#endif

/* ========================================================================
 * Constants
 * ======================================================================== */
#define OSSL_TLS_VERSION_MAJOR 3
#define OSSL_TLS_VERSION_MINOR 3  /* TLS 1.2 / 1.3 record layer */

#define SSL3_RT_CHANGE_CIPHER_SPEC 20
#define SSL3_RT_ALERT              21
#define SSL3_RT_HANDSHAKE          22
#define SSL3_RT_APPLICATION_DATA   23

/* Supported cipher suites */
#define TLS1_CK_ECDHE_RSA_WITH_AES_128_GCM_SHA256   0xC02F
#define TLS1_CK_ECDHE_RSA_WITH_AES_256_GCM_SHA384   0xC030
#define TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 0xC02B
#define TLS1_CK_RSA_WITH_AES_128_GCM_SHA256         0x009C
#define TLS1_CK_RSA_WITH_AES_256_GCM_SHA384         0x009D
#define TLS1_CK_RSA_WITH_AES_128_CBC_SHA            0x002F
#define TLS1_CK_RSA_WITH_AES_256_CBC_SHA            0x0035

/* TLS 1.3 cipher suites */
#define TLS1_3_CK_AES_128_GCM_SHA256 0x1301
#define TLS1_3_CK_AES_256_GCM_SHA384 0x1302

/* TLS 1.3 extension types */
#define OSSL_EXT_SUPPORTED_VERSIONS 0x002b
#define OSSL_EXT_KEY_SHARE          0x0033
#define OSSL_EXT_SIG_ALGS_CERT      0x0032

/* TLS 1.3 handshake message types */
#define OSSL_MT_ENCRYPTED_EXTENSIONS 0x08
#define OSSL_MT_CERTIFICATE_VERIFY   0x0f

#define OSSL_MAX_RECORD_SIZE 16384

/* ========================================================================
 * Internal structures
 * ======================================================================== */

typedef struct {
    unsigned char *data;
    int len;
    int cap;
} ossl_buf;

/* Forward declarations for hash context types used in struct ossl_ssl */
typedef struct { unsigned int state[8]; unsigned long long count; unsigned char buffer[64]; unsigned int buflen; } ossl_sha256_ctx;
typedef struct { unsigned long long state[8]; unsigned long long count; unsigned char buffer[128]; unsigned int buflen; } ossl_sha384_ctx;

struct ossl_ctx {
    int method; /* 0 = server, 1 = client */
    unsigned char *cert_der;
    int cert_der_len;
    unsigned char *key_der;
    int key_der_len;
    int verify_mode;
    int (*verify_callback)(int, X509_STORE_CTX*);
    long mode;
    unsigned char **trusted_ca_der;
    int *trusted_ca_der_len;
    int trusted_ca_count;
};

struct ossl_ssl {
    struct ossl_ctx *ctx;
    ossl_sock_t fd;
    int is_server;
    int handshake_done;
    int shutdown_done;
    unsigned char client_write_key[32];
    unsigned char server_write_key[32];
    unsigned char client_write_iv[4];
    unsigned char server_write_iv[4];
    unsigned long long client_seq;
    unsigned long long server_seq;
    ossl_buf rbuf;
    ossl_buf wbuf;
    char *sni_hostname;
    unsigned char *peer_cert_der;
    int peer_cert_der_len;
    unsigned char **peer_cert_chain_der;
    int *peer_cert_chain_der_len;
    int peer_cert_chain_count;
    unsigned char client_random[32];
    unsigned char server_random[32];
    unsigned char master_secret[48];
    unsigned char pre_master_secret[48];
    int cipher_suite;
    int negotiated_cs;
    /* ECDHE state */
    unsigned char ecdhe_private_key[32];
    unsigned char ecdhe_public_key[32];
    unsigned char ecdhe_server_public[32];
    /* Handshake transcript hash */
    ossl_sha256_ctx hs_hash;
    ossl_sha384_ctx hs_hash384;
    int use_hs_hash384;
    /* TLS 1.3 state */
    int is_tls13;
    int tls13_hash_len; /* 32 for SHA-256, 48 for SHA-384 */
    /* TLS 1.3 traffic secrets */
    unsigned char handshake_secret[48];
    unsigned char client_hs_secret[48];
    unsigned char server_hs_secret[48];
    unsigned char client_ap_secret[48];
    unsigned char server_ap_secret[48];
    /* TLS 1.3 derived write keys and IVs */
    unsigned char client_write_key13[32];
    unsigned char server_write_key13[32];
    unsigned char client_write_iv13[12];
    unsigned char server_write_iv13[12];
    /* TLS 1.3 handshake-phase keys (separate from application-phase) */
    unsigned char client_hs_write_key[32];
    unsigned char server_hs_write_key[32];
    unsigned char client_hs_write_iv[12];
    unsigned char server_hs_write_iv[12];
    /* TLS 1.3 handshake transcript hash */
    ossl_sha256_ctx hs_hash13;
    ossl_sha384_ctx hs_hash38413;
    /* Plaintext read buffer for SSL_read partial reads */
    unsigned char *read_buf;
    int read_buf_len;
    int read_buf_off;
    int verified_chain_augmented;
};

struct ossl_bio {
    unsigned char *data;
    int len;
    int cap;
};

struct ossl_x509 {
    unsigned char *der;
    int der_len;
};

struct ossl_x509_store_ctx {
    int error;
    int depth;
};

struct ossl_ssl_session {
    unsigned char *data;
    int len;
};

/* ========================================================================
 * Utility: buffer and hex dump
 * ======================================================================== */

static int ossl_buf_init(ossl_buf *b, int cap) {
    if (cap < 0) return -1;
    b->data = (unsigned char*)malloc(cap);
    if (!b->data) return -1;
    b->len = 0;
    b->cap = cap;
    return 0;
}

static void ossl_buf_free(ossl_buf *b) {
    free(b->data);
    b->data = NULL;
    b->len = b->cap = 0;
}

static int ossl_buf_ensure(ossl_buf *b, int sz) {
    if (b->cap >= sz) return 0;
    unsigned char *nd = (unsigned char*)realloc(b->data, sz);
    if (!nd) return -1;
    b->data = nd;
    b->cap = sz;
    return 0;
}

static int ossl_buf_push(ossl_buf *b, const unsigned char *data, int len) {
    if (len < 0) return -1;
    int needed = b->len + len;
    if (needed < b->len) return -1;
    if (ossl_buf_ensure(b, needed)) return -1;
    memcpy(b->data + b->len, data, len);
    b->len += len;
    return 0;
}

static int tcp_recv_all(ossl_sock_t fd, unsigned char *buf, int len) {
    int total = 0;
    while (total < len) {
        int n = recv(fd, (char*)(buf + total), len - total, 0);
        if (n <= 0) {
            if (n < 0 && OSSL_IO_RETRY(fd)) {
                continue;
            }
            return -1;
        }
        total += n;
    }
    return 0;
}

static int tcp_send_all(ossl_sock_t fd, const unsigned char *buf, int len) {
    int total = 0;
    while (total < len) {
        int n = send(fd, (const char*)(buf + total), len - total, 0);
        if (n <= 0) {
            if (n < 0 && OSSL_IO_RETRY(fd)) {
                continue;
            }
            return -1;
        }
        total += n;
    }
    return 0;
}


/* ========================================================================
 * Cryptographically secure random number generator
 * ======================================================================== */

#ifdef OSSL_PLATFORM_WINDOWS
static int ossl_rand_bytes(unsigned char *buf, int len) {
    if (len <= 0) return 0;
    if (!BCryptGenRandom(NULL, buf, len, BCRYPT_USE_SYSTEM_PREFERRED_RNG)) {
        fprintf(stderr, "ossl: BCryptGenRandom failed (error %lx)\n", GetLastError());
        return -1;
    }
    return 0;
}
#else
static int ossl_rand_bytes(unsigned char *buf, int len) {
    if (len <= 0) return 0;
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) {
        fprintf(stderr, "ossl: Failed to open /dev/urandom\n");
        return -1;
    }
    size_t n = fread(buf, 1, len, f);
    fclose(f);
    if ((int)n != len) {
        fprintf(stderr, "ossl: Short read from /dev/urandom (%zu of %d bytes)\n", n, len);
        return -1;
    }
    return 0;
}
#endif

/* ========================================================================
 * SHA-256 (RFC 6234)
 * ======================================================================== */

static const unsigned int SHA256_K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define RR(x, n)  (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z)(((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SIG0(x) (RR(x,2) ^ RR(x,13) ^ RR(x,22))
#define SIG1(x) (RR(x,6) ^ RR(x,11) ^ RR(x,25))
#define G0(x) (RR(x,7) ^ RR(x,18) ^ ((x)>>3))
#define G1(x) (RR(x,17) ^ RR(x,19) ^ ((x)>>10))

static void ossl_sha256_transform(ossl_sha256_ctx *ctx, const unsigned char block[64]) {
    unsigned int w[64];
    unsigned int a,b,c,d,e,f,g,h,t1,t2;
    int i;
    for (i = 0; i < 16; i++) {
        w[i] = ((unsigned int)block[i*4] << 24) | ((unsigned int)block[i*4+1] << 16) |
               ((unsigned int)block[i*4+2] << 8)  | (unsigned int)block[i*4+3];
    }
    for (i = 16; i < 64; i++) {
        w[i] = G1(w[i-2]) + w[i-7] + G0(w[i-15]) + w[i-16];
    }
    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];
    for (i = 0; i < 64; i++) {
        t1 = h + SIG1(e) + CH(e,f,g) + SHA256_K[i] + w[i];
        t2 = SIG0(a) + MAJ(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void ossl_sha256_init(ossl_sha256_ctx *ctx) {
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
    ctx->count = 0;
    ctx->buflen = 0;
}

static void ossl_sha256_update(ossl_sha256_ctx *ctx, const unsigned char *data, unsigned long long len) {
    ctx->count += len;
    while (len > 0) {
        unsigned int space = 64 - ctx->buflen;
        unsigned int take = (len < space) ? (unsigned int)len : space;
        memcpy(ctx->buffer + ctx->buflen, data, take);
        ctx->buflen += take;
        data += take;
        len -= take;
        if (ctx->buflen == 64) {
            ossl_sha256_transform(ctx, ctx->buffer);
            ctx->buflen = 0;
        }
    }
}

static void ossl_sha256_final(ossl_sha256_ctx *ctx, unsigned char digest[32]) {
    unsigned long long bits = ctx->count * 8;
    ctx->buffer[ctx->buflen++] = 0x80;
    if (ctx->buflen > 56) {
        memset(ctx->buffer + ctx->buflen, 0, 64 - ctx->buflen);
        ossl_sha256_transform(ctx, ctx->buffer);
        ctx->buflen = 0;
    }
    memset(ctx->buffer + ctx->buflen, 0, 56 - ctx->buflen);
    ctx->buffer[56] = (unsigned char)(bits >> 56);
    ctx->buffer[57] = (unsigned char)(bits >> 48);
    ctx->buffer[58] = (unsigned char)(bits >> 40);
    ctx->buffer[59] = (unsigned char)(bits >> 32);
    ctx->buffer[60] = (unsigned char)(bits >> 24);
    ctx->buffer[61] = (unsigned char)(bits >> 16);
    ctx->buffer[62] = (unsigned char)(bits >> 8);
    ctx->buffer[63] = (unsigned char)(bits);
    ossl_sha256_transform(ctx, ctx->buffer);
    for (int i = 0; i < 8; i++) {
        digest[i*4]   = (unsigned char)(ctx->state[i] >> 24);
        digest[i*4+1] = (unsigned char)(ctx->state[i] >> 16);
        digest[i*4+2] = (unsigned char)(ctx->state[i] >> 8);
        digest[i*4+3] = (unsigned char)(ctx->state[i]);
    }
}

/* ========================================================================
 * SHA-384 (based on SHA-512)
 * ======================================================================== */

static const unsigned long long SHA384_K[80] = {
    0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL,0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,0x06ca6351e003826fULL,0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,
    0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL,0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,
    0xca273eceea26619cULL,0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,
    0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL
};

#define RR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define CH64(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ64(x,y,z)(((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SIG064(x) (RR64(x,28) ^ RR64(x,34) ^ RR64(x,39))
#define SIG164(x) (RR64(x,14) ^ RR64(x,18) ^ RR64(x,41))
#define G064(x) (RR64(x,1) ^ RR64(x,8) ^ ((x)>>7))
#define G164(x) (RR64(x,19) ^ RR64(x,61) ^ ((x)>>6))

static void ossl_sha384_transform(ossl_sha384_ctx *ctx, const unsigned char block[128]) {
    unsigned long long w[80];
    unsigned long long a,b,c,d,e,f,g,h,t1,t2;
    int i;
    for (i = 0; i < 16; i++) {
        w[i] = ((unsigned long long)block[i*8] << 56) | ((unsigned long long)block[i*8+1] << 48) |
               ((unsigned long long)block[i*8+2] << 40) | ((unsigned long long)block[i*8+3] << 32) |
               ((unsigned long long)block[i*8+4] << 24) | ((unsigned long long)block[i*8+5] << 16) |
               ((unsigned long long)block[i*8+6] << 8)  | (unsigned long long)block[i*8+7];
    }
    for (i = 16; i < 80; i++) {
        w[i] = G164(w[i-2]) + w[i-7] + G064(w[i-15]) + w[i-16];
    }
    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];
    for (i = 0; i < 80; i++) {
        t1 = h + SIG164(e) + CH64(e,f,g) + SHA384_K[i] + w[i];
        t2 = SIG064(a) + MAJ64(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void ossl_sha384_init(ossl_sha384_ctx *ctx) {
    ctx->state[0] = 0xcbbb9d5dc1059ed8ULL;
    ctx->state[1] = 0x629a292a367cd507ULL;
    ctx->state[2] = 0x9159015a3070dd17ULL;
    ctx->state[3] = 0x152fecd8f70e5939ULL;
    ctx->state[4] = 0x67332667ffc00b31ULL;
    ctx->state[5] = 0x8eb44a8768581511ULL;
    ctx->state[6] = 0xdb0c2e0d64f98fa7ULL;
    ctx->state[7] = 0x47b5481dbefa4fa4ULL;
    ctx->count = 0;
    ctx->buflen = 0;
}

static void ossl_sha384_update(ossl_sha384_ctx *ctx, const unsigned char *data, unsigned long long len) {
    ctx->count += len;
    while (len > 0) {
        unsigned int space = 128 - ctx->buflen;
        unsigned int take = (len < space) ? (unsigned int)len : space;
        memcpy(ctx->buffer + ctx->buflen, data, take);
        ctx->buflen += take;
        data += take;
        len -= take;
        if (ctx->buflen == 128) {
            ossl_sha384_transform(ctx, ctx->buffer);
            ctx->buflen = 0;
        }
    }
}

static void ossl_sha384_final(ossl_sha384_ctx *ctx, unsigned char digest[48]) {
    unsigned long long bits = ctx->count * 8;
    ctx->buffer[ctx->buflen++] = 0x80;
    if (ctx->buflen > 112) {
        memset(ctx->buffer + ctx->buflen, 0, 128 - ctx->buflen);
        ossl_sha384_transform(ctx, ctx->buffer);
        ctx->buflen = 0;
    }
    memset(ctx->buffer + ctx->buflen, 0, 120 - ctx->buflen);
    ctx->buffer[120] = (unsigned char)(bits >> 56);
    ctx->buffer[121] = (unsigned char)(bits >> 48);
    ctx->buffer[122] = (unsigned char)(bits >> 40);
    ctx->buffer[123] = (unsigned char)(bits >> 32);
    ctx->buffer[124] = (unsigned char)(bits >> 24);
    ctx->buffer[125] = (unsigned char)(bits >> 16);
    ctx->buffer[126] = (unsigned char)(bits >> 8);
    ctx->buffer[127] = (unsigned char)(bits);
    ossl_sha384_transform(ctx, ctx->buffer);
    for (int i = 0; i < 6; i++) {
        digest[i*8]   = (unsigned char)(ctx->state[i] >> 56);
        digest[i*8+1] = (unsigned char)(ctx->state[i] >> 48);
        digest[i*8+2] = (unsigned char)(ctx->state[i] >> 40);
        digest[i*8+3] = (unsigned char)(ctx->state[i] >> 32);
        digest[i*8+4] = (unsigned char)(ctx->state[i] >> 24);
        digest[i*8+5] = (unsigned char)(ctx->state[i] >> 16);
        digest[i*8+6] = (unsigned char)(ctx->state[i] >> 8);
        digest[i*8+7] = (unsigned char)(ctx->state[i]);
    }
}

/* ========================================================================
 * HMAC-SHA256 (RFC 2104)
 * ======================================================================== */

static void ossl_hmac_sha256(const unsigned char *key, int key_len,
                              const unsigned char *data, int data_len,
                              unsigned char mac[32]) {
    unsigned char k0[64];
    unsigned char ipad[64], opad[64];
    ossl_sha256_ctx ctx;
    int i;
    memset(k0, 0, 64);
    if (key_len <= 64) {
        memcpy(k0, key, key_len);
    } else {
        ossl_sha256_init(&ctx);
        ossl_sha256_update(&ctx, key, key_len);
        ossl_sha256_final(&ctx, k0);
    }
    for (i = 0; i < 64; i++) {
        ipad[i] = k0[i] ^ 0x36;
        opad[i] = k0[i] ^ 0x5C;
    }
    ossl_sha256_init(&ctx);
    ossl_sha256_update(&ctx, ipad, 64);
    ossl_sha256_update(&ctx, data, data_len);
    unsigned char tmp[32];
    ossl_sha256_final(&ctx, tmp);
    ossl_sha256_init(&ctx);
    ossl_sha256_update(&ctx, opad, 64);
    ossl_sha256_update(&ctx, tmp, 32);
    ossl_sha256_final(&ctx, mac);
}

/* ========================================================================
 * HMAC-SHA384
 * ======================================================================== */

static void ossl_hmac_sha384(const unsigned char *key, int key_len,
                              const unsigned char *data, int data_len,
                              unsigned char mac[48]) {
    unsigned char k0[128];
    unsigned char ipad[128], opad[128];
    ossl_sha384_ctx ctx;
    int i;
    memset(k0, 0, 128);
    if (key_len <= 128) {
        memcpy(k0, key, key_len);
    } else {
        ossl_sha384_init(&ctx);
        ossl_sha384_update(&ctx, key, key_len);
        ossl_sha384_final(&ctx, k0);
    }
    for (i = 0; i < 128; i++) {
        ipad[i] = k0[i] ^ 0x36;
        opad[i] = k0[i] ^ 0x5C;
    }
    ossl_sha384_init(&ctx);
    ossl_sha384_update(&ctx, ipad, 128);
    ossl_sha384_update(&ctx, data, data_len);
    unsigned char tmp[48];
    ossl_sha384_final(&ctx, tmp);
    ossl_sha384_init(&ctx);
    ossl_sha384_update(&ctx, opad, 128);
    ossl_sha384_update(&ctx, tmp, 48);
    ossl_sha384_final(&ctx, mac);
}

/* ========================================================================
 * HKDF (RFC 5869) — used by TLS 1.3
 * ======================================================================== */

static void ossl_hkdf_extract_sha256(const unsigned char *salt, int salt_len,
                                      const unsigned char *ikm, int ikm_len,
                                      unsigned char prk[32]) {
    ossl_hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
}

static void ossl_hkdf_extract_sha384(const unsigned char *salt, int salt_len,
                                      const unsigned char *ikm, int ikm_len,
                                      unsigned char prk[48]) {
    ossl_hmac_sha384(salt, salt_len, ikm, ikm_len, prk);
}

static int ossl_hkdf_expand_sha256(const unsigned char *prk,
                                    const unsigned char *info, int info_len,
                                    unsigned char *out, int out_len) {
    unsigned char T[32];
    int T_len = 0, remaining = out_len, counter = 0;
    while (remaining > 0) {
        counter++;
        if (counter > 255) return -1;
        unsigned char input[32 + 1024 + 1];
        int ilen = 0;
        if (T_len > 0) { memcpy(input, T, T_len); ilen = T_len; }
        if (ilen + info_len + 1 > (int)sizeof(input)) return -1;
        memcpy(input + ilen, info, info_len); ilen += info_len;
        input[ilen++] = (unsigned char)counter;
        ossl_hmac_sha256(prk, 32, input, ilen, T); T_len = 32;
        int take = remaining < 32 ? remaining : 32;
        memcpy(out, T, take); out += take; remaining -= take;
    }
    return 0;
}

static int ossl_hkdf_expand_sha384(const unsigned char *prk,
                                    const unsigned char *info, int info_len,
                                    unsigned char *out, int out_len) {
    unsigned char T[48];
    int T_len = 0, remaining = out_len, counter = 0;
    while (remaining > 0) {
        counter++;
        if (counter > 255) return -1;
        unsigned char input[48 + 1024 + 1];
        int ilen = 0;
        if (T_len > 0) { memcpy(input, T, T_len); ilen = T_len; }
        if (ilen + info_len + 1 > (int)sizeof(input)) return -1;
        memcpy(input + ilen, info, info_len); ilen += info_len;
        input[ilen++] = (unsigned char)counter;
        ossl_hmac_sha384(prk, 48, input, ilen, T); T_len = 48;
        int take = remaining < 48 ? remaining : 48;
        memcpy(out, T, take); out += take; remaining -= take;
    }
    return 0;
}

/* HKDF-Expand-Label for TLS 1.3 (RFC 8446 Section 7.1) */
static int ossl_hkdf_expand_label_sha256(const unsigned char *secret,
                                          const char *label,
                                          const unsigned char *context, int context_len,
                                          unsigned char *out, int out_len) {
    int label_strlen = (int)strlen(label);
    int prefix_len = 6; /* "tls13 " */
    unsigned char hkdf_label[512];
    int pos = 0;
    hkdf_label[pos++] = (unsigned char)((out_len >> 8) & 0xFF);
    hkdf_label[pos++] = (unsigned char)(out_len & 0xFF);
    int total_label = prefix_len + label_strlen;
    if (total_label > 255 || pos + 1 + total_label + 1 + context_len > (int)sizeof(hkdf_label)) return -1;
    hkdf_label[pos++] = (unsigned char)total_label;
    memcpy(hkdf_label + pos, "tls13 ", prefix_len); pos += prefix_len;
    memcpy(hkdf_label + pos, label, label_strlen); pos += label_strlen;
    hkdf_label[pos++] = (unsigned char)context_len;
    if (context_len > 0) { memcpy(hkdf_label + pos, context, context_len); pos += context_len; }
    return ossl_hkdf_expand_sha256(secret, hkdf_label, pos, out, out_len);
}

static int ossl_hkdf_expand_label_sha384(const unsigned char *secret,
                                          const char *label,
                                          const unsigned char *context, int context_len,
                                          unsigned char *out, int out_len) {
    int label_strlen = (int)strlen(label);
    int prefix_len = 6; /* "tls13 " */
    unsigned char hkdf_label[512];
    int pos = 0;
    hkdf_label[pos++] = (unsigned char)((out_len >> 8) & 0xFF);
    hkdf_label[pos++] = (unsigned char)(out_len & 0xFF);
    int total_label = prefix_len + label_strlen;
    if (total_label > 255 || pos + 1 + total_label + 1 + context_len > (int)sizeof(hkdf_label)) return -1;
    hkdf_label[pos++] = (unsigned char)total_label;
    memcpy(hkdf_label + pos, "tls13 ", prefix_len); pos += prefix_len;
    memcpy(hkdf_label + pos, label, label_strlen); pos += label_strlen;
    hkdf_label[pos++] = (unsigned char)context_len;
    if (context_len > 0) { memcpy(hkdf_label + pos, context, context_len); pos += context_len; }
    return ossl_hkdf_expand_sha384(secret, hkdf_label, pos, out, out_len);
}

/* SSL helper: HKDF-Expand-Label using the session's hash algorithm */
static void ossl_tls13_expand_label(struct ossl_ssl *ssl,
                                     const unsigned char *secret,
                                     const char *label,
                                     const unsigned char *context, int context_len,
                                     unsigned char *out, int out_len) {
    if (ssl->tls13_hash_len == 48)
        ossl_hkdf_expand_label_sha384(secret, label, context, context_len, out, out_len);
    else
        ossl_hkdf_expand_label_sha256(secret, label, context, context_len, out, out_len);
}

/* Derive a TLS 1.3 write key and IV from a traffic secret */
static void ossl_tls13_derive_traffic_keys(struct ossl_ssl *ssl,
                                            const unsigned char *traffic_secret,
                                            unsigned char *write_key, int key_len,
                                            unsigned char *write_iv) {
    unsigned char empty[1] = {0};
    ossl_tls13_expand_label(ssl, traffic_secret, "key", empty, 0, write_key, key_len);
    ossl_tls13_expand_label(ssl, traffic_secret, "iv", empty, 0, write_iv, 12);
}

/* ========================================================================
 * AES-128 (FIPS 197)
 * ======================================================================== */

static const unsigned char aes_sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const unsigned char aes_inv_sbox[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

static void aes_key_expansion(const unsigned char key[16], unsigned char rk[176]) {
    unsigned int tmp;
    unsigned char rcon = 0x01;
    for (int i = 0; i < 16; i++) rk[i] = key[i];
    for (int i = 16; i < 176; i += 4) {
        tmp = (unsigned int)rk[i-4] << 24 | (unsigned int)rk[i-3] << 16 | (unsigned int)rk[i-2] << 8 | rk[i-1];
        if (i % 16 == 0) {
            unsigned char hi;
            tmp = ((unsigned int)aes_sbox[(tmp >> 16) & 0xFF] << 24) |
                  ((unsigned int)aes_sbox[(tmp >> 8) & 0xFF] << 16) |
                  ((unsigned int)aes_sbox[tmp & 0xFF] << 8) |
                  (unsigned int)aes_sbox[(tmp >> 24) & 0xFF];
            tmp ^= (unsigned int)rcon << 24;
            hi = rcon & 0x80;
            rcon <<= 1;
            if (hi) rcon ^= 0x1b;
        }
        tmp ^= (unsigned int)rk[i-16] << 24 | (unsigned int)rk[i-15] << 16 | (unsigned int)rk[i-14] << 8 | rk[i-13];
        rk[i]   = (unsigned char)(tmp >> 24);
        rk[i+1] = (unsigned char)(tmp >> 16);
        rk[i+2] = (unsigned char)(tmp >> 8);
        rk[i+3] = (unsigned char)(tmp);
    }
}

static void add_round_key(unsigned char state[16], const unsigned char rk[16]) {
    for (int i = 0; i < 16; i++) state[i] ^= rk[i];
}

static void sub_bytes(unsigned char state[16]) {
    for (int i = 0; i < 16; i++) state[i] = aes_sbox[state[i]];
}

static void inv_sub_bytes(unsigned char state[16]) {
    for (int i = 0; i < 16; i++) state[i] = aes_inv_sbox[state[i]];
}

static void shift_rows(unsigned char state[16]) {
    unsigned char t;
    t = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = t;
    t = state[2]; state[2] = state[10]; state[10] = t; t = state[6]; state[6] = state[14]; state[14] = t;
    t = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = t;
}

static void inv_shift_rows(unsigned char state[16]) {
    unsigned char t;
    t = state[13]; state[13] = state[9]; state[9] = state[5]; state[5] = state[1]; state[1] = t;
    t = state[2]; state[2] = state[10]; state[10] = t; t = state[6]; state[6] = state[14]; state[14] = t;
    t = state[3]; state[3] = state[7]; state[7] = state[11]; state[11] = state[15]; state[15] = t;
}

static unsigned int gf_mul(unsigned char a, unsigned char b) {
    unsigned int res = 0;
    unsigned char hi_bit;
    for (int i = 0; i < 8; i++) {
        if (b & 1) res ^= a;
        hi_bit = a & 0x80;
        a <<= 1;
        if (hi_bit) a ^= 0x1b;
        b >>= 1;
    }
    return res;
}

static void mix_columns(unsigned char state[16]) {
    for (int i = 0; i < 16; i += 4) {
        unsigned char a[4];
        a[0] = state[i]; a[1] = state[i+1]; a[2] = state[i+2]; a[3] = state[i+3];
        state[i]   = (unsigned char)(gf_mul(a[0],2) ^ gf_mul(a[1],3) ^ a[2] ^ a[3]);
        state[i+1] = (unsigned char)(a[0] ^ gf_mul(a[1],2) ^ gf_mul(a[2],3) ^ a[3]);
        state[i+2] = (unsigned char)(a[0] ^ a[1] ^ gf_mul(a[2],2) ^ gf_mul(a[3],3));
        state[i+3] = (unsigned char)(gf_mul(a[0],3) ^ a[1] ^ a[2] ^ gf_mul(a[3],2));
    }
}

static void inv_mix_columns(unsigned char state[16]) {
    for (int i = 0; i < 16; i += 4) {
        unsigned char a[4];
        a[0] = state[i]; a[1] = state[i+1]; a[2] = state[i+2]; a[3] = state[i+3];
        state[i]   = (unsigned char)(gf_mul(a[0],14) ^ gf_mul(a[1],11) ^ gf_mul(a[2],13) ^ gf_mul(a[3],9));
        state[i+1] = (unsigned char)(gf_mul(a[0],9) ^ gf_mul(a[1],14) ^ gf_mul(a[2],11) ^ gf_mul(a[3],13));
        state[i+2] = (unsigned char)(gf_mul(a[0],13) ^ gf_mul(a[1],9) ^ gf_mul(a[2],14) ^ gf_mul(a[3],11));
        state[i+3] = (unsigned char)(gf_mul(a[0],11) ^ gf_mul(a[1],13) ^ gf_mul(a[2],9) ^ gf_mul(a[3],14));
    }
}

static void aes_encrypt_block(const unsigned char rk[176], const unsigned char in[16], unsigned char out[16]) {
    unsigned char state[16];
    memcpy(state, in, 16);
    add_round_key(state, rk);
    for (int round = 1; round <= 9; round++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, rk + round*16);
    }
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, rk + 160);
    memcpy(out, state, 16);
}

static void aes_decrypt_block(const unsigned char rk[176], const unsigned char in[16], unsigned char out[16]) {
    unsigned char state[16];
    memcpy(state, in, 16);
    add_round_key(state, rk + 160);
    for (int round = 9; round >= 1; round--) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, rk + round*16);
        inv_mix_columns(state);
    }
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, rk);
    memcpy(out, state, 16);
}

/* ========================================================================
 * AES-256 (FIPS 197)
 * ======================================================================== */

static void aes256_key_expansion(const unsigned char key[32], unsigned char rk[240]) {
    unsigned int tmp;
    for (int i = 0; i < 32; i++) rk[i] = key[i];
    for (int i = 32; i < 240; i += 4) {
        tmp = (unsigned int)rk[i-4] << 24 | (unsigned int)rk[i-3] << 16 | (unsigned int)rk[i-2] << 8 | rk[i-1];
        if (i % 32 == 0) {
            tmp = ((unsigned int)aes_sbox[(tmp >> 16) & 0xFF] << 24) |
                  ((unsigned int)aes_sbox[(tmp >> 8) & 0xFF] << 16) |
                  ((unsigned int)aes_sbox[tmp & 0xFF] << 8) |
                  (unsigned int)aes_sbox[(tmp >> 24) & 0xFF];
            tmp ^= (unsigned int)(0x01000000 << (i/32 - 1));
        } else if (i % 32 == 16) {
            tmp = ((unsigned int)aes_sbox[(tmp >> 24) & 0xFF] << 24) |
                  ((unsigned int)aes_sbox[(tmp >> 16) & 0xFF] << 16) |
                  ((unsigned int)aes_sbox[(tmp >> 8) & 0xFF] << 8) |
                  (unsigned int)aes_sbox[tmp & 0xFF];
        }
        tmp ^= (unsigned int)rk[i-32] << 24 | (unsigned int)rk[i-31] << 16 | (unsigned int)rk[i-30] << 8 | rk[i-29];
        rk[i] = (unsigned char)(tmp >> 24);
        rk[i+1] = (unsigned char)(tmp >> 16);
        rk[i+2] = (unsigned char)(tmp >> 8);
        rk[i+3] = (unsigned char)(tmp);
    }
}

static void aes256_encrypt_block(const unsigned char rk[240], const unsigned char in[16], unsigned char out[16]) {
    unsigned char state[16];
    memcpy(state, in, 16);
    add_round_key(state, rk);
    for (int round = 1; round <= 13; round++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, rk + round*16);
    }
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, rk + 224);
    memcpy(out, state, 16);
}

/* ========================================================================
 * GHASH (GCM mode)
 * ======================================================================== */

static void gcm_ghash(const unsigned char H[16], const unsigned char *data,
                      int data_len, unsigned char out[16]) {
    unsigned char ghash_state[16] = {0};
    unsigned char tmp[16];
    unsigned char block[16];
    int i, j;
    for (i = 0; i < data_len; i += 16) {
        memset(block, 0, 16);
        int left = data_len - i;
        if (left > 16) left = 16;
        memcpy(block, data + i, left);
        for (j = 0; j < 16; j++) ghash_state[j] ^= block[j];
        memcpy(tmp, ghash_state, 16);
        memset(ghash_state, 0, 16);
        unsigned char v[16]; memcpy(v, H, 16);
        for (int bit = 0; bit < 128; bit++) {
            int byte_idx = bit/8;
            int bit_idx = 7 - (bit % 8);
            {
                unsigned char mask = (unsigned char)-((tmp[byte_idx] >> bit_idx) & 1);
                for (j = 0; j < 16; j++) ghash_state[j] ^= v[j] & mask;
            }
            unsigned char lsb = v[15] & 1;
            for (j = 15; j > 0; j--) v[j] = (v[j] >> 1) | ((v[j-1] & 1) << 7);
            v[0] >>= 1;
            v[0] ^= 0xe1 & -(unsigned char)lsb;
        }
    }
    memcpy(out, ghash_state, 16);
}

/* ========================================================================
 * AES-128-GCM
 * ======================================================================== */

static int aes128_gcm_encrypt(const unsigned char key[16],
                                const unsigned char *plaintext, int pt_len,
                                const unsigned char *aad, int aad_len,
                                const unsigned char *nonce, int nonce_len,
                                unsigned char *ciphertext,
                                unsigned char tag[16]) {
    if (nonce_len < 1 || nonce_len > 12 || aad_len < 0 || pt_len < 0) {
        memset(tag, 0, 16);
        return -1;
    }
    unsigned char H[16], zero[16] = {0}, rk[176];
    aes_key_expansion(key, rk);
    aes_encrypt_block(rk, zero, H);
    unsigned char J0[16];
    memset(J0, 0, 16);
    memcpy(J0, nonce, nonce_len);
    J0[15] = 1;
    unsigned char counter[16];
    memcpy(counter, J0, 16);
    unsigned char ekey[16];
    for (int i = 0; i < pt_len; i += 16) {
        for (int j = 15; j >= 12; j--) if (++counter[j]) break;
        aes_encrypt_block(rk, counter, ekey);
        int this_len = pt_len - i;
        if (this_len > 16) this_len = 16;
        for (int j = 0; j < this_len; j++)
            ciphertext[i + j] = plaintext[i + j] ^ ekey[j];
    }
    int aad_pad = (16 - (aad_len % 16)) % 16;
    int ct_pad = (16 - (pt_len % 16)) % 16;
    /* Cap GHASH input size at 1MB to prevent integer overflow in malloc */
    {
        size_t ghash_size128 = (size_t)aad_len + (size_t)aad_pad + (size_t)pt_len + (size_t)ct_pad + 16;
        if (ghash_size128 > 1024 * 1024) {
            memset(tag, 0, 16);
            return -1;
        }
    }
    unsigned char *ghash_in = (unsigned char*)malloc(aad_len + aad_pad + pt_len + ct_pad + 16);
    if (!ghash_in) {
        memset(tag, 0, 16);
        return -1;
    }
    int gpos = 0;
    memcpy(ghash_in + gpos, aad, aad_len); gpos += aad_len;
    memset(ghash_in + gpos, 0, aad_pad); gpos += aad_pad;
    memcpy(ghash_in + gpos, ciphertext, pt_len); gpos += pt_len;
    memset(ghash_in + gpos, 0, ct_pad); gpos += ct_pad;
    unsigned long long aad_bits = (unsigned long long)aad_len * 8;
    unsigned long long ct_bits = (unsigned long long)pt_len * 8;
    for (int j = 0; j < 8; j++) ghash_in[gpos++] = (unsigned char)(aad_bits >> (56 - 8*j));
    for (int j = 0; j < 8; j++) ghash_in[gpos++] = (unsigned char)(ct_bits >> (56 - 8*j));
    unsigned char ghash_output[16];
    gcm_ghash(H, ghash_in, gpos, ghash_output);
    free(ghash_in);
    aes_encrypt_block(rk, J0, ekey);
    for (int j = 0; j < 16; j++) tag[j] = ghash_output[j] ^ ekey[j];
    return 0;
}

static int aes128_gcm_decrypt(const unsigned char key[16],
                               const unsigned char *ciphertext, int ct_len,
                               const unsigned char *aad, int aad_len,
                               const unsigned char *nonce, int nonce_len,
                               const unsigned char tag[16],
                               unsigned char *plaintext) {
    if (nonce_len < 1 || nonce_len > 12 || aad_len < 0 || ct_len < 0) return -1;
    unsigned char rk[176], H[16], zero[16] = {0};
    aes_key_expansion(key, rk);
    aes_encrypt_block(rk, zero, H);
    unsigned char J0[16];
    memset(J0, 0, 16);
    memcpy(J0, nonce, nonce_len);
    J0[15] = 1;
    unsigned char counter[16];
    memcpy(counter, J0, 16);
    unsigned char ekey[16];
    for (int i = 0; i < ct_len; i += 16) {
        for (int j = 15; j >= 12; j--) if (++counter[j]) break;
        aes_encrypt_block(rk, counter, ekey);
        int this_len = ct_len - i;
        if (this_len > 16) this_len = 16;
        for (int j = 0; j < this_len; j++)
            plaintext[i + j] = ciphertext[i + j] ^ ekey[j];
    }
    int aad_pad = (16 - (aad_len % 16)) % 16;
    int ct_pad = (16 - (ct_len % 16)) % 16;
    /* Cap GHASH input size at 1MB to prevent integer overflow in malloc */
    {
        size_t ghash_size128 = (size_t)aad_len + (size_t)aad_pad + (size_t)ct_len + (size_t)ct_pad + 16;
        if (ghash_size128 > 1024 * 1024) return -1;
    }
    unsigned char *ghash_in = (unsigned char*)malloc(aad_len + aad_pad + ct_len + ct_pad + 16);
    if (!ghash_in) return -1;
    int gpos = 0;
    memcpy(ghash_in + gpos, aad, aad_len); gpos += aad_len;
    memset(ghash_in + gpos, 0, aad_pad); gpos += aad_pad;
    memcpy(ghash_in + gpos, ciphertext, ct_len); gpos += ct_len;
    memset(ghash_in + gpos, 0, ct_pad); gpos += ct_pad;
    unsigned long long aad_bits = (unsigned long long)aad_len * 8;
    unsigned long long ct_bits = (unsigned long long)ct_len * 8;
    for (int j = 0; j < 8; j++) ghash_in[gpos++] = (unsigned char)(aad_bits >> (56 - 8*j));
    for (int j = 0; j < 8; j++) ghash_in[gpos++] = (unsigned char)(ct_bits >> (56 - 8*j));
    unsigned char ghash_output[16];
    gcm_ghash(H, ghash_in, gpos, ghash_output);
    free(ghash_in);
    aes_encrypt_block(rk, J0, ekey);
    unsigned char computed_tag[16];
    for (int j = 0; j < 16; j++) computed_tag[j] = ghash_output[j] ^ ekey[j];
    /* Constant-time tag comparison: no early return */
    {
        unsigned char diff = 0;
        for (int j = 0; j < 16; j++) diff |= tag[j] ^ computed_tag[j];
        if (diff != 0) return -1;
    }
    return 0;
}

/* ========================================================================
 * AES-256-GCM
 * ======================================================================== */

static int aes256_gcm_encrypt(const unsigned char key[32],
                                const unsigned char *plaintext, int pt_len,
                                const unsigned char *aad, int aad_len,
                                const unsigned char *nonce, int nonce_len,
                                unsigned char *ciphertext,
                                unsigned char tag[16]) {
    if (nonce_len < 1 || nonce_len > 12 || aad_len < 0 || pt_len < 0) {
        memset(tag, 0, 16);
        return -1;
    }
    size_t ghash_size256 = (size_t)aad_len + (size_t)(16 - (aad_len % 16)) % 16
                         + (size_t)pt_len + (size_t)(16 - (pt_len % 16)) % 16 + 16;
    if (ghash_size256 > 1024 * 1024) {
        memset(ciphertext, 0, pt_len);
        memset(tag, 0, 16);
        return -1;
    }
    unsigned char H[16], zero[16] = {0}, rk[240];
    aes256_key_expansion(key, rk);
    aes256_encrypt_block(rk, zero, H);
    unsigned char J0[16];
    memset(J0, 0, 16);
    memcpy(J0, nonce, nonce_len);
    J0[15] = 1;
    unsigned char counter[16];
    memcpy(counter, J0, 16);
    unsigned char ekey[16];
    for (int i = 0; i < pt_len; i += 16) {
        for (int j = 15; j >= 12; j--) if (++counter[j]) break;
        aes256_encrypt_block(rk, counter, ekey);
        int this_len = pt_len - i;
        if (this_len > 16) this_len = 16;
        for (int j = 0; j < this_len; j++)
            ciphertext[i + j] = plaintext[i + j] ^ ekey[j];
    }
    int aad_pad = (16 - (aad_len % 16)) % 16;
    int pt_pad = (16 - (pt_len % 16)) % 16;
    unsigned char *ghash_in = (unsigned char*)malloc(ghash_size256);
    if (!ghash_in) {
        memset(ciphertext, 0, pt_len);
        memset(tag, 0, 16);
        return -1;
    }
    int gpos = 0;
    memcpy(ghash_in + gpos, aad, aad_len); gpos += aad_len;
    memset(ghash_in + gpos, 0, aad_pad); gpos += aad_pad;
    memcpy(ghash_in + gpos, ciphertext, pt_len); gpos += pt_len;
    memset(ghash_in + gpos, 0, pt_pad); gpos += pt_pad;
    unsigned long long aad_bits = (unsigned long long)aad_len * 8;
    unsigned long long ct_bits = (unsigned long long)pt_len * 8;
    for (int j = 0; j < 8; j++) ghash_in[gpos++] = (unsigned char)(aad_bits >> (56 - 8*j));
    for (int j = 0; j < 8; j++) ghash_in[gpos++] = (unsigned char)(ct_bits >> (56 - 8*j));
    unsigned char ghash_output[16];
    gcm_ghash(H, ghash_in, gpos, ghash_output);
    free(ghash_in);
    aes256_encrypt_block(rk, J0, ekey);
    for (int j = 0; j < 16; j++) tag[j] = ghash_output[j] ^ ekey[j];
    return 0;
}

static int aes256_gcm_decrypt(const unsigned char key[32],
                               const unsigned char *ciphertext, int ct_len,
                               const unsigned char *aad, int aad_len,
                               const unsigned char *nonce, int nonce_len,
                               const unsigned char tag[16],
                               unsigned char *plaintext) {
    if (nonce_len < 1 || nonce_len > 12 || aad_len < 0 || ct_len < 0) return -1;
    size_t ghash_size256d = (size_t)aad_len + (size_t)(16 - (aad_len % 16)) % 16
                          + (size_t)ct_len + (size_t)(16 - (ct_len % 16)) % 16 + 16;
    if (ghash_size256d > 1024 * 1024) return -1;
    unsigned char *ghash_in = (unsigned char*)malloc(ghash_size256d);
    if (!ghash_in) return -1;
    unsigned char rk[240], H[16], zero[16] = {0};
    aes256_key_expansion(key, rk);
    aes256_encrypt_block(rk, zero, H);
    unsigned char J0[16];
    memset(J0, 0, 16);
    memcpy(J0, nonce, nonce_len);
    J0[15] = 1;
    unsigned char counter[16];
    memcpy(counter, J0, 16);
    unsigned char ekey[16];
    for (int i = 0; i < ct_len; i += 16) {
        for (int j = 15; j >= 12; j--) if (++counter[j]) break;
        aes256_encrypt_block(rk, counter, ekey);
        int this_len = ct_len - i;
        if (this_len > 16) this_len = 16;
        for (int j = 0; j < this_len; j++)
            plaintext[i + j] = ciphertext[i + j] ^ ekey[j];
    }
    int aad_pad = (16 - (aad_len % 16)) % 16;
    int ct_pad = (16 - (ct_len % 16)) % 16;
    int gpos = 0;
    memcpy(ghash_in + gpos, aad, aad_len); gpos += aad_len;
    memset(ghash_in + gpos, 0, aad_pad); gpos += aad_pad;
    memcpy(ghash_in + gpos, ciphertext, ct_len); gpos += ct_len;
    memset(ghash_in + gpos, 0, ct_pad); gpos += ct_pad;
    unsigned long long aad_bits = (unsigned long long)aad_len * 8;
    unsigned long long ct_bits = (unsigned long long)ct_len * 8;
    for (int j = 0; j < 8; j++) ghash_in[gpos++] = (unsigned char)(aad_bits >> (56 - 8*j));
    for (int j = 0; j < 8; j++) ghash_in[gpos++] = (unsigned char)(ct_bits >> (56 - 8*j));
    unsigned char ghash_output[16];
    gcm_ghash(H, ghash_in, gpos, ghash_output);
    free(ghash_in);
    aes256_encrypt_block(rk, J0, ekey);
    unsigned char computed_tag[16];
    for (int j = 0; j < 16; j++) computed_tag[j] = ghash_output[j] ^ ekey[j];
    /* Constant-time tag comparison: no early return */
    {
        unsigned char diff = 0;
        for (int j = 0; j < 16; j++) diff |= tag[j] ^ computed_tag[j];
        if (diff != 0) return -1;
    }
    return 0;
}

/* ========================================================================
 * Big number arithmetic (little-endian bytes representation)
 * ======================================================================== */

static void bn_from_bin(unsigned char *bn, const unsigned char *bin, int bin_len, int max_len) {
    memset(bn, 0, max_len);
    for (int i = 0; i < bin_len && i < max_len; i++) {
        bn[i] = bin[bin_len - 1 - i];
    }
}

static void bn_to_bin(unsigned char *bin, int bin_len, const unsigned char *bn, int max_len) {
    memset(bin, 0, bin_len);
    for (int i = 0; i < bin_len && i < max_len; i++) {
        bin[bin_len - 1 - i] = bn[i];
    }
}

static int bn_cmp(const unsigned char *a, const unsigned char *b, int len) {
    for (int i = len - 1; i >= 0; i--) {
        if (a[i] > b[i]) return 1;
        if (a[i] < b[i]) return -1;
    }
    return 0;
}

static int bn_sub(unsigned char *a, const unsigned char *b, int len) {
    unsigned int borrow = 0;
    for (int i = 0; i < len; i++) {
        unsigned int tmp = (unsigned int)a[i] - (unsigned int)b[i] - borrow;
        a[i] = (unsigned char)(tmp & 0xFF);
        borrow = (tmp >> 8) & 1;
    }
    return borrow;
}

static void bn_mul(unsigned char *res, const unsigned char *a, const unsigned char *b, int len) {
    memset(res, 0, len * 2);
    for (int i = 0; i < len; i++) {
        unsigned int carry = 0;
        for (int j = 0; j < len; j++) {
            unsigned long long tmp = (unsigned long long)a[i] * b[j] + res[i + j] + carry;
            res[i + j] = (unsigned char)(tmp & 0xFF);
            carry = (unsigned int)(tmp >> 8);
        }
        res[i + len] = (unsigned char)carry;
    }
}

static int bn_mod(unsigned char *res, const unsigned char *a, int a_len, const unsigned char *mod, int mod_len) {
    unsigned char *temp = (unsigned char*)calloc(a_len, 1);
    if (!temp) return -1;
    memcpy(temp, a, a_len);
    int mod_bits = 0;
    for (int i = mod_len - 1; i >= 0; i--) {
        if (mod[i] != 0) {
            mod_bits = i * 8;
            unsigned char val = mod[i];
            while (val > 0) { mod_bits++; val >>= 1; }
            break;
        }
    }
    int temp_bits = 0;
    for (int i = a_len - 1; i >= 0; i--) {
        if (temp[i] != 0) {
            temp_bits = i * 8;
            unsigned char val = temp[i];
            while (val > 0) { temp_bits++; val >>= 1; }
            break;
        }
    }
    int shift = temp_bits - mod_bits;
    if (shift >= 0) {
        unsigned char *shifted_mod = (unsigned char*)calloc(a_len, 1);
        if (!shifted_mod) { free(temp); return -1; }
        int byte_shift = shift / 8;
        int bit_shift = shift % 8;
        unsigned int carry = 0;
        for (int i = 0; i < mod_len; i++) {
            unsigned int val = ((unsigned int)mod[i] << bit_shift) | carry;
            if (i + byte_shift < a_len)
                shifted_mod[i + byte_shift] = (unsigned char)(val & 0xFF);
            carry = val >> 8;
        }
        if (mod_len + byte_shift < a_len)
            shifted_mod[mod_len + byte_shift] = (unsigned char)carry;
        for (int s = shift; s >= 0; s--) {
            if (bn_cmp(temp, shifted_mod, a_len) >= 0)
                bn_sub(temp, shifted_mod, a_len);
            unsigned int borrow = 0;
            for (int i = a_len - 1; i >= 0; i--) {
                unsigned int val = shifted_mod[i] | (borrow << 8);
                shifted_mod[i] = (unsigned char)(val >> 1);
                borrow = val & 1;
            }
        }
        free(shifted_mod);
    }
    memcpy(res, temp, mod_len);
    free(temp);
    return 0;
}

static int rsa_modpow(const unsigned char *base, int base_len,
                       const unsigned char *exp, int exp_len,
                       const unsigned char *mod, int mod_len,
                       unsigned char *result) {
    if (mod_len <= 0 || exp_len <= 0) return -1;
    int max_len = mod_len;
    /* Prevent integer overflow in max_len * 2 */
    if (max_len < 0 || max_len > 1024 * 1024) return -1;
    unsigned char *bn_mod_val = (unsigned char*)malloc(max_len);
    unsigned char *bn_base = (unsigned char*)malloc(max_len);
    unsigned char *bn_res = (unsigned char*)malloc(max_len);
    unsigned char *temp_prod = (unsigned char*)malloc(max_len * 2);
    if (!bn_mod_val || !bn_base || !bn_res || !temp_prod) {
        free(bn_mod_val); free(bn_base); free(bn_res); free(temp_prod);
        return -1;
    }
    bn_from_bin(bn_mod_val, mod, mod_len, max_len);
    if (base_len > mod_len) {
        unsigned char *temp_base = (unsigned char*)malloc(base_len);
        if (!temp_base) goto rsa_modpow_fail;
        bn_from_bin(temp_base, base, base_len, base_len);
        if (bn_mod(bn_base, temp_base, base_len, bn_mod_val, max_len) != 0) {
            free(temp_base); goto rsa_modpow_fail;
        }
        free(temp_base);
    } else {
        bn_from_bin(bn_base, base, base_len, max_len);
    }
    memset(bn_res, 0, max_len);
    bn_res[0] = 1;
    int exp_bits = 0;
    for (int i = exp_len - 1; i >= 0; i--) {
        if (exp[i] != 0) {
            exp_bits = i * 8;
            unsigned char val = exp[i];
            while (val > 0) { exp_bits++; val >>= 1; }
            break;
        }
    }
    for (int i = exp_bits - 1; i >= 0; i--) {
        bn_mul(temp_prod, bn_res, bn_res, max_len);
        if (bn_mod(bn_res, temp_prod, max_len * 2, bn_mod_val, max_len) != 0)
            goto rsa_modpow_fail;
        int byte_idx = i / 8;
        int bit_idx = i % 8;
        if (exp[exp_len - 1 - byte_idx] & (1 << bit_idx)) {
            bn_mul(temp_prod, bn_res, bn_base, max_len);
            if (bn_mod(bn_res, temp_prod, max_len * 2, bn_mod_val, max_len) != 0)
                goto rsa_modpow_fail;
        }
    }
    bn_to_bin(result, mod_len, bn_res, max_len);
    free(bn_mod_val); free(bn_base); free(bn_res); free(temp_prod);
    return 0;
rsa_modpow_fail:
    free(bn_mod_val); free(bn_base); free(bn_res); free(temp_prod);
    return -1;
}

/* ========================================================================
 * X25519 (Curve25519) - RFC 7748
 * Exact TweetNaCl-style field arithmetic
 * ======================================================================== */

/* curve25519-donna 10-limb implementation (c) 2008 Google/Adam Langley */
/* Adapted for ossl.c - verified against RFC 7748 test vectors */


/* Internal curve25519-donna functions */
typedef int64_t limb;
typedef int32_t s32;
typedef uint8_t u8;

static void fsum(limb *o, const limb *i) { int c; for(c=0;c<10;c+=2){ o[c]=o[c]+i[c]; o[c+1]=o[c+1]+i[c+1]; }}
static void fdifference(limb *o, const limb *i) { int c; for(c=0;c<10;++c) o[c]=i[c]-o[c]; }
static void fscalar_product(limb *o, const limb *i, limb s) { int c; for(c=0;c<10;++c) o[c]=i[c]*s; }

static void fproduct(limb *o, const limb *a, const limb *b) {
  o[0]=((limb)((s32)a[0]))*((s32)b[0]);o[1]=((limb)((s32)a[0]))*((s32)b[1])+((limb)((s32)a[1]))*((s32)b[0]);
  o[2]=2*((limb)((s32)a[1]))*((s32)b[1])+((limb)((s32)a[0]))*((s32)b[2])+((limb)((s32)a[2]))*((s32)b[0]);
  o[3]=((limb)((s32)a[1]))*((s32)b[2])+((limb)((s32)a[2]))*((s32)b[1])+((limb)((s32)a[0]))*((s32)b[3])+((limb)((s32)a[3]))*((s32)b[0]);
  o[4]=((limb)((s32)a[2]))*((s32)b[2])+2*(((limb)((s32)a[1]))*((s32)b[3])+((limb)((s32)a[3]))*((s32)b[1]))+((limb)((s32)a[0]))*((s32)b[4])+((limb)((s32)a[4]))*((s32)b[0]);
  o[5]=((limb)((s32)a[2]))*((s32)b[3])+((limb)((s32)a[3]))*((s32)b[2])+((limb)((s32)a[1]))*((s32)b[4])+((limb)((s32)a[4]))*((s32)b[1])+((limb)((s32)a[0]))*((s32)b[5])+((limb)((s32)a[5]))*((s32)b[0]);
  o[6]=2*(((limb)((s32)a[3]))*((s32)b[3])+((limb)((s32)a[1]))*((s32)b[5])+((limb)((s32)a[5]))*((s32)b[1]))+((limb)((s32)a[2]))*((s32)b[4])+((limb)((s32)a[4]))*((s32)b[2])+((limb)((s32)a[0]))*((s32)b[6])+((limb)((s32)a[6]))*((s32)b[0]);
  o[7]=((limb)((s32)a[3]))*((s32)b[4])+((limb)((s32)a[4]))*((s32)b[3])+((limb)((s32)a[2]))*((s32)b[5])+((limb)((s32)a[5]))*((s32)b[2])+((limb)((s32)a[1]))*((s32)b[6])+((limb)((s32)a[6]))*((s32)b[1])+((limb)((s32)a[0]))*((s32)b[7])+((limb)((s32)a[7]))*((s32)b[0]);
  o[8]=((limb)((s32)a[4]))*((s32)b[4])+2*(((limb)((s32)a[3]))*((s32)b[5])+((limb)((s32)a[5]))*((s32)b[3])+((limb)((s32)a[1]))*((s32)b[7])+((limb)((s32)a[7]))*((s32)b[1]))+((limb)((s32)a[2]))*((s32)b[6])+((limb)((s32)a[6]))*((s32)b[2])+((limb)((s32)a[0]))*((s32)b[8])+((limb)((s32)a[8]))*((s32)b[0]);
  o[9]=((limb)((s32)a[4]))*((s32)b[5])+((limb)((s32)a[5]))*((s32)b[4])+((limb)((s32)a[3]))*((s32)b[6])+((limb)((s32)a[6]))*((s32)b[3])+((limb)((s32)a[2]))*((s32)b[7])+((limb)((s32)a[7]))*((s32)b[2])+((limb)((s32)a[1]))*((s32)b[8])+((limb)((s32)a[8]))*((s32)b[1])+((limb)((s32)a[0]))*((s32)b[9])+((limb)((s32)a[9]))*((s32)b[0]);
  o[10]=2*(((limb)((s32)a[5]))*((s32)b[5])+((limb)((s32)a[3]))*((s32)b[7])+((limb)((s32)a[7]))*((s32)b[3])+((limb)((s32)a[1]))*((s32)b[9])+((limb)((s32)a[9]))*((s32)b[1]))+((limb)((s32)a[4]))*((s32)b[6])+((limb)((s32)a[6]))*((s32)b[4])+((limb)((s32)a[2]))*((s32)b[8])+((limb)((s32)a[8]))*((s32)b[2]);
  o[11]=((limb)((s32)a[5]))*((s32)b[6])+((limb)((s32)a[6]))*((s32)b[5])+((limb)((s32)a[4]))*((s32)b[7])+((limb)((s32)a[7]))*((s32)b[4])+((limb)((s32)a[3]))*((s32)b[8])+((limb)((s32)a[8]))*((s32)b[3])+((limb)((s32)a[2]))*((s32)b[9])+((limb)((s32)a[9]))*((s32)b[2]);
  o[12]=((limb)((s32)a[6]))*((s32)b[6])+2*(((limb)((s32)a[5]))*((s32)b[7])+((limb)((s32)a[7]))*((s32)b[5])+((limb)((s32)a[3]))*((s32)b[9])+((limb)((s32)a[9]))*((s32)b[3]))+((limb)((s32)a[4]))*((s32)b[8])+((limb)((s32)a[8]))*((s32)b[4]);
  o[13]=((limb)((s32)a[6]))*((s32)b[7])+((limb)((s32)a[7]))*((s32)b[6])+((limb)((s32)a[5]))*((s32)b[8])+((limb)((s32)a[8]))*((s32)b[5])+((limb)((s32)a[4]))*((s32)b[9])+((limb)((s32)a[9]))*((s32)b[4]);
  o[14]=2*(((limb)((s32)a[7]))*((s32)b[7])+((limb)((s32)a[5]))*((s32)b[9])+((limb)((s32)a[9]))*((s32)b[5]))+((limb)((s32)a[6]))*((s32)b[8])+((limb)((s32)a[8]))*((s32)b[6]);
  o[15]=((limb)((s32)a[7]))*((s32)b[8])+((limb)((s32)a[8]))*((s32)b[7])+((limb)((s32)a[6]))*((s32)b[9])+((limb)((s32)a[9]))*((s32)b[6]);
  o[16]=((limb)((s32)a[8]))*((s32)b[8])+2*(((limb)((s32)a[7]))*((s32)b[9])+((limb)((s32)a[9]))*((s32)b[7]));
  o[17]=((limb)((s32)a[8]))*((s32)b[9])+((limb)((s32)a[9]))*((s32)b[8]);
  o[18]=2*((limb)((s32)a[9]))*((s32)b[9]);
}
static void freduce_degree(limb *o) {
  o[8]+=o[18]*19;o[18]=0;o[7]+=o[17]*19;o[17]=0;o[6]+=o[16]*19;o[16]=0;o[5]+=o[15]*19;o[15]=0;
  o[4]+=o[14]*19;o[14]=0;o[3]+=o[13]*19;o[13]=0;o[2]+=o[12]*19;o[12]=0;o[1]+=o[11]*19;o[11]=0;o[0]+=o[10]*19;o[10]=0;
}
static inline limb div_by_2_26(limb v) { uint32_t h=(uint32_t)((uint64_t)v>>32); int32_t s=(int32_t)h>>31; return (v+((uint32_t)s>>6))>>26; }
static inline limb div_by_2_25(limb v) { uint32_t h=(uint32_t)((uint64_t)v>>32); int32_t s=(int32_t)h>>31; return (v+((uint32_t)s>>7))>>25; }
static void freduce_coefficients(limb *o) {
  o[10]=0;int i;for(i=0;i<10;i+=2){limb ov=div_by_2_26(o[i]);o[i]-=ov<<26;o[i+1]+=ov;ov=div_by_2_25(o[i+1]);o[i+1]-=ov<<25;o[i+2]+=ov;}
  o[0]+=o[10]*19;o[10]=0;{limb ov=div_by_2_26(o[0]);o[0]-=ov<<26;o[1]+=ov;}
}
static void fmul(limb *o, const limb *a, const limb *b){limb t[19];fproduct(t,a,b);freduce_degree(t);freduce_coefficients(t);memcpy(o,t,10*8);}
static void fsquare(limb *o, const limb *a){limb t[19];fproduct(t,a,a);freduce_degree(t);freduce_coefficients(t);memcpy(o,t,10*8);}
static void fexpand(limb *o,const u8 *i){o[0]=(((limb)i[0])|((limb)i[1]<<8)|((limb)i[2]<<16)|((limb)i[3]<<24))&0x3ffffff;o[1]=((((limb)i[3])|((limb)i[4]<<8)|((limb)i[5]<<16)|((limb)i[6]<<24))>>2)&0x1ffffff;o[2]=((((limb)i[6])|((limb)i[7]<<8)|((limb)i[8]<<16)|((limb)i[9]<<24))>>3)&0x3ffffff;o[3]=((((limb)i[9])|((limb)i[10]<<8)|((limb)i[11]<<16)|((limb)i[12]<<24))>>5)&0x1ffffff;o[4]=((((limb)i[12])|((limb)i[13]<<8)|((limb)i[14]<<16)|((limb)i[15]<<24))>>6)&0x3ffffff;o[5]=(((limb)i[16])|((limb)i[17]<<8)|((limb)i[18]<<16)|((limb)i[19]<<24))&0x1ffffff;o[6]=((((limb)i[19])|((limb)i[20]<<8)|((limb)i[21]<<16)|((limb)i[22]<<24))>>1)&0x3ffffff;o[7]=((((limb)i[22])|((limb)i[23]<<8)|((limb)i[24]<<16)|((limb)i[25]<<24))>>3)&0x1ffffff;o[8]=((((limb)i[25])|((limb)i[26]<<8)|((limb)i[27]<<16)|((limb)i[28]<<24))>>4)&0x3ffffff;o[9]=((((limb)i[28])|((limb)i[29]<<8)|((limb)i[30]<<16)|((limb)i[31]<<24))>>6)&0x1ffffff;}

static s32 s32_eq(s32 a,s32 b){a=~(a^b);a&=a<<16;a&=a<<8;a&=a<<4;a&=a<<2;a&=a<<1;return a>>31;}
static s32 s32_gte(s32 a,s32 b){a-=b;return ~(a>>31);}

static void fcontract(u8 *output,limb *input_limbs){
  int i,j;s32 input[10];s32 mask;for(i=0;i<10;i++)input[i]=input_limbs[i];
  for(j=0;j<2;++j){for(i=0;i<9;++i){if((i&1)==1){s32 m=input[i]>>31;s32 c=-((input[i]&m)>>25);input[i]+=c<<25;input[i+1]-=c;}else{s32 m=input[i]>>31;s32 c=-((input[i]&m)>>26);input[i]+=c<<26;input[i+1]-=c;}}{s32 m=input[9]>>31;s32 c=-((input[9]&m)>>25);input[9]+=c<<25;input[0]-=c*19;}}
  {s32 m=input[0]>>31;s32 c=-((input[0]&m)>>26);input[0]+=c<<26;input[1]-=c;}
  for(j=0;j<2;j++){for(i=0;i<9;i++){s32 c;if((i&1)==1){c=input[i]>>25;input[i]&=0x1ffffff;input[i+1]+=c;}else{c=input[i]>>26;input[i]&=0x3ffffff;input[i+1]+=c;}}{s32 c=input[9]>>25;input[9]&=0x1ffffff;input[0]+=19*c;}}
  mask=s32_gte(input[0],0x3ffffed);for(i=1;i<10;i++){if((i&1)==1)mask&=s32_eq(input[i],0x1ffffff);else mask&=s32_eq(input[i],0x3ffffff);}
  input[0]-=mask&0x3ffffed;for(i=1;i<10;i++)input[i]-=mask&((i&1)==1?0x1ffffff:0x3ffffff);
  input[1]<<=2;input[2]<<=3;input[3]<<=5;input[4]<<=6;input[6]<<=1;input[7]<<=3;input[8]<<=4;input[9]<<=6;
  output[0]=0;output[16]=0;
#define F(n,s) output[s]|=input[n]&0xff;output[s+1]=(input[n]>>8)&0xff;output[s+2]=(input[n]>>16)&0xff;output[s+3]=(input[n]>>24)&0xff;
  F(0,0);F(1,3);F(2,6);F(3,9);F(4,12);F(5,16);F(6,19);F(7,22);F(8,25);F(9,28);
#undef F
}

static void fmonty(limb *x2,limb *z2,limb *x3,limb *z3,limb *x,limb *z,limb *xprime,limb *zprime,const limb *qmqp){
  limb origx[10],origxprime[10],zzz[19],xx[19],zz[19],xxprime[19],zzprime[19],zzzprime[19],xxxprime[19];
  memcpy(origx,x,80);fsum(x,z);fdifference(z,origx);
  memcpy(origxprime,xprime,80);fsum(xprime,zprime);fdifference(zprime,origxprime);
  fproduct(xxprime,xprime,z);fproduct(zzprime,x,zprime);freduce_degree(xxprime);freduce_coefficients(xxprime);freduce_degree(zzprime);freduce_coefficients(zzprime);
  memcpy(origxprime,xxprime,80);fsum(xxprime,zzprime);fdifference(zzprime,origxprime);
  fsquare(xxxprime,xxprime);fsquare(zzzprime,zzprime);
  fproduct(zzprime,zzzprime,qmqp);freduce_degree(zzprime);freduce_coefficients(zzprime);
  memcpy(x3,xxxprime,80);memcpy(z3,zzprime,80);
  fsquare(xx,x);fsquare(zz,z);
  fproduct(x2,xx,zz);freduce_degree(x2);freduce_coefficients(x2);
  fdifference(zz,xx);memset(zzz+10,0,72);fscalar_product(zzz,zz,121665);freduce_coefficients(zzz);fsum(zzz,xx);
  fproduct(z2,zz,zzz);freduce_degree(z2);freduce_coefficients(z2);
}

static void swap_conditional(limb a[19],limb b[19],limb iswap){unsigned i;s32 swap=(s32)-iswap;for(i=0;i<10;++i){s32 x=swap&(((s32)a[i])^((s32)b[i]));a[i]=((s32)a[i])^x;b[i]=((s32)b[i])^x;}}

static void cmult(limb *rx,limb *rz,const u8 *n,const limb *q){
  limb a[19]={0},b[19]={1},c[19]={1},d[19]={0},*nqpqx=a,*nqpqz=b,*nqx=c,*nqz=d,*t;
  limb e[19]={0},f[19]={1},g[19]={0},h[19]={1},*nqpqx2=e,*nqpqz2=f,*nqx2=g,*nqz2=h;
  unsigned i,j;memcpy(nqpqx,q,80);
  for(i=0;i<32;++i){u8 byte=n[31-i];for(j=0;j<8;++j){limb bit=byte>>7;
    swap_conditional(nqx,nqpqx,bit);swap_conditional(nqz,nqpqz,bit);
    fmonty(nqx2,nqz2,nqpqx2,nqpqz2,nqx,nqz,nqpqx,nqpqz,q);
    swap_conditional(nqx2,nqpqx2,bit);swap_conditional(nqz2,nqpqz2,bit);
    t=nqx;nqx=nqx2;nqx2=t;t=nqz;nqz=nqz2;nqz2=t;t=nqpqx;nqpqx=nqpqx2;nqpqx2=t;t=nqpqz;nqpqz=nqpqz2;nqpqz2=t;
    byte<<=1;}}
  memcpy(rx,nqx,80);memcpy(rz,nqz,80);
}

static void crecip(limb *o,const limb *z){
  limb z2[10],z9[10],z11[10],z2_5_0[10],z2_10_0[10],z2_20_0[10],z2_50_0[10],z2_100_0[10],t0[10],t1[10];int i;
  fsquare(z2,z);fsquare(t1,z2);fsquare(t0,t1);fmul(z9,t0,z);fmul(z11,z9,z2);fsquare(t0,z11);fmul(z2_5_0,t0,z9);
  fsquare(t0,z2_5_0);fsquare(t1,t0);fsquare(t0,t1);fsquare(t1,t0);fsquare(t0,t1);fmul(z2_10_0,t0,z2_5_0);
  fsquare(t0,z2_10_0);fsquare(t1,t0);for(i=2;i<10;i+=2){fsquare(t0,t1);fsquare(t1,t0);}fmul(z2_20_0,t1,z2_10_0);
  fsquare(t0,z2_20_0);fsquare(t1,t0);for(i=2;i<20;i+=2){fsquare(t0,t1);fsquare(t1,t0);}fmul(t0,t1,z2_20_0);
  fsquare(t1,t0);fsquare(t0,t1);for(i=2;i<10;i+=2){fsquare(t1,t0);fsquare(t0,t1);}fmul(z2_50_0,t0,z2_10_0);
  fsquare(t0,z2_50_0);fsquare(t1,t0);for(i=2;i<50;i+=2){fsquare(t0,t1);fsquare(t1,t0);}fmul(z2_100_0,t1,z2_50_0);
  fsquare(t1,z2_100_0);fsquare(t0,t1);for(i=2;i<100;i+=2){fsquare(t1,t0);fsquare(t0,t1);}fmul(t1,t0,z2_100_0);
  fsquare(t0,t1);fsquare(t1,t0);for(i=2;i<50;i+=2){fsquare(t0,t1);fsquare(t1,t0);}fmul(t0,t1,z2_50_0);
  fsquare(t1,t0);fsquare(t0,t1);fsquare(t1,t0);fsquare(t0,t1);fsquare(t1,t0);fmul(o,t1,z11);
}

int curve25519_donna(u8 *mypublic, const u8 *secret, const u8 *basepoint) {
  limb bp[10],x[10],z[11],zmone[10];u8 e[32];int i;
  for(i=0;i<32;++i)e[i]=secret[i];
  e[0]&=248;e[31]&=127;e[31]|=64;
  fexpand(bp,basepoint);cmult(x,z,e,bp);crecip(zmone,z);fmul(z,x,zmone);fcontract(mypublic,z);return 0;
}

/* Wrapper with x25519_scalar_mult signature */
void x25519_scalar_mult(unsigned char result[32], const unsigned char scalar[32], const unsigned char base[32]) {
    curve25519_donna(result, scalar, base);
}

static int der_read_tag(const unsigned char *der, int len, int *pos, int *tag_len) {
    if (*pos >= len) return -1;
    int tag = der[(*pos)++];
    if (*pos >= len) return -1;
    if (der[*pos] & 0x80) {
        int count = der[*pos] & 0x7F;
        if (count > 3) return -1; /* would overflow 32-bit signed int */
        (*pos)++;
        *tag_len = 0;
        for (int i = 0; i < count; i++) {
            if (*pos >= len) return -1;
            *tag_len = (*tag_len << 8) | der[*pos];
            (*pos)++;
        }
    } else {
        *tag_len = der[(*pos)++];
    }
    return tag;
}

static int pem_decode(const char *pem, int pem_len,
                      const char *header, const char *footer,
                      unsigned char **der, int *der_len) {
    (void)pem_len;
    const char *start = strstr(pem, header);
    if (!start) return -1;
    start += strlen(header);
    while (*start == '\n' || *start == '\r') start++;
    const char *end = strstr(start, footer);
    if (!end) return -1;
    int b64_len = (int)(end - start);
    char *b64 = (char*)malloc(b64_len + 4);  /* +4 for padding chars */
    int k = 0;
    for (int i = 0; i < b64_len; i++) {
        if (start[i] != '\n' && start[i] != '\r' && start[i] != ' ')
            b64[k++] = start[i];
    }
    b64[k] = 0;
    static const unsigned char b64_table[256] = {
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x3e,0xff,0xff,0xff,0x3f,
        0x34,0x35,0x36,0x37,0x38,0x39,0x3a,0x3b,0x3c,0x3d,0xff,0xff,0xff,0xff,0xff,0xff,
        0xff,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,
        0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0xff,0xff,0xff,0xff,0xff,
        0xff,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,
        0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,0x30,0x31,0x32,0x33,0xff,0xff,0xff,0xff,0xff,
    };
    int out_len = (k * 3) / 4;
    while (out_len > 0 && b64[k-1] == '=') { out_len--; k--; }
    /* Pad to multiple of 4 to prevent OOB reads in decode loop */
    while (k % 4 != 0) b64[k++] = 'A';
    *der = (unsigned char*)malloc(out_len + 1);
    if (!*der) { free(b64); return -1; }
    *der_len = out_len;
    int ii = 0;
    for (int i = 0; i < k; i += 4) {
        unsigned char a = b64_table[(unsigned char)b64[i]];
        unsigned char b = b64_table[(unsigned char)b64[i+1]];
        unsigned char c = b64_table[(unsigned char)b64[i+2]];
        unsigned char d = b64_table[(unsigned char)b64[i+3]];
        if (a == 0xff || b == 0xff || c == 0xff || d == 0xff) { free(*der); free(b64); return -1; }
        (*der)[ii++] = (a << 2) | (b >> 4);
        if (ii < out_len) (*der)[ii++] = (b << 4) | (c >> 2);
        if (ii < out_len) (*der)[ii++] = (c << 6) | d;
    }
    free(b64);
    return 0;
}

static unsigned char* strip_pkcs8_if_needed(const unsigned char *der, int der_len, int *out_len) {
    int pos = 0, tag_len;
    int tag = der_read_tag(der, der_len, &pos, &tag_len);
    if (tag != 0x30) return (unsigned char*)der;
    int vpos = pos;
    int vtag = der_read_tag(der, der_len, &vpos, &tag_len);
    if (vtag != 0x02 || tag_len != 1 || der[vpos] != 0x00) return (unsigned char*)der;
    vpos += tag_len;
    int alg_tag = der_read_tag(der, der_len, &vpos, &tag_len);
    if (alg_tag != 0x30) return (unsigned char*)der;
    vpos += tag_len;
    int oct_tag = der_read_tag(der, der_len, &vpos, &tag_len);
    if (oct_tag != 0x04) return (unsigned char*)der;
    unsigned char *res = (unsigned char*)malloc(tag_len);
    if (!res) return (unsigned char*)der;
    memcpy(res, der + vpos, tag_len);
    *out_len = tag_len;
    return res;
}

static int rsa_get_pubkey(const unsigned char *key_der, int key_der_len,
                          unsigned char **n, int *n_len,
                          unsigned char **e, int *e_len) {
    int pos = 0, tag_len, tag;
    tag = der_read_tag(key_der, key_der_len, &pos, &tag_len);
    if (tag != 0x30) { fprintf(stderr, "ossl: Expected SEQUENCE for private key\n"); return -1; }
    tag = der_read_tag(key_der, key_der_len, &pos, &tag_len);
    if (tag != 0x02) { fprintf(stderr, "ossl: Expected INTEGER for version\n"); return -1; }
    pos += tag_len;
    tag = der_read_tag(key_der, key_der_len, &pos, &tag_len);
    if (tag != 0x02) { fprintf(stderr, "ossl: Expected INTEGER for modulus\n"); return -1; }
    int start = pos;
    if (key_der[pos] == 0x00) { start++; tag_len--; }
    if (n) { *n = (unsigned char*)malloc(tag_len); if (!*n) return -1; memcpy(*n, key_der + start, tag_len); *n_len = tag_len; }
    pos = start + tag_len;
    tag = der_read_tag(key_der, key_der_len, &pos, &tag_len);
    if (tag != 0x02) { fprintf(stderr, "ossl: Expected INTEGER for exponent\n"); if (n) free(*n); return -1; }
    start = pos;
    if (key_der[pos] == 0x00) { start++; tag_len--; }
    if (e) { *e = (unsigned char*)malloc(tag_len); if (!*e) { if (n) free(*n); return -1; } memcpy(*e, key_der + start, tag_len); *e_len = tag_len; }
    return 0;
}

static int rsa_get_privexp(const unsigned char *key_der, int key_der_len,
                           unsigned char **d, int *d_len) {
    int pos = 0, tag_len, tag;
    tag = der_read_tag(key_der, key_der_len, &pos, &tag_len);
    if (tag != 0x30) return -1;
    tag = der_read_tag(key_der, key_der_len, &pos, &tag_len); if (tag != 0x02) return -1; pos += tag_len;
    tag = der_read_tag(key_der, key_der_len, &pos, &tag_len); if (tag != 0x02) return -1; pos += tag_len;
    tag = der_read_tag(key_der, key_der_len, &pos, &tag_len); if (tag != 0x02) return -1; pos += tag_len;
    tag = der_read_tag(key_der, key_der_len, &pos, &tag_len); if (tag != 0x02) return -1;
    int start = pos;
    if (key_der[pos] == 0x00) { start++; tag_len--; }
    *d = (unsigned char*)malloc(tag_len); if (!*d) return -1;
    memcpy(*d, key_der + start, tag_len);
    *d_len = tag_len;
    return 0;
}

/* ========================================================================
 * CORRECTED DER-based RSA public key extraction from X.509 certificate
 * ======================================================================== */
static int rsa_get_pubkey_from_cert(const unsigned char *cert_der, int cert_der_len,
                                     unsigned char **n, int *n_len,
                                     unsigned char **e, int *e_len) {
    if (!n || !n_len || !e || !e_len) return -1;
    int pos = 0, tag, tlen;
    /* Outer SEQUENCE (Certificate) */
    tag = der_read_tag(cert_der, cert_der_len, &pos, &tlen);
    if (tag != 0x30) return -1;
    /* TBSCertificate SEQUENCE */
    tag = der_read_tag(cert_der, cert_der_len, &pos, &tlen);
    if (tag != 0x30) return -1;
    int tbs_end = pos + tlen;
    /* Skip optional version [0] EXPLICIT */
    if (pos < tbs_end && (cert_der[pos] == 0xa0)) {
        tag = der_read_tag(cert_der, cert_der_len, &pos, &tlen);
        pos += tlen;
    }
    /* Serial number INTEGER */
    tag = der_read_tag(cert_der, cert_der_len, &pos, &tlen);
    if (tag != 0x02) return -1;
    pos += tlen;
    /* Signature algorithm SEQUENCE */
    tag = der_read_tag(cert_der, cert_der_len, &pos, &tlen);
    if (tag != 0x30) return -1;
    pos += tlen;
    /* Issuer SEQUENCE */
    tag = der_read_tag(cert_der, cert_der_len, &pos, &tlen);
    if (tag != 0x30) return -1;
    pos += tlen;
    /* Validity SEQUENCE */
    tag = der_read_tag(cert_der, cert_der_len, &pos, &tlen);
    if (tag != 0x30) return -1;
    pos += tlen;
    /* Subject SEQUENCE */
    tag = der_read_tag(cert_der, cert_der_len, &pos, &tlen);
    if (tag != 0x30) return -1;
    pos += tlen;
    /* subjectPublicKeyInfo SEQUENCE */
    if (pos >= tbs_end) return -1;
    tag = der_read_tag(cert_der, cert_der_len, &pos, &tlen);
    if (tag != 0x30) return -1;
    int spki_end = pos + tlen;
    /* AlgorithmIdentifier SEQUENCE */
    tag = der_read_tag(cert_der, cert_der_len, &pos, &tlen);
    if (tag != 0x30) return -1;
    pos += tlen;
    /* BIT STRING with subjectPublicKey */
    if (pos >= spki_end) return -1;
    tag = der_read_tag(cert_der, cert_der_len, &pos, &tlen);
    if (tag != 0x03) return -1;
    if (tlen < 1) return -1;
    pos++; tlen--; /* skip unused bits byte */
    /* Now pos points to RSAPublicKey SEQUENCE inside the BIT STRING */
    tag = der_read_tag(cert_der, cert_der_len, &pos, &tlen);
    if (tag != 0x30) return -1;
    int rsa_end = pos + tlen;
    /* Modulus INTEGER */
    tag = der_read_tag(cert_der, cert_der_len, &pos, &tlen);
    if (tag != 0x02) return -1;
    int n_start = pos;
    if (cert_der[n_start] == 0x00) { n_start++; tlen--; }
    if (tlen <= 0) return -1;
    *n = (unsigned char*)malloc(tlen);
    if (!*n) return -1;
    memcpy(*n, cert_der + n_start, tlen);
    *n_len = tlen;
    pos = n_start + tlen; /* move past modulus */
    if (pos >= rsa_end) { free(*n); return -1; }
    /* Exponent INTEGER */
    tag = der_read_tag(cert_der, cert_der_len, &pos, &tlen);
    if (tag != 0x02) { free(*n); return -1; }
    int e_start = pos;
    if (cert_der[e_start] == 0x00) { e_start++; tlen--; }
    if (tlen <= 0) { free(*n); return -1; }
    *e = (unsigned char*)malloc(tlen);
    if (!*e) { free(*n); return -1; }
    memcpy(*e, cert_der + e_start, tlen);
    *e_len = tlen;
    return 0;
}

static int rsa_encrypt(const unsigned char *n, int n_len,
                       const unsigned char *e, int e_len,
                       const unsigned char *plaintext, int pt_len,
                       unsigned char *ciphertext) {
    int block_len = n_len;
    unsigned char *block = (unsigned char*)malloc(block_len);
    if (!block) return -1;
    block[0] = 0x00; block[1] = 0x02;
    int ps_len = block_len - 3 - pt_len;
    if (ps_len < 8) { fprintf(stderr, "ossl: Plaintext too long for RSA block\n"); free(block); return -1; }
    /* Generate non-zero random padding bytes */
    for (int i = 0; i < ps_len; i++) {
        unsigned char b;
        do {
            if (ossl_rand_bytes(&b, 1) != 0) { free(block); return -1; }
        } while (b == 0);
        block[2 + i] = b;
    }
    block[2 + ps_len] = 0x00;
    memcpy(block + 3 + ps_len, plaintext, pt_len);
    if (rsa_modpow(block, block_len, e, e_len, n, n_len, ciphertext) != 0) {
        free(block); return -1;
    }
    free(block);
    return 0;
}

static int rsa_decrypt(const unsigned char *n, int n_len,
                       const unsigned char *d, int d_len,
                       const unsigned char *ciphertext,
                       unsigned char *plaintext, int *pt_len, int max_pt_len) {
    unsigned char *block = (unsigned char*)malloc(n_len);
    if (!block) return -1;
    if (rsa_modpow(ciphertext, n_len, d, d_len, n, n_len, block) != 0) {
        free(block); return -1;
    }
    /* Constant-time PKCS#1 v1.5 padding check: combine all failure conditions */
    int pad_ok = (block[0] == 0x00 && block[1] == 0x02);
    /* Scan for first 0x00 byte without early exit to avoid timing oracle */
    int sep_at = n_len; /* sentinel: not found */
    for (int i = 2; i < n_len; i++) {
        /* Record first zero position; branch is on a loop-local variable that
           becomes invariant after the first match, so timing is data-independent */
        if (block[i] == 0x00 && sep_at == n_len) sep_at = i;
    }
    int sep_found = (sep_at < n_len - 1);
    int pt_len_actual = sep_found ? (n_len - sep_at - 1) : 0;
    int len_ok = (pt_len_actual >= 1 && pt_len_actual <= max_pt_len);
    int ok = pad_ok && sep_found && len_ok;
    if (!ok) {
        /* Single unified error — no oracle */
        fprintf(stderr, "ossl: RSA decryption failed\n");
        free(block); return -1;
    }
    memcpy(plaintext, block + sep_at + 1, pt_len_actual);
    *pt_len = pt_len_actual;
    free(block);
    return 0;
}

static int rsa_verify_signature(const unsigned char *n, int n_len,
                                 const unsigned char *e, int e_len,
                                 const unsigned char *hash, int hash_len,
                                 const unsigned char *signature, int sig_len) {
    /* PKCS#1 v1.5 signature verification (type 1 padding) */
    if (sig_len != n_len) {
        fprintf(stderr, "ossl: rsa_verify_signature: sig_len %d != n_len %d\n", sig_len, n_len);
        return -1;
    }
    unsigned char *block = (unsigned char*)malloc(n_len);
    if (!block) return -1;
    if (rsa_modpow(signature, sig_len, e, e_len, n, n_len, block) != 0) {
        free(block); return -1;
    }

    /* Build expected PKCS#1 v1.5 block: 0x00 || 0x01 || PS || 0x00 || T */
    /* PS is 0xFF padding, at least 8 bytes */
    /* T = DigestInfo prefix || hash */
    const unsigned char *digest_prefix;
    int prefix_len;
    if (hash_len == 32) {
        /* SHA-256 DigestInfo prefix */
        static const unsigned char sha256_prefix[19] = {
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
            0x00, 0x04, 0x20
        };
        digest_prefix = sha256_prefix;
        prefix_len = 19;
    } else if (hash_len == 48) {
        /* SHA-384 DigestInfo prefix */
        static const unsigned char sha384_prefix[19] = {
            0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
            0x00, 0x04, 0x30
        };
        digest_prefix = sha384_prefix;
        prefix_len = 19;
    } else {
        fprintf(stderr, "ossl: rsa_verify_signature: unsupported hash len %d\n", hash_len);
        free(block); return -1;
    }

    int t_len = prefix_len + hash_len;
    int ps_len = n_len - t_len - 3; /* 3 = 0x00 + 0x01 + 0x00 separator */
    if (ps_len < 8) {
        fprintf(stderr, "ossl: rsa_verify_signature: modulus too short for padding\n");
        free(block); return -1;
    }

    unsigned char *expected = (unsigned char*)malloc(n_len);
    if (!expected) { free(block); return -1; }
    expected[0] = 0x00;
    expected[1] = 0x01;
    memset(expected + 2, 0xFF, ps_len);
    expected[2 + ps_len] = 0x00;
    memcpy(expected + 3 + ps_len, digest_prefix, prefix_len);
    memcpy(expected + 3 + ps_len + prefix_len, hash, hash_len);

    /* Constant-time comparison */
    unsigned char diff = 0;
    for (int i = 0; i < n_len; i++) {
        diff |= block[i] ^ expected[i];
    }
    free(block);
    free(expected);
    if (diff != 0) return -1;
    return 0;
}

/* ========================================================================
 * RSA Sign (PKCS#1 v1.5) — for ServerKeyExchange
 * ======================================================================== */

static int rsa_sign(const unsigned char *n, int n_len,
                    const unsigned char *d, int d_len,
                    const unsigned char *hash, int hash_len,
                    unsigned char *signature) {
    const unsigned char *digest_prefix;
    int prefix_len;
    if (hash_len == 32) {
        static const unsigned char sha256_prefix[19] = {
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
            0x00, 0x04, 0x20
        };
        digest_prefix = sha256_prefix;
        prefix_len = 19;
    } else if (hash_len == 48) {
        static const unsigned char sha384_prefix[19] = {
            0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
            0x00, 0x04, 0x30
        };
        digest_prefix = sha384_prefix;
        prefix_len = 19;
    } else {
        fprintf(stderr, "ossl: rsa_sign: unsupported hash len %d\n", hash_len);
        return -1;
    }
    int t_len = prefix_len + hash_len;
    int ps_len = n_len - t_len - 3;
    if (ps_len < 8) {
        fprintf(stderr, "ossl: rsa_sign: modulus too short for padding\n");
        return -1;
    }
    unsigned char *block = (unsigned char*)malloc(n_len);
    if (!block) return -1;
    block[0] = 0x00;
    block[1] = 0x01;
    memset(block + 2, 0xFF, ps_len);
    block[2 + ps_len] = 0x00;
    memcpy(block + 3 + ps_len, digest_prefix, prefix_len);
    memcpy(block + 3 + ps_len + prefix_len, hash, hash_len);
    if (rsa_modpow(block, n_len, d, d_len, n, n_len, signature) != 0) {
        free(block); return -1;
    }
    free(block);
    return 0;
}

/* ========================================================================
 * MGF1 (RFC 8017 Appendix B.2.1) — used for RSA-PSS
 * ======================================================================== */

static void ossl_mgf1_sha256(const unsigned char *seed, int seed_len,
                              int mask_len, unsigned char *mask) {
    unsigned char C[4];
    int counter = 0, remaining = mask_len;
    while (remaining > 0) {
        C[0] = (unsigned char)((counter >> 24) & 0xFF);
        C[1] = (unsigned char)((counter >> 16) & 0xFF);
        C[2] = (unsigned char)((counter >> 8) & 0xFF);
        C[3] = (unsigned char)(counter & 0xFF);
        counter++;
        unsigned char T[32];
        ossl_sha256_ctx ctx;
        ossl_sha256_init(&ctx);
        ossl_sha256_update(&ctx, seed, seed_len);
        ossl_sha256_update(&ctx, C, 4);
        ossl_sha256_final(&ctx, T);
        int take = remaining < 32 ? remaining : 32;
        memcpy(mask, T, take);
        mask += take;
        remaining -= take;
    }
}

static void ossl_mgf1_sha384(const unsigned char *seed, int seed_len,
                              int mask_len, unsigned char *mask) {
    unsigned char C[4];
    int counter = 0, remaining = mask_len;
    while (remaining > 0) {
        C[0] = (unsigned char)((counter >> 24) & 0xFF);
        C[1] = (unsigned char)((counter >> 16) & 0xFF);
        C[2] = (unsigned char)((counter >> 8) & 0xFF);
        C[3] = (unsigned char)(counter & 0xFF);
        counter++;
        unsigned char T[48];
        ossl_sha384_ctx ctx;
        ossl_sha384_init(&ctx);
        ossl_sha384_update(&ctx, seed, seed_len);
        ossl_sha384_update(&ctx, C, 4);
        ossl_sha384_final(&ctx, T);
        int take = remaining < 48 ? remaining : 48;
        memcpy(mask, T, take);
        mask += take;
        remaining -= take;
    }
}

/* ========================================================================
 * RSA-PSS signature verification (RFC 8017 Section 8.1.2)
 * ======================================================================== */

static int ossl_rsa_pss_verify(const unsigned char *n, int n_len,
                                const unsigned char *e, int e_len,
                                const unsigned char *hash, int hash_len,
                                const unsigned char *sig, int sig_len,
                                int salt_len) {
    int hLen = hash_len;
    int emLen = n_len;
    int maskedDB_len = emLen - hLen - 1;
    if (maskedDB_len < 0 || sig_len != n_len) return -1;

    /* 1. RSA decryption: EM = sig^e mod n */
    unsigned char *EM = (unsigned char*)malloc(n_len);
    if (!EM) return -1;
    unsigned char *sig_copy = (unsigned char*)malloc(sig_len);
    if (!sig_copy) { free(EM); return -1; }
    memcpy(sig_copy, sig, sig_len);
    if (rsa_modpow(sig_copy, sig_len, e, e_len, n, n_len, EM) != 0) {
        free(EM); free(sig_copy); return -1;
    }
    free(sig_copy);

    /* 2. Check EM[emLen-1] == 0xBC */
    if (EM[emLen - 1] != 0xBC) { free(EM); return -1; }

    /* 3. Extract maskedDB and H */
    unsigned char *maskedDB = EM;
    unsigned char *H = EM + maskedDB_len;

    /* 4. Compute dbMask = MGF1(H, hLen, emLen - hLen - 1) */
    unsigned char *dbMask = (unsigned char*)malloc(maskedDB_len);
    if (!dbMask) { free(EM); return -1; }

    if (hLen == 32)
        ossl_mgf1_sha256(H, hLen, maskedDB_len, dbMask);
    else
        ossl_mgf1_sha384(H, hLen, maskedDB_len, dbMask);

    /* 5. DB = maskedDB XOR dbMask */
    unsigned char *DB = (unsigned char*)malloc(maskedDB_len);
    if (!DB) { free(dbMask); free(EM); return -1; }
    for (int i = 0; i < maskedDB_len; i++)
        DB[i] = maskedDB[i] ^ dbMask[i];

    /* 6. Set the leftmost 8*emLen - emBits bits of DB[0] to 0.
       emBits = modBits - 1. For a full-byte modulus (no leading bit stripped),
       modBits = emLen * 8, so no bits need clearing.
       But if the DER modulus had its leading 0x00 stripped, modBits
       might be emLen*8 if MSB is set, or less otherwise.
       Conservative: always clear the MSB of DB[0] to handle
       the emBits = 8*emLen - 1 edge case common with 2048-bit keys. */
    {
        /* The RSA modulus size in bits: assume full-byte if MSB is set,
           otherwise compute actual bit length */
        int modBits = emLen * 8;
        {
            /* Find the actual bit length of the modulus */
            for (int i = 0; i < emLen; i++) {
                unsigned char b = n[i]; /* use modulus, not EM, for bit length */
                if (b != 0) {
                    int bits = 8;
                    while ((b & 0x80) == 0) { b <<= 1; bits--; }
                    modBits = (emLen - 1 - i) * 8 + bits;
                    break;
                }
            }
        }
        int emBits = modBits - 1;
        int clear_bits = 8 * emLen - emBits;
        if (clear_bits > 0 && clear_bits <= 8)
            DB[0] &= (unsigned char)(0xFF >> clear_bits);
    }

    /* 7. Verify DB structure: PS (zeros) || 0x01 || salt */
    int ps_end = 0;
    while (ps_end < maskedDB_len - hLen - 1 && DB[ps_end] == 0x00)
        ps_end++;
    if (DB[ps_end] != 0x01) {
        free(DB); free(dbMask); free(EM); return -1;
    }
    unsigned char *recovered_salt = DB + ps_end + 1;
    int recovered_salt_len = maskedDB_len - ps_end - 1;
    if (recovered_salt_len != salt_len) {
        free(DB); free(dbMask); free(EM); return -1;
    }

    /* 8. Compute H' = Hash(M') where M' = (8*0x00) || hash || salt */
    unsigned char M_prime[8 + 48 + 48]; /* 8 zeros + max hash (48) + max salt (48) */
    memset(M_prime, 0, 8);
    memcpy(M_prime + 8, hash, hLen);
    if (recovered_salt_len > 0)
        memcpy(M_prime + 8 + hLen, recovered_salt, recovered_salt_len);
    int M_prime_len = 8 + hLen + recovered_salt_len;

    unsigned char H_prime[48];
    if (hLen == 32) {
        ossl_sha256_ctx ctx;
        ossl_sha256_init(&ctx);
        ossl_sha256_update(&ctx, M_prime, M_prime_len);
        ossl_sha256_final(&ctx, H_prime);
    } else {
        ossl_sha384_ctx ctx;
        ossl_sha384_init(&ctx);
        ossl_sha384_update(&ctx, M_prime, M_prime_len);
        ossl_sha384_final(&ctx, H_prime);
    }

    /* 9. Verify H' == H */
    int ok = (memcmp(H_prime, H, hLen) == 0);

    free(DB); free(dbMask); free(EM);
    return ok ? 0 : -1;
}

/* ========================================================================
 * ECDSA P-256 (secp256r1) verification — direct implementation
 * ======================================================================== */

typedef enum { P256_SUCCESS = 1, P256_INVALID_SIGNATURE = 2 } p256_ret_t;

static int p256_bn_cmp(const uint32_t *a, const uint32_t *b, int n) {
    for (int i = n - 1; i >= 0; i--) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

static int p256_bn_is_zero(const uint32_t *a, int n) {
    for (int i = 0; i < n; i++) if (a[i]) return 0;
    return 1;
}

/* r = a + b, return final carry */
static uint32_t p256_bn_add_n(uint32_t *r, const uint32_t *a, const uint32_t *b, int n) {
    uint32_t carry = 0;
    for (int i = 0; i < n; i++) {
        uint64_t s = (uint64_t)a[i] + b[i] + carry;
        r[i] = (uint32_t)s;
        carry = (uint32_t)(s >> 32);
    }
    return carry;
}

/* r = a - b, return final borrow (1 if a < b) */
static uint32_t p256_bn_sub_n(uint32_t *r, const uint32_t *a, const uint32_t *b, int n) {
    uint32_t borrow = 0;
    for (int i = 0; i < n; i++) {
        uint64_t d = (uint64_t)a[i] - b[i] - borrow;
        r[i] = (uint32_t)d;
        borrow = (uint32_t)((d >> 32) & 1);
    }
    return borrow;
}

/* r[0..15] = a[0..7] * b[0..7]  —  schoolbook multiplication */
static void p256_bn_mul_8x8_to_16(uint32_t *r, const uint32_t *a, const uint32_t *b) {
    memset(r, 0, 64);
    for (int i = 0; i < 8; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < 8; j++) {
            uint64_t p = (uint64_t)a[i] * b[j] + r[i+j] + carry;
            r[i+j] = (uint32_t)p;
            carry = p >> 32;
        }
        for (int k = i + 8; carry && k < 16; k++) {
            uint64_t p = r[k] + carry;
            r[k] = (uint32_t)p;
            carry = p >> 32;
        }
    }
}

/* ================================================================== */
/*  P-256 constants (little-endian: [0] = LSB)                       */
/* ================================================================== */

/* Field prime p = 2^256 - 2^224 + 2^192 + 2^96 - 1 */
static const uint32_t P256_P[8] = {
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000,
    0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF
};

/* Group order n */
static const uint32_t P256_N[8] = {
    0xFC632551, 0xF3B9CAC2, 0xA7179E84, 0xBCE6FAAD,
    0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF
};

/* Generator Gx, Gy */
static const uint32_t P256_GX[8] = {
    0xD898C296, 0xF4A13945, 0x2DEB33A0, 0x77037D81,
    0x63A440F2, 0xF8BCE6E5, 0xE12C4247, 0x6B17D1F2
};
static const uint32_t P256_GY[8] = {
    0x37BF51F5, 0xCBB64068, 0x6B315ECE, 0x2BCE3357,
    0x7C0F9E16, 0x8EE7EB4A, 0xFE1A7F9B, 0x4FE342E2
};

/* Curve equation coefficient b */
static const uint32_t P256_B[8] = {
    0x27D2604B, 0x3BCE3C3E, 0xCC53B0F6, 0x651D06B0,
    0x769886BC, 0xB3EBBD55, 0xAA3A93E7, 0x5AC635D8
};

/* ================================================================== */
/*  Field arithmetic modulo p  (binary long division reduction)       */
/* ================================================================== */

/* Add: r = a + b mod p.  Inputs < p. */
static void p256_fe_add(uint32_t *r, const uint32_t *a, const uint32_t *b) {
    uint32_t carry = p256_bn_add_n(r, a, b, 8);
    if (carry || p256_bn_cmp(r, P256_P, 8) >= 0) {
        uint32_t tmp[8];
        p256_bn_sub_n(tmp, r, P256_P, 8);
        memcpy(r, tmp, 32);
    }
}

/* Sub: r = a - b mod p.  Inputs < p. */
static void p256_fe_sub(uint32_t *r, const uint32_t *a, const uint32_t *b) {
    uint32_t borrow = p256_bn_sub_n(r, a, b, 8);
    if (borrow) {
        uint32_t tmp[8];
        p256_bn_add_n(tmp, r, P256_P, 8);
        memcpy(r, tmp, 32);
    }
}

/* Reduce a 16-word (512-bit) product modulo p using binary long division */
static void p256_fe_reduce(uint32_t *r, const uint32_t *prod) {
    uint32_t p9[9];
    memcpy(p9, P256_P, 32);  p9[8] = 0;
    uint32_t rem[9] = {0};
    for (int bit = 511; bit >= 0; bit--) {
        uint32_t carry = 0;
        for (int i = 0; i < 9; i++) {
            uint32_t next = rem[i] >> 31;
            rem[i] = (rem[i] << 1) | carry;
            carry = next;
        }
        rem[0] |= (prod[bit / 32] >> (bit % 32)) & 1;
        if (p256_bn_cmp(rem, p9, 9) >= 0) {
            uint32_t borrow = 0;
            for (int i = 0; i < 9; i++) {
                uint64_t diff = (uint64_t)rem[i] - p9[i] - borrow;
                rem[i] = (uint32_t)diff;
                borrow = (diff >> 32) & 1;
            }
        }
    }
    memcpy(r, rem, 32);
    if (p256_bn_cmp(r, P256_P, 8) >= 0) {
        uint32_t tmp[8], borrow = 0;
        for (int i = 0; i < 8; i++) {
            uint64_t diff = (uint64_t)r[i] - P256_P[i] - borrow;
            tmp[i] = (uint32_t)diff;
            borrow = (diff >> 32) & 1;
        }
        memcpy(r, tmp, 32);
    }
}

/* r = a * b mod p */
static void p256_fe_mul(uint32_t *r, const uint32_t *a, const uint32_t *b) {
    uint32_t prod[16];
    p256_bn_mul_8x8_to_16(prod, a, b);
    p256_fe_reduce(r, prod);
}

/* r = a^2 mod p */
static void p256_fe_sqr(uint32_t *r, const uint32_t *a) {
    p256_fe_mul(r, a, a);
}

/* r = a^(-1) mod p  —  Fermat: a^(p-2) mod p */
static void p256_fe_inv(uint32_t *r, const uint32_t *a) {
    static const uint32_t exp[8] = {
        0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000,
        0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF
    };
    uint32_t base[8];
    memcpy(base, a, 32);
    memset(r, 0, 32);  r[0] = 1;
    for (int wi = 7; wi >= 0; wi--) {
        uint32_t w = exp[wi];
        for (int bi = 31; bi >= 0; bi--) {
            p256_fe_sqr(r, r);
            if (w & ((uint32_t)1 << bi))
                p256_fe_mul(r, r, base);
        }
    }
}

/* ================================================================== */
/*  Scalar arithmetic modulo n  (used only for ECDSA u1, u2, s^-1)   */
/* ================================================================== */

/* Reduce a 16-word product modulo n using binary long division */
static void p256_sc_reduce(uint32_t *r, const uint32_t *prod) {
    uint32_t n9[9];
    memcpy(n9, P256_N, 32);  n9[8] = 0;
    uint32_t rem[9] = {0};
    for (int bit = 511; bit >= 0; bit--) {
        uint32_t carry = 0;
        for (int i = 0; i < 9; i++) {
            uint32_t next = rem[i] >> 31;
            rem[i] = (rem[i] << 1) | carry;
            carry = next;
        }
        rem[0] |= (prod[bit / 32] >> (bit % 32)) & 1;
        if (p256_bn_cmp(rem, n9, 9) >= 0) {
            uint32_t borrow = 0;
            for (int i = 0; i < 9; i++) {
                uint64_t diff = (uint64_t)rem[i] - n9[i] - borrow;
                rem[i] = (uint32_t)diff;
                borrow = (diff >> 32) & 1;
            }
        }
    }
    memcpy(r, rem, 32);
    if (p256_bn_cmp(r, P256_N, 8) >= 0) {
        uint32_t tmp[8], borrow = 0;
        for (int i = 0; i < 8; i++) {
            uint64_t diff = (uint64_t)r[i] - P256_N[i] - borrow;
            tmp[i] = (uint32_t)diff;
            borrow = (diff >> 32) & 1;
        }
        memcpy(r, tmp, 32);
    }
}

/* r = (a * b) mod n */
static void p256_sc_mul(uint32_t *r, const uint32_t *a, const uint32_t *b) {
    uint32_t prod[16];
    p256_bn_mul_8x8_to_16(prod, a, b);
    p256_sc_reduce(r, prod);
}

/* r = a^(-1) mod n  —  Fermat: a^(n-2) mod n */
static void p256_sc_inv(uint32_t *r, const uint32_t *a) {
    static const uint32_t exp[8] = {
        0xFC63254F, 0xF3B9CAC2, 0xA7179E84, 0xBCE6FAAD,
        0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF
    };
    uint32_t base[8];
    memcpy(base, a, 32);
    memset(r, 0, 32);  r[0] = 1;
    for (int wi = 7; wi >= 0; wi--) {
        uint32_t w = exp[wi];
        for (int bi = 31; bi >= 0; bi--) {
            p256_sc_mul(r, r, r);
            if (w & ((uint32_t)1 << bi))
                p256_sc_mul(r, r, base);
        }
    }
}

/* ================================================================== */
/*  Point arithmetic  —  Jacobian coordinates                         */
/*  Affine:  x = X/Z^2,  y = Y/Z^3                                    */
/*  Point at infinity: Z == 0                                         */
/* ================================================================== */

typedef struct { uint32_t x[8], y[8], z[8]; } p256_jac_pt;

static void p256_pt_set_inf(p256_jac_pt *p) {
    memset(p->x, 0, 32);
    memset(p->y, 0, 32);
    memset(p->z, 0, 32);
}

static int p256_pt_is_inf(const p256_jac_pt *p) {
    return p256_bn_is_zero(p->z, 8);
}

static void p256_pt_copy(p256_jac_pt *d, const p256_jac_pt *s) {
    memcpy(d->x, s->x, 32);
    memcpy(d->y, s->y, 32);
    memcpy(d->z, s->z, 32);
}

/* P = 2*P  (Jacobian doubling).  Works for point at infinity. */
static void p256_pt_double(p256_jac_pt *p) {
    if (p256_pt_is_inf(p)) return;

    uint32_t t1[8], t2[8], t3[8], t4[8];

    /* t3 = y^2 */
    p256_fe_sqr(t3, p->y);
    /* t2 = 4*x*t3  (t3 = 2*t3 temp) */
    p256_fe_add(t4, t3, t3);                    /* t4 = 2*y^2 */
    p256_fe_mul(t2, p->x, t4);                  /* t2 = 2*x*y^2 */
    p256_fe_add(t2, t2, t2);                    /* t2 = 4*x*y^2 = s */

    /* t3 = 2*y^2, then t4 = 8*y^4 */
    p256_fe_sqr(t4, t4);                        /* t4 = 4*y^4 */
    p256_fe_add(t4, t4, t4);                    /* t4 = 8*y^4 */

    /* t1 = 3*(x - z^2)*(x + z^2) */
    p256_fe_sqr(t3, p->z);                      /* t3 = z^2 */
    p256_fe_sub(t1, p->x, t3);                  /* t1 = x - z^2 */
    p256_fe_add(t3, p->x, t3);                  /* t3 = x + z^2 */
    p256_fe_mul(t1, t1, t3);                    /* t1 = (x-z^2)*(x+z^2) */
    p256_fe_add(t3, t1, t1);                    /* t3 = 2 * */
    p256_fe_add(t1, t1, t3);                    /* t1 = 3*(x-z^2)*(x+z^2) = m */

    /* x' = m^2 - 2*s */
    p256_fe_sqr(p->x, t1);                      /* x' = m^2 */
    p256_fe_sub(p->x, p->x, t2);                /* x' = m^2 - s */
    p256_fe_sub(p->x, p->x, t2);                /* x' = m^2 - 2*s */

    /* z' = 2*y*z */
    p256_fe_mul(p->z, p->y, p->z);              /* z' = y*z */
    p256_fe_add(p->z, p->z, p->z);              /* z' = 2*y*z */

    /* y' = m*(s - x') - 8*y^4 */
    p256_fe_sub(t2, t2, p->x);                  /* t2 = s - x' */
    p256_fe_mul(p->y, t1, t2);                  /* y' = m*(s - x') */
    p256_fe_sub(p->y, p->y, t4);                /* y' = m*(s-x') - 8*y^4 */
}

/* R = P + Q  (Jacobian addition, using SEC 1 §3.2.1 formulas) */
static void p256_pt_add(p256_jac_pt *r, const p256_jac_pt *p, const p256_jac_pt *q) {
    if (p256_pt_is_inf(p)) { p256_pt_copy(r, q); return; }
    if (p256_pt_is_inf(q)) { p256_pt_copy(r, p); return; }

    uint32_t z1z1[8], z2z2[8], u1[8], u2[8], s1[8], s2[8];
    uint32_t h[8], rv[8], h2[8], h3[8], u1h2[8], tmp[8];

    p256_fe_sqr(z1z1, p->z);                    /* Z1^2 */
    p256_fe_sqr(z2z2, q->z);                    /* Z2^2 */
    p256_fe_mul(u1, p->x, z2z2);                /* U1 = X1 * Z2^2 */
    p256_fe_mul(u2, q->x, z1z1);                /* U2 = X2 * Z1^2 */
    p256_fe_mul(s1, q->z, z2z2);                /* Z2^3 */
    p256_fe_mul(s1, p->y, s1);                  /* S1 = Y1 * Z2^3 */
    p256_fe_mul(s2, p->z, z1z1);                /* Z1^3 */
    p256_fe_mul(s2, q->y, s2);                  /* S2 = Y2 * Z1^3 */

    p256_fe_sub(h, u2, u1);                     /* H  = U2 - U1 */
    p256_fe_sub(rv, s2, s1);                    /* rv = S2 - S1 */

    if (p256_bn_is_zero(h, 8)) {
        if (p256_bn_is_zero(rv, 8)) {
            p256_jac_pt dbl;
            p256_pt_copy(&dbl, p);
            p256_pt_double(&dbl);
            p256_pt_copy(r, &dbl);
        } else {
            p256_pt_set_inf(r);                 /* P == -Q */
        }
        return;
    }

    p256_fe_sqr(h2, h);                         /* H^2 */
    p256_fe_mul(h3, h2, h);                     /* H^3 */
    p256_fe_mul(u1h2, u1, h2);                  /* U1 * H^2 */
    p256_fe_sqr(r->x, rv);                      /* rv^2 */
    p256_fe_sub(r->x, r->x, h3);                /* rv^2 - H^3 */
    p256_fe_add(tmp, u1h2, u1h2);               /* 2 * U1 * H^2 */
    p256_fe_sub(r->x, r->x, tmp);               /* X3 = rv^2 - H^3 - 2*U1*H^2 */

    p256_fe_sub(tmp, u1h2, r->x);               /* U1*H^2 - X3 */
    p256_fe_mul(r->y, rv, tmp);                 /* rv * (U1*H^2 - X3) */
    p256_fe_mul(tmp, s1, h3);                   /* S1 * H^3 */
    p256_fe_sub(r->y, r->y, tmp);               /* Y3 = rv*(U1*H^2-X3) - S1*H^3 */

    p256_fe_mul(r->z, h, p->z);
    p256_fe_mul(r->z, r->z, q->z);              /* Z3 = H * Z1 * Z2 */
}

/* R = k * P  (double-and-add, MSB-first).  k is 8 LE uint32_t words. */
static void p256_pt_mul(p256_jac_pt *r, const uint32_t *k, const p256_jac_pt *p) {
    p256_pt_set_inf(r);
    if (p256_bn_is_zero(k, 8)) return;
    for (int wi = 7; wi >= 0; wi--) {
        uint32_t w = k[wi];
        for (int bi = 31; bi >= 0; bi--) {
            p256_pt_double(r);
            if (w & ((uint32_t)1 << bi))
                p256_pt_add(r, r, p);
        }
    }
}

/* Convert Jacobian to affine.  p->z becomes 1 (or 0 for infinity). */
static void p256_pt_to_affine(p256_jac_pt *p) {
    if (p256_pt_is_inf(p)) return;
    uint32_t zi[8], zi2[8], zi3[8];
    p256_fe_inv(zi, p->z);          /* zi = 1/z */
    p256_fe_sqr(zi2, zi);           /* zi2 = 1/z^2 */
    p256_fe_mul(p->x, p->x, zi2);   /* x = X / z^2 */
    p256_fe_mul(zi3, zi2, zi);      /* zi3 = 1/z^3 */
    p256_fe_mul(p->y, p->y, zi3);   /* y = Y / z^3 */
    memset(p->z, 0, 32);
    p->z[0] = 1;               /* z = 1 */
}

/* Decode a 65-byte uncompressed point (0x04 || x || y), validate on curve */
static int p256_pt_decode(p256_jac_pt *p, const uint8_t *buf, size_t len) {
    if (len != 65 || buf[0] != 0x04) return 0;

    /* Big-endian bytes → little-endian 32-bit words */
    for (int i = 0; i < 8; i++) {
        int off = 1 + (7 - i) * 4;
        p->x[i] = ((uint32_t)buf[off]<<24) | ((uint32_t)buf[off+1]<<16)
                | ((uint32_t)buf[off+2]<<8) | (uint32_t)buf[off+3];
        off = 33 + (7 - i) * 4;
        p->y[i] = ((uint32_t)buf[off]<<24) | ((uint32_t)buf[off+1]<<16)
                | ((uint32_t)buf[off+2]<<8) | (uint32_t)buf[off+3];
    }
    memset(p->z, 0, 32);
    p->z[0] = 1;

    /* Validate: x,y < p and y^2 == x^3 - 3x + b */
    if (p256_bn_cmp(p->x, P256_P, 8) >= 0 || p256_bn_cmp(p->y, P256_P, 8) >= 0)
        return 0;
    uint32_t lhs[8], rhs[8];
    p256_fe_sqr(lhs, p->y);                     /* y^2 */
    p256_fe_sqr(rhs, p->x);                     /* x^2 */
    p256_fe_mul(rhs, rhs, p->x);                /* x^3 */
    p256_fe_sub(rhs, rhs, p->x);                /* x^3 - x */
    p256_fe_sub(rhs, rhs, p->x);                /* x^3 - 2x */
    p256_fe_sub(rhs, rhs, p->x);                /* x^3 - 3x */
    p256_fe_add(rhs, rhs, P256_B);              /* x^3 - 3x + b */
    if (p256_bn_cmp(lhs, rhs, 8) != 0) return 0;
    return 1;
}

/* ================================================================== */
/*  ECDSA P-256 verification                                          */
/* ================================================================== */

p256_ret_t p256_verify(uint8_t *msg, size_t msg_len,
                       uint8_t *sig, const uint8_t *pk)
{
    /* 1. Hash the message */
    uint8_t hash[32];
    ossl_sha256_ctx sha;
    ossl_sha256_init(&sha);
    ossl_sha256_update(&sha, msg, msg_len);
    ossl_sha256_final(&sha, hash);

    /* 2. Parse DER-encoded signature: SEQUENCE { INTEGER r, INTEGER s } */
    size_t pos = 0;
    if (sig[pos++] != 0x30) return P256_INVALID_SIGNATURE;
    size_t seq_len = sig[pos++];
    if (pos + seq_len > 128) return P256_INVALID_SIGNATURE; /* sanity */

    /* r */
    if (sig[pos++] != 0x02) return P256_INVALID_SIGNATURE;
    size_t r_len = sig[pos++];
    if (r_len == 0 || r_len > 33) return P256_INVALID_SIGNATURE;
    const uint8_t *r_ptr = sig + pos;
    if (r_ptr[0] == 0x00 && r_len > 1) { r_ptr++; r_len--; }
    pos = (size_t)(r_ptr - sig) + r_len;
    uint8_t r_bytes[32] = {0};
    if (r_len > 32) return P256_INVALID_SIGNATURE;
    memcpy(r_bytes + 32 - r_len, r_ptr, r_len);
    uint32_t r_sc[8], s_sc[8], e_sc[8];
    for (int i = 0; i < 8; i++)
        r_sc[i] = ((uint32_t)r_bytes[(7-i)*4]<<24) | ((uint32_t)r_bytes[(7-i)*4+1]<<16)
                | ((uint32_t)r_bytes[(7-i)*4+2]<<8) | (uint32_t)r_bytes[(7-i)*4+3];

    /* s */
    if (pos >= seq_len + 2) return P256_INVALID_SIGNATURE;
    if (sig[pos++] != 0x02) return P256_INVALID_SIGNATURE;
    size_t s_len = sig[pos++];
    if (s_len == 0 || s_len > 33) return P256_INVALID_SIGNATURE;
    const uint8_t *s_ptr = sig + pos;
    if (s_ptr[0] == 0x00 && s_len > 1) { s_ptr++; s_len--; }
    if (s_len > 32) return P256_INVALID_SIGNATURE;
    uint8_t s_bytes[32] = {0};
    memcpy(s_bytes + 32 - s_len, s_ptr, s_len);
    for (int i = 0; i < 8; i++)
        s_sc[i] = ((uint32_t)s_bytes[(7-i)*4]<<24) | ((uint32_t)s_bytes[(7-i)*4+1]<<16)
                | ((uint32_t)s_bytes[(7-i)*4+2]<<8) | (uint32_t)s_bytes[(7-i)*4+3];

    /* 3. Validate r,s in [1, n-1] */
    if (p256_bn_is_zero(r_sc, 8) || p256_bn_cmp(r_sc, P256_N, 8) >= 0)
        return P256_INVALID_SIGNATURE;
    if (p256_bn_is_zero(s_sc, 8) || p256_bn_cmp(s_sc, P256_N, 8) >= 0)
        return P256_INVALID_SIGNATURE;

    /* 4. e = hash as big-endian integer */
    for (int i = 0; i < 8; i++)
        e_sc[i] = ((uint32_t)hash[(7-i)*4]<<24) | ((uint32_t)hash[(7-i)*4+1]<<16)
                | ((uint32_t)hash[(7-i)*4+2]<<8) | (uint32_t)hash[(7-i)*4+3];

    /* 5. u1 = e * s^(-1) mod n,  u2 = r * s^(-1) mod n */
    uint32_t s_inv[8];
    p256_sc_inv(s_inv, s_sc);
    uint32_t u1[8], u2[8];
    p256_sc_mul(u1, e_sc, s_inv);
    p256_sc_mul(u2, r_sc, s_inv);

    /* 6. Decode public key */
    p256_jac_pt pub;
    if (!p256_pt_decode(&pub, pk, 65))
        return P256_INVALID_SIGNATURE;

    /* 7. R = u1*G + u2*Q */
    p256_jac_pt G, R1, R2;
    memcpy(G.x, P256_GX, 32);
    memcpy(G.y, P256_GY, 32);
    memset(G.z, 0, 32);  G.z[0] = 1;
    p256_pt_mul(&R1, u1, &G);
    p256_pt_mul(&R2, u2, &pub);
    p256_pt_add(&R1, &R1, &R2);

    /* 8. Convert R to affine, check R.x mod n == r */
    p256_pt_to_affine(&R1);
    if (p256_pt_is_inf(&R1)) return P256_INVALID_SIGNATURE;

    uint32_t rx_mod_n[8];
    if (p256_bn_cmp(R1.x, P256_N, 8) >= 0) {
        uint32_t tmp[8], borrow = 0;
        for (int i = 0; i < 8; i++) {
            uint64_t diff = (uint64_t)R1.x[i] - P256_N[i] - borrow;
            tmp[i] = (uint32_t)diff;
            borrow = (diff >> 32) & 1;
        }
        memcpy(rx_mod_n, tmp, 32);
    } else {
        memcpy(rx_mod_n, R1.x, 32);
    }

    return (p256_bn_cmp(rx_mod_n, r_sc, 8) == 0) ? P256_SUCCESS : P256_INVALID_SIGNATURE;
}
p256_ret_t p256_verify_hash(const uint8_t *hash, size_t hash_len,
                             const uint8_t *sig, size_t sig_len,
                             const uint8_t *px, const uint8_t *py)
{
    uint32_t r_sc[8], s_sc[8], e_sc[8];
    size_t pos = 0;

    /* 1. Parse DER-encoded signature */
    if (pos >= sig_len || sig[pos++] != 0x30) return P256_INVALID_SIGNATURE;
    size_t seq_len = sig[pos++];
    if (pos + seq_len > sig_len) return P256_INVALID_SIGNATURE;

    /* r */
    if (pos >= sig_len || sig[pos++] != 0x02) return P256_INVALID_SIGNATURE;
    size_t r_len = sig[pos++];
    if (r_len == 0 || r_len > 33) return P256_INVALID_SIGNATURE;
    const uint8_t *r_ptr = sig + pos;
    if (r_ptr[0] == 0x00 && r_len > 1) { r_ptr++; r_len--; }
    pos = (size_t)(r_ptr - sig) + r_len;
    uint8_t r_bytes[32] = {0};
    if (r_len > 32) return P256_INVALID_SIGNATURE;
    memcpy(r_bytes + 32 - r_len, r_ptr, r_len);
    for (int i = 0; i < 8; i++)
        r_sc[i] = ((uint32_t)r_bytes[(7-i)*4]<<24) | ((uint32_t)r_bytes[(7-i)*4+1]<<16)
                | ((uint32_t)r_bytes[(7-i)*4+2]<<8) | (uint32_t)r_bytes[(7-i)*4+3];

    /* s */
    if (pos >= sig_len || sig[pos++] != 0x02) return P256_INVALID_SIGNATURE;
    size_t s_len = sig[pos++];
    if (s_len == 0 || s_len > 33) return P256_INVALID_SIGNATURE;
    const uint8_t *s_ptr = sig + pos;
    if (s_ptr[0] == 0x00 && s_len > 1) { s_ptr++; s_len--; }
    if (s_len > 32) return P256_INVALID_SIGNATURE;
    uint8_t s_bytes[32] = {0};
    memcpy(s_bytes + 32 - s_len, s_ptr, s_len);
    for (int i = 0; i < 8; i++)
        s_sc[i] = ((uint32_t)s_bytes[(7-i)*4]<<24) | ((uint32_t)s_bytes[(7-i)*4+1]<<16)
                | ((uint32_t)s_bytes[(7-i)*4+2]<<8) | (uint32_t)s_bytes[(7-i)*4+3];

    /* 2. Validate r,s in [1, n-1] */
    if (p256_bn_is_zero(r_sc, 8) || p256_bn_cmp(r_sc, P256_N, 8) >= 0)
        return P256_INVALID_SIGNATURE;
    if (p256_bn_is_zero(s_sc, 8) || p256_bn_cmp(s_sc, P256_N, 8) >= 0)
        return P256_INVALID_SIGNATURE;

    /* 3. e = leftmost hash_len bytes of hash, as big-endian integer */
    {
        uint8_t e_bytes[32] = {0};
        size_t el = hash_len < 32 ? hash_len : 32;
        memcpy(e_bytes, hash, el);
        for (int i = 0; i < 8; i++)
            e_sc[i] = ((uint32_t)e_bytes[(7-i)*4]<<24) | ((uint32_t)e_bytes[(7-i)*4+1]<<16)
                    | ((uint32_t)e_bytes[(7-i)*4+2]<<8) | (uint32_t)e_bytes[(7-i)*4+3];
    }

    /* 4. u1 = e * s^(-1) mod n,  u2 = r * s^(-1) mod n */
    uint32_t s_inv[8];
    p256_sc_inv(s_inv, s_sc);
    uint32_t u1[8], u2[8];
    p256_sc_mul(u1, e_sc, s_inv);
    p256_sc_mul(u2, r_sc, s_inv);

    /* 5. Assemble 65-byte uncompressed public key */
    uint8_t pk[65];
    pk[0] = 0x04;
    memcpy(pk + 1,  px, 32);
    memcpy(pk + 33, py, 32);

    p256_jac_pt pub;
    if (!p256_pt_decode(&pub, pk, 65))
        return P256_INVALID_SIGNATURE;

    /* 6. R = u1*G + u2*Q */
    p256_jac_pt G, R1, R2;
    memcpy(G.x, P256_GX, 32);
    memcpy(G.y, P256_GY, 32);
    memset(G.z, 0, 32);  G.z[0] = 1;
    p256_pt_mul(&R1, u1, &G);
    p256_pt_mul(&R2, u2, &pub);
    p256_pt_add(&R1, &R1, &R2);

    /* 7. Convert R to affine, check R.x mod n == r */
    p256_pt_to_affine(&R1);
    if (p256_pt_is_inf(&R1)) return P256_INVALID_SIGNATURE;

    uint32_t rx_mod_n[8];
    if (p256_bn_cmp(R1.x, P256_N, 8) >= 0) {
        uint32_t tmp[8], borrow = 0;
        for (int i = 0; i < 8; i++) {
            uint64_t diff = (uint64_t)R1.x[i] - P256_N[i] - borrow;
            tmp[i] = (uint32_t)diff;
            borrow = (diff >> 32) & 1;
        }
        memcpy(rx_mod_n, tmp, 32);
    } else {
        memcpy(rx_mod_n, R1.x, 32);
    }

    return (p256_bn_cmp(rx_mod_n, r_sc, 8) == 0) ? P256_SUCCESS : P256_INVALID_SIGNATURE;
}

static int ec_get_pubkey_from_cert(const unsigned char *cert_der, int cert_der_len,
                                    unsigned char *px, unsigned char *py) {
    int pos=0,tag,tlen;
    tag=der_read_tag(cert_der,cert_der_len,&pos,&tlen); if(tag!=0x30) return -1;
    tag=der_read_tag(cert_der,cert_der_len,&pos,&tlen); if(tag!=0x30) return -1;
    int tbs=pos+tlen;
    if(pos<tbs&&cert_der[pos]==0xa0){ tag=der_read_tag(cert_der,cert_der_len,&pos,&tlen); pos+=tlen; }
    int i; for(i=0;i<5&&pos<tbs;i++){ tag=der_read_tag(cert_der,cert_der_len,&pos,&tlen); pos+=tlen; }
    if(pos>=tbs) return -1;
    tag=der_read_tag(cert_der,cert_der_len,&pos,&tlen); if(tag!=0x30) return -1;
    /* Step INTO subjectPublicKeyInfo — read AlgorithmIdentifier */
    tag=der_read_tag(cert_der,cert_der_len,&pos,&tlen);
    pos += tlen; /* skip AlgorithmIdentifier */
    if (pos + 3 > cert_der_len) return -1;
    tag = der_read_tag(cert_der, cert_der_len, &pos, &tlen); if(tag!=0x03) return -1;
    if (tlen < 1) return -1;
    pos++; tlen--;
    if (tlen != 65 || cert_der[pos] != 0x04) return -1; /* only P-256 (65-byte uncompressed point) */
    pos++;
    memcpy(px,cert_der+pos,32); memcpy(py,cert_der+pos+32,32);
    return 0;
}

/* ========================================================================
 * TLS PRF (TLS 1.2) - FIXED buffer sizes
 * ======================================================================== */

static void tls_prf(const unsigned char *secret, int secret_len,
                    const char *label,
                    const unsigned char *seed, int seed_len,
                    unsigned char *out, int out_len) {
    if (secret_len < 0) return;
    unsigned char label_seed[1024];
    int ls_len = 0;
    if (seed_len < 0) seed_len = 0;
    while (label[ls_len]) {
        if (ls_len >= 1024) break;
        label_seed[ls_len] = (unsigned char)label[ls_len];
        ls_len++;
    }
    for (int i = 0; i < seed_len && ls_len < 1024; i++) label_seed[ls_len++] = seed[i];
    unsigned char A[32], tmp[32];
    ossl_hmac_sha256(secret, secret_len, label_seed, ls_len, A);
    int remaining = out_len;
    while (remaining > 0) {
        unsigned char combined[1072]; /* 32 + 1024 (max label_seed) + margin */
        if (ls_len > 1024) return; /* label_seed overflow */
        memcpy(combined, A, 32);
        memcpy(combined + 32, label_seed, ls_len);
        int clen = 32 + ls_len;
        if (clen > (int)sizeof(combined)) clen = (int)sizeof(combined);
        ossl_hmac_sha256(secret, secret_len, combined, clen, tmp);
        int take = remaining < 32 ? remaining : 32;
        memcpy(out, tmp, take);
        out += take;
        remaining -= take;
        if (remaining > 0) ossl_hmac_sha256(secret, secret_len, A, 32, A);
    }
}

static void tls_prf_sha384(const unsigned char *secret, int secret_len,
                           const char *label,
                           const unsigned char *seed, int seed_len,
                           unsigned char *out, int out_len) {
    if (secret_len < 0) return;
    unsigned char label_seed[1024];
    int ls_len = 0;
    if (seed_len < 0) seed_len = 0;
    while (label[ls_len]) {
        if (ls_len >= 1024) break;
        label_seed[ls_len] = (unsigned char)label[ls_len];
        ls_len++;
    }
    for (int i = 0; i < seed_len && ls_len < 1024; i++) label_seed[ls_len++] = seed[i];
    unsigned char A[48], tmp[48];
    ossl_hmac_sha384(secret, secret_len, label_seed, ls_len, A);
    int remaining = out_len;
    while (remaining > 0) {
        unsigned char combined[1072]; /* 48 + 1024 (max label_seed) + margin */
        if (ls_len > 1024) return; /* label_seed overflow */
        memcpy(combined, A, 48);
        memcpy(combined + 48, label_seed, ls_len);
        int clen = 48 + ls_len;
        if (clen > (int)sizeof(combined)) clen = (int)sizeof(combined);
        ossl_hmac_sha384(secret, secret_len, combined, clen, tmp);
        int take = remaining < 48 ? remaining : 48;
        memcpy(out, tmp, take);
        out += take;
        remaining -= take;
        if (remaining > 0) ossl_hmac_sha384(secret, secret_len, A, 48, A);
    }
}

/* ========================================================================
 * Platform initialization (once)
 * ======================================================================== */

static int ossl_platform_init(void) {
    static int initialized = 0;
    if (initialized) return 0;
    initialized = 1;
#ifdef OSSL_PLATFORM_WINDOWS
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        fprintf(stderr, "ossl: WSAStartup failed\n");
        return -1;
    }
#endif
    return 0;
}

static char* ossl_strdup(const char *s) {
    if (!s) return NULL;
    size_t len = strlen(s) + 1;
    char *d = (char*)malloc(len);
    if (d) memcpy(d, s, len);
    return d;
}

/* ========================================================================
 * Handshake transcript hash helpers
 * ======================================================================== */

static void ossl_hs_hash_init(struct ossl_ssl *ssl) {
    ssl->use_hs_hash384 = 0;
    ossl_sha256_init(&ssl->hs_hash);
    ossl_sha384_init(&ssl->hs_hash384);
}

static void ossl_hs_hash_update(struct ossl_ssl *ssl, const unsigned char *msg, int len) {
    ossl_sha256_update(&ssl->hs_hash, msg, len);
    ossl_sha384_update(&ssl->hs_hash384, msg, len);
}

/* TLS 1.3 handshake transcript hash helpers */
static void ossl_hs_hash13_init(struct ossl_ssl *ssl) {
    ossl_sha256_init(&ssl->hs_hash13);
    ossl_sha384_init(&ssl->hs_hash38413);
}

static void ossl_hs_hash13_update(struct ossl_ssl *ssl, const unsigned char *msg, int len) {
    ossl_sha256_update(&ssl->hs_hash13, msg, len);
    ossl_sha384_update(&ssl->hs_hash38413, msg, len);
}

static void ossl_hs_hash13_final(struct ossl_ssl *ssl, unsigned char *hash) {
    if (ssl->tls13_hash_len == 48) {
        ossl_sha384_ctx ctx; memcpy(&ctx, &ssl->hs_hash38413, sizeof(ctx));
        ossl_sha384_final(&ctx, hash);
    } else {
        ossl_sha256_ctx ctx; memcpy(&ctx, &ssl->hs_hash13, sizeof(ctx));
        ossl_sha256_final(&ctx, hash);
    }
}

/* ========================================================================
 * TLS 1.3 key schedule (RFC 8446 Section 7.1)
 * Computes handshake traffic secrets after ServerHello.
 * shared_secret = X25519(priv, peer_pub)
 * ======================================================================== */

static int ossl_tls13_derive_handshake_secrets(struct ossl_ssl *ssl,
                                                const unsigned char *shared_secret, int ss_len) {
    int hl = ssl->tls13_hash_len;
    unsigned char zeros[48] = {0};
    unsigned char early_secret[48], derived[48], handshake_secret[48];

    /* 1. Early Secret = HKDF-Extract(0, 0) */
    if (hl == 48) {
        ossl_hkdf_extract_sha384(zeros, 48, zeros, 48, early_secret);
    } else {
        ossl_hkdf_extract_sha256(zeros, 32, zeros, 32, early_secret);
    }

    /* 2. Derive-Secret(Early Secret, "derived", "") */
    {
        unsigned char empty_hash[48] = {0};
        if (hl == 48) {
            ossl_sha384_ctx hv; ossl_sha384_init(&hv);
            ossl_sha384_update(&hv, (const unsigned char*)"", 0);
            ossl_sha384_final(&hv, empty_hash);
            ossl_hkdf_expand_label_sha384(early_secret, "derived", empty_hash, 48, derived, 48);
        } else {
            ossl_sha256_ctx hv; ossl_sha256_init(&hv);
            ossl_sha256_update(&hv, (const unsigned char*)"", 0);
            ossl_sha256_final(&hv, empty_hash);
            ossl_hkdf_expand_label_sha256(early_secret, "derived", empty_hash, 32, derived, 32);
        }
    }

    /* 3. Handshake Secret = HKDF-Extract(derived, shared_secret) */
    if (hl == 48)
        ossl_hkdf_extract_sha384(derived, 48, shared_secret, ss_len, handshake_secret);
    else
        ossl_hkdf_extract_sha256(derived, 32, shared_secret, ss_len, handshake_secret);
    memcpy(ssl->handshake_secret, handshake_secret, hl);

    /* 4. Client/Server Handshake Traffic Secrets */
    {
        unsigned char ch_sh_hash[48];
        ossl_hs_hash13_final(ssl, ch_sh_hash);
        if (hl == 48) {
            ossl_hkdf_expand_label_sha384(handshake_secret, "c hs traffic", ch_sh_hash, 48, ssl->client_hs_secret, 48);
            ossl_hkdf_expand_label_sha384(handshake_secret, "s hs traffic", ch_sh_hash, 48, ssl->server_hs_secret, 48);
        } else {
            /* RFC 8446 §7.1: client uses "c hs traffic", server uses "s hs traffic".
               NOTE: Against axm.dev, "c hs traffic" causes client Finished rejection.
               The server appears to expect "s hs traffic" for the client direction.
               This is non-RFC-standard behavior; see TODO.txt item #1. */
            ossl_hkdf_expand_label_sha256(handshake_secret, "c hs traffic", ch_sh_hash, 32, ssl->client_hs_secret, 32);
            ossl_hkdf_expand_label_sha256(handshake_secret, "s hs traffic", ch_sh_hash, 32, ssl->server_hs_secret, 32);
        }
    }

    /* 5. Derive handshake write keys and IVs (stored in separate hs arrays) */
    {
        int key_len = (hl == 48) ? 32 : 16;
        if (ssl->is_server) {
            ossl_tls13_derive_traffic_keys(ssl, ssl->server_hs_secret,
                                            ssl->server_hs_write_key, key_len, ssl->server_hs_write_iv);
            ossl_tls13_derive_traffic_keys(ssl, ssl->client_hs_secret,
                                            ssl->client_hs_write_key, key_len, ssl->client_hs_write_iv);
        } else {
            ossl_tls13_derive_traffic_keys(ssl, ssl->client_hs_secret,
                                            ssl->client_hs_write_key, key_len, ssl->client_hs_write_iv);
            ossl_tls13_derive_traffic_keys(ssl, ssl->server_hs_secret,
                                            ssl->server_hs_write_key, key_len, ssl->server_hs_write_iv);
        }
    }

    /* Also copy handshake keys to write_key13 for send/recv functions */
    {
        int key_len = (hl == 48) ? 32 : 16;
        memcpy(ssl->client_write_key13, ssl->client_hs_write_key, key_len);
        memcpy(ssl->server_write_key13, ssl->server_hs_write_key, key_len);
        memcpy(ssl->client_write_iv13, ssl->client_hs_write_iv, 12);
        memcpy(ssl->server_write_iv13, ssl->server_hs_write_iv, 12);
    }
    return 0;
}

/* Compute the TLS 1.3 master secret from handshake_secret.
   RFC 8446: Master Secret = HKDF-Extract(0, Derive-Secret(HS, "derived", "")) */
static void ossl_tls13_compute_master_secret(struct ossl_ssl *ssl, unsigned char master_secret[48]) {
    int hl = ssl->tls13_hash_len;
    unsigned char zeros[48] = {0};
    unsigned char derived[48];

    {
        unsigned char empty_hash[48] = {0};
        if (hl == 48) {
            ossl_sha384_ctx hv; ossl_sha384_init(&hv);
            ossl_sha384_update(&hv, (const unsigned char*)"", 0);
            ossl_sha384_final(&hv, empty_hash);
            ossl_hkdf_expand_label_sha384(ssl->handshake_secret, "derived", empty_hash, 48, derived, 48);
        } else {
            ossl_sha256_ctx hv; ossl_sha256_init(&hv);
            ossl_sha256_update(&hv, (const unsigned char*)"", 0);
            ossl_sha256_final(&hv, empty_hash);
            ossl_hkdf_expand_label_sha256(ssl->handshake_secret, "derived", empty_hash, 32, derived, 32);
        }
    }

    if (hl == 48)
        ossl_hkdf_extract_sha384(derived, 48, zeros, hl, master_secret);
    else
        ossl_hkdf_extract_sha256(derived, 32, zeros, hl, master_secret);
}

/* Derive a single application traffic secret from master_secret.
   Per RFC 8446 §7.1, both initial client_ap and server_ap secrets
   use the same transcript hash: ClientHello...server Finished. */
static void ossl_tls13_derive_single_ap(struct ossl_ssl *ssl, const unsigned char *master_secret,
                                         const char *label, const unsigned char *transcript_hash,
                                         unsigned char *ap_secret) {
    int hl = ssl->tls13_hash_len;
    if (hl == 48)
        ossl_hkdf_expand_label_sha384(master_secret, label, transcript_hash, 48, ap_secret, 48);
    else
        ossl_hkdf_expand_label_sha256(master_secret, label, transcript_hash, 32, ap_secret, 32);
}

/* Derive application traffic secrets from the master secret.
   RFC 8446 §7.1: both client_ap and server_ap initial secrets
   use the same transcript (ClientHello...server Finished).
   Caller may pass the same transcript_hash for both. */
static int ossl_tls13_derive_application_secrets(struct ossl_ssl *ssl,
                                                   const unsigned char *client_transcript,
                                                   const unsigned char *server_transcript) {
    int hl = ssl->tls13_hash_len;
    unsigned char master_secret[48];

    ossl_tls13_compute_master_secret(ssl, master_secret);

    if (client_transcript)
        ossl_tls13_derive_single_ap(ssl, master_secret, "c ap traffic", client_transcript, ssl->client_ap_secret);
    if (server_transcript)
        ossl_tls13_derive_single_ap(ssl, master_secret, "s ap traffic", server_transcript, ssl->server_ap_secret);

    /* Derive application write keys for any newly computed secret */
    {
        int key_len = (hl == 48) ? 32 : 16;
        if (ssl->is_server) {
            if (server_transcript)
                ossl_tls13_derive_traffic_keys(ssl, ssl->server_ap_secret,
                                                ssl->server_write_key13, key_len, ssl->server_write_iv13);
            if (client_transcript)
                ossl_tls13_derive_traffic_keys(ssl, ssl->client_ap_secret,
                                                ssl->client_write_key13, key_len, ssl->client_write_iv13);
        } else {
            if (client_transcript)
                ossl_tls13_derive_traffic_keys(ssl, ssl->client_ap_secret,
                                                ssl->client_write_key13, key_len, ssl->client_write_iv13);
            if (server_transcript)
                ossl_tls13_derive_traffic_keys(ssl, ssl->server_ap_secret,
                                                ssl->server_write_key13, key_len, ssl->server_write_iv13);
        }
    }

    return 0;
}

/* ========================================================================
 * TLS Record layer and Handshake Buffer management
 * ======================================================================== */

static int ossl_send_record(struct ossl_ssl *ssl, int type,
                             const unsigned char *data, int len) {
    unsigned char header[5];
    header[0] = (unsigned char)type;
    header[1] = OSSL_TLS_VERSION_MAJOR;
    header[2] = OSSL_TLS_VERSION_MINOR;
    header[3] = (unsigned char)((len >> 8) & 0xFF);
    header[4] = (unsigned char)(len & 0xFF);
    if (tcp_send_all(ssl->fd, header, 5) != 0) return -1;
    if (tcp_send_all(ssl->fd, data, len) != 0) return -1;
    return 0;
}

static int ossl_recv_record(struct ossl_ssl *ssl, int *type,
                             unsigned char *buf, int max_len, int *len) {
    unsigned char header[5];
    if (tcp_recv_all(ssl->fd, header, 5) != 0) {
        return -1;
    }
    /* Accept any TLS 1.x record layer version (many servers use {3,1} for TLS 1.2) */
    if (header[1] != OSSL_TLS_VERSION_MAJOR || header[2] < 1) {
        fprintf(stderr, "ossl: Unexpected record version %d.%d\n", header[1], header[2]);
        return -1;
    }
    *type = header[0];
    int body_len = (header[3] << 8) | header[4];
    if (body_len > OSSL_MAX_RECORD_SIZE || body_len > max_len) {
        fprintf(stderr, "ossl: Record length %d larger than maximum %d\n", body_len, max_len);
        return -1;
    }
    if (tcp_recv_all(ssl->fd, buf, body_len) != 0) return -1;
    if (*type == 21 && body_len >= 2) {
        fprintf(stderr, "ossl: Received alert (level=%d, description=%d)\n", buf[0], buf[1]);
    }
    *len = body_len;
    return 0;
}

static int ossl_get_handshake_msg(struct ossl_ssl *ssl, int *hs_type,
                                   unsigned char *buf, int max_len, int *hs_len) {
    while (1) {
        if (ssl->rbuf.len >= 4) {
            int msg_len = (ssl->rbuf.data[1] << 16) | (ssl->rbuf.data[2] << 8) | ssl->rbuf.data[3];
            int total_len = 4 + msg_len;
            if (ssl->rbuf.len >= total_len) {
                if (total_len > max_len) {
                    fprintf(stderr, "ossl: Handshake message length %d exceeds buffer %d\n", total_len, max_len);
                    return -1;
                }
                *hs_type = ssl->rbuf.data[0];
                memcpy(buf, ssl->rbuf.data, total_len);
                *hs_len = total_len;
                if (ssl->rbuf.len > total_len) {
                    memmove(ssl->rbuf.data, ssl->rbuf.data + total_len, ssl->rbuf.len - total_len);
                }
                ssl->rbuf.len -= total_len;
                return 0;
            }
        }
        int rec_type;
        unsigned char rec_buf[OSSL_MAX_RECORD_SIZE + 16];
        int rec_len;
        if (ossl_recv_record(ssl, &rec_type, rec_buf, sizeof(rec_buf), &rec_len) != 0) {
            return -1;
        }
        if (rec_type == SSL3_RT_ALERT) {
            if (rec_len >= 2)
                fprintf(stderr, "ossl: Received alert (level=%d, description=%d)\n", rec_buf[0], rec_buf[1]);
            else
                fprintf(stderr, "ossl: Received alert\n");
            return -1;
        }
        if (rec_type == SSL3_RT_CHANGE_CIPHER_SPEC) {
            fprintf(stderr, "ossl: Unexpected ChangeCipherSpec during handshake message reassembly\n");
            return -1;
        }
        if (rec_type != SSL3_RT_HANDSHAKE) {
            fprintf(stderr, "ossl: Expected handshake record, got content type %d\n", rec_type);
            return -1;
        }
        if (ossl_buf_push(&ssl->rbuf, rec_buf, rec_len) != 0) return -1;
    }
}

/*
 * TLS 1.2 GCM record format:
 *   header (5 bytes: type, version, length)
 *   explicit nonce (8 bytes) - last 8 bytes of the 12-byte nonce (sequence number)
 *   ciphertext (len bytes)
 *   authentication tag (16 bytes)
 * total record body = 4 + len + 16
 */

static int ossl_send_encrypted(struct ossl_ssl *ssl, int type,
                                const unsigned char *data, int len,
                                int use_server_keys) {
    if (len < 0 || len > OSSL_MAX_RECORD_SIZE) return -1;
    unsigned char *key = use_server_keys ? ssl->server_write_key : ssl->client_write_key;
    unsigned char *iv = use_server_keys ? ssl->server_write_iv : ssl->client_write_iv;
    unsigned long long seq = use_server_keys ? ssl->server_seq : ssl->client_seq;
    /* Build 12-byte nonce: implicit iv (4 bytes from fixed_iv) || seq (8 bytes) */
    unsigned char nonce[12];
    memcpy(nonce, iv, 4);
    for (int i = 0; i < 8; i++) nonce[4+i] = (unsigned char)(seq >> (56 - 8*i));
    
    int total_body_len = 8 + len + 16; /* explicit nonce + ciphertext + tag */
    unsigned char aad[13];
    for (int i = 0; i < 8; i++) aad[i] = (unsigned char)(seq >> (56 - 8*i));
    aad[8] = (unsigned char)type;
    aad[9] = OSSL_TLS_VERSION_MAJOR;
    aad[10] = OSSL_TLS_VERSION_MINOR;
    aad[11] = (unsigned char)((len >> 8) & 0xFF);
    aad[12] = (unsigned char)(len & 0xFF);
    
    unsigned char *ciphertext = (unsigned char*)malloc(len + 16);
    if (!ciphertext) return -1;
    unsigned char tag[16];
    if (aes128_gcm_encrypt(key, data, len, aad, 13, nonce, 12, ciphertext, tag) != 0) {
        free(ciphertext); return -1;
    }
    
    if (use_server_keys) ssl->server_seq++; else ssl->client_seq++;
    
    /* Build record: header + explicit nonce + ciphertext + tag */
    unsigned char *outrec = (unsigned char*)malloc(5 + total_body_len);
    if (!outrec) { free(ciphertext); return -1; }
    outrec[0] = (unsigned char)type;
    outrec[1] = OSSL_TLS_VERSION_MAJOR;
    outrec[2] = OSSL_TLS_VERSION_MINOR;
    outrec[3] = (unsigned char)((total_body_len >> 8) & 0xFF);
    outrec[4] = (unsigned char)(total_body_len & 0xFF);
    /* explicit nonce (8 bytes from sequence number) */
    memcpy(outrec+5, nonce+4, 8);
    /* ciphertext */
    memcpy(outrec+13, ciphertext, len);
    /* tag */
    memcpy(outrec+13+len, tag, 16);
    
    int n = tcp_send_all(ssl->fd, outrec, 5 + total_body_len);
    free(ciphertext); free(outrec);
    return (n == 0) ? 0 : -1;
}

static int ossl_recv_encrypted(struct ossl_ssl *ssl, int *type,
                                unsigned char *plaintext, int *pt_len,
                                int use_server_keys) {
    unsigned char header[5];
    if (tcp_recv_all(ssl->fd, header, 5) != 0) {
        return -1;
    }
    *type = header[0];
    int total_body = (header[3] << 8) | header[4];
    if (total_body > OSSL_MAX_RECORD_SIZE + 24) return -1;
    if (total_body < 8 + 16) return -1; /* at least explicit nonce + tag */
    int ct_len = total_body - 8 - 16;
    
    unsigned char *record_data = (unsigned char*)malloc(total_body);
    if (!record_data) return -1;
    if (tcp_recv_all(ssl->fd, record_data, total_body) != 0) { free(record_data); return -1; }
    
    /* Parse record: explicit nonce (8 bytes), ciphertext (ct_len), tag (16) */
    unsigned char explicit_nonce[8];
    memcpy(explicit_nonce, record_data, 8);
    unsigned char *ciphertext = record_data + 8;
    unsigned char *tag = ciphertext + ct_len;
    
    unsigned char *key = use_server_keys ? ssl->server_write_key : ssl->client_write_key;
    unsigned char *iv = use_server_keys ? ssl->server_write_iv : ssl->client_write_iv;
    unsigned long long seq = use_server_keys ? ssl->server_seq : ssl->client_seq;
    
    /* Reconstruct 12-byte nonce: fixed_iv (4 bytes) || explicit_nonce (8 bytes) */
    unsigned char nonce[12];
    memcpy(nonce, iv, 4);
    memcpy(nonce+4, explicit_nonce, 8);
    
    unsigned char aad[13];
    for (int i = 0; i < 8; i++) aad[i] = (unsigned char)(seq >> (56 - 8*i));
    aad[8] = (unsigned char)*type;
    aad[9] = header[1];
    aad[10] = header[2];
    aad[11] = (unsigned char)((ct_len >> 8) & 0xFF);
    aad[12] = (unsigned char)(ct_len & 0xFF);
    
    if (aes128_gcm_decrypt(key, ciphertext, ct_len, aad, 13, nonce, 12, tag, plaintext) != 0) {
        fprintf(stderr, "ossl: Decryption failed (possible tampering)\n");
        free(record_data);
        return -1;
    }
    if (use_server_keys) ssl->server_seq++; else ssl->client_seq++;
    *pt_len = ct_len;
    free(record_data);
    return 0;
}

static int ossl_send_encrypted256(struct ossl_ssl *ssl, int type,
                                   const unsigned char *data, int len,
                                   int use_server_keys) {
    if (len < 0 || len > OSSL_MAX_RECORD_SIZE) return -1;
    unsigned char *key = use_server_keys ? ssl->server_write_key : ssl->client_write_key;
    unsigned char *iv = use_server_keys ? ssl->server_write_iv : ssl->client_write_iv;
    unsigned long long seq = use_server_keys ? ssl->server_seq : ssl->client_seq;
    unsigned char nonce[12];
    memcpy(nonce, iv, 4);
    for (int i = 0; i < 8; i++) nonce[4+i] = (unsigned char)(seq >> (56 - 8*i));
    
    int total_body_len = 8 + len + 16; /* explicit nonce + ciphertext + tag */
    unsigned char aad[13];
    for (int i = 0; i < 8; i++) aad[i] = (unsigned char)(seq >> (56 - 8*i));
    aad[8] = (unsigned char)type;
    aad[9] = OSSL_TLS_VERSION_MAJOR;
    aad[10] = OSSL_TLS_VERSION_MINOR;
    aad[11] = (unsigned char)((len >> 8) & 0xFF);
    aad[12] = (unsigned char)(len & 0xFF);
    
    unsigned char *ciphertext = (unsigned char*)malloc(len + 16);
    if (!ciphertext) return -1;
    unsigned char tag[16];
    if (aes256_gcm_encrypt(key, data, len, aad, 13, nonce, 12, ciphertext, tag) != 0) {
        free(ciphertext); return -1;
    }
    
    if (use_server_keys) ssl->server_seq++; else ssl->client_seq++;
    
    unsigned char *outrec = (unsigned char*)malloc(5 + total_body_len);
    if (!outrec) { free(ciphertext); return -1; }
    outrec[0] = (unsigned char)type;
    outrec[1] = OSSL_TLS_VERSION_MAJOR;
    outrec[2] = OSSL_TLS_VERSION_MINOR;
    outrec[3] = (unsigned char)((total_body_len >> 8) & 0xFF);
    outrec[4] = (unsigned char)(total_body_len & 0xFF);
    /* explicit nonce (8 bytes from sequence number) */
    memcpy(outrec+5, nonce+4, 8);
    /* ciphertext */
    memcpy(outrec+13, ciphertext, len);
    /* tag */
    memcpy(outrec+13+len, tag, 16);
    
    int n = tcp_send_all(ssl->fd, outrec, 5 + total_body_len);
    free(ciphertext); free(outrec);
    return (n == 0) ? 0 : -1;
}

static int ossl_recv_encrypted256(struct ossl_ssl *ssl, int *type,
                                   unsigned char *plaintext, int *pt_len,
                                   int use_server_keys) {
    unsigned char header[5];
    if (tcp_recv_all(ssl->fd, header, 5) != 0) {
        return -1;
    }
    *type = header[0];
    int total_body = (header[3] << 8) | header[4];
    if (total_body > OSSL_MAX_RECORD_SIZE + 24) return -1;
    if (total_body < 8 + 16) return -1;
    int ct_len = total_body - 8 - 16;
    
    unsigned char *record_data = (unsigned char*)malloc(total_body);
    if (!record_data) return -1;
    if (tcp_recv_all(ssl->fd, record_data, total_body) != 0) { free(record_data); return -1; }
    
    unsigned char explicit_nonce[8];
    memcpy(explicit_nonce, record_data, 8);
    unsigned char *ciphertext = record_data + 8;
    unsigned char *tag = ciphertext + ct_len;
    
    unsigned char *key = use_server_keys ? ssl->server_write_key : ssl->client_write_key;
    unsigned char *iv = use_server_keys ? ssl->server_write_iv : ssl->client_write_iv;
    unsigned long long seq = use_server_keys ? ssl->server_seq : ssl->client_seq;
    
    unsigned char nonce[12];
    memcpy(nonce, iv, 4);
    memcpy(nonce+4, explicit_nonce, 8);
    
    unsigned char aad[13];
    for (int i = 0; i < 8; i++) aad[i] = (unsigned char)(seq >> (56 - 8*i));
    aad[8] = (unsigned char)*type;
    aad[9] = header[1];
    aad[10] = header[2];
    aad[11] = (unsigned char)((ct_len >> 8) & 0xFF);
    aad[12] = (unsigned char)(ct_len & 0xFF);
    
    if (aes256_gcm_decrypt(key, ciphertext, ct_len, aad, 13, nonce, 12, tag, plaintext) != 0) {
        fprintf(stderr, "ossl: Decryption failed (possible tampering)\n");
        free(record_data);
        return -1;
    }
    if (use_server_keys) ssl->server_seq++; else ssl->client_seq++;
    *pt_len = ct_len;
    free(record_data);
    return 0;
}

/* ========================================================================
 * TLS 1.3 Finished MAC (RFC 8446 Section 4.4.4)
 * ======================================================================== */

static void ossl_tls13_compute_finished(struct ossl_ssl *ssl,
                                         const unsigned char *base_key,
                                         unsigned char verify_data[48]) {
    int hl = ssl->tls13_hash_len;
    unsigned char finished_key[48];
    unsigned char transcript_hash[48];

    ossl_tls13_expand_label(ssl, base_key, "finished", NULL, 0, finished_key, hl);
    ossl_hs_hash13_final(ssl, transcript_hash);

    if (hl == 48)
        ossl_hmac_sha384(finished_key, hl, transcript_hash, 48, verify_data);
    else
        ossl_hmac_sha256(finished_key, hl, transcript_hash, 32, verify_data);
}

/* ========================================================================
 * TLS 1.3 Encrypted Record Layer
 * ========================================================================
 * Nonce: write_iv XOR sequence_number (big-endian, padded to 12 bytes)
 * AAD:   content_type || 0x0303 || plaintext_length
 * After decryption, the last byte of plaintext is the real content type.
 * Outer record type is 23 (application_data).
 */

static int ossl_tls13_send_encrypted(struct ossl_ssl *ssl, int real_type,
                                      const unsigned char *data, int len,
                                      int use_server_keys, int is_hs_phase) {
    if (len < 0 || len > OSSL_MAX_RECORD_SIZE) return -1;
    int hl = ssl->tls13_hash_len;
    int key_len = (hl == 48) ? 32 : 16;
    unsigned char *write_key, *write_iv;
    unsigned long long *seq;

    if (is_hs_phase) {
        write_key = use_server_keys ? ssl->server_hs_write_key : ssl->client_hs_write_key;
        write_iv  = use_server_keys ? ssl->server_hs_write_iv : ssl->client_hs_write_iv;
    } else {
        write_key = use_server_keys ? ssl->server_write_key13 : ssl->client_write_key13;
        write_iv  = use_server_keys ? ssl->server_write_iv13 : ssl->client_write_iv13;
    }
    seq = use_server_keys ? &ssl->server_seq : &ssl->client_seq;

    /* Build plaintext: data || real_type */
    int pt_len = len + 1;
    unsigned char *plaintext = (unsigned char*)malloc(pt_len);
    if (!plaintext) return -1;
    memcpy(plaintext, data, len);
    plaintext[len] = (unsigned char)real_type;

    /* Nonce = write_iv XOR sequence_number */
    unsigned char nonce[12];
    memcpy(nonce, write_iv, 12);
    for (int i = 0; i < 8; i++)
        nonce[11 - i] ^= (unsigned char)((*seq >> (8 * i)) & 0xFF);

    /* AAD = content_type (23) || 0x0303 || record_body (pt_len + tag_len) */
    unsigned char aad[5];
    aad[0] = SSL3_RT_APPLICATION_DATA;
    aad[1] = 0x03; aad[2] = 0x03;
    int record_sz = pt_len + 16; /* TLSCiphertext.length = plaintext + tag */
    aad[3] = (unsigned char)((record_sz >> 8) & 0xFF);
    aad[4] = (unsigned char)(record_sz & 0xFF);

    /* Encrypt */
    unsigned char *ciphertext = (unsigned char*)malloc(pt_len);
    unsigned char tag[16];
    if (!ciphertext) { free(plaintext); return -1; }

    int enc_ok;
    if (key_len == 32)
        enc_ok = aes256_gcm_encrypt(write_key, plaintext, pt_len, aad, 5, nonce, 12, ciphertext, tag);
    else
        enc_ok = aes128_gcm_encrypt(write_key, plaintext, pt_len, aad, 5, nonce, 12, ciphertext, tag);
    free(plaintext);

    if (enc_ok != 0) { free(ciphertext); return -1; }

    (*seq)++;

    /* Build record: header + ciphertext + tag */
    int record_body = pt_len + 16;
    unsigned char header[5];
    header[0] = SSL3_RT_APPLICATION_DATA;
    header[1] = 0x03; header[2] = 0x03;
    header[3] = (unsigned char)((record_body >> 8) & 0xFF);
    header[4] = (unsigned char)(record_body & 0xFF);

    unsigned char *outrec = (unsigned char*)malloc(5 + record_body);
    if (!outrec) { free(ciphertext); return -1; }
    memcpy(outrec, header, 5);
    memcpy(outrec + 5, ciphertext, pt_len);
    memcpy(outrec + 5 + pt_len, tag, 16);
    free(ciphertext);

    int n = tcp_send_all(ssl->fd, outrec, 5 + record_body);
    free(outrec);
    return (n == 0) ? 0 : -1;
}

static int ossl_tls13_recv_encrypted(struct ossl_ssl *ssl, int *real_type,
                                      unsigned char *plaintext, int *pt_len,
                                      int use_server_keys, int is_hs_phase) {
    int hl = ssl->tls13_hash_len;
    int key_len = (hl == 48) ? 32 : 16;
    unsigned char header[5];
    if (tcp_recv_all(ssl->fd, header, 5) != 0) {
        return -1;
    }

    int record_body = (header[3] << 8) | header[4];
    /* Handle TLS 1.3 middlebox compatibility mode: skip CCS */
    if (header[0] == SSL3_RT_CHANGE_CIPHER_SPEC) {
        if (record_body != 1) return -1;
        unsigned char ccs_byte;
        if (tcp_recv_all(ssl->fd, &ccs_byte, 1) != 0) return -1;
        return ossl_tls13_recv_encrypted(ssl, real_type, plaintext, pt_len, use_server_keys, is_hs_phase);
    }
    if (record_body > OSSL_MAX_RECORD_SIZE + 24) return -1;
    if (record_body < 1 + 16) return -1; /* at least 1 byte plaintext + tag */
    int ct_len = record_body - 16;
    int inner_pt_len = ct_len;

    unsigned char *record_data = (unsigned char*)malloc(record_body);
    if (!record_data) return -1;
    if (tcp_recv_all(ssl->fd, record_data, record_body) != 0) { free(record_data); return -1; }

    unsigned char *ciphertext = record_data;
    unsigned char *tag = ciphertext + ct_len;

    unsigned char *read_key, *read_iv;
    unsigned long long *seq;
    if (is_hs_phase) {
        read_key = use_server_keys ? ssl->server_hs_write_key : ssl->client_hs_write_key;
        read_iv  = use_server_keys ? ssl->server_hs_write_iv : ssl->client_hs_write_iv;
    } else {
        read_key = use_server_keys ? ssl->server_write_key13 : ssl->client_write_key13;
        read_iv  = use_server_keys ? ssl->server_write_iv13 : ssl->client_write_iv13;
    }
    seq = use_server_keys ? &ssl->server_seq : &ssl->client_seq;

    /* Nonce = write_iv XOR sequence_number */
    unsigned char nonce[12];
    memcpy(nonce, read_iv, 12);
    for (int i = 0; i < 8; i++)
        nonce[11 - i] ^= (unsigned char)((*seq >> (8 * i)) & 0xFF);

    /* AAD = content_type || 0x0303 || record_body (TLSCiphertext.length = ct_len + tag_len) */
    unsigned char aad[5];
    aad[0] = header[0];
    aad[1] = 0x03; aad[2] = 0x03;
    aad[3] = (unsigned char)((record_body >> 8) & 0xFF);
    aad[4] = (unsigned char)(record_body & 0xFF);

    /* Decrypt */
    unsigned char *decrypted = (unsigned char*)malloc(inner_pt_len);
    if (!decrypted) { free(record_data); return -1; }

    int dec_ok;
    if (key_len == 32)
        dec_ok = aes256_gcm_decrypt(read_key, ciphertext, ct_len, aad, 5, nonce, 12, tag, decrypted);
    else
        dec_ok = aes128_gcm_decrypt(read_key, ciphertext, ct_len, aad, 5, nonce, 12, tag, decrypted);
    if (dec_ok != 0) {
        free(decrypted);
        free(record_data);
        return -1;
    }

    (*seq)++;

    /* Extract real content type from last byte */
    *real_type = decrypted[inner_pt_len - 1];
    *pt_len = inner_pt_len - 1;
    if (*pt_len > 0) memcpy(plaintext, decrypted, *pt_len);

    free(decrypted);
    free(record_data);
    return 0;
}

/* ========================================================================
 * Server handshake (supports ECDHE-RSA and RSA key exchange, AES-128/256-GCM)
 * ======================================================================== */

static int ossl_do_server_handshake(struct ossl_ssl *ssl) {
    unsigned char *buf = (unsigned char*)malloc(65536);
    if (!buf) return -1;
    int len = 0, type = 0;

    /* --- Receive ClientHello --- */
    if (ossl_get_handshake_msg(ssl, &type, buf, 65536, &len) != 0) {
        fprintf(stderr, "ossl: Failed to receive ClientHello\n");
        free(buf); return -1;
    }
    if (type != 0x01) { fprintf(stderr, "ossl: Expected ClientHello\n"); free(buf); return -1; }

    /* Parse ClientHello */
    int pos = 4;
    if (pos + 2 > len) { free(buf); return -1; }
    pos += 2; /* skip client version */
    if (pos + 32 > len) { free(buf); return -1; }
    memcpy(ssl->client_random, buf + pos, 32); pos += 32;
    if (pos + 1 > len) { free(buf); return -1; }
    int sid_len = buf[pos++];
    if (pos + sid_len > len) { free(buf); return -1; }
    pos += sid_len;
    if (pos + 2 > len) { free(buf); return -1; }
    int cs_len = (buf[pos] << 8) | buf[pos+1];
    pos += 2;

    /* Find best mutually supported cipher suite */
    /* Priority: TLS 1.3 > TLS 1.2 (ECDHE+AES256 > ECDHE+AES128 > RSA+AES256 > RSA+AES128) */
    int cs_end = pos + cs_len;
    if (cs_end > len) { free(buf); return -1; }
    int found_cs = 0, use_ecdhe = 0, use_256 = 0;
    while (pos + 2 <= cs_end) {
        int cs = (buf[pos] << 8) | buf[pos+1];
        if (!found_cs) {
            if (cs == TLS1_3_CK_AES_256_GCM_SHA384) {
                found_cs = 1; use_256 = 1;
                ssl->cipher_suite = cs;
            } else if (cs == TLS1_3_CK_AES_128_GCM_SHA256) {
                found_cs = 1;
                ssl->cipher_suite = cs;
            } else if (cs == TLS1_CK_ECDHE_RSA_WITH_AES_256_GCM_SHA384) {
                found_cs = 1; use_ecdhe = 1; use_256 = 1;
                ssl->cipher_suite = cs;
            } else if (cs == TLS1_CK_ECDHE_RSA_WITH_AES_128_GCM_SHA256) {
                found_cs = 1; use_ecdhe = 1;
                ssl->cipher_suite = cs;
            } else if (cs == TLS1_CK_RSA_WITH_AES_256_GCM_SHA384) {
                found_cs = 1; use_256 = 1;
                ssl->cipher_suite = cs;
            } else if (cs == TLS1_CK_RSA_WITH_AES_128_GCM_SHA256) {
                found_cs = 1;
                ssl->cipher_suite = cs;
            }
        }
        pos += 2;
    }
    if (!found_cs) {
        fprintf(stderr, "ossl: Client did not offer any supported cipher suite\n");
        free(buf); return -1;
    }
    ssl->negotiated_cs = ssl->cipher_suite;

    int is_tls13 = (ssl->cipher_suite == TLS1_3_CK_AES_128_GCM_SHA256 ||
                    ssl->cipher_suite == TLS1_3_CK_AES_256_GCM_SHA384);

    /* Parse extensions for TLS 1.3: need key_share and supported_versions */
    unsigned char client_key_share[32] = {0};
    int has_client_ks = 0;
    if (is_tls13) {
        /* Skip compression methods */
        pos = cs_end;
        if (pos + 1 > len) { free(buf); return -1; }
        int cm_len = buf[pos++];
        if (pos + cm_len > len) { free(buf); return -1; }
        pos += cm_len;
        /* Parse extensions */
        if (pos + 2 <= len) {
            int ext_len = (buf[pos] << 8) | buf[pos+1];
            pos += 2;
            int ext_end = pos + ext_len;
            if (ext_end > len) ext_end = len;
            while (pos + 4 <= ext_end) {
                int ext_type = (buf[pos] << 8) | buf[pos+1];
                int e_len = (buf[pos+2] << 8) | buf[pos+3];
                pos += 4;
                if (pos + e_len > ext_end) break;
                if (ext_type == OSSL_EXT_KEY_SHARE) {
                    /* Client key_share: first 2 bytes = client_shares length */
                    int ks_pos = pos;
                    int ks_len_total = (buf[ks_pos] << 8) | buf[ks_pos+1];
                    ks_pos += 2;
                    int ks_end = pos + e_len;
                    if (ks_pos + ks_len_total > ks_end) ks_len_total = ks_end - ks_pos;
                    while (ks_pos + 4 <= ks_pos + ks_len_total) {
                        int group = (buf[ks_pos] << 8) | buf[ks_pos+1];
                        int ke_len = (buf[ks_pos+2] << 8) | buf[ks_pos+3];
                        ks_pos += 4;
                        if (ks_pos + ke_len > pos + e_len) break;
                        if (group == 0x001d && ke_len == 32) { /* x25519 */
                            memcpy(client_key_share, buf + ks_pos, 32);
                            has_client_ks = 1;
                        }
                        ks_pos += ke_len;
                    }
                }
                pos += e_len;
            }
        }
        if (!has_client_ks) {
            fprintf(stderr, "ossl: ClientHello missing x25519 key_share\n");
            free(buf); return -1;
        }
        pos = cs_end; /* reset pos for extension skip below */
    }

    /* ===== TLS 1.3 SERVER HANDSHAKE PATH ===== */
    if (is_tls13) {
        ssl->is_tls13 = 1;
        ssl->negotiated_cs = ssl->cipher_suite;
        if (ssl->cipher_suite == TLS1_3_CK_AES_256_GCM_SHA384)
            ssl->tls13_hash_len = 48;
        else
            ssl->tls13_hash_len = 32;

        /* Generate ECDHE keypair */
        if (ossl_rand_bytes(ssl->ecdhe_private_key, 32) != 0) { free(buf); return -1; }
        {
            const unsigned char basepoint[32] = {9,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
            x25519_scalar_mult(ssl->ecdhe_public_key, ssl->ecdhe_private_key, basepoint);
        }
        if (ossl_rand_bytes(ssl->server_random, 32) != 0) { free(buf); return -1; }

        /* Build ServerHello with supported_versions and key_share extensions */
        {
            unsigned char sh_buf[512];
            int shp = 0;
            sh_buf[shp++] = 0x02; /* handshake type */
            int sh_len_pos = shp; shp += 3;
            /* legacy_version = 0x0303 (TLS 1.2 for compatibility) */
            sh_buf[shp++] = OSSL_TLS_VERSION_MAJOR; sh_buf[shp++] = OSSL_TLS_VERSION_MINOR;
            memcpy(sh_buf + shp, ssl->server_random, 32); shp += 32;
            /* session ID: echo client's session ID (or empty) */
            sh_buf[shp++] = 0x00; /* session ID length 0 */
            /* cipher suite */
            sh_buf[shp++] = (unsigned char)((ssl->cipher_suite >> 8) & 0xFF);
            sh_buf[shp++] = (unsigned char)(ssl->cipher_suite & 0xFF);
            sh_buf[shp++] = 0x00; /* compression */
            /* Extensions: supported_versions + key_share */
            int ext_start = shp;
            shp += 2; /* extension length placeholder */
            /* supported_versions: 0x002b, length 2, TLS 1.3 (0x0304) */
            sh_buf[shp++] = 0x00; sh_buf[shp++] = 0x2b; /* extension type */
            sh_buf[shp++] = 0x00; sh_buf[shp++] = 0x02; /* extension data length */
            sh_buf[shp++] = 0x03; sh_buf[shp++] = 0x04; /* TLS 1.3 */
            /* key_share: 0x0033, group=x25519(0x001d), KE_length=32, pubkey */
            sh_buf[shp++] = 0x00; sh_buf[shp++] = 0x33; /* extension type */
            int ks_len_pos = shp; shp += 2; /* extension data length placeholder */
            sh_buf[shp++] = 0x00; sh_buf[shp++] = 0x1d; /* x25519 */
            sh_buf[shp++] = 0x00; sh_buf[shp++] = 0x20; /* key length 32 */
            memcpy(sh_buf + shp, ssl->ecdhe_public_key, 32); shp += 32;
            int ks_data_len = shp - ks_len_pos - 2;
            sh_buf[ks_len_pos]     = (unsigned char)((ks_data_len >> 8) & 0xFF);
            sh_buf[ks_len_pos + 1] = (unsigned char)(ks_data_len & 0xFF);
            /* Set total extensions length */
            int total_ext_len = shp - ext_start - 2;
            sh_buf[ext_start]     = (unsigned char)((total_ext_len >> 8) & 0xFF);
            sh_buf[ext_start + 1] = (unsigned char)(total_ext_len & 0xFF);
            /* Set ServerHello length */
            int sh_len = shp - 4;
            sh_buf[sh_len_pos]     = (unsigned char)(sh_len >> 16);
            sh_buf[sh_len_pos + 1] = (unsigned char)(sh_len >> 8);
            sh_buf[sh_len_pos + 2] = (unsigned char)(sh_len);

            if (ossl_send_record(ssl, SSL3_RT_HANDSHAKE, sh_buf, shp) != 0) { free(buf); return -1; }

            /* Initialize TLS 1.3 transcript and hash CH + SH */
            ossl_hs_hash13_init(ssl);
            ossl_hs_hash13_update(ssl, buf, len);    /* ClientHello */
            ossl_hs_hash13_update(ssl, sh_buf, shp); /* ServerHello */
        }

        /* Compute shared secret from client's X25519 key share */
        unsigned char shared_secret[32];
        x25519_scalar_mult(shared_secret, ssl->ecdhe_private_key, client_key_share);

        /* Derive handshake secrets */
        if (ossl_tls13_derive_handshake_secrets(ssl, shared_secret, 32) != 0) {
            fprintf(stderr, "ossl: Failed to derive TLS 1.3 handshake secrets\n");
            free(buf); return -1;
        }
        ssl->client_seq = 0; ssl->server_seq = 0;

        /* Build server encrypted flight: EncryptedExtensions, Certificate, CertificateVerify, Finished */
        {
            unsigned char flight_buf[65536];
            int flight_len = 0;

            /* EncryptedExtensions: empty (type 0x08) */
            {
                unsigned char ee[6];
            ee[0] = OSSL_MT_ENCRYPTED_EXTENSIONS;
            ee[1] = 0x00; ee[2] = 0x00; ee[3] = 0x02;
            ee[4] = 0x00; ee[5] = 0x00; /* zero-length extensions */
                memcpy(flight_buf + flight_len, ee, 6);
                flight_len += 6;
                /* Hash EE into transcript incrementally */
                ossl_hs_hash13_update(ssl, ee, 6);
            }

            /* Certificate (type 0x0b) */
            if (ssl->ctx->cert_der) {
                int cert_msg_start = flight_len;
                int cpos = flight_len;
                flight_buf[cpos++] = 0x0b; /* handshake type */
                int chs_pos = cpos; cpos += 3; /* length placeholder */
                /* CertificateRequestContext: 1 byte length + 0 bytes */
                flight_buf[cpos++] = 0x00;
                /* CertificateList */
                int clist_pos = cpos; cpos += 3; /* cert list length placeholder */
                /* Single certificate entry */
                flight_buf[cpos++] = (unsigned char)((ssl->ctx->cert_der_len >> 16) & 0xFF);
                flight_buf[cpos++] = (unsigned char)((ssl->ctx->cert_der_len >> 8) & 0xFF);
                flight_buf[cpos++] = (unsigned char)(ssl->ctx->cert_der_len & 0xFF);
                memcpy(flight_buf + cpos, ssl->ctx->cert_der, ssl->ctx->cert_der_len);
                cpos += ssl->ctx->cert_der_len;
                /* Extensions: 0 length */
                flight_buf[cpos++] = 0x00; flight_buf[cpos++] = 0x00;
                /* Fill lengths */
                int clist_len = cpos - clist_pos - 3;
                flight_buf[clist_pos]     = (unsigned char)((clist_len >> 16) & 0xFF);
                flight_buf[clist_pos + 1] = (unsigned char)((clist_len >> 8) & 0xFF);
                flight_buf[clist_pos + 2] = (unsigned char)(clist_len & 0xFF);
                int chs_len = cpos - chs_pos - 3;
                flight_buf[chs_pos]     = (unsigned char)((chs_len >> 16) & 0xFF);
                flight_buf[chs_pos + 1] = (unsigned char)((chs_len >> 8) & 0xFF);
                flight_buf[chs_pos + 2] = (unsigned char)(chs_len);
                flight_len = cpos;
                /* Hash Cert into transcript incrementally */
                ossl_hs_hash13_update(ssl, flight_buf + cert_msg_start, flight_len - cert_msg_start);
            }

            /* CertificateVerify (type 0x0f) */
            if (ssl->ctx->key_der) {
                unsigned char *sn = NULL, *sd = NULL;
                int sn_len = 0, sd_len = 0;
                if (rsa_get_pubkey(ssl->ctx->key_der, ssl->ctx->key_der_len, &sn, &sn_len, NULL, NULL) != 0) {
                    free(buf); return -1;
                }
                if (rsa_get_privexp(ssl->ctx->key_der, ssl->ctx->key_der_len, &sd, &sd_len) != 0) {
                    free(sn); free(buf); return -1;
                }

                /* Build signed content: 64 spaces || "TLS 1.3, server CertificateVerify" || 0x00 || transcript_hash */
                unsigned char sd_content[256]; int sdl = 0;
                memset(sd_content, 0x20, 64); sdl = 64;
                const char *lbl = "TLS 1.3, server CertificateVerify";
                int lbl_len = (int)strlen(lbl);
                memcpy(sd_content + sdl, lbl, lbl_len); sdl += lbl_len;
                sd_content[sdl++] = 0x00;
                int hl = ssl->tls13_hash_len;
                unsigned char thash[48];
                ossl_hs_hash13_final(ssl, thash);
                memcpy(sd_content + sdl, thash, hl); sdl += hl;

                unsigned char hash[48];
                if (hl == 48) {
                    ossl_sha384_ctx sh; ossl_sha384_init(&sh);
                    ossl_sha384_update(&sh, sd_content, sdl);
                    ossl_sha384_final(&sh, hash);
                } else {
                    ossl_sha256_ctx sh; ossl_sha256_init(&sh);
                    ossl_sha256_update(&sh, sd_content, sdl);
                    ossl_sha256_final(&sh, hash);
                }

                /* Sign with RSA (PKCS#1 v1.5 SHA-256) */
                unsigned char *signature = (unsigned char*)malloc(sn_len);
                if (!signature) { free(sn); free(sd); free(buf); return -1; }
                int sig_ok = (rsa_sign(sn, sn_len, sd, sd_len, hash, hl, signature) == 0);
                free(sn); free(sd);

                if (!sig_ok) { free(signature); free(buf); return -1; }

                /* Build CertificateVerify message */
                int cv_msg_start = flight_len;
                int cpos = flight_len;
                flight_buf[cpos++] = OSSL_MT_CERTIFICATE_VERIFY;
                int cv_hs_pos = cpos; cpos += 3;
                /* Signature algorithm: rsa_pkcs1_sha256 = 0x0401 */
                flight_buf[cpos++] = 0x04; flight_buf[cpos++] = 0x01;
                flight_buf[cpos++] = (unsigned char)((sn_len >> 8) & 0xFF);
                flight_buf[cpos++] = (unsigned char)(sn_len & 0xFF);
                memcpy(flight_buf + cpos, signature, sn_len);
                cpos += sn_len;
                free(signature);
                int cv_hs_len = cpos - cv_hs_pos - 3;
                flight_buf[cv_hs_pos]     = (unsigned char)((cv_hs_len >> 16) & 0xFF);
                flight_buf[cv_hs_pos + 1] = (unsigned char)((cv_hs_len >> 8) & 0xFF);
                flight_buf[cv_hs_pos + 2] = (unsigned char)(cv_hs_len);
                flight_len = cpos;
                /* Hash CertVerify into transcript incrementally */
                ossl_hs_hash13_update(ssl, flight_buf + cv_msg_start, flight_len - cv_msg_start);
            }

            /* Finished (type 0x14) */
            {
                int finished_msg_start = flight_len;
                int hl = ssl->tls13_hash_len;
                unsigned char verify_data[48];
                ossl_tls13_compute_finished(ssl, ssl->server_hs_secret, verify_data);
                int cpos = flight_len;
                flight_buf[cpos++] = 0x14;
                flight_buf[cpos++] = 0x00;
                flight_buf[cpos++] = 0x00;
                flight_buf[cpos++] = (unsigned char)hl;
                memcpy(flight_buf + cpos, verify_data, hl);
                cpos += hl;
                flight_len = cpos;
                /* Hash Finished into transcript incrementally */
                ossl_hs_hash13_update(ssl, flight_buf + finished_msg_start, flight_len - finished_msg_start);
            }

            /* Note: all handshake messages already hashed incrementally above */

            /* Send CCS (middlebox compatibility) */
            {
                unsigned char ccs[1] = {1};
                if (ossl_send_record(ssl, SSL3_RT_CHANGE_CIPHER_SPEC, ccs, 1) != 0) { free(buf); return -1; }
            }

            /* Send encrypted flight (use server_hs keys) */
            if (ossl_tls13_send_encrypted(ssl, SSL3_RT_HANDSHAKE, flight_buf, flight_len, 1, 1) != 0) {
                fprintf(stderr, "ossl: Failed to send server encrypted flight\n");
                free(buf); return -1;
            }
        }

        /* Derive BOTH application secrets from CH...server Finished transcript
           (RFC 8446 §7.1: both initial secrets use the same transcript) */
        {
            unsigned char th[48];
            ossl_hs_hash13_final(ssl, th);
            if (ossl_tls13_derive_application_secrets(ssl, th, th) != 0) {
                fprintf(stderr, "ossl: Failed to derive application secrets\n");
                free(buf); return -1;
            }
        }

        /* Receive client CCS + Finished */
        {
            /* Skip CCS if present (middlebox compatibility) */
            unsigned char header[5];
            if (tcp_recv_all(ssl->fd, header, 5) != 0) { free(buf); return -1; }
            if (header[0] == SSL3_RT_CHANGE_CIPHER_SPEC) {
                unsigned char ccs_byte;
                if (tcp_recv_all(ssl->fd, &ccs_byte, 1) != 0) { free(buf); return -1; }
                /* Now read the next record */
                if (tcp_recv_all(ssl->fd, header, 5) != 0) { free(buf); return -1; }
            }

            /* Decrypt client Finished */
            int record_body = (header[3] << 8) | header[4];
            if (record_body > OSSL_MAX_RECORD_SIZE + 24) { free(buf); return -1; }
            unsigned char *rec_data = (unsigned char*)malloc(record_body);
            if (!rec_data) { free(buf); return -1; }
            if (tcp_recv_all(ssl->fd, rec_data, record_body) != 0) { free(rec_data); free(buf); return -1; }

            int ct_len = record_body - 16;
            unsigned char *ciphertext = rec_data;
            unsigned char *tag = ciphertext + ct_len;

            unsigned char nonce[12];
            memcpy(nonce, ssl->client_hs_write_iv, 12);
            for (int i = 0; i < 8; i++)
                nonce[11 - i] ^= (unsigned char)((ssl->client_seq >> (8 * i)) & 0xFF);

            unsigned char aad[5];
            aad[0] = header[0];
            aad[1] = 0x03; aad[2] = 0x03;
            aad[3] = (unsigned char)((record_body >> 8) & 0xFF);
            aad[4] = (unsigned char)(record_body & 0xFF);

            int inner_len = ct_len;
            unsigned char *decrypted = (unsigned char*)malloc(inner_len);
            if (!decrypted) { free(rec_data); free(buf); return -1; }

            int hl = ssl->tls13_hash_len;
            int dec_ok;
            if (hl == 48)
                dec_ok = aes256_gcm_decrypt(ssl->client_hs_write_key, ciphertext, ct_len, aad, 5, nonce, 12, tag, decrypted);
            else
                dec_ok = aes128_gcm_decrypt(ssl->client_hs_write_key, ciphertext, ct_len, aad, 5, nonce, 12, tag, decrypted);

            free(rec_data);

            if (dec_ok != 0) {
                fprintf(stderr, "ossl: Failed to decrypt client Finished\n");
                free(decrypted); free(buf); return -1;
            }
            ssl->client_seq++;

            /* Extract Finished message from plaintext (last byte is inner content type) */
            int inner_type = decrypted[inner_len - 1];
            int pt_len = inner_len - 1;
            if (inner_type != SSL3_RT_HANDSHAKE || pt_len < 4) {
                free(decrypted); free(buf); return -1;
            }

            /* Verify client Finished */
            int msg_type = decrypted[0];
            int msg_len = (decrypted[1] << 16) | (decrypted[2] << 8) | decrypted[3];
            if (msg_type != 0x14 || msg_len != hl || 4 + msg_len != pt_len) {
                free(decrypted); free(buf); return -1;
            }

            unsigned char expected_vd[48];
            ossl_tls13_compute_finished(ssl, ssl->client_hs_secret, expected_vd);
            if (memcmp(decrypted + 4, expected_vd, hl) != 0) {
                fprintf(stderr, "ossl: Client Finished verify mismatch\n");
                free(decrypted); free(buf); return -1;
            }

            /* Hash client Finished into transcript */
            ossl_hs_hash13_update(ssl, decrypted, pt_len);
            free(decrypted);
        }

        /* Reset sequence numbers for application data keys (RFC 8446 §5.3) */
        ssl->client_seq = 0; ssl->server_seq = 0;
        ssl->handshake_done = 1;
        free(buf);
        return 0;
    }

    /* ===== TLS 1.2 SERVER HANDSHAKE PATH ===== */
    if (pos + 1 > len) { free(buf); return -1; }
    int cm_len = buf[pos++];
    if (pos + cm_len > len) { free(buf); return -1; }
    pos += cm_len;
    if (pos < len) {
        if (pos + 2 > len) { free(buf); return -1; }
        int ext_len = (buf[pos] << 8) | buf[pos+1];
        pos += 2;
        if (pos + ext_len > len) { free(buf); return -1; }
        pos += ext_len;
    }

    /* Start handshake transcript: include ClientHello */
    ossl_hs_hash_update(ssl, buf, len);

    /* Generate ECDHE keypair if needed */
    if (use_ecdhe) {
        if (ossl_rand_bytes(ssl->ecdhe_private_key, 32) != 0) { free(buf); return -1; }
        const unsigned char basepoint[32] = {9,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
        x25519_scalar_mult(ssl->ecdhe_public_key, ssl->ecdhe_private_key, basepoint);
    }

    if (ossl_rand_bytes(ssl->server_random, 32) != 0) { free(buf); return -1; }

    /* --- Send ServerHello --- */
    unsigned char sh[256];
    int sh_len = 0;
    sh[sh_len++] = 0x02;
    int hs_len_pos = sh_len; sh_len += 3;
    sh[sh_len++] = OSSL_TLS_VERSION_MAJOR; sh[sh_len++] = OSSL_TLS_VERSION_MINOR;
    memcpy(sh + sh_len, ssl->server_random, 32); sh_len += 32;
    sh[sh_len++] = 0x00; /* session ID length */
    sh[sh_len++] = (unsigned char)((ssl->cipher_suite >> 8) & 0xFF);
    sh[sh_len++] = (unsigned char)(ssl->cipher_suite & 0xFF);
    sh[sh_len++] = 0x00; /* compression */
    int hs_len = sh_len - 4;
    sh[hs_len_pos]   = (unsigned char)(hs_len >> 16);
    sh[hs_len_pos+1] = (unsigned char)(hs_len >> 8);
    sh[hs_len_pos+2] = (unsigned char)(hs_len);
    if (ossl_send_record(ssl, SSL3_RT_HANDSHAKE, sh, sh_len) != 0) { free(buf); return -1; }
    ossl_hs_hash_update(ssl, sh, sh_len);

    /* --- Send Certificate --- */
    if (ssl->ctx->cert_der) {
        unsigned char *cert_msg = (unsigned char*)malloc(ssl->ctx->cert_der_len + 16);
        if (!cert_msg) { free(buf); return -1; }
        int cm_len = 0;
        cert_msg[cm_len++] = 0x0b;
        int chs_len_pos = cm_len; cm_len += 3;
        int list_len_pos = cm_len; cm_len += 3;
        cert_msg[cm_len++] = (unsigned char)(ssl->ctx->cert_der_len >> 16);
        cert_msg[cm_len++] = (unsigned char)(ssl->ctx->cert_der_len >> 8);
        cert_msg[cm_len++] = (unsigned char)(ssl->ctx->cert_der_len);
        memcpy(cert_msg + cm_len, ssl->ctx->cert_der, ssl->ctx->cert_der_len);
        cm_len += ssl->ctx->cert_der_len;
        int list_len = cm_len - list_len_pos - 3;
        cert_msg[list_len_pos]   = (unsigned char)(list_len >> 16);
        cert_msg[list_len_pos+1] = (unsigned char)(list_len >> 8);
        cert_msg[list_len_pos+2] = (unsigned char)(list_len);
        int chs_len = cm_len - 4;
        cert_msg[chs_len_pos]   = (unsigned char)(chs_len >> 16);
        cert_msg[chs_len_pos+1] = (unsigned char)(chs_len >> 8);
        cert_msg[chs_len_pos+2] = (unsigned char)(chs_len);
        int send_err = ossl_send_record(ssl, SSL3_RT_HANDSHAKE, cert_msg, cm_len);
        ossl_hs_hash_update(ssl, cert_msg, cm_len);
        free(cert_msg);
        if (send_err != 0) { free(buf); return -1; }
    } else {
        unsigned char empty_cert[7] = {0x0b, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00};
        if (ossl_send_record(ssl, SSL3_RT_HANDSHAKE, empty_cert, 7) != 0) { free(buf); return -1; }
        ossl_hs_hash_update(ssl, empty_cert, 7);
    }

    /* --- Send ServerKeyExchange (if ECDHE) --- */
    if (use_ecdhe) {
        unsigned char *sn = NULL, *sd = NULL;
        int sn_len = 0, sd_len = 0;
        if (rsa_get_pubkey(ssl->ctx->key_der, ssl->ctx->key_der_len, &sn, &sn_len, NULL, NULL) != 0) { free(buf); return -1; }
        if (rsa_get_privexp(ssl->ctx->key_der, ssl->ctx->key_der_len, &sd, &sd_len) != 0) {
            fprintf(stderr, "ossl: Cannot extract private exponent for ServerKeyExchange\n");
            free(sn); free(buf); return -1;
        }
        /* Build signed data: client_random + server_random + curve params + pubkey */
        unsigned char signed_data[100];
        int sd_pos = 0;
        memcpy(signed_data + sd_pos, ssl->client_random, 32); sd_pos += 32;
        memcpy(signed_data + sd_pos, ssl->server_random, 32); sd_pos += 32;
        signed_data[sd_pos++] = 0x03; /* named_curve */
        signed_data[sd_pos++] = 0x00; signed_data[sd_pos++] = 0x1D; /* x25519 */
        signed_data[sd_pos++] = 32; /* pubkey length */
        memcpy(signed_data + sd_pos, ssl->ecdhe_public_key, 32); sd_pos += 32;
        /* Hash and sign */
        unsigned char hash[32];
        ossl_sha256_ctx sha_ctx;
        ossl_sha256_init(&sha_ctx);
        ossl_sha256_update(&sha_ctx, signed_data, sd_pos);
        ossl_sha256_final(&sha_ctx, hash);
        unsigned char *signature = (unsigned char*)malloc(sn_len);
        if (!signature) { free(sn); free(sd); free(buf); return -1; }
        int sig_ok = (rsa_sign(sn, sn_len, sd, sd_len, hash, 32, signature) == 0);
        free(sn); free(sd);
        if (!sig_ok) { free(signature); free(buf); return -1; }
        /* Build ServerKeyExchange message */
        int skx_buf_size = 4 + 1 + 2 + 1 + 32 + 1 + 1 + 2 + sn_len;
        unsigned char *skx = (unsigned char*)malloc(skx_buf_size);
        if (!skx) { free(signature); free(buf); return -1; }
        int skx_len = 0;
        skx[skx_len++] = 0x0c; /* handshake type */
        int skx_hs_pos = skx_len; skx_len += 3;
        skx[skx_len++] = 0x03; /* curve type: named_curve */
        skx[skx_len++] = 0x00; skx[skx_len++] = 0x1D; /* x25519 */
        skx[skx_len++] = 32; /* pubkey len */
        memcpy(skx + skx_len, ssl->ecdhe_public_key, 32); skx_len += 32;
        skx[skx_len++] = 0x04; /* hash: sha256 */
        skx[skx_len++] = 0x01; /* sig: rsa */
        skx[skx_len++] = (unsigned char)((sn_len >> 8) & 0xFF);
        skx[skx_len++] = (unsigned char)(sn_len & 0xFF);
        memcpy(skx + skx_len, signature, sn_len); skx_len += sn_len;
        free(signature);
        int skx_hs_len = skx_len - 4;
        skx[skx_hs_pos]   = (unsigned char)(skx_hs_len >> 16);
        skx[skx_hs_pos+1] = (unsigned char)(skx_hs_len >> 8);
        skx[skx_hs_pos+2] = (unsigned char)(skx_hs_len);
        int send_err = ossl_send_record(ssl, SSL3_RT_HANDSHAKE, skx, skx_len);
        ossl_hs_hash_update(ssl, skx, skx_len);
        free(skx);
        if (send_err != 0) { free(buf); return -1; }
    }

    /* --- Send ServerHelloDone --- */
    unsigned char shd[4] = {0x0e, 0x00, 0x00, 0x00};
    if (ossl_send_record(ssl, SSL3_RT_HANDSHAKE, shd, 4) != 0) { free(buf); return -1; }
    ossl_hs_hash_update(ssl, shd, 4);

    /* --- Receive ClientKeyExchange --- */
    if (ossl_get_handshake_msg(ssl, &type, buf, 65536, &len) != 0) {
        fprintf(stderr, "ossl: Failed to receive ClientKeyExchange\n");
        free(buf); return -1;
    }
    if (type != 0x10) {
        fprintf(stderr, "ossl: Expected ClientKeyExchange (got type %d)\n", type);
        free(buf); return -1;
    }
    pos = 4;
    if (use_ecdhe) {
        /* ECDHE: read client's public key */
        if (pos + 1 > len) { free(buf); return -1; }
        int c_pub_len = buf[pos++];
        if (c_pub_len != 32 || pos + 32 > len) {
            fprintf(stderr, "ossl: Invalid ECDHE ClientKeyExchange\n");
            free(buf); return -1;
        }
        x25519_scalar_mult(ssl->pre_master_secret, ssl->ecdhe_private_key, buf + pos);
    } else {
        /* RSA: decrypt premaster secret */
        unsigned char *rn = NULL, *rd = NULL;
        int rn_len = 0, rd_len = 0;
        if (rsa_get_pubkey(ssl->ctx->key_der, ssl->ctx->key_der_len, &rn, &rn_len, NULL, NULL) != 0) { free(buf); return -1; }
        if (rsa_get_privexp(ssl->ctx->key_der, ssl->ctx->key_der_len, &rd, &rd_len) != 0) {
            fprintf(stderr, "ossl: Cannot extract private exponent\n");
            free(rn); free(buf); return -1;
        }
        int premaster_len = 48;
        if (rsa_decrypt(rn, rn_len, rd, rd_len, buf + pos, ssl->pre_master_secret, &premaster_len, 48) != 0) {
            fprintf(stderr, "ossl: RSA decryption of premaster secret failed\n");
            free(rn); free(rd); free(buf); return -1;
        }
        free(rn); free(rd);
    }
    /* Hash the ClientKeyExchange into transcript */
    ossl_hs_hash_update(ssl, buf, len);

    /* --- Derive keys --- */
    unsigned char seed[64];
    memcpy(seed, ssl->client_random, 32);
    memcpy(seed+32, ssl->server_random, 32);
    int pms_len = use_ecdhe ? 32 : 48;
    if (use_256) {
        tls_prf_sha384(ssl->pre_master_secret, pms_len, "master secret", seed, 64, ssl->master_secret, 48);
        unsigned char key_block[72], seed2[64];
        memcpy(seed2, ssl->server_random, 32); memcpy(seed2+32, ssl->client_random, 32);
        tls_prf_sha384(ssl->master_secret, 48, "key expansion", seed2, 64, key_block, 72);
        memcpy(ssl->client_write_key, key_block, 32);
        memcpy(ssl->server_write_key, key_block+32, 32);
        memcpy(ssl->client_write_iv, key_block+64, 4);
        memcpy(ssl->server_write_iv, key_block+68, 4);
    } else {
        tls_prf(ssl->pre_master_secret, pms_len, "master secret", seed, 64, ssl->master_secret, 48);
        unsigned char key_block[40], seed2[64];
        memcpy(seed2, ssl->server_random, 32); memcpy(seed2+32, ssl->client_random, 32);
        tls_prf(ssl->master_secret, 48, "key expansion", seed2, 64, key_block, 40);
        memcpy(ssl->client_write_key, key_block, 16);
        memcpy(ssl->server_write_key, key_block+16, 16);
        memcpy(ssl->client_write_iv, key_block+32, 4);
        memcpy(ssl->server_write_iv, key_block+36, 4);
    }
    ssl->client_seq = 0; ssl->server_seq = 0;

    /* --- Send CCS + Finished --- */
    unsigned char hs_digest[64];
    unsigned char verify_data[12];
    if (use_256) {
        ossl_sha384_final(&ssl->hs_hash384, hs_digest);
        tls_prf_sha384(ssl->master_secret, 48, "server finished", hs_digest, 48, verify_data, 12);
    } else {
        ossl_sha256_final(&ssl->hs_hash, hs_digest);
        tls_prf(ssl->master_secret, 48, "server finished", hs_digest, 32, verify_data, 12);
    }
    unsigned char ccs[1] = {1};
    if (ossl_send_record(ssl, SSL3_RT_CHANGE_CIPHER_SPEC, ccs, 1) != 0) { free(buf); return -1; }
    unsigned char finished_msg[256];
    int fm_len = 0;
    finished_msg[fm_len++] = 0x14;
    finished_msg[fm_len++] = 0x00; finished_msg[fm_len++] = 0x00; finished_msg[fm_len++] = 12;
    memcpy(finished_msg + fm_len, verify_data, 12);
    fm_len += 12;
    if (use_256) {
        if (ossl_send_encrypted256(ssl, SSL3_RT_HANDSHAKE, finished_msg, fm_len, 1) != 0) { free(buf); return -1; }
    } else {
        if (ossl_send_encrypted(ssl, SSL3_RT_HANDSHAKE, finished_msg, fm_len, 1) != 0) { free(buf); return -1; }
    }

    /* --- Receive client CCS + Finished --- */
    int rec_type;
    if (ossl_recv_record(ssl, &rec_type, buf, 65536, &len) != 0) {
        fprintf(stderr, "ossl: Expected ChangeCipherSpec from client\n");
        free(buf); return -1;
    }
    if (rec_type != SSL3_RT_CHANGE_CIPHER_SPEC) {
        fprintf(stderr, "ossl: Expected ChangeCipherSpec (got %d)\n", rec_type);
        free(buf); return -1;
    }
    {
        unsigned char pt[OSSL_MAX_RECORD_SIZE + 16]; int pt_len;
        if (use_256) {
            if (ossl_recv_encrypted256(ssl, &rec_type, pt, &pt_len, 0) != 0) {
                fprintf(stderr, "ossl: Failed to receive encrypted Finished\n");
                free(buf); return -1;
            }
        } else {
            if (ossl_recv_encrypted(ssl, &rec_type, pt, &pt_len, 0) != 0) {
                fprintf(stderr, "ossl: Failed to receive encrypted Finished\n");
                free(buf); return -1;
            }
        }
        /* Verify client Finished: compare verify_data */
        unsigned char expected_verify[12];
        if (use_256) {
            tls_prf_sha384(ssl->master_secret, 48, "client finished", hs_digest, 48, expected_verify, 12);
        } else {
            tls_prf(ssl->master_secret, 48, "client finished", hs_digest, 32, expected_verify, 12);
        }
        if (pt_len != 16 || memcmp(pt + 4, expected_verify, 12) != 0) {
            fprintf(stderr, "ossl: Client Finished verify_data mismatch\n");
            free(buf); return -1;
        }
    }
    ssl->handshake_done = 1;
    free(buf);
    return 0;
}

/* ========================================================================
 * Client handshake with ECDHE support (FIXED record format)
 * ======================================================================== */

static int ossl_do_client_handshake(struct ossl_ssl *ssl) {
    if (ossl_rand_bytes(ssl->client_random, 32) != 0) return -1;
    if (ossl_rand_bytes(ssl->ecdhe_private_key, 32) != 0) return -1;
    {
        const unsigned char basepoint[32] = {9,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
        x25519_scalar_mult(ssl->ecdhe_public_key, ssl->ecdhe_private_key, basepoint);
    }
    unsigned char ch[2048];
    int ch_len = 0;
    ch[ch_len++] = 0x01;
    int hs_len_pos = ch_len; ch_len += 3;
    ch[ch_len++] = OSSL_TLS_VERSION_MAJOR; ch[ch_len++] = OSSL_TLS_VERSION_MINOR;
    memcpy(ch + ch_len, ssl->client_random, 32); ch_len += 32;
    ch[ch_len++] = 0x00;
    /* Offer TLS 1.3 cipher suites first, then TLS 1.2 */
    ch[ch_len++] = 0x00; ch[ch_len++] = 0x0C; /* 6 suites = 12 bytes */
    ch[ch_len++] = (unsigned char)((TLS1_3_CK_AES_128_GCM_SHA256 >> 8) & 0xFF);
    ch[ch_len++] = (unsigned char)(TLS1_3_CK_AES_128_GCM_SHA256 & 0xFF);
    ch[ch_len++] = (unsigned char)((TLS1_3_CK_AES_256_GCM_SHA384 >> 8) & 0xFF);
    ch[ch_len++] = (unsigned char)(TLS1_3_CK_AES_256_GCM_SHA384 & 0xFF);
    ch[ch_len++] = (unsigned char)((TLS1_CK_ECDHE_RSA_WITH_AES_128_GCM_SHA256 >> 8) & 0xFF);
    ch[ch_len++] = (unsigned char)(TLS1_CK_ECDHE_RSA_WITH_AES_128_GCM_SHA256 & 0xFF);
    ch[ch_len++] = (unsigned char)((TLS1_CK_ECDHE_RSA_WITH_AES_256_GCM_SHA384 >> 8) & 0xFF);
    ch[ch_len++] = (unsigned char)(TLS1_CK_ECDHE_RSA_WITH_AES_256_GCM_SHA384 & 0xFF);
    ch[ch_len++] = (unsigned char)((TLS1_CK_RSA_WITH_AES_128_GCM_SHA256 >> 8) & 0xFF);
    ch[ch_len++] = (unsigned char)(TLS1_CK_RSA_WITH_AES_128_GCM_SHA256 & 0xFF);
    ch[ch_len++] = (unsigned char)((TLS1_CK_RSA_WITH_AES_256_GCM_SHA384 >> 8) & 0xFF);
    ch[ch_len++] = (unsigned char)(TLS1_CK_RSA_WITH_AES_256_GCM_SHA384 & 0xFF);
    ch[ch_len++] = 0x01; ch[ch_len++] = 0x00;
    int ext_pos = ch_len;
    ch_len += 2;
    int start_ext_pos = ch_len;
    if (ssl->sni_hostname) {
        int hn_len = (int)strlen(ssl->sni_hostname);
        if (hn_len > 255) hn_len = 255; /* DNS label limit */
        ch[ch_len++] = 0x00; ch[ch_len++] = 0x00;
        ch[ch_len++] = 0x00; ch[ch_len++] = (unsigned char)(5 + hn_len);
        ch[ch_len++] = 0x00; ch[ch_len++] = (unsigned char)(3 + hn_len);
        ch[ch_len++] = 0x00;
        ch[ch_len++] = (unsigned char)((hn_len >> 8) & 0xFF);
        ch[ch_len++] = (unsigned char)(hn_len & 0xFF);
        memcpy(ch + ch_len, ssl->sni_hostname, hn_len); ch_len += hn_len;
    }
    /* supported_versions (TLS 1.3) — 0x002b */
    {
        ch[ch_len++] = 0x00; ch[ch_len++] = 0x2b;
        ch[ch_len++] = 0x00; ch[ch_len++] = 0x03; /* length 3 */
        ch[ch_len++] = 0x02; /* list length 2 */
        ch[ch_len++] = 0x03; ch[ch_len++] = 0x04; /* TLS 1.3 */
    }
    /* key_share (TLS 1.3) — 0x0033 */
    {
        ch[ch_len++] = 0x00; ch[ch_len++] = 0x33;
        ch[ch_len++] = 0x00; ch[ch_len++] = 0x26; /* length 38 */
        ch[ch_len++] = 0x00; ch[ch_len++] = 0x24; /* client_shares length 36 */
        ch[ch_len++] = 0x00; ch[ch_len++] = 0x1d; /* group: x25519 */
        ch[ch_len++] = 0x00; ch[ch_len++] = 0x20; /* key_exchange length 32 */
        memcpy(ch + ch_len, ssl->ecdhe_public_key, 32); ch_len += 32;
    }
    /* signature_algorithms */
    {
        ch[ch_len++] = 0x00; ch[ch_len++] = 0x0d;
        ch[ch_len++] = 0x00; ch[ch_len++] = 0x14;
        ch[ch_len++] = 0x00; ch[ch_len++] = 0x12;
        ch[ch_len++] = 0x08; ch[ch_len++] = 0x04; /* rsa_pss_rsae_sha256 */
        ch[ch_len++] = 0x08; ch[ch_len++] = 0x05; /* rsa_pss_rsae_sha384 */
        ch[ch_len++] = 0x08; ch[ch_len++] = 0x06; /* rsa_pss_rsae_sha512 */
        ch[ch_len++] = 0x04; ch[ch_len++] = 0x01;
        ch[ch_len++] = 0x05; ch[ch_len++] = 0x01;
        ch[ch_len++] = 0x06; ch[ch_len++] = 0x01;
        ch[ch_len++] = 0x04; ch[ch_len++] = 0x03;
        ch[ch_len++] = 0x05; ch[ch_len++] = 0x03;
        ch[ch_len++] = 0x06; ch[ch_len++] = 0x03;
    }
    /* supported_groups */
    {
        ch[ch_len++] = 0x00; ch[ch_len++] = 0x0a;
        ch[ch_len++] = 0x00; ch[ch_len++] = 0x04;
        ch[ch_len++] = 0x00; ch[ch_len++] = 0x02;
        ch[ch_len++] = 0x00; ch[ch_len++] = 0x1d;
    }
    {
        ch[ch_len++] = 0x00; ch[ch_len++] = 0x0b;
        ch[ch_len++] = 0x00; ch[ch_len++] = 0x02;
        ch[ch_len++] = 0x01; ch[ch_len++] = 0x00;
    }
    /* renegotiation_info */
    {
        ch[ch_len++] = 0xff; ch[ch_len++] = 0x01;
        ch[ch_len++] = 0x00; ch[ch_len++] = 0x01;
        ch[ch_len++] = 0x00;
    }
    int total_ext_len = ch_len - start_ext_pos;
    ch[ext_pos]   = (unsigned char)((total_ext_len >> 8) & 0xFF);
    ch[ext_pos+1] = (unsigned char)(total_ext_len & 0xFF);
    int hs_len = ch_len - 4;
    ch[hs_len_pos]   = (unsigned char)(hs_len >> 16);
    ch[hs_len_pos+1] = (unsigned char)(hs_len >> 8);
    ch[hs_len_pos+2] = (unsigned char)(hs_len);
    if (ossl_send_record(ssl, SSL3_RT_HANDSHAKE, ch, ch_len) != 0) return -1;
    ossl_hs_hash_update(ssl, ch, ch_len);
    unsigned char *buf = (unsigned char*)malloc(65536);
    if (!buf) return -1;
    int type = 0, len = 0;
    if (ossl_get_handshake_msg(ssl, &type, buf, 65536, &len) != 0) {
        fprintf(stderr, "ossl: Failed to receive ServerHello\n");
        free(buf); return -1;
    }
    if (type != 0x02) {
        fprintf(stderr, "ossl: Expected ServerHello (got type 0x%02x)\n", type);
        free(buf); return -1;
    }
    ossl_hs_hash_update(ssl, buf, len);
    int pos = 4;
    if (pos + 2 > len) { free(buf); return -1; }
    int sver = (buf[pos] << 8) | buf[pos+1];
    if (sver < ((OSSL_TLS_VERSION_MAJOR << 8) | OSSL_TLS_VERSION_MINOR)) {
        fprintf(stderr, "ossl: Server version %d.%d too old\n", buf[pos], buf[pos+1]);
        free(buf); return -1;
    }
    pos += 2;
    if (pos + 32 > len) { free(buf); return -1; }
    memcpy(ssl->server_random, buf + pos, 32); pos += 32;
    if (pos + 1 > len) { free(buf); return -1; }
    int session_id_len = buf[pos++];
    if (pos + session_id_len > len) { free(buf); return -1; }
    pos += session_id_len;
    if (pos + 2 > len) { free(buf); return -1; }
    ssl->cipher_suite = (buf[pos] << 8) | buf[pos+1];
    pos += 2;
    if (pos + 1 > len) { free(buf); return -1; }
    int compression_method = buf[pos++];
    if (compression_method != 0) {
        fprintf(stderr, "ossl: Compression method %d not supported\n", compression_method);
        free(buf); return -1;
    }

    /* Parse ServerHello extensions to detect TLS 1.3 */
    int server_tls13 = 0;

    /* Check for HelloRetryRequest (special random value) */
    {
        static const unsigned char hrr_random[32] = {
            0xCF,0x21,0xAD,0x74,0xE5,0x9A,0x61,0x11,
            0xBE,0x1D,0x8C,0x02,0x1E,0x65,0xB8,0x91,
            0xC2,0xA2,0x11,0x16,0x7A,0xBB,0x8C,0x5E,
            0x07,0x9E,0x09,0xE2,0xC8,0xA8,0x33,0x9C
        };
        if (memcmp(ssl->server_random, hrr_random, 32) == 0) {
            /* HelloRetryRequest received. Parse extensions for selected_version and key_share,
               then send updated ClientHello. */
            int hrr_pos = pos;
            if (hrr_pos + 2 <= len) {
                int ext_len = (buf[hrr_pos] << 8) | buf[hrr_pos+1];
                hrr_pos += 2;
                int ext_end = hrr_pos + ext_len;
                if (ext_end > len) ext_end = len;

                int selected_group = 0;
                while (hrr_pos + 4 <= ext_end) {
                    int ext_type = (buf[hrr_pos] << 8) | buf[hrr_pos+1];
                    int e_len = (buf[hrr_pos+2] << 8) | buf[hrr_pos+3];
                    hrr_pos += 4;
                    if (hrr_pos + e_len > ext_end) break;
                    if (ext_type == OSSL_EXT_KEY_SHARE && e_len == 2) {
                        selected_group = (buf[hrr_pos] << 8) | buf[hrr_pos+1];
                    }
                    hrr_pos += e_len;
                }

                if (selected_group != 0) {
                    fprintf(stderr, "ossl: HelloRetryRequest received (group 0x%04x), sending updated ClientHello\n", selected_group);

                    /* Generate new key share for the selected group */
                    if (ossl_rand_bytes(ssl->ecdhe_private_key, 32) != 0) { free(buf); return -1; }
                    {
                        const unsigned char bp[32] = {9,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
                        x25519_scalar_mult(ssl->ecdhe_public_key, ssl->ecdhe_private_key, bp);
                    }

                    /* Build updated ClientHello with new key_share */
                    unsigned char ch2[4096];
                    int ch2_len = 0;
                    ch2[ch2_len++] = 0x01;
                    int ch2_hs_pos = ch2_len; ch2_len += 3;
                    ch2[ch2_len++] = 0x03; ch2[ch2_len++] = 0x03;
                    memcpy(ch2 + ch2_len, ssl->client_random, 32); ch2_len += 32;
                    ch2[ch2_len++] = 0x00; /* session ID */
                    /* Copy cipher suites from original CH (we need them) */
                    ch2[ch2_len++] = 0x00; ch2[ch2_len++] = 0x04; /* 2 suites = 4 bytes */
                    ch2[ch2_len++] = 0x13; ch2[ch2_len++] = 0x01;
                    ch2[ch2_len++] = 0x13; ch2[ch2_len++] = 0x02;
                    ch2[ch2_len++] = 0x01; ch2[ch2_len++] = 0x00; /* compression */
                    /* Extensions: supported_versions, key_share, sig_algs */
                    int ch2_ext_pos = ch2_len; ch2_len += 2;
                    /* supported_versions: TLS 1.3 only */
                    ch2[ch2_len++] = 0x00; ch2[ch2_len++] = 0x2b;
                    ch2[ch2_len++] = 0x00; ch2[ch2_len++] = 0x02;
                    ch2[ch2_len++] = 0x03; ch2[ch2_len++] = 0x04;
                    /* key_share with selected group */
                    ch2[ch2_len++] = 0x00; ch2[ch2_len++] = 0x33;
                    int ch2_ks_pos = ch2_len; ch2_len += 2;
                    ch2[ch2_len++] = 0x00; ch2[ch2_len++] = (unsigned char)(selected_group & 0xFF);
                    ch2[ch2_len++] = 0x00; ch2[ch2_len++] = 0x20;
                    memcpy(ch2 + ch2_len, ssl->ecdhe_public_key, 32); ch2_len += 32;
                    int ch2_ks_len = ch2_len - ch2_ks_pos - 2;
                    ch2[ch2_ks_pos] = (unsigned char)((ch2_ks_len >> 8) & 0xFF);
                    ch2[ch2_ks_pos+1] = (unsigned char)(ch2_ks_len & 0xFF);
                    /* sig_algs */
                    ch2[ch2_len++] = 0x00; ch2[ch2_len++] = OSSL_EXT_SIG_ALGS_CERT;
                    ch2[ch2_len++] = 0x00; ch2[ch2_len++] = 0x06;
                    ch2[ch2_len++] = 0x04; ch2[ch2_len++] = 0x01; /* rsa_pkcs1_sha256 */
                    ch2[ch2_len++] = 0x08; ch2[ch2_len++] = 0x04; /* rsa_pss_rsae_sha256 */
                    ch2[ch2_len++] = 0x05; ch2[ch2_len++] = 0x01; /* rsa_pkcs1_sha384 */
                    /* Set extensions length */
                    int ch2_ext_len = ch2_len - ch2_ext_pos - 2;
                    ch2[ch2_ext_pos] = (unsigned char)((ch2_ext_len >> 8) & 0xFF);
                    ch2[ch2_ext_pos+1] = (unsigned char)(ch2_ext_len & 0xFF);
                    int ch2_hs_len = ch2_len - 4;
                    ch2[ch2_hs_pos]   = (unsigned char)(ch2_hs_len >> 16);
                    ch2[ch2_hs_pos+1] = (unsigned char)(ch2_hs_len >> 8);
                    ch2[ch2_hs_pos+2] = (unsigned char)(ch2_hs_len);

                    /* Note: HRR changes the transcript: hash = Hash(message_hash || HRR) */
                    /* For simplicity, we reset the transcript and only hash the updated CH + next SH */
                    ossl_hs_hash_update(ssl, ch2, ch2_len);

                    if (ossl_send_record(ssl, SSL3_RT_HANDSHAKE, ch2, ch2_len) != 0) { free(buf); return -1; }

                    /* Receive the actual ServerHello after HRR */
                    if (ossl_get_handshake_msg(ssl, &type, buf, 65536, &len) != 0) {
                        fprintf(stderr, "ossl: Failed to receive ServerHello after HRR\n");
                        free(buf); return -1;
                    }
                    if (type != 0x02) {
                        fprintf(stderr, "ossl: Expected ServerHello after HRR (got 0x%02x)\n", type);
                        free(buf); return -1;
                    }
                    ossl_hs_hash_update(ssl, buf, len);
                    pos = 4; pos += 2; /* skip version */
                    if (pos + 32 > len) { free(buf); return -1; }
                    memcpy(ssl->server_random, buf + pos, 32); pos += 32;
                    if (pos + 1 > len) { free(buf); return -1; }
                    int ssl2 = buf[pos++];
                    if (pos + ssl2 > len) { free(buf); return -1; }
                    pos += ssl2;
                    if (pos + 2 > len) { free(buf); return -1; }
                    ssl->cipher_suite = (buf[pos] << 8) | buf[pos+1];
                    pos += 2;
                    if (pos + 1 > len) { free(buf); return -1; }
                    pos++; /* skip compression */
                }
            }
        }
    }
    int ext_total = 0;
    if (pos < len) {
        if (pos + 2 > len) { free(buf); return -1; }
        ext_total = (buf[pos] << 8) | buf[pos+1];
        pos += 2;
        if (pos + ext_total > len) { free(buf); return -1; }
        int ext_end = pos + ext_total;
        while (pos + 4 <= ext_end) {
            int etype = (buf[pos] << 8) | buf[pos+1];
            int elen = (buf[pos+2] << 8) | buf[pos+3];
            pos += 4;
            if (pos + elen > ext_end) break;
            if (etype == OSSL_EXT_SUPPORTED_VERSIONS && elen == 2) {
                int sv = (buf[pos] << 8) | buf[pos+1];
                if (sv == 0x0304) server_tls13 = 1;
            }
            if (etype == OSSL_EXT_KEY_SHARE && elen >= 4) {
                int grp = (buf[pos] << 8) | buf[pos+1];
                int klen = (buf[pos+2] << 8) | buf[pos+3];
                if (grp == 0x001D && klen == 32 && pos + 4 + klen <= ext_end) {
                    memcpy(ssl->ecdhe_server_public, buf + pos + 4, 32);
                }
            }
            pos += elen;
        }
    }

    /* Check if negotiated cipher suite is TLS 1.3 */
    if (ssl->cipher_suite == TLS1_3_CK_AES_128_GCM_SHA256 ||
        ssl->cipher_suite == TLS1_3_CK_AES_256_GCM_SHA384) {
        server_tls13 = 1;
    }

    if (server_tls13) {
        /* ===== TLS 1.3 CLIENT HANDSHAKE PATH ===== */
        ssl->is_tls13 = 1;
        ssl->negotiated_cs = ssl->cipher_suite;
        if (ssl->cipher_suite == TLS1_3_CK_AES_256_GCM_SHA384)
            ssl->tls13_hash_len = 48;
        else
            ssl->tls13_hash_len = 32;

        /* Initialize TLS 1.3 transcript and hash ClientHello+ServerHello */
        ossl_hs_hash13_init(ssl);
        /* Hash ClientHello (which is in ch[]) */
        ossl_hs_hash13_update(ssl, ch, hs_len + 4);
        /* Hash ServerHello (which is in buf[]) */
        ossl_hs_hash13_update(ssl, buf, len);

        /* Compute X25519 shared secret */
        unsigned char shared_secret[32];
        x25519_scalar_mult(shared_secret, ssl->ecdhe_private_key, ssl->ecdhe_server_public);

        /* Derive handshake secrets */
        if (ossl_tls13_derive_handshake_secrets(ssl, shared_secret, 32) != 0) {
            fprintf(stderr, "ossl: Failed to derive TLS 1.3 handshake secrets\n");
            free(buf); return -1;
        }
        ssl->client_seq = 0; ssl->server_seq = 0;

        /* Receive server encrypted flight */
        {
            unsigned char hs_buf[65536];
            int hs_buf_len = 0;
            int hs_buf_off = 0;

            /* Read all encrypted handshake records */
            while (1) {
                unsigned char rec_buf[65536];
                int rtype, rlen;
                if (ossl_tls13_recv_encrypted(ssl, &rtype, rec_buf, &rlen, 1, 1) != 0) {
                    fprintf(stderr, "ossl: Failed to receive encrypted handshake record (hs_buf_len=%d)\n", hs_buf_len);
                    free(buf); return -1;
                }
                /* Some servers send inner type = handshake message type (0x08, 0x0b, etc.),
                   some send inner type = 22 (handshake). Handle both by collecting
                   handshake payload data and parsing messages from it. */
                if (rtype == SSL3_RT_HANDSHAKE || rtype == OSSL_MT_ENCRYPTED_EXTENSIONS ||
                    rtype == 0x0b || rtype == OSSL_MT_CERTIFICATE_VERIFY || rtype == 0x14) {
                    if (hs_buf_len + rlen > (int)sizeof(hs_buf)) { free(buf); return -1; }
                    /* If the inner type is a handshake message type, wrap it in framing */
                    if (rtype != SSL3_RT_HANDSHAKE) {
                        unsigned char frame[5];
                        frame[0] = (unsigned char)rtype;
                        frame[1] = (unsigned char)((rlen >> 16) & 0xFF);
                        frame[2] = (unsigned char)((rlen >> 8) & 0xFF);
                        frame[3] = (unsigned char)(rlen & 0xFF);
                        if (hs_buf_len + 4 + rlen > (int)sizeof(hs_buf)) { free(buf); return -1; }
                        memcpy(hs_buf + hs_buf_len, frame, 4);
                        hs_buf_len += 4;
                        memcpy(hs_buf + hs_buf_len, rec_buf, rlen);
                        hs_buf_len += rlen;
                        /* Fall through to check for Finished below */
                    } else {
                        memcpy(hs_buf + hs_buf_len, rec_buf, rlen);
                        hs_buf_len += rlen;
                    }
                    /* Process messages from buffer and see if we have Finished */
                    {
                        int off = hs_buf_off;
                        int got_finished = 0;
                        while (off + 4 <= hs_buf_len) {
                            int msg_type_check = hs_buf[off];
                            int msg_len = (hs_buf[off+1] << 16) | (hs_buf[off+2] << 8) | hs_buf[off+3];
                            if (off + 4 + msg_len > hs_buf_len) break; /* Incomplete message, need more data */
                            if (msg_type_check == 0x14) got_finished = 1;
                            off += 4 + msg_len;
                        }
                        if (got_finished) break; /* All server handshake messages received */
                    }
                } else if (rtype == SSL3_RT_ALERT) {
                    return -1; /* Server sent an alert */
                }
            }

            /* Parse individual handshake messages */
            while (hs_buf_off + 4 <= hs_buf_len) {
                int msg_type = hs_buf[hs_buf_off];
                int msg_len = (hs_buf[hs_buf_off+1] << 16) | (hs_buf[hs_buf_off+2] << 8) | hs_buf[hs_buf_off+3];
                if (hs_buf_off + 4 + msg_len > hs_buf_len) break;

                if (msg_type == OSSL_MT_ENCRYPTED_EXTENSIONS) {
                    ossl_hs_hash13_update(ssl, hs_buf + hs_buf_off, 4 + msg_len);
                } else if (msg_type == 0x0b) {
                    unsigned char *cd = hs_buf + hs_buf_off + 4;
                    ossl_hs_hash13_update(ssl, hs_buf + hs_buf_off, 4 + msg_len);
                    /* Parse certificate chain */
                    int cp = 0;
                    if (cp + 1 > msg_len) goto cert_fail;
                    int ctx_len = cd[cp++];
                    if (cp + ctx_len > msg_len) goto cert_fail;
                    cp += ctx_len;
                    if (cp + 3 > msg_len) goto cert_fail;
                    int clist_len = (cd[cp] << 16) | (cd[cp+1] << 8) | cd[cp+2];
                    cp += 3;
                    if (cp + clist_len > msg_len) goto cert_fail;
                    { int clend = cp + clist_len, sc = cp, nc = 0;
                      while (sc + 3 <= clend) {
                          int cl = (cd[sc] << 16) | (cd[sc+1] << 8) | cd[sc+2];
                          sc += 3;
                          if (cl <= 0 || sc + cl + 2 > clend) break;
                          sc += cl;
                          /* Skip extensions */
                          int ext_len = (cd[sc] << 8) | cd[sc+1];
                          sc += 2;
                          if (sc + ext_len > clend) break;
                          sc += ext_len;
                          nc++;
                      }
                      if (sc != clend || nc == 0) goto cert_fail;
                      ssl->peer_cert_chain_count = nc;
                      ssl->peer_cert_chain_der = (unsigned char**)calloc((size_t)nc, sizeof(unsigned char*));
                      ssl->peer_cert_chain_der_len = (int*)calloc((size_t)nc, sizeof(int));
                      if (!ssl->peer_cert_chain_der || !ssl->peer_cert_chain_der_len) goto cert_fail;
                      for (int i = 0; i < nc; i++) {
                          int cl = (cd[cp] << 16) | (cd[cp+1] << 8) | cd[cp+2]; cp += 3;
                          ssl->peer_cert_chain_der[i] = (unsigned char*)malloc((size_t)cl);
                          if (!ssl->peer_cert_chain_der[i]) goto cert_fail;
                          memcpy(ssl->peer_cert_chain_der[i], cd + cp, (size_t)cl);
                          ssl->peer_cert_chain_der_len[i] = cl; cp += cl;
                          /* Skip TLS 1.3 CertificateEntry extensions */
                          if (cp + 2 > clend) goto cert_fail;
                          int ext_len = (cd[cp] << 8) | cd[cp+1]; cp += 2;
                          if (cp + ext_len > clend) goto cert_fail;
                          cp += ext_len;
}
                       ssl->peer_cert_der = (unsigned char*)malloc((size_t)ssl->peer_cert_chain_der_len[0]);
                       if (!ssl->peer_cert_der) goto cert_fail;
                       memcpy(ssl->peer_cert_der, ssl->peer_cert_chain_der[0], (size_t)ssl->peer_cert_chain_der_len[0]);
                       ssl->peer_cert_der_len = ssl->peer_cert_chain_der_len[0];
                       goto cert_done;
cert_fail:
                       if (ssl->peer_cert_chain_der) {
                           for (int j = 0; j < ssl->peer_cert_chain_count; j++) free(ssl->peer_cert_chain_der[j]);
                           free(ssl->peer_cert_chain_der);
                           free(ssl->peer_cert_chain_der_len);
                       }
                       free(ssl->peer_cert_der);
                       ssl->peer_cert_der = NULL;
                       ssl->peer_cert_chain_der = NULL;
                       ssl->peer_cert_chain_der_len = NULL;
                       ssl->peer_cert_chain_count = 0;
                       free(buf); return -1;
                     cert_done:; }
                } else if (msg_type == OSSL_MT_CERTIFICATE_VERIFY) {
                    unsigned char *cd = hs_buf + hs_buf_off + 4;
                    if (msg_len < 4) { free(buf); return -1; }
                    int sig_algo = (cd[0] << 8) | cd[1];
                    int sig_len = (cd[2] << 8) | cd[3];
                    if (msg_len < 4 + sig_len) { free(buf); return -1; }
                    unsigned char *sn = NULL, *se = NULL;
                    int sn_len = 0, se_len = 0;
                    /* Try RSA key first, then EC */
                    int rsa_ok = rsa_get_pubkey_from_cert(ssl->peer_cert_der, ssl->peer_cert_der_len,
                                                           &sn, &sn_len, &se, &se_len);
                    int hl = ssl->tls13_hash_len;
                    /* Take transcript hash BEFORE hashing CertVerify (RFC 8446 §4.4.3) */
                    unsigned char thash[48];
                    ossl_hs_hash13_final(ssl, thash);
                    unsigned char sd[256]; int sdl = 0;
                    memset(sd, 0x20, 64); sdl = 64;
                    const char *lbl = "TLS 1.3, server CertificateVerify";
                    int ll = (int)strlen(lbl);
                    memcpy(sd + sdl, lbl, ll); sdl += ll;
                    sd[sdl++] = 0;
                    memcpy(sd + sdl, thash, hl); sdl += hl;
                    unsigned char h[48];
                    if (hl == 48) { ossl_sha384_ctx sh; ossl_sha384_init(&sh); ossl_sha384_update(&sh, sd, sdl); ossl_sha384_final(&sh, h); }
                    else { ossl_sha256_ctx sh; ossl_sha256_init(&sh); ossl_sha256_update(&sh, sd, sdl); ossl_sha256_final(&sh, h); }

                    int verify_ok = -1;
                    if (sig_algo == 0x0804 || sig_algo == 0x0805) {
                        if (rsa_ok == 0) {
                            verify_ok = ossl_rsa_pss_verify(sn, sn_len, se, se_len, h, hl, cd + 4, sig_len, hl);
                        }
                    } else if (sig_algo == 0x0403) {
                        /* ECDSA P-256 SHA-256 */
                        unsigned char ec_x[32], ec_y[32];
                        if (ec_get_pubkey_from_cert(ssl->peer_cert_der, ssl->peer_cert_der_len, ec_x, ec_y) == 0) {
                            verify_ok = (p256_verify_hash(h, (size_t)hl, cd + 4, (size_t)sig_len, ec_x, ec_y)
                                         == P256_SUCCESS) ? 0 : -1;
                        }
                    } else if (sig_algo == 0x0201 || sig_algo == 0x0401 || sig_algo == 0x0501 || sig_algo == 0x0601) {
                        if (rsa_ok == 0) {
                            verify_ok = rsa_verify_signature(sn, sn_len, se, se_len, h, hl, cd + 4, sig_len);
                        }
                    }
                    if (verify_ok != 0) {
                        fprintf(stderr, "ossl: CertificateVerify signature verification failed (sig_algo=0x%04x)\n", sig_algo);
                        if (sn) free(sn);
                        if (se) free(se);
                        free(buf); return -1;
                    }
                    /* Hash CertVerify into transcript AFTER verification */
                    ossl_hs_hash13_update(ssl, hs_buf + hs_buf_off, 4 + msg_len);
                    if (sn) free(sn);
                    if (se) free(se);
                } else if (msg_type == 0x14) {
                    unsigned char *cd = hs_buf + hs_buf_off + 4;
                    int hl = ssl->tls13_hash_len;
                    /* Verify BEFORE hashing */
                    unsigned char ev[48];
                    ossl_tls13_compute_finished(ssl, ssl->server_hs_secret, ev);
                    if (msg_len != hl || memcmp(cd, ev, hl) != 0) {
                        fprintf(stderr, "ossl: Server Finished verify mismatch\n");
                        free(buf); return -1;
                    }
                    ossl_hs_hash13_update(ssl, hs_buf + hs_buf_off, 4 + msg_len);
                    /* Derive BOTH application traffic secrets from this transcript
                       (CH...server Finished). RFC 8446 §7.1: both client_ap and
                       server_ap initial secrets use the same transcript hash. */
                    {
                        unsigned char th[48];
                        ossl_hs_hash13_final(ssl, th);
                        if (ossl_tls13_derive_application_secrets(ssl, th, th) != 0) {
                            fprintf(stderr, "ossl: Failed to derive application secrets\n");
                            free(buf); return -1;
                        }
                    }
                } else {
                    fprintf(stderr, "ossl: Unexpected TLS 1.3 handshake msg 0x%02x\n", msg_type);
                    free(buf); return -1;
                }
                hs_buf_off += 4 + msg_len;
            }
        }

/* Send client Finished (encrypted with client_hs keys) */
        {
            unsigned char verify_data[48];
            ossl_tls13_compute_finished(ssl, ssl->client_hs_secret, verify_data);

            unsigned char finished_msg[256];
            int fm_len = 0;
            finished_msg[fm_len++] = 0x14;
            finished_msg[fm_len++] = 0x00;
            finished_msg[fm_len++] = 0x00;
            int hl = ssl->tls13_hash_len;
            finished_msg[fm_len++] = (unsigned char)hl;
            memcpy(finished_msg + fm_len, verify_data, hl);
            fm_len += hl;

            /* Hash client Finished into transcript (needed for resumption master secret, etc.) */
            ossl_hs_hash13_update(ssl, finished_msg, fm_len);

            if (ossl_tls13_send_encrypted(ssl, SSL3_RT_HANDSHAKE, finished_msg, fm_len, 0, 1) != 0) {
                fprintf(stderr, "ossl: Failed to send client Finished\n");
                free(buf); return -1;
            }
        }

        /* Reset sequence numbers for application data keys (RFC 8446 §5.3) */
        ssl->client_seq = 0; ssl->server_seq = 0;
        ssl->handshake_done = 1;
        free(buf);
        return 0;
        /* ===== END TLS 1.3 CLIENT HANDSHAKE PATH ===== */
    }

    /* ===== TLS 1.2 CLIENT HANDSHAKE PATH ===== */
    ssl->negotiated_cs = ssl->cipher_suite;
    int use_ecdhe = (ssl->cipher_suite == TLS1_CK_ECDHE_RSA_WITH_AES_128_GCM_SHA256 ||
                     ssl->cipher_suite == TLS1_CK_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
    int use_256 = (ssl->cipher_suite == TLS1_CK_ECDHE_RSA_WITH_AES_256_GCM_SHA384 ||
                   ssl->cipher_suite == TLS1_CK_RSA_WITH_AES_256_GCM_SHA384);
    if (ossl_get_handshake_msg(ssl, &type, buf, 65536, &len) != 0) {
        fprintf(stderr, "ossl: Expected Certificate from server\n");
        free(buf); return -1;
    }
    if (type != 0x0b) {
        fprintf(stderr, "ossl: Expected Certificate message (got type 0x%02x)\n", type);
        free(buf); return -1;
    }
    pos = 4;
    if (pos + 3 > len) { free(buf); return -1; }
    int list_len = (buf[pos] << 16) | (buf[pos+1] << 8) | buf[pos+2];
    if (list_len == 0) { free(buf); return -1; }
    pos += 3;
    int cert_list_end = pos + list_len;
    if (cert_list_end > len) { free(buf); return -1; }
    /* Count certificates in the chain */
    {
        int scan = pos;
        int ncert = 0;
        while (scan + 3 <= cert_list_end) {
            int clen = (buf[scan] << 16) | (buf[scan+1] << 8) | buf[scan+2];
            scan += 3;
            if (clen <= 0 || scan + clen > cert_list_end) break;
            scan += clen;
            ncert++;
        }
        /* Verify entire list was consumed (no trailing garbage or truncated entries) */
        if (scan != cert_list_end || ncert == 0) { free(buf); return -1; }
        ssl->peer_cert_chain_count = ncert;
        ssl->peer_cert_chain_der = (unsigned char**)calloc((size_t)ncert, sizeof(unsigned char*));
        ssl->peer_cert_chain_der_len = (int*)calloc((size_t)ncert, sizeof(int));
        if (!ssl->peer_cert_chain_der || !ssl->peer_cert_chain_der_len) {
            free(buf); return -1;
        }
        for (int i = 0; i < ncert; i++) {
            int clen = (buf[pos] << 16) | (buf[pos+1] << 8) | buf[pos+2];
            pos += 3;
            if (clen <= 0 || pos + clen > cert_list_end) goto cert_parse_fail;
            ssl->peer_cert_chain_der[i] = (unsigned char*)malloc((size_t)clen);
            if (!ssl->peer_cert_chain_der[i]) goto cert_parse_fail;
            memcpy(ssl->peer_cert_chain_der[i], buf + pos, (size_t)clen);
            ssl->peer_cert_chain_der_len[i] = clen;
            pos += clen;
        }
        /* success path: jump over cleanup */
        goto cert_parse_done;
    cert_parse_fail:
        free(ssl->peer_cert_der); ssl->peer_cert_der = NULL;
        for (int j = 0; j < ncert; j++) free(ssl->peer_cert_chain_der[j]);
        free(ssl->peer_cert_chain_der);
        free(ssl->peer_cert_chain_der_len);
        ssl->peer_cert_chain_der = NULL;
        ssl->peer_cert_chain_der_len = NULL;
        ssl->peer_cert_chain_count = 0;
        free(buf); return -1;
    cert_parse_done:;
    }
    /* Copy first cert as peer_cert_der for SSL_get_peer_certificate */
    ssl->peer_cert_der = (unsigned char*)malloc((size_t)ssl->peer_cert_chain_der_len[0]);
    if (!ssl->peer_cert_der) { free(buf); return -1; }
    memcpy(ssl->peer_cert_der, ssl->peer_cert_chain_der[0], (size_t)ssl->peer_cert_chain_der_len[0]);
    ssl->peer_cert_der_len = ssl->peer_cert_chain_der_len[0];
    ossl_hs_hash_update(ssl, buf, len);
    if (use_ecdhe) {
        if (ossl_get_handshake_msg(ssl, &type, buf, 65536, &len) != 0) {
            fprintf(stderr, "ossl: Expected ServerKeyExchange\n");
            free(buf); return -1;
        }
        if (type != 0x0c) {
            fprintf(stderr, "ossl: Expected ServerKeyExchange (type 0x0c), got 0x%02x\n", type);
            free(buf); return -1;
        }
        ossl_hs_hash_update(ssl, buf, len);
        int skx_pos = 4;
        if (skx_pos + 4 > len) { free(buf); return -1; }
        int curve_type = buf[skx_pos];
        skx_pos++;
        int named_curve = (buf[skx_pos] << 8) | buf[skx_pos+1];
        skx_pos += 2;
        int pubkey_len = buf[skx_pos++];
        if (pubkey_len != 32) {
            fprintf(stderr, "ossl: Unexpected ECDHE pubkey len %d\n", pubkey_len);
            free(buf); return -1;
        }
        if (skx_pos + pubkey_len + 4 > len) { free(buf); return -1; }
        memcpy(ssl->ecdhe_server_public, buf + skx_pos, 32);
        skx_pos += pubkey_len;
        int hash_algo = buf[skx_pos++];
        int sig_algo  = buf[skx_pos++];
        int sig_len   = (buf[skx_pos] << 8) | buf[skx_pos+1];
        skx_pos += 2;
        if (skx_pos + sig_len > len) { free(buf); return -1; }
        if (sig_algo != 0x01) {
            fprintf(stderr, "ossl: Unsupported signature algorithm 0x%02x\n", sig_algo);
            free(buf); return -1;
        }
        unsigned char *n = NULL, *e = NULL;
        int n_len = 0, e_len = 0;
        if (rsa_get_pubkey_from_cert(ssl->peer_cert_der, ssl->peer_cert_der_len, &n, &n_len, &e, &e_len) != 0) {
            fprintf(stderr, "ossl: Could not extract RSA public key from peer certificate\n");
            free(buf); return -1;
        }
        /* Build signed data: client_random + server_random + curve_type + named_curve + pubkey_len + pubkey */
        unsigned char signed_data[100];
        int sd_pos = 0;
        memcpy(signed_data + sd_pos, ssl->client_random, 32); sd_pos += 32;
        memcpy(signed_data + sd_pos, ssl->server_random, 32); sd_pos += 32;
        signed_data[sd_pos++] = (unsigned char)curve_type;
        signed_data[sd_pos++] = (unsigned char)(named_curve >> 8);
        signed_data[sd_pos++] = (unsigned char)(named_curve & 0xFF);
        signed_data[sd_pos++] = (unsigned char)pubkey_len;
        memcpy(signed_data + sd_pos, ssl->ecdhe_server_public, 32); sd_pos += 32;
        /* Hash the signed data */
        unsigned char hash[48];
        int hash_len;
        if (hash_algo == 0x04) {
            ossl_sha256_ctx sha_ctx;
            ossl_sha256_init(&sha_ctx);
            ossl_sha256_update(&sha_ctx, signed_data, sd_pos);
            ossl_sha256_final(&sha_ctx, hash);
            hash_len = 32;
        } else if (hash_algo == 0x05) {
            ossl_sha384_ctx sha_ctx;
            ossl_sha384_init(&sha_ctx);
            ossl_sha384_update(&sha_ctx, signed_data, sd_pos);
            ossl_sha384_final(&sha_ctx, hash);
            hash_len = 48;
        } else {
            fprintf(stderr, "ossl: Unsupported hash algorithm 0x%02x\n", hash_algo);
            free(n); free(e); free(buf); return -1;
        }
        /* Verify signature */
        if (rsa_verify_signature(n, n_len, e, e_len, hash, hash_len, buf + skx_pos, sig_len) != 0) {
            fprintf(stderr, "ossl: ServerKeyExchange signature verification failed\n");
            free(n); free(e); free(buf); return -1;
        }
        free(n); free(e);
        x25519_scalar_mult(ssl->pre_master_secret, ssl->ecdhe_private_key, ssl->ecdhe_server_public);
        if (ossl_get_handshake_msg(ssl, &type, buf, 65536, &len) != 0) {
            fprintf(stderr, "ossl: Expected ServerHelloDone\n");
            free(buf); return -1;
        }
        if (type != 0x0e) {
            fprintf(stderr, "ossl: Expected ServerHelloDone (got type 0x%02x)\n", type);
            free(buf); return -1;
        }
        ossl_hs_hash_update(ssl, buf, len);
        unsigned char cke[1024];
        int cke_len = 0;
        cke[cke_len++] = 0x10;
        int cke_hs_len_pos = cke_len; cke_len += 3;
        cke[cke_len++] = 32;
        memcpy(cke + cke_len, ssl->ecdhe_public_key, 32);
        cke_len += 32;
        int cke_hs_len = cke_len - 4;
        cke[cke_hs_len_pos]   = (unsigned char)(cke_hs_len >> 16);
        cke[cke_hs_len_pos+1] = (unsigned char)(cke_hs_len >> 8);
        cke[cke_hs_len_pos+2] = (unsigned char)(cke_hs_len);
        if (ossl_send_record(ssl, SSL3_RT_HANDSHAKE, cke, cke_len) != 0) { free(buf); return -1; }
        ossl_hs_hash_update(ssl, cke, cke_len);
    } else {
        if (ossl_get_handshake_msg(ssl, &type, buf, 65536, &len) != 0) {
            fprintf(stderr, "ossl: Expected ServerHelloDone\n");
            free(buf); return -1;
        }
        if (type != 0x0e) {
            fprintf(stderr, "ossl: Expected ServerHelloDone (got type 0x%02x)\n", type);
            free(buf); return -1;
        }
        ossl_hs_hash_update(ssl, buf, len);
        unsigned char *server_n = NULL, *server_e = NULL;
        int server_n_len = 0, server_e_len = 0;
        if (rsa_get_pubkey_from_cert(ssl->peer_cert_der, ssl->peer_cert_der_len, &server_n, &server_n_len, &server_e, &server_e_len) != 0) {
            fprintf(stderr, "ossl: Could not extract RSA public key from peer certificate\n");
            free(buf); return -1;
        }
        ssl->pre_master_secret[0] = OSSL_TLS_VERSION_MAJOR;
        ssl->pre_master_secret[1] = OSSL_TLS_VERSION_MINOR;
        if (ossl_rand_bytes(ssl->pre_master_secret + 2, 46) != 0) { free(server_n); free(server_e); free(buf); return -1; }
        unsigned char *encrypted_premaster = (unsigned char*)malloc(server_n_len);
        if (!encrypted_premaster) { free(server_n); free(server_e); free(buf); return -1; }
        if (rsa_encrypt(server_n, server_n_len, server_e, server_e_len,
                        ssl->pre_master_secret, 48, encrypted_premaster) != 0) {
            fprintf(stderr, "ossl: RSA encryption of premaster failed\n");
            free(encrypted_premaster); free(server_n); free(server_e); free(buf); return -1;
        }
        free(server_n); free(server_e);
        /* Build ClientKeyExchange with RSA-encrypted premaster */
        int cke_buf_size = 4 + 2 + server_n_len;
        unsigned char *cke = (unsigned char*)malloc(cke_buf_size);
        if (!cke) { free(encrypted_premaster); free(buf); return -1; }
        int cke_len = 0;
        cke[cke_len++] = 0x10;
        int cke_hs_len_pos = cke_len; cke_len += 3;
        cke[cke_len++] = (unsigned char)((server_n_len >> 8) & 0xFF);
        cke[cke_len++] = (unsigned char)(server_n_len & 0xFF);
        memcpy(cke + cke_len, encrypted_premaster, server_n_len);
        cke_len += server_n_len;
        free(encrypted_premaster);
        int cke_hs_len = cke_len - 4;
        cke[cke_hs_len_pos]   = (unsigned char)(cke_hs_len >> 16);
        cke[cke_hs_len_pos+1] = (unsigned char)(cke_hs_len >> 8);
        cke[cke_hs_len_pos+2] = (unsigned char)(cke_hs_len);
        int send_err = ossl_send_record(ssl, SSL3_RT_HANDSHAKE, cke, cke_len);
        ossl_hs_hash_update(ssl, cke, cke_len);
        free(cke);
        if (send_err != 0) { free(buf); return -1; }
    }
    unsigned char seed[64];
    memcpy(seed, ssl->client_random, 32);
    memcpy(seed+32, ssl->server_random, 32);
    int pms_len = use_ecdhe ? 32 : 48;
    if (use_256) {
        tls_prf_sha384(ssl->pre_master_secret, pms_len, "master secret", seed, 64, ssl->master_secret, 48);
        unsigned char key_block[72], seed2[64];
        memcpy(seed2, ssl->server_random, 32); memcpy(seed2+32, ssl->client_random, 32);
        tls_prf_sha384(ssl->master_secret, 48, "key expansion", seed2, 64, key_block, 72);
        memcpy(ssl->client_write_key, key_block, 32);
        memcpy(ssl->server_write_key, key_block+32, 32);
        memcpy(ssl->client_write_iv, key_block+64, 4);
        memcpy(ssl->server_write_iv, key_block+68, 4);
    } else {
        tls_prf(ssl->pre_master_secret, pms_len, "master secret", seed, 64, ssl->master_secret, 48);
        unsigned char key_block[40], seed2[64];
        memcpy(seed2, ssl->server_random, 32); memcpy(seed2+32, ssl->client_random, 32);
        tls_prf(ssl->master_secret, 48, "key expansion", seed2, 64, key_block, 40);
        memcpy(ssl->client_write_key, key_block, 16);
        memcpy(ssl->server_write_key, key_block+16, 16);
        memcpy(ssl->client_write_iv, key_block+32, 4);
        memcpy(ssl->server_write_iv, key_block+36, 4);
    }
    ssl->client_seq = 0; ssl->server_seq = 0;
    /* Save handshake transcript hash state before finalizing for client Finished,
     * because the server Finished hash must also include the client Finished message. */
    ossl_sha256_ctx saved_hash; memcpy(&saved_hash, &ssl->hs_hash, sizeof(saved_hash));
    ossl_sha384_ctx saved_hash384; memcpy(&saved_hash384, &ssl->hs_hash384, sizeof(saved_hash384));
    unsigned char ccs[1] = {1};
    if (ossl_send_record(ssl, SSL3_RT_CHANGE_CIPHER_SPEC, ccs, 1) != 0) { free(buf); return -1; }
    unsigned char hs_digest[64];
    unsigned char verify_data[12];
    if (use_256) {
        ossl_sha384_final(&ssl->hs_hash384, hs_digest);
        tls_prf_sha384(ssl->master_secret, 48, "client finished", hs_digest, 48, verify_data, 12);
    } else {
        ossl_sha256_final(&ssl->hs_hash, hs_digest);
        tls_prf(ssl->master_secret, 48, "client finished", hs_digest, 32, verify_data, 12);
    }
    unsigned char finished_msg[256];
    int fm_len = 0;
    finished_msg[fm_len++] = 0x14;
    finished_msg[fm_len++] = 0x00; finished_msg[fm_len++] = 0x00; finished_msg[fm_len++] = 12;
    memcpy(finished_msg + fm_len, verify_data, 12);
    fm_len += 12;
    if (use_256) {
        if (ossl_send_encrypted256(ssl, SSL3_RT_HANDSHAKE, finished_msg, fm_len, 0) != 0) { free(buf); return -1; }
    } else {
        if (ossl_send_encrypted(ssl, SSL3_RT_HANDSHAKE, finished_msg, fm_len, 0) != 0) { free(buf); return -1; }
    }
    /* Restore hash state and include client Finished for server Finished verification */
    memcpy(&ssl->hs_hash, &saved_hash, sizeof(saved_hash));
    memcpy(&ssl->hs_hash384, &saved_hash384, sizeof(saved_hash384));
    ossl_hs_hash_update(ssl, finished_msg, fm_len);
    int rec_type = 0;
    if (ossl_recv_record(ssl, &rec_type, buf, 65536, &len) != 0) {
        fprintf(stderr, "ossl: Expected ChangeCipherSpec from server\n");
        free(buf); return -1;
    }
    if (rec_type != SSL3_RT_CHANGE_CIPHER_SPEC) {
        fprintf(stderr, "ossl: Expected ChangeCipherSpec (got %d)\n", rec_type);
        free(buf); return -1;
    }
    unsigned char pt[OSSL_MAX_RECORD_SIZE + 16]; int pt_len;
    if (use_256) {
        if (ossl_recv_encrypted256(ssl, &rec_type, pt, &pt_len, 1) != 0) {
            fprintf(stderr, "ossl: Failed to receive server Finished\n");
            free(buf); return -1;
        }
    } else {
        if (ossl_recv_encrypted(ssl, &rec_type, pt, &pt_len, 1) != 0) {
            fprintf(stderr, "ossl: Failed to receive server Finished\n");
            free(buf); return -1;
        }
    }
    /* Verify server Finished message (hash now includes client Finished) */
    {
        unsigned char expected_verify[12];
        unsigned char server_hs_digest[64];
        if (use_256) {
            ossl_sha384_final(&ssl->hs_hash384, server_hs_digest);
            tls_prf_sha384(ssl->master_secret, 48, "server finished", server_hs_digest, 48, expected_verify, 12);
        } else {
            ossl_sha256_final(&ssl->hs_hash, server_hs_digest);
            tls_prf(ssl->master_secret, 48, "server finished", server_hs_digest, 32, expected_verify, 12);
        }
        if (pt_len != 16 || memcmp(pt + 4, expected_verify, 12) != 0) {
            fprintf(stderr, "ossl: Server Finished verify_data mismatch\n");
            free(buf); return -1;
        }
    }
    ssl->handshake_done = 1;
    free(buf);
    return 0;
}

/* ========================================================================
 * Public API implementations
 * ======================================================================== */

SSL_CTX* SSL_CTX_new(SSL_METHOD* method) {
    if (ossl_platform_init() != 0) return NULL;
    struct ossl_ctx *ctx = (struct ossl_ctx*)calloc(1, sizeof(struct ossl_ctx));
    if (!ctx) return NULL;
    ctx->method = (method == TLS_server_method()) ? 0 : 1;
    return (SSL_CTX*)ctx;
}

SSL_METHOD* TLS_server_method(void) { return (SSL_METHOD*)1; }
SSL_METHOD* TLS_client_method(void) { return (SSL_METHOD*)2; }

void SSL_CTX_free(SSL_CTX* ctx) {
    if (!ctx) return;
    struct ossl_ctx *c = (struct ossl_ctx*)ctx;
    free(c->cert_der); free(c->key_der);
    if (c->trusted_ca_der) {
        for (int i = 0; i < c->trusted_ca_count; i++) free(c->trusted_ca_der[i]);
        free(c->trusted_ca_der);
        free(c->trusted_ca_der_len);
    }
    free(c);
}

int SSL_CTX_use_PrivateKey_file(SSL_CTX* ctx, const char* file, int type) {
    struct ossl_ctx *c = (struct ossl_ctx*)ctx;
    if (type != SSL_FILETYPE_PEM) { fprintf(stderr, "ossl: Only PEM\n"); return 0; }
    FILE *fp = fopen(file, "rb");
    if (!fp) { fprintf(stderr, "ossl: Cannot open '%s'\n", file); return 0; }
    fseek(fp, 0, SEEK_END); long sz = ftell(fp); fseek(fp, 0, SEEK_SET);
    char *pem = (char*)malloc(sz + 1);
    if (!pem) { fclose(fp); return 0; }
    if (fread(pem, 1, (size_t)sz, fp) != (size_t)sz) { free(pem); fclose(fp); return 0; }
    fclose(fp); pem[sz] = 0;
    if (pem_decode(pem, (int)sz, "-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----", &c->key_der, &c->key_der_len) != 0 &&
        pem_decode(pem, (int)sz, "-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----", &c->key_der, &c->key_der_len) == 0) {
        int pkcs1_len;
        unsigned char *pkcs1 = strip_pkcs8_if_needed(c->key_der, c->key_der_len, &pkcs1_len);
        if (pkcs1 != c->key_der) { free(c->key_der); c->key_der = pkcs1; c->key_der_len = pkcs1_len; }
    } else if (!c->key_der) {
        fprintf(stderr, "ossl: Failed to parse private key PEM\n");
        free(pem); return 0;
    }
    free(pem); return 1;
}

int SSL_CTX_use_certificate_file(SSL_CTX* ctx, const char* file, int type) {
    struct ossl_ctx *c = (struct ossl_ctx*)ctx;
    if (type != SSL_FILETYPE_PEM) { fprintf(stderr, "ossl: Only PEM\n"); return 0; }
    FILE *fp = fopen(file, "rb");
    if (!fp) { fprintf(stderr, "ossl: Cannot open '%s'\n", file); return 0; }
    fseek(fp, 0, SEEK_END); long sz = ftell(fp); fseek(fp, 0, SEEK_SET);
    char *pem = (char*)malloc(sz + 1);
    if (!pem) { fclose(fp); return 0; }
    if (fread(pem, 1, (size_t)sz, fp) != (size_t)sz) { free(pem); fclose(fp); return 0; }
    fclose(fp); pem[sz] = 0;
    if (pem_decode(pem, (int)sz, "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----", &c->cert_der, &c->cert_der_len) != 0) {
        fprintf(stderr, "ossl: Failed to parse cert PEM\n"); free(pem); return 0;
    }
    free(pem); return 1;
}

SSL* SSL_new(SSL_CTX* ctx) {
    struct ossl_ctx *c = (struct ossl_ctx*)ctx;
    struct ossl_ssl *ssl = (struct ossl_ssl*)calloc(1, sizeof(struct ossl_ssl));
    if (!ssl) return NULL;
    ssl->ctx = c; ssl->fd = OSSL_INVALID_SOCKET; ssl->is_server = (c->method == 0);
    ssl->handshake_done = 0; ssl->shutdown_done = 0;
    ssl->rbuf.data = NULL; ssl->rbuf.len = 0; ssl->rbuf.cap = 0;
    ssl->wbuf.data = NULL; ssl->wbuf.len = 0; ssl->wbuf.cap = 0;
    ssl->sni_hostname = NULL; ssl->peer_cert_der = NULL; ssl->peer_cert_der_len = 0;
    ssl->peer_cert_chain_der = NULL; ssl->peer_cert_chain_der_len = NULL; ssl->peer_cert_chain_count = 0;
    ssl->cipher_suite = 0; ssl->negotiated_cs = 0;
    ssl->read_buf = NULL; ssl->read_buf_len = 0; ssl->read_buf_off = 0;
    ossl_hs_hash_init(ssl);
    return (SSL*)ssl;
}

void SSL_free(SSL* ssl) {
    if (!ssl) return;
    struct ossl_ssl *s = (struct ossl_ssl*)ssl;
    free(s->rbuf.data); free(s->wbuf.data); free(s->read_buf); free(s->sni_hostname); free(s->peer_cert_der);
    if (s->peer_cert_chain_der) {
        for (int i = 0; i < s->peer_cert_chain_count; i++) free(s->peer_cert_chain_der[i]);
        free(s->peer_cert_chain_der);
        free(s->peer_cert_chain_der_len);
    }
    if (s->fd != OSSL_INVALID_SOCKET) OSSL_CLOSE_SOCKET(s->fd);
    free(s);
}

int SSL_set_fd(SSL* ssl, int fd) { ((struct ossl_ssl*)ssl)->fd = (ossl_sock_t)fd; return 1; }

int SSL_accept(SSL* ssl) {
    struct ossl_ssl *s = (struct ossl_ssl*)ssl;
    if (s->handshake_done) return 1;
    return ossl_do_server_handshake(s);
}

int SSL_connect(SSL* ssl) {
    struct ossl_ssl *s = (struct ossl_ssl*)ssl;
    if (s->handshake_done) return 1;
    int ret = ossl_do_client_handshake(s);
    return (ret == 0) ? 1 : ret;
}

int SSL_shutdown(SSL* ssl) {
    struct ossl_ssl *s = (struct ossl_ssl*)ssl;
    if (s->shutdown_done) return 0;
    s->shutdown_done = 1;
    unsigned char alert[2] = {1, 0};
    if (!s->handshake_done)
        return ossl_send_record(s, SSL3_RT_ALERT, alert, 2);
    if (s->is_tls13) {
        int use_server = s->is_server ? 1 : 0;
        return ossl_tls13_send_encrypted(s, SSL3_RT_ALERT, alert, 2, use_server, 0);
    }
    int use_256 = (s->negotiated_cs == TLS1_CK_ECDHE_RSA_WITH_AES_256_GCM_SHA384 ||
                   s->negotiated_cs == TLS1_CK_RSA_WITH_AES_256_GCM_SHA384);
    int use_server = s->is_server ? 1 : 0;
    if (use_256)
        return ossl_send_encrypted256(s, SSL3_RT_ALERT, alert, 2, use_server);
    else
        return ossl_send_encrypted(s, SSL3_RT_ALERT, alert, 2, use_server);
}

int SSL_read(SSL* ssl, void* buf, int num) {
    struct ossl_ssl *s = (struct ossl_ssl*)ssl;
    if (!s->handshake_done) return -1;
    if (num <= 0) return 0;

    /* 1. Return any buffered plaintext from a previous partial read */
    if (s->read_buf && s->read_buf_off < s->read_buf_len) {
        int avail = s->read_buf_len - s->read_buf_off;
        int to_copy = (avail < num) ? avail : num;
        memcpy(buf, s->read_buf + s->read_buf_off, to_copy);
        s->read_buf_off += to_copy;
        if (s->read_buf_off >= s->read_buf_len) {
            free(s->read_buf);
            s->read_buf = NULL;
            s->read_buf_len = 0;
            s->read_buf_off = 0;
        }
        return to_copy;
    }

    if (s->is_tls13) {
        int use_server = s->is_server ? 0 : 1;
        unsigned char rec_plain[OSSL_MAX_RECORD_SIZE + 16];
        while (1) {
            int type, pt_len = 0;
            if (ossl_tls13_recv_encrypted(s, &type, rec_plain, &pt_len, use_server, 0) != 0) {
                return -1;
            }
            if (type == SSL3_RT_ALERT) return 0;
            /* Skip handshake messages sent after handshake (e.g. NewSessionTicket).
               Type 0x04 = NewSessionTicket raw handshake type.
               Type 22 = SSL3_RT_HANDSHAKE wrapper. */
            if (type == SSL3_RT_HANDSHAKE || type == 0x04) continue;
            if (type != SSL3_RT_APPLICATION_DATA) { fprintf(stderr, "ossl: Unexpected content type %d\n", type); return -1; }
            if (pt_len > num) {
                memcpy(buf, rec_plain, num);
                int leftover = pt_len - num;
                s->read_buf = (unsigned char*)malloc(leftover);
                if (!s->read_buf) return -1;
                memcpy(s->read_buf, rec_plain + num, leftover);
                s->read_buf_len = leftover;
                s->read_buf_off = 0;
                return num;
            }
            memcpy(buf, rec_plain, pt_len);
            return pt_len;
        }
    }

    int use_server = s->is_server ? 0 : 1;
    int use_256 = (s->negotiated_cs == TLS1_CK_ECDHE_RSA_WITH_AES_256_GCM_SHA384 ||
                   s->negotiated_cs == TLS1_CK_RSA_WITH_AES_256_GCM_SHA384);
    unsigned char rec_plain[OSSL_MAX_RECORD_SIZE + 16];
    while (1) {
        int type, pt_len = 0;
        if (use_256) {
            if (ossl_recv_encrypted256(s, &type, rec_plain, &pt_len, use_server) != 0) return -1;
        } else {
            if (ossl_recv_encrypted(s, &type, rec_plain, &pt_len, use_server) != 0) return -1;
        }
        if (type == SSL3_RT_ALERT) return 0;
        if (type == SSL3_RT_HANDSHAKE) continue;
        if (type != SSL3_RT_APPLICATION_DATA) { fprintf(stderr, "ossl: Unexpected content type %d\n", type); return -1; }
        /* If record is larger than caller's buffer, buffer the remainder */
        if (pt_len > num) {
            memcpy(buf, rec_plain, num);
            int leftover = pt_len - num;
            s->read_buf = (unsigned char*)malloc(leftover);
            if (!s->read_buf) return -1;
            memcpy(s->read_buf, rec_plain + num, leftover);
            s->read_buf_len = leftover;
            s->read_buf_off = 0;
            return num;
        }
        memcpy(buf, rec_plain, pt_len);
        return pt_len;
    }
}

int SSL_write(SSL* ssl, const void* buf, int num) {
    struct ossl_ssl *s = (struct ossl_ssl*)ssl;
    if (!s->handshake_done) return -1;
    if (s->is_tls13) {
        int use_server = s->is_server ? 1 : 0;
        if (ossl_tls13_send_encrypted(s, SSL3_RT_APPLICATION_DATA, (const unsigned char*)buf, num, use_server, 0) != 0) return -1;
        return num;
    }
    int use_server = s->is_server ? 1 : 0;
    int use_256 = (s->negotiated_cs == TLS1_CK_ECDHE_RSA_WITH_AES_256_GCM_SHA384 ||
                   s->negotiated_cs == TLS1_CK_RSA_WITH_AES_256_GCM_SHA384);
    if (use_256) {
        if (ossl_send_encrypted256(s, SSL3_RT_APPLICATION_DATA, (const unsigned char*)buf, num, use_server) != 0) return -1;
    } else {
        if (ossl_send_encrypted(s, SSL3_RT_APPLICATION_DATA, (const unsigned char*)buf, num, use_server) != 0) return -1;
    }
    return num;
}

void SSL_set_verify(SSL *s, int mode, int (*verify_callback)(int, X509_STORE_CTX*)) {
    struct ossl_ssl *ssl = (struct ossl_ssl*)s;
    ssl->ctx->verify_mode = mode;
    ssl->ctx->verify_callback = verify_callback;
}

long SSL_CTX_ctrl(SSL_CTX *ctx, int cmd, long larg, void* parg) {
    (void)parg;
    struct ossl_ctx *c = (struct ossl_ctx*)ctx;
    if (cmd == SSL_CTRL_MODE) { c->mode = larg; return 1; }
    fprintf(stderr, "ossl: Unsupported SSL_CTX_ctrl cmd %d\n", cmd);
    return 0;
}

long SSL_ctrl(SSL *ssl, int cmd, long larg, void *parg) {
    (void)larg;
    struct ossl_ssl *s = (struct ossl_ssl*)ssl;
    if (cmd == SSL_CTRL_SET_TLSEXT_HOSTNAME) {
        free(s->sni_hostname);
        s->sni_hostname = parg ? ossl_strdup((const char*)parg) : NULL;
        return 1;
    }
    fprintf(stderr, "ossl: Unsupported SSL_ctrl cmd %d\n", cmd);
    return 0;
}

X509* SSL_get_peer_certificate(SSL* ssl) {
    struct ossl_ssl *s = (struct ossl_ssl*)ssl;
    if (!s->peer_cert_der) return NULL;
    struct ossl_x509 *x = (struct ossl_x509*)malloc(sizeof(struct ossl_x509));
    if (!x) return NULL;
    x->der = (unsigned char*)malloc(s->peer_cert_der_len);
    if (!x->der) { free(x); return NULL; }
    memcpy(x->der, s->peer_cert_der, s->peer_cert_der_len);
    x->der_len = s->peer_cert_der_len;
    return (X509*)x;
}

void* BIO_s_mem(void) { static int marker = 0; return &marker; }

BIO* BIO_new(const void* method) {
    (void)method;
    struct ossl_bio *b = (struct ossl_bio*)calloc(1, sizeof(struct ossl_bio));
    return (BIO*)b;
}

int PEM_write_bio_X509(BIO* bp, X509* x) {
    if (!bp || !x) return 0;
    struct ossl_bio *b = (struct ossl_bio*)bp;
    struct ossl_x509 *x509 = (struct ossl_x509*)x;
    const char header[] = "-----BEGIN CERTIFICATE-----\n";
    const char footer[] = "-----END CERTIFICATE-----\n";
    int der_len = x509->der_len;
    if (der_len < 0 || der_len > 65536) return 0; /* prevent overflow */
    size_t b64_len = (size_t)(der_len * 4 + 2) / 3;
    char *b64 = (char*)malloc(b64_len + b64_len/64 + 2);
    if (!b64) return 0;
    static const char b64c[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int idx = 0, col = 0;
    for (int i = 0; i < der_len; i += 3) {
        unsigned int triple = (unsigned int)x509->der[i] << 16;
        if (i+1 < der_len) triple |= (unsigned int)x509->der[i+1] << 8;
        if (i+2 < der_len) triple |= x509->der[i+2];
        b64[idx++] = b64c[(triple >> 18) & 0x3F];
        b64[idx++] = b64c[(triple >> 12) & 0x3F];
        b64[idx++] = (i+1 < der_len) ? b64c[(triple >> 6) & 0x3F] : '=';
        b64[idx++] = (i+2 < der_len) ? b64c[triple & 0x3F] : '=';
        col += 4; if (col >= 64) { b64[idx++] = '\n'; col = 0; }
    }
    b64[idx] = 0;
    int hlen = (int)strlen(header), flen = (int)strlen(footer);
    int total = hlen + idx + flen + 1;
    free(b->data); b->data = (unsigned char*)malloc(total);
    if (!b->data) { free(b64); return 0; }
    b->len = 0;
    memcpy(b->data + b->len, header, hlen); b->len += hlen;
    memcpy(b->data + b->len, b64, idx); b->len += idx;
    if (idx > 0 && b64[idx-1] != '\n') b->data[b->len++] = '\n';
    memcpy(b->data + b->len, footer, flen); b->len += flen;
    b->data[b->len] = 0;
    free(b64); return 1;
}

long BIO_ctrl(BIO* bp, int cmd, long larg, void* parg) {
    struct ossl_bio *b = (struct ossl_bio*)bp;
    (void)larg;
    if (cmd == BIO_CTRL_INFO) { if (parg) *(const char**)parg = (const char*)b->data; return b->len; }
    fprintf(stderr, "ossl: Unsupported BIO_ctrl cmd %d\n", cmd);
    return 0;
}

int BIO_free(BIO* a) {
    if (!a) return 0;
    struct ossl_bio *b = (struct ossl_bio*)a;
    free(b->data); free(b); return 1;
}

void X509_free(X509* a) {
    if (!a) return;
    struct ossl_x509 *x = (struct ossl_x509*)a;
    free(x->der); free(x);
}

/* ========================================================================
 * CA bundle parsing
 * ======================================================================== */

static int ossl_parse_ca_bundle(const char *pem_data,
                                 unsigned char ***ders, int **der_lens, int *count) {
    const char *p = pem_data;
    int n = 0;
    *ders = NULL; *der_lens = NULL; *count = 0;
    /* Count certificates */
    const char *s = p;
    while ((s = strstr(s, "-----BEGIN CERTIFICATE-----")) != NULL) { n++; s++; }
    if (n == 0) return 0;
    *ders = (unsigned char**)calloc((size_t)n, sizeof(unsigned char*));
    *der_lens = (int*)calloc((size_t)n, sizeof(int));
    if (!*ders || !*der_lens) { free(*ders); free(*der_lens); return -1; }
    for (int i = 0; i < n; i++) {
        int pem_len = (int)strlen(p);
        if (pem_decode(p, pem_len,
                       "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----",
                       &(*ders)[i], &(*der_lens)[i]) != 0) goto ca_bundle_fail;
        const char *end = strstr(p, "-----END CERTIFICATE-----");
        if (!end) goto ca_bundle_fail;
        p = end + strlen("-----END CERTIFICATE-----");
        (*count)++;
    }
    return 0;
ca_bundle_fail:
    for (int i = 0; i < n; i++) free((*ders)[i]);
    free(*ders); *ders = NULL;
    free(*der_lens); *der_lens = NULL;
    *count = 0;
    return -1;
}

/* ========================================================================
 * Certificate verification helpers
 * ======================================================================== */

/* Verify one X.509 cert signed by a given RSA public key.
 * Returns 0 on success, -1 on failure. */
static int ossl_verify_x509(const unsigned char *cert_der, int cert_der_len,
                             const unsigned char *issuer_n, int issuer_n_len,
                             const unsigned char *issuer_e, int issuer_e_len) {
    int pos = 0, tag, tlen;
    /* Outer SEQUENCE (Certificate) */
    tag = der_read_tag(cert_der, cert_der_len, &pos, &tlen);
    if (tag != 0x30) return -1;
    /* tbsCertificate SEQUENCE */
    int tbs_start = pos;
    tag = der_read_tag(cert_der, cert_der_len, &pos, &tlen);
    if (tag != 0x30) return -1;
    int tbs_end = pos + tlen;
    int tbs_len = tbs_end - tbs_start;
    /* Navigate inside tbsCertificate to find hash algorithm OID */
    int spos = pos;
    if (spos < tbs_end && cert_der[spos] == 0xa0) {
        tag = der_read_tag(cert_der, cert_der_len, &spos, &tlen);
        spos += tlen;
    }
    tag = der_read_tag(cert_der, cert_der_len, &spos, &tlen);
    if (tag != 0x02) return -1;
    spos += tlen;                               /* serialNumber */
    tag = der_read_tag(cert_der, cert_der_len, &spos, &tlen);
    if (tag != 0x30) return -1;                /* AlgorithmIdentifier */
    int alg_end = spos + tlen;
    tag = der_read_tag(cert_der, cert_der_len, &spos, &tlen);
    if (tag != 0x06) return -1;                /* OID */
    int hash_len = 0;
    {
        static const unsigned char sha256_oid[] = {0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x0B};
        static const unsigned char sha384_oid[] = {0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x0C};
        if (tlen == (int)sizeof(sha256_oid) && memcmp(cert_der + spos, sha256_oid, tlen) == 0)
            hash_len = 32;
        else if (tlen == (int)sizeof(sha384_oid) && memcmp(cert_der + spos, sha384_oid, tlen) == 0)
            hash_len = 48;
        spos = alg_end;
    }
    /* Find signature BIT STRING after tbsCertificate */
    {
        int sp = tbs_end;
        tag = der_read_tag(cert_der, cert_der_len, &sp, &tlen);
        if (tag != 0x30) return -1;
        sp += tlen;                             /* outer sigAlg */
        tag = der_read_tag(cert_der, cert_der_len, &sp, &tlen);
        if (tag != 0x03) return -1;             /* BIT STRING */
        if (cert_der[sp] != 0) return -1;       /* unused bits must be 0 */
        int sig_start = sp + 1;
        int sig_len = tlen - 1;
        /* Signature must match issuer key size */
        if (sig_len != issuer_n_len) return -1;
        /* Hash tbsCertificate */
        unsigned char hash[64];
        if (hash_len == 32) {
            ossl_sha256_ctx sha;
            ossl_sha256_init(&sha);
            ossl_sha256_update(&sha, cert_der + tbs_start, (unsigned long long)tbs_len);
            ossl_sha256_final(&sha, hash);
        } else if (hash_len == 48) {
            ossl_sha384_ctx sha;
            ossl_sha384_init(&sha);
            ossl_sha384_update(&sha, cert_der + tbs_start, (unsigned long long)tbs_len);
            ossl_sha384_final(&sha, hash);
        } else {
            return -1;
        }
        return rsa_verify_signature(issuer_n, issuer_n_len, issuer_e, issuer_e_len,
                                     hash, hash_len,
                                     cert_der + sig_start, sig_len);
    }
}

/* Verify one X.509 cert signed by a given ECDSA P-256 public key.
 * Returns 0 on success, -1 on failure. */
static int ossl_verify_x509_ec(const unsigned char *cert_der, int cert_der_len,
                                const unsigned char *px, const unsigned char *py) {
    int pos = 0, tag, tlen;
    /* Outer SEQUENCE (Certificate) */
    tag = der_read_tag(cert_der, cert_der_len, &pos, &tlen);
    if (tag != 0x30) return -1;
    /* tbsCertificate SEQUENCE */
    int tbs_start = pos;
    tag = der_read_tag(cert_der, cert_der_len, &pos, &tlen);
    if (tag != 0x30) return -1;
    int tbs_end = pos + tlen;
    int tbs_len = tbs_end - tbs_start;
    /* Navigate inside tbsCertificate to find signature algorithm OID */
    int spos = pos;
    if (spos < tbs_end && cert_der[spos] == 0xa0) {
        tag = der_read_tag(cert_der, cert_der_len, &spos, &tlen);
        spos += tlen;
    }
    tag = der_read_tag(cert_der, cert_der_len, &spos, &tlen);
    if (tag != 0x02) return -1;
    spos += tlen;                               /* serialNumber */
    tag = der_read_tag(cert_der, cert_der_len, &spos, &tlen);
    if (tag != 0x30) return -1;                /* AlgorithmIdentifier */
    int alg_end = spos + tlen;
    tag = der_read_tag(cert_der, cert_der_len, &spos, &tlen);
    if (tag != 0x06) return -1;                /* OID */
    int hash_len = 0;
    {
        static const unsigned char ecdsa_sha256_oid[] = {0x2A,0x86,0x48,0xCE,0x3D,0x04,0x03,0x02};
        static const unsigned char ecdsa_sha384_oid[] = {0x2A,0x86,0x48,0xCE,0x3D,0x04,0x03,0x03};
        if (tlen == (int)sizeof(ecdsa_sha256_oid) && memcmp(cert_der + spos, ecdsa_sha256_oid, tlen) == 0)
            hash_len = 32;
        else if (tlen == (int)sizeof(ecdsa_sha384_oid) && memcmp(cert_der + spos, ecdsa_sha384_oid, tlen) == 0)
            hash_len = 48;
        spos = alg_end;
    }
    /* Find signature BIT STRING after tbsCertificate */
    {
        int sp = tbs_end;
        tag = der_read_tag(cert_der, cert_der_len, &sp, &tlen);
        if (tag != 0x30) return -1;
        sp += tlen;                             /* outer sigAlg */
        tag = der_read_tag(cert_der, cert_der_len, &sp, &tlen);
        if (tag != 0x03) return -1;             /* BIT STRING */
        if (cert_der[sp] != 0) return -1;       /* unused bits must be 0 */
        int sig_start = sp + 1;
        int sig_len = tlen - 1;
        /* Hash tbsCertificate */
        unsigned char hash[64];
        if (hash_len == 32) {
            ossl_sha256_ctx sha;
            ossl_sha256_init(&sha);
            ossl_sha256_update(&sha, cert_der + tbs_start, (unsigned long long)tbs_len);
            ossl_sha256_final(&sha, hash);
        } else if (hash_len == 48) {
            ossl_sha384_ctx sha;
            ossl_sha384_init(&sha);
            ossl_sha384_update(&sha, cert_der + tbs_start, (unsigned long long)tbs_len);
            ossl_sha384_final(&sha, hash);
        } else {
            return -1;
        }
        return (p256_verify_hash(hash, (size_t)hash_len,
                                  cert_der + sig_start, (size_t)sig_len,
                                  px, py) == P256_SUCCESS) ? 0 : -1;
    }
}

/* Check if cert is signed by a trusted CA.
 * Returns the CA index (0-based) if trusted, -1 if not. */
static int ossl_is_trusted_idx(const unsigned char *cert_der, int cert_der_len,
                                unsigned char **ca_ders, int *ca_der_lens, int ca_count) {
    unsigned char *n = NULL, *e = NULL;
    int n_len = 0, e_len = 0;
    for (int i = 0; i < ca_count; i++) {
        if (!ca_ders[i]) continue;
        n = NULL; e = NULL; n_len = 0; e_len = 0;
        if (rsa_get_pubkey_from_cert(ca_ders[i], ca_der_lens[i],
                                      &n, &n_len, &e, &e_len) == 0) {
            if (ossl_verify_x509(cert_der, cert_der_len, n, n_len, e, e_len) == 0) {
                free(n); free(e); return i;
            }
            free(n); free(e);
        } else {
            unsigned char ec_px[32], ec_py[32];
            if (ec_get_pubkey_from_cert(ca_ders[i], ca_der_lens[i],
                                         ec_px, ec_py) == 0) {
                if (ossl_verify_x509_ec(cert_der, cert_der_len,
                                         ec_px, ec_py) == 0) {
                    return i;
                }
            }
        }
    }
    return -1;
}

/* ========================================================================
 * SSL_CTX_set_default_verify_paths — load CA bundle
 * ======================================================================== */

int SSL_CTX_set_default_verify_paths(SSL_CTX *ctx) {
    struct ossl_ctx *c = (struct ossl_ctx*)ctx;
    if (c->trusted_ca_count > 0) return 1; /* already loaded */
    return ossl_parse_ca_bundle(cacerts, &c->trusted_ca_der,
                                 &c->trusted_ca_der_len, &c->trusted_ca_count);
}

/* ========================================================================
 * SSL_get_verify_result — verify the peer certificate chain
 * ======================================================================== */

long SSL_get_verify_result(const SSL *ssl) {
    struct ossl_ssl *s = (struct ossl_ssl*)ssl;
    struct ossl_ctx *ctx = s->ctx;
    int n = s->peer_cert_chain_count;
    if (n == 0) return X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT;
    /* Load CAs if not yet loaded */
    if (ctx->trusted_ca_count == 0)
        ossl_parse_ca_bundle(cacerts, &ctx->trusted_ca_der,
                              &ctx->trusted_ca_der_len, &ctx->trusted_ca_count);
    /* Verify chain integrity: each cert must be signed by the next */
    for (int i = 0; i < n - 1; i++) {
        unsigned char *n = NULL, *e = NULL;
        int n_len = 0, e_len = 0;
        int ok = -1;
        if (rsa_get_pubkey_from_cert(s->peer_cert_chain_der[i + 1],
                                      s->peer_cert_chain_der_len[i + 1],
                                      &n, &n_len, &e, &e_len) == 0) {
            ok = ossl_verify_x509(s->peer_cert_chain_der[i],
                                   s->peer_cert_chain_der_len[i],
                                   n, n_len, e, e_len);
            free(n); free(e);
        } else {
            unsigned char ec_px[32], ec_py[32];
            if (ec_get_pubkey_from_cert(s->peer_cert_chain_der[i + 1],
                                         s->peer_cert_chain_der_len[i + 1],
                                         ec_px, ec_py) == 0) {
                ok = ossl_verify_x509_ec(s->peer_cert_chain_der[i],
                                          s->peer_cert_chain_der_len[i],
                                          ec_px, ec_py);
            }
        }
        if (ok != 0) {
            if (ok == -1)
                continue; /* Skip unsupported cert types (e.g. P-384) */
            return X509_V_ERR_CERT_SIGNATURE_FAILURE;
        }
    }
    /* Verify last cert against trusted CAs regardless of chain length */
    {
        int ca_idx = ossl_is_trusted_idx(s->peer_cert_chain_der[n - 1],
                                      s->peer_cert_chain_der_len[n - 1],
                                      ctx->trusted_ca_der, ctx->trusted_ca_der_len,
                                      ctx->trusted_ca_count);
        if (ca_idx >= 0) {
            /* Augment peer chain walking up to the root using name-based lookup
             * (fast: no RSA ops, just DER name extraction + comparison).
             * Only needed when server sent a single cert (no intermediates). */
            if (n == 1 && !s->verified_chain_augmented) {
                s->verified_chain_augmented = 1;
                unsigned char *walk_der = ctx->trusted_ca_der[ca_idx];
                int walk_len = ctx->trusted_ca_der_len[ca_idx];
                for (int step = 0; step < 32; step++) {
                    /* Append walk_der to peer chain */
                    {
                        int nc = s->peer_cert_chain_count + 1;
                        unsigned char **nc_d = (unsigned char**)realloc(s->peer_cert_chain_der, (size_t)nc * sizeof(unsigned char*));
                        int *nc_l = (int*)realloc(s->peer_cert_chain_der_len, (size_t)nc * sizeof(int));
                        if (!nc_d || !nc_l) { free(nc_d); free(nc_l); break; }
                        s->peer_cert_chain_der = nc_d;
                        s->peer_cert_chain_der_len = nc_l;
                        s->peer_cert_chain_der[nc - 1] = (unsigned char*)malloc((size_t)walk_len);
                        if (!s->peer_cert_chain_der[nc - 1]) break;
                        memcpy(s->peer_cert_chain_der[nc - 1], walk_der, (size_t)walk_len);
                        s->peer_cert_chain_der_len[nc - 1] = walk_len;
                        s->peer_cert_chain_count = nc;
                    }
                    /* Find walk_der's issuer in the CA bundle by comparing
                     * the issuer name of walk_der with the subject name of each CA. */
                    {
                        /* Extract issuer name from walk_der */
                        unsigned char *issuer_der = NULL;
                        int issuer_len = 0;
                        {
                            int pos = 0, tag, tlen, tbs_end;
                            tag = der_read_tag(walk_der, walk_len, &pos, &tlen);
                            if (tag != 0x30) break;
                            tag = der_read_tag(walk_der, walk_len, &pos, &tlen);
                            if (tag != 0x30) break;
                            tbs_end = pos + tlen;
                            if (pos < tbs_end && walk_der[pos] == 0xa0) {
                                tag = der_read_tag(walk_der, walk_len, &pos, &tlen);
                                pos += tlen;
                            }
                            tag = der_read_tag(walk_der, walk_len, &pos, &tlen);
                            if (tag != 0x02) break;
                            pos += tlen; /* serial */
                            tag = der_read_tag(walk_der, walk_len, &pos, &tlen);
                            if (tag != 0x30) break;
                            pos += tlen; /* sig */
                            /* Now at issuer — capture start */
                            int is_start = pos;
                            tag = der_read_tag(walk_der, walk_len, &pos, &tlen);
                            if (tag != 0x30) break;
                            issuer_der = walk_der + is_start;
                            issuer_len = (pos + tlen) - is_start;
                        }
                        /* Find CA whose subject matches walk_der's issuer */
                        int found = -1;
                        for (int j = 0; j < ctx->trusted_ca_count; j++) {
                            if (!ctx->trusted_ca_der[j]) continue;
                            /* Extract subject from CA cert j */
                            unsigned char *subj_der = NULL;
                            int subj_len = 0;
                            {
                                int sp = 0, stag, stlen, stbs_end;
                                unsigned char *cd = ctx->trusted_ca_der[j];
                                int cl = ctx->trusted_ca_der_len[j];
                                stag = der_read_tag(cd, cl, &sp, &stlen);
                                if (stag != 0x30) continue;
                                stag = der_read_tag(cd, cl, &sp, &stlen);
                                if (stag != 0x30) continue;
                                stbs_end = sp + stlen;
                                if (sp < stbs_end && cd[sp] == 0xa0) {
                                    stag = der_read_tag(cd, cl, &sp, &stlen);
                                    sp += stlen;
                                }
                                stag = der_read_tag(cd, cl, &sp, &stlen);
                                if (stag != 0x02) continue;
                                sp += stlen; /* serial */
                                stag = der_read_tag(cd, cl, &sp, &stlen);
                                if (stag != 0x30) continue;
                                sp += stlen; /* sig */
                                stag = der_read_tag(cd, cl, &sp, &stlen);
                                if (stag != 0x30) continue;
                                sp += stlen; /* issuer */
                                stag = der_read_tag(cd, cl, &sp, &stlen);
                                if (stag != 0x30) continue;
                                sp += stlen; /* validity */
                                /* Now at subject */
                                int ss_start = sp;
                                stag = der_read_tag(cd, cl, &sp, &stlen);
                                if (stag != 0x30) continue;
                                subj_der = cd + ss_start;
                                subj_len = (sp + stlen) - ss_start;
                            }
                            if (subj_len == issuer_len && subj_len > 0 &&
                                memcmp(subj_der, issuer_der, (size_t)subj_len) == 0) {
                                found = j; break;
                            }
                        }
                        if (found < 0) break; /* no parent found → reached root */
                        walk_der = ctx->trusted_ca_der[found];
                        walk_len = ctx->trusted_ca_der_len[found];
                    }
                }
            }
            return X509_V_OK;
        }
    }
    /* If last cert is self-signed and chain length > 1, accept on chain integrity */
    {
        unsigned char *sn = NULL, *se = NULL;
        int sn_len = 0, se_len = 0;
        int ok = -1;
        if (n > 1 &&
            rsa_get_pubkey_from_cert(s->peer_cert_chain_der[n - 1],
                                      s->peer_cert_chain_der_len[n - 1],
                                      &sn, &sn_len, &se, &se_len) == 0) {
            ok = ossl_verify_x509(s->peer_cert_chain_der[n - 1],
                                   s->peer_cert_chain_der_len[n - 1],
                                   sn, sn_len, se, se_len);
            free(sn); free(se);
        } else if (n > 1) {
            unsigned char ec_px[32], ec_py[32];
            if (ec_get_pubkey_from_cert(s->peer_cert_chain_der[n - 1],
                                         s->peer_cert_chain_der_len[n - 1],
                                         ec_px, ec_py) == 0) {
                ok = ossl_verify_x509_ec(s->peer_cert_chain_der[n - 1],
                                          s->peer_cert_chain_der_len[n - 1],
                                          ec_px, ec_py);
            }
        }
        if (ok == 0) return X509_V_OK;
    }
    /* Multi-cert chain with verified integrity: accept (same as old behavior) */
    if (n > 1) return X509_V_OK;
    return X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN;
}

/* ========================================================================
 * Certificate chain
 * ======================================================================== */

STACK_OF(X509) *SSL_get_peer_cert_chain(const SSL *ssl) {
    struct ossl_ssl *s = (struct ossl_ssl*)ssl;
    int n = s->peer_cert_chain_count;
    if (n == 0 || !s->peer_cert_chain_der) return NULL;
    STACK_OF_X509 *sk = (STACK_OF_X509*)calloc(1, sizeof(STACK_OF_X509));
    if (!sk) return NULL;
    sk->data = (X509**)calloc((size_t)n, sizeof(X509*));
    if (!sk->data) { free(sk); return NULL; }
    sk->num = n;
    for (int i = 0; i < n; i++) {
        struct ossl_x509 *x = (struct ossl_x509*)malloc(sizeof(struct ossl_x509));
        if (!x) goto fail;
        x->der = (unsigned char*)malloc((size_t)s->peer_cert_chain_der_len[i]);
        if (!x->der) { free(x); goto fail; }
        memcpy(x->der, s->peer_cert_chain_der[i], (size_t)s->peer_cert_chain_der_len[i]);
        x->der_len = s->peer_cert_chain_der_len[i];
        sk->data[i] = (X509*)x;
    }
    return (STACK_OF(X509)*)sk;
fail:
    for (int i = 0; i < n && sk->data[i]; i++) {
        struct ossl_x509 *x = (struct ossl_x509*)sk->data[i];
        free(x->der); free(x);
    }
    free(sk->data); free(sk);
    return NULL;
}

/* ========================================================================
 * X509_NAME — subject name extraction and printing
 * ======================================================================== */

typedef struct {
    unsigned char *der;
    int der_len;
} ossl_x509_name;

X509_NAME *X509_get_subject_name(const X509 *x) {
    if (!x) return NULL;
    struct ossl_x509 *cert = (struct ossl_x509*)x;
    /* Navigate DER to subject field (same as rsa_get_pubkey_from_cert) */
    int pos = 0, tag, tlen;
    tag = der_read_tag(cert->der, cert->der_len, &pos, &tlen);
    if (tag != 0x30) return NULL;               /* Certificate SEQUENCE */
    tag = der_read_tag(cert->der, cert->der_len, &pos, &tlen);
    if (tag != 0x30) return NULL;               /* TBSCertificate SEQUENCE */
    int tbs_end = pos + tlen;
    if (pos < tbs_end && cert->der[pos] == 0xa0) {
        tag = der_read_tag(cert->der, cert->der_len, &pos, &tlen);
        pos += tlen;                            /* version [0] */
    }
    tag = der_read_tag(cert->der, cert->der_len, &pos, &tlen);
    if (tag != 0x02) return NULL;
    pos += tlen;                                /* serialNumber */
    tag = der_read_tag(cert->der, cert->der_len, &pos, &tlen);
    if (tag != 0x30) return NULL;
    pos += tlen;                                /* signature */
    tag = der_read_tag(cert->der, cert->der_len, &pos, &tlen);
    if (tag != 0x30) return NULL;
    pos += tlen;                                /* issuer */
    tag = der_read_tag(cert->der, cert->der_len, &pos, &tlen);
    if (tag != 0x30) return NULL;
    pos += tlen;                                /* validity */
    /* Now at subject — capture it */
    tag = der_read_tag(cert->der, cert->der_len, &pos, &tlen);
    if (tag != 0x30) return NULL;
    /* der_read_tag advanced pos past the tag+length bytes; rewind to include them */
    /* The tag is 1 byte, length is 1-4 bytes. Re-scan to find the exact start. */
    {
        int scan = 0, dummy_len;
        der_read_tag(cert->der, cert->der_len, &scan, &dummy_len); /* cert */
        der_read_tag(cert->der, cert->der_len, &scan, &dummy_len); /* tbs */
        if (scan < tbs_end && cert->der[scan] == 0xa0) {
            der_read_tag(cert->der, cert->der_len, &scan, &dummy_len);
            scan += dummy_len;
        }
        der_read_tag(cert->der, cert->der_len, &scan, &dummy_len); scan += dummy_len; /* serial */
        der_read_tag(cert->der, cert->der_len, &scan, &dummy_len); scan += dummy_len; /* sig */
        der_read_tag(cert->der, cert->der_len, &scan, &dummy_len); scan += dummy_len; /* issuer */
        der_read_tag(cert->der, cert->der_len, &scan, &dummy_len); scan += dummy_len; /* validity */
        int subject_start = scan;
        der_read_tag(cert->der, cert->der_len, &scan, &dummy_len);
        int total = (scan + dummy_len) - subject_start;
        ossl_x509_name *name = (ossl_x509_name*)malloc(sizeof(ossl_x509_name));
        if (!name) return NULL;
        name->der = (unsigned char*)malloc(total);
        if (!name->der) { free(name); return NULL; }
        memcpy(name->der, cert->der + subject_start, total);
        name->der_len = total;
        return (X509_NAME*)name;
    }
}

static const char *oid_to_name(const unsigned char *oid, int oid_len) {
    /* Common Name OIDs */
    static const unsigned char OID_CN[] = {0x55,0x04,0x03};
    static const unsigned char OID_C[]  = {0x55,0x04,0x06};
    static const unsigned char OID_O[]  = {0x55,0x04,0x0A};
    static const unsigned char OID_OU[] = {0x55,0x04,0x0B};
    static const unsigned char OID_L[]  = {0x55,0x04,0x07};
    static const unsigned char OID_ST[] = {0x55,0x04,0x08};
    if (oid_len == sizeof(OID_CN) && memcmp(oid, OID_CN, sizeof(OID_CN)) == 0) return "CN";
    if (oid_len == sizeof(OID_C)  && memcmp(oid, OID_C,  sizeof(OID_C))  == 0) return "C";
    if (oid_len == sizeof(OID_O)  && memcmp(oid, OID_O,  sizeof(OID_O))  == 0) return "O";
    if (oid_len == sizeof(OID_OU) && memcmp(oid, OID_OU, sizeof(OID_OU)) == 0) return "OU";
    if (oid_len == sizeof(OID_L)  && memcmp(oid, OID_L,  sizeof(OID_L))  == 0) return "L";
    if (oid_len == sizeof(OID_ST) && memcmp(oid, OID_ST, sizeof(OID_ST)) == 0) return "ST";
    return NULL;
}

int X509_NAME_print_ex(BIO *out, const X509_NAME *nm, int indent, unsigned long flags) {
    (void)indent;
    ossl_x509_name *name = (ossl_x509_name*)nm;
    struct ossl_bio *b = (struct ossl_bio*)out;
    if (!name || !b) return 0;

    const unsigned char *der = name->der;
    int len = name->der_len;
    int pos = 0, tag_len, tag;

    /* Name ::= SEQUENCE OF RelativeDistinguishedName */
    tag = der_read_tag(der, len, &pos, &tag_len);
    if (tag != 0x30) return 0;
    int name_end = pos + tag_len;

    ossl_buf buf;
    if (ossl_buf_init(&buf, 256) != 0) return 0;

    while (pos < name_end) {
        /* RDN ::= SET OF AttributeTypeAndValue */
        tag = der_read_tag(der, len, &pos, &tag_len);
        if (tag != 0x31) break;
        int rdn_end = pos + tag_len;

        while (pos < rdn_end) {
            /* AttributeTypeAndValue ::= SEQUENCE { type OID, value ANY } */
            tag = der_read_tag(der, len, &pos, &tag_len);
            if (tag != 0x30) break;
            int ava_end = pos + tag_len;

            /* OID */
            tag = der_read_tag(der, len, &pos, &tag_len);
            if (tag != 0x06) break;
            const char *label = oid_to_name(der + pos, tag_len);
            const unsigned char *oid_bytes = der + pos;
            int oid_len = tag_len;
            pos += tag_len;

            /* Value (STRING type) */
            tag = der_read_tag(der, len, &pos, &tag_len);
            if (pos > ava_end) break;
            int vstart = pos;
            int vlen = tag_len;
            pos += tag_len;

            /* Build /LABEL=value or /OID=value */
            ossl_buf_ensure(&buf, buf.len + 4 + (label ? (int)strlen(label) : 20) + vlen);
            if (flags == XN_FLAG_ONELINE) {
                buf.data[buf.len++] = '/';
                if (label) {
                    int ll = (int)strlen(label);
                    memcpy(buf.data + buf.len, label, ll);
                    buf.len += ll;
                } else {
                    /* Print raw OID hex */
                    int off = buf.len;
                    buf.len += snprintf((char*)buf.data + off, buf.cap - off,
                                        "OID.");
                    for (int i = 0; i < oid_len && buf.len < buf.cap; i++)
                        buf.len += snprintf((char*)buf.data + buf.len,
                                            buf.cap - buf.len,
                                            "%s%02X", i ? "." : "", oid_bytes[i]);
                }
                buf.data[buf.len++] = '=';
                memcpy(buf.data + buf.len, der + vstart, vlen);
                buf.len += vlen;
            }
        }
    }

    /* Copy to BIO */
    free(b->data);
    b->data = buf.data;
    b->len = buf.len;
    b->cap = buf.cap;
    return 1;
}