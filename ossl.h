#ifndef OSSL_H
#define OSSL_H

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque types */
typedef void SSL_CTX;
typedef void SSL_METHOD;
typedef void SSL;
typedef void X509_STORE_CTX;
typedef void X509;
#ifdef X509_NAME
#undef X509_NAME
#endif
typedef void X509_NAME;
typedef void BIO;
typedef void SSL_SESSION;

/* Context */
SSL_CTX* SSL_CTX_new(SSL_METHOD* method);
SSL_METHOD* TLS_server_method(void);
SSL_METHOD* TLS_client_method(void);
void SSL_CTX_free(SSL_CTX* ctx);

/* Certificate loading */
#define SSL_FILETYPE_PEM 1
#define SSL_FILETYPE_ASN1 2
int SSL_CTX_use_PrivateKey_file(SSL_CTX* ctx, const char* file, int type);
int SSL_CTX_use_certificate_file(SSL_CTX* ctx, const char* file, int type);

/* SSL object */
SSL* SSL_new(SSL_CTX* ctx);
void SSL_free(SSL* ssl);
int SSL_set_fd(SSL* ssl, int fd);

/* Handshake and I/O */
int SSL_accept(SSL* ssl);
int SSL_connect(SSL* ssl);
int SSL_shutdown(SSL* ssl);
int SSL_read(SSL* ssl, void* buf, int num);
int SSL_write(SSL* ssl, const void* buf, int num);

/* Verification */
#define X509_V_OK 0
#define X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT 2
#define X509_V_ERR_CERT_SIGNATURE_FAILURE 7
#define X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN 19
#define XN_FLAG_ONELINE 0
#define SSL_VERIFY_NONE 0
void SSL_set_verify(SSL *s, int mode, int (*verify_callback)(int, X509_STORE_CTX*));
int SSL_CTX_set_default_verify_paths(SSL_CTX *ctx);
long SSL_get_verify_result(const SSL *ssl);

/* Chain enumeration */
#define STACK_OF(type) struct stack_st_##type
STACK_OF(X509) {
    int num;
    X509 **data;
};
typedef STACK_OF(X509) STACK_OF_X509;
#define sk_X509_num(st)         (((st) != NULL) ? (st)->num : 0)
#define sk_X509_value(st, i)    (((st) != NULL) ? (st)->data[i] : NULL)
STACK_OF(X509) *SSL_get_peer_cert_chain(const SSL *ssl);
X509_NAME *X509_get_subject_name(const X509 *x);
int X509_NAME_print_ex(BIO *out, const X509_NAME *nm, int indent, unsigned long flags);

/* Options */
#define SSL_MODE_ENABLE_PARTIAL_WRITE 0x1
#define SSL_CTRL_MODE 33
long SSL_CTX_ctrl(SSL_CTX *ctx, int cmd, long larg, void* parg);
#define SSL_CTX_set_mode(ctx,op) SSL_CTX_ctrl((ctx),SSL_CTRL_MODE,(op),0)

/* SNI */
#define SSL_CTRL_SET_TLSEXT_HOSTNAME 55
#define TLSEXT_NAMETYPE_host_name 0
long SSL_ctrl(SSL *ssl, int cmd, long larg, void *parg);
#define SSL_set_tlsext_host_name(s,name) SSL_ctrl(s,SSL_CTRL_SET_TLSEXT_HOSTNAME,TLSEXT_NAMETYPE_host_name, (void *)name)

/* Certificate retrieval */
X509* SSL_get_peer_certificate(SSL* ssl);
void* BIO_s_mem(void);
BIO* BIO_new(const void* method);
int PEM_write_bio_X509(BIO* bp, X509* x);
#define BIO_CTRL_INFO 3
#define BIO_get_mem_data(b,pp) BIO_ctrl(b,BIO_CTRL_INFO,0,(char*)(pp))
long BIO_ctrl(BIO* bp, int cmd, long larg, void* parg);
int BIO_free(BIO* a);
void X509_free(X509* a);

#ifdef __cplusplus
}
#endif

#endif /* OSSL_H */