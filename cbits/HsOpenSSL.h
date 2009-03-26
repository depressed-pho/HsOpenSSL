#ifndef HSOPENSSL_H_INCLUDED
#define HSOPENSSL_H_INCLUDED
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/objects.h>
#include <openssl/opensslconf.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/ssl.h>
#include <openssl/stack.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <openssl/dsa.h>

/* OpenSSL ********************************************************************/
void HsOpenSSL_OpenSSL_add_all_algorithms();
void HsOpenSSL_OPENSSL_free(void* ptr);

/* BIO ************************************************************************/
void HsOpenSSL_BIO_set_flags(BIO* bio, int flags);
int HsOpenSSL_BIO_flush(BIO* bio);
int HsOpenSSL_BIO_reset(BIO* bio);
int HsOpenSSL_BIO_eof(BIO* bio);
int HsOpenSSL_BIO_set_md(BIO* bio, EVP_MD* md);
int HsOpenSSL_BIO_set_buffer_size(BIO* bio, int bufSize);
int HsOpenSSL_BIO_should_retry(BIO* bio);
int HsOpenSSL_BIO_FLAGS_BASE64_NO_NL();

/* EVP ************************************************************************/
int HsOpenSSL_EVP_MD_size(EVP_MD* md);
int HsOpenSSL_EVP_CIPHER_CTX_block_size(EVP_CIPHER_CTX* ctx);
int HsOpenSSL_EVP_CIPHER_iv_length(EVP_CIPHER* cipher);

/* X509 ***********************************************************************/
long HsOpenSSL_X509_get_version(X509* x509);
ASN1_TIME* HsOpenSSL_X509_get_notBefore(X509* x509);
ASN1_TIME* HsOpenSSL_X509_get_notAfter(X509* x509);

long HsOpenSSL_X509_REQ_get_version(X509_REQ* req);
X509_NAME* HsOpenSSL_X509_REQ_get_subject_name(X509_REQ* req);

long HsOpenSSL_X509_CRL_get_version(X509_CRL* crl);
ASN1_TIME* HsOpenSSL_X509_CRL_get_lastUpdate(X509_CRL* crl);
ASN1_TIME* HsOpenSSL_X509_CRL_get_nextUpdate(X509_CRL* crl);
X509_NAME* HsOpenSSL_X509_CRL_get_issuer(X509_CRL* crl);
STACK_OF(X509_REVOKED)* HsOpenSSL_X509_CRL_get_REVOKED(X509_CRL* crl);

/* PKCS#7 *********************************************************************/
long HsOpenSSL_PKCS7_is_detached(PKCS7* pkcs7);

/* ASN1 ***********************************************************************/
ASN1_INTEGER* HsOpenSSL_M_ASN1_INTEGER_new();
void HsOpenSSL_M_ASN1_INTEGER_free(ASN1_INTEGER* intPtr);
ASN1_INTEGER* HsOpenSSL_M_ASN1_TIME_new();
void HsOpenSSL_M_ASN1_TIME_free(ASN1_TIME* timePtr);

/* Threads ********************************************************************/
void HsOpenSSL_setupMutex();

/* DSA ************************************************************************/
int HsOpenSSL_dsa_sign(DSA *dsa, const unsigned char *ddata, int len,
                       BIGNUM **r, BIGNUM **s);
int HsOpenSSL_dsa_verify(DSA *dsa, const unsigned char *ddata, int len,
                         BIGNUM *r, BIGNUM *s);
DSA* HsOpenSSL_DSAPublicKey_dup(const DSA* dsa);
DSA* HsOpenSSL_DSAPrivateKey_dup(const DSA* dsa);

#endif
