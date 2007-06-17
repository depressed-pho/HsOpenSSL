#ifndef HSOPENSSL_H_INCLUDED
#define HSOPENSSL_H_INCLUDED
#include <openssl/opensslconf.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

/* OpenSSL ********************************************************************/
void HsOpenSSL_OpenSSL_add_all_algorithms();
void HsOpenSSL_OPENSSL_free(void* ptr);

/* BIO ************************************************************************/
void HsOpenSSL_BIO_set_flags(BIO* bio, int flags);
int HsOpenSSL_BIO_flush(BIO* bio);
int HsOpenSSL_BIO_eof(BIO* bio);
int HsOpenSSL_BIO_set_md(BIO* bio, EVP_MD* md);
int HsOpenSSL_BIO_FLAGS_BASE64_NO_NL();

/* EVP ************************************************************************/
int HsOpenSSL_EVP_MD_size(EVP_MD* md);
int HsOpenSSL_EVP_CIPHER_CTX_block_size(EVP_CIPHER_CTX* ctx);
int HsOpenSSL_EVP_CIPHER_iv_length(EVP_CIPHER* cipher);

#endif
