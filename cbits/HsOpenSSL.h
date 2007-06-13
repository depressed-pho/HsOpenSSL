#ifndef HSOPENSSL_H_INCLUDED
#define HSOPENSSL_H_INCLUDED
#include <openssl/bio.h>
#include <openssl/evp.h>

/* BIO ************************************************************************/
void HsOpenSSL_BIO_set_flags(BIO* bio, int flags);
int HsOpenSSL_BIO_flush(BIO* bio);
int HsOpenSSL_BIO_eof(BIO* bio);
int HsOpenSSL_BIO_set_md(BIO* bio, EVP_MD* md);
int HsOpenSSL_BIO_FLAGS_BASE64_NO_NL();

/* EVP ************************************************************************/
int HsOpenSSL_EVP_MD_size(EVP_MD* md);

#endif
