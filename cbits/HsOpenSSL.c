#include "HsOpenSSL.h"

/* OpenSSL ********************************************************************/
void HsOpenSSL_OpenSSL_add_all_algorithms() {
    OpenSSL_add_all_algorithms();
}

void HsOpenSSL_OPENSSL_free(void* ptr) {
    OPENSSL_free(ptr);
}

/* BIO ************************************************************************/
void HsOpenSSL_BIO_set_flags(BIO* bio, int flags) {
    BIO_set_flags(bio, flags);
}

int HsOpenSSL_BIO_flush(BIO* bio) {
    return BIO_flush(bio);
}

int HsOpenSSL_BIO_eof(BIO* bio) {
    return BIO_eof(bio);
}

int HsOpenSSL_BIO_set_md(BIO* bio, EVP_MD* md) {
    return BIO_set_md(bio, md);
}

int HsOpenSSL_BIO_FLAGS_BASE64_NO_NL() {
    return BIO_FLAGS_BASE64_NO_NL;
}

/* EVP ************************************************************************/
int HsOpenSSL_EVP_MD_size(EVP_MD* md) {
    return EVP_MD_size(md);
}

int HsOpenSSL_EVP_CIPHER_CTX_block_size(EVP_CIPHER_CTX* ctx) {
    return EVP_CIPHER_CTX_block_size(ctx);
}
