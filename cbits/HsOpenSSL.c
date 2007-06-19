#include <pthread.h>
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

int HsOpenSSL_BIO_reset(BIO* bio) {
    return BIO_reset(bio);
}

int HsOpenSSL_BIO_eof(BIO* bio) {
    return BIO_eof(bio);
}

int HsOpenSSL_BIO_set_md(BIO* bio, EVP_MD* md) {
    return BIO_set_md(bio, md);
}

int HsOpenSSL_BIO_set_buffer_size(BIO* bio, int bufSize) {
    return BIO_set_buffer_size(bio, bufSize);
}

int HsOpenSSL_BIO_should_retry(BIO* bio) {
    return BIO_should_retry(bio);
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

int HsOpenSSL_EVP_CIPHER_iv_length(EVP_CIPHER* cipher) {
    return EVP_CIPHER_iv_length(cipher);
}

/* Threads ********************************************************************/
static pthread_mutex_t* mutex_at;

struct CRYPTO_dynlock_value {
    pthread_mutex_t mutex;
};

static void HsOpenSSL_lockingCallback(int mode, int n, const char* file, int line) {
    if (mode & CRYPTO_LOCK) {
        pthread_mutex_lock(&mutex_at[n]);
    }
    else {
        pthread_mutex_unlock(&mutex_at[n]);
    }
}

static unsigned long HsOpenSSL_idCallback() {
    return (unsigned long)pthread_self();
}

static struct CRYPTO_dynlock_value* HsOpenSSL_dynlockCreateCallback(const char* file, int line) {
    struct CRYPTO_dynlock_value* val;

    val = OPENSSL_malloc(sizeof(struct CRYPTO_dynlock_value));
    pthread_mutex_init(&val->mutex, NULL);

    return val;
}

static void HsOpenSSL_dynlockLockCallback(int mode, struct CRYPTO_dynlock_value* val, const char* file, int line) {
    if (mode & CRYPTO_LOCK) {
        pthread_mutex_lock(&val->mutex);
    }
    else {
        pthread_mutex_unlock(&val->mutex);
    }
}

static void HsOpenSSL_dynlockDestroyCallback(struct CRYPTO_dynlock_value* val, const char* file, int line) {
    pthread_mutex_destroy(&val->mutex);
    OPENSSL_free(val);
}

void HsOpenSSL_setupMutex() {
    int i;
    
    mutex_at = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));

    for (i = 0; i < CRYPTO_num_locks(); i++) {
        pthread_mutex_init(&mutex_at[i], NULL);
    }

    CRYPTO_set_locking_callback(HsOpenSSL_lockingCallback);
    CRYPTO_set_id_callback(HsOpenSSL_idCallback);
    
    CRYPTO_set_dynlock_create_callback(HsOpenSSL_dynlockCreateCallback);
    CRYPTO_set_dynlock_lock_callback(HsOpenSSL_dynlockLockCallback);
    CRYPTO_set_dynlock_destroy_callback(HsOpenSSL_dynlockDestroyCallback);
}
