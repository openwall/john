#include <stdio.h>
#include <string.h>

#define OSSL_CBC_FUNC(n) \
        void openssl_AES_enc##n##_CBC(unsigned char *in, unsigned char *out, unsigned char *key, size_t num_blocks, unsigned char *iv); \
        void openssl_AES_dec##n##_CBC(unsigned char *in, unsigned char *out, unsigned char *key, size_t num_blocks, unsigned char *iv);

OSSL_CBC_FUNC(128)
OSSL_CBC_FUNC(192)
OSSL_CBC_FUNC(256)

#undef OSSL_CBC_FUNC
