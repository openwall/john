#include <openssl/aes.h>
#include <stddef.h>

static inline void aes_key_mgmt(AES_KEY *akey, unsigned char *key, unsigned int key_length, int direction) {
	if (direction == AES_ENCRYPT) {
		AES_set_encrypt_key(key, key_length, akey);
	} else {
		AES_set_decrypt_key(key, key_length, akey);
	}
}

static inline void aes_cbc(unsigned char *in, unsigned char *out, unsigned char *key, size_t num_blocks, unsigned char *iv, unsigned int key_length, int direction) {
	AES_KEY akey;
	aes_key_mgmt(&akey, key, key_length, direction);
	AES_cbc_encrypt(in, out, num_blocks * AES_BLOCK_SIZE, &akey, iv, direction);
}

#define OSSL_CBC_FUNC(n) \
	void openssl_AES_enc##n##_CBC(unsigned char *in, unsigned char *out, unsigned char *key, size_t num_blocks, unsigned char *iv) { aes_cbc(in, out, key, num_blocks, iv, n, AES_ENCRYPT); } \
	void openssl_AES_dec##n##_CBC(unsigned char *in, unsigned char *out, unsigned char *key, size_t num_blocks, unsigned char *iv) { aes_cbc(in, out, key, num_blocks, iv, n, AES_DECRYPT); }

OSSL_CBC_FUNC(128)
OSSL_CBC_FUNC(192)
OSSL_CBC_FUNC(256)

#undef OSSL_CBC_FUNC

// There are other AES functions that could be implemented here.
