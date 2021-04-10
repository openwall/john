#include <stddef.h>
#include <string.h>

// NOTE, we need to handle this for non-AC built. I am sure there is some openssl version
// to check in that case. I do not know it, so for now, I will only deal with AC builds
#if HAVE_AES_ENCRYPT

#include <openssl/aes.h>

#else

/*
 * this code copied from oSSL newer version. This is ALL we do, so it
 * has been pared down here.
 */
#define AES_ENCRYPT	1
#define AES_DECRYPT	0
/* Because array size can't be a const in C, the following two are macros.
   Both sizes are in bytes. */
#define AES_MAXNR 14
#define AES_BLOCK_SIZE 16
typedef struct aes_key_st {
    unsigned int rd_key[4 *(AES_MAXNR + 1)];
    int rounds;
} AES_KEY;
typedef void (*block128_f)(const unsigned char in[16], unsigned char out[16], const void *key);

#include "ossl_aes_crypto.c"

// ignore the FIPS crap.
void JTR_AES_cbc_encrypt(const unsigned char *in, unsigned char *out, size_t len, const AES_KEY *key, unsigned char *ivec, const int enc) {
	if (enc) CRYPTO_cbc128_encrypt(in,out,len,key,ivec,(block128_f)AES_encrypt);
	else CRYPTO_cbc128_decrypt(in,out,len,key,ivec,(block128_f)AES_decrypt);
}
#define AES_cbc_encrypt JTR_AES_cbc_encrypt
/*
 * This is the end of the oSSL code
 */


#endif

inline static void aes_key_mgmt(AES_KEY *akey, unsigned char *key, unsigned int key_length, int direction) {
	if (direction == AES_ENCRYPT) {
		AES_set_encrypt_key(key, key_length, akey);
	} else {
		AES_set_decrypt_key(key, key_length, akey);
	}
}

inline static void aes_cbc(unsigned char *in, unsigned char *out, unsigned char *key, size_t num_blocks, unsigned char *iv, unsigned int key_length, int direction) {
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

// Here are the 'low level' ones (some)  These are tied in with aes/aes.h
#undef AES_encrypt
void JTR_AES_encrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key) {
	AES_encrypt(in, out, key);
}
#undef AES_decrypt
void JTR_AES_decrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key) {
	AES_decrypt(in, out, key);
}

#undef AES_set_encrypt_key
int JTR_AES_set_encrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key) {
	return AES_set_encrypt_key(userKey, bits, key);
}

#undef AES_set_decrypt_key
int JTR_AES_set_decrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key) {
	return AES_set_decrypt_key(userKey, bits, key);
}
