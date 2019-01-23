/*
 * (c) 2014 Harrison Neal. Licensed under GPLv2.
 * A set of convenience functions that return a function pointer to an
 * appropriate AES implementation depending on your platform.
 *
 * NOTE: These functions are intended to be used by algorithms that
 * continuously switch out AES keys - with each computation, state is
 * built, used and torn down.
 * Consider using straight OpenSSL EVP methods if your algorithm would
 * do a lot of work with any single key.
 *
 * declarations moved from aes.h to aes/openssl/ossl-aes-externs.h
 * This was done to allow calling functions AND the library to
 * utilize the same function declarations (i.e. here)
 */

#if !defined (__OSSL_AES_EXTERNS_H__)
#define __OSSL_AES_EXTERNS_H__

/*
 * this code copied from oSSL newer version. This is ALL we do, so it
 * has been pared down here.
 */
#define AES_ENCRYPT	1
#define AES_DECRYPT	0
#define AES_MAXNR 14
#define AES_BLOCK_SIZE 16

typedef struct aes_key_st {
    unsigned int rd_key[4 *(AES_MAXNR + 1)];
    int rounds;
} AES_KEY;

extern void JTR_AES_encrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key);
extern void JTR_AES_decrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key);
extern int JTR_AES_set_encrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key);
extern int JTR_AES_set_decrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key);
extern void JTR_AES_cbc_encrypt(const unsigned char *in, unsigned char *out, size_t len, const AES_KEY *key, unsigned char *ivec, const int enc);


#endif  // __OSSL_AES_EXTERNS_H__
