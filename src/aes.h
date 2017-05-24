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
 */

#ifndef JTR_AES_H
#define JTR_AES_H

#include <stdio.h>
#include <string.h>
#ifdef AC_BUILT
#include "autoconfig.h"
#endif

// Input, output, key, number of blocks
typedef void (*aes_fptr_vanilla)(unsigned char *, unsigned char *, unsigned char *, size_t);
// Input, output, key, number of blocks, iv
typedef void (*aes_fptr_cbc)(unsigned char *, unsigned char *, unsigned char *, size_t, unsigned char *);
// Input, output, key, number of blocks, iv
typedef void (*aes_fptr_ctr)(unsigned char *, unsigned char *, unsigned char *, size_t, unsigned char *);

#define FUNC(r,p) aes_fptr_##r get_##p();

#include "aes/aes_func.h"

#undef FUNC

extern int using_aes_asm();
extern const char *get_AES_type_string();

#if HAVE_AES_ENCRYPT

#include <openssl/aes.h>

#else
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
#define AES_encrypt(a,b,c) JTR_AES_encrypt(a,b,c)

#define AES_ecb_encrypt(a,b,c,d) (d == AES_ENCRYPT) ? JTR_AES_encrypt(a,b,c) : JTR_AES_decrypt(a,b,c)

extern void JTR_AES_decrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key);
#define AES_decrypt(a,b,c) JTR_AES_decrypt(a,b,c)

extern int JTR_AES_set_encrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key);
#define AES_set_encrypt_key(a,b,c) JTR_AES_set_encrypt_key(a,b,c)

extern int JTR_AES_set_decrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key);
#define AES_set_decrypt_key(a,b,c) JTR_AES_set_decrypt_key(a,b,c)

extern void JTR_AES_cbc_encrypt(const unsigned char *in, unsigned char *out, size_t len, const AES_KEY *key, unsigned char *ivec, const int enc);
#define AES_cbc_encrypt(a,b,c,d,e,f) JTR_AES_cbc_encrypt(a,b,c,d,e,f)

// probably need to also do AES_cbc_decrypt, but will wait until someone 'needs' it.

#endif

#endif /* JTR_AES_H */
