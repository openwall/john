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

/* note, all function/type declarations moved to common location */
#include "aes/openssl/ossl-aes-externs.h"

#define AES_encrypt(a,b,c) JTR_AES_encrypt(a,b,c)
#define AES_ecb_encrypt(a,b,c,d) (d == AES_ENCRYPT) ? JTR_AES_encrypt(a,b,c) : JTR_AES_decrypt(a,b,c)
#define AES_decrypt(a,b,c) JTR_AES_decrypt(a,b,c)
#define AES_set_encrypt_key(a,b,c) JTR_AES_set_encrypt_key(a,b,c)
#define AES_set_decrypt_key(a,b,c) JTR_AES_set_decrypt_key(a,b,c)
#define AES_cbc_encrypt(a,b,c,d,e,f) JTR_AES_cbc_encrypt(a,b,c,d,e,f)

// probably need to also do AES_cbc_decrypt, but will wait until someone 'needs' it.

#endif

#endif /* JTR_AES_H */
