/*
 *
 * This software was written by JimF jfoug AT cox dot net
 * in 2012. No copyright is claimed, and the software is hereby
 * placed in the public domain. In case this attempt to disclaim
 * copyright and place the software in the public domain is deemed
 * null and void, then the software is Copyright © 2012 JimF
 * and it is hereby released to the general public under the following
 * terms:
 *
 * This software may be modified, redistributed, and used for any
 * purpose, in source and binary forms, with or without modification.
 */

/*
 * SHA-224 and SHA-256 hash function.
 * Will use Openssl if the openssl version is great enough.
 * otherwise, we use C code, in ssh2.c, and some #defines
 * to make that code 'appear' like OpenSSL  It was done this
 * way, just in case there are versions of OSSL that have some
 * of this code, older than what we 'know' about. If we do not
 * use differnt names, (and #defines to map), we run the risk
 * of having multiple defined functions/data.
 *
 * NOTE, if FORCE_GENERIC_SHA2 is defined before this header is
 * included, then the generic data_types/functions are used.
 *
 */

#include <string.h>

#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER >= 0x00908000 && !defined(FORCE_GENERIC_SHA2)

#if defined(__APPLE__) && defined(__MACH__)
#ifdef __MAC_OS_X_VERSION_MIN_REQUIRED
#if __MAC_OS_X_VERSION_MIN_REQUIRED >= 1070
#define COMMON_DIGEST_FOR_OPENSSL
#define SHA2_LIB "CommonCrypto"
#include <CommonCrypto/CommonDigest.h>
#define JTR_INC_COMMON_CRYPTO_SHA2
#else
#define SHA2_LIB "OpenSSL"
#include <openssl/sha.h>
#endif
#else
#define SHA2_LIB "OpenSSL"
#include <openssl/sha.h>
#endif
#else
#define SHA2_LIB "OpenSSL"
#include <openssl/sha.h>
#endif

#undef GENERIC_SHA2

#else	// OPENSSL_VERSION_NUMBER ! >= 0x00908000

#include "johnswap.h"
#include "stdbool.h"
#include "stdint.h"
#include <limits.h>
#ifndef _MSC_VER
#include <sys/param.h>
#endif
#include <sys/types.h>

#define SHA2_LIB "generic"
#define GENERIC_SHA2

// Does sha256 AND sha224. Sha224 is same, but only returns
// 224 bits, and has a different init IV. Other than that
// the code is exactly the same.
// NOTE, only handles up to 2^32/8 bytes of data, but for
// JtR this is MORE than enough.
typedef struct
{
    ARCH_WORD_32 h[8];          // SHA256 state
	ARCH_WORD_32 Nl,Nh;			// UNUSED but here to be compatible with oSSL
    unsigned char buffer[64];   // current/building data 'block'. It IS in alignment
	unsigned int num,md_len;	// UNUSED but here to be compatible with oSSL
    unsigned int total;         // number of bytes processed
    int bIs256;                 // if 1 SHA256, else SHA224
} sha256_ctx;

extern void sha256_init   (sha256_ctx *ctx, int bIs256);
extern void sha256_update (sha256_ctx *ctx, const void *input, int len);
extern void sha256_final  (void *output, sha256_ctx *ctx);
// Low level function, exposed, so we can keep from doing swapping, IF we have already swapped the memory.
extern void sha256_hash_block(sha256_ctx *ctx, const unsigned char data[64], int perform_endian_swap);

#define SHA256_CTX           sha256_ctx
#define SHA224_Init(a)       sha256_init(a,0)
#define SHA256_Init(a)       sha256_init(a,1)
#define SHA224_Update(a,b,c) sha256_update(a,b,c)
#define SHA256_Update(a,b,c) sha256_update(a,b,c)
#define SHA224_Final(a,b)    sha256_final(a,b)
#define SHA256_Final(a,b)    sha256_final(a,b)

// Does sha512 and sha384
typedef struct
{
    ARCH_WORD_64 h[8];          // SHA512 state
	ARCH_WORD_64 Nl,Nh;			// UNUSED but here to be compatible with oSSL
    unsigned char buffer[128];  // current/building data 'block'.  It IS in alignment
	unsigned int num,md_len;	// UNUSED but here to be compatible with oSSL
    unsigned int total;         // number of bytes processed
    int bIs512;                 // if 1 SHA512, else SHA384
} sha512_ctx;

extern void sha512_init(sha512_ctx *ctx, int bIs512);
extern void sha512_update(sha512_ctx *ctx, const void *input, int len);
extern void sha512_final(void *output, sha512_ctx *ctx);
// Low level function, exposed, so we can keep from doing swapping, IF we have already swapped the memory.
extern void sha512_hash_block(sha512_ctx *ctx, const unsigned char data[128], int perform_endian_swap);

#define SHA512_CTX           sha512_ctx
#define SHA384_Init(a)       sha512_init(a,0)
#define SHA512_Init(a)       sha512_init(a,1)
#define SHA512_Update(a,b,c) sha512_update(a,b,c)
#define SHA384_Update(a,b,c) sha512_update(a,b,c)
#define SHA512_Final(a,b)    sha512_final(a,b)
#define SHA384_Final(a,b)    sha512_final(a,b)

#if ARCH_LITTLE_ENDIAN
#define OUTBE32(n,b,i) do { (b)[i] = ((n)>>24); (b)[i+1] = ((n)>>16); (b)[i+2] = ((n)>>8); (b)[i+3] = (n); } while(0)
#define OUTBE64(n,b,i) do {                     \
    (b)[(i)]   = (unsigned char) ( (n) >> 56 ); \
    (b)[(i)+1] = (unsigned char) ( (n) >> 48 ); \
    (b)[(i)+2] = (unsigned char) ( (n) >> 40 ); \
    (b)[(i)+3] = (unsigned char) ( (n) >> 32 ); \
    (b)[(i)+4] = (unsigned char) ( (n) >> 24 ); \
    (b)[(i)+5] = (unsigned char) ( (n) >> 16 ); \
    (b)[(i)+6] = (unsigned char) ( (n) >>  8 ); \
    (b)[(i)+7] = (unsigned char) ( (n)       ); \
} while(0)

#else
#define OUTBE32(n,b,i) *((ARCH_WORD_32*)&(b[i]))=n
#define OUTBE64(n,b,i) *((ARCH_WORD_64*)&(b[i]))=n
#endif

#endif
