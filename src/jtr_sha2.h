/*
 *
 * This software was written by JimF jfoug AT cox dot net
 * in 2013. No copyright is claimed, and the software is hereby
 * placed in the public domain. In case this attempt to disclaim
 * copyright and place the software in the public domain is deemed
 * null and void, then the software is Copyright (c) 2013 JimF
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
 * use different names, (and #defines to map), we run the risk
 * of having multiple defined functions/data.
 *
 * NOTE, if FORCE_GENERIC_SHA2 is defined before this header is
 * included, then the generic data_types/functions are used.
 *
 */

#ifndef __JTR_SHA2___H_
#define __JTR_SHA2___H_

#include <stdint.h>

#if !AC_BUILT || HAVE_LIMITS_H
#include <limits.h>
#endif
#if (!AC_BUILT || HAVE_SYS_PARAM_H) && !defined (_MSC_VER)
#include <sys/param.h>
#endif
#include <sys/types.h>

#include "johnswap.h"
#include "stdbool.h"

// Does sha256 AND sha224. Sha224 is same, but only returns
// 224 bits, and has a different init IV. Other than that
// the code is exactly the same.
// NOTE, only handles up to 2^32/8 bytes of data, but for
// JtR this is MORE than enough.
typedef struct
{
	uint32_t h[8];          // SHA256 state
	uint32_t Nl,Nh;         // UNUSED but here to be compatible with oSSL
	unsigned char buffer[64];   // current/building data 'block'. It IS in alignment
	unsigned int num,md_len;    // UNUSED but here to be compatible with oSSL
	unsigned int total;         // number of bytes processed
	int bIs256;                 // if 1 SHA256, else SHA224
} jtr_sha256_ctx;

extern void jtr_sha256_init   (jtr_sha256_ctx *ctx, int bIs256);
extern void jtr_sha256_update (jtr_sha256_ctx *ctx, const void *input, int len);
extern void jtr_sha256_final  (void *output, jtr_sha256_ctx *ctx);
// Low level function, exposed, so we can keep from doing swapping, IF we have already swapped the memory.
extern void jtr_sha256_hash_block(jtr_sha256_ctx *ctx, const unsigned char data[64], int perform_endian_swap);

#undef SHA256_CTX
#undef SHA224_Init
#undef SHA256_Init
#undef SHA224_Update
#undef SHA256_Update
#undef SHA224_Final
#undef SHA256_Final

#define SHA256_CTX           jtr_sha256_ctx
#define SHA224_Init(a)       jtr_sha256_init(a,0)
#define SHA256_Init(a)       jtr_sha256_init(a,1)
#define SHA224_Update(a,b,c) jtr_sha256_update(a,b,c)
#define SHA256_Update(a,b,c) jtr_sha256_update(a,b,c)
#define SHA224_Final(a,b)    jtr_sha256_final(a,b)
#define SHA256_Final(a,b)    jtr_sha256_final(a,b)

// Does sha512 and sha384
typedef struct
{
	uint64_t h[8];          // SHA512 state
	uint64_t Nl,Nh;         // UNUSED but here to be compatible with oSSL
	unsigned char buffer[128];  // current/building data 'block'.  It IS in alignment
	unsigned int num,md_len;    // UNUSED but here to be compatible with oSSL
	unsigned int total;         // number of bytes processed
	int bIs512;                 // if 1 SHA512, else SHA384
	int bIsQnxBuggy;            // if 1, then final fails to clean last MD buffer
} jtr_sha512_ctx;

extern void jtr_sha512_init(jtr_sha512_ctx *ctx, int bIs512);
extern void jtr_sha512_update(jtr_sha512_ctx *ctx, const void *input, int len);
extern void jtr_sha512_final(void *output, jtr_sha512_ctx *ctx);
// Low level function, exposed, so we can keep from doing swapping, IF we have already swapped the memory.
extern void jtr_sha512_hash_block(jtr_sha512_ctx *ctx, const unsigned char data[128], int perform_endian_swap);

#undef SHA512_CTX
#undef SHA384_Init
#undef SHA512_Init
#undef SHA512_Update
#undef SHA384_Update
#undef SHA512_Final
#undef SHA384_Final

#define SHA512_CTX           jtr_sha512_ctx
#define SHA384_Init(a)       jtr_sha512_init(a,0)
#define SHA512_Init(a)       jtr_sha512_init(a,1)
#define SHA512_Update(a,b,c) jtr_sha512_update(a,b,c)
#define SHA384_Update(a,b,c) jtr_sha512_update(a,b,c)
#define SHA512_Final(a,b)    jtr_sha512_final(a,b)
#define SHA384_Final(a,b)    jtr_sha512_final(a,b)

#if ARCH_LITTLE_ENDIAN
#define OUTBE32(n,b,i) do { (b)[i] = ((n)>>24); (b)[i+1] = ((n)>>16); (b)[i+2] = ((n)>>8); (b)[i+3] = (n); } while(0)
#define OUTBE64(n,b,i) do {	  \
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
#define OUTBE32(n,b,i) *((uint32_t*)&(b[i]))=n
#define OUTBE64(n,b,i) *((uint64_t*)&(b[i]))=n
#endif

#endif
