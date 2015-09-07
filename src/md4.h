/*
 * This is an OpenSSL-compatible implementation of the RSA Data Security,
 * Inc. MD4 Message-Digest Algorithm (RFC 1320).
 *
 * Written by Solar Designer <solar at openwall.com> in 2001, and placed
 * in the public domain.  There's absolutely no warranty.
 *
 * See md4.c for more information.
 */

#include "arch.h"

#ifdef HAVE_LIBSSL
#include <openssl/md4.h>
#elif !defined(_MD4_H)
#define _MD4_H

#define MD4_Init john_MD4_Init
#define MD4_Update john_MD4_Update
#define MD4_Final john_MD4_Final

/* Any 32-bit or wider unsigned integer data type will do */
typedef unsigned int MD4_u32plus;

typedef struct {
	MD4_u32plus A, B, C, D;
	MD4_u32plus lo, hi;
	unsigned char buffer[64];
	MD4_u32plus block[16];
} MD4_CTX;

extern void MD4_Init(MD4_CTX *ctx);
extern void MD4_Update(MD4_CTX *ctx, const void *data, unsigned long size);
extern void MD4_Final(unsigned char *result, MD4_CTX *ctx);

#endif
