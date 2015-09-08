/*
 * This is an OpenSSL-compatible implementation of the RSA Data Security,
 * Inc. MD5 Message-Digest Algorithm (RFC 1321).
 *
 * Written by Solar Designer <solar at openwall.com> in 2001, and placed
 * in the public domain.  There's absolutely no warranty.
 *
 * See md5.c for more information.
 *
 * This file has been modified in the JtR jumbo patch.
 * If you reuse the code for another purpose, please download the original from:
 * http://openwall.info/wiki/people/solar/software/public-domain-source-code/md5
 */

#if !defined(_MD5_H)
#define _MD5_H

/* Any 32-bit or wider unsigned integer data type will do */
/* this needs to be defined no matter if building with HAVE_LIBSSL or not */
typedef unsigned int MD5_u32plus;

#include "arch.h"

#ifdef HAVE_LIBSSL
#include <openssl/md5.h>

#else

#define MD5_Init john_MD5_Init
#define MD5_Update john_MD5_Update
#define MD5_Final john_MD5_Final

typedef struct {
	MD5_u32plus A, B, C, D;
	MD5_u32plus lo, hi;
	unsigned char buffer[64];
	MD5_u32plus block[16];
} MD5_CTX;

extern void MD5_Init(MD5_CTX *ctx);
extern void MD5_Update(MD5_CTX *ctx, const void *data, unsigned long size);
extern void MD5_PreFinal(MD5_CTX *ctx);
extern void MD5_Final(unsigned char *result, MD5_CTX *ctx);
#endif /* HAVE_LIBSSL */

#endif /* _MD5_H */
