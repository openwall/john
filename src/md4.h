/*
 * This is an OpenSSL-compatible implementation of the RSA Data Security,
 * Inc. MD4 Message-Digest Algorithm (RFC 1320).
 *
 * Written by Solar Designer <solar at openwall.com> in 2001, and placed
 * in the public domain.  There's absolutely no warranty.
 *
 * See md4.c for more information.
 */

#ifdef HAVE_OPENSSL
#include <openssl/md4.h>
#elif !defined(_MD4_H)
#define _MD4_H

#define MD4_Init john_MD4_Init
#define MD4_Update john_MD4_Update
#define MD4_Final john_MD4_Final

/* Any 32-bit or wider unsigned integer data type will do */
typedef unsigned int MD4_u32plus;

typedef struct {
	MD4_u32plus lo, hi;
	MD4_u32plus a, b, c, d;
	unsigned char buffer[64];
	MD4_u32plus block[16];
} MD4_CTX;

extern void MD4_Init(MD4_CTX *ctx);
extern void MD4_Update(MD4_CTX *ctx, void *data, unsigned long size);
extern void MD4_Final(unsigned char *result, MD4_CTX *ctx);

/* Bartavelle's SSE/MMX asm functions */
#if (MMX_COEF == 2)
#ifdef _MSC_VER
int __fastcall mdfourmmx_VC(unsigned char *out, unsigned char *in, int n);
int __fastcall mdfourmmx_nosizeupdate_VC(unsigned char *out, unsigned char *in, int n);
#define mdfourmmx mdfourmmx_VC
#define mdfourmmx_nosizeupdate mdfourmmx_nosizeupdate_VC
#else
extern int mdfourmmx(unsigned char *out, unsigned char *in, int n) __attribute__((regparm(3)));
extern int mdfourmmx_nosizeupdate(unsigned char *out, unsigned char *in, int n) __attribute__((regparm(3)));
#endif
#endif

#if (MMX_COEF == 4)
#ifdef _MSC_VER
int __fastcall mdfoursse2_VC(unsigned char *out, unsigned char *in, int n);
int __fastcall mdfoursse2_nosizeupdate_VC(unsigned char *out, unsigned char *in, int n);
#define mdfourmmx mdfoursse2_VC
#define mdfourmmx_nosizeupdate mdfoursse2_nosizeupdate_VC
#else
#define mdfourmmx mdfoursse2
#define mdfourmmx_nosizeupdate mdfoursse2_nosizeupdate
extern int mdfoursse2(unsigned char *out, unsigned char *in, int n) __attribute__((regparm(3)));
extern int mdfoursse2_nosizeupdate(unsigned char *out, unsigned char *in, int n) __attribute__((regparm(3)));
#endif
#endif

#endif
