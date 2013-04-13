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

/* Any 32-bit or wider unsigned integer data type will do */
/* this needs to be defined no matter if building with HAVE_OPENSSL or not */
typedef unsigned int MD5_u32plus;

#ifdef HAVE_OPENSSL
#include <openssl/md5.h>

#elif !defined(_MD5_H)
#define _MD5_H

#define MD5_Init john_MD5_Init
#define MD5_Update john_MD5_Update
#define MD5_Final john_MD5_Final

typedef struct {
	MD5_u32plus lo, hi;
	MD5_u32plus a, b, c, d;
	unsigned char buffer[64];
	MD5_u32plus block[16];
} MD5_CTX;

extern void MD5_Init(MD5_CTX *ctx);
extern void MD5_Update(MD5_CTX *ctx, void *data, unsigned long size);
extern void MD5_PreFinal(MD5_CTX *ctx);
extern void MD5_Final(unsigned char *result, MD5_CTX *ctx);
#endif

/* Now, the MMX code is NOT dependent upon the HAVE_OPENSSL */

#ifdef MMX_COEF
#ifdef _MSC_VER
/* NOTE, in VC, void __fastcall f(unsigned char *out, unsigned char *in, int n)
 * puts these registers:
 *  n   -> pushed on stack
 *  ECX -> out
 *  EDX -> in
 *  Thus to get into this code, we ECX -> EAX and get ECX from the stack (minus the return push)
 *  Also do a ret 4 after the emms in the mdfivemmx_noinit (to pop the push of eax)
 */
int __fastcall mdfivemmx_VC(unsigned char *out, unsigned char *in, int n);
int __fastcall mdfivemmx_nosizeupdate_VC(unsigned char *out, unsigned char *in, int n);
int __fastcall mdfivemmx_noinit_sizeupdate_VC(unsigned char *out, unsigned char *in, int n);
int __fastcall mdfivemmx_noinit_nosizeupdate_VC(unsigned char *out, unsigned char *in, int n);
int __fastcall mdfivemmx_noinit_uniformsizeupdate_VC(unsigned char *out, unsigned char *in, int n);

#define mdfivemmx mdfivemmx_VC
#define mdfivemmx_nosizeupdate mdfivemmx_nosizeupdate_VC
#define mdfivemmx_noinit_sizeupdate mdfivemmx_noinit_sizeupdate_VC
#define mdfivemmx_noinit_nosizeupdate mdfivemmx_noinit_nosizeupdate_VC
#define mdfivemmx_noinit_uniformsizeupdate mdfivemmx_noinit_uniformsizeupdate_VC
#else
extern int mdfivemmx(unsigned char *out, unsigned char *in, int n) __attribute__((regparm(3)));
extern int mdfivemmx_nosizeupdate(unsigned char *out, unsigned char *in, int n) __attribute__((regparm(3)));
extern int mdfivemmx_noinit_sizeupdate(unsigned char *out, unsigned char *in, int n) __attribute__((regparm(3)));
extern int mdfivemmx_noinit_nosizeupdate(unsigned char *out, unsigned char *in, int n) __attribute__((regparm(3)));
extern int mdfivemmx_noinit_uniformsizeupdate(unsigned char *out, unsigned char *in, int n) __attribute__((regparm(3)));
#endif
#endif
