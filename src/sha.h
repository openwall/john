#ifndef JOHN_SHA_H
#define JOHN_SHA_H

#if AC_BUILT
#include "autoconfig.h"
#endif

#if HAVE_LIBCRYPTO || HAVE_COMMONCRYPTO
#include <openssl/opensslv.h>

#include "arch.h"
#if HAVE_COMMONCRYPTO || (!AC_BUILT &&	  \
	!defined(SIMD_COEF_32) && defined(__APPLE__) && defined(__MACH__) && \
	 defined(__MAC_OS_X_VERSION_MIN_REQUIRED) && \
	 __MAC_OS_X_VERSION_MIN_REQUIRED >= 1070)
/* Mitigate CommonCrypto name clashes */
#include "md4.h"
#include "md5.h"
#define COMMON_DIGEST_FOR_OPENSSL 1
#include <CommonCrypto/CommonDigest.h>
#ifndef SHA_CBLOCK
#define SHA_CBLOCK CC_SHA1_BLOCK_BYTES
#endif
#ifndef SHA_LBLOCK
#define SHA_LBLOCK CC_SHA1_BLOCK_LONG
#endif
#else
#include <openssl/sha.h>
#endif

/* For the abuse in pbkdf2_hmac_sha1.h and mscash2_fmt_plug.c */
#define SHA_H0 h0
#define SHA_H1 h1
#define SHA_H2 h2
#define SHA_H3 h3
#define SHA_H4 h4

#else /* !(HAVE_LIBCRYPTO || HAVE_COMMONCRYPTO) */
#include "sph_sha1.h"
#define SHA_CTX sph_sha1_context
#define SHA1_Init sph_sha1_init
#define SHA1_Update sph_sha1
#define SHA1_Final(dst, ctx) sph_sha1_close((ctx), (dst))
#define SHA_CBLOCK 64
#define SHA_LBLOCK 16
#define SHA_H0 val[0]
#define SHA_H1 val[1]
#define SHA_H2 val[2]
#define SHA_H3 val[3]
#define SHA_H4 val[4]
#endif

#ifndef SHA_DIGEST_LENGTH
#define SHA_DIGEST_LENGTH 20
#endif

#endif
