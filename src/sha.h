#ifndef JOHN_SHA_H
#define JOHN_SHA_H

#include "aligned.h"
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
#endif
