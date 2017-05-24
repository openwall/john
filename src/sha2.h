/*
 *
 * This software was written by JimF jfoug AT cox dot net in
 * 2012-2013. No copyright is claimed, and the software is hereby
 * placed in the public domain. In case this attempt to disclaim
 * copyright and place the software in the public domain is deemed
 * null and void, then the software is Copyright (c) 2012-2013 JimF
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

#ifndef _JOHN_SHA2_h
#define _JOHN_SHA2_h

#include <string.h>
#include "arch.h"
#include "aligned.h"
#include <openssl/opensslv.h>
#include "openssl_local_overrides.h"

#if (AC_BUILT && HAVE_SHA256 && !FORCE_GENERIC_SHA2) ||	  \
    (!AC_BUILT && OPENSSL_VERSION_NUMBER >= 0x00908000 && !FORCE_GENERIC_SHA2)

#if HAVE_COMMONCRYPTO || (!AC_BUILT &&	  \
	!defined(SIMD_COEF_32) && defined(__APPLE__) && defined(__MACH__) && \
	 defined(__MAC_OS_X_VERSION_MIN_REQUIRED) && \
	 __MAC_OS_X_VERSION_MIN_REQUIRED >= 1070)
/* Mitigate CommonCrypto name clashes */
#include "md4.h"
#include "md5.h"
#define COMMON_DIGEST_FOR_OPENSSL 1
#define SHA2_LIB "CommonCrypto"
#include <CommonCrypto/CommonDigest.h>
#define JTR_INC_COMMON_CRYPTO_SHA2
#else
#define SHA2_LIB "OpenSSL"
#include <openssl/sha.h>
#endif

#undef GENERIC_SHA2

#else	// OPENSSL_VERSION_NUMBER ! >= 0x00908000

#include <openssl/sha.h>
#include "jtr_sha2.h"

#define SHA2_LIB "generic"
#define GENERIC_SHA2


#endif

#endif /* _JOHN_SHA2_h */
