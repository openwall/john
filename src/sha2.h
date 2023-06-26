/*
 * This software is
 * Copyright (c) 2012-2013 JimF,
 * Copyright (c) 2012-2023 magnum,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
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
#include <stdint.h>
#include "arch.h"
#include "aligned.h"

#if HAVE_LIBCRYPTO
#include <openssl/opensslv.h>
#elif !defined(FORCE_GENERIC_SHA2)
#define FORCE_GENERIC_SHA2 1
#endif

#include "openssl_local_overrides.h"

#if (AC_BUILT && HAVE_SHA256 && !FORCE_GENERIC_SHA2) ||	  \
    (!AC_BUILT && OPENSSL_VERSION_NUMBER >= 0x00908000 && !FORCE_GENERIC_SHA2)

#include <openssl/sha.h>
#undef GENERIC_SHA2

#else	// OPENSSL_VERSION_NUMBER ! >= 0x00908000

#if HAVE_LIBCRYPTO
#include <openssl/sha.h>
#endif
#include "jtr_sha2.h"
#define GENERIC_SHA2

#endif	// OPENSSL_VERSION_NUMBER ! >= 0x00908000

#ifndef SHA224_DIGEST_LENGTH
#define SHA224_DIGEST_LENGTH 28
#endif

#ifndef SHA256_DIGEST_LENGTH
#define SHA256_DIGEST_LENGTH 32
#endif

#ifndef SHA384_DIGEST_LENGTH
#define SHA384_DIGEST_LENGTH 48
#endif

#ifndef SHA512_DIGEST_LENGTH
#define SHA512_DIGEST_LENGTH 64
#endif

extern void sha224_reverse(uint32_t *hash);
extern void sha224_unreverse(uint32_t *hash);
extern void sha256_reverse(uint32_t *hash);
extern void sha384_reverse(uint64_t *hash);
extern void sha384_unreverse(uint64_t *hash);
extern void sha512_reverse(uint64_t *hash);

#endif /* _JOHN_SHA2_h */
