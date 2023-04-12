#ifndef JOHN_SHA_H
#define JOHN_SHA_H

#include <stdint.h>

#if AC_BUILT
#include "autoconfig.h"
#endif

#if HAVE_LIBCRYPTO
#include <openssl/opensslv.h>
#include <openssl/sha.h>

/* For the abuse in pbkdf2_hmac_sha1.h and mscash2_fmt_plug.c */
#define SHA_H0 h0
#define SHA_H1 h1
#define SHA_H2 h2
#define SHA_H3 h3
#define SHA_H4 h4

#else /* ! HAVE_LIBCRYPTO */

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

#endif /* HAVE_LIBCRYPTO */

#ifndef SHA_DIGEST_LENGTH
#define SHA_DIGEST_LENGTH 20
#endif

extern void sha1_reverse(uint32_t *hash);
extern void sha1_unreverse(uint32_t *hash);
extern void sha1_reverse3(uint32_t *hash);
extern void sha1_unreverse3(uint32_t *hash);

#endif /* JOHN_SHA_H */
