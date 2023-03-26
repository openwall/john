/*
 * This is an OpenSSL-compatible implementation of the RSA Data Security,
 * Inc. MD4 Message-Digest Algorithm (RFC 1320).
 *
 * Written by Solar Designer <solar at openwall.com> in 2001, and placed
 * in the public domain.  There's absolutely no warranty.
 *
 * This differs from Colin Plumb's older public domain implementation in
 * that no 32-bit integer data type is required, there's no compile-time
 * endianness configuration, and the function prototypes match OpenSSL's.
 * The primary goals are portability and ease of use.
 *
 * This implementation is meant to be fast, but not as fast as possible.
 * Some known optimizations are not included to reduce source code size
 * and avoid compile-time configuration.
 *
 * ... MD4_Final() has been modified in revision of this code found in the
 * JtR jumbo patch, dropping the memset() call.  You will likely want to undo
 * this change if you reuse the code for another purpose.  Or better yet,
 * download the original from:
 * http://openwall.info/wiki/people/solar/software/public-domain-source-code/md4
 */

#include "md4.h"

#if !HAVE_LIBCRYPTO
#include <string.h>

/*
 * The basic MD4 functions.
 *
 * F and G are optimized compared to their RFC 1320 definitions, with the
 * optimization for F borrowed from Colin Plumb's MD5 implementation.
 */
#define F(x, y, z)			((z) ^ ((x) & ((y) ^ (z))))
#if 0 /* Wei Dai's trick, but we let the compiler cache/reuse or not */
#define G(x, y, z)			(y ^ ((x ^ y) & (y ^ z)))
#elif 0
#define G(x, y, z)			((x & y) ^ (x & z) ^ (y & z))
#else
#define G(x, y, z)			(((x) & ((y) | (z))) | ((y) & (z)))
#endif
#define H(x, y, z)			(((x) ^ (y)) ^ (z))
#define H2(x, y, z)			((x) ^ ((y) ^ (z)))

/*
 * The MD4 transformation for all three rounds.
 */
#define STEP(f, a, b, c, d, x, s) \
	(a) += f((b), (c), (d)) + (x); \
	(a) = (((a) << (s)) | (((a) & 0xffffffff) >> (32 - (s))));

/*
 * SET reads 4 input bytes in little-endian byte order and stores them
 * in a properly aligned word in host byte order.
 *
 * The check for little-endian architectures that tolerate unaligned
 * memory accesses is just an optimization.  Nothing will break if it
 * doesn't work.
 */
#if ARCH_ALLOWS_UNALIGNED==1
#define SET(n) \
	(*(MD4_u32plus *)&ptr[(n) * 4])
#define GET(n) \
	SET(n)
#else
#define SET(n) \
	(ctx->block[(n)] = \
	(MD4_u32plus)ptr[(n) * 4] | \
	((MD4_u32plus)ptr[(n) * 4 + 1] << 8) | \
	((MD4_u32plus)ptr[(n) * 4 + 2] << 16) | \
	((MD4_u32plus)ptr[(n) * 4 + 3] << 24))
#define GET(n) \
	(ctx->block[(n)])
#endif

/*
 * This processes one or more 64-byte data blocks, but does NOT update
 * the bit counters.  There are no alignment requirements.
 */
static const void *body(MD4_CTX *ctx, const void *data, unsigned long size)
{
	unsigned const char *ptr;
	MD4_u32plus a, b, c, d;
	MD4_u32plus saved_a, saved_b, saved_c, saved_d;

	ptr = data;

	a = ctx->A;
	b = ctx->B;
	c = ctx->C;
	d = ctx->D;

	do {
		saved_a = a;
		saved_b = b;
		saved_c = c;
		saved_d = d;

/* Round 1 */
		STEP(F, a, b, c, d, SET(0), 3)
		STEP(F, d, a, b, c, SET(1), 7)
		STEP(F, c, d, a, b, SET(2), 11)
		STEP(F, b, c, d, a, SET(3), 19)
		STEP(F, a, b, c, d, SET(4), 3)
		STEP(F, d, a, b, c, SET(5), 7)
		STEP(F, c, d, a, b, SET(6), 11)
		STEP(F, b, c, d, a, SET(7), 19)
		STEP(F, a, b, c, d, SET(8), 3)
		STEP(F, d, a, b, c, SET(9), 7)
		STEP(F, c, d, a, b, SET(10), 11)
		STEP(F, b, c, d, a, SET(11), 19)
		STEP(F, a, b, c, d, SET(12), 3)
		STEP(F, d, a, b, c, SET(13), 7)
		STEP(F, c, d, a, b, SET(14), 11)
		STEP(F, b, c, d, a, SET(15), 19)

/* Round 2 */
		STEP(G, a, b, c, d, GET(0) + 0x5a827999, 3)
		STEP(G, d, a, b, c, GET(4) + 0x5a827999, 5)
		STEP(G, c, d, a, b, GET(8) + 0x5a827999, 9)
		STEP(G, b, c, d, a, GET(12) + 0x5a827999, 13)
		STEP(G, a, b, c, d, GET(1) + 0x5a827999, 3)
		STEP(G, d, a, b, c, GET(5) + 0x5a827999, 5)
		STEP(G, c, d, a, b, GET(9) + 0x5a827999, 9)
		STEP(G, b, c, d, a, GET(13) + 0x5a827999, 13)
		STEP(G, a, b, c, d, GET(2) + 0x5a827999, 3)
		STEP(G, d, a, b, c, GET(6) + 0x5a827999, 5)
		STEP(G, c, d, a, b, GET(10) + 0x5a827999, 9)
		STEP(G, b, c, d, a, GET(14) + 0x5a827999, 13)
		STEP(G, a, b, c, d, GET(3) + 0x5a827999, 3)
		STEP(G, d, a, b, c, GET(7) + 0x5a827999, 5)
		STEP(G, c, d, a, b, GET(11) + 0x5a827999, 9)
		STEP(G, b, c, d, a, GET(15) + 0x5a827999, 13)

/* Round 3 */
		STEP(H, a, b, c, d, GET(0) + 0x6ed9eba1, 3)
		STEP(H2, d, a, b, c, GET(8) + 0x6ed9eba1, 9)
		STEP(H, c, d, a, b, GET(4) + 0x6ed9eba1, 11)
		STEP(H2, b, c, d, a, GET(12) + 0x6ed9eba1, 15)
		STEP(H, a, b, c, d, GET(2) + 0x6ed9eba1, 3)
		STEP(H2, d, a, b, c, GET(10) + 0x6ed9eba1, 9)
		STEP(H, c, d, a, b, GET(6) + 0x6ed9eba1, 11)
		STEP(H2, b, c, d, a, GET(14) + 0x6ed9eba1, 15)
		STEP(H, a, b, c, d, GET(1) + 0x6ed9eba1, 3)
		STEP(H2, d, a, b, c, GET(9) + 0x6ed9eba1, 9)
		STEP(H, c, d, a, b, GET(5) + 0x6ed9eba1, 11)
		STEP(H2, b, c, d, a, GET(13) + 0x6ed9eba1, 15)
		STEP(H, a, b, c, d, GET(3) + 0x6ed9eba1, 3)
		STEP(H2, d, a, b, c, GET(11) + 0x6ed9eba1, 9)
		STEP(H, c, d, a, b, GET(7) + 0x6ed9eba1, 11)
		STEP(H2, b, c, d, a, GET(15) + 0x6ed9eba1, 15)

		a += saved_a;
		b += saved_b;
		c += saved_c;
		d += saved_d;

		ptr += 64;
	} while (size -= 64);

	ctx->A = a;
	ctx->B = b;
	ctx->C = c;
	ctx->D = d;

	return ptr;
}

void MD4_Init(MD4_CTX *ctx)
{
	ctx->A = 0x67452301;
	ctx->B = 0xefcdab89;
	ctx->C = 0x98badcfe;
	ctx->D = 0x10325476;

	ctx->lo = 0;
	ctx->hi = 0;
}

void MD4_Update(MD4_CTX *ctx, const void *data, unsigned long size)
{
	MD4_u32plus saved_lo;
	unsigned long used, free;

	saved_lo = ctx->lo;
	if ((ctx->lo = (saved_lo + size) & 0x1fffffff) < saved_lo)
		ctx->hi++;
	ctx->hi += size >> 29;

	used = saved_lo & 0x3f;

	if (used) {
		free = 64 - used;

		if (size < free) {
			memcpy(&ctx->buffer[used], data, size);
			return;
		}

		memcpy(&ctx->buffer[used], data, free);
		data = (unsigned char *)data + free;
		size -= free;
		body(ctx, ctx->buffer, 64);
	}

	if (size >= 64) {
		data = body(ctx, data, size & ~(unsigned long)0x3f);
		size &= 0x3f;
	}

	memcpy(ctx->buffer, data, size);
}

void MD4_Final(unsigned char *result, MD4_CTX *ctx)
{
	unsigned long used, free;

	used = ctx->lo & 0x3f;

	ctx->buffer[used++] = 0x80;

	free = 64 - used;

	if (free < 8) {
		memset(&ctx->buffer[used], 0, free);
		body(ctx, ctx->buffer, 64);
		used = 0;
		free = 64;
	}

	memset(&ctx->buffer[used], 0, free - 8);

	ctx->lo <<= 3;
	ctx->buffer[56] = ctx->lo;
	ctx->buffer[57] = ctx->lo >> 8;
	ctx->buffer[58] = ctx->lo >> 16;
	ctx->buffer[59] = ctx->lo >> 24;
	ctx->buffer[60] = ctx->hi;
	ctx->buffer[61] = ctx->hi >> 8;
	ctx->buffer[62] = ctx->hi >> 16;
	ctx->buffer[63] = ctx->hi >> 24;

	body(ctx, ctx->buffer, 64);

	result[0] = ctx->A;
	result[1] = ctx->A >> 8;
	result[2] = ctx->A >> 16;
	result[3] = ctx->A >> 24;
	result[4] = ctx->B;
	result[5] = ctx->B >> 8;
	result[6] = ctx->B >> 16;
	result[7] = ctx->B >> 24;
	result[8] = ctx->C;
	result[9] = ctx->C >> 8;
	result[10] = ctx->C >> 16;
	result[11] = ctx->C >> 24;
	result[12] = ctx->D;
	result[13] = ctx->D >> 8;
	result[14] = ctx->D >> 16;
	result[15] = ctx->D >> 24;

#if 0
	memset(ctx, 0, sizeof(*ctx));
#endif
}

#endif /* !HAVE_LIBCRYPTO */

#undef INIT_A
#undef INIT_B
#undef INIT_C
#undef INIT_D
#undef SQRT_3
#define INIT_A 0x67452301
#define INIT_B 0xefcdab89
#define INIT_C 0x98badcfe
#define INIT_D 0x10325476
#define SQRT_3 0x6ed9eba1

void md4_reverse(uint32_t *hash)
{
	hash[0] -= INIT_A;
	hash[1] -= INIT_B;
	hash[2] -= INIT_C;
	hash[3] -= INIT_D;
	hash[1]  = (hash[1] >> 15) | (hash[1] << 17);
	hash[1] -= SQRT_3 + (hash[2] ^ hash[3] ^ hash[0]);
	hash[1]  = (hash[1] >> 15) | (hash[1] << 17);
	hash[1] -= SQRT_3;
}

void md4_unreverse(uint32_t *hash)
{
	hash[1] += SQRT_3;
	hash[1]  = (hash[1] >> 17) | (hash[1] << 15);
	hash[1] += SQRT_3 + (hash[2] ^ hash[3] ^ hash[0]);
	hash[1]  = (hash[1] >> 17) | (hash[1] << 15);
	hash[3] += INIT_D;
	hash[2] += INIT_C;
	hash[1] += INIT_B;
	hash[0] += INIT_A;
}
