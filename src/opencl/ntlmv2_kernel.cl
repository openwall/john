/*
 * NTLMv2
 * MD4 + 2 x HMAC-MD5, with Unicode conversion on GPU
 *
 * Copyright (c) 2012, magnum
 * This software is hereby released to the general public under
 * the following terms: Redistribution and use in source and binary
 * forms, with or without modification, are permitted.
 */

#include "opencl_device_info.h"
#include "opencl_unicode.h"

/* Do not support full UTF-16 with surrogate pairs */
//#define UCS_2

#define CONCAT(TYPE,WIDTH)	TYPE ## WIDTH
#define VECTOR(x, y)		CONCAT(x, y)

/* host code may pass -DV_WIDTH=2 or some other width */
#if defined(V_WIDTH) && V_WIDTH > 1
#define MAYBE_VECTOR_UINT	VECTOR(uint, V_WIDTH)
#else
#define MAYBE_VECTOR_UINT	uint
#define SCALAR
#endif

#if gpu_amd(DEVICE_INFO)
#define USE_BITSELECT
#endif

/* Workaround for problem seen with 9600GT */
#if gpu_nvidia(DEVICE_INFO)
#define MAYBE_CONSTANT const __global
#else
#define MAYBE_CONSTANT	__constant
#endif

#if 0 // gpu_nvidia(DEVICE_INFO) || amd_gcn(DEVICE_INFO)
inline uint SWAP32(uint x)
{
	x = rotate(x, 16U);
	return ((x & 0x00FF00FF) << 8) + ((x >> 8) & 0x00FF00FF);
}
#else
#define SWAP32(a)	(as_uint(as_uchar4(a).wzyx))
#endif

#if no_byte_addressable(DEVICE_INFO)
#define PUTCHAR(buf, index, val) (buf)[(index)>>2] = ((buf)[(index)>>2] & ~(0xffU << (((index) & 3) << 3))) + ((val) << (((index) & 3) << 3))
#define PUTSHORT(buf, index, val) (buf)[(index)>>1] = ((buf)[(index)>>1] & ~(0xffffU << (((index) & 1) << 4))) + ((val) << (((index) & 1) << 4))
#define XORCHAR(buf, index, val) (buf)[(index)>>2] = ((buf)[(index)>>2]) ^ ((val) << (((index) & 3) << 3))
#else
#define PUTCHAR(buf, index, val) ((uchar*)(buf))[index] = (val)
#define PUTSHORT(buf, index, val) ((ushort*)(buf))[index] = (val)
#define XORCHAR(buf, index, val) ((uchar*)(buf))[index] ^= (val)
#endif

/* Functions common to MD4 and MD5 */
#ifdef USE_BITSELECT
#define F(x, y, z)	bitselect((z), (y), (x))
#else
#define F(x, y, z)	((z) ^ ((x) & ((y) ^ (z))))
#endif

#define H(x, y, z)	((x) ^ (y) ^ (z))


/* The basic MD4 functions */
#define MD4G(x, y, z)	(((x) & ((y) | (z))) | ((y) & (z)))


/* The MD4 transformation for all three rounds. */
#define MD4STEP(f, a, b, c, d, x, s)  \
	(a) += f((b), (c), (d)) + (x); \
	    (a) = rotate((a), (uint)(s))


/* Raw'n'lean MD4 with context in output buffer */
/* NOTE: This version thrashes the input block! */
#define	md4_block(block, output) { \
		a = output[0]; \
		b = output[1]; \
		c = output[2]; \
		d = output[3]; \
		MD4STEP(F, a, b, c, d, block[0], 3); \
		MD4STEP(F, d, a, b, c, block[1], 7); \
		MD4STEP(F, c, d, a, b, block[2], 11); \
		MD4STEP(F, b, c, d, a, block[3], 19); \
		MD4STEP(F, a, b, c, d, block[4], 3); \
		MD4STEP(F, d, a, b, c, block[5], 7); \
		MD4STEP(F, c, d, a, b, block[6], 11); \
		MD4STEP(F, b, c, d, a, block[7], 19); \
		MD4STEP(F, a, b, c, d, block[8], 3); \
		MD4STEP(F, d, a, b, c, block[9], 7); \
		MD4STEP(F, c, d, a, b, block[10], 11); \
		MD4STEP(F, b, c, d, a, block[11], 19); \
		MD4STEP(F, a, b, c, d, block[12], 3); \
		MD4STEP(F, d, a, b, c, block[13], 7); \
		MD4STEP(F, c, d, a, b, block[14], 11); \
		MD4STEP(F, b, c, d, a, block[15], 19); \
		MD4STEP(MD4G, a, b, c, d, block[0] + 0x5a827999, 3); \
		MD4STEP(MD4G, d, a, b, c, block[4] + 0x5a827999, 5); \
		MD4STEP(MD4G, c, d, a, b, block[8] + 0x5a827999, 9); \
		MD4STEP(MD4G, b, c, d, a, block[12] + 0x5a827999, 13); \
		MD4STEP(MD4G, a, b, c, d, block[1] + 0x5a827999, 3); \
		MD4STEP(MD4G, d, a, b, c, block[5] + 0x5a827999, 5); \
		MD4STEP(MD4G, c, d, a, b, block[9] + 0x5a827999, 9); \
		MD4STEP(MD4G, b, c, d, a, block[13] + 0x5a827999, 13); \
		MD4STEP(MD4G, a, b, c, d, block[2] + 0x5a827999, 3); \
		MD4STEP(MD4G, d, a, b, c, block[6] + 0x5a827999, 5); \
		MD4STEP(MD4G, c, d, a, b, block[10] + 0x5a827999, 9); \
		MD4STEP(MD4G, b, c, d, a, block[14] + 0x5a827999, 13); \
		MD4STEP(MD4G, a, b, c, d, block[3] + 0x5a827999, 3); \
		MD4STEP(MD4G, d, a, b, c, block[7] + 0x5a827999, 5); \
		MD4STEP(MD4G, c, d, a, b, block[11] + 0x5a827999, 9); \
		MD4STEP(MD4G, b, c, d, a, block[15] + 0x5a827999, 13); \
		MD4STEP(H, a, b, c, d, block[0] + 0x6ed9eba1, 3); \
		MD4STEP(H, d, a, b, c, block[8] + 0x6ed9eba1, 9); \
		MD4STEP(H, c, d, a, b, block[4] + 0x6ed9eba1, 11); \
		MD4STEP(H, b, c, d, a, block[12] + 0x6ed9eba1, 15); \
		MD4STEP(H, a, b, c, d, block[2] + 0x6ed9eba1, 3); \
		MD4STEP(H, d, a, b, c, block[10] + 0x6ed9eba1, 9); \
		MD4STEP(H, c, d, a, b, block[6] + 0x6ed9eba1, 11); \
		MD4STEP(H, b, c, d, a, block[14] + 0x6ed9eba1, 15); \
		MD4STEP(H, a, b, c, d, block[1] + 0x6ed9eba1, 3); \
		MD4STEP(H, d, a, b, c, block[9] + 0x6ed9eba1, 9); \
		MD4STEP(H, c, d, a, b, block[5] + 0x6ed9eba1, 11); \
		MD4STEP(H, b, c, d, a, block[13] + 0x6ed9eba1, 15); \
		MD4STEP(H, a, b, c, d, block[3] + 0x6ed9eba1, 3); \
		MD4STEP(H, d, a, b, c, block[11] + 0x6ed9eba1, 9); \
		MD4STEP(H, c, d, a, b, block[7] + 0x6ed9eba1, 11); \
		MD4STEP(H, b, c, d, a, block[15] + 0x6ed9eba1, 15); \
		output[0] += a; \
		output[1] += b; \
		output[2] += c; \
		output[3] += d; \
	}

/* The basic MD5 functions */
/* F and H are the same as for MD4, above */
#ifdef USE_BITSELECT
#define G(x, y, z)	bitselect((y), (x), (z))
#else
#define G(x, y, z)	((y) ^ ((z) & ((x) ^ (y))))
#endif

#define I(x, y, z)	((y) ^ ((x) | ~(z)))


/* The MD5 transformation for all four rounds. */
#define STEP(f, a, b, c, d, x, t, s)	  \
	(a) += f((b), (c), (d)) + (x) + (t); \
	    (a) = rotate((a), (uint)(s)); \
	    (a) += (b)


/* Raw'n'lean MD5 with context in output buffer */
/* NOTE: This version thrashes the input block! */
#define md5_block(block, output)  \
	{ \
		a = output[0]; \
		b = output[1]; \
		c = output[2]; \
		d = output[3]; \
		STEP(F, a, b, c, d, block[0], 0xd76aa478, 7); \
		STEP(F, d, a, b, c, block[1], 0xe8c7b756, 12); \
		STEP(F, c, d, a, b, block[2], 0x242070db, 17); \
		STEP(F, b, c, d, a, block[3], 0xc1bdceee, 22); \
		STEP(F, a, b, c, d, block[4], 0xf57c0faf, 7); \
		STEP(F, d, a, b, c, block[5], 0x4787c62a, 12); \
		STEP(F, c, d, a, b, block[6], 0xa8304613, 17); \
		STEP(F, b, c, d, a, block[7], 0xfd469501, 22); \
		STEP(F, a, b, c, d, block[8], 0x698098d8, 7); \
		STEP(F, d, a, b, c, block[9], 0x8b44f7af, 12); \
		STEP(F, c, d, a, b, block[10], 0xffff5bb1, 17); \
		STEP(F, b, c, d, a, block[11], 0x895cd7be, 22); \
		STEP(F, a, b, c, d, block[12], 0x6b901122, 7); \
		STEP(F, d, a, b, c, block[13], 0xfd987193, 12); \
		STEP(F, c, d, a, b, block[14], 0xa679438e, 17); \
		STEP(F, b, c, d, a, block[15], 0x49b40821, 22); \
		STEP(G, a, b, c, d, block[1], 0xf61e2562, 5); \
		STEP(G, d, a, b, c, block[6], 0xc040b340, 9); \
		STEP(G, c, d, a, b, block[11], 0x265e5a51, 14); \
		STEP(G, b, c, d, a, block[0], 0xe9b6c7aa, 20); \
		STEP(G, a, b, c, d, block[5], 0xd62f105d, 5); \
		STEP(G, d, a, b, c, block[10], 0x02441453, 9); \
		STEP(G, c, d, a, b, block[15], 0xd8a1e681, 14); \
		STEP(G, b, c, d, a, block[4], 0xe7d3fbc8, 20); \
		STEP(G, a, b, c, d, block[9], 0x21e1cde6, 5); \
		STEP(G, d, a, b, c, block[14], 0xc33707d6, 9); \
		STEP(G, c, d, a, b, block[3], 0xf4d50d87, 14); \
		STEP(G, b, c, d, a, block[8], 0x455a14ed, 20); \
		STEP(G, a, b, c, d, block[13], 0xa9e3e905, 5); \
		STEP(G, d, a, b, c, block[2], 0xfcefa3f8, 9); \
		STEP(G, c, d, a, b, block[7], 0x676f02d9, 14); \
		STEP(G, b, c, d, a, block[12], 0x8d2a4c8a, 20); \
		STEP(H, a, b, c, d, block[5], 0xfffa3942, 4); \
		STEP(H, d, a, b, c, block[8], 0x8771f681, 11); \
		STEP(H, c, d, a, b, block[11], 0x6d9d6122, 16); \
		STEP(H, b, c, d, a, block[14], 0xfde5380c, 23); \
		STEP(H, a, b, c, d, block[1], 0xa4beea44, 4); \
		STEP(H, d, a, b, c, block[4], 0x4bdecfa9, 11); \
		STEP(H, c, d, a, b, block[7], 0xf6bb4b60, 16); \
		STEP(H, b, c, d, a, block[10], 0xbebfbc70, 23); \
		STEP(H, a, b, c, d, block[13], 0x289b7ec6, 4); \
		STEP(H, d, a, b, c, block[0], 0xeaa127fa, 11); \
		STEP(H, c, d, a, b, block[3], 0xd4ef3085, 16); \
		STEP(H, b, c, d, a, block[6], 0x04881d05, 23); \
		STEP(H, a, b, c, d, block[9], 0xd9d4d039, 4); \
		STEP(H, d, a, b, c, block[12], 0xe6db99e5, 11); \
		STEP(H, c, d, a, b, block[15], 0x1fa27cf8, 16); \
		STEP(H, b, c, d, a, block[2], 0xc4ac5665, 23); \
		STEP(I, a, b, c, d, block[0], 0xf4292244, 6); \
		STEP(I, d, a, b, c, block[7], 0x432aff97, 10); \
		STEP(I, c, d, a, b, block[14], 0xab9423a7, 15); \
		STEP(I, b, c, d, a, block[5], 0xfc93a039, 21); \
		STEP(I, a, b, c, d, block[12], 0x655b59c3, 6); \
		STEP(I, d, a, b, c, block[3], 0x8f0ccc92, 10); \
		STEP(I, c, d, a, b, block[10], 0xffeff47d, 15); \
		STEP(I, b, c, d, a, block[1], 0x85845dd1, 21); \
		STEP(I, a, b, c, d, block[8], 0x6fa87e4f, 6); \
		STEP(I, d, a, b, c, block[15], 0xfe2ce6e0, 10); \
		STEP(I, c, d, a, b, block[6], 0xa3014314, 15); \
		STEP(I, b, c, d, a, block[13], 0x4e0811a1, 21); \
		STEP(I, a, b, c, d, block[4], 0xf7537e82, 6); \
		STEP(I, d, a, b, c, block[11], 0xbd3af235, 10); \
		STEP(I, c, d, a, b, block[2], 0x2ad7d2bb, 15); \
		STEP(I, b, c, d, a, block[9], 0xeb86d391, 21); \
		output[0] += a; \
		output[1] += b; \
		output[2] += c; \
		output[3] += d; \
	}


#define md5_init(output) {	  \
	output[0] = 0x67452301; \
	output[1] = 0xefcdab89; \
	output[2] = 0x98badcfe; \
	output[3] = 0x10325476; \
	}

#define md4_init(output)	md5_init(output)

#define dump_stuff_msg(msg, x, size) {	  \
		uint ii; \
		printf("%s : ", msg); \
		for (ii = 0; ii < (size)/4; ii++) \
			printf("%08x ", SWAP32(x[ii])); \
		printf("\n"); \
	}

#define VEC_IN(INPUT, OUTPUT, INDEX, LEN)	  \
	OUTPUT[(gid / V_WIDTH) * (LEN) * V_WIDTH + (gid % V_WIDTH) + (INDEX) * V_WIDTH] = INPUT[(INDEX)]

#ifdef UTF_8

__kernel void ntlmv2_nthash(const __global uchar *source,
                            __global const uint *index,
                            __global uint *nthash)
{
	uint i;
	uint gid = get_global_id(0);
	uint block[16] = { 0 };
	uint a, b, c, d;
	uint output[4];
	uint base = index[gid];
	const __global UTF8 *sourceEnd;
	UTF16 *target = (UTF16*)block;
	UTF16 *targetStart = target;
	const UTF16 *targetEnd = &target[PLAINTEXT_LENGTH];
	UTF32 ch;
	uint extraBytesToRead;

	sourceEnd = source + index[gid + 1];
	source += base;

	/* Input buffer is UTF-8 without zero-termination */
	while (source < sourceEnd) {
		if (*source < 0xC0) {
			*target++ = (UTF16)*source++;
			if (*source == 0 || target >= targetEnd) {
				break;
			}
			continue;
		}
		ch = *source;
		// This point must not be reached with *source < 0xC0
		extraBytesToRead =
			opt_trailingBytesUTF8[ch & 0x3f];
		if (source + extraBytesToRead >= sourceEnd) {
			break;
		}
		switch (extraBytesToRead) {
		case 3:
			ch <<= 6;
			ch += *++source;
		case 2:
			ch <<= 6;
			ch += *++source;
		case 1:
			ch <<= 6;
			ch += *++source;
			++source;
			break;
		default:
			*target = 0x80;
			break; // from switch
		}
		if (*target == 0x80)
			break; // from while
		ch -= offsetsFromUTF8[extraBytesToRead];
#ifdef UCS_2
		/* UCS-2 only */
		*target++ = (UTF16)ch;
#else
		/* full UTF-16 with surrogate pairs */
		if (ch <= UNI_MAX_BMP) {  /* Target is a character <= 0xFFFF */
			*target++ = (UTF16)ch;
		} else {  /* target is a character in range 0xFFFF - 0x10FFFF. */
			if (target + 1 >= targetEnd)
				break;
			ch -= halfBase;
			*target++ = (UTF16)((ch >> halfShift) + UNI_SUR_HIGH_START);
			*target++ = (UTF16)((ch & halfMask) + UNI_SUR_LOW_START);
		}
#endif
		if (*source == 0 || target >= targetEnd)
			break;
	}
	*target = 0x80;	// Terminate

	block[14] = (uint)(target - targetStart) << 4;

	/* Initial hash of password */
	md4_init(output);
	md4_block(block, output);

	for (i = 0; i < 4; i++)
		VEC_IN(output, nthash, i, 4);
}

#elif !defined(ISO_8859_1) && !defined(ASCII)

__kernel void ntlmv2_nthash(const __global uchar *password,
                            __global const uint *index,
                            __global uint *nthash)
{
	uint i;
	uint gid = get_global_id(0);
	uint block[16] = { 0 };
	uint a, b, c, d;
	uint output[4];
	uint base = index[gid];
	uint len = index[gid + 1] - base;

	password += base;

	/* Work-around for self-tests not always calling set_key() like IRL */
	len = (len > PLAINTEXT_LENGTH) ? 0 : len;

	/* Input buffer is in a 'codepage' encoding, without zero-termination */
	for (i = 0; i < len; i++)
		PUTSHORT(block, i, (password[i] < 0x80) ?
		        password[i] : cp[password[i] & 0x7f]);
	PUTCHAR(block, 2 * i, 0x80);
	block[14] = i << 4;

	/* Initial hash of password */
	md4_init(output);
	md4_block(block, output);

	for (i = 0; i < 4; i++)
		VEC_IN(output, nthash, i, 4);
}

#else

__kernel void ntlmv2_nthash(const __global uchar *password,
                            __global const uint *index,
                            __global uint *nthash)
{
	uint i;
	uint gid = get_global_id(0);
	uint block[16] = { 0 };
	uint a, b, c, d;
	uint output[4];
	uint base = index[gid];
	uint len = index[gid + 1] - base;

	password += base;

	/* Work-around for self-tests not always calling set_key() like IRL */
	len = (len > PLAINTEXT_LENGTH) ? 0 : len;

	/* Input buffer is in ISO-8859-1 encoding, without zero-termination.
	   we can just type-cast this to UTF16 */
	for (i = 0; i < len; i++)
		PUTCHAR(block, 2 * i, password[i]);
	PUTCHAR(block, 2 * i, 0x80);
	block[14] = i << 4;

	/* Initial hash of password */
	md4_init(output);
	md4_block(block, output);

	for (i = 0; i < 4; i++)
		VEC_IN(output, nthash, i, 4);
}

#endif /* encodings */

__kernel
__attribute__((vec_type_hint(MAYBE_VECTOR_UINT)))
void ntlmv2_final(const __global MAYBE_VECTOR_UINT *nthash, MAYBE_CONSTANT uint *challenge, __global uint *result)
{
	uint i;
	uint gid = get_global_id(0);
	uint gws = get_global_size(0);
	MAYBE_VECTOR_UINT block[16];
	MAYBE_VECTOR_UINT output[4], hash[4];
	MAYBE_VECTOR_UINT a, b, c, d;
	uint challenge_size;

	/* 1st HMAC */
	md5_init(output);

	for (i = 0; i < 4; i++)
		block[i] = 0x36363636 ^ nthash[gid * 4 + i];
	for (i = 4; i < 16; i++)
		block[i] = 0x36363636;
	md5_block(block, output); /* md5_update(ipad, 64) */

	/* challenge == identity[32].len,server_chal.client_chal[len] */
	/* Salt buffer is prepared with 0x80, zero-padding and length,
	 * it can be one or two blocks */
	for (i = 0; i < 16; i++)
		block[i] = *challenge++;
	md5_block(block, output); /* md5_update(salt, saltlen), md5_final() */

	if (challenge[14]) { /* salt longer than 27 characters */
		for (i = 0; i < 16; i++)
			block[i] = *challenge++;
		md5_block(block, output); /* alternate final */
	} else
		challenge += 16;

	for (i = 0; i < 4; i++)
		hash[i] = output[i];
	for (i = 0; i < 4; i++)
		block[i] = 0x5c5c5c5c ^ nthash[gid * 4 + i];

	md5_init(output);
	for (i = 4; i < 16; i++)
		block[i] = 0x5c5c5c5c;
	md5_block(block, output); /* md5_update(opad, 64) */

	for (i = 0; i < 4; i++)
		block[i] = hash[i];
	block[4] = 0x80;
	for (i = 5; i < 14; i++)
		block[i] = 0;
	block[14] = (64 + 16) << 3;
	block[15] = 0;
	md5_block(block, output); /* md5_update(hash, 16), md5_final() */

	/* 2nd HMAC */
	for (i = 0; i < 4; i++)
		hash[i] = output[i];
	for (i = 0; i < 4; i++)
		block[i] = 0x36363636 ^ output[i];

	md5_init(output);
	for (i = 4; i < 16; i++)
		block[i] = 0x36363636;
	md5_block(block, output); /* md5_update(ipad, 64) */

	/* Challenge:  blocks (of MD5),
	 * Server Challenge + Client Challenge (Blob) +
	 * 0x80, null padded and len set in get_salt() */
	challenge_size = *challenge++;

	/* At least this will not diverge */
	while (challenge_size--) {
		for (i = 0; i < 16; i++)
			block[i] = *challenge++;
		md5_block(block, output); /* md5_update(challenge, len), md5_final() */
	}

	for (i = 0; i < 4; i++)
		block[i] = 0x5c5c5c5c ^ hash[i];
	for (i = 0; i < 4; i++)
		hash[i] = output[i];

	md5_init(output);
	for (i = 4; i < 16; i++)
		block[i] = 0x5c5c5c5c;
	md5_block(block, output); /* md5_update(opad, 64) */

	for (i = 0; i < 4; i++)
		block[i] = hash[i];
	block[4] = 0x80;
	for (i = 5; i < 14; i++)
		block[i] = 0;
	block[14] = (64 + 16) << 3;
	block[15] = 0;
	md5_block(block, output); /* md5_update(hash, 16), md5_final() */

	for (i = 0; i < 4; i++)
#ifdef SCALAR
		result[i * gws + gid] = output[i];
#else

#define VEC_OUT(NUM)	  \
	result[i * gws * V_WIDTH + gid * V_WIDTH + 0x##NUM] = output[i].s##NUM

	{

		VEC_OUT(0);
		VEC_OUT(1);
#if V_WIDTH > 2
		VEC_OUT(2);
#if V_WIDTH > 3
		VEC_OUT(3);
#if V_WIDTH > 4
		VEC_OUT(4);
		VEC_OUT(5);
		VEC_OUT(6);
		VEC_OUT(7);
#if V_WIDTH > 8
		VEC_OUT(8);
		VEC_OUT(9);
		VEC_OUT(a);
		VEC_OUT(b);
		VEC_OUT(c);
		VEC_OUT(d);
		VEC_OUT(e);
		VEC_OUT(f);
#endif
#endif
#endif
#endif
	}
#endif
}
