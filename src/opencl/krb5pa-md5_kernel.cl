/*
 * Kerberos 5 AS_REQ Pre-Auth etype 23
 * MD4 + HMAC-MD5 + RC4, with Unicode conversion on GPU
 *
 * Copyright (c) 2013, magnum
 * This software is hereby released to the general public under
 * the following terms: Redistribution and use in source and binary
 * forms, with or without modification, are permitted.
 */

#include "opencl_device_info.h"
#include "opencl_unicode.h"

/* Do not support full UTF-16 with surrogate pairs */
//#define UCS_2

#if gpu_amd(DEVICE_INFO)
#define USE_BITSELECT
#endif

/* Workaround for problem seen with 9600GT */
#if gpu_nvidia(DEVICE_INFO)
#define MAYBE_CONSTANT const __global
#else
#define MAYBE_CONSTANT __constant
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

#if !no_byte_addressable(DEVICE_INFO)
__constant uint rc4_iv[64] = { 0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
                                 0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
                                 0x23222120, 0x27262524, 0x2b2a2928, 0x2f2e2d2c,
                                 0x33323130, 0x37363534, 0x3b3a3938, 0x3f3e3d3c,
                                 0x43424140, 0x47464544, 0x4b4a4948, 0x4f4e4d4c,
                                 0x53525150, 0x57565554, 0x5b5a5958, 0x5f5e5d5c,
                                 0x63626160, 0x67666564, 0x6b6a6968, 0x6f6e6d6c,
                                 0x73727170, 0x77767574, 0x7b7a7978, 0x7f7e7d7c,
                                 0x83828180, 0x87868584, 0x8b8a8988, 0x8f8e8d8c,
                                 0x93929190, 0x97969594, 0x9b9a9998, 0x9f9e9d9c,
                                 0xa3a2a1a0, 0xa7a6a5a4, 0xabaaa9a8, 0xafaeadac,
                                 0xb3b2b1b0, 0xb7b6b5b4, 0xbbbab9b8, 0xbfbebdbc,
                                 0xc3c2c1c0, 0xc7c6c5c4, 0xcbcac9c8, 0xcfcecdcc,
                                 0xd3d2d1d0, 0xd7d6d5d4, 0xdbdad9d8, 0xdfdedddc,
                                 0xe3e2e1e0, 0xe7e6e5e4, 0xebeae9e8, 0xefeeedec,
                                 0xf3f2f1f0, 0xf7f6f5f4, 0xfbfaf9f8, 0xfffefdfc
};
#endif

#if 0
#define swap_byte(a, b) (((a) ^= (b)), ((b) ^= (a)), ((a) ^= (b)))
#else
#define swap_byte(a, b) {	  \
		uchar tmp = a; \
		a = b; \
		b = tmp; \
	}
#endif

#define swap_state(n) {	  \
		index2 = (key[index1] + state[(n)] + index2) & 255; \
		swap_byte(state[(n)], state[index2]); \
		index1 = (index1 + 1) & 15 /* (& 15 == % length) */; \
	}

/* One-shot rc4 with fixed key length and decrypt length of 16 */
inline void rc4(const uint *key_w, MAYBE_CONSTANT uint *in,
                __global uint *out /*, uint length */)
{
	const uchar *key = (uchar*)key_w;
	uint x;
	uint y = 0;
	uint index1 = 0;
	uint index2 = 0;
#if no_byte_addressable(DEVICE_INFO)
	uint state[256];

	/* RC4_init() */
	for (x = 0; x < 256; x++)
		state[x] = x;
#else
	uint state_w[64];
	uchar *state = (uchar*)state_w;

	/* RC4_init() */
	for (x = 0; x < 64; x++)
		state_w[x] = rc4_iv[x];
#endif
#if 0
	/* RC4_set_key() */
	for (x = 0; x < 256; x++)
		swap_state(x);
#else
	/* RC4_set_key() */
	/* Unrolled hard-coded for key length 16 */
	for (x = 0; x < 256; x++) {
		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1 = 0;
	}
#endif

	/* RC4() */
	/* Unrolled for avoiding byte-addressed stores */
	for (x = 1; x <= 16 /* length */; x++) {
		uint xor_word;

		y = (state[x] + y) & 255;
		swap_byte(state[x], state[y]);
		xor_word = state[(state[x++] + state[y]) & 255];

		y = (state[x] + y) & 255;
		swap_byte(state[x], state[y]);
		xor_word |= state[(state[x++] + state[y]) & 255] << 8;

		y = (state[x] + y) & 255;
		swap_byte(state[x], state[y]);
		xor_word |= state[(state[x++] + state[y]) & 255] << 16;

		y = (state[x] + y) & 255;
		swap_byte(state[x], state[y]);
		xor_word |= state[(state[x] + state[y]) & 255] << 24;

		*out++ = *in++ ^ xor_word;
	}
}

#define dump_stuff_msg(msg, x, size) {	  \
		uint ii; \
		printf("%s : ", msg); \
		for (ii = 0; ii < (size)/4; ii++) \
			printf("%08x ", SWAP32(x[ii])); \
		printf("\n"); \
	}

#ifdef UTF_8

__kernel void krb5pa_md5_nthash(const __global uchar *source,
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
		nthash[gid * 4 + i] = output[i];
}

#elif !defined(ISO_8859_1) && !defined(ASCII)

__kernel void krb5pa_md5_nthash(const __global uchar *password,
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
		nthash[gid * 4 + i] = output[i];
}

#else

__kernel void krb5pa_md5_nthash(const __global uchar *password,
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
		nthash[gid * 4 + i] = output[i];
}

#endif /* encodings */

__kernel void krb5pa_md5_final(const __global uint *nthash,
                               MAYBE_CONSTANT uint *salts,
                               __global uint *result)
{
	uint i;
	uint gid = get_global_id(0);
	uint block[16];
	uint output[4], hash[4];
	uint a, b, c, d;

	/* 1st HMAC */
	md5_init(output);

	for (i = 0; i < 4; i++)
		block[i] = 0x36363636 ^ nthash[gid * 4 + i];
	for (i = 4; i < 16; i++)
		block[i] = 0x36363636;
	md5_block(block, output); /* md5_update(ipad, 64) */

	block[0] = 0x01;    /* little endian "one", 4 bytes */
	block[1] = 0x80;
	for (i = 2; i < 14; i++)
		block[i] = 0;
	block[14] = (64 + 4) << 3;
	block[15] = 0;
	md5_block(block, output); /* md5_update(one, 4), md5_final() */

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

	for (i = 0; i < 4; i++)
		block[i] = *salts++; /* checksum, 16 bytes */
	block[4] = 0x80;
	for (i = 5; i < 14; i++)
		block[i] = 0;
	block[14] = (64 + 16) << 3;
	block[15] = 0;
	md5_block(block, output); /* md5_update(cs, 16), md5_final() */

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

	/* output is our RC4 key. salts now point to encrypted timestamp. */
	rc4(output, salts, &result[gid * 4]);
}
