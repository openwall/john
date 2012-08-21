/* MD5 OpenCL kernel based on Solar Designer's MD5 algorithm implementation at:
 * http://openwall.info/wiki/people/solar/software/public-domain-source-code/md5
 *
 * This software is Copyright (c) 2010, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 *
 * Useful References:
 * 1. CUDA MD5 Hashing Experiments, http://majuric.org/software/cudamd5/
 * 2. oclcrack, http://sghctoma.extra.hu/index.php?p=entry&id=11
 * 3. http://people.eku.edu/styere/Encrypt/JS-MD5.html
 * 4. http://en.wikipedia.org/wiki/MD5#Algorithm */

#pragma OPENCL EXTENSION cl_khr_byte_addressable_store : disable

/* Macros for reading/writing chars from int32's (from rar_kernel.cl) */
#define GETCHAR(buf, index) (((uchar*)(buf))[(index)])
#define PUTCHAR(buf, index, val) (buf)[(index)>>2] = ((buf)[(index)>>2] & ~(0xffU << (((index) & 3) << 3))) + ((val) << (((index) & 3) << 3))

/* The basic MD5 functions */
#define F(x, y, z)			((z) ^ ((x) & ((y) ^ (z))))
#define G(x, y, z)			((y) ^ ((z) & ((x) ^ (y))))
#define H(x, y, z)			((x) ^ (y) ^ (z))
#define I(x, y, z)			((y) ^ ((x) | ~(z)))

/* The MD5 transformation for all four rounds. */
#define STEP(f, a, b, c, d, x, t, s) \
    (a) += f((b), (c), (d)) + (x) + (t); \
    (a) = (((a) << (s)) | (((a) & 0xffffffff) >> (32 - (s)))); \
    (a) += (b);

#define GET(i) (key[(i)])

/* some constants used below magically appear after make */
//#define KEY_LENGTH (MD5_PLAINTEXT_LENGTH + 1)

/* OpenCL kernel entry point. Copy KEY_LENGTH bytes key to be hashed from
 * global to local (thread) memory. Break the key into 16 32-bit (uint)
 * words. MD5 hash of a key is 128 bit (uint4). */
__kernel void md5(__global uint *data_info, __global const uint * keys, __global uint * hashes)
{
	int id = get_global_id(0);
	uint key[16] = { 0 };
	uint i;
	uint num_keys = data_info[1];
	uint KEY_LENGTH = data_info[0] + 1;

	int base = id * (KEY_LENGTH / 4);

	for (i = 0; i != (KEY_LENGTH / 4) && keys[base + i]; i++)
		key[i] = keys[base + i];

	/* padding code (borrowed from MD5_eq.c) */
	char *p = (char *) key;
	for (i = 0; i != 64 && p[i]; i++);
            
	//p[i] = 0x80;
	//p[56] = i << 3;
	//p[57] = i >> 5;

        PUTCHAR(key, i, 0x80);
        PUTCHAR(key, 56, i << 3);
        PUTCHAR(key, 57, i >> 5);

	uint a, b, c, d;
	a = 0x67452301;
	b = 0xefcdab89;
	c = 0x98badcfe;
	d = 0x10325476;

	/* Round 1 */
	STEP(F, a, b, c, d, GET(0), 0xd76aa478, 7)
	STEP(F, d, a, b, c, GET(1), 0xe8c7b756, 12)
	STEP(F, c, d, a, b, GET(2), 0x242070db, 17)
	STEP(F, b, c, d, a, GET(3), 0xc1bdceee, 22)
	STEP(F, a, b, c, d, GET(4), 0xf57c0faf, 7)
	STEP(F, d, a, b, c, GET(5), 0x4787c62a, 12)
	STEP(F, c, d, a, b, GET(6), 0xa8304613, 17)
	STEP(F, b, c, d, a, GET(7), 0xfd469501, 22)
	STEP(F, a, b, c, d, GET(8), 0x698098d8, 7)
	STEP(F, d, a, b, c, GET(9), 0x8b44f7af, 12)
	STEP(F, c, d, a, b, GET(10), 0xffff5bb1, 17)
	STEP(F, b, c, d, a, GET(11), 0x895cd7be, 22)
	STEP(F, a, b, c, d, GET(12), 0x6b901122, 7)
	STEP(F, d, a, b, c, GET(13), 0xfd987193, 12)
	STEP(F, c, d, a, b, GET(14), 0xa679438e, 17)
	STEP(F, b, c, d, a, GET(15), 0x49b40821, 22)

	/* Round 2 */
	STEP(G, a, b, c, d, GET(1), 0xf61e2562, 5)
	STEP(G, d, a, b, c, GET(6), 0xc040b340, 9)
	STEP(G, c, d, a, b, GET(11), 0x265e5a51, 14)
	STEP(G, b, c, d, a, GET(0), 0xe9b6c7aa, 20)
	STEP(G, a, b, c, d, GET(5), 0xd62f105d, 5)
	STEP(G, d, a, b, c, GET(10), 0x02441453, 9)
	STEP(G, c, d, a, b, GET(15), 0xd8a1e681, 14)
	STEP(G, b, c, d, a, GET(4), 0xe7d3fbc8, 20)
	STEP(G, a, b, c, d, GET(9), 0x21e1cde6, 5)
	STEP(G, d, a, b, c, GET(14), 0xc33707d6, 9)
	STEP(G, c, d, a, b, GET(3), 0xf4d50d87, 14)
	STEP(G, b, c, d, a, GET(8), 0x455a14ed, 20)
	STEP(G, a, b, c, d, GET(13), 0xa9e3e905, 5)
	STEP(G, d, a, b, c, GET(2), 0xfcefa3f8, 9)
	STEP(G, c, d, a, b, GET(7), 0x676f02d9, 14)
	STEP(G, b, c, d, a, GET(12), 0x8d2a4c8a, 20)

	/* Round 3 */
	STEP(H, a, b, c, d, GET(5), 0xfffa3942, 4)
	STEP(H, d, a, b, c, GET(8), 0x8771f681, 11)
	STEP(H, c, d, a, b, GET(11), 0x6d9d6122, 16)
	STEP(H, b, c, d, a, GET(14), 0xfde5380c, 23)
	STEP(H, a, b, c, d, GET(1), 0xa4beea44, 4)
	STEP(H, d, a, b, c, GET(4), 0x4bdecfa9, 11)
	STEP(H, c, d, a, b, GET(7), 0xf6bb4b60, 16)
	STEP(H, b, c, d, a, GET(10), 0xbebfbc70, 23)
	STEP(H, a, b, c, d, GET(13), 0x289b7ec6, 4)
	STEP(H, d, a, b, c, GET(0), 0xeaa127fa, 11)
	STEP(H, c, d, a, b, GET(3), 0xd4ef3085, 16)
	STEP(H, b, c, d, a, GET(6), 0x04881d05, 23)
	STEP(H, a, b, c, d, GET(9), 0xd9d4d039, 4)
	STEP(H, d, a, b, c, GET(12), 0xe6db99e5, 11)
	STEP(H, c, d, a, b, GET(15), 0x1fa27cf8, 16)
	STEP(H, b, c, d, a, GET(2), 0xc4ac5665, 23)

	/* Round 4 */
	STEP(I, a, b, c, d, GET(0), 0xf4292244, 6)
	STEP(I, d, a, b, c, GET(7), 0x432aff97, 10)
	STEP(I, c, d, a, b, GET(14), 0xab9423a7, 15)
	STEP(I, b, c, d, a, GET(5), 0xfc93a039, 21)
	STEP(I, a, b, c, d, GET(12), 0x655b59c3, 6)
	STEP(I, d, a, b, c, GET(3), 0x8f0ccc92, 10)
	STEP(I, c, d, a, b, GET(10), 0xffeff47d, 15)
	STEP(I, b, c, d, a, GET(1), 0x85845dd1, 21)
	STEP(I, a, b, c, d, GET(8), 0x6fa87e4f, 6)
	STEP(I, d, a, b, c, GET(15), 0xfe2ce6e0, 10)
	STEP(I, c, d, a, b, GET(6), 0xa3014314, 15)
	STEP(I, b, c, d, a, GET(13), 0x4e0811a1, 21)
	STEP(I, a, b, c, d, GET(4), 0xf7537e82, 6)
	STEP(I, d, a, b, c, GET(11), 0xbd3af235, 10)
	STEP(I, c, d, a, b, GET(2), 0x2ad7d2bb, 15)
	STEP(I, b, c, d, a, GET(9), 0xeb86d391, 21)

	/* The following hack allows only 1/4 of the hash data to be copied in crypt_all.
	 * This code doesn't seem to have any performance gains but has other benefits */
	hashes[id] = a + 0x67452301;
	hashes[1 * num_keys + id] = b + 0xefcdab89;
	hashes[2 * num_keys + id] = c + 0x98badcfe;
	hashes[3 * num_keys + id] = d + 0x10325476;
}
