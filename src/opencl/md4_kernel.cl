/* MD4 OpenCL kernel based on Solar Designer's MD4 algorithm implementation at:
 * http://openwall.info/wiki/people/solar/software/public-domain-source-code/md4
 * This code is in public domain.
 *
 * This software is Copyright (c) 2010, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 *
 * Useful References:
 * 1  nt_opencl_kernel.c (written by Alain Espinosa <alainesp at gmail.com>)
 * 2. http://tools.ietf.org/html/rfc1320
 * 3. http://en.wikipedia.org/wiki/MD4  */

#pragma OPENCL EXTENSION cl_khr_byte_addressable_store : disable

/* Macros for reading/writing chars from int32's (from rar_kernel.cl) */
#define GETCHAR(buf, index) (((uchar*)(buf))[(index)])
#define PUTCHAR(buf, index, val) (buf)[(index)>>2] = ((buf)[(index)>>2] & ~(0xffU << (((index) & 3) << 3))) + ((val) << (((index) & 3) << 3))

/* The basic MD4 functions */
#define F(x, y, z)          ((z) ^ ((x) & ((y) ^ (z))))
#define G(x, y, z)          (((x) & ((y) | (z))) | ((y) & (z)))
#define H(x, y, z)          ((x) ^ (y) ^ (z))

/* The MD4 transformation for all three rounds. */
#define STEP(f, a, b, c, d, x, s) \
    (a) += f((b), (c), (d)) + (x); \
    (a) = (((a) << (s)) | (((a) & 0xffffffff) >> (32 - (s))));

#define GET(i) (key[(i)])

/* some constants used below magically appear after make */
//#define KEY_LENGTH (MD4_PLAINTEXT_LENGTH + 1)

/* OpenCL kernel entry point. Copy KEY_LENGTH bytes key to be hashed from
 * global to local memory. Break the key into 16 32-bit (uint) words.
 * MD4 hash of a key is 128 bit (uint4). */
__kernel void md4(__global uint *data_info, __global const uint * keys, __global uint * hashes)
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
	STEP(F, a, b, c, d, GET(0), 3)
	STEP(F, d, a, b, c, GET(1), 7)
	STEP(F, c, d, a, b, GET(2), 11)
	STEP(F, b, c, d, a, GET(3), 19)
	STEP(F, a, b, c, d, GET(4), 3)
	STEP(F, d, a, b, c, GET(5), 7)
	STEP(F, c, d, a, b, GET(6), 11)
	STEP(F, b, c, d, a, GET(7), 19)
	STEP(F, a, b, c, d, GET(8), 3)
	STEP(F, d, a, b, c, GET(9), 7)
	STEP(F, c, d, a, b, GET(10), 11)
	STEP(F, b, c, d, a, GET(11), 19)
	STEP(F, a, b, c, d, GET(12), 3)
	STEP(F, d, a, b, c, GET(13), 7)
	STEP(F, c, d, a, b, GET(14), 11)
	STEP(F, b, c, d, a, GET(15), 19)

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
	STEP(H, d, a, b, c, GET(8) + 0x6ed9eba1, 9)
	STEP(H, c, d, a, b, GET(4) + 0x6ed9eba1, 11)
	STEP(H, b, c, d, a, GET(12) + 0x6ed9eba1, 15)
	STEP(H, a, b, c, d, GET(2) + 0x6ed9eba1, 3)
	STEP(H, d, a, b, c, GET(10) + 0x6ed9eba1, 9)
	STEP(H, c, d, a, b, GET(6) + 0x6ed9eba1, 11)
	STEP(H, b, c, d, a, GET(14) + 0x6ed9eba1, 15)
	STEP(H, a, b, c, d, GET(1) + 0x6ed9eba1, 3)
	STEP(H, d, a, b, c, GET(9) + 0x6ed9eba1, 9)
	STEP(H, c, d, a, b, GET(5) + 0x6ed9eba1, 11)
	STEP(H, b, c, d, a, GET(13) + 0x6ed9eba1, 15)
	STEP(H, a, b, c, d, GET(3) + 0x6ed9eba1, 3)
	STEP(H, d, a, b, c, GET(11) + 0x6ed9eba1, 9)
	STEP(H, c, d, a, b, GET(7) + 0x6ed9eba1, 11)
	STEP(H, b, c, d, a, GET(15) + 0x6ed9eba1, 15)

	/* The following hack allows only 1/4 of the hash data to be copied in crypt_all.
	 * This code doesn't seem to have any performance gains but has other benefits */
	hashes[id] = a + 0x67452301;
	hashes[1 * num_keys + id] = b + 0xefcdab89;
	hashes[2 * num_keys + id] = c + 0x98badcfe;
	hashes[3 * num_keys + id] = d + 0x10325476;
}
