/*
 * Office 2007:
 * GeneratePasswordHashUsingSHA1() [50002 x SHA-1]
 * and DeriveKey() [xor 0x36 to a 64-byte block and 2 x SHA-1]
 *
 * Copyright 2012, magnum
 * This software is hereby released to the general public under
 * the following terms: Redistribution and use in source and binary
 * forms, with or without modification, are permitted.
 *
 * This is thanks to Dhiru writing the CPU code first!
 */

#if (DEVICE_INFO & 1) // CPU
//#define DEBUG
#endif
#ifdef cl_khr_byte_addressable_store
#pragma OPENCL EXTENSION cl_khr_byte_addressable_store : disable
#endif
#if (DEVICE_INFO & 129) // CPU, or NVIDIA GPU
#define NVIDIA
#endif

#define UNICODE_LENGTH		104 /* Including 0x0080 */

#ifdef NVIDIA
inline uint SWAP32(uint x)
{
	x = rotate(x, 16U);
	return ((x & 0x00FF00FF) << 8) + ((x >> 8) & 0x00FF00FF);
}
#else
#define SWAP32(a)	(as_uint(as_uchar4(a).wzyx))
#endif

/* SHA1 constants and IVs */
#define K0	0x5A827999
#define K1	0x6ED9EBA1
#define K2	0x8F1BBCDC
#define K3	0xCA62C1D6

#define H1	0x67452301
#define H2	0xEFCDAB89
#define H3	0x98BADCFE
#define H4	0x10325476
#define H5	0xC3D2E1F0

/* raw'n'lean sha1, context kept in output buffer.
   Note that we alter the input buffer! */
inline void sha1_block(uint *W, uint *output) {
	uint A, B, C, D, E, temp;

	A = output[0];
	B = output[1];
	C = output[2];
	D = output[3];
	E = output[4];

#undef R
#define R(t)	  \
	( \
		temp = W[(t -  3) & 0x0F] ^ W[(t - 8) & 0x0F] ^ \
		W[(t - 14) & 0x0F] ^ W[ t      & 0x0F], \
		( W[t & 0x0F] = rotate(temp, 1U) ) \
		)

#undef P
#define P(a,b,c,d,e,x)	\
	{ \
		e += rotate(a, 5U) + F(b,c,d) + K + x; \
		b = rotate(b, 30U); \
	}

#ifdef NVIDIA
#define F(x,y,z)	(z ^ (x & (y ^ z)))
#else
#define F(x,y,z)	bitselect(z, y, x)
#endif

#define K		0x5A827999

	P( A, B, C, D, E, W[0]  );
	P( E, A, B, C, D, W[1]  );
	P( D, E, A, B, C, W[2]  );
	P( C, D, E, A, B, W[3]  );
	P( B, C, D, E, A, W[4]  );
	P( A, B, C, D, E, W[5]  );
	P( E, A, B, C, D, W[6]  );
	P( D, E, A, B, C, W[7]  );
	P( C, D, E, A, B, W[8]  );
	P( B, C, D, E, A, W[9]  );
	P( A, B, C, D, E, W[10] );
	P( E, A, B, C, D, W[11] );
	P( D, E, A, B, C, W[12] );
	P( C, D, E, A, B, W[13] );
	P( B, C, D, E, A, W[14] );
	P( A, B, C, D, E, W[15] );
	P( E, A, B, C, D, R(16) );
	P( D, E, A, B, C, R(17) );
	P( C, D, E, A, B, R(18) );
	P( B, C, D, E, A, R(19) );

#undef K
#undef F

#define F(x,y,z)	(x ^ y ^ z)
#define K		0x6ED9EBA1

	P( A, B, C, D, E, R(20) );
	P( E, A, B, C, D, R(21) );
	P( D, E, A, B, C, R(22) );
	P( C, D, E, A, B, R(23) );
	P( B, C, D, E, A, R(24) );
	P( A, B, C, D, E, R(25) );
	P( E, A, B, C, D, R(26) );
	P( D, E, A, B, C, R(27) );
	P( C, D, E, A, B, R(28) );
	P( B, C, D, E, A, R(29) );
	P( A, B, C, D, E, R(30) );
	P( E, A, B, C, D, R(31) );
	P( D, E, A, B, C, R(32) );
	P( C, D, E, A, B, R(33) );
	P( B, C, D, E, A, R(34) );
	P( A, B, C, D, E, R(35) );
	P( E, A, B, C, D, R(36) );
	P( D, E, A, B, C, R(37) );
	P( C, D, E, A, B, R(38) );
	P( B, C, D, E, A, R(39) );

#undef K
#undef F

#ifdef NVIDIA
#define F(x,y,z)	((x & y) | (z & (x | y)))
#else
#define F(x,y,z)	(bitselect(x, y, z) ^ bitselect(x, 0U, y))
#endif
#define K		0x8F1BBCDC

	P( A, B, C, D, E, R(40) );
	P( E, A, B, C, D, R(41) );
	P( D, E, A, B, C, R(42) );
	P( C, D, E, A, B, R(43) );
	P( B, C, D, E, A, R(44) );
	P( A, B, C, D, E, R(45) );
	P( E, A, B, C, D, R(46) );
	P( D, E, A, B, C, R(47) );
	P( C, D, E, A, B, R(48) );
	P( B, C, D, E, A, R(49) );
	P( A, B, C, D, E, R(50) );
	P( E, A, B, C, D, R(51) );
	P( D, E, A, B, C, R(52) );
	P( C, D, E, A, B, R(53) );
	P( B, C, D, E, A, R(54) );
	P( A, B, C, D, E, R(55) );
	P( E, A, B, C, D, R(56) );
	P( D, E, A, B, C, R(57) );
	P( C, D, E, A, B, R(58) );
	P( B, C, D, E, A, R(59) );

#undef K
#undef F

#define F(x,y,z)	(x ^ y ^ z)
#define K		0xCA62C1D6

	P( A, B, C, D, E, R(60) );
	P( E, A, B, C, D, R(61) );
	P( D, E, A, B, C, R(62) );
	P( C, D, E, A, B, R(63) );
	P( B, C, D, E, A, R(64) );
	P( A, B, C, D, E, R(65) );
	P( E, A, B, C, D, R(66) );
	P( D, E, A, B, C, R(67) );
	P( C, D, E, A, B, R(68) );
	P( B, C, D, E, A, R(69) );
	P( A, B, C, D, E, R(70) );
	P( E, A, B, C, D, R(71) );
	P( D, E, A, B, C, R(72) );
	P( C, D, E, A, B, R(73) );
	P( B, C, D, E, A, R(74) );
	P( A, B, C, D, E, R(75) );
	P( E, A, B, C, D, R(76) );
	P( D, E, A, B, C, R(77) );
	P( C, D, E, A, B, R(78) );
	P( B, C, D, E, A, R(79) );

#undef K
#undef F

	output[0] += A;
	output[1] += B;
	output[2] += C;
	output[3] += D;
	output[4] += E;
}

inline void sha1_init(uint *output) {
	output[0] = H1;
	output[1] = H2;
	output[2] = H3;
	output[3] = H4;
	output[4] = H5;
}

#ifdef DEBUG
inline void dump_stuff_noeol(uchar *x, uint size) {
	uint i;
	for(i=0;i<size;i++)
	{
		printf((__constant char*)"%.2x", ((uchar*)x)[i]);
		if( (i%4)==3 )
		printf((__constant char*)" ");
	}
}
inline void dump_stuff(uchar* x, uint size)
{
	dump_stuff_noeol(x,size);
	printf((__constant char*)"\n");
}
inline void dump_stuff_msg(__constant char *msg, uchar *x, uint size) {
	printf((__constant char*)"%s : ", msg);
	dump_stuff(x, size);
}
#endif

__kernel void GenerateSHA1pwhash(
	__global uint *unicode_pw, /* [gws][104/sizeof(int)]       */
	__global uint *pw_len,     /* [gws] length in octets       */
	__constant uint *salt,     /* [16/sizeof(int)]             */
	__global uint *pwhash)     /* [gws][24/sizeof(int)] output */
{
	uint i;
	uint block[16];
	uint output[5];
	uint gid = get_global_id(0);

	/* Initial hash of salt + password */
	/* The ending 0x80 is already in the buffer */
	sha1_init(output);
#pragma unroll
	for (i = 0; i < 4; i++)
		block[i] = SWAP32(salt[i]);
#pragma unroll
	for (i = 4; i < 16; i++)
		block[i] = SWAP32(unicode_pw[gid * (UNICODE_LENGTH>>2) + i - 4]);
	if (pw_len[gid] < 40) {
		block[14] = 0;
		block[15] = (pw_len[gid] + 16) << 3;
	}
#ifdef DEBUG
	//dump_stuff_msg("1st", (uchar*)block, 64);
#endif
	sha1_block(block, output);
	if (pw_len[gid] >= 40) {
#pragma unroll
		for (i = 0; i < 14; i++)
			block[i] = SWAP32(unicode_pw[gid * (UNICODE_LENGTH>>2) + i + 12]);
		block[14] = 0;
		block[15] = (pw_len[gid] + 16) << 3;
#ifdef DEBUG
		//dump_stuff_msg("2nd", (uchar*)block, 64);
#endif
		sha1_block(block, output);
	}
#ifdef DEBUG
	if (gid == 0) dump_stuff_msg((__constant char*)"out", (uchar*)output, 20);
#endif
#pragma unroll
	for (i = 0; i < 5; i++)
		pwhash[gid * 6 + i] = output[i];
	pwhash[gid * 6 + 5] = 0;
}

__kernel void Hash1k(__global uint *pwhash) /* [gws][20/sizeof(int)] in/out */
{
	uint i, j;
	uint block[16];
	uint output[5];
	uint gid = get_global_id(0);
	uint base = pwhash[gid * 6 + 5];

#pragma unroll
	for (i = 0; i < 5; i++)
		output[i] = pwhash[gid * 6 + i];

#ifdef DEBUG
	if (gid == 0) dump_stuff_msg((__constant char*)" in", (uchar*)output, 20);
	if (gid == 0) printf((__constant char*)"base: %u\n", base);
#endif

	/* 1K rounds of sha1(serial.last hash)
	 * We avoid byte-swapping back and forth */
	for (j = 0; j < 1024; j++)
	{
		block[0] = SWAP32(base + j);
#pragma unroll
		for (i = 1; i < 6; i++)
			block[i] = output[i - 1];
		sha1_init(output);
		block[6] = 0x80000000;
#pragma unroll
		for (i = 7; i < 15; i++)
			block[i] = 0;
		block[15] = 24 << 3;
		sha1_block(block, output);
	}
#ifdef DEBUG
	if (gid == 0) dump_stuff_msg((__constant char*)"out", (uchar*)output, 20);
#endif
#pragma unroll
	for (i = 0; i < 5; i++)
		pwhash[gid * 6 + i] = output[i];
	pwhash[gid * 6 + 5] += 1024;
}

__kernel void Generate2007key(
	__global uint *pwhash,     /* [gws][20/sizeof(int)] input */
	__global uint *key)        /* [gws][16/sizeof(int)] output */
{
	uint i, j;
	uint block[16];
	uint output[5];
	uint gid = get_global_id(0);

#pragma unroll
	for (i = 0; i < 5; i++)
		output[i] = pwhash[gid * 6 + i];
#ifdef DEBUG
	if (gid == 0) dump_stuff_msg((__constant char*)"in", (uchar*)output, 20);
#endif
	/* Remainder of sha1(serial.last hash)
	 * We avoid byte-swapping back and forth */
	for (j = 49152; j < 50000; j++)
	{
		block[0] = SWAP32(j);
#pragma unroll
		for (i = 1; i < 6; i++)
			block[i] = output[i - 1];
		sha1_init(output);
		block[6] = 0x80000000;
#pragma unroll
		for (i = 7; i < 15; i++)
			block[i] = 0;
		block[15] = 24 << 3;
		sha1_block(block, output);
	}

	/* Final hash */
#pragma unroll
	for (i = 0; i < 5; i++)
		block[i] = output[i];
	sha1_init(output);
	block[5] = 0;
	block[6] = 0x80000000;
#pragma unroll
	for (i = 7; i < 15; i++)
		block[i] = 0;
	block[15] = 24 << 3;
	sha1_block(block, output);

	/* DeriveKey */
#pragma unroll
	for (i = 0; i < 5; i++)
		block[i] = output[i] ^ 0x36363636;
	sha1_init(output);
#pragma unroll
	for (i = 5; i < 16; i++)
		block[i] = 0x36363636;
	sha1_block(block, output);
	/* sha1_final (last block was 64 bytes) */
	block[0] = 0x80000000;
#pragma unroll
	for (i = 1; i < 15; i++)
		block[i] = 0;
	block[15] = 64 << 3;
	sha1_block(block, output);

	/* Endian-swap to output (we only use 16 bytes) */
#pragma unroll
	for (i = 0; i < 4; i++)
		key[gid * 4 + i] = SWAP32(output[i]);
}
