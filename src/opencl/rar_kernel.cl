/*
 * RAR key & iv generation (256K x SHA-1), Copyright 2012, magnum
 *
 * This software is hereby released to the general public under
 * the following terms: Redistribution and use in source and binary
 * forms, with or without modification, are permitted.
 */

#ifdef cl_khr_byte_addressable_store
#pragma OPENCL EXTENSION cl_khr_byte_addressable_store : disable
#endif
#ifdef cl_nv_pragma_unroll
#pragma OPENCL EXTENSION cl_nv_pragma_unroll : enable
#endif

#define PLAINTEXT_LENGTH	16	/* must match opencl_rar_fmt.c */
#define ROUNDS			0x40000

/* Macros for reading/writing chars from int32's */
//#define GETCHAR(buf, index) (((buf)[(index)>>2] & 0xffU << (((index) & 3) << 3)) >> (((index) & 3) << 3))
#define GETCHAR(buf, index) (((__local uchar*)(buf))[(index)])
#define PUTCHAR(buf, index, val) (buf)[(index)>>2] = (buf)[(index)>>2] & ~(0xff << (((index) & 3) << 3)) | (((val) & 0xff) << (((index) & 3) << 3))
#define GETCHAR_BE(buf, index) (((buf)[(index)>>2] & 0xffU << ((3 - ((index) & 3)) << 3)) >> ((3 - ((index) & 3)) << 3))
#define PUTCHAR_BE(buf, index, val) (buf)[(index)>>2] = (buf)[(index)>>2] & ~(0xff << (((3 - (index) & 3) << 3))) | (((val) & 0xff) << (((3 - (index) & 3) << 3)))

/* This is the fastest I've found for GTX580 */
inline uint SWAP32(uint x)
{
	x = (x << 16) + (x >> 16);
	return ((x & 0x00FF00FF) << 8) + ((x >> 8) & 0x00FF00FF);
}

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

/* raw'n'lean sha1, context kept in output buffer */
void sha1_block(uint *W, uint *output) {
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
		( W[t & 0x0F] = rotate((int)temp,1) ) \
		)

#undef P
#define P(a,b,c,d,e,x)	\
	{ \
		e += rotate((int)a,5) + F(b,c,d) + K + x; \
		b = rotate((int)b,30); \
	}

#define F(x,y,z)	(z ^ (x & (y ^ z)))
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

#define F(x,y,z)	((x & y) | (z & (x | y)))
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

void sha1_final(uint *block, uint *output, uint tot_len)
{
	uint len = (tot_len & 63) >> 2;

	switch(tot_len & 3) {
	case 0:
		block[len] = 0x80000000;
		break;
	case 1:
		block[len] = block[len] & 0xff000000 | 0x800000;
		break;
	case 2:
		block[len] = block[len] & 0xffff0000 | 0x8000;
		break;
	case 3:
		block[len] = block[len] & 0xffffff00 | 0x80;
		break;
	}
	len++;
	if (len > 13) {
		sha1_block(block, output);
		len = 0;
	}
	while (len < 15)
		block[len++] = 0;
	block[15] = tot_len << 3;
	sha1_block(block, output);
}

/* len is given in words, not bytes */
inline void memcpy32(uint *d, const uint *s, uint len)
{
	while(len--)
		*d++ = *s++;
}

/* The double block[] buffer saves us a LOT of branching, 20% speedup. */
__kernel void SetCryptKeys(
	__global uint *unicode_pw,
	__global uint *pw_len,
	__constant uint *salt,
	__global uint *aes_key, __global uint *aes_iv,
	__local uint *locmem)
{
	uint i, j, len, pwlen, b;
	uint block[2][16];
	uint output[5];
	uint gid = get_global_id(0);
	__local uint *RawPsw = &locmem[get_local_id(0) * 40];

	pwlen = pw_len[gid];

	/* Copy to fast memory, one version for every aligment need */
	RawPsw[0] = SWAP32(unicode_pw[gid * PLAINTEXT_LENGTH / 2]);
	for (i = 1; i < (pwlen + 3) >> 2; i++) {
		RawPsw[i] = SWAP32(unicode_pw[gid * PLAINTEXT_LENGTH / 2 + i]);
	}
#pragma unroll 8
	for (i = 0; i < 8; i++) {
		//uint temp = GETCHAR(salt, i);
		uint temp = ((__constant uchar*)salt)[i];
		PUTCHAR_BE(RawPsw, pwlen + i, temp);
	}
	pwlen += 8;
	for (i = 0; i < ((pwlen + 3) >> 2) - 1; i++) {
		RawPsw[i + 10] = (RawPsw[i] << 24) + (RawPsw[i + 1] >> 8);
		RawPsw[i + 20] = (RawPsw[i] << 16) + (RawPsw[i + 1] >> 16);
		RawPsw[i + 30] = (RawPsw[i] << 8) + (RawPsw[i + 1] >> 24);
	}
	RawPsw[i + 10] = (RawPsw[i] << 24);
	RawPsw[i + 20] = (RawPsw[i] << 16);
	RawPsw[i + 30] = (RawPsw[i] << 8);

	b = len = 0;
	sha1_init(output);

	/* First iteration unrolled here: */
	block[0][0] = RawPsw[0];
	block[0][1] = RawPsw[1];
	block[0][2] = RawPsw[2];
	for (i = 3; i < (pwlen + 3) >> 2; i++)
		block[0][i] = RawPsw[i];
	len += pwlen;

	/* Serial */
	if (!(len & 3)) {
		block[0][len >> 2] = 0;
		len += 3;
	} else {
		PUTCHAR_BE(block[0], len, 0); len++;
		PUTCHAR_BE(block[0], len, 0); len++;
		PUTCHAR_BE(block[0], len, 0); len++;
	}

	/* Pick first byte of IV */
	{
		uint tempblock[16];
		uint tempout[5];

		memcpy32(tempblock, block[b], (((len + 3) & 63) >> 2));
		memcpy32(tempout, output, 5);

		sha1_final(tempblock, tempout, len);

		//PUTCHAR(aes_iv, gid * 16, GETCHAR(tempout, 16));
		PUTCHAR(aes_iv, gid * 16, ((uchar*)tempout)[16]);
	}

	for (j = 1; j < ROUNDS; j++)
	{
		switch (len & 3) {
		case 0:	/* 32-bit aligned! */
			block[0][((len >> 2) + 0) & 31] = RawPsw[0];
			block[0][((len >> 2) + 1) & 31] = RawPsw[1];
			block[0][((len >> 2) + 2) & 31] = RawPsw[2];
			for (i = 3; i < (pwlen + 3) >> 2; i++)
				block[0][((len >> 2) + i) & 31] = RawPsw[i];
			break;
		case 1:	/* unaligned mod 1 */
			PUTCHAR_BE(block[0], (len + 0) & 127, GETCHAR_BE(RawPsw, 0));
			PUTCHAR_BE(block[0], (len + 1) & 127, GETCHAR_BE(RawPsw, 1));
			PUTCHAR_BE(block[0], (len + 2) & 127, GETCHAR_BE(RawPsw, 2));
			block[0][((len >> 2) + 0 + 1) & 31] = RawPsw[10 + 0];
			block[0][((len >> 2) + 1 + 1) & 31] = RawPsw[10 + 1];
			for (i = 2; i < (pwlen + 3) >> 2; i++)
				block[0][((len >> 2) + i + 1) & 31] = RawPsw[10 + i];
			break;
		case 2:	/* unaligned mod 2 */
			PUTCHAR_BE(block[0], (len + 0) & 127, GETCHAR_BE(RawPsw, 0));
			PUTCHAR_BE(block[0], (len + 1) & 127, GETCHAR_BE(RawPsw, 1));
			block[0][((len >> 2) + 0 + 1) & 31] = RawPsw[20 + 0];
			block[0][((len >> 2) + 1 + 1) & 31] = RawPsw[20 + 1];
			for (i = 2; i < (pwlen + 3) >> 2; i++)
				block[0][((len >> 2) + i + 1) & 31] = RawPsw[20 + i];
			break;
		case 3:	/* unaligned mod 3 */
			PUTCHAR_BE(block[0], (len + 0) & 127, GETCHAR_BE(RawPsw, 0));
			block[0][((len >> 2) + 0 + 1) & 31] = RawPsw[30 + 0];
			block[0][((len >> 2) + 1 + 1) & 31] = RawPsw[30 + 1];
			for (i = 2; i < (pwlen + 3) >> 2; i++)
				block[0][((len >> 2) + i + 1) & 31] = RawPsw[30 + i];
			break;
		}
		len += pwlen;

		/* Serial */
		if (!(len & 3)) {
#ifdef __ENDIAN_LITTLE__
			block[0][(len >> 2) & 31] = SWAP32(j);
#else
			block[0][(len >> 2) & 31] = j;
#endif
			len += 3;
		} else {
			PUTCHAR_BE(block[0], len & 127, j); len++;
			PUTCHAR_BE(block[0], len & 127, j >> 8); len++;
			PUTCHAR_BE(block[0], len & 127, j >> 16); len++;
		}

		/* If we have a full buffer, submit it and switch! */
		if ((len & 64) != (b << 6)) {
			sha1_block(block[b], output);
			b = 1 - b;
		}

		/* Every 16K'th round, we do a final and pick one byte of IV */
		if (j % (ROUNDS >> 4) == 0)
		{
			uint tempblock[16];
			uint tempout[5];

			/* hardcoding 16 here might be faster */
			memcpy32(tempblock, block[b], (((len + 3) & 63) >> 2));
			memcpy32(tempout, output, 5);

			sha1_final(tempblock, tempout, len);

			//PUTCHAR(aes_iv, gid * 16 + (j >> 14), GETCHAR(tempout, 16));
			PUTCHAR(aes_iv, gid * 16 + (j >> 14), ((uchar*)tempout)[16]);
		}
	}
	sha1_final(block[b], output, len);

	// Non-endian-swapping copy
	aes_key[gid * 4] = output[0];
	aes_key[gid * 4 + 1] = output[1];
	aes_key[gid * 4 + 2] = output[2];
	aes_key[gid * 4 + 3] = output[3];
}
