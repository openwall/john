/*
 * RAR key & iv generation (256K x SHA-1), Copyright 2012, magnum
 *
 * This software is hereby released to the general public under
 * the following terms: Redistribution and use in source and binary
 * forms, with or without modification, are permitted.
 */

#define PLAINTEXT_LENGTH	16	/* must match opencl_rar_fmt.c */
#define ROUNDS			0x40000

/* This is the fastest I've found for GTX580 (it uses mad) */
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
void sha1_block(uint *LW, uint *output) {
	uint A, B, C, D, E, temp, W[16];

	A = output[0];
	B = output[1];
	C = output[2];
	D = output[3];
	E = output[4];

	W[0] = SWAP32(LW[0]);
	W[1] = SWAP32(LW[1]);
	W[2] = SWAP32(LW[2]);
	W[3] = SWAP32(LW[3]);
	W[4] = SWAP32(LW[4]);
	W[5] = SWAP32(LW[5]);
	W[6] = SWAP32(LW[6]);
	W[7] = SWAP32(LW[7]);
	W[8] = SWAP32(LW[8]);
	W[9] = SWAP32(LW[9]);
	W[10] = SWAP32(LW[10]);
	W[11] = SWAP32(LW[11]);
	W[12] = SWAP32(LW[12]);
	W[13] = SWAP32(LW[13]);
	W[14] = SWAP32(LW[14]);
	W[15] = SWAP32(LW[15]);

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
	uint len = tot_len & 63;

	((char*)block)[len++] = 0x80;
	if (len > 55) {
		sha1_block(block, output);
		len = 0;
	}
	while (len < 56)
		((char*)block)[len++] = 0;

	block[14] = 0;
	block[15] = SWAP32(tot_len << 3);
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
	__global const uchar *unicode_pw,
	__global const uint *pw_len,
	__constant uchar *salt,
	__global uint *aes_key, __global uchar *aes_iv)
{
	uint i, j, len, pwlen, b;
	union {
		uint w[2][16];
		uchar c[128];
	} block;
	union {
		uint w[5];
		uchar c[20];
	} output;
	uint gid = get_global_id(0);
	uchar RawPsw[2 * PLAINTEXT_LENGTH + 8];

	pwlen = pw_len[gid];

	/* Copy to fast memory */
	RawPsw[0] = unicode_pw[gid * 2 * PLAINTEXT_LENGTH];
	RawPsw[1] = unicode_pw[gid * 2 * PLAINTEXT_LENGTH + 1];
	for (i = 2; i < pwlen; i += 2 ) {
		RawPsw[i] = unicode_pw[gid * 2 * PLAINTEXT_LENGTH + i];
		RawPsw[i + 1] = unicode_pw[gid * 2 * PLAINTEXT_LENGTH + i + 1];
	}
	RawPsw[pwlen] = salt[0];
	RawPsw[pwlen + 1] = salt[1];
	RawPsw[pwlen + 2] = salt[2];
	RawPsw[pwlen + 3] = salt[3];
	RawPsw[pwlen + 4] = salt[4];
	RawPsw[pwlen + 5] = salt[5];
	RawPsw[pwlen + 6] = salt[6];
	RawPsw[pwlen + 7] = salt[7];
	pwlen += 8;

	sha1_init(output.w);

	/* First round is unrolled here. This should not make a difference
	   (it's one of 262144) but it makes for a 2% boost */
	block.c[0] = RawPsw[0];
	block.c[1] = RawPsw[1];
	block.c[2] = RawPsw[2];
	block.c[3] = RawPsw[3];
	block.c[4] = RawPsw[4];
	block.c[5] = RawPsw[5];
	block.c[6] = RawPsw[6];
	block.c[7] = RawPsw[7];
	block.c[8] = RawPsw[8];
	block.c[9] = RawPsw[9];

	for (i = 10; i < pwlen; i += 2) {
		block.c[i] = RawPsw[i];
		block.c[i + 1] = RawPsw[i + 1];
	}

	block.c[i++] = 0;
	block.c[i++] = 0;
	block.c[i++] = 0;

	len = pwlen + 3;
	b = 0;

	{
		uint tempblock[16];
		union {
			uint w[5];
			uchar c[20];
		} tempout;

		memcpy32(tempblock, block.w[b], 9);
		memcpy32(tempout.w, output.w, 5);

		sha1_final(tempblock, tempout.w, len);

		aes_iv[gid * 16] = tempout.c[16];
	}

	for (j = 1; j < ROUNDS; j++)
	{
		/* Password + salt, length is at least 10 and always even so
		   we unroll it accordingly. */
		block.c[len++ & 127] = RawPsw[0];
		block.c[len++ & 127] = RawPsw[1];
		block.c[len++ & 127] = RawPsw[2];
		block.c[len++ & 127] = RawPsw[3];
		block.c[len++ & 127] = RawPsw[4];
		block.c[len++ & 127] = RawPsw[5];
		block.c[len++ & 127] = RawPsw[6];
		block.c[len++ & 127] = RawPsw[7];
		block.c[len++ & 127] = RawPsw[8];
		block.c[len++ & 127] = RawPsw[9];
		for (i = 10; i < pwlen; i += 2) {
			block.c[len++ & 127] = RawPsw[i];
			block.c[len++ & 127] = RawPsw[i + 1];
		}

		/* Serial */
		block.c[len++ & 127] = j;
		block.c[len++ & 127] = j >> 8;
		block.c[len++ & 127] = j >> 16;

		/* If we have a full buffer, submit it and switch! */
		if ((len & 64) != (b << 6)) {
			sha1_block(block.w[b], output.w);
			b = 1 - b;
		}

		/* Every 16K'th round, we do a final and pick one byte of IV */
		if (j % (ROUNDS >> 4) == 0)
		{
			uint tempblock[16];
			union {
				uint w[5];
				uchar c[20];
			} tempout;

			 /* (len + 3) & 15 is slower than hardcoding 16 here */
			memcpy32(tempblock, block.w[b], 16);
			memcpy32(tempout.w, output.w, 5);

			sha1_final(tempblock, tempout.w, len);

			aes_iv[gid * 16 + (j >> 14)] = tempout.c[16];
		}
	}
	sha1_final(block.w[b], output.w, len);

	// Non-endian-swapping copy
	aes_key[gid * 4] = output.w[0];
	aes_key[gid * 4 + 1] = output.w[1];
	aes_key[gid * 4 + 2] = output.w[2];
	aes_key[gid * 4 + 3] = output.w[3];
}
