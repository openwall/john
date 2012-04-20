/*
 * RAR key & iv generation (256K x SHA-1), Copyright 2012, magnum
 *
 * This software is hereby released to the general public under
 * the following terms: Redistribution and use in source and binary
 * forms, with or without modification, are permitted.
 */

#ifdef cl_khr_byte_addressable_store
#pragma OPENCL EXTENSION cl_khr_byte_addressable_store : enable
#endif
#ifdef cl_nv_pragma_unroll
#pragma OPENCL EXTENSION cl_nv_pragma_unroll : enable
#endif

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
#if 1
	switch (len & 3) {
	case 1:
		((char*)block)[len++] = 0;
	case 2:
		((short*)block)[len / 2] = 0;
		len += 2;
		break;
	case 3:
		((char*)block)[len++] = 0;
	}
	len >>= 2;
	while (len < 14)
		block[len++] = 0;
#else
	while (len < 56)
		((char*)block)[len++] = 0;
#endif
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

//#define DEBUG
#ifdef DEBUG
void dump_stuff(uchar* x, uint size)
{
        uint i;
        for(i=0;i<size;i++)
        {
	        printf("%.2x", x[i]);
                if( (i%4)==3 )
                        printf(" ");
        }
        printf("\n");
}
void dump_stuff_msg(__constant char *msg, uchar *x, uint size) {
	printf("%s : ", msg);
	dump_stuff(x, size);
}
void dump_stuffL(__local uchar* x, uint size)
{
        uint i;
        for(i=0;i<size;i++)
        {
	        printf("%.2x", x[i]);
                if( (i%4)==3 )
                        printf(" ");
        }
        printf("\n");
}
void dump_stuffL_msg(__constant char *msg, __local uchar *x, uint size) {
	printf("%s : ", msg);
	dump_stuffL(x, size);
}
#endif

typedef union {
	uint w[(2 * PLAINTEXT_LENGTH + 8) / 4];
	ushort s[(2 * PLAINTEXT_LENGTH + 8) / 2];
	uchar c[2 * PLAINTEXT_LENGTH + 8];
} RawPsw_u;

/* The double block[] buffer saves us a LOT of branching, 20% speedup. */
__kernel void SetCryptKeys(
	__global uint *unicode_pw,
	__global uint *pw_len,
	__constant ushort *salt,
	__global uint *aes_key, __global uchar *aes_iv,
	__local RawPsw_u *locmem)
{
	uint i, j, len, pwlen, b;
	union {
		uint w[2][16];
		ushort s[64];
		uchar c[128];
	} block;
	union {
		uint w[5];
		uchar c[20];
	} output;
	uint gid = get_global_id(0);
	__local RawPsw_u *RawPsw = &locmem[get_local_id(0)];

	pwlen = pw_len[gid];

	/* Copy to fast memory */
	RawPsw->s[0] = ((__global ushort*)unicode_pw)[gid * PLAINTEXT_LENGTH];
	for (i = 1; i < pwlen / 2; i++)
		RawPsw->s[i] = ((__global ushort*)unicode_pw)[gid * PLAINTEXT_LENGTH + i];
	RawPsw->s[pwlen / 2] = ((__constant ushort*)salt)[0];
	RawPsw->s[pwlen / 2 + 1] = ((__constant ushort*)salt)[1];
	RawPsw->s[pwlen / 2 + 2] = ((__constant ushort*)salt)[2];
	RawPsw->s[pwlen / 2 + 3] = ((__constant ushort*)salt)[3];
	pwlen += 8;

#ifdef DEBUG
	dump_stuffL_msg("RawPsw", RawPsw->c, pwlen);
#endif
	sha1_init(output.w);

	/* First round is unrolled here. This should not make a difference
	   (it's one of 262144) but it makes for a 2% boost */
	block.w[0][0] = RawPsw->w[0];
	block.w[0][1] = RawPsw->w[1];
	block.s[4] = RawPsw->s[4];
	for (i = 5; i < pwlen / 2; i++)
		block.s[i] = RawPsw->s[i];

	block.s[i++] = 0;
	block.c[i * 2] = 0;

	len = pwlen + 3;
	b = 0;

#ifdef DEBUG
	dump_stuff_msg("1st", block.c, 64);
#endif
	{
		uint tempblock[16];
		union {
			uint w[5];
			uchar c[20];
		} tempout;

		memcpy32(tempblock, block.w[0],
		         (2 * PLAINTEXT_LENGTH + 8 + 3 + 3) & 15);
		memcpy32(tempout.w, output.w, 5);

		sha1_final(tempblock, tempout.w, len);

		aes_iv[gid * 16] = tempout.c[16];
	}

	for (j = 1; j < ROUNDS; j++)
	{
		/* Password + salt, length is at least 10 and always even so
		   we unroll it accordingly. We also take advantage of any
		   alignment */
		switch (len & 3) {

		case 0: // aligned to int
		{
			uint tlen = len >> 2;
			block.w[0][tlen & 31] = RawPsw->w[0];
			block.w[0][(tlen + 1) & 31] = RawPsw->w[1];
			block.w[0][(tlen + 2) & 31] = RawPsw->w[2];
			for (i = 3; i <= pwlen / 4; i++)
				block.w[0][(tlen + i) & 31] = RawPsw->w[i];
			len += pwlen;
			break;
		}

#if 0
		case 2: // aligned to short
		{
			uint tlen = len >> 1;
			block.s[tlen & 63] = RawPsw->s[0];
			block.s[(tlen + 1) & 63] = RawPsw->s[1];
			block.s[(tlen + 2) & 63] = RawPsw->s[2];
			block.s[(tlen + 3) & 63] = RawPsw->s[3];
			block.s[(tlen + 4) & 63] = RawPsw->s[4];
			for (i = 5; i <= pwlen / 2; i++)
				block.s[(tlen + i) & 63] = RawPsw->s[i];
			len += pwlen;
			break;
		}
#endif
		default: // unaligned
			block.c[len++ & 127] = RawPsw->c[0];
			block.c[len++ & 127] = RawPsw->c[1];
			block.c[len++ & 127] = RawPsw->c[2];
			block.c[len++ & 127] = RawPsw->c[3];
			block.c[len++ & 127] = RawPsw->c[4];
			block.c[len++ & 127] = RawPsw->c[5];
			block.c[len++ & 127] = RawPsw->c[6];
			block.c[len++ & 127] = RawPsw->c[7];
			block.c[len++ & 127] = RawPsw->c[8];
			block.c[len++ & 127] = RawPsw->c[9];
			for (i = 10; i < pwlen; i += 2) {
				block.c[len++ & 127] = RawPsw->c[i];
				block.c[len++ & 127] = RawPsw->c[i + 1];
			}
		}

		/* Serial */
#if 0
		if (len & 3) {
			// unaligned
			block.c[len++ & 127] = j;
			block.c[len++ & 127] = j >> 8;
			block.c[len++ & 127] = j >> 16;
		} else {
			// aligned to int
			block.w[0][(len >> 2) & 31] = j;
			len += 3;
		}
#else
		block.c[len++ & 127] = j;
		block.c[len++ & 127] = j >> 8;
		block.c[len++ & 127] = j >> 16;
#endif

		/* If we have a full buffer, submit it and switch! */
		if ((len & 64) != (b << 6)) {
			sha1_block(block.w[b], output.w);
			b = 1 - b;
		}

#ifdef DEBUG
		if (j < 7) {
			printf("%uth : ", j);
			dump_stuff(block.c, 128);
		}
#endif
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
