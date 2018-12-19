/* FEAL8 – Implementation of NTT’s FEAL-8 cipher. Version of 11 September 1989. */
/*
 * Modifications, May, 2014, JimF.  Made BE compatible (change in f() only).
 * Made all internal functions static, and put a feal_ colorization on the
 * 3 exported functions (changed feal8.h also)
 */

#include "feal8.h"
#include <stdio.h>
#include <stdlib.h>

#include "common.h"
#include "johnswap.h"

static MAYBE_INLINE ByteType Rot2(ByteType X)
/*
     Evaluate the Rot2 function.
*/
{
	return (X << 2) | (X >> 6);
}

static MAYBE_INLINE ByteType S0(ByteType X1, ByteType X2)
{
	return Rot2((X1 + X2) & 0xff);
}

static MAYBE_INLINE ByteType S1(ByteType X1, ByteType X2)
{
	return Rot2((X1 + X2 + 1) & 0xff);
}

static MAYBE_INLINE HalfWord f(HalfWord AA, QuarterWord BB)
/*
     Evaluate the f function.
*/
{
	ByteType f1, f2;
	union {
		HalfWord All;
		ByteType Byte[sizeof(HalfWord)];
	} RetVal, A;
	union {
		HalfWord All;
		ByteType Byte[sizeof(HalfWord)];
	} B;

	A.All = AA;
	B.All = BB;
#if ARCH_LITTLE_ENDIAN
	f1 = A.Byte[1] ^ B.Byte[0] ^ A.Byte[0];
	f2 = A.Byte[2] ^ B.Byte[1] ^ A.Byte[3];
#else
	/* this was the only change required to make it BE compatible */
	f1 = A.Byte[1] ^ B.Byte[2] ^ A.Byte[0];
	f2 = A.Byte[2] ^ B.Byte[3] ^ A.Byte[3];
#endif
	f1 = S1(f1, f2);
	f2 = S0(f2, f1);
	RetVal.Byte[1] = f1;
	RetVal.Byte[2] = f2;
	RetVal.Byte[0] = S0(A.Byte[0], f1);
	RetVal.Byte[3] = S1(A.Byte[3], f2);
	return RetVal.All;
}

static MAYBE_INLINE HalfWord MakeH1(ByteType * B)
/*
     Assemble a HalfWord from the four bytes provided.
*/
{
	union {
		HalfWord All;
		ByteType Byte[4];
	} RetVal;

	RetVal.Byte[0] = *B++;
	RetVal.Byte[1] = *B++;
	RetVal.Byte[2] = *B++;
	RetVal.Byte[3] = *B;
	return RetVal.All;
}

static MAYBE_INLINE void DissH1(HalfWord H, ByteType * D)
/*
     Disassemble the given halfword into 4 bytes.
*/
{
	union {
		HalfWord All;
		ByteType Byte[4];
	} T;

	T.All = H;
	*D++ = T.Byte[0];
	*D++ = T.Byte[1];
	*D++ = T.Byte[2];
	*D = T.Byte[3];
}

static MAYBE_INLINE void DissQ1(QuarterWord Q, ByteType * B)
/*
     Disassemble a quarterword into two Bytes.
*/
{
	union {
		QuarterWord All;
		ByteType Byte[2];
	} QQ;

	QQ.All = Q;
	*B++ = QQ.Byte[0];
	*B = QQ.Byte[1];
}

static MAYBE_INLINE HalfWord MakeH2(QuarterWord * Q)
/*
     Make a halfword from the two quarterwords given.
*/
{
	ByteType B[4];

	DissQ1(*Q++, B);
	DissQ1(*Q, B + 2);
	return MakeH1(B);
}

static MAYBE_INLINE HalfWord FK(HalfWord AA, HalfWord BB)
/*
     Evaluate the FK function.
*/
{
	ByteType FK1, FK2;
	union {
		HalfWord All;
		ByteType Byte[4];
	} RetVal, A, B;

	A.All = AA;
	B.All = BB;
	FK1 = A.Byte[1] ^ A.Byte[0];
	FK2 = A.Byte[2] ^ A.Byte[3];
	FK1 = S1(FK1, FK2 ^ B.Byte[0]);
	FK2 = S0(FK2, FK1 ^ B.Byte[1]);
	RetVal.Byte[1] = FK1;
	RetVal.Byte[2] = FK2;
	RetVal.Byte[0] = S0(A.Byte[0], FK1 ^ B.Byte[2]);
	RetVal.Byte[3] = S1(A.Byte[3], FK2 ^ B.Byte[3]);
	return RetVal.All;
}

void feal_SetKey(ByteType * KP, struct JtR_FEAL8_CTX *ctx)
/*
     KP points to an array of 8 bytes.
*/
{
	union {
		HalfWord All;
		ByteType Byte[4];
	} A, B, D, NewB;
	union {
		QuarterWord All;
		ByteType Byte[2];
	} Q;
	int i;
	QuarterWord *Out;

	A.Byte[0] = *KP++;
	A.Byte[1] = *KP++;
	A.Byte[2] = *KP++;
	A.Byte[3] = *KP++;
	B.Byte[0] = *KP++;
	B.Byte[1] = *KP++;
	B.Byte[2] = *KP++;
	B.Byte[3] = *KP;
	D.All = 0;

	for (i = 1, Out = ctx->K; i <= 8; ++i) {
		NewB.All = FK(A.All, B.All ^ D.All);
		//D = A ;
		A = B;
		B = NewB;
		Q.Byte[0] = B.Byte[0];
		Q.Byte[1] = B.Byte[1];
		*Out++ = Q.All;
		Q.Byte[0] = B.Byte[2];
		Q.Byte[1] = B.Byte[3];
		*Out++ = Q.All;
	}
	ctx->K89   = MakeH2(ctx->K + 8);
	ctx->K1011 = MakeH2(ctx->K + 10);
	ctx->K1213 = MakeH2(ctx->K + 12);
	ctx->K1415 = MakeH2(ctx->K + 14);
}

void feal_Decrypt(ByteType * Cipher, ByteType * Plain, struct JtR_FEAL8_CTX *ctx)
/*
     Decrypt a block, using the last key set.
*/
{
	HalfWord L, R, NewL;
	int r;

	R = MakeH1(Cipher);
	L = MakeH1(Cipher + 4);
	R ^= ctx->K1213;
	L ^= ctx->K1415;
	L ^= R;

	for (r = 7; r >= 0; --r) {
		NewL = R ^ f(L, ctx->K[r]);
		R = L;
		L = NewL;
	}

	R ^= L;
	R ^= ctx->K1011;
	L ^= ctx->K89;

	DissH1(L, Plain);
	DissH1(R, Plain + 4);
}

void feal_Encrypt(ByteType * Plain, ByteType * Cipher, struct JtR_FEAL8_CTX *ctx)
/*
     Encrypt a block, using the last key set.
*/
{
	HalfWord L, R, NewR;
	int r;

	L = MakeH1(Plain);
	R = MakeH1(Plain + 4);
	L ^= ctx->K89;
	R ^= ctx->K1011;
	R ^= L;

#ifdef FEAL_DEBUG
	printf("p:  %08lx %08lx\n", L, R);
#endif
	for (r = 0; r < 8; ++r) {
		NewR = L ^ f(R, ctx->K[r]);
		L = R;
		R = NewR;
#ifdef FEAL_DEBUG
		printf("%2d: %08lx %08lx\n", r, L, R);
#endif
	}

	L ^= R;
	R ^= ctx->K1213;
	L ^= ctx->K1415;

	DissH1(R, Cipher);
	DissH1(L, Cipher + 4);
}
