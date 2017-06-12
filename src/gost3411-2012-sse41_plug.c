#if __SSE4_1__

#include <mmintrin.h>
#include <emmintrin.h>
#include <smmintrin.h>

#include "gost3411-tables.h"
#include "gost3411-2012-sse41.h"
#include "arch.h"
#include "memdbg.h"

#if ARCH_BITS == 32
#undef _mm_cvtsi64_si128
#define _mm_cvtsi64_si128 my__mm_cvtsi64_si128

inline static __m128i _mm_cvtsi64_si128(long long a) {
	return _mm_set_epi32(0, 0, (unsigned int)(a >> 32), (unsigned int)a);
}

#undef _mm_insert_epi64
#define _mm_insert_epi64 my__mm_insert_epi64

inline static __m128i _mm_insert_epi64(__m128i a, uint64_t b, int c) {
//	c <<= 1;
//	a = _mm_insert_epi32(a, (unsigned int)b, c);
//	return _mm_insert_epi32(a, (unsigned int)(b >> 32), c + 1);
/* The above code failes to build UNLESS optimizations are set. Since we only call
   this function with a constant of 1, we can simply use 2 and 3 constants and
   then the code build either in optimized or non optimized mode */
	a = _mm_insert_epi32(a, (unsigned int)b, 2);
	return _mm_insert_epi32(a, (unsigned int)(b >> 32), 3);
}
#endif

inline static void add512(const union uint512_u* x, const union uint512_u* y, union uint512_u* r)
{
	uint_fast8_t i, CF;

	CF = 0;
	for (i=0; i<8; ++i) {
		uint64_t a   = x->QWORD[i];
		uint64_t b   = y->QWORD[i];
		uint64_t sum = a + b + CF;
		CF           = ((sum < b) ? 1 : ((sum > b) ? 0 : CF));
		r->QWORD[i]  = sum;
	}
}

inline static __m128i extract0(__m128i xmm0, __m128i xmm1, __m128i xmm2, __m128i xmm3)
{
	uint64_t r0, r1;

	r0  = Ax[0][(uint8_t)_mm_extract_epi8(xmm0, 0)];
	r0 ^= Ax[1][(uint8_t)_mm_extract_epi8(xmm0, 8)];
	r0 ^= Ax[2][(uint8_t)_mm_extract_epi8(xmm1, 0)];
	r0 ^= Ax[3][(uint8_t)_mm_extract_epi8(xmm1, 8)];
	r0 ^= Ax[4][(uint8_t)_mm_extract_epi8(xmm2, 0)];
	r0 ^= Ax[5][(uint8_t)_mm_extract_epi8(xmm2, 8)];
	r0 ^= Ax[6][(uint8_t)_mm_extract_epi8(xmm3, 0)];
	r0 ^= Ax[7][(uint8_t)_mm_extract_epi8(xmm3, 8)];

	r1  = Ax[0][(uint8_t)_mm_extract_epi8(xmm0, 1)];
	r1 ^= Ax[1][(uint8_t)_mm_extract_epi8(xmm0, 9)];
	r1 ^= Ax[2][(uint8_t)_mm_extract_epi8(xmm1, 1)];
	r1 ^= Ax[3][(uint8_t)_mm_extract_epi8(xmm1, 9)];
	r1 ^= Ax[4][(uint8_t)_mm_extract_epi8(xmm2, 1)];
	r1 ^= Ax[5][(uint8_t)_mm_extract_epi8(xmm2, 9)];
	r1 ^= Ax[6][(uint8_t)_mm_extract_epi8(xmm3, 1)];
	r1 ^= Ax[7][(uint8_t)_mm_extract_epi8(xmm3, 9)];

	return _mm_insert_epi64(_mm_cvtsi64_si128(r0), r1, 1);
}

inline static __m128i extract2(__m128i xmm0, __m128i xmm1, __m128i xmm2, __m128i xmm3)
{
	uint64_t r0, r1;

	r0  = Ax[0][(uint8_t)_mm_extract_epi8(xmm0, 2)];
	r0 ^= Ax[1][(uint8_t)_mm_extract_epi8(xmm0, 10)];
	r0 ^= Ax[2][(uint8_t)_mm_extract_epi8(xmm1, 2)];
	r0 ^= Ax[3][(uint8_t)_mm_extract_epi8(xmm1, 10)];
	r0 ^= Ax[4][(uint8_t)_mm_extract_epi8(xmm2, 2)];
	r0 ^= Ax[5][(uint8_t)_mm_extract_epi8(xmm2, 10)];
	r0 ^= Ax[6][(uint8_t)_mm_extract_epi8(xmm3, 2)];
	r0 ^= Ax[7][(uint8_t)_mm_extract_epi8(xmm3, 10)];

	r1  = Ax[0][(uint8_t)_mm_extract_epi8(xmm0, 3)];
	r1 ^= Ax[1][(uint8_t)_mm_extract_epi8(xmm0, 11)];
	r1 ^= Ax[2][(uint8_t)_mm_extract_epi8(xmm1, 3)];
	r1 ^= Ax[3][(uint8_t)_mm_extract_epi8(xmm1, 11)];
	r1 ^= Ax[4][(uint8_t)_mm_extract_epi8(xmm2, 3)];
	r1 ^= Ax[5][(uint8_t)_mm_extract_epi8(xmm2, 11)];
	r1 ^= Ax[6][(uint8_t)_mm_extract_epi8(xmm3, 3)];
	r1 ^= Ax[7][(uint8_t)_mm_extract_epi8(xmm3, 11)];

	return _mm_insert_epi64(_mm_cvtsi64_si128(r0), r1, 1);
}

inline static __m128i extract4(__m128i xmm0, __m128i xmm1, __m128i xmm2, __m128i xmm3)
{
	uint64_t r0, r1;

	r0  = Ax[0][(uint8_t)_mm_extract_epi8(xmm0, 4)];
	r0 ^= Ax[1][(uint8_t)_mm_extract_epi8(xmm0, 12)];
	r0 ^= Ax[2][(uint8_t)_mm_extract_epi8(xmm1, 4)];
	r0 ^= Ax[3][(uint8_t)_mm_extract_epi8(xmm1, 12)];
	r0 ^= Ax[4][(uint8_t)_mm_extract_epi8(xmm2, 4)];
	r0 ^= Ax[5][(uint8_t)_mm_extract_epi8(xmm2, 12)];
	r0 ^= Ax[6][(uint8_t)_mm_extract_epi8(xmm3, 4)];
	r0 ^= Ax[7][(uint8_t)_mm_extract_epi8(xmm3, 12)];

	r1  = Ax[0][(uint8_t)_mm_extract_epi8(xmm0, 5)];
	r1 ^= Ax[1][(uint8_t)_mm_extract_epi8(xmm0, 13)];
	r1 ^= Ax[2][(uint8_t)_mm_extract_epi8(xmm1, 5)];
	r1 ^= Ax[3][(uint8_t)_mm_extract_epi8(xmm1, 13)];
	r1 ^= Ax[4][(uint8_t)_mm_extract_epi8(xmm2, 5)];
	r1 ^= Ax[5][(uint8_t)_mm_extract_epi8(xmm2, 13)];
	r1 ^= Ax[6][(uint8_t)_mm_extract_epi8(xmm3, 5)];
	r1 ^= Ax[7][(uint8_t)_mm_extract_epi8(xmm3, 13)];

	return _mm_insert_epi64(_mm_cvtsi64_si128(r0), r1, 1);
}

inline static __m128i extract6(__m128i xmm0, __m128i xmm1, __m128i xmm2, __m128i xmm3)
{
	uint64_t r0, r1;

	r0  = Ax[0][(uint8_t)_mm_extract_epi8(xmm0, 6)];
	r0 ^= Ax[1][(uint8_t)_mm_extract_epi8(xmm0, 14)];
	r0 ^= Ax[2][(uint8_t)_mm_extract_epi8(xmm1, 6)];
	r0 ^= Ax[3][(uint8_t)_mm_extract_epi8(xmm1, 14)];
	r0 ^= Ax[4][(uint8_t)_mm_extract_epi8(xmm2, 6)];
	r0 ^= Ax[5][(uint8_t)_mm_extract_epi8(xmm2, 14)];
	r0 ^= Ax[6][(uint8_t)_mm_extract_epi8(xmm3, 6)];
	r0 ^= Ax[7][(uint8_t)_mm_extract_epi8(xmm3, 14)];

	r1  = Ax[0][(uint8_t)_mm_extract_epi8(xmm0, 7)];
	r1 ^= Ax[1][(uint8_t)_mm_extract_epi8(xmm0, 15)];
	r1 ^= Ax[2][(uint8_t)_mm_extract_epi8(xmm1, 7)];
	r1 ^= Ax[3][(uint8_t)_mm_extract_epi8(xmm1, 15)];
	r1 ^= Ax[4][(uint8_t)_mm_extract_epi8(xmm2, 7)];
	r1 ^= Ax[5][(uint8_t)_mm_extract_epi8(xmm2, 15)];
	r1 ^= Ax[6][(uint8_t)_mm_extract_epi8(xmm3, 7)];
	r1 ^= Ax[7][(uint8_t)_mm_extract_epi8(xmm3, 15)];

	return _mm_insert_epi64(_mm_cvtsi64_si128(r0), r1, 1);
}

inline static void g(union uint512_u* h, const union uint512_u* N, const unsigned char* m)
{
	__m128i xmm0, xmm2, xmm4, xmm6;
	__m128i xmm1, xmm3, xmm5, xmm7;
	__m128i tmm0, tmm1, tmm2, tmm3;
	uint_fast8_t i;
	const __m128i *pN = (const __m128i*)N;
	const __m128i *pM = (const __m128i*)m;
	__m128i      *pH = (__m128i*)h;
	const __m128i* p;

	xmm0 = _mm_load_si128(&pN[0]);
	xmm2 = _mm_load_si128(&pN[1]);
	xmm4 = _mm_load_si128(&pN[2]);
	xmm6 = _mm_load_si128(&pN[3]);

	/* XLPS128M(h, xmm0, xmm2, xmm4, xmm6); */
	xmm0 = _mm_xor_si128(xmm0, _mm_load_si128(&pH[0]));
	xmm2 = _mm_xor_si128(xmm2, _mm_load_si128(&pH[1]));
	xmm4 = _mm_xor_si128(xmm4, _mm_load_si128(&pH[2]));
	xmm6 = _mm_xor_si128(xmm6, _mm_load_si128(&pH[3]));

	tmm0 = extract0(xmm0, xmm2, xmm4, xmm6);
	tmm1 = extract2(xmm0, xmm2, xmm4, xmm6);
	tmm2 = extract4(xmm0, xmm2, xmm4, xmm6);
	tmm3 = extract6(xmm0, xmm2, xmm4, xmm6);

	xmm0 = tmm0;
	xmm2 = tmm1;
	xmm4 = tmm2;
	xmm6 = tmm3;
	/**/

	xmm1 = _mm_load_si128(&pM[0]);
	xmm3 = _mm_load_si128(&pM[1]);
	xmm5 = _mm_load_si128(&pM[2]);
	xmm7 = _mm_load_si128(&pM[3]);

	/* XLPS128R */
	xmm1 = _mm_xor_si128(xmm1, xmm0);
	xmm3 = _mm_xor_si128(xmm3, xmm2);
	xmm5 = _mm_xor_si128(xmm5, xmm4);
	xmm7 = _mm_xor_si128(xmm7, xmm6);

	tmm0 = extract0(xmm1, xmm3, xmm5, xmm7);
	tmm1 = extract2(xmm1, xmm3, xmm5, xmm7);
	tmm2 = extract4(xmm1, xmm3, xmm5, xmm7);
	tmm3 = extract6(xmm1, xmm3, xmm5, xmm7);

	xmm1 = tmm0;
	xmm3 = tmm1;
	xmm5 = tmm2;
	xmm7 = tmm3;
	/* end of XLPS128R */

	for (i=0; i<11; ++i) {
		/* XLPS128M(&C[i], xmm0, xmm2, xmm4, xmm6); */
		p = (const __m128i*)&C[i];
		xmm0 = _mm_xor_si128(xmm0, _mm_load_si128(&p[0]));
		xmm2 = _mm_xor_si128(xmm2, _mm_load_si128(&p[1]));
		xmm4 = _mm_xor_si128(xmm4, _mm_load_si128(&p[2]));
		xmm6 = _mm_xor_si128(xmm6, _mm_load_si128(&p[3]));

		tmm0 = extract0(xmm0, xmm2, xmm4, xmm6);
		tmm1 = extract2(xmm0, xmm2, xmm4, xmm6);
		tmm2 = extract4(xmm0, xmm2, xmm4, xmm6);
		tmm3 = extract6(xmm0, xmm2, xmm4, xmm6);

		xmm0 = tmm0;
		xmm2 = tmm1;
		xmm4 = tmm2;
		xmm6 = tmm3;
		/**/

		/* XLPS128R */
		xmm1 = _mm_xor_si128(xmm1, xmm0);
		xmm3 = _mm_xor_si128(xmm3, xmm2);
		xmm5 = _mm_xor_si128(xmm5, xmm4);
		xmm7 = _mm_xor_si128(xmm7, xmm6);

		tmm0 = extract0(xmm1, xmm3, xmm5, xmm7);
		tmm1 = extract2(xmm1, xmm3, xmm5, xmm7);
		tmm2 = extract4(xmm1, xmm3, xmm5, xmm7);
		tmm3 = extract6(xmm1, xmm3, xmm5, xmm7);

		xmm1 = tmm0;
		xmm3 = tmm1;
		xmm5 = tmm2;
		xmm7 = tmm3;
		/* end of XLPS128R */
	}

	/*XLPS128M(&C[11], xmm0, xmm2, xmm4, xmm6);*/
	p = (const __m128i*)&C[11];
	xmm0 = _mm_xor_si128(xmm0, _mm_load_si128(&p[0]));
	xmm2 = _mm_xor_si128(xmm2, _mm_load_si128(&p[1]));
	xmm4 = _mm_xor_si128(xmm4, _mm_load_si128(&p[2]));
	xmm6 = _mm_xor_si128(xmm6, _mm_load_si128(&p[3]));

	tmm0 = extract0(xmm0, xmm2, xmm4, xmm6);
	tmm1 = extract2(xmm0, xmm2, xmm4, xmm6);
	tmm2 = extract4(xmm0, xmm2, xmm4, xmm6);
	tmm3 = extract6(xmm0, xmm2, xmm4, xmm6);

	xmm0 = tmm0;
	xmm2 = tmm1;
	xmm4 = tmm2;
	xmm6 = tmm3;

	xmm0 = _mm_xor_si128(xmm0, xmm1);
	xmm2 = _mm_xor_si128(xmm2, xmm3);
	xmm4 = _mm_xor_si128(xmm4, xmm5);
	xmm6 = _mm_xor_si128(xmm6, xmm7);

	xmm0 = _mm_xor_si128(xmm0, _mm_load_si128(&pH[0]));
	xmm2 = _mm_xor_si128(xmm2, _mm_load_si128(&pH[1]));
	xmm4 = _mm_xor_si128(xmm4, _mm_load_si128(&pH[2]));
	xmm6 = _mm_xor_si128(xmm6, _mm_load_si128(&pH[3]));

	xmm0 = _mm_xor_si128(xmm0, _mm_load_si128(&pM[0]));
	xmm2 = _mm_xor_si128(xmm2, _mm_load_si128(&pM[1]));
	xmm4 = _mm_xor_si128(xmm4, _mm_load_si128(&pM[2]));
	xmm6 = _mm_xor_si128(xmm6, _mm_load_si128(&pM[3]));

	_mm_store_si128(&pH[0], xmm0);
	_mm_store_si128(&pH[1], xmm2);
	_mm_store_si128(&pH[2], xmm4);
	_mm_store_si128(&pH[3], xmm6);
}

void GOST34112012Init(void* ctx, const unsigned int digest_size)
{
        GOST34112012Context* CTX = (GOST34112012Context*)ctx;

        memset(CTX, 0, sizeof(GOST34112012Context));
        CTX->digest_size = digest_size;

        if (256 == digest_size) {
                CTX->h.QWORD[0] = 0x0101010101010101ULL;
                CTX->h.QWORD[1] = 0x0101010101010101ULL;
                CTX->h.QWORD[2] = 0x0101010101010101ULL;
                CTX->h.QWORD[3] = 0x0101010101010101ULL;
                CTX->h.QWORD[4] = 0x0101010101010101ULL;
                CTX->h.QWORD[5] = 0x0101010101010101ULL;
                CTX->h.QWORD[6] = 0x0101010101010101ULL;
                CTX->h.QWORD[7] = 0x0101010101010101ULL;
        }
}


inline static void stage2(GOST34112012Context* CTX, const unsigned char* data)
{
	g(&CTX->h, &CTX->N, data);

	add512(&CTX->N, &buffer512, &CTX->N);
	add512(&CTX->Sigma, (const union uint512_u*)data, &CTX->Sigma);
}

void GOST34112012Update(void* ctx, const unsigned char* data, size_t len)
{
	size_t chunksize;
	GOST34112012Context* CTX = (GOST34112012Context*)ctx;

	while (len > 63 && CTX->bufsize == 0) {
		stage2(CTX, data);

		data += 64;
		len  -= 64;
	}

	while (len) {
		chunksize = 64 - CTX->bufsize;
		if (chunksize > len) {
			chunksize = len;
		}

		memcpy(&CTX->buffer[CTX->bufsize], data, chunksize);

		CTX->bufsize += chunksize;
		len          -= chunksize;
		data         += chunksize;

		if (CTX->bufsize == 64) {
			stage2(CTX, CTX->buffer);
			CTX->bufsize = 0;
		}
	}

	_mm_empty();
}

void GOST34112012Final(void* ctx, unsigned char* digest)
{
	GOST34112012Context* CTX = (GOST34112012Context*)ctx;
	ALIGN(16) union uint512_u buf;

	memset(&CTX->buffer[CTX->bufsize], 0, sizeof(CTX->buffer) - CTX->bufsize);

	buf.QWORD[0] = CTX->bufsize << 3;
	memset(((char*)&buf) + sizeof(buf.QWORD[0]), 0, sizeof(buf) - sizeof(buf.QWORD[0]));

	if (CTX->bufsize <= 63) {
		CTX->buffer[CTX->bufsize] = 1;
		memset(CTX->buffer + CTX->bufsize + 1, 0, sizeof(CTX->buffer) - CTX->bufsize + 1);
	}

	g(&CTX->h, &CTX->N, (const unsigned char*)&CTX->buffer);

	add512(&CTX->N, &buf, &CTX->N);
	add512(&CTX->Sigma, (const union uint512_u*)&CTX->buffer[0], &CTX->Sigma);

	g(&CTX->h, &buffer0, (const unsigned char*)&CTX->N);
	g(&CTX->h, &buffer0, (const unsigned char*)&CTX->Sigma);

	memcpy(&CTX->hash, &CTX->h, sizeof(CTX->hash));

	if (CTX->digest_size == 256) {
		memcpy(digest, &(CTX->hash.QWORD[4]), 32);
	}
	else {
		memcpy(digest, &(CTX->hash.QWORD[0]), 64);
	}

	memset(CTX, 0, sizeof(GOST34112012Context));
	_mm_empty();
}

#endif /* __SSE4_1__ */
