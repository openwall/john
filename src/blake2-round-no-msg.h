/*
   BLAKE2 reference source code package - optimized C implementations

   Written in 2012 by Samuel Neves <sneves@dei.uc.pt>

   To the extent possible under law, the author(s) have dedicated all copyright
   and related and neighboring rights to this software to the public domain
   worldwide. This software is distributed without any warranty.

   You should have received a copy of the CC0 Public Domain Dedication along with
   this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
*/

#define G(a,b,c,d) \
	a = a + b ; \
	d = rotr64(d ^ a, 32); \
	c = c + d; \
	b = rotr64(b ^ c, 24); \
	a = a + b ; \
	d = rotr64(d ^ a, 16); \
	c = c + d; \
	b = rotr64(b ^ c, 63); 

#define BLAKE2_ROUND_NOMSG(v0,v1,v2,v3,v4,v5,v6,v7,v8,v9,v10,v11,v12,v13,v14,v15)  \
	G((v0), (v4), (v8), (v12)); \
	G((v1), (v5), (v9), (v13)); \
	G((v2), (v6), (v10), (v14)); \
	G((v3), (v7), (v11), (v15)); \
	G((v0), (v5), (v10), (v15)); \
	G((v1), (v6), (v11), (v12)); \
	G((v2), (v7), (v8), (v13)); \
	G((v3), (v4), (v9), (v14)); 

#define G1_SSE(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h) \
	row1l = _mm_add_epi64(row1l, row2l); \
	row1h = _mm_add_epi64(row1h, row2h); \
	\
	row4l = _mm_xor_si128(row4l, row1l); \
	row4h = _mm_xor_si128(row4h, row1h); \
	\
	row4l = _mm_roti_epi64(row4l, -32); \
	row4h = _mm_roti_epi64(row4h, -32); \
	\
	row3l = _mm_add_epi64(row3l, row4l); \
	row3h = _mm_add_epi64(row3h, row4h); \
	\
	row2l = _mm_xor_si128(row2l, row3l); \
	row2h = _mm_xor_si128(row2h, row3h); \
	\
	row2l = _mm_roti_epi64(row2l, -24); \
	row2h = _mm_roti_epi64(row2h, -24); \
 
#define G2_SSE(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h) \
	row1l = _mm_add_epi64(row1l, row2l); \
	row1h = _mm_add_epi64(row1h, row2h); \
	\
	row4l = _mm_xor_si128(row4l, row1l); \
	row4h = _mm_xor_si128(row4h, row1h); \
	\
	row4l = _mm_roti_epi64(row4l, -16); \
	row4h = _mm_roti_epi64(row4h, -16); \
	\
	row3l = _mm_add_epi64(row3l, row4l); \
	row3h = _mm_add_epi64(row3h, row4h); \
	\
	row2l = _mm_xor_si128(row2l, row3l); \
	row2h = _mm_xor_si128(row2h, row3h); \
	\
	row2l = _mm_roti_epi64(row2l, -63); \
	row2h = _mm_roti_epi64(row2h, -63); \

#define BLAKE2_ROUND_NO_MSG_SSE(row1l,row1h,row2l,row2h,row3l,row3h,row4l,row4h) \
	G1_SSE(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h); \
	G2_SSE(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h); \
	\
	DIAGONALIZE(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h); \
	\
	G1_SSE(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h); \
	G2_SSE(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h); \
	\
	UNDIAGONALIZE(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h);
