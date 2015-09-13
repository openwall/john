/**
 * Header file for Blake2b's and BlaMka's internal permutation in the form of a sponge. 
 * This code is based on the original Blake2b's implementation provided by 
 * Samuel Neves (https://blake2.net/). SSE-oriented implementation.
 * 
 * Author: The Lyra PHC team (http://www.lyra2.net/) -- 2015.
 * 
 * This software is hereby placed in the public domain.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This file was modified by Agnieszka Bielec <bielecagnieszka8 at gmail.com> on June,2015.
 */

#include "arch.h"

#ifdef SIMD_COEF_64

#ifndef SPONGE_SSE_H_
#define SPONGE_SSE_H_

#include <stdint.h>
#include <emmintrin.h>

#if defined(__GNUC__)
#define ALIGN __attribute__ ((aligned(32)))
#elif defined(_MSC_VER)
#define ALIGN __declspec(align(32))
#else
#define ALIGN
#endif

//Block length required so Blake2's Initialization Vector (IV) is not overwritten (THIS SHOULD NOT BE MODIFIED)
#define BLOCK_LEN_BLAKE2_SAFE_INT64 8                                   //512 bits (=64 bytes, =8 uint64_t)
#define BLOCK_LEN_BLAKE2_SAFE_INT128 (BLOCK_LEN_BLAKE2_SAFE_INT64/2)                                   
#define BLOCK_LEN_BLAKE2_SAFE_BYTES (BLOCK_LEN_BLAKE2_SAFE_INT64 * 8)   //same as above, in bytes

//default block length: 768 bits
#ifndef BLOCK_LEN_INT64             
        #define BLOCK_LEN_INT64 12                                      //Block length: 768 bits (=96 bytes, =12 uint64_t)
#endif

#define BLOCK_LEN_INT128 (BLOCK_LEN_INT64/2)

#define BLOCK_LEN_BYTES (BLOCK_LEN_INT64 * 8)                           //Block length, in bytes

#ifndef SPONGE
        #define SPONGE 0                                                //SPONGE 0 = BLAKE2, SPONGE 1 = BLAMKA and SPONGE 2 = HALF-ROUND BLAMKA
#endif

#ifndef RHO
        #define RHO 1                                                   //Number of reduced rounds performed
#endif

/*Blake 2b IV Array*/
static const uint64_t blake2b_IV[8] =
{
  0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
  0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
  0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
  0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

/*Main change compared with Blake2b*/
static inline __m128i fBlaMka(__m128i x, __m128i y){
    __m128i z = _mm_mul_epu32 (x, y);
    
    z = _mm_slli_epi64 (z, 1);
    
    z = _mm_add_epi64 (z, x);
    z = _mm_add_epi64 (z, y);
    
    return z;
}

#define G1_BLAMKA(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h) \
  row1l = fBlaMka(row1l, row2l); \
  row1h = fBlaMka(row1h, row2h); \
  \
  row4l = _mm_xor_si128(row4l, row1l); \
  row4h = _mm_xor_si128(row4h, row1h); \
  \
  row4l = _mm_roti_epi64(row4l, -32); \
  row4h = _mm_roti_epi64(row4h, -32); \
  \
  row3l = fBlaMka(row3l, row4l); \
  row3h = fBlaMka(row3h, row4h); \
  \
  row2l = _mm_xor_si128(row2l, row3l); \
  row2h = _mm_xor_si128(row2h, row3h); \
  \
  row2l = _mm_roti_epi64(row2l, -24); \
  row2h = _mm_roti_epi64(row2h, -24); \
 
#define G2_BLAMKA(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h) \
  row1l = fBlaMka(row1l, row2l); \
  row1h = fBlaMka(row1h, row2h); \
  \
  row4l = _mm_xor_si128(row4l, row1l); \
  row4h = _mm_xor_si128(row4h, row1h); \
  \
  row4l = _mm_roti_epi64(row4l, -16); \
  row4h = _mm_roti_epi64(row4h, -16); \
  \
  row3l = fBlaMka(row3l, row4l); \
  row3h = fBlaMka(row3h, row4h); \
  \
  row2l = _mm_xor_si128(row2l, row3l); \
  row2h = _mm_xor_si128(row2h, row3h); \
  \
  row2l = _mm_roti_epi64(row2l, -63); \
  row2h = _mm_roti_epi64(row2h, -63); \

/*One Round of the BlaMka's compression function*/
#define ROUND_LYRA_BLAMKA(r) \
  G1_BLAMKA(v[0],v[2],v[4],v[6],v[1],v[3],v[5],v[7]); \
  G2_BLAMKA(v[0],v[2],v[4],v[6],v[1],v[3],v[5],v[7]); \
  DIAGONALIZE(v[0],v[2],v[4],v[6],v[1],v[3],v[5],v[7]); \
  G1_BLAMKA(v[0],v[2],v[4],v[6],v[1],v[3],v[5],v[7]); \
  G2_BLAMKA(v[0],v[2],v[4],v[6],v[1],v[3],v[5],v[7]); \
  UNDIAGONALIZE(v[0],v[2],v[4],v[6],v[1],v[3],v[5],v[7]);

/*Half Round of the BlaMka's compression function*/
#define HALF_ROUND_LYRA_BLAMKA(r) \
  G1_BLAMKA(v[0],v[2],v[4],v[6],v[1],v[3],v[5],v[7]); \
  G2_BLAMKA(v[0],v[2],v[4],v[6],v[1],v[3],v[5],v[7]); \
  DIAGONALIZE(v[0],v[2],v[4],v[6],v[1],v[3],v[5],v[7]);

#define G1_LYRA(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h) \
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
 
#define G2_LYRA(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h) \
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

#define ROUND_LYRA_SSE(r) \
  G1_LYRA(v[0],v[2],v[4],v[6],v[1],v[3],v[5],v[7]); \
  G2_LYRA(v[0],v[2],v[4],v[6],v[1],v[3],v[5],v[7]); \
  DIAGONALIZE(v[0],v[2],v[4],v[6],v[1],v[3],v[5],v[7]); \
  G1_LYRA(v[0],v[2],v[4],v[6],v[1],v[3],v[5],v[7]); \
  G2_LYRA(v[0],v[2],v[4],v[6],v[1],v[3],v[5],v[7]); \
  UNDIAGONALIZE(v[0],v[2],v[4],v[6],v[1],v[3],v[5],v[7]);

//---- Housekeeping
void initState(__m128i state[/*8*/]);

//---- Squeezes
void squeeze(__m128i *state, unsigned char *out, unsigned int len);
void reducedSqueezeRow0(__m128i* state, __m128i* rowOut);

//---- Absorbs
void absorbColumn(__m128i *state, __m128i *in);
void absorbBlockBlake2Safe(__m128i *state, const __m128i *in);

//---- Duplexes
void reducedDuplexRow1and2(__m128i *state, __m128i *rowIn, __m128i *rowOut);
void reducedDuplexRowFilling(__m128i *state, __m128i *rowInOut, __m128i *rowIn0, __m128i *rowIn1, __m128i *rowOut);
void reducedDuplexRowWandering(__m128i *state, __m128i *rowInOut0, __m128i *rowInOut1, __m128i *rowIn0, __m128i *rowIn1);
void reducedDuplexRowWanderingParallel(__m128i *state, __m128i *rowInOut0, __m128i *rowInP, __m128i *rowIn0);

//---- Misc
void printArray(unsigned char *array, unsigned int size, char *name);

#endif //#ifdef SIMD_COEF_64

#endif /* SPONGE_H_ */
