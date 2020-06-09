#include "arch.h"
#if !defined(JOHN_NO_SIMD) && (defined(__SSE2__) || defined(__SSE4_1__) || defined(__XOP__))
/*
   BLAKE2 reference source code package - optimized C implementations

   Written in 2012 by Samuel Neves <sneves@dei.uc.pt>

   To the extent possible under law, the author(s) have dedicated all copyright
   and related and neighboring rights to this software to the public domain
   worldwide. This software is distributed without any warranty.

   You should have received a copy of the CC0 Public Domain Dedication along with
   this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
*/

#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "blake2.h"
#include "blake2-impl.h"

#include <emmintrin.h>
#if defined(__SSSE3__)
#include <tmmintrin.h>
#endif
#if defined(__SSE4_1__)
#include <smmintrin.h>
#endif
#if defined(__AVX__)
#include <immintrin.h>
#endif
#if defined(__XOP__)
#include <x86intrin.h>
#endif

#include "blake2b-round.h"

JTR_ALIGN( 64 ) static const union {
  uint64_t u64[8];
  __m128i m128[4];
} blake2b_IV =
{{
  0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
  0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
  0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
  0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
}};

/* Some helper functions, not necessarily useful */
inline static int blake2b_set_lastnode( blake2b_state *S )
{
  S->f[1] = ~0ULL;
  return 0;
}

inline static int blake2b_set_lastblock( blake2b_state *S )
{
  if ( S->last_node ) blake2b_set_lastnode( S );

  S->f[0] = ~0ULL;
  return 0;
}

inline static int blake2b_increment_counter( blake2b_state *S, const uint64_t inc )
{
#if __x86_64__
  // ADD/ADC chain
  __uint128_t t = ( ( __uint128_t )S->t[1] << 64 ) | S->t[0];
  t += inc;
  S->t[0] = ( uint64_t )( t >>  0 );
  S->t[1] = ( uint64_t )( t >> 64 );
#else
  S->t[0] += inc;
  S->t[1] += ( S->t[0] < inc );
#endif
  return 0;
}


/* init xors IV with input parameter block */
int blake2b_init_param( blake2b_state *S, const blake2b_param *P )
{
  uint8_t *p, *h, *v;
  int i;
  //blake2b_init0( S );
  v = ( uint8_t * )( &blake2b_IV );
  h = ( uint8_t * )( S->h );
  p = ( uint8_t * )( P );
  /* IV XOR ParamBlock */
  memset( S, 0, sizeof( blake2b_state ) );

  for ( i = 0; i < BLAKE2B_OUTBYTES; ++i ) h[i] = v[i] ^ p[i];

  return 0;
}


/* Some sort of default parameter block initialization, for sequential blake2b */
int blake2b_init( blake2b_state *S, const uint8_t outlen )
{
  const blake2b_param P =
  {
    outlen,
    0,
    1,
    1,
    0,
    0,
    0,
    0,
    {0},
    {0},
    {0}
  };
  if ( ( !outlen ) || ( outlen > BLAKE2B_OUTBYTES ) ) return -1;
  return blake2b_init_param( S, &P );
}

int blake2b_init_key( blake2b_state *S, const uint8_t outlen, const void *key, const uint8_t keylen )
{
  const blake2b_param P =
  {
    outlen,
    keylen,
    1,
    1,
    0,
    0,
    0,
    0,
    {0},
    {0},
    {0}
  };

  if ( ( !outlen ) || ( outlen > BLAKE2B_OUTBYTES ) ) return -1;

  if ( ( !keylen ) || keylen > BLAKE2B_KEYBYTES ) return -1;

  if ( blake2b_init_param( S, &P ) < 0 )
    return 0;

  {
    uint8_t block[BLAKE2B_BLOCKBYTES];
    memset( block, 0, BLAKE2B_BLOCKBYTES );
    memcpy( block, key, keylen );
    blake2b_update( S, block, BLAKE2B_BLOCKBYTES );
    //secure_zero_memory( block, BLAKE2B_BLOCKBYTES ); /* Burn the key from stack */
  }
  return 0;
}

inline static int blake2b_compress( blake2b_state *S, const uint8_t block[BLAKE2B_BLOCKBYTES] )
{
  __m128i row1l, row1h;
  __m128i row2l, row2h;
  __m128i row3l, row3h;
  __m128i row4l, row4h;
  __m128i b0, b1;
  __m128i t0, t1;
#if defined(__SSSE3__) && !defined(__XOP__)
  const __m128i r16 = _mm_setr_epi8( 2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9 );
  const __m128i r24 = _mm_setr_epi8( 3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10 );
#endif
#if defined(__SSE4_1__)
  const __m128i m0 = LOADU( block + 00 );
  const __m128i m1 = LOADU( block + 16 );
  const __m128i m2 = LOADU( block + 32 );
  const __m128i m3 = LOADU( block + 48 );
  const __m128i m4 = LOADU( block + 64 );
  const __m128i m5 = LOADU( block + 80 );
  const __m128i m6 = LOADU( block + 96 );
  const __m128i m7 = LOADU( block + 112 );
#else
  const uint64_t  m0 = ( ( uint64_t * )block )[ 0];
  const uint64_t  m1 = ( ( uint64_t * )block )[ 1];
  const uint64_t  m2 = ( ( uint64_t * )block )[ 2];
  const uint64_t  m3 = ( ( uint64_t * )block )[ 3];
  const uint64_t  m4 = ( ( uint64_t * )block )[ 4];
  const uint64_t  m5 = ( ( uint64_t * )block )[ 5];
  const uint64_t  m6 = ( ( uint64_t * )block )[ 6];
  const uint64_t  m7 = ( ( uint64_t * )block )[ 7];
  const uint64_t  m8 = ( ( uint64_t * )block )[ 8];
  const uint64_t  m9 = ( ( uint64_t * )block )[ 9];
  const uint64_t m10 = ( ( uint64_t * )block )[10];
  const uint64_t m11 = ( ( uint64_t * )block )[11];
  const uint64_t m12 = ( ( uint64_t * )block )[12];
  const uint64_t m13 = ( ( uint64_t * )block )[13];
  const uint64_t m14 = ( ( uint64_t * )block )[14];
  const uint64_t m15 = ( ( uint64_t * )block )[15];
#endif
  row1l = LOAD( &S->h[0] );
  row1h = LOAD( &S->h[2] );
  row2l = LOAD( &S->h[4] );
  row2h = LOAD( &S->h[6] );
  row3l = LOAD( &blake2b_IV.m128[0] );
  row3h = LOAD( &blake2b_IV.m128[1] );
  row4l = _mm_xor_si128( LOAD( &blake2b_IV.m128[2] ), LOAD( &S->t[0] ) );
  row4h = _mm_xor_si128( LOAD( &blake2b_IV.m128[3] ), LOAD( &S->f[0] ) );
  ROUND( 0 );
  ROUND( 1 );
  ROUND( 2 );
  ROUND( 3 );
  ROUND( 4 );
  ROUND( 5 );
  ROUND( 6 );
  ROUND( 7 );
  ROUND( 8 );
  ROUND( 9 );
  ROUND( 10 );
  ROUND( 11 );
  row1l = _mm_xor_si128( row3l, row1l );
  row1h = _mm_xor_si128( row3h, row1h );
  STORE( &S->h[0], _mm_xor_si128( LOAD( &S->h[0] ), row1l ) );
  STORE( &S->h[2], _mm_xor_si128( LOAD( &S->h[2] ), row1h ) );
  row2l = _mm_xor_si128( row4l, row2l );
  row2h = _mm_xor_si128( row4h, row2h );
  STORE( &S->h[4], _mm_xor_si128( LOAD( &S->h[4] ), row2l ) );
  STORE( &S->h[6], _mm_xor_si128( LOAD( &S->h[6] ), row2h ) );
  return 0;
}


int blake2b_update( blake2b_state *S, const uint8_t *in, uint64_t inlen )
{
  while( inlen > 0 )
  {
    size_t left = S->buflen;
    size_t fill = 2 * BLAKE2B_BLOCKBYTES - left;

    if ( inlen > fill )
    {
      memcpy( S->buf + left, in, fill ); // Fill buffer
      S->buflen += fill;
      blake2b_increment_counter( S, BLAKE2B_BLOCKBYTES );
      blake2b_compress( S, S->buf ); // Compress
      memcpy( S->buf, S->buf + BLAKE2B_BLOCKBYTES, BLAKE2B_BLOCKBYTES ); // Shift buffer left
      S->buflen -= BLAKE2B_BLOCKBYTES;
      in += fill;
      inlen -= fill;
    }
    else // inlen <= fill
    {
      memcpy( S->buf + left, in, inlen );
      S->buflen += inlen; // Be lazy, do not compress
      in += inlen;
      inlen -= inlen;
    }
  }

  return 0;
}


int blake2b_final( blake2b_state *S, uint8_t *out, uint8_t outlen )
{
  if ( S->buflen > BLAKE2B_BLOCKBYTES )
  {
    blake2b_increment_counter( S, BLAKE2B_BLOCKBYTES );
    blake2b_compress( S, S->buf );
    S->buflen -= BLAKE2B_BLOCKBYTES;
    memcpy( S->buf, S->buf + BLAKE2B_BLOCKBYTES, S->buflen );
  }

  blake2b_increment_counter( S, S->buflen );
  blake2b_set_lastblock( S );
  memset( S->buf + S->buflen, 0, 2 * BLAKE2B_BLOCKBYTES - S->buflen ); /* Padding */
  blake2b_compress( S, S->buf );
  memcpy( out, &S->h[0], outlen );
  return 0;
}


int blake2b( uint8_t *out, const void *in, const void *key, const uint8_t outlen, const uint64_t inlen, uint8_t keylen )
{
  blake2b_state S[1];

  /* Verify parameters */
  if ( NULL == in ) return -1;

  if ( NULL == out ) return -1;

  if ( NULL == key ) keylen = 0;

  if ( keylen )
  {
    if ( blake2b_init_key( S, outlen, key, keylen ) < 0 ) return -1;
  }
  else
  {
    if ( blake2b_init( S, outlen ) < 0 ) return -1;
  }

  blake2b_update( S, ( uint8_t * )in, inlen );
  blake2b_final( S, out, outlen );
  return 0;
}

#endif
