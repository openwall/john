/** libkeccak-tiny
 *
 * A single-file implementation of SHA-3 and SHAKE.
 *
 * Implementor: David Leon Gil
 * License: CC0, attribution kindly requested. Blame taken too,
 * but not liability.
 */

#ifndef _OPENCL_KECCAK_H
#define _OPENCL_KECCAK_H

#include "opencl_misc.h"

/******** The Keccak-f[1600] permutation ********/

/*** Constants. ***/
__constant uint rho[24] =
{
     1,  3,  6, 10, 15, 21,
    28, 36, 45, 55,  2, 14,
    27, 41, 56,  8, 25, 43,
    62, 18, 39, 61, 20, 44
};

__constant uint pi[24] =
{
    10,  7, 11, 17, 18, 3,
     5, 16,  8, 21, 24, 4,
    15, 23, 19, 13, 12, 2,
    20, 14, 22,  9,  6, 1
};

__constant uint64_t RC[24] =
{
  0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808aUL,
  0x8000000080008000UL, 0x000000000000808bUL, 0x0000000080000001UL,
  0x8000000080008081UL, 0x8000000000008009UL, 0x000000000000008aUL,
  0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000aUL,
  0x000000008000808bUL, 0x800000000000008bUL, 0x8000000000008089UL,
  0x8000000000008003UL, 0x8000000000008002UL, 0x8000000000000080UL,
  0x000000000000800aUL, 0x800000008000000aUL, 0x8000000080008081UL,
  0x8000000000008080UL, 0x0000000080000001UL, 0x8000000080008008UL
};

/*** Helper macros to unroll the permutation. ***/
#define rol(x, s) rotate(x, (uint64_t)s)
#define REPEAT6(e) e e e e e e
#define REPEAT24(e) REPEAT6(e e e e)
#define REPEAT5(e) e e e e e

#define FOR5(v, s, e) \
  v = 0;              \
  REPEAT5(e; v += s;)

/*** Keccak-f[1600] ***/
inline void keccakf(void* state)
{
	uint64_t* a = (uint64_t*)state;
	uint64_t b[5] = { 0 };
	uint64_t t = 0;
	uint x, y;

	for (int i = 0; i < 24; i++) {
		// Theta
		FOR5(x, 1,
		     b[x] = 0;
		     FOR5(y, 5,
		          b[x] ^= a[x + y];
		     )
		)
		FOR5(x, 1,
		     FOR5(y, 5,
		          a[y + x] ^= b[(x + 4) % 5] ^ rol(b[(x + 1) % 5], 1);
			 )
		)
		// Rho and pi
		t = a[1];
		x = 0;
		REPEAT24(b[0] = a[pi[x]];
		         a[pi[x]] = rol(t, rho[x]);
		         t = b[0];
		         x++;
		)
		// Chi
		FOR5(y, 5,
		     FOR5(x, 1,
		          b[x] = a[y + x];
			 )
		     FOR5(x, 1,
		          a[y + x] = b[x] ^ ((~b[(x + 1) % 5]) & b[(x + 2) % 5]);
			 )
		)
		// Iota
		a[0] ^= RC[i];
	}
}

/******** The FIPS202-defined functions. ********/

/*** Some helper macros. ***/

#define _(S) do { S } while (0)

#define FOR(i, ST, L, S) \
  _(for (uint i = 0; i < L; i += ST) { S; })

#define mkapply_ds(NAME, S)                                          \
  inline void NAME(uint8_t* dst,                                     \
                   const uint8_t* src,                               \
                   uint len) {                                       \
      FOR(i, 1, len, S);                                             \
  }

#define mkapply_sd(NAME, S)                                          \
  inline void NAME(const uint8_t* src,                               \
                   uint8_t* dst,                                     \
                   uint len) {                                       \
      FOR(i, 1, len, S);                                             \
  }

mkapply_ds(xorin, dst[i] ^= src[i])  // xorin
mkapply_sd(setout, dst[i] = src[i])  // setout

#define P keccakf
#define Plen 200

// Fold P*F over the full blocks of an input.
#define foldP(I, L, F) \
  while (L >= rate) {  \
    F(a, I, rate);     \
    P(a);              \
    I += rate;         \
    L -= rate;         \
  }

/** The sponge-based hash construction. **/
inline void hash(uint8_t* out, uint outlen, const uint8_t* in, uint inlen,
                 uint rate, uint8_t delim)
{
	uint8_t a[Plen] = { 0 };

	// Absorb input.
	foldP(in, inlen, xorin);
	// Xor in the DS and pad frame.
	a[inlen] ^= delim;
	a[rate - 1] ^= 0x80;
	// Xor in the last block.
	xorin(a, in, inlen);
	// Apply P
	P(a);
	// Squeeze output.
	foldP(out, outlen, setout);
	setout(a, out, outlen);
}

/*** Helper macros to define SHA3 and SHAKE instances. ***/
#define defshake(bits)                                            \
  inline void shake##bits(uint8_t* out, uint outlen,              \
                          const uint8_t* in, uint inlen) {        \
      hash(out, outlen, in, inlen, 200 - (bits / 4), 0x1f);       \
  }

#define defsha3(bits)                                             \
  inline void sha3_##bits(uint8_t* out, uint outlen,              \
                          const uint8_t* in, uint inlen) {        \
      hash(out, outlen, in, inlen, 200 - (bits / 4), 0x06);       \
  }

#define defkeccak(bits)                                           \
  inline void keccak_##bits(uint8_t* out, uint outlen,            \
                            const uint8_t* in, uint inlen) {      \
      hash(out, outlen, in, inlen, 200 - (bits / 4), 0x01);       \
  }

defkeccak(256)

#endif /* _OPENCL_KECCAK_H */
