/*
 * Developed by Claudio André <claudioandre.br at gmail.com> in 2012
 *
 * Copyright (c) 2012-2015 Claudio André <claudioandre.br at gmail.com>
 * This program comes with ABSOLUTELY NO WARRANTY; express or implied.
 *
 * This is free software, and you are welcome to redistribute it
 * under certain conditions; as expressed here
 * http://www.gnu.org/licenses/gpl-2.0.html
 */

#ifndef OPENCL_SHA512_H
#define OPENCL_SHA512_H

#include "opencl_sha2_common.h"
#include "opencl_rotate.h"

#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1

// Macros.
#define SWAP64_V(n)             SWAP64(n)

#define Sigma0(x)               ((ror64(x,28UL)) ^ (ror64(x,34UL)) ^ (ror64(x,39UL)))
#define Sigma1(x)               ((ror64(x,14UL)) ^ (ror64(x,18UL)) ^ (ror64(x,41UL)))
#define sigma0(x)               ((ror64(x,1UL))  ^ (ror64(x,8UL))  ^ (x>>7))
#define sigma1(x)               ((ror64(x,19UL)) ^ (ror64(x,61UL)) ^ (x>>6))

//SHA512 constants.
#define H0      0x6a09e667f3bcc908UL
#define H1      0xbb67ae8584caa73bUL
#define H2      0x3c6ef372fe94f82bUL
#define H3      0xa54ff53a5f1d36f1UL
#define H4      0x510e527fade682d1UL
#define H5      0x9b05688c2b3e6c1fUL
#define H6      0x1f83d9abfb41bd6bUL
#define H7      0x5be0cd19137e2179UL

#ifdef _OPENCL_COMPILER
__constant uint64_t k[] = {
    0x428a2f98d728ae22UL, 0x7137449123ef65cdUL, 0xb5c0fbcfec4d3b2fUL,
    0xe9b5dba58189dbbcUL, 0x3956c25bf348b538UL, 0x59f111f1b605d019UL,
    0x923f82a4af194f9bUL, 0xab1c5ed5da6d8118UL, 0xd807aa98a3030242UL,
    0x12835b0145706fbeUL, 0x243185be4ee4b28cUL, 0x550c7dc3d5ffb4e2UL,
    0x72be5d74f27b896fUL, 0x80deb1fe3b1696b1UL, 0x9bdc06a725c71235UL,
    0xc19bf174cf692694UL, 0xe49b69c19ef14ad2UL, 0xefbe4786384f25e3UL,
    0x0fc19dc68b8cd5b5UL, 0x240ca1cc77ac9c65UL, 0x2de92c6f592b0275UL,
    0x4a7484aa6ea6e483UL, 0x5cb0a9dcbd41fbd4UL, 0x76f988da831153b5UL,
    0x983e5152ee66dfabUL, 0xa831c66d2db43210UL, 0xb00327c898fb213fUL,
    0xbf597fc7beef0ee4UL, 0xc6e00bf33da88fc2UL, 0xd5a79147930aa725UL,
    0x06ca6351e003826fUL, 0x142929670a0e6e70UL, 0x27b70a8546d22ffcUL,
    0x2e1b21385c26c926UL, 0x4d2c6dfc5ac42aedUL, 0x53380d139d95b3dfUL,
    0x650a73548baf63deUL, 0x766a0abb3c77b2a8UL, 0x81c2c92e47edaee6UL,
    0x92722c851482353bUL, 0xa2bfe8a14cf10364UL, 0xa81a664bbc423001UL,
    0xc24b8b70d0f89791UL, 0xc76c51a30654be30UL, 0xd192e819d6ef5218UL,
    0xd69906245565a910UL, 0xf40e35855771202aUL, 0x106aa07032bbd1b8UL,
    0x19a4c116b8d2d0c8UL, 0x1e376c085141ab53UL, 0x2748774cdf8eeb99UL,
    0x34b0bcb5e19b48a8UL, 0x391c0cb3c5c95a63UL, 0x4ed8aa4ae3418acbUL,
    0x5b9cca4f7763e373UL, 0x682e6ff3d6b2b8a3UL, 0x748f82ee5defb2fcUL,
    0x78a5636f43172f60UL, 0x84c87814a1f0ab72UL, 0x8cc702081a6439ecUL,
    0x90befffa23631e28UL, 0xa4506cebde82bde9UL, 0xbef9a3f7b2c67915UL,
    0xc67178f2e372532bUL, 0xca273eceea26619cUL, 0xd186b8c721c0c207UL,
    0xeada7dd6cde0eb1eUL, 0xf57d4f7fee6ed178UL, 0x06f067aa72176fbaUL,
    0x0a637dc5a2c898a6UL, 0x113f9804bef90daeUL, 0x1b710b35131c471bUL,
    0x28db77f523047d84UL, 0x32caab7b40c72493UL, 0x3c9ebe0a15c9bebcUL,
    0x431d67c49c100d4cUL, 0x4cc5d4becb3e42b6UL, 0x597f299cfc657e2aUL,
    0x5fcb6fab3ad6faecUL, 0x6c44198c4a475817UL
};

__constant uint64_t clear_mask[] = {
	0xffffffffffffffffUL, 0x00000000000000ffUL, //0,   8bits
	0x000000000000ffffUL, 0x0000000000ffffffUL, //16, 24bits
	0x00000000ffffffffUL, 0x000000ffffffffffUL, //32, 40bits
	0x0000ffffffffffffUL, 0x00ffffffffffffffUL, //48, 56bits
	0xffffffffffffffffUL                        //64    bits
};

#define OFFSET(index, position)                    \
    (get_global_id(0) +                            \
        (get_global_size(0) *                      \
        (index * 9 + position))                    \
    )

#define CLEAR_BUFFER_64(dest, start) {             \
    uint32_t tmp, pos;                             \
    tmp = ((start) & 7U);                          \
    pos = ((start) >> 3);                          \
    dest[pos] = dest[pos] & clear_mask[tmp];       \
    if (tmp)                                       \
        length = pos + 1;                          \
    else                                           \
    length = pos;                                  \
}

#define CLEAR_BUFFER_64_SINGLE(dest, start) {      \
    uint32_t tmp, pos;                             \
    tmp = ((start) & 7U);                          \
    pos = ((start) >> 3);                          \
    dest[pos] = dest[pos] & clear_mask[tmp];       \
}

#define APPEND_BE_SINGLE(dest, src, start) {       \
    uint32_t tmp, pos;                             \
    tmp = (((start) & 7U) << 3);                   \
    pos = ((start) >> 3);                          \
    dest[pos] = (dest[pos] | (src >> tmp));        \
}

#define APPEND_BE_SPECIAL(dest, src, index, start) {      \
    uint32_t tmp, pos, offset;                            \
    tmp = (((start) & 7U) << 3);                          \
    pos = ((start) >> 3);                                 \
    offset = OFFSET(index, pos);                          \
    dest[offset] = (dest[offset] | (src >> tmp));         \
    if (pos < 7) {                                        \
    pos++;                                                \
    offset = OFFSET(index, pos);                          \
    dest[offset] = (tmp ? (src << (64U - tmp)) : 0UL);    \
    }                                                     \
}

#define APPEND_BE_BUFFER(dest, src)                       \
    dest[pos] = (dest[pos] | (src >> tmp));               \
    dest[++pos] = (tmp ? (src << (64U - tmp)) : 0UL);

#define APPEND_BE_BUFFER_F(dest, src)                     \
    dest[pos] = (dest[pos] | (src >> tmp));               \
    if (pos < 15)                                         \
        dest[++pos] = (tmp ? (src << (64U - tmp)) : 0UL); \

#define APPEND_SINGLE(dest, src, start) {               \
    uint32_t tmp, pos;                                  \
    tmp = (((start) & 7U) << 3);                        \
    pos = ((start) >> 3);                               \
    dest[pos] = (dest[pos] | (src << tmp));             \
}

#define APPEND_BUFFER_F(dest, src)                      \
    dest[pos] = (dest[pos] | (src << tmp));             \
    if (pos < 15)                                       \
        dest[++pos] = (tmp ? (src >> (64U - tmp)) : 0UL);
#endif

#endif                          /* OPENCL_SHA512_H */
