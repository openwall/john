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

#ifndef OPENCL_SHA256_H
#define OPENCL_SHA256_H

#include "opencl_sha2_common.h"
#include "opencl_rotate.h"

#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1

//Macros.
#define SWAP32_V(n)   \
    (((n) << 24)           | (((n) & 0xff00U) << 8) | \
    (((n) >> 8) & 0xff00U) | ((n) >> 24))
#define Sigma0(x)       ((ror32(x,2U))  ^ (ror32(x,13U)) ^ (ror32(x,22U)))
#define Sigma1(x)       ((ror32(x,6U))  ^ (ror32(x,11U)) ^ (ror32(x,25U)))
#define sigma0(x)       ((ror32(x,7U))  ^ (ror32(x,18U)) ^ (x>>3))
#define sigma1(x)       ((ror32(x,17U)) ^ (ror32(x,19U)) ^ (x>>10))

//SHA256 constants.
#define H0      0x6a09e667U
#define H1      0xbb67ae85U
#define H2      0x3c6ef372U
#define H3      0xa54ff53aU
#define H4      0x510e527fU
#define H5      0x9b05688cU
#define H6      0x1f83d9abU
#define H7      0x5be0cd19U

#ifdef _OPENCL_COMPILER
__constant uint32_t k[] = {
	0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
	0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
	0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
	0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
	0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
	0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
	0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
	0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
	0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
	0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
	0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
	0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
	0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
	0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
	0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
	0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
};

__constant uint32_t clear_mask[] = {
	0xffffffffU, 0x000000ffU,   //0,   8bits
	0x0000ffffU, 0x00ffffffU,   //16, 24bits
	0xffffffffU                 //32    bits
};

__constant uint32_t clear_be_mask[] = {
	0xffffffffU, 0xff000000U,   //0,   8bits
	0xffff0000U, 0xffffff00U,   //16, 24bits
	0xffffffffU                 //32    bits
};

#define OFFSET(index, position)            \
    (get_global_id(0) +                \
        (get_global_size(0) *          \
        (index * 32 + position))           \
    )

#define CLEAR_BUFFER_32(dest, start) {             \
    uint32_t tmp, pos;                             \
    tmp = ((start) & 3U);              \
    pos = ((start) >> 2);              \
    dest[pos] = dest[pos] & clear_mask[tmp];       \
    if (tmp)                                       \
        length = pos + 1;                          \
    else                                           \
    length = pos;                              \
}

#define CLEAR_BUFFER_32_SINGLE(dest, start) {      \
    uint32_t tmp, pos;                             \
    tmp = ((start) & 3U);              \
    pos = ((start) >> 2);              \
    dest[pos] = dest[pos] & clear_mask[tmp];       \
}

#define APPEND_BE_SINGLE(dest, src, start) {       \
    uint32_t tmp, pos;                             \
    tmp = (((start) & 3U) << 3);                   \
    pos = ((start) >> 2);                          \
    dest[pos] = (dest[pos] | (src >> tmp));        \
}

#define APPEND_BE_SPECIAL(dest, src, index, start) {            \
    uint32_t tmp, pos, offset;                      \
    tmp = (((start) & 3U) << 3);                    \
    pos = ((start) >> 2);                       \
    offset = OFFSET(index, pos);                    \
    dest[offset] = (dest[offset] | (src >> tmp));           \
    if (pos < 17) {                             \
    pos++;                              \
    offset = OFFSET(index, pos);                    \
    dest[offset] = (tmp ? (src << (32U - tmp)) : 0U);       \
    }                                   \
}

#define APPEND_BE_BUFFER(dest, src)                 \
    dest[pos] = (dest[pos] | (src >> tmp));             \
    dest[++pos] = (tmp ? (src << (32U - tmp)) : 0U);

#define APPEND_BE_BUFFER_F(dest, src)                   \
    dest[pos] = (dest[pos] | (src >> tmp));             \
    if (pos < 15)                           \
        dest[++pos] = (tmp ? (src << (32U - tmp)) : 0U);        \

#define APPEND_SINGLE(dest, src, start) {               \
    uint32_t tmp, pos;                          \
    tmp = (((start) & 3U) << 3);                    \
    pos = ((start) >> 2);                       \
    dest[pos] = (dest[pos] | (src << tmp));             \
}

#define APPEND_BUFFER_F(dest, src)                  \
    dest[pos] = (dest[pos] | (src << tmp));             \
    if (pos < 15)                           \
        dest[++pos] = (tmp ? (src >> (32U - tmp)) : 0U);
#endif

#endif                          /* OPENCL_SHA256_H */
