/*
* This software is Copyright (c) 2012 Lukas Odzioba <ukasz@openwall.net> 
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
*/
//#include <stdio.h>
//#include <stdlib.h>
//#include <assert.h>
//#include <string.h>
//#include "../cuda_pwsafe.h"
//#include "cuda_common.cuh"
#define uint8_t                         unsigned char
#define uint32_t                        unsigned int
#define rol(x,n) ((x << n) | (x >> (32-n)))
#define ror(x,n) ((x >> n) | (x << (32-n)))
#define Ch(x, y, z) (z ^ (x & (y ^ z)))
#define Maj(x, y, z) ((y & z) | (x & (y | z)))
#define Sigma0(x) ((ror(x,2))  ^ (ror(x,13)) ^ (ror(x,22)))
#define Sigma1(x) ((ror(x,6))  ^ (ror(x,11)) ^ (ror(x,25)))
#define sigma0(x) ((ror(x,7))  ^ (ror(x,18)) ^ (x>>3))
#define sigma1(x) ((ror(x,17)) ^ (ror(x,19)) ^ (x>>10))
# define SWAP32(n) \
    (((n) << 24) | (((n) & 0xff00) << 8) | (((n) >> 8) & 0xff00) | ((n) >> 24))
#pragma OPENCL EXTENSION cl_khr_byte_addressable_store : disable

#define PWSAFE_IN_SIZE (KEYS_PER_CRYPT * sizeof(pwsafe_pass))
#define PWSAFE_OUT_SIZE (KEYS_PER_CRYPT * sizeof(pwsafe_hash))
#define PWSAFE_SALT_SIZE (sizeof(pwsafe_salt))


typedef struct {
        uint8_t v[15];
        uint8_t length;
} pwsafe_pass;

typedef struct {
        uint32_t cracked;       ///cracked or not
} pwsafe_hash;

typedef struct {
        int version;
        uint32_t iterations;
        uint8_t hash[32];
 //       uint8_t length;
        uint8_t salt[32];
} pwsafe_salt;

__constant uint32_t k[] = {
                0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
                0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74,
                0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
                0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3,
                0xd5a79147, 0x06ca6351, 0x14292967,
                0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354,
                0x766a0abb, 0x81c2c92e, 0x92722c85,
                0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
                0xd6990624, 0xf40e3585, 0x106aa070,
                0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3,
                0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa,
                0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };

        __constant uint32_t H[] = {
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f,
                0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        };

__kernel void pwsafe(__global pwsafe_pass * in,
    __global pwsafe_hash * out, __global pwsafe_salt * salt)
{
        uint32_t idx = get_global_id(0);
        uint32_t pl = in[idx].length, j, i;



        uint32_t w[64];
        for (i = 0; i < 14; i++)
                w[i] = 0;
        for (j = 0; j < pl; j++) {
                uint32_t tmp = 0;
                tmp |= (((uint32_t) in[idx].v[j]) << ((3 - (j & 0x3)) << 3));
                w[j / 4] |= tmp;
        }
        for (; j < 32 + pl; j++) {
                uint32_t tmp = 0;
                tmp |=
                    (((uint32_t) salt->salt[j - pl]) << ((3 -
                            (j & 0x3)) << 3));
                w[j / 4] |= tmp;
        }
        w[j / 4] |= (((uint32_t) 0x80) << ((3 - (j & 0x3)) << 3));
        w[15] = 0x00000000 | (j * 8);

        for (j = 16; j < 64; j++) {
                w[j] =
                    sigma1(w[j - 2]) + w[j - 7] + sigma0(w[j - 15]) + w[j -
                    16];
        }

        uint32_t a = H[0];
        uint32_t b = H[1];
        uint32_t c = H[2];
        uint32_t d = H[3];
        uint32_t e = H[4];
        uint32_t f = H[5];
        uint32_t g = H[6];
        uint32_t h = H[7];
#pragma unroll 64
        for (uint32_t j = 0; j < 64; j++) {
                uint32_t t1 = h + Sigma1(e) + Ch(e, f, g) + k[j] + w[j];
                uint32_t t2 = Sigma0(a) + Maj(a, b, c);
                h = g;
                g = f;
                f = e;
                e = d + t1;
                d = c;
                c = b;
                b = a;
                a = t1 + t2;
        }

        for (i = 0; i <= salt->iterations; i++) {
                w[0] = a + H[0];
                w[1] = b + H[1];
                w[2] = c + H[2];
                w[3] = d + H[3];
                w[4] = e + H[4];
                w[5] = f + H[5];
                w[6] = g + H[6];
                w[7] = h + H[7];
                w[9] = w[10] = w[11] = w[12] = w[13] = w[14] = 0;
                w[8] = 0x80000000;
                w[15] = 0x00000100;
                for (j = 16; j < 64; j++)
                        w[j] =
                            sigma1(w[j - 2]) + w[j - 7] + sigma0(w[j - 15]) +
                            w[j - 16];

                a = H[0];
                b = H[1];
                c = H[2];
                d = H[3];
                e = H[4];
                f = H[5];
                g = H[6];
                h = H[7];
#pragma unroll 64
                for (uint32_t j = 0; j < 64; j++) {
                        uint32_t t1 =
                            h + Sigma1(e) + Ch(e, f, g) + k[j] + w[j];
                        uint32_t t2 = Sigma0(a) + Maj(a, b, c);
                        h = g;
                        g = f;
                        f = e;
                        e = d + t1;
                        d = c;
                        c = b;
                        b = a;
                        a = t1 + t2;
                }
        }
        uint32_t cmp = 1;
    
        __global uint32_t *v =  salt->hash;
        cmp &= (*v++ == a + H[0]);
        cmp &= (*v++ == b + H[1]);
        cmp &= (*v++ == c + H[2]);
        cmp &= (*v++ == d + H[3]);
        cmp &= (*v++ == e + H[4]);
        cmp &= (*v++ == f + H[5]);
        cmp &= (*v++ == g + H[6]);
        cmp &= (*v++ == h + H[7]);

        out[idx].cracked = cmp;
}

