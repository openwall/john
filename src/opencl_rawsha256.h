/*
 * Developed by Claudio André <claudio.andre at correios.net.br> in 2012
 *
 * More information at http://openwall.info/wiki/john/OpenCL-RAWSHA-256
 *
 * Copyright (c) 2012 Claudio André <claudio.andre at correios.net.br>
 * This program comes with ABSOLUTELY NO WARRANTY; express or implied.
 *
 * This is free software, and you are welcome to redistribute it
 * under certain conditions; as expressed here
 * http://www.gnu.org/licenses/gpl-2.0.html
 */

#ifndef _RAWSHA256_H
#define _RAWSHA256_H

#include "opencl_device_info.h"

//Type names definition.
#define uint8_t  unsigned char
#define uint16_t unsigned short
#define uint32_t unsigned int
#define uint64_t unsigned long  //Tip: unsigned long long int failed on compile (AMD).

//Functions.
#define MAX(x,y)                ((x) > (y) ? (x) : (y))
#define MIN(x,y)                ((x) < (y) ? (x) : (y))

//Constants.
#define PLAINTEXT_LENGTH        32      /* 31 characters + 0x80 */
#define PLAINTEXT_TEXT          "32"
#define CIPHERTEXT_LENGTH       64
#define PLAINTEXT_ARRAY         (PLAINTEXT_LENGTH / 4)
#define BINARY_SIZE             4
#define FULL_BINARY_SIZE        32
#define SALT_SIZE               0
#define STEP                    65536

#define KEYS_PER_CORE_CPU       65536
#define KEYS_PER_CORE_GPU       512
#define MIN_KEYS_PER_CRYPT      1024
#define MAX_KEYS_PER_CRYPT      2048*2048*4+1

//Macros.
#define SWAP(n) \
            (((n) << 24)                \
          | (((n) & 0xff00) << 8)       \
          | (((n) >> 8) & 0xff00)       \
          | ((n) >> 24))

#define SWAP32_V(n)             SWAP(n)

#if gpu_amd(DEVICE_INFO)
        #define Ch(x, y, z)     bitselect(z, y, x)
        #define Maj(x, y, z)    bitselect(x, y, z ^ x)
        #define ror(x, n)       rotate(x, (uint32_t) 32-n)
        #define SWAP32(n)       (as_uint(as_uchar4(n).s3210))
#else
        #if gpu_nvidia(DEVICE_INFO)
            #pragma OPENCL EXTENSION cl_nv_pragma_unroll : enable
        #endif
        #define Ch(x, y, z)     ((x & y) ^ ( (~x) & z))
        #define Maj(x, y, z)    ((x & y) ^ (x & z) ^ (y & z))
        #define ror(x, n)       ((x >> n) | (x << (32-n)))
        #define SWAP32(n)       SWAP(n)
#endif
#define Sigma0(x)               ((ror(x,2))  ^ (ror(x,13)) ^ (ror(x,22)))
#define Sigma1(x)               ((ror(x,6))  ^ (ror(x,11)) ^ (ror(x,25)))
#define sigma0(x)               ((ror(x,7))  ^ (ror(x,18)) ^ (x>>3))
#define sigma1(x)               ((ror(x,17)) ^ (ror(x,19)) ^ (x>>10))

/* Macros for reading/writing chars from int32's (from rar_kernel.cl) */
#define GETCHAR(buf, index) ((buf)[(index)])
#define ATTRIB(buf, index, val) (buf)[(index)] = val
#define PUTCHAR(buf, index, val) (buf)[(index)>>2] = ((buf)[(index)>>2] & ~(0xffU << (((index) & 3) << 3))) + ((val) << (((index) & 3) << 3))

//Data types.
typedef union {
    uint8_t                     mem_08[4];
    uint16_t                    mem_16[2];
    uint32_t                    mem_32[1];
} buffer_32;

typedef struct {
    uint32_t                    length;
    buffer_32                   pass[PLAINTEXT_ARRAY];
} sha256_password;

typedef struct {
    uint32_t                    v[8];           //256 bits
} sha256_hash;

typedef struct {
    uint32_t                    H[8];           //256 bits
    uint32_t                    buflen;
    buffer_32                   buffer[16];     //512 bits
} sha256_ctx;
#endif