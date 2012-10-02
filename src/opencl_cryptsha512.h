/*
 * Developed by Claudio André <claudio.andre at correios.net.br> in 2012
 *
 * More information at http://openwall.info/wiki/john/OpenCL-SHA-512
 *
 * Copyright (c) 2012 Claudio André <claudio.andre at correios.net.br>
 * This program comes with ABSOLUTELY NO WARRANTY; express or implied.
 *
 * This is free software, and you are welcome to redistribute it
 * under certain conditions; as expressed here
 * http://www.gnu.org/licenses/gpl-2.0.html
 */

#ifndef _CRYPTSHA512_H
#define _CRYPTSHA512_H

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
#define FALSE                   0
#define TRUE                    1
#define ROUNDS_PREFIX           "rounds="
#define ROUNDS_DEFAULT          5000
#define ROUNDS_MIN              1000
#define ROUNDS_MAX              999999999

#define SALT_LENGTH             16
#define PLAINTEXT_LENGTH        16
#define CIPHERTEXT_LENGTH	86
#define BUFFER_ARRAY            8
#define SALT_ARRAY              (SALT_LENGTH / 8)
#define PLAINTEXT_ARRAY         (PLAINTEXT_LENGTH / 8)
#define BINARY_SIZE             64
#define STEP                    512

#define HASH_LOOPS              (7*3*2)
#define KEYS_PER_CORE_CPU       128
#define KEYS_PER_CORE_GPU       512
#define MIN_KEYS_PER_CRYPT      128
#define MAX_KEYS_PER_CRYPT      2048*1024

//Macros.
#define SWAP(n) \
            (((n) << 56)                      \
          | (((n) & 0xff00) << 40)            \
          | (((n) & 0xff0000) << 24)          \
          | (((n) & 0xff000000) << 8)         \
          | (((n) >> 8) & 0xff000000)         \
          | (((n) >> 24) & 0xff0000)          \
          | (((n) >> 40) & 0xff00)            \
          | ((n) >> 56))

#define SWAP64_V(n)             SWAP(n)

#if gpu_amd(DEVICE_INFO)
        #define Ch(x,y,z)       bitselect(z, y, x)
        #define Maj(x,y,z)      bitselect(x, y, z ^ x)
        #define ror(x, n)       rotate(x, (uint64_t) 64-n)
        #define SWAP64(n)       (as_ulong(as_uchar8(n).s76543210))
#else
        #if gpu_nvidia(DEVICE_INFO)
            #pragma OPENCL EXTENSION cl_nv_pragma_unroll : enable
        #endif
        #define Ch(x,y,z)       ((x & y) ^ ( (~x) & z))
        #define Maj(x,y,z)      ((x & y) ^ (x & z) ^ (y & z))
        #define ror(x, n)       ((x >> n) | (x << (64-n)))
        #define SWAP64(n)       SWAP(n)
#endif
#define Sigma0(x)               ((ror(x,28)) ^ (ror(x,34)) ^ (ror(x,39)))
#define Sigma1(x)               ((ror(x,14)) ^ (ror(x,18)) ^ (ror(x,41)))
#define sigma0(x)               ((ror(x,1))  ^ (ror(x,8))  ^ (x>>7))
#define sigma1(x)               ((ror(x,19)) ^ (ror(x,61)) ^ (x>>6))

/* Macros for reading/writing chars from int32's (from rar_kernel.cl) */
#define GETCHAR(buf, index) ((buf)[(index)])
#define ATTRIB(buf, index, val) (buf)[(index)] = val
#define PUTCHAR(buf, index, val) (buf)[(index)>>2] = ((buf)[(index)>>2] & ~(0xffU << (((index) & 3) << 3))) + ((val) << (((index) & 3) << 3))

//Data types.
typedef union {
    uint8_t                     mem_08[8];
    uint16_t                    mem_16[4];
    uint32_t                    mem_32[2];
    uint64_t                    mem_64[1];
} buffer_64;

typedef struct {
    uint32_t                    rounds;
    uint32_t                    length;
    uint32_t                    initial;
    buffer_64                   salt[SALT_ARRAY];
} sha512_salt;
#define SALT_SIZE               sizeof(sha512_salt)

typedef struct {
    uint32_t                    length;
    buffer_64                   pass[PLAINTEXT_ARRAY];
} sha512_password;

typedef struct {
    uint64_t                    v[8];           //512 bits
} sha512_hash;

typedef struct {
    uint64_t                    H[8];           //512 bits
    uint32_t                    total;
    uint32_t                    buflen;
    buffer_64                   buffer[16];     //1024bits
#if cpu(DEVICE_INFO)
    uint64_t                    safety_trail;   //To avoid memory override
#endif
} sha512_ctx;

typedef struct {
    buffer_64                   alt_result[8];
    buffer_64                   temp_result[SALT_ARRAY];
    buffer_64                   p_sequence[PLAINTEXT_ARRAY];
} sha512_buffers;
#endif