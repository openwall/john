/*
 * Developed by Claudio André <claudio.andre at correios.net.br> in 2012
 *
 * Copyright (c) 2012 Claudio André <claudio.andre at correios.net.br>
 * This program comes with ABSOLUTELY NO WARRANTY; express or implied.
 *
 * This is free software, and you are welcome to redistribute it
 * under certain conditions; as expressed here
 * http://www.gnu.org/licenses/gpl-2.0.html
 */

#ifndef OPENCL_SHA256_H
#define	OPENCL_SHA256_H

//Type names definition.
#define uint8_t  unsigned char
#define uint16_t unsigned short
#define uint32_t unsigned int
#define uint64_t unsigned long  //Tip: unsigned long long int failed on compile (AMD).

#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1

//Macros.
#define SWAP(n) \
            (((n) << 24)               | (((n) & 0xff00) << 8) |     \
            (((n) >> 8) & 0xff00)      | ((n) >> 24))

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

/* Macro for get a multiple of a given value */
#define GET_MULTIPLE(dividend, divisor) ((unsigned int) ((dividend / divisor) * divisor))

#if no_byte_addressable(DEVICE_INFO)
    #define PUT         PUTCHAR
    #define BUFFER      ctx->buffer->mem_32
#else
    #define PUT         ATTRIB
    #define BUFFER      ctx->buffer->mem_08
#endif

//SHA256 constants.
#define H0      0x6a09e667U
#define H1      0xbb67ae85U
#define H2      0x3c6ef372U
#define H3      0xa54ff53aU
#define H4      0x510e527fU
#define H5      0x9b05688cU
#define H6      0x1f83d9abU
#define H7      0x5be0cd19U

#endif	/* OPENCL_SHA256_H */