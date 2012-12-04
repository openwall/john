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

#ifndef OPENCL_SHA512_H
#define	OPENCL_SHA512_H

//Type names definition.
#define uint8_t  unsigned char
#define uint16_t unsigned short
#define uint32_t unsigned int
#define uint64_t unsigned long  //Tip: unsigned long long int failed on compile (AMD).

#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1

//Macros.
#define SWAP(n) \
            (((n)             << 56)   | (((n) & 0xff00)     << 40) |   \
            (((n) & 0xff0000) << 24)   | (((n) & 0xff000000) << 8)  |   \
            (((n) >> 8)  & 0xff000000) | (((n) >> 24) & 0xff0000)   |   \
            (((n) >> 40) & 0xff00)     | ((n)  >> 56))

#define SWAP64_V(n)             SWAP(n)

#if gpu_amd(DEVICE_INFO)
        #define Ch(x,y,z)       bitselect(z, y, x)
        #define Maj(x,y,z)      bitselect(x, y, z ^ x)
        #define ror(x, n)       rotate(x, (64UL-n))
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
#define Sigma0(x)               ((ror(x,28UL)) ^ (ror(x,34UL)) ^ (ror(x,39UL)))
#define Sigma1(x)               ((ror(x,14UL)) ^ (ror(x,18UL)) ^ (ror(x,41UL)))
#define sigma0(x)               ((ror(x,1UL))  ^ (ror(x,8UL))  ^ (x>>7))
#define sigma1(x)               ((ror(x,19UL)) ^ (ror(x,61UL)) ^ (x>>6))

/* Macros for reading/writing chars from int32's (from rar_kernel.cl) */
#define GETCHAR(buf, index) ((buf)[(index)])
#define ATTRIB(buf, index, val) (buf)[(index)] = val
#define PUTCHAR(buf, index, val) (buf)[(index)>>2] = ((buf)[(index)>>2] & ~(0xffU << (((index) & 3) << 3))) + ((val) << (((index) & 3) << 3))

/* Macro for get a multiple of a given value */
#define GET_MULTIPLE(dividend, divisor) ((unsigned int) ((dividend / divisor) * divisor))

/* No byte addressable macros */
#if no_byte_addressable(DEVICE_INFO)
    #define PUT         PUTCHAR
    #define BUFFER      ctx->buffer->mem_32
#else
    #define PUT         ATTRIB
    #define BUFFER      ctx->buffer->mem_08
#endif

#endif	/* OPENCL_SHA512_H */

