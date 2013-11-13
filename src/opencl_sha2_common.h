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

#ifndef OPENCL_SHA2_COMMON_H
#define	OPENCL_SHA2_COMMON_H

// Type names definition.
// NOTE: long is always 64-bit in OpenCL, and long long is 128 bit.
#ifdef _OPENCL_COMPILER
	#define uint8_t  unsigned char
	#define uint16_t unsigned short
	#define uint32_t unsigned int
	#define uint64_t unsigned long
#endif

//Functions.
#define MAX(x,y)                ((x) > (y) ? (x) : (y))
#define MIN(x,y)                ((x) < (y) ? (x) : (y))

/* Macros for reading/writing chars from int32's (from rar_kernel.cl) */
#define GETCHAR(buf, index) ((buf)[(index)])
#define ATTRIB(buf, index, val) (buf)[(index)] = val
#if gpu_amd(DEVICE_INFO) || no_byte_addressable(DEVICE_INFO)
#define PUTCHAR(buf, index, val) (buf)[(index)>>2] = ((buf)[(index)>>2] & ~(0xffU << (((index) & 3) << 3))) + ((val) << (((index) & 3) << 3))
#else
#define PUTCHAR(buf, index, val) ((uchar*)(buf))[(index)] = (val)
#endif

/* Macro for get a multiple of a given value */
#define GET_MULTIPLE(dividend, divisor)		((divisor) ? ((dividend / divisor) * divisor) : (dividend))
#define GET_MULTIPLE_BIGGER(dividend, divisor)	(divisor) ? (((dividend + divisor - 1) / divisor) * divisor) : (dividend)

#define HASH_LOOPS              (7*3*2)
#define TRANSFER_SIZE           (1024 * 64)

#ifdef _OPENCL_COMPILER
#if no_byte_addressable(DEVICE_INFO)
    #define PUT         PUTCHAR
    #define BUFFER      ctx->buffer->mem_32
#else
    #define PUT         ATTRIB
    #define BUFFER      ctx->buffer->mem_08
#endif
#endif

#ifndef _OPENCL_COMPILER
/* --
 * Public domain hash function by DJ Bernstein
 * We are hashing almost the entire struct
-- */
int common_salt_hash(void * salt, int salt_size, int salt_hash_size);
#endif

#endif	/* OPENCL_SHA2_COMMON_H */
