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
#undef MAX
#undef MIN
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

#define HASH_LOOPS              (7*3*2)
#define TRANSFER_SIZE           (1024 * 64)

#ifdef _OPENCL_COMPILER
#define CLEAR_CTX(i)\
    ctx.buffer[i].mem_64[0] = 0;


#define ROUND_A(a, b, c, d, e, f, g, h, ki, wi)\
	t = (ki) + (wi) + (h) + Sigma1(e) + Ch((e),(f),(g));\
	d += (t); h = (t) + Sigma0(a) + Maj((a), (b), (c));\

#define ROUND_B(a, b, c, d, e, f, g, h, ki, wi, wj, wk, wl, wm)\
	wi = sigma1(wj) + sigma0(wk) + wl + wm;\
	t = (ki) + (wi) + (h) + Sigma1(e) + Ch((e),(f),(g));\
	d += (t); h = (t) + Sigma0(a) + Maj((a), (b), (c));\

#define SHA512_SHORT()\
	ROUND_A(A,B,C,D,E,F,G,H,k[0],W[0])\
	ROUND_A(H,A,B,C,D,E,F,G,k[1],W[1])\
	ROUND_A(G,H,A,B,C,D,E,F,k[2],W[2])\
	ROUND_A(F,G,H,A,B,C,D,E,k[3],W[3])\
	ROUND_A(E,F,G,H,A,B,C,D,k[4],W[4])\
	ROUND_A(D,E,F,G,H,A,B,C,k[5],W[5])\
	ROUND_A(C,D,E,F,G,H,A,B,k[6],W[6])\
	ROUND_A(B,C,D,E,F,G,H,A,k[7],W[7])\
	ROUND_A(A,B,C,D,E,F,G,H,k[8],W[8])\
	ROUND_A(H,A,B,C,D,E,F,G,k[9],W[9])\
	ROUND_A(G,H,A,B,C,D,E,F,k[10],W[10])\
	ROUND_A(F,G,H,A,B,C,D,E,k[11],W[11])\
	ROUND_A(E,F,G,H,A,B,C,D,k[12],W[12])\
	ROUND_A(D,E,F,G,H,A,B,C,k[13],W[13])\
	ROUND_A(C,D,E,F,G,H,A,B,k[14],W[14])\
	ROUND_A(B,C,D,E,F,G,H,A,k[15],W[15])\
	ROUND_B(A,B,C,D,E,F,G,H,k[16],W[0],  W[14],W[1],W[0],W[9])\
	ROUND_B(H,A,B,C,D,E,F,G,k[17],W[1],  W[15],W[2],W[1],W[10])\
	ROUND_B(G,H,A,B,C,D,E,F,k[18],W[2],  W[0],W[3],W[2],W[11])\
	ROUND_B(F,G,H,A,B,C,D,E,k[19],W[3],  W[1],W[4],W[3],W[12])\
	ROUND_B(E,F,G,H,A,B,C,D,k[20],W[4],  W[2],W[5],W[4],W[13])\
	ROUND_B(D,E,F,G,H,A,B,C,k[21],W[5],  W[3],W[6],W[5],W[14])\
	ROUND_B(C,D,E,F,G,H,A,B,k[22],W[6],  W[4],W[7],W[6],W[15])\
	ROUND_B(B,C,D,E,F,G,H,A,k[23],W[7],  W[5],W[8],W[7],W[0])\
	ROUND_B(A,B,C,D,E,F,G,H,k[24],W[8],  W[6],W[9],W[8],W[1])\
	ROUND_B(H,A,B,C,D,E,F,G,k[25],W[9],  W[7],W[10],W[9],W[2])\
	ROUND_B(G,H,A,B,C,D,E,F,k[26],W[10],  W[8],W[11],W[10],W[3])\
	ROUND_B(F,G,H,A,B,C,D,E,k[27],W[11],  W[9],W[12],W[11],W[4])\
	ROUND_B(E,F,G,H,A,B,C,D,k[28],W[12],  W[10],W[13],W[12],W[5])\
	ROUND_B(D,E,F,G,H,A,B,C,k[29],W[13],  W[11],W[14],W[13],W[6])\
	ROUND_B(C,D,E,F,G,H,A,B,k[30],W[14],  W[12],W[15],W[14],W[7])\
	ROUND_B(B,C,D,E,F,G,H,A,k[31],W[15],  W[13],W[0],W[15],W[8])\
	ROUND_B(A,B,C,D,E,F,G,H,k[32],W[0],  W[14],W[1],W[0],W[9])\
	ROUND_B(H,A,B,C,D,E,F,G,k[33],W[1],  W[15],W[2],W[1],W[10])\
	ROUND_B(G,H,A,B,C,D,E,F,k[34],W[2],  W[0],W[3],W[2],W[11])\
	ROUND_B(F,G,H,A,B,C,D,E,k[35],W[3],  W[1],W[4],W[3],W[12])\
	ROUND_B(E,F,G,H,A,B,C,D,k[36],W[4],  W[2],W[5],W[4],W[13])\
	ROUND_B(D,E,F,G,H,A,B,C,k[37],W[5],  W[3],W[6],W[5],W[14])\
	ROUND_B(C,D,E,F,G,H,A,B,k[38],W[6],  W[4],W[7],W[6],W[15])\
	ROUND_B(B,C,D,E,F,G,H,A,k[39],W[7],  W[5],W[8],W[7],W[0])\
	ROUND_B(A,B,C,D,E,F,G,H,k[40],W[8],  W[6],W[9],W[8],W[1])\
	ROUND_B(H,A,B,C,D,E,F,G,k[41],W[9],  W[7],W[10],W[9],W[2])\
	ROUND_B(G,H,A,B,C,D,E,F,k[42],W[10],  W[8],W[11],W[10],W[3])\
	ROUND_B(F,G,H,A,B,C,D,E,k[43],W[11],  W[9],W[12],W[11],W[4])\
	ROUND_B(E,F,G,H,A,B,C,D,k[44],W[12],  W[10],W[13],W[12],W[5])\
	ROUND_B(D,E,F,G,H,A,B,C,k[45],W[13],  W[11],W[14],W[13],W[6])\
	ROUND_B(C,D,E,F,G,H,A,B,k[46],W[14],  W[12],W[15],W[14],W[7])\
	ROUND_B(B,C,D,E,F,G,H,A,k[47],W[15],  W[13],W[0],W[15],W[8])\
	ROUND_B(A,B,C,D,E,F,G,H,k[48],W[0],  W[14],W[1],W[0],W[9])\
	ROUND_B(H,A,B,C,D,E,F,G,k[49],W[1],  W[15],W[2],W[1],W[10])\
	ROUND_B(G,H,A,B,C,D,E,F,k[50],W[2],  W[0],W[3],W[2],W[11])\
	ROUND_B(F,G,H,A,B,C,D,E,k[51],W[3],  W[1],W[4],W[3],W[12])\
	ROUND_B(E,F,G,H,A,B,C,D,k[52],W[4],  W[2],W[5],W[4],W[13])\
	ROUND_B(D,E,F,G,H,A,B,C,k[53],W[5],  W[3],W[6],W[5],W[14])\
	ROUND_B(C,D,E,F,G,H,A,B,k[54],W[6],  W[4],W[7],W[6],W[15])\
	ROUND_B(B,C,D,E,F,G,H,A,k[55],W[7],  W[5],W[8],W[7],W[0])\
	ROUND_B(A,B,C,D,E,F,G,H,k[56],W[8],  W[6],W[9],W[8],W[1])\
	ROUND_B(H,A,B,C,D,E,F,G,k[57],W[9],  W[7],W[10],W[9],W[2])\
	ROUND_B(G,H,A,B,C,D,E,F,k[58],W[10],  W[8],W[11],W[10],W[3])\
	ROUND_B(F,G,H,A,B,C,D,E,k[59],W[11],  W[9],W[12],W[11],W[4])\
	ROUND_B(E,F,G,H,A,B,C,D,k[60],W[12],  W[10],W[13],W[12],W[5])\
	ROUND_B(D,E,F,G,H,A,B,C,k[61],W[13],  W[11],W[14],W[13],W[6])\
	ROUND_B(C,D,E,F,G,H,A,B,k[62],W[14],  W[12],W[15],W[14],W[7])\
	ROUND_B(B,C,D,E,F,G,H,A,k[63],W[15],  W[13],W[0],W[15],W[8])\
	ROUND_B(A,B,C,D,E,F,G,H,k[64],W[0],  W[14],W[1],W[0],W[9])\
	ROUND_B(H,A,B,C,D,E,F,G,k[65],W[1],  W[15],W[2],W[1],W[10])\
	ROUND_B(G,H,A,B,C,D,E,F,k[66],W[2],  W[0],W[3],W[2],W[11])\
	ROUND_B(F,G,H,A,B,C,D,E,k[67],W[3],  W[1],W[4],W[3],W[12])\
	ROUND_B(E,F,G,H,A,B,C,D,k[68],W[4],  W[2],W[5],W[4],W[13])\
	ROUND_B(D,E,F,G,H,A,B,C,k[69],W[5],  W[3],W[6],W[5],W[14])\
	ROUND_B(C,D,E,F,G,H,A,B,k[70],W[6],  W[4],W[7],W[6],W[15])\
	ROUND_B(B,C,D,E,F,G,H,A,k[71],W[7],  W[5],W[8],W[7],W[0])\
	ROUND_B(A,B,C,D,E,F,G,H,k[72],W[8],  W[6],W[9],W[8],W[1])\
	ROUND_B(H,A,B,C,D,E,F,G,k[73],W[9],  W[7],W[10],W[9],W[2])\
	ROUND_B(G,H,A,B,C,D,E,F,k[74],W[10],  W[8],W[11],W[10],W[3])\
	ROUND_B(F,G,H,A,B,C,D,E,k[75],W[11],  W[9],W[12],W[11],W[4])\
	ROUND_B(E,F,G,H,A,B,C,D,k[76],W[12],  W[10],W[13],W[12],W[5])\

#define SHA512()\
	ROUND_A(A,B,C,D,E,F,G,H,k[0],W[0])\
	ROUND_A(H,A,B,C,D,E,F,G,k[1],W[1])\
	ROUND_A(G,H,A,B,C,D,E,F,k[2],W[2])\
	ROUND_A(F,G,H,A,B,C,D,E,k[3],W[3])\
	ROUND_A(E,F,G,H,A,B,C,D,k[4],W[4])\
	ROUND_A(D,E,F,G,H,A,B,C,k[5],W[5])\
	ROUND_A(C,D,E,F,G,H,A,B,k[6],W[6])\
	ROUND_A(B,C,D,E,F,G,H,A,k[7],W[7])\
	ROUND_A(A,B,C,D,E,F,G,H,k[8],W[8])\
	ROUND_A(H,A,B,C,D,E,F,G,k[9],W[9])\
	ROUND_A(G,H,A,B,C,D,E,F,k[10],W[10])\
	ROUND_A(F,G,H,A,B,C,D,E,k[11],W[11])\
	ROUND_A(E,F,G,H,A,B,C,D,k[12],W[12])\
	ROUND_A(D,E,F,G,H,A,B,C,k[13],W[13])\
	ROUND_A(C,D,E,F,G,H,A,B,k[14],W[14])\
	ROUND_A(B,C,D,E,F,G,H,A,k[15],W[15])\
	ROUND_B(A,B,C,D,E,F,G,H,k[16],W[0],  W[14],W[1],W[0],W[9])\
	ROUND_B(H,A,B,C,D,E,F,G,k[17],W[1],  W[15],W[2],W[1],W[10])\
	ROUND_B(G,H,A,B,C,D,E,F,k[18],W[2],  W[0],W[3],W[2],W[11])\
	ROUND_B(F,G,H,A,B,C,D,E,k[19],W[3],  W[1],W[4],W[3],W[12])\
	ROUND_B(E,F,G,H,A,B,C,D,k[20],W[4],  W[2],W[5],W[4],W[13])\
	ROUND_B(D,E,F,G,H,A,B,C,k[21],W[5],  W[3],W[6],W[5],W[14])\
	ROUND_B(C,D,E,F,G,H,A,B,k[22],W[6],  W[4],W[7],W[6],W[15])\
	ROUND_B(B,C,D,E,F,G,H,A,k[23],W[7],  W[5],W[8],W[7],W[0])\
	ROUND_B(A,B,C,D,E,F,G,H,k[24],W[8],  W[6],W[9],W[8],W[1])\
	ROUND_B(H,A,B,C,D,E,F,G,k[25],W[9],  W[7],W[10],W[9],W[2])\
	ROUND_B(G,H,A,B,C,D,E,F,k[26],W[10],  W[8],W[11],W[10],W[3])\
	ROUND_B(F,G,H,A,B,C,D,E,k[27],W[11],  W[9],W[12],W[11],W[4])\
	ROUND_B(E,F,G,H,A,B,C,D,k[28],W[12],  W[10],W[13],W[12],W[5])\
	ROUND_B(D,E,F,G,H,A,B,C,k[29],W[13],  W[11],W[14],W[13],W[6])\
	ROUND_B(C,D,E,F,G,H,A,B,k[30],W[14],  W[12],W[15],W[14],W[7])\
	ROUND_B(B,C,D,E,F,G,H,A,k[31],W[15],  W[13],W[0],W[15],W[8])\
	ROUND_B(A,B,C,D,E,F,G,H,k[32],W[0],  W[14],W[1],W[0],W[9])\
	ROUND_B(H,A,B,C,D,E,F,G,k[33],W[1],  W[15],W[2],W[1],W[10])\
	ROUND_B(G,H,A,B,C,D,E,F,k[34],W[2],  W[0],W[3],W[2],W[11])\
	ROUND_B(F,G,H,A,B,C,D,E,k[35],W[3],  W[1],W[4],W[3],W[12])\
	ROUND_B(E,F,G,H,A,B,C,D,k[36],W[4],  W[2],W[5],W[4],W[13])\
	ROUND_B(D,E,F,G,H,A,B,C,k[37],W[5],  W[3],W[6],W[5],W[14])\
	ROUND_B(C,D,E,F,G,H,A,B,k[38],W[6],  W[4],W[7],W[6],W[15])\
	ROUND_B(B,C,D,E,F,G,H,A,k[39],W[7],  W[5],W[8],W[7],W[0])\
	ROUND_B(A,B,C,D,E,F,G,H,k[40],W[8],  W[6],W[9],W[8],W[1])\
	ROUND_B(H,A,B,C,D,E,F,G,k[41],W[9],  W[7],W[10],W[9],W[2])\
	ROUND_B(G,H,A,B,C,D,E,F,k[42],W[10],  W[8],W[11],W[10],W[3])\
	ROUND_B(F,G,H,A,B,C,D,E,k[43],W[11],  W[9],W[12],W[11],W[4])\
	ROUND_B(E,F,G,H,A,B,C,D,k[44],W[12],  W[10],W[13],W[12],W[5])\
	ROUND_B(D,E,F,G,H,A,B,C,k[45],W[13],  W[11],W[14],W[13],W[6])\
	ROUND_B(C,D,E,F,G,H,A,B,k[46],W[14],  W[12],W[15],W[14],W[7])\
	ROUND_B(B,C,D,E,F,G,H,A,k[47],W[15],  W[13],W[0],W[15],W[8])\
	ROUND_B(A,B,C,D,E,F,G,H,k[48],W[0],  W[14],W[1],W[0],W[9])\
	ROUND_B(H,A,B,C,D,E,F,G,k[49],W[1],  W[15],W[2],W[1],W[10])\
	ROUND_B(G,H,A,B,C,D,E,F,k[50],W[2],  W[0],W[3],W[2],W[11])\
	ROUND_B(F,G,H,A,B,C,D,E,k[51],W[3],  W[1],W[4],W[3],W[12])\
	ROUND_B(E,F,G,H,A,B,C,D,k[52],W[4],  W[2],W[5],W[4],W[13])\
	ROUND_B(D,E,F,G,H,A,B,C,k[53],W[5],  W[3],W[6],W[5],W[14])\
	ROUND_B(C,D,E,F,G,H,A,B,k[54],W[6],  W[4],W[7],W[6],W[15])\
	ROUND_B(B,C,D,E,F,G,H,A,k[55],W[7],  W[5],W[8],W[7],W[0])\
	ROUND_B(A,B,C,D,E,F,G,H,k[56],W[8],  W[6],W[9],W[8],W[1])\
	ROUND_B(H,A,B,C,D,E,F,G,k[57],W[9],  W[7],W[10],W[9],W[2])\
	ROUND_B(G,H,A,B,C,D,E,F,k[58],W[10],  W[8],W[11],W[10],W[3])\
	ROUND_B(F,G,H,A,B,C,D,E,k[59],W[11],  W[9],W[12],W[11],W[4])\
	ROUND_B(E,F,G,H,A,B,C,D,k[60],W[12],  W[10],W[13],W[12],W[5])\
	ROUND_B(D,E,F,G,H,A,B,C,k[61],W[13],  W[11],W[14],W[13],W[6])\
	ROUND_B(C,D,E,F,G,H,A,B,k[62],W[14],  W[12],W[15],W[14],W[7])\
	ROUND_B(B,C,D,E,F,G,H,A,k[63],W[15],  W[13],W[0],W[15],W[8])\
	ROUND_B(A,B,C,D,E,F,G,H,k[64],W[0],  W[14],W[1],W[0],W[9])\
	ROUND_B(H,A,B,C,D,E,F,G,k[65],W[1],  W[15],W[2],W[1],W[10])\
	ROUND_B(G,H,A,B,C,D,E,F,k[66],W[2],  W[0],W[3],W[2],W[11])\
	ROUND_B(F,G,H,A,B,C,D,E,k[67],W[3],  W[1],W[4],W[3],W[12])\
	ROUND_B(E,F,G,H,A,B,C,D,k[68],W[4],  W[2],W[5],W[4],W[13])\
	ROUND_B(D,E,F,G,H,A,B,C,k[69],W[5],  W[3],W[6],W[5],W[14])\
	ROUND_B(C,D,E,F,G,H,A,B,k[70],W[6],  W[4],W[7],W[6],W[15])\
	ROUND_B(B,C,D,E,F,G,H,A,k[71],W[7],  W[5],W[8],W[7],W[0])\
	ROUND_B(A,B,C,D,E,F,G,H,k[72],W[8],  W[6],W[9],W[8],W[1])\
	ROUND_B(H,A,B,C,D,E,F,G,k[73],W[9],  W[7],W[10],W[9],W[2])\
	ROUND_B(G,H,A,B,C,D,E,F,k[74],W[10],  W[8],W[11],W[10],W[3])\
	ROUND_B(F,G,H,A,B,C,D,E,k[75],W[11],  W[9],W[12],W[11],W[4])\
	ROUND_B(E,F,G,H,A,B,C,D,k[76],W[12],  W[10],W[13],W[12],W[5])\
	ROUND_B(D,E,F,G,H,A,B,C,k[77],W[13],  W[11],W[14],W[13],W[6])\
	ROUND_B(C,D,E,F,G,H,A,B,k[78],W[14],  W[12],W[15],W[14],W[7])\
	ROUND_B(B,C,D,E,F,G,H,A,k[79],W[15],  W[13],W[0],W[15],W[8])

#if no_byte_addressable(DEVICE_INFO)
    #define PUT         PUTCHAR
    #define BUFFER      ctx->buffer->mem_32
    #define F_BUFFER    ctx.buffer->mem_32
#else
    #define PUT         ATTRIB
    #define BUFFER      ctx->buffer->mem_08
    #define F_BUFFER    ctx.buffer->mem_08
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
