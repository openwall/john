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

#ifndef OPENCL_SHA2_COMMON_H
#define OPENCL_SHA2_COMMON_H

// Type names definition.
// NOTE: long is always 64-bit in OpenCL, and long long is 128 bit.
#ifdef _OPENCL_COMPILER
#include "opencl_misc.h"

// ** Precomputed index to position/values. **
//0:        0                   =>  1
//0: 3      14,28                   =>  2
//0: 7      6,12,18,24,30,36            =>  6
//0: 3,7    2,4,8,10,16,20,22,26,32,34,38,40    => 12
//1:        21                  =>  1
//1: 3      7,35                    =>  2
//1: 7      3,9,15,27,33,39             =>  6
//1: 3,7    1,5,11,13,17,19,23,25,29,31,37,41   => 12
__constant int loop_index[] = {
	0, /* 0,000 */ 7, /* 1,111 */ 3, /* 2,011 */ 5, /* 3,101 */
	3, /* 4,011 */ 7, /* 5,111 */ 1, /* 6,001 */ 6, /* 7,110 */
	3, /* 8,011 */ 5, /* 9,101 */ 3, /*10,011 */ 7, /*11,111 */
	1, /*12,001 */ 7, /*13,111 */ 2, /*14,010 */ 5, /*15,101 */
	3, /*16,011 */ 7, /*17,111 */ 1, /*18,001 */ 7, /*19,111 */
	3, /*20,011 */ 4, /*21,100 */ 3, /*22,011 */ 7, /*23,111 */
	1, /*24,001 */ 7, /*25,111 */ 3, /*26,011 */ 5, /*27,101 */
	2, /*28,010 */ 7, /*29,111 */ 1, /*30,001 */ 7, /*31,111 */
	3, /*32,011 */ 5, /*33,101 */ 3, /*34,011 */ 6, /*35,110 */
	1, /*36,001 */ 7, /*37,111 */ 3, /*38,011 */ 5, /*39,101 */
	3, /*40,011 */ 7,           /*41,111 */
};

__constant int generator_index[] = {
	0,                          /*  0, 000 */
	6,                          /*  6, 001 */
	14,                         /* 14, 010 */
	2,                          /*  2, 011 */
	21,                         /* 21, 100 */
	3,                          /*  3, 101 */
	7,                          /*  7, 110 */
	1                           /*  1, 111 */
};
#endif

#undef USE_BITSELECT            //What used in opencl_misc cannot handle all situations.
#if gpu_amd(DEVICE_INFO)        //At least, it will fail for cpu and nvidia
#define USE_BITSELECT   1
#endif

//Macros.
#ifdef USE_BITSELECT
#define Ch(x, y, z)     bitselect(z, y, x)
#define Maj(x, y, z)    bitselect(x, y, z ^ x)
#else
#if HAVE_LUT3 && BITS_32
#define Ch(x, y, z) lut3(x, y, z, 0xca)
#elif HAVE_ANDNOT
#define Ch(x, y, z) ((x & y) ^ ((~x) & z))
#else
#define Ch(x, y, z) (z ^ (x & (y ^ z)))
#endif

#if HAVE_LUT3 && BITS_32
#define Maj(x, y, z) lut3(x, y, z, 0xe8)
#else
#define Maj(x, y, z) ((x & y) | (z & (x | y)))
#endif
#endif

// Start documenting NVIDIA OpenCL bugs.
///#if gpu_nvidia(DEVICE_INFO)
///#define NVIDIA_STUPID_BUG_1    1
///#endif

// Start documenting AMD OpenCL bugs.
///#if amd_vliw5(DEVICE_INFO) || amd_vliw4(DEVICE_INFO)
///amd_vliw4() is a guess.

///Needed (at least) in 14.9 and 15.7
///TODO: can't remove the [unroll]. (At least) HD 6770.
///#ifdef AMD_STUPID_BUG_1
///  #pragma unroll 2
///#endif
///for (uint i = 16U; i < 80U; i++) {
///#define AMD_STUPID_BUG_1    1

///TODO: can't use a valid command twice on sha256crypt. (At least) HD 6770.
///Fixed (back in 14.12). Kept for future reference.
/// ----------------------
///  #define SWAP32(n)  rotate(n & 0x00FF00FF, 24U) | rotate(n & 0xFF00FF00, 8U)
///  #ifdef AMD_STUPID_BUG_2
///    #define SWAP_V(n)    bitselect(rotate(n, 24U), rotate(n, 8U), 0x00FF00FFU)
/// ----------------------
///#define AMD_STUPID_BUG_2

///TODO: can't use constant. (At least) HD 6770.
///Fixed. Kept for future reference.
/// ----------------------
///inline void sha512_prepare(__constant   sha512_salt     * salt_data,
/// ----------------------
///#define AMD_STUPID_BUG_3
///#endif

//Functions.
/* Macros for reading/writing chars from int32's (from rar_kernel.cl) */
#define ATTRIB(buf, index, val) (buf)[(index)] = val

#if no_byte_addressable(DEVICE_INFO) || (gpu_amd(DEVICE_INFO) && defined(AMD_PUTCHAR_NOCAST))
#define USE_32BITS_FOR_CHAR
#endif

#ifdef USE_32BITS_FOR_CHAR
#define PUT         PUTCHAR
#define BUFFER      ctx->buffer->mem_32
#define F_BUFFER    ctx.buffer->mem_32
#else
#define PUT         ATTRIB
#define BUFFER      ctx->buffer->mem_08
#define F_BUFFER    ctx.buffer->mem_08
#endif
#define TRANSFER_SIZE           (1024 * 64)

#define ROUND_A(A, B, C, D, E, F, G, H, ki, wi)\
    t = (ki) + (wi) + (H) + Sigma1(E) + Ch((E),(F),(G));\
    D += (t); H = (t) + Sigma0(A) + Maj((A), (B), (C));

#define ROUND_B(A, B, C, D, E, F, G, H, ki, wi, wj, wk, wl, wm)\
    wi = (wl) + (wm) + sigma1(wj) + sigma0(wk);\
    t = (ki) + (wi) + (H) + Sigma1(E) + Ch((E),(F),(G));\
    D += (t); H = (t) + Sigma0(A) + Maj((A), (B), (C));

#define SHA256_SHORT()\
    ROUND_A(a, b, c, d, e, f, g, h, k[0],  w[0])\
    ROUND_A(h, a, b, c, d, e, f, g, k[1],  w[1])\
    ROUND_A(g, h, a, b, c, d, e, f, k[2],  w[2])\
    ROUND_A(f, g, h, a, b, c, d, e, k[3],  w[3])\
    ROUND_A(e, f, g, h, a, b, c, d, k[4],  w[4])\
    ROUND_A(d, e, f, g, h, a, b, c, k[5],  w[5])\
    ROUND_A(c, d, e, f, g, h, a, b, k[6],  w[6])\
    ROUND_A(b, c, d, e, f, g, h, a, k[7],  w[7])\
    ROUND_A(a, b, c, d, e, f, g, h, k[8],  w[8])\
    ROUND_A(h, a, b, c, d, e, f, g, k[9],  w[9])\
    ROUND_A(g, h, a, b, c, d, e, f, k[10], w[10])\
    ROUND_A(f, g, h, a, b, c, d, e, k[11], w[11])\
    ROUND_A(e, f, g, h, a, b, c, d, k[12], w[12])\
    ROUND_A(d, e, f, g, h, a, b, c, k[13], w[13])\
    ROUND_A(c, d, e, f, g, h, a, b, k[14], w[14])\
    ROUND_A(b, c, d, e, f, g, h, a, k[15], w[15])\
    ROUND_B(a, b, c, d, e, f, g, h, k[16], w[0],  w[14], w[1],  w[0],  w[9])\
    ROUND_B(h, a, b, c, d, e, f, g, k[17], w[1],  w[15], w[2],  w[1],  w[10])\
    ROUND_B(g, h, a, b, c, d, e, f, k[18], w[2],  w[0],  w[3],  w[2],  w[11])\
    ROUND_B(f, g, h, a, b, c, d, e, k[19], w[3],  w[1],  w[4],  w[3],  w[12])\
    ROUND_B(e, f, g, h, a, b, c, d, k[20], w[4],  w[2],  w[5],  w[4],  w[13])\
    ROUND_B(d, e, f, g, h, a, b, c, k[21], w[5],  w[3],  w[6],  w[5],  w[14])\
    ROUND_B(c, d, e, f, g, h, a, b, k[22], w[6],  w[4],  w[7],  w[6],  w[15])\
    ROUND_B(b, c, d, e, f, g, h, a, k[23], w[7],  w[5],  w[8],  w[7],  w[0])\
    ROUND_B(a, b, c, d, e, f, g, h, k[24], w[8],  w[6],  w[9],  w[8],  w[1])\
    ROUND_B(h, a, b, c, d, e, f, g, k[25], w[9],  w[7],  w[10], w[9],  w[2])\
    ROUND_B(g, h, a, b, c, d, e, f, k[26], w[10], w[8],  w[11], w[10], w[3])\
    ROUND_B(f, g, h, a, b, c, d, e, k[27], w[11], w[9],  w[12], w[11], w[4])\
    ROUND_B(e, f, g, h, a, b, c, d, k[28], w[12], w[10], w[13], w[12], w[5])\
    ROUND_B(d, e, f, g, h, a, b, c, k[29], w[13], w[11], w[14], w[13], w[6])\
    ROUND_B(c, d, e, f, g, h, a, b, k[30], w[14], w[12], w[15], w[14], w[7])\
    ROUND_B(b, c, d, e, f, g, h, a, k[31], w[15], w[13], w[0],  w[15], w[8])\
    ROUND_B(a, b, c, d, e, f, g, h, k[32], w[0],  w[14], w[1],  w[0],  w[9])\
    ROUND_B(h, a, b, c, d, e, f, g, k[33], w[1],  w[15], w[2],  w[1],  w[10])\
    ROUND_B(g, h, a, b, c, d, e, f, k[34], w[2],  w[0],  w[3],  w[2],  w[11])\
    ROUND_B(f, g, h, a, b, c, d, e, k[35], w[3],  w[1],  w[4],  w[3],  w[12])\
    ROUND_B(e, f, g, h, a, b, c, d, k[36], w[4],  w[2],  w[5],  w[4],  w[13])\
    ROUND_B(d, e, f, g, h, a, b, c, k[37], w[5],  w[3],  w[6],  w[5],  w[14])\
    ROUND_B(c, d, e, f, g, h, a, b, k[38], w[6],  w[4],  w[7],  w[6],  w[15])\
    ROUND_B(b, c, d, e, f, g, h, a, k[39], w[7],  w[5],  w[8],  w[7],  w[0])\
    ROUND_B(a, b, c, d, e, f, g, h, k[40], w[8],  w[6],  w[9],  w[8],  w[1])\
    ROUND_B(h, a, b, c, d, e, f, g, k[41], w[9],  w[7],  w[10], w[9],  w[2])\
    ROUND_B(g, h, a, b, c, d, e, f, k[42], w[10], w[8],  w[11], w[10], w[3])\
    ROUND_B(f, g, h, a, b, c, d, e, k[43], w[11], w[9],  w[12], w[11], w[4])\
    ROUND_B(e, f, g, h, a, b, c, d, k[44], w[12], w[10], w[13], w[12], w[5])\
    ROUND_B(d, e, f, g, h, a, b, c, k[45], w[13], w[11], w[14], w[13], w[6])\
    ROUND_B(c, d, e, f, g, h, a, b, k[46], w[14], w[12], w[15], w[14], w[7])\
    ROUND_B(b, c, d, e, f, g, h, a, k[47], w[15], w[13], w[0],  w[15], w[8])\
    ROUND_B(a, b, c, d, e, f, g, h, k[48], w[0],  w[14], w[1],  w[0],  w[9])\
    ROUND_B(h, a, b, c, d, e, f, g, k[49], w[1],  w[15], w[2],  w[1],  w[10])\
    ROUND_B(g, h, a, b, c, d, e, f, k[50], w[2],  w[0],  w[3],  w[2],  w[11])\
    ROUND_B(f, g, h, a, b, c, d, e, k[51], w[3],  w[1],  w[4],  w[3],  w[12])\
    ROUND_B(e, f, g, h, a, b, c, d, k[52], w[4],  w[2],  w[5],  w[4],  w[13])\
    ROUND_B(d, e, f, g, h, a, b, c, k[53], w[5],  w[3],  w[6],  w[5],  w[14])\
    ROUND_B(c, d, e, f, g, h, a, b, k[54], w[6],  w[4],  w[7],  w[6],  w[15])\
    ROUND_B(b, c, d, e, f, g, h, a, k[55], w[7],  w[5],  w[8],  w[7],  w[0])\
    ROUND_B(a, b, c, d, e, f, g, h, k[56], w[8],  w[6],  w[9],  w[8],  w[1])\
    ROUND_B(h, a, b, c, d, e, f, g, k[57], w[9],  w[7],  w[10], w[9],  w[2])\
    ROUND_B(g, h, a, b, c, d, e, f, k[58], w[10], w[8],  w[11], w[10], w[3])\
    ROUND_B(f, g, h, a, b, c, d, e, k[59], w[11], w[9],  w[12], w[11], w[4])\
    ROUND_B(e, f, g, h, a, b, c, d, k[60], w[12], w[10], w[13], w[12], w[5])

#define SHA256()\
    ROUND_A(a, b, c, d, e, f, g, h, k[0],  w[0])\
    ROUND_A(h, a, b, c, d, e, f, g, k[1],  w[1])\
    ROUND_A(g, h, a, b, c, d, e, f, k[2],  w[2])\
    ROUND_A(f, g, h, a, b, c, d, e, k[3],  w[3])\
    ROUND_A(e, f, g, h, a, b, c, d, k[4],  w[4])\
    ROUND_A(d, e, f, g, h, a, b, c, k[5],  w[5])\
    ROUND_A(c, d, e, f, g, h, a, b, k[6],  w[6])\
    ROUND_A(b, c, d, e, f, g, h, a, k[7],  w[7])\
    ROUND_A(a, b, c, d, e, f, g, h, k[8],  w[8])\
    ROUND_A(h, a, b, c, d, e, f, g, k[9],  w[9])\
    ROUND_A(g, h, a, b, c, d, e, f, k[10], w[10])\
    ROUND_A(f, g, h, a, b, c, d, e, k[11], w[11])\
    ROUND_A(e, f, g, h, a, b, c, d, k[12], w[12])\
    ROUND_A(d, e, f, g, h, a, b, c, k[13], w[13])\
    ROUND_A(c, d, e, f, g, h, a, b, k[14], w[14])\
    ROUND_A(b, c, d, e, f, g, h, a, k[15], w[15])\
    ROUND_B(a, b, c, d, e, f, g, h, k[16], w[0],  w[14], w[1],  w[0],  w[9])\
    ROUND_B(h, a, b, c, d, e, f, g, k[17], w[1],  w[15], w[2],  w[1],  w[10])\
    ROUND_B(g, h, a, b, c, d, e, f, k[18], w[2],  w[0],  w[3],  w[2],  w[11])\
    ROUND_B(f, g, h, a, b, c, d, e, k[19], w[3],  w[1],  w[4],  w[3],  w[12])\
    ROUND_B(e, f, g, h, a, b, c, d, k[20], w[4],  w[2],  w[5],  w[4],  w[13])\
    ROUND_B(d, e, f, g, h, a, b, c, k[21], w[5],  w[3],  w[6],  w[5],  w[14])\
    ROUND_B(c, d, e, f, g, h, a, b, k[22], w[6],  w[4],  w[7],  w[6],  w[15])\
    ROUND_B(b, c, d, e, f, g, h, a, k[23], w[7],  w[5],  w[8],  w[7],  w[0])\
    ROUND_B(a, b, c, d, e, f, g, h, k[24], w[8],  w[6],  w[9],  w[8],  w[1])\
    ROUND_B(h, a, b, c, d, e, f, g, k[25], w[9],  w[7],  w[10], w[9],  w[2])\
    ROUND_B(g, h, a, b, c, d, e, f, k[26], w[10], w[8],  w[11], w[10], w[3])\
    ROUND_B(f, g, h, a, b, c, d, e, k[27], w[11], w[9],  w[12], w[11], w[4])\
    ROUND_B(e, f, g, h, a, b, c, d, k[28], w[12], w[10], w[13], w[12], w[5])\
    ROUND_B(d, e, f, g, h, a, b, c, k[29], w[13], w[11], w[14], w[13], w[6])\
    ROUND_B(c, d, e, f, g, h, a, b, k[30], w[14], w[12], w[15], w[14], w[7])\
    ROUND_B(b, c, d, e, f, g, h, a, k[31], w[15], w[13], w[0],  w[15], w[8])\
    ROUND_B(a, b, c, d, e, f, g, h, k[32], w[0],  w[14], w[1],  w[0],  w[9])\
    ROUND_B(h, a, b, c, d, e, f, g, k[33], w[1],  w[15], w[2],  w[1],  w[10])\
    ROUND_B(g, h, a, b, c, d, e, f, k[34], w[2],  w[0],  w[3],  w[2],  w[11])\
    ROUND_B(f, g, h, a, b, c, d, e, k[35], w[3],  w[1],  w[4],  w[3],  w[12])\
    ROUND_B(e, f, g, h, a, b, c, d, k[36], w[4],  w[2],  w[5],  w[4],  w[13])\
    ROUND_B(d, e, f, g, h, a, b, c, k[37], w[5],  w[3],  w[6],  w[5],  w[14])\
    ROUND_B(c, d, e, f, g, h, a, b, k[38], w[6],  w[4],  w[7],  w[6],  w[15])\
    ROUND_B(b, c, d, e, f, g, h, a, k[39], w[7],  w[5],  w[8],  w[7],  w[0])\
    ROUND_B(a, b, c, d, e, f, g, h, k[40], w[8],  w[6],  w[9],  w[8],  w[1])\
    ROUND_B(h, a, b, c, d, e, f, g, k[41], w[9],  w[7],  w[10], w[9],  w[2])\
    ROUND_B(g, h, a, b, c, d, e, f, k[42], w[10], w[8],  w[11], w[10], w[3])\
    ROUND_B(f, g, h, a, b, c, d, e, k[43], w[11], w[9],  w[12], w[11], w[4])\
    ROUND_B(e, f, g, h, a, b, c, d, k[44], w[12], w[10], w[13], w[12], w[5])\
    ROUND_B(d, e, f, g, h, a, b, c, k[45], w[13], w[11], w[14], w[13], w[6])\
    ROUND_B(c, d, e, f, g, h, a, b, k[46], w[14], w[12], w[15], w[14], w[7])\
    ROUND_B(b, c, d, e, f, g, h, a, k[47], w[15], w[13], w[0],  w[15], w[8])\
    ROUND_B(a, b, c, d, e, f, g, h, k[48], w[0],  w[14], w[1],  w[0],  w[9])\
    ROUND_B(h, a, b, c, d, e, f, g, k[49], w[1],  w[15], w[2],  w[1],  w[10])\
    ROUND_B(g, h, a, b, c, d, e, f, k[50], w[2],  w[0],  w[3],  w[2],  w[11])\
    ROUND_B(f, g, h, a, b, c, d, e, k[51], w[3],  w[1],  w[4],  w[3],  w[12])\
    ROUND_B(e, f, g, h, a, b, c, d, k[52], w[4],  w[2],  w[5],  w[4],  w[13])\
    ROUND_B(d, e, f, g, h, a, b, c, k[53], w[5],  w[3],  w[6],  w[5],  w[14])\
    ROUND_B(c, d, e, f, g, h, a, b, k[54], w[6],  w[4],  w[7],  w[6],  w[15])\
    ROUND_B(b, c, d, e, f, g, h, a, k[55], w[7],  w[5],  w[8],  w[7],  w[0])\
    ROUND_B(a, b, c, d, e, f, g, h, k[56], w[8],  w[6],  w[9],  w[8],  w[1])\
    ROUND_B(h, a, b, c, d, e, f, g, k[57], w[9],  w[7],  w[10], w[9],  w[2])\
    ROUND_B(g, h, a, b, c, d, e, f, k[58], w[10], w[8],  w[11], w[10], w[3])\
    ROUND_B(f, g, h, a, b, c, d, e, k[59], w[11], w[9],  w[12], w[11], w[4])\
    ROUND_B(e, f, g, h, a, b, c, d, k[60], w[12], w[10], w[13], w[12], w[5])\
    ROUND_B(d, e, f, g, h, a, b, c, k[61], w[13], w[11], w[14], w[13], w[6])\
    ROUND_B(c, d, e, f, g, h, a, b, k[62], w[14], w[12], w[15], w[14], w[7])\
    ROUND_B(b, c, d, e, f, g, h, a, k[63], w[15], w[13], w[0],  w[15], w[8])

#define SHA512_SHORT()\
    ROUND_A(a, b, c, d, e, f, g, h, k[0],  w[0])\
    ROUND_A(h, a, b, c, d, e, f, g, k[1],  w[1])\
    ROUND_A(g, h, a, b, c, d, e, f, k[2],  w[2])\
    ROUND_A(f, g, h, a, b, c, d, e, k[3],  w[3])\
    ROUND_A(e, f, g, h, a, b, c, d, k[4],  w[4])\
    ROUND_A(d, e, f, g, h, a, b, c, k[5],  w[5])\
    ROUND_A(c, d, e, f, g, h, a, b, k[6],  w[6])\
    ROUND_A(b, c, d, e, f, g, h, a, k[7],  w[7])\
    ROUND_A(a, b, c, d, e, f, g, h, k[8],  w[8])\
    ROUND_A(h, a, b, c, d, e, f, g, k[9],  w[9])\
    ROUND_A(g, h, a, b, c, d, e, f, k[10], w[10])\
    ROUND_A(f, g, h, a, b, c, d, e, k[11], w[11])\
    ROUND_A(e, f, g, h, a, b, c, d, k[12], w[12])\
    ROUND_A(d, e, f, g, h, a, b, c, k[13], w[13])\
    ROUND_A(c, d, e, f, g, h, a, b, k[14], w[14])\
    ROUND_A(b, c, d, e, f, g, h, a, k[15], w[15])\
    ROUND_B(a, b, c, d, e, f, g, h, k[16], w[0],  w[14], w[1],  w[0],  w[9])\
    ROUND_B(h, a, b, c, d, e, f, g, k[17], w[1],  w[15], w[2],  w[1],  w[10])\
    ROUND_B(g, h, a, b, c, d, e, f, k[18], w[2],  w[0],  w[3],  w[2],  w[11])\
    ROUND_B(f, g, h, a, b, c, d, e, k[19], w[3],  w[1],  w[4],  w[3],  w[12])\
    ROUND_B(e, f, g, h, a, b, c, d, k[20], w[4],  w[2],  w[5],  w[4],  w[13])\
    ROUND_B(d, e, f, g, h, a, b, c, k[21], w[5],  w[3],  w[6],  w[5],  w[14])\
    ROUND_B(c, d, e, f, g, h, a, b, k[22], w[6],  w[4],  w[7],  w[6],  w[15])\
    ROUND_B(b, c, d, e, f, g, h, a, k[23], w[7],  w[5],  w[8],  w[7],  w[0])\
    ROUND_B(a, b, c, d, e, f, g, h, k[24], w[8],  w[6],  w[9],  w[8],  w[1])\
    ROUND_B(h, a, b, c, d, e, f, g, k[25], w[9],  w[7],  w[10], w[9],  w[2])\
    ROUND_B(g, h, a, b, c, d, e, f, k[26], w[10], w[8],  w[11], w[10], w[3])\
    ROUND_B(f, g, h, a, b, c, d, e, k[27], w[11], w[9],  w[12], w[11], w[4])\
    ROUND_B(e, f, g, h, a, b, c, d, k[28], w[12], w[10], w[13], w[12], w[5])\
    ROUND_B(d, e, f, g, h, a, b, c, k[29], w[13], w[11], w[14], w[13], w[6])\
    ROUND_B(c, d, e, f, g, h, a, b, k[30], w[14], w[12], w[15], w[14], w[7])\
    ROUND_B(b, c, d, e, f, g, h, a, k[31], w[15], w[13], w[0],  w[15], w[8])\
    ROUND_B(a, b, c, d, e, f, g, h, k[32], w[0],  w[14], w[1],  w[0],  w[9])\
    ROUND_B(h, a, b, c, d, e, f, g, k[33], w[1],  w[15], w[2],  w[1],  w[10])\
    ROUND_B(g, h, a, b, c, d, e, f, k[34], w[2],  w[0],  w[3],  w[2],  w[11])\
    ROUND_B(f, g, h, a, b, c, d, e, k[35], w[3],  w[1],  w[4],  w[3],  w[12])\
    ROUND_B(e, f, g, h, a, b, c, d, k[36], w[4],  w[2],  w[5],  w[4],  w[13])\
    ROUND_B(d, e, f, g, h, a, b, c, k[37], w[5],  w[3],  w[6],  w[5],  w[14])\
    ROUND_B(c, d, e, f, g, h, a, b, k[38], w[6],  w[4],  w[7],  w[6],  w[15])\
    ROUND_B(b, c, d, e, f, g, h, a, k[39], w[7],  w[5],  w[8],  w[7],  w[0])\
    ROUND_B(a, b, c, d, e, f, g, h, k[40], w[8],  w[6],  w[9],  w[8],  w[1])\
    ROUND_B(h, a, b, c, d, e, f, g, k[41], w[9],  w[7],  w[10], w[9],  w[2])\
    ROUND_B(g, h, a, b, c, d, e, f, k[42], w[10], w[8],  w[11], w[10], w[3])\
    ROUND_B(f, g, h, a, b, c, d, e, k[43], w[11], w[9],  w[12], w[11], w[4])\
    ROUND_B(e, f, g, h, a, b, c, d, k[44], w[12], w[10], w[13], w[12], w[5])\
    ROUND_B(d, e, f, g, h, a, b, c, k[45], w[13], w[11], w[14], w[13], w[6])\
    ROUND_B(c, d, e, f, g, h, a, b, k[46], w[14], w[12], w[15], w[14], w[7])\
    ROUND_B(b, c, d, e, f, g, h, a, k[47], w[15], w[13], w[0],  w[15], w[8])\
    ROUND_B(a, b, c, d, e, f, g, h, k[48], w[0],  w[14], w[1],  w[0],  w[9])\
    ROUND_B(h, a, b, c, d, e, f, g, k[49], w[1],  w[15], w[2],  w[1],  w[10])\
    ROUND_B(g, h, a, b, c, d, e, f, k[50], w[2],  w[0],  w[3],  w[2],  w[11])\
    ROUND_B(f, g, h, a, b, c, d, e, k[51], w[3],  w[1],  w[4],  w[3],  w[12])\
    ROUND_B(e, f, g, h, a, b, c, d, k[52], w[4],  w[2],  w[5],  w[4],  w[13])\
    ROUND_B(d, e, f, g, h, a, b, c, k[53], w[5],  w[3],  w[6],  w[5],  w[14])\
    ROUND_B(c, d, e, f, g, h, a, b, k[54], w[6],  w[4],  w[7],  w[6],  w[15])\
    ROUND_B(b, c, d, e, f, g, h, a, k[55], w[7],  w[5],  w[8],  w[7],  w[0])\
    ROUND_B(a, b, c, d, e, f, g, h, k[56], w[8],  w[6],  w[9],  w[8],  w[1])\
    ROUND_B(h, a, b, c, d, e, f, g, k[57], w[9],  w[7],  w[10], w[9],  w[2])\
    ROUND_B(g, h, a, b, c, d, e, f, k[58], w[10], w[8],  w[11], w[10], w[3])\
    ROUND_B(f, g, h, a, b, c, d, e, k[59], w[11], w[9],  w[12], w[11], w[4])\
    ROUND_B(e, f, g, h, a, b, c, d, k[60], w[12], w[10], w[13], w[12], w[5])\
    ROUND_B(d, e, f, g, h, a, b, c, k[61], w[13], w[11], w[14], w[13], w[6])\
    ROUND_B(c, d, e, f, g, h, a, b, k[62], w[14], w[12], w[15], w[14], w[7])\
    ROUND_B(b, c, d, e, f, g, h, a, k[63], w[15], w[13], w[0],  w[15], w[8])\
    ROUND_B(a, b, c, d, e, f, g, h, k[64], w[0],  w[14], w[1],  w[0],  w[9])\
    ROUND_B(h, a, b, c, d, e, f, g, k[65], w[1],  w[15], w[2],  w[1],  w[10])\
    ROUND_B(g, h, a, b, c, d, e, f, k[66], w[2],  w[0],  w[3],  w[2],  w[11])\
    ROUND_B(f, g, h, a, b, c, d, e, k[67], w[3],  w[1],  w[4],  w[3],  w[12])\
    ROUND_B(e, f, g, h, a, b, c, d, k[68], w[4],  w[2],  w[5],  w[4],  w[13])\
    ROUND_B(d, e, f, g, h, a, b, c, k[69], w[5],  w[3],  w[6],  w[5],  w[14])\
    ROUND_B(c, d, e, f, g, h, a, b, k[70], w[6],  w[4],  w[7],  w[6],  w[15])\
    ROUND_B(b, c, d, e, f, g, h, a, k[71], w[7],  w[5],  w[8],  w[7],  w[0])\
    ROUND_B(a, b, c, d, e, f, g, h, k[72], w[8],  w[6],  w[9],  w[8],  w[1])\
    ROUND_B(h, a, b, c, d, e, f, g, k[73], w[9],  w[7],  w[10], w[9],  w[2])\
    ROUND_B(g, h, a, b, c, d, e, f, k[74], w[10], w[8],  w[11], w[10], w[3])\
    ROUND_B(f, g, h, a, b, c, d, e, k[75], w[11], w[9],  w[12], w[11], w[4])\
    ROUND_B(e, f, g, h, a, b, c, d, k[76], w[12], w[10], w[13], w[12], w[5])

#define SHA512()\
    ROUND_A(a, b, c, d, e, f, g, h, k[0],  w[0])\
    ROUND_A(h, a, b, c, d, e, f, g, k[1],  w[1])\
    ROUND_A(g, h, a, b, c, d, e, f, k[2],  w[2])\
    ROUND_A(f, g, h, a, b, c, d, e, k[3],  w[3])\
    ROUND_A(e, f, g, h, a, b, c, d, k[4],  w[4])\
    ROUND_A(d, e, f, g, h, a, b, c, k[5],  w[5])\
    ROUND_A(c, d, e, f, g, h, a, b, k[6],  w[6])\
    ROUND_A(b, c, d, e, f, g, h, a, k[7],  w[7])\
    ROUND_A(a, b, c, d, e, f, g, h, k[8],  w[8])\
    ROUND_A(h, a, b, c, d, e, f, g, k[9],  w[9])\
    ROUND_A(g, h, a, b, c, d, e, f, k[10], w[10])\
    ROUND_A(f, g, h, a, b, c, d, e, k[11], w[11])\
    ROUND_A(e, f, g, h, a, b, c, d, k[12], w[12])\
    ROUND_A(d, e, f, g, h, a, b, c, k[13], w[13])\
    ROUND_A(c, d, e, f, g, h, a, b, k[14], w[14])\
    ROUND_A(b, c, d, e, f, g, h, a, k[15], w[15])\
    ROUND_B(a, b, c, d, e, f, g, h, k[16], w[0],  w[14], w[1],  w[0],  w[9])\
    ROUND_B(h, a, b, c, d, e, f, g, k[17], w[1],  w[15], w[2],  w[1],  w[10])\
    ROUND_B(g, h, a, b, c, d, e, f, k[18], w[2],  w[0],  w[3],  w[2],  w[11])\
    ROUND_B(f, g, h, a, b, c, d, e, k[19], w[3],  w[1],  w[4],  w[3],  w[12])\
    ROUND_B(e, f, g, h, a, b, c, d, k[20], w[4],  w[2],  w[5],  w[4],  w[13])\
    ROUND_B(d, e, f, g, h, a, b, c, k[21], w[5],  w[3],  w[6],  w[5],  w[14])\
    ROUND_B(c, d, e, f, g, h, a, b, k[22], w[6],  w[4],  w[7],  w[6],  w[15])\
    ROUND_B(b, c, d, e, f, g, h, a, k[23], w[7],  w[5],  w[8],  w[7],  w[0])\
    ROUND_B(a, b, c, d, e, f, g, h, k[24], w[8],  w[6],  w[9],  w[8],  w[1])\
    ROUND_B(h, a, b, c, d, e, f, g, k[25], w[9],  w[7],  w[10], w[9],  w[2])\
    ROUND_B(g, h, a, b, c, d, e, f, k[26], w[10], w[8],  w[11], w[10], w[3])\
    ROUND_B(f, g, h, a, b, c, d, e, k[27], w[11], w[9],  w[12], w[11], w[4])\
    ROUND_B(e, f, g, h, a, b, c, d, k[28], w[12], w[10], w[13], w[12], w[5])\
    ROUND_B(d, e, f, g, h, a, b, c, k[29], w[13], w[11], w[14], w[13], w[6])\
    ROUND_B(c, d, e, f, g, h, a, b, k[30], w[14], w[12], w[15], w[14], w[7])\
    ROUND_B(b, c, d, e, f, g, h, a, k[31], w[15], w[13], w[0],  w[15], w[8])\
    ROUND_B(a, b, c, d, e, f, g, h, k[32], w[0],  w[14], w[1],  w[0],  w[9])\
    ROUND_B(h, a, b, c, d, e, f, g, k[33], w[1],  w[15], w[2],  w[1],  w[10])\
    ROUND_B(g, h, a, b, c, d, e, f, k[34], w[2],  w[0],  w[3],  w[2],  w[11])\
    ROUND_B(f, g, h, a, b, c, d, e, k[35], w[3],  w[1],  w[4],  w[3],  w[12])\
    ROUND_B(e, f, g, h, a, b, c, d, k[36], w[4],  w[2],  w[5],  w[4],  w[13])\
    ROUND_B(d, e, f, g, h, a, b, c, k[37], w[5],  w[3],  w[6],  w[5],  w[14])\
    ROUND_B(c, d, e, f, g, h, a, b, k[38], w[6],  w[4],  w[7],  w[6],  w[15])\
    ROUND_B(b, c, d, e, f, g, h, a, k[39], w[7],  w[5],  w[8],  w[7],  w[0])\
    ROUND_B(a, b, c, d, e, f, g, h, k[40], w[8],  w[6],  w[9],  w[8],  w[1])\
    ROUND_B(h, a, b, c, d, e, f, g, k[41], w[9],  w[7],  w[10], w[9],  w[2])\
    ROUND_B(g, h, a, b, c, d, e, f, k[42], w[10], w[8],  w[11], w[10], w[3])\
    ROUND_B(f, g, h, a, b, c, d, e, k[43], w[11], w[9],  w[12], w[11], w[4])\
    ROUND_B(e, f, g, h, a, b, c, d, k[44], w[12], w[10], w[13], w[12], w[5])\
    ROUND_B(d, e, f, g, h, a, b, c, k[45], w[13], w[11], w[14], w[13], w[6])\
    ROUND_B(c, d, e, f, g, h, a, b, k[46], w[14], w[12], w[15], w[14], w[7])\
    ROUND_B(b, c, d, e, f, g, h, a, k[47], w[15], w[13], w[0],  w[15], w[8])\
    ROUND_B(a, b, c, d, e, f, g, h, k[48], w[0],  w[14], w[1],  w[0],  w[9])\
    ROUND_B(h, a, b, c, d, e, f, g, k[49], w[1],  w[15], w[2],  w[1],  w[10])\
    ROUND_B(g, h, a, b, c, d, e, f, k[50], w[2],  w[0],  w[3],  w[2],  w[11])\
    ROUND_B(f, g, h, a, b, c, d, e, k[51], w[3],  w[1],  w[4],  w[3],  w[12])\
    ROUND_B(e, f, g, h, a, b, c, d, k[52], w[4],  w[2],  w[5],  w[4],  w[13])\
    ROUND_B(d, e, f, g, h, a, b, c, k[53], w[5],  w[3],  w[6],  w[5],  w[14])\
    ROUND_B(c, d, e, f, g, h, a, b, k[54], w[6],  w[4],  w[7],  w[6],  w[15])\
    ROUND_B(b, c, d, e, f, g, h, a, k[55], w[7],  w[5],  w[8],  w[7],  w[0])\
    ROUND_B(a, b, c, d, e, f, g, h, k[56], w[8],  w[6],  w[9],  w[8],  w[1])\
    ROUND_B(h, a, b, c, d, e, f, g, k[57], w[9],  w[7],  w[10], w[9],  w[2])\
    ROUND_B(g, h, a, b, c, d, e, f, k[58], w[10], w[8],  w[11], w[10], w[3])\
    ROUND_B(f, g, h, a, b, c, d, e, k[59], w[11], w[9],  w[12], w[11], w[4])\
    ROUND_B(e, f, g, h, a, b, c, d, k[60], w[12], w[10], w[13], w[12], w[5])\
    ROUND_B(d, e, f, g, h, a, b, c, k[61], w[13], w[11], w[14], w[13], w[6])\
    ROUND_B(c, d, e, f, g, h, a, b, k[62], w[14], w[12], w[15], w[14], w[7])\
    ROUND_B(b, c, d, e, f, g, h, a, k[63], w[15], w[13], w[0],  w[15], w[8])\
    ROUND_B(a, b, c, d, e, f, g, h, k[64], w[0],  w[14], w[1],  w[0],  w[9])\
    ROUND_B(h, a, b, c, d, e, f, g, k[65], w[1],  w[15], w[2],  w[1],  w[10])\
    ROUND_B(g, h, a, b, c, d, e, f, k[66], w[2],  w[0],  w[3],  w[2],  w[11])\
    ROUND_B(f, g, h, a, b, c, d, e, k[67], w[3],  w[1],  w[4],  w[3],  w[12])\
    ROUND_B(e, f, g, h, a, b, c, d, k[68], w[4],  w[2],  w[5],  w[4],  w[13])\
    ROUND_B(d, e, f, g, h, a, b, c, k[69], w[5],  w[3],  w[6],  w[5],  w[14])\
    ROUND_B(c, d, e, f, g, h, a, b, k[70], w[6],  w[4],  w[7],  w[6],  w[15])\
    ROUND_B(b, c, d, e, f, g, h, a, k[71], w[7],  w[5],  w[8],  w[7],  w[0])\
    ROUND_B(a, b, c, d, e, f, g, h, k[72], w[8],  w[6],  w[9],  w[8],  w[1])\
    ROUND_B(h, a, b, c, d, e, f, g, k[73], w[9],  w[7],  w[10], w[9],  w[2])\
    ROUND_B(g, h, a, b, c, d, e, f, k[74], w[10], w[8],  w[11], w[10], w[3])\
    ROUND_B(f, g, h, a, b, c, d, e, k[75], w[11], w[9],  w[12], w[11], w[4])\
    ROUND_B(e, f, g, h, a, b, c, d, k[76], w[12], w[10], w[13], w[12], w[5])\
    ROUND_B(d, e, f, g, h, a, b, c, k[77], w[13], w[11], w[14], w[13], w[6])\
    ROUND_B(c, d, e, f, g, h, a, b, k[78], w[14], w[12], w[15], w[14], w[7])\
    ROUND_B(b, c, d, e, f, g, h, a, k[79], w[15], w[13], w[0],  w[15], w[8])

#ifndef _OPENCL_COMPILER
/* --
 * Public domain hash function by DJ Bernstein
 * We are hashing almost the entire struct
-- */
int common_salt_hash(void *salt, int salt_size, int salt_hash_size);
#endif

#endif                          /* OPENCL_SHA2_COMMON_H */
