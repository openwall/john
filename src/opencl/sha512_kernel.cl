/*
 * Developed by Claudio André <claudio.andre at correios.net.br> in 2012
 *
 * More information at http://openwall.info/wiki/john/OpenCL-RAWSHA-512
 * More information at http://openwall.info/wiki/john/OpenCL-XSHA-512
 *
 * Copyright (c) 2012 Claudio André <claudio.andre at correios.net.br>
 * This program comes with ABSOLUTELY NO WARRANTY; express or implied.
 *
 * This is free software, and you are welcome to redistribute it
 * under certain conditions; as expressed here
 * http://www.gnu.org/licenses/gpl-2.0.html
 */

#include "opencl_rawsha512.h"

inline void _memcpy(               uint32_t * dest,
                    __global const uint32_t * src,
                             const uint32_t   len) {

    for (uint32_t i = 0; i < len; i += 4)
        *dest++ = *src++;
}

#define ROUND_A(a, b, c, d, e, f, g, h, ki, wi)\
	t = (ki) + (wi) + (h) + Sigma1(e) + Ch((e),(f),(g));\
	d += (t); h = (t) + Sigma0(a) + Maj((a), (b), (c));\

#define ROUND_B(a, b, c, d, e, f, g, h, ki, wi, wj, wk, wl, wm)\
	wi = sigma1(wj) + sigma0(wk) + wl + wm;\
	t = (ki) + (wi) + (h) + Sigma1(e) + Ch((e),(f),(g));\
	d += (t); h = (t) + Sigma0(a) + Maj((a), (b), (c));\

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
	//ROUND_B(D,E,F,G,H,A,B,C,k[77],W[13],  W[11],W[14],W[13],W[6])\
	//ROUND_B(C,D,E,F,G,H,A,B,k[78],W[14],  W[12],W[15],W[14],W[7])\
	//ROUND_B(B,C,D,E,F,G,H,A,k[79],W[15],  W[13],W[0],W[15],W[8])

inline void sha512_block(sha512_ctx * ctx) {
    uint64_t A = H0;
    uint64_t B = H1;
    uint64_t C = H2;
    uint64_t D = H3;
    uint64_t E = H4;
    uint64_t F = H5;
    uint64_t G = H6;
    uint64_t H = H7;
    uint64_t t;
    uint64_t W[16];

    #pragma unroll
    for (int i = 0; i < 15; i++)
        W[i] = SWAP64(ctx->buffer[i].mem_64[0]);
    W[15] = (uint64_t) (ctx->buflen * 8);

    /* Do the job. */
    SHA512()

    /* Put checksum in context given as argument. */
    ctx->H[0] = D;
}

#define CLEAR_CTX(i)\
    ctx.buffer[i].mem_64[0] = 0;

__kernel
void kernel_crypt_raw(__global   const uint32_t  * keys_buffer,
                      __global   const uint32_t  * index,
                      __global   uint32_t        * out_buffer) {

    //Compute buffers (on CPU and NVIDIA, better private)
    sha512_ctx     ctx;

    //Get the task to be done
    size_t gid = get_global_id(0);

    //Get position and length of informed key.
    uint32_t base = index[gid];
    ctx.buflen = base & 63;

    //Ajust keys to it start position.
    keys_buffer += (base >> 6);

    //Clear the buffer.
    CLEAR_CTX(0) \
    CLEAR_CTX(1) \
    CLEAR_CTX(2) \
    CLEAR_CTX(3) \
    CLEAR_CTX(4) \
    CLEAR_CTX(5) \
    CLEAR_CTX(6) \
    CLEAR_CTX(7) \
    CLEAR_CTX(8) \
    CLEAR_CTX(9) \
    CLEAR_CTX(10) \
    CLEAR_CTX(11) \
    CLEAR_CTX(12) \
    CLEAR_CTX(13) \
    CLEAR_CTX(14)

    //Get password.
    _memcpy(ctx.buffer->mem_32, keys_buffer, ctx.buflen);

    //Do the job
    PUT(F_BUFFER, ctx.buflen, 0x80);
    CLEAR_BUFFER_64_FAST(ctx.buffer->mem_64, ctx.buflen + 1);

    /* Run the collected hash value through SHA512. */
    sha512_block(&ctx);

    //Save parcial results.
    out_buffer[gid] = (uint32_t) ctx.H[0];
}

__kernel
void kernel_crypt_xsha(__constant sha512_salt     * salt,
                       __global   const uint32_t  * keys_buffer,
                       __global   const uint32_t  * index,
                       __global   uint32_t        * out_buffer) {

    //Compute buffers (on CPU and NVIDIA, better private)
    sha512_ctx     ctx;

    //Get the task to be done
    size_t gid = get_global_id(0);

    //Get position and length of informed key.
    uint32_t base = index[gid];
    ctx.buflen = base & 63;

    //Ajust keys to it start position.
    keys_buffer += (base >> 6);

    //Clear the buffer.
    CLEAR_CTX(0) \
    CLEAR_CTX(1) \
    CLEAR_CTX(2) \
    CLEAR_CTX(3) \
    CLEAR_CTX(4) \
    CLEAR_CTX(5) \
    CLEAR_CTX(6) \
    CLEAR_CTX(7) \
    CLEAR_CTX(8) \
    CLEAR_CTX(9) \
    CLEAR_CTX(10) \
    CLEAR_CTX(11) \
    CLEAR_CTX(12) \
    CLEAR_CTX(13) \
    CLEAR_CTX(14)

    //Get salt information.
    ctx.buffer->mem_32[0] = salt->salt;

    //Get password.
    _memcpy(ctx.buffer->mem_32 + 1, keys_buffer, ctx.buflen);
    ctx.buflen += SALT_SIZE_X;

    //Do the job
    PUT(F_BUFFER, ctx.buflen, 0x80);
    CLEAR_BUFFER_64_FAST(ctx.buffer->mem_64, ctx.buflen + 1);

    /* Run the collected hash value through SHA512. */
    sha512_block(&ctx);

    //Save parcial results.
    out_buffer[gid] = (uint32_t) ctx.H[0];
}

__kernel
void kernel_cmp(__global   uint32_t        * partial_hash,
                __constant uint32_t        * partial_binary,
                __global   int             * result) {

    //Get the task to be done
    size_t gid = get_global_id(0);

    //Compare with partial computed hash.
    if (*partial_binary == partial_hash[gid]) {
        //Barrier point. FIX IT
        *result = 1;
    }
}
