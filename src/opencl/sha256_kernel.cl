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

#define _OPENCL_COMPILER
#include "opencl_rawsha256.h"

inline void init_ctx(sha256_ctx * ctx) {

    ctx->H[0] = H0;
}

inline void _memcpy(               uint8_t * dest,
                    __global const uint8_t * src) {

    uint32_t * l = (uint32_t *) dest;
    __global uint32_t * s = (__global uint32_t *) src;

    #pragma unroll
    for (int i = 0; i < PLAINTEXT_LENGTH; i += 4)
        *l++ = SWAP32(s[i/4]);
}

inline void sha256_block(sha256_ctx * ctx) {
#define a   ctx->H[0]
#define w   ctx->buffer->mem_32

    uint32_t b = H1;
    uint32_t c = H2;
    uint32_t d = H3;
    uint32_t e = H4;
    uint32_t f = H5;
    uint32_t g = H6;
    uint32_t h = H7;
    uint32_t t1;

    // From 0 to 15.
    ROUND_0_TO_15(a, b, c, d, e, f, g, h, k01, w, 0);
    ROUND_0_TO_15(h, a, b, c, d, e, f, g, k02, w, 1);
    ROUND_0_TO_15(g, h, a, b, c, d, e, f, k03, w, 2);
    ROUND_0_TO_15(f, g, h, a, b, c, d, e, k04, w, 3);
    ROUND_0_TO_15(e, f, g, h, a, b, c, d, k05, w, 4);
    ROUND_0_TO_15(d, e, f, g, h, a, b, c, k06, w, 5);
    ROUND_0_TO_15(c, d, e, f, g, h, a, b, k07, w, 6);
    ROUND_0_TO_15(b, c, d, e, f, g, h, a, k08, w, 7);
    ROUND_0_TO_15(a, b, c, d, e, f, g, h, k09, w, 8);
    ROUND_0_TO_15(h, a, b, c, d, e, f, g, k10, w, 9);
    ROUND_0_TO_15(g, h, a, b, c, d, e, f, k11, w, 10);
    ROUND_0_TO_15(f, g, h, a, b, c, d, e, k12, w, 11);
    ROUND_0_TO_15(e, f, g, h, a, b, c, d, k13, w, 12);
    ROUND_0_TO_15(d, e, f, g, h, a, b, c, k14, w, 13);
    ROUND_0_TO_15(c, d, e, f, g, h, a, b, k15, w, 14);
    ROUND_0_TO_15(b, c, d, e, f, g, h, a, k16, w, 15);

    // From 16 to 60 (64 - 4 rounds).
    ROUND_16_TO_END(a, b, c, d, e, f, g, h, k17, w, 16);
    ROUND_16_TO_END(h, a, b, c, d, e, f, g, k18, w, 17);
    ROUND_16_TO_END(g, h, a, b, c, d, e, f, k19, w, 18);
    ROUND_16_TO_END(f, g, h, a, b, c, d, e, k20, w, 19);
    ROUND_16_TO_END(e, f, g, h, a, b, c, d, k21, w, 20);
    ROUND_16_TO_END(d, e, f, g, h, a, b, c, k22, w, 21);
    ROUND_16_TO_END(c, d, e, f, g, h, a, b, k23, w, 22);
    ROUND_16_TO_END(b, c, d, e, f, g, h, a, k24, w, 23);

    ROUND_16_TO_END(a, b, c, d, e, f, g, h, k25, w, 24);
    ROUND_16_TO_END(h, a, b, c, d, e, f, g, k26, w, 25);
    ROUND_16_TO_END(g, h, a, b, c, d, e, f, k27, w, 26);
    ROUND_16_TO_END(f, g, h, a, b, c, d, e, k28, w, 27);
    ROUND_16_TO_END(e, f, g, h, a, b, c, d, k29, w, 28);
    ROUND_16_TO_END(d, e, f, g, h, a, b, c, k30, w, 29);
    ROUND_16_TO_END(c, d, e, f, g, h, a, b, k31, w, 30);
    ROUND_16_TO_END(b, c, d, e, f, g, h, a, k32, w, 31);

    ROUND_16_TO_END(a, b, c, d, e, f, g, h, k33, w, 32);
    ROUND_16_TO_END(h, a, b, c, d, e, f, g, k34, w, 33);
    ROUND_16_TO_END(g, h, a, b, c, d, e, f, k35, w, 34);
    ROUND_16_TO_END(f, g, h, a, b, c, d, e, k36, w, 35);
    ROUND_16_TO_END(e, f, g, h, a, b, c, d, k37, w, 36);
    ROUND_16_TO_END(d, e, f, g, h, a, b, c, k38, w, 37);
    ROUND_16_TO_END(c, d, e, f, g, h, a, b, k39, w, 38);
    ROUND_16_TO_END(b, c, d, e, f, g, h, a, k40, w, 39);

    ROUND_16_TO_END(a, b, c, d, e, f, g, h, k41, w, 40);
    ROUND_16_TO_END(h, a, b, c, d, e, f, g, k42, w, 41);
    ROUND_16_TO_END(g, h, a, b, c, d, e, f, k43, w, 42);
    ROUND_16_TO_END(f, g, h, a, b, c, d, e, k44, w, 43);
    ROUND_16_TO_END(e, f, g, h, a, b, c, d, k45, w, 44);
    ROUND_16_TO_END(d, e, f, g, h, a, b, c, k46, w, 45);
    ROUND_16_TO_END(c, d, e, f, g, h, a, b, k47, w, 46);
    ROUND_16_TO_END(b, c, d, e, f, g, h, a, k48, w, 47);

    ROUND_16_TO_END(a, b, c, d, e, f, g, h, k49, w, 48);
    ROUND_16_TO_END(h, a, b, c, d, e, f, g, k50, w, 49);
    ROUND_16_TO_END(g, h, a, b, c, d, e, f, k51, w, 50);
    ROUND_16_TO_END(f, g, h, a, b, c, d, e, k52, w, 51);
    ROUND_16_TO_END(e, f, g, h, a, b, c, d, k53, w, 52);
    ROUND_16_TO_END(d, e, f, g, h, a, b, c, k54, w, 53);
    ROUND_16_TO_END(c, d, e, f, g, h, a, b, k55, w, 54);
    ROUND_16_TO_END(b, c, d, e, f, g, h, a, k56, w, 55);

    ROUND_16_TO_END(a, b, c, d, e, f, g, h, k57, w, 56);
    ROUND_16_TO_END(h, a, b, c, d, e, f, g, k58, w, 57);
    ROUND_16_TO_END(g, h, a, b, c, d, e, f, k59, w, 58);
    ROUND_16_TO_END(f, g, h, a, b, c, d, e, k60, w, 59);
    ROUND_16_TO_END(e, f, g, h, a, b, c, d, k61, w, 60);

    //Send result back.
    ctx->H[0] = d;
}

inline void insert_to_buffer(         sha256_ctx    * ctx,
                             __global const uint8_t * string,
                                      const uint32_t  len) {

    _memcpy(ctx->buffer->mem_08, string);
    ctx->buflen = len;
}

inline void ctx_update(         sha256_ctx * ctx,
                       __global uint8_t    * string,
                                uint32_t     len) {

    insert_to_buffer(ctx, string, len);
}

inline void ctx_append_1(sha256_ctx * ctx) {

    uint32_t length = PLAINTEXT_LENGTH;
    uint32_t * l = (uint32_t *) (ctx->buffer->mem_08 + length);

    while (length < 60) {
        *l++ = 0;
        length += 4;
    }
}

inline void ctx_add_length(sha256_ctx * ctx) {

    ctx->buffer[15].mem_32[0] = ctx->buflen * 8;
}

inline void finish_ctx(sha256_ctx * ctx) {

    ctx_append_1(ctx);
    ctx_add_length(ctx);
}

inline void sha256_crypt(__global sha256_password * keys_data,
                                  sha256_ctx      * ctx) {
#define pass        keys_data->pass->mem_08
#define passlen     keys_data->length

    init_ctx(ctx);

    ctx_update(ctx, pass, passlen);
    finish_ctx(ctx);

    /* Run the collected hash value through sha256. */
    sha256_block(ctx);
}

__kernel
void kernel_crypt(__global   sha256_password * keys_buffer,
                  __global   uint32_t        * out_buffer) {

    //Compute buffers (on CPU and NVIDIA, better private)
    sha256_ctx     ctx;

    //Get the task to be done
    size_t gid = get_global_id(0);

    //Do the job
    sha256_crypt(&keys_buffer[gid], &ctx);

    //Save parcial results.
    out_buffer[gid] = ctx.H[0];
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