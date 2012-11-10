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

__constant uint32_t k[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

inline void init_ctx(sha256_ctx * ctx) {
    ctx->H[0] = 0x6a09e667;
    ctx->H[1] = 0xbb67ae85;
    ctx->H[2] = 0x3c6ef372;
    ctx->H[3] = 0xa54ff53a;
    ctx->H[4] = 0x510e527f;
    ctx->H[5] = 0x9b05688c;
    ctx->H[6] = 0x1f83d9ab;
    ctx->H[7] = 0x5be0cd19;
    ctx->buflen = 0;
}

inline void _memcpy(               uint8_t * dest,
                    __global const uint8_t * src) {
    int i = 0;

    uint32_t * l = (uint32_t *) dest;
    __global uint32_t * s = (__global uint32_t *) src;

    while (i < PLAINTEXT_LENGTH) {
        *l++ = *s++;
        i += 4;
    }
}

inline void sha256_block(sha256_ctx * ctx) {
#define  a   ctx->H[0]
#define  b   ctx->H[1]
#define  c   ctx->H[2]
#define  d   ctx->H[3]
#define  e   ctx->H[4]
#define  f   ctx->H[5]
#define  g   ctx->H[6]
#define  h   ctx->H[7]

    uint32_t t1, t2;
    uint32_t w[16];

    #pragma unroll
    for (int i = 0; i < 16; i++)
        w[i] = SWAP32(ctx->buffer->mem_32[i]);

    #pragma unroll
    for (int i = 0; i < 16; i++) {
        t1 = k[i] + w[i] + h + Sigma1(e) + Ch(e, f, g);
        t2 = Maj(a, b, c) + Sigma0(a);

        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    #pragma unroll
    for (int i = 16; i < 61; i++) {
        w[i & 15] = sigma1(w[(i - 2) & 15]) + sigma0(w[(i - 15) & 15]) + w[(i - 16) & 15] + w[(i - 7) & 15];
        t1 = k[i] + w[i & 15] + h + Sigma1(e) + Ch(e, f, g);
        t2 = Maj(a, b, c) + Sigma0(a);

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

inline void insert_to_buffer(         sha256_ctx    * ctx,
                             __global const uint8_t * string,
                                      const uint32_t  len) {

    _memcpy(ctx->buffer->mem_08, string);
    ctx->buflen += len;
}

inline void ctx_update(         sha256_ctx * ctx,
                       __global uint8_t    * string,
                                uint32_t     len) {

    insert_to_buffer(ctx, string, len);
}

inline void ctx_append_1(sha256_ctx * ctx) {

    uint32_t length = PLAINTEXT_LENGTH;
    uint32_t * l = (uint32_t *) (ctx->buffer->mem_08 + length);

    while (length < 64) {
        *l++ = 0;
        length += 4;
    }
}

inline void ctx_add_length(sha256_ctx * ctx) {

    ctx->buffer[15].mem_32[0] = SWAP32(ctx->buflen * 8);
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