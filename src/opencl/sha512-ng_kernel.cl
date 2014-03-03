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

#include "opencl_rawsha512-ng.h"

inline void _memcpy(               uint32_t * dest,
                    __global const uint32_t * src,
                             const uint32_t   len) {

    for (uint32_t i = 0; i < len; i += 4)
        *dest++ = *src++;
}

inline void sha512_block(sha512_ctx * ctx) {
    uint64_t a = H0;
    uint64_t b = H1;
    uint64_t c = H2;
    uint64_t d = H3;
    uint64_t e = H4;
    uint64_t f = H5;
    uint64_t g = H6;
    uint64_t h = H7;
    uint64_t t1, t2;
    uint64_t w[16];

    #pragma unroll
    for (int i = 0; i < 15; i++)
        w[i] = SWAP64(ctx->buffer[i].mem_64[0]);
    w[15] = ctx->buffer[15].mem_64[0];

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
    for (int i = 16; i < 77; i++) {
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
    /* Put checksum in context given as argument. */
    ctx->H[0] = a;
}

inline void ctx_append_1(sha512_ctx * ctx) {

    PUT(BUFFER, ctx->buflen, 0x80);

    CLEAR_BUFFER_64_FAST(ctx->buffer->mem_64, ctx->buflen + 1);
}

inline void ctx_add_length(sha512_ctx * ctx) {

    ctx->buffer[15].mem_64[0] = (uint64_t) (ctx->buflen * 8);
}

inline void finish_ctx(sha512_ctx * ctx) {

    ctx_append_1(ctx);
    ctx_add_length(ctx);
}

inline void sha512_crypt(sha512_ctx * ctx) {

    finish_ctx(ctx);

    /* Run the collected hash value through SHA512. */
    sha512_block(ctx);
}

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
    #pragma unroll
    for (uint32_t i = 0; i < 15; i++)
        ctx.buffer[i].mem_64[0] = 0;

    //Get password.
    _memcpy(ctx.buffer->mem_32, keys_buffer, ctx.buflen);

    //Do the job
    sha512_crypt(&ctx);

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
    #pragma unroll
    for (uint32_t i = 0; i < 15; i++)
        ctx.buffer[i].mem_64[0] = 0;

    //Get salt information.
    ctx.buffer->mem_32[0] = salt->salt;

    //Get password.
    _memcpy(ctx.buffer->mem_32 + 1, keys_buffer, ctx.buflen);
    ctx.buflen += SALT_SIZE_X;

    //Do the job
    sha512_crypt(&ctx);

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
