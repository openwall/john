/*
 * Developed by Claudio André <claudioandre.br at gmail.com> in 2012
 *
 * More information at http://openwall.info/wiki/john/OpenCL-SHA-256
 *
 * Copyright (c) 2012-2015 Claudio André <claudioandre.br at gmail.com>
 * This program comes with ABSOLUTELY NO WARRANTY; express or implied.
 *
 * This is free software, and you are welcome to redistribute it
 * under certain conditions; as expressed here
 * http://www.gnu.org/licenses/gpl-2.0.html
 */

#include "opencl_sha256crypt.h"

#if __CPU__
    #define UNROLL
    #define FAST
#endif

inline void init_ctx(sha256_ctx * ctx) {
    ctx->H[0] = H0;
    ctx->H[1] = H1;
    ctx->H[2] = H2;
    ctx->H[3] = H3;
    ctx->H[4] = H4;
    ctx->H[5] = H5;
    ctx->H[6] = H6;
    ctx->H[7] = H7;
    ctx->total = 0;
    ctx->buflen = 0;
}

inline void memcpy_R(      uint8_t * dest,
                     const uint8_t * src,
                     const uint32_t srclen) {
    uint32_t i = 0;

    uint64_t * l = (uint64_t *) dest;
    uint64_t * s = (uint64_t *) src;

    while (i < srclen) {
        *l++ = *s++;
        i += 8;
    }
}

inline void memcpy_C(                 uint8_t * dest,
                     __constant const uint8_t * src,
                     const uint32_t srclen) {
    uint32_t i = 0;

    uint64_t * l = (uint64_t *) dest;
    __constant uint64_t * s = (__constant uint64_t *) src;

    while (i < srclen) {
        *l++ = *s++;
        i += 8;
    }
}

inline void memcpy_G(               uint8_t * dest,
                     __global const uint8_t * src,
                     const uint32_t srclen) {
    uint32_t i = 0;

    uint64_t * l = (uint64_t *) dest;
    __global uint64_t * s = (__global uint64_t *) src;

    while (i < srclen) {
        *l++ = *s++;
        i += 8;
    }
}

inline void sha256_block(sha256_ctx * ctx) {
    uint32_t a = ctx->H[0];
    uint32_t b = ctx->H[1];
    uint32_t c = ctx->H[2];
    uint32_t d = ctx->H[3];
    uint32_t e = ctx->H[4];
    uint32_t f = ctx->H[5];
    uint32_t g = ctx->H[6];
    uint32_t h = ctx->H[7];
    uint32_t t1, t2;
    uint32_t w[16];

#ifdef UNROLL
    #pragma unroll
#endif
    for (int i = 0; i < 16; i++)
        w[i] = SWAP32(ctx->buffer->mem_32[i]);

#ifdef UNROLL
    #pragma unroll
#endif
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

#ifdef UNROLL
    #pragma unroll
#endif
    for (int i = 16; i < 64; i++) {
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
    ctx->H[0] += a;
    ctx->H[1] += b;
    ctx->H[2] += c;
    ctx->H[3] += d;
    ctx->H[4] += e;
    ctx->H[5] += f;
    ctx->H[6] += g;
    ctx->H[7] += h;
}

inline void insert_to_buffer_R(sha256_ctx    * ctx,
                        const uint8_t * string,
                        const uint32_t len) {

#ifdef FAST
    memcpy_R(ctx->buffer->mem_08 + ctx->buflen, string, len);
#else
    for (uint32_t i = 0; i < len; i++)
        PUT(BUFFER, ctx->buflen + i, string[i]);
#endif
    ctx->buflen += len;
}

inline void insert_to_buffer_C(           sha256_ctx    * ctx,
                        __constant const uint8_t * string,
                                 const uint32_t len) {
#ifdef FAST
    memcpy_C(ctx->buffer->mem_08 + ctx->buflen, string, len);
#else
    for (uint32_t i = 0; i < len; i++)
        PUT(BUFFER, ctx->buflen + i, string[i]);
#endif
    ctx->buflen += len;
}

inline void insert_to_buffer_G(         sha256_ctx    * ctx,
                        __global const uint8_t * string,
                                 const uint32_t len) {
#ifdef FAST
    memcpy_G(ctx->buffer->mem_08 + ctx->buflen, string, len);
#else
    for (uint32_t i = 0; i < len; i++)
        PUT(BUFFER, ctx->buflen + i, string[i]);
#endif
    ctx->buflen += len;
}

inline void ctx_update_R(sha256_ctx * ctx,
                  uint8_t    * string, uint32_t len) {

    ctx->total += len;
    uint32_t startpos = ctx->buflen;

    insert_to_buffer_R(ctx, string, (startpos + len <= 64 ? len : 64 - startpos));

    if (ctx->buflen == 64) {
        uint32_t offset = 64 - startpos;
        sha256_block(ctx);
        ctx->buflen = 0;
        insert_to_buffer_R(ctx, (string + offset), len - offset);
    }
}

inline void ctx_update_C(           sha256_ctx * ctx,
                  __constant uint8_t    * string, uint32_t len) {

    ctx->total += len;
    uint32_t startpos = ctx->buflen;

    insert_to_buffer_C(ctx, string, (startpos + len <= 64 ? len : 64 - startpos));

    if (ctx->buflen == 64) {  //Branching.
        uint32_t offset = 64 - startpos;
        sha256_block(ctx);
        ctx->buflen = 0;
        insert_to_buffer_C(ctx, (string + offset), len - offset);
    }
}

inline void ctx_update_G(         sha256_ctx * ctx,
                  __global uint8_t    * string, uint32_t len) {

    ctx->total += len;
    uint32_t startpos = ctx->buflen;

    insert_to_buffer_G(ctx, string, (startpos + len <= 64 ? len : 64 - startpos));

    if (ctx->buflen == 64) {  //Branching.
        uint32_t offset = 64 - startpos;
        sha256_block(ctx);
        ctx->buflen = 0;
        insert_to_buffer_G(ctx, (string + offset), len - offset);
    }
}

inline void ctx_append_1(sha256_ctx * ctx) {

    uint32_t length = ctx->buflen;
    PUT(BUFFER, length, 0x80);

    while (++length & 7)
        PUT(BUFFER, length, 0);

    uint64_t * l = (uint64_t *) (ctx->buffer->mem_08 + length);

    while (length < 64) {
        *l++ = 0;
        length += 8;
    }
}

inline void ctx_add_length(sha256_ctx * ctx) {

    ctx->buffer[15].mem_32[0] = SWAP32(ctx->total * 8);
}

inline void finish_ctx(sha256_ctx * ctx) {

    ctx_append_1(ctx);
    ctx_add_length(ctx);
    ctx->buflen = 0;
}

inline void clear_ctx_buffer(sha256_ctx * ctx) {

    uint64_t * l = (uint64_t *) ctx->buffer;

#ifdef UNROLL
    #pragma unroll
#endif
    for (int i = 0; i < 8; i++)
        *l++ = 0;

    ctx->buflen = 0;
}

inline void sha256_digest_move(sha256_ctx * ctx,
                               uint32_t   * result,
                               const int size) {

    #pragma unroll
    for (int i = 0; i < size; i++)
        result[i] = SWAP32(ctx->H[i]);
}

inline void sha256_digest(sha256_ctx * ctx) {

    if (ctx->buflen <= 55) { //data+0x80+datasize fits in one 512bit block
        finish_ctx(ctx);

    } else {
        bool moved = true;

        if (ctx->buflen < 64) { //data and 0x80 fits in one block
            ctx_append_1(ctx);
            moved = false;
        }
        sha256_block(ctx);
        clear_ctx_buffer(ctx);

        if (moved) //append 1,the rest is already clean
            PUT(BUFFER, 0, 0x80);
        ctx_add_length(ctx);
    }
    sha256_block(ctx);
}

inline void sha256_prepare(__constant sha256_salt     * salt_data,
                           __global   sha256_password * keys_data,
                                      sha256_buffers  * fast_buffers,
                                      sha256_ctx      * ctx) {

#define pass        keys_data->pass->mem_08
#define passlen     keys_data->length
#define salt        salt_data->salt->mem_08
#define saltlen     salt_data->length
#define alt_result  fast_buffers->alt_result
#define temp_result fast_buffers->temp_result
#define p_sequence  fast_buffers->p_sequence

    init_ctx(ctx);

    ctx_update_G(ctx, pass, passlen);
    ctx_update_C(ctx, salt, saltlen);
    ctx_update_G(ctx, pass, passlen);

    sha256_digest(ctx);
    sha256_digest_move(ctx, alt_result->mem_32, BUFFER_ARRAY);
    init_ctx(ctx);

    ctx_update_G(ctx, pass, passlen);
    ctx_update_C(ctx, salt, saltlen);
    ctx_update_R(ctx, alt_result->mem_08, passlen);

    for (uint32_t i = passlen; i > 0; i >>= 1) {

	if (i & 1)
            ctx_update_R(ctx, alt_result->mem_08, 32U);
	else
            ctx_update_G(ctx, pass, passlen);
    }
    sha256_digest(ctx);
    sha256_digest_move(ctx, alt_result->mem_32, BUFFER_ARRAY);
    init_ctx(ctx);

    for (uint32_t i = 0; i < passlen; i++)
        ctx_update_G(ctx, pass, passlen);

    sha256_digest(ctx);
    sha256_digest_move(ctx, p_sequence->mem_32, PLAINTEXT_ARRAY);
    init_ctx(ctx);

    /* For every character in the password add the entire password. */
    for (uint32_t i = 0; i < 16U + alt_result->mem_08[0]; i++)
        ctx_update_C(ctx, salt, saltlen);

    /* Finish the digest.  */
    sha256_digest(ctx);
    sha256_digest_move(ctx, temp_result->mem_32, SALT_ARRAY);
}
#undef salt
#undef pass
#undef saltlen
#undef passlen

inline void sha256_crypt(sha256_buffers  * fast_buffers,
                  sha256_ctx      * ctx,
                  const uint32_t saltlen, const uint32_t passlen,
                  const uint32_t rounds) {

    /* Repeatedly run the collected hash value through SHA256 to burn cycles. */
    for (uint32_t i = 0; i < rounds; i++) {
        init_ctx(ctx);

        ctx_update_R(ctx, ((i & 1) ? p_sequence->mem_08 : alt_result->mem_08),
                          ((i & 1) ? passlen : 32U));

        if (i % 3)
            ctx_update_R(ctx, temp_result->mem_08, saltlen);

        if (i % 7)
            ctx_update_R(ctx, p_sequence->mem_08, passlen);

        ctx_update_R(ctx, ((i & 1) ? alt_result->mem_08 : p_sequence->mem_08),
                          ((i & 1) ? 32U :                passlen));
        sha256_digest(ctx);
        sha256_digest_move(ctx, alt_result->mem_32, BUFFER_ARRAY);
    }
}
#undef alt_result
#undef temp_result
#undef p_sequence
#undef ctx

__kernel
void kernel_crypt(__constant sha256_salt     * salt,
                  __global   sha256_password * keys_buffer,
                  __global   sha256_hash     * out_buffer) {

    //Compute buffers (on CPU, better private)
    sha256_buffers fast_buffers;
    sha256_ctx     ctx;

    //Get the task to be done
    size_t gid = get_global_id(0);

    //Do the job
    sha256_prepare(salt, &keys_buffer[gid], &fast_buffers, &ctx);
    sha256_crypt(&fast_buffers, &ctx,
                 salt->length, keys_buffer[gid].length, salt->rounds);

    //Send results to the host.
#ifdef UNROLL
    #pragma unroll
#endif
    for (int i = 0; i < 8; i++)
        out_buffer[gid].v[i] = fast_buffers.alt_result[i].mem_32[0];
}
