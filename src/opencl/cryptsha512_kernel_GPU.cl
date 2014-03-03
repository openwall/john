/*
 * Developed by Claudio André <claudio.andre at correios.net.br> in 2012
 *
 * More information at http://openwall.info/wiki/john/OpenCL-SHA-512
 *
 * Copyright (c) 2012 Claudio André <claudio.andre at correios.net.br>
 * This program comes with ABSOLUTELY NO WARRANTY; express or implied.
 *
 * This is free software, and you are welcome to redistribute it
 * under certain conditions; as expressed here
 * http://www.gnu.org/licenses/gpl-2.0.html
 */

#include "opencl_cryptsha512.h"

#if gpu(DEVICE_INFO)
    #define VECTOR_USAGE
#endif

#if ! amd_gcn(DEVICE_INFO)
    #define UNROLL
#endif

inline void init_ctx(sha512_ctx * ctx) {
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

inline void sha512_block(sha512_ctx * ctx) {
    uint64_t a = ctx->H[0];
    uint64_t b = ctx->H[1];
    uint64_t c = ctx->H[2];
    uint64_t d = ctx->H[3];
    uint64_t e = ctx->H[4];
    uint64_t f = ctx->H[5];
    uint64_t g = ctx->H[6];
    uint64_t h = ctx->H[7];
    uint64_t t1, t2;
    uint64_t w[16];

#ifdef VECTOR_USAGE
    ulong16  w_vector;
    w_vector = vload16(0, ctx->buffer->mem_64);
    w_vector = SWAP64_V(w_vector);
    vstore16(w_vector, 0, w);
#else
    #pragma unroll
    for (int i = 0; i < 16; i++)
        w[i] = SWAP64(ctx->buffer[i].mem_64[0]);
#endif

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

#if ! amd_gcn(DEVICE_INFO)
    #pragma unroll 16  // NVIDIA Compiler segfaults if i use: "#pragma unroll"
#else
    #pragma unroll 8
#endif
    for (int i = 16; i < 80; i++) {
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

inline void insert_to_buffer_R(sha512_ctx    * ctx,
                               const uint8_t * string,
                               const uint32_t len) {

    for (uint32_t i = 0; i < len; i++)
        PUT(BUFFER, ctx->buflen + i, string[i]);

    ctx->buflen += len;
}

inline void insert_to_buffer_C(           sha512_ctx    * ctx,
                               __constant const uint8_t * string,
                               const uint32_t len) {

    for (uint32_t i = 0; i < len; i++)
        PUT(BUFFER, ctx->buflen + i, string[i]);

    ctx->buflen += len;
}

inline void insert_to_buffer_G(         sha512_ctx    * ctx,
                               __global const uint8_t * string,
                               const uint32_t len) {
    for (uint32_t i = 0; i < len; i++)
        PUT(BUFFER, ctx->buflen + i, string[i]);

    ctx->buflen += len;
}

inline void ctx_update_R(sha512_ctx * ctx,
                         uint8_t    * string,
                         const uint32_t len) {

    ctx->total += len;
    uint32_t startpos = ctx->buflen;

    insert_to_buffer_R(ctx, string, (startpos + len <= 128 ? len : 128 - startpos));

    if (ctx->buflen == 128) {  //Branching.
        uint32_t offset = 128 - startpos;
        sha512_block(ctx);
        ctx->buflen = 0;
        insert_to_buffer_R(ctx, (string + offset), len - offset);
    }
}

inline void ctx_update_C(           sha512_ctx * ctx,
                         __constant uint8_t    * string,
                         const uint32_t len) {

    ctx->total += len;
    uint32_t startpos = ctx->buflen;

    insert_to_buffer_C(ctx, string, (startpos + len <= 128 ? len : 128 - startpos));

    if (ctx->buflen == 128) {  //Branching.
        uint32_t offset = 128 - startpos;
        sha512_block(ctx);
        ctx->buflen = 0;
        insert_to_buffer_C(ctx, (string + offset), len - offset);
    }
}

inline void ctx_update_G(         sha512_ctx * ctx,
                         __global uint8_t    * string, uint32_t len) {

    ctx->total += len;
    uint32_t startpos = ctx->buflen;

    insert_to_buffer_G(ctx, string, (startpos + len <= 128 ? len : 128 - startpos));

    if (ctx->buflen == 128) {  //Branching.
        uint32_t offset = 128 - startpos;
        sha512_block(ctx);
        ctx->buflen = 0;
        insert_to_buffer_G(ctx, (string + offset), len - offset);
    }
}

inline void ctx_update_special(         sha512_ctx * ctx,
                               __global uint8_t    * string,
                               const uint32_t len) {
    __global uint64_t * src = (__global uint64_t *) string;
    uint64_t * dst = ctx->buffer->mem_64;

    ctx->total += len;
    ctx->buflen += len;

    for (uint32_t i = 0; i < len; i+=8)
        *dst++ = *src++;
}

#if amd_gcn(DEVICE_INFO)
inline void clear_buffer(uint64_t     * src,
                         const uint32_t len,
                         const uint32_t limit) {

    uint32_t length = len;
    uint8_t * string = (uint8_t *) src;

    while (length & 7)
        PUT(string, length++, 0);

    uint64_t * l = (uint64_t *) (string + length);

    while (length < (limit  * 8)) {
        *l++ = 0;
        length += 8;
    }
}

inline void ctx_append_1(sha512_ctx * ctx) {

    uint32_t length = ctx->buflen;
    PUT(BUFFER, length, 0x80);

    while (++length & 7)
        PUT(BUFFER, length, 0);

    uint64_t * l = (uint64_t *) (ctx->buffer->mem_08 + length);

    while (length < 128) {
        *l++ = 0;
        length += 8;
    }
}

#else
inline void clear_buffer(uint64_t     * destination,
                         const uint32_t len,
                         const uint32_t limit) {

    uint32_t length;

    CLEAR_BUFFER_64(destination, len);

    uint64_t * l = destination + length;

    while (length < limit) {
        *l++ = 0;
        length++;
    }
}

inline void ctx_append_1(sha512_ctx * ctx) {

    uint32_t length;
    PUT(BUFFER, ctx->buflen, 0x80);

    CLEAR_BUFFER_64(ctx->buffer->mem_64, ctx->buflen + 1);

    uint64_t * l = ctx->buffer->mem_64 + length;

    while (length < 16) {
        *l++ = 0;
        length++;
    }
}
#endif

inline void ctx_add_length(sha512_ctx * ctx) {

    ctx->buffer[15].mem_64[0] = SWAP64((uint64_t) (ctx->total * 8));
}

inline void finish_ctx(sha512_ctx * ctx) {

    ctx_append_1(ctx);
    ctx_add_length(ctx);
    ctx->buflen = 0;
}

inline void clear_ctx_buffer(sha512_ctx * ctx) {

#ifdef VECTOR_USAGE
    ulong16  w_vector = 0;
    vstore16(w_vector, 0, ctx->buffer->mem_64);
#else
    #pragma unroll
    for (int i = 0; i < 16; i++)
        ctx->buffer[i].mem_64[0] = 0;
#endif

    ctx->buflen = 0;
}

inline void sha512_digest_move(sha512_ctx * ctx,
                               uint64_t   * result,
                               const int size) {

    #pragma unroll
    for (int i = 0; i < size; i++)
        result[i] = SWAP64(ctx->H[i]);
}

inline void sha512_digest(sha512_ctx * ctx) {

    if (ctx->buflen <= 111) { //data+0x80+datasize fits in one 1024bit block
        finish_ctx(ctx);

    } else {
        bool moved = true;

        if (ctx->buflen < 128) { //data and 0x80 fits in one block
            ctx_append_1(ctx);
            moved = false;
        }
        sha512_block(ctx);
        clear_ctx_buffer(ctx);

        if (moved) //append 1,the rest is already clean
            PUT(BUFFER, 0, 0x80);
        ctx_add_length(ctx);
    }
    sha512_block(ctx);
}

inline void sha512_digest_special(sha512_ctx * ctx) {

    PUT(BUFFER, ctx->total, 0x80); //Do the ctx_append_1(ctx);

    if (ctx->total <= 111) { //data+0x80+datasize fits in one 1024bit block
        ctx_add_length(ctx);

    } else {
        sha512_block(ctx);
        clear_ctx_buffer(ctx);
        ctx_add_length(ctx);
    }
    sha512_block(ctx);
}

inline void sha512_prepare(__constant sha512_salt     * salt_data,
                           __global   sha512_password * keys_data,
                           __global   sha512_buffers  * tmp_memory,
                                      sha512_buffers  * fast_buffers,
                                      sha512_ctx      * ctx) {

#define pass        keys_data->pass->mem_08
#define passlen     keys_data->length
#define salt        salt_data->salt->mem_08
#define saltlen     salt_data->length
#define alt_result  fast_buffers->alt_result
#define temp_result fast_buffers->temp_result
#define p_sequence  fast_buffers->p_sequence

    init_ctx(ctx);

    ctx_update_special(ctx, pass, passlen);
    ctx_update_C(ctx, salt, saltlen);
    ctx_update_G(ctx, pass, passlen);

    sha512_digest(ctx);
    sha512_digest_move(ctx, alt_result->mem_64, BUFFER_ARRAY);
    init_ctx(ctx);

    ctx_update_special(ctx, pass, passlen);
    ctx_update_C(ctx, salt, saltlen);
    ctx_update_R(ctx, alt_result->mem_08, passlen);

    for (uint32_t i = passlen; i > 0; i >>= 1) {

        if (i & 1)
            ctx_update_R(ctx, alt_result->mem_08, 64U);
        else
            ctx_update_G(ctx, pass, passlen);
    }
    sha512_digest(ctx);
    sha512_digest_move(ctx, alt_result->mem_64, BUFFER_ARRAY);
    init_ctx(ctx);

    for (uint32_t i = 0; i < passlen; i++)
        ctx_update_G(ctx, pass, passlen);

    sha512_digest(ctx);
    sha512_digest_move(ctx, p_sequence->mem_64, PLAINTEXT_ARRAY);
    clear_buffer(p_sequence->mem_64, passlen, PLAINTEXT_ARRAY);
    init_ctx(ctx);

    /* For every character in the password add the entire password. */
    for (uint32_t i = 0; i < 16U + alt_result->mem_08[0]; i++)
        ctx_update_C(ctx, salt, saltlen);

    /* Finish the digest. */
    sha512_digest(ctx);
    sha512_digest_move(ctx, temp_result->mem_64, SALT_ARRAY);
    clear_buffer(temp_result->mem_64, saltlen, SALT_ARRAY);
}
#undef salt
#undef pass
#undef saltlen
#undef passlen
#undef temp_result
#undef p_sequence

#define temp_result fast_buffers->temp_result
#define p_sequence  fast_buffers->p_sequence

#if amd_gcn(DEVICE_INFO)
inline void sha512_crypt(sha512_buffers * fast_buffers,
                         sha512_ctx     * ctx,
                         const uint32_t saltlen, const uint32_t passlen,
                         const uint32_t initial, const uint32_t rounds) {

    /* Repeatedly run the collected hash value through SHA512 to burn cycles. */
    for (uint32_t i = initial; i < rounds; i++) {
        //Prepare CTX buffer.
        init_ctx(ctx);

        ctx_update_R(ctx, ((i & 1) ? p_sequence->mem_08 : alt_result->mem_08),
                          ((i & 1) ? passlen : 64U));

        if (i % 3)
            ctx_update_R(ctx, temp_result->mem_08, saltlen);

        if (i % 7)
            ctx_update_R(ctx, p_sequence->mem_08, passlen);

        ctx_update_R(ctx, ((i & 1) ? alt_result->mem_08 : p_sequence->mem_08),
                          ((i & 1) ? 64U :                passlen));

        sha512_digest(ctx);
        sha512_digest_move(ctx, alt_result->mem_64, BUFFER_ARRAY);
    }
}

#else
inline void sha512_crypt(sha512_buffers * fast_buffers,
                         sha512_ctx     * ctx,
                         const uint32_t saltlen, const uint32_t passlen,
                         const uint32_t initial, const uint32_t rounds) {

    /* Repeatedly run the collected hash value through SHA512 to burn cycles. */
    for (uint32_t i = initial; i < rounds; i++) {
        //Prepare CTX buffer.
        init_ctx(ctx);
        clear_ctx_buffer(ctx);

        if (i & 1) {
            ctx->buffer[0].mem_64[0] = p_sequence[0].mem_64[0];
            ctx->buffer[1].mem_64[0] = p_sequence[1].mem_64[0];
            ctx->buffer[2].mem_64[0] = p_sequence[2].mem_64[0];
            ctx->total = passlen;
        } else {
            ctx->buffer[0].mem_64[0] = alt_result[0].mem_64[0];
            ctx->buffer[1].mem_64[0] = alt_result[1].mem_64[0];
            ctx->buffer[2].mem_64[0] = alt_result[2].mem_64[0];
            ctx->buffer[3].mem_64[0] = alt_result[3].mem_64[0];
            ctx->buffer[4].mem_64[0] = alt_result[4].mem_64[0];
            ctx->buffer[5].mem_64[0] = alt_result[5].mem_64[0];
            ctx->buffer[6].mem_64[0] = alt_result[6].mem_64[0];
            ctx->buffer[7].mem_64[0] = alt_result[7].mem_64[0];
            ctx->total = 64U;
        }

        if (i % 3) {
            APPEND(ctx->buffer->mem_64, temp_result[0].mem_64[0], ctx->total);
            APPEND(ctx->buffer->mem_64, temp_result[1].mem_64[0], ctx->total + 8);
            ctx->total += saltlen;
        }

        if (i % 7) {
            APPEND(ctx->buffer->mem_64, p_sequence[0].mem_64[0], ctx->total);
            APPEND(ctx->buffer->mem_64, p_sequence[1].mem_64[0], ctx->total + 8);
            APPEND(ctx->buffer->mem_64, p_sequence[2].mem_64[0], ctx->total + 16);
            ctx->total += passlen;
        }

        if (i & 1) {
            APPEND(ctx->buffer->mem_64, alt_result[0].mem_64[0], ctx->total);
            APPEND(ctx->buffer->mem_64, alt_result[1].mem_64[0], ctx->total + 8);
            APPEND(ctx->buffer->mem_64, alt_result[2].mem_64[0], ctx->total + 16);
            APPEND(ctx->buffer->mem_64, alt_result[3].mem_64[0], ctx->total + 24);
            APPEND(ctx->buffer->mem_64, alt_result[4].mem_64[0], ctx->total + 32);
            APPEND(ctx->buffer->mem_64, alt_result[5].mem_64[0], ctx->total + 40);
            APPEND(ctx->buffer->mem_64, alt_result[6].mem_64[0], ctx->total + 48);
            APPEND_FINAL(ctx->buffer->mem_64, alt_result[7].mem_64[0], ctx->total + 56);
            ctx->total += 64U;
        } else {
            APPEND(ctx->buffer->mem_64, p_sequence[0].mem_64[0], ctx->total);
            APPEND(ctx->buffer->mem_64, p_sequence[1].mem_64[0], ctx->total + 8);
            APPEND_FINAL(ctx->buffer->mem_64, p_sequence[2].mem_64[0], ctx->total + 16);
            ctx->total += passlen;
        }
        sha512_digest_special(ctx);
        sha512_digest_move(ctx, alt_result->mem_64, BUFFER_ARRAY);
    }
}
#endif
#undef alt_result
#undef temp_result
#undef p_sequence

__kernel
void kernel_prepare(__constant sha512_salt     * salt,
                    __global   sha512_password * keys_buffer,
                    __global   sha512_buffers  * tmp_memory) {

    //Compute buffers (on Nvidia, better private)
    sha512_buffers fast_buffers;
    sha512_ctx     ctx_data;

    //Get the task to be done
    size_t gid = get_global_id(0);

    //Do the job
    sha512_prepare(salt, &keys_buffer[gid], &tmp_memory[gid], &fast_buffers, &ctx_data);

    //Save results.
    #pragma unroll
    for (int i = 0; i < 8; i++)
        tmp_memory[gid].alt_result[i].mem_64[0] = fast_buffers.alt_result[i].mem_64[0];

    #pragma unroll
    for (int i = 0; i < SALT_ARRAY; i++)
        tmp_memory[gid].temp_result[i].mem_64[0] = fast_buffers.temp_result[i].mem_64[0];

    #pragma unroll
    for (int i = 0; i < PLAINTEXT_ARRAY; i++)
        tmp_memory[gid].p_sequence[i].mem_64[0] = fast_buffers.p_sequence[i].mem_64[0];

}

__kernel
void kernel_crypt(__constant sha512_salt     * salt,
                  __global   sha512_password * keys_buffer,
                  __global   sha512_hash     * out_buffer,
                  __global   sha512_buffers  * tmp_memory) {

    //Compute buffers (on Nvidia, better private)
    sha512_buffers fast_buffers;
    sha512_ctx     ctx_data;

    //Get the task to be done
    size_t gid = get_global_id(0);

    //Transfer host data to faster memory
    #pragma unroll
    for (int i = 0; i < 8; i++)
        fast_buffers.alt_result[i].mem_64[0] = tmp_memory[gid].alt_result[i].mem_64[0];

    #pragma unroll
    for (int i = 0; i < SALT_ARRAY; i++)
        fast_buffers.temp_result[i].mem_64[0] = tmp_memory[gid].temp_result[i].mem_64[0];

    #pragma unroll
    for (int i = 0; i < PLAINTEXT_ARRAY; i++)
        fast_buffers.p_sequence[i].mem_64[0] = tmp_memory[gid].p_sequence[i].mem_64[0];

    //Do the job
    sha512_crypt(&fast_buffers, &ctx_data,
                 salt->length, keys_buffer[gid].length, 0, HASH_LOOPS);

    //Save results.
    #pragma unroll
    for (int i = 0; i < 8; i++)
        tmp_memory[gid].alt_result[i].mem_64[0] = fast_buffers.alt_result[i].mem_64[0];
}

__kernel
void kernel_final(__constant sha512_salt     * salt,
                  __global   sha512_password * keys_buffer,
                  __global   sha512_hash     * out_buffer,
                  __global   sha512_buffers  * tmp_memory) {

    //Compute buffers (on Nvidia, better private)
    sha512_buffers fast_buffers;
    sha512_ctx     ctx_data;

    //Get the task to be done
    size_t gid = get_global_id(0);

    //Transfer host data to faster memory
    #pragma unroll
    for (int i = 0; i < 8; i++)
        fast_buffers.alt_result[i].mem_64[0] = tmp_memory[gid].alt_result[i].mem_64[0];

    #pragma unroll
    for (int i = 0; i < SALT_ARRAY; i++)
        fast_buffers.temp_result[i].mem_64[0] = tmp_memory[gid].temp_result[i].mem_64[0];

    #pragma unroll
    for (int i = 0; i < PLAINTEXT_ARRAY; i++)
        fast_buffers.p_sequence[i].mem_64[0] = tmp_memory[gid].p_sequence[i].mem_64[0];

    //Do the job
    sha512_crypt(&fast_buffers, &ctx_data,
                 salt->length, keys_buffer[gid].length, 0, salt->final);

    //Send results to the host.
    #pragma unroll
    for (int i = 0; i < 8; i++)
        out_buffer[gid].v[i] = fast_buffers.alt_result[i].mem_64[0];
}
