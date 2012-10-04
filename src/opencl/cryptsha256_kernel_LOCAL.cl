/*
 * Developed by Claudio André <claudio.andre at correios.net.br> in 2012
 *
 * More information at http://openwall.info/wiki/john/OpenCL-SHA-256
 *
 * Copyright (c) 2012 Claudio André <claudio.andre at correios.net.br>
 * This program comes with ABSOLUTELY NO WARRANTY; express or implied.
 *
 * This is free software, and you are welcome to redistribute it
 * under certain conditions; as expressed here
 * http://www.gnu.org/licenses/gpl-2.0.html
 */

#define _OPENCL_COMPILER
#include "opencl_cryptsha256.h"

#if no_byte_addressable(DEVICE_INFO)
    #define PUT         PUTCHAR
    #define BUFFER      ctx->buffer->mem_32
#else
    #define PUT         ATTRIB
    #define BUFFER      ctx->buffer->mem_08
#endif

#if gpu(DEVICE_INFO)
    #define VECTOR_USAGE
#endif

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

inline void init_ctx(__local sha256_ctx * ctx) {
    ctx->H[0] = 0x6a09e667;
    ctx->H[1] = 0xbb67ae85;
    ctx->H[2] = 0x3c6ef372;
    ctx->H[3] = 0xa54ff53a;
    ctx->H[4] = 0x510e527f;
    ctx->H[5] = 0x9b05688c;
    ctx->H[6] = 0x1f83d9ab;
    ctx->H[7] = 0x5be0cd19;
    ctx->total = 0;
    ctx->buflen = 0;
}

inline void get_host_data(__global sha256_password * keys_data,
                          __local  sha256_password * fast_keys) {

    //Transfer data to faster memory
    //Password information
    fast_keys->length = keys_data->length;

    #pragma unroll
    for (int i = 0; i < PLAINTEXT_ARRAY; i++)
        fast_keys->pass->mem_32[i] = keys_data->pass->mem_32[i];
}

inline void get_temp_data(__global sha256_buffers * tmp_memory,
                          __local  sha256_buffers * fast_buffers) {

    __global uint64_t * src;
    __local  uint64_t * dst;

    src = (__global uint64_t *) tmp_memory->alt_result;
    dst = (__local  uint64_t *) fast_buffers->alt_result;
    #pragma unroll
    for (int i = 0; i < (8 / 2); i++)
        *dst++ = *src++;

    src = (__global uint64_t *) tmp_memory->temp_result;
    dst = (__local uint64_t *) fast_buffers->temp_result;
    #pragma unroll
    for (int i = 0; i < (SALT_ARRAY / 2); i++)
        *dst++ = *src++;

    src = (__global uint64_t *) tmp_memory->p_sequence;
    dst = (__local uint64_t *) fast_buffers->p_sequence;
    #pragma unroll
    for (int i = 0; i < (PLAINTEXT_ARRAY / 2); i++)
        *dst++ = *src++;
}

inline void sha256_block(__local sha256_ctx * ctx) {
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

#ifdef VECTOR_USAGE
    uint16  w_vector;
    w_vector = vload16(0, ctx->buffer->mem_32);
    w_vector = SWAP32_V(w_vector);
    vstore16(w_vector, 0, w);
#else
    #pragma unroll
    for (int i = 0; i < 16; i++)
        w[i] = SWAP32(ctx->buffer->mem_32[i]);
#endif

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

inline void insert_to_buffer_L(__local sha256_ctx    * ctx,
                               __local const uint8_t * string,
                               const uint32_t len) {

    for (uint32_t i = 0; i < len; i++)
        PUT(BUFFER, ctx->buflen + i, string[i]);

    ctx->buflen += len;
}

inline void insert_to_buffer_C(__local    sha256_ctx    * ctx,
                               __constant const uint8_t * string,
                               const uint32_t len) {

    for (uint32_t i = 0; i < len; i++)
        PUT(BUFFER, ctx->buflen + i, string[i]);

    ctx->buflen += len;
}

inline void ctx_update_L(__local sha256_ctx * ctx,
                         __local uint8_t    * string,
                         const uint32_t len) {

    ctx->total += len;
    uint32_t startpos = ctx->buflen;

    insert_to_buffer_L(ctx, string, (startpos + len <= 64 ? len : 64 - startpos));

    if (ctx->buflen == 64) {  //Branching.
        uint32_t offset = 64 - startpos;
        sha256_block(ctx);
        ctx->buflen = 0;
        insert_to_buffer_L(ctx, (string + offset), len - offset);
    }
}

inline void ctx_update_C(__local    sha256_ctx * ctx,
                         __constant uint8_t    * string,
                         const uint32_t len) {

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

inline void ctx_append_1(__local sha256_ctx * ctx) {

    uint32_t length = ctx->buflen;
    PUT(BUFFER, length, 0x80);

    while (++length & 7)
        PUT(BUFFER, length, 0);

    __local uint64_t * l = (__local uint64_t *) (ctx->buffer->mem_08 + length);

    while (length < 64) {
        *l++ = 0;
        length += 8;
    }
}

inline void ctx_add_length(__local sha256_ctx * ctx) {

    ctx->buffer[15].mem_32[0] = SWAP32(ctx->total * 8);
}

inline void finish_ctx(__local sha256_ctx * ctx) {

    ctx_append_1(ctx);
    ctx_add_length(ctx);
    ctx->buflen = 0;
}

inline void clear_ctx_buffer(__local sha256_ctx * ctx) {

#ifdef VECTOR_USAGE
    uint16  w_vector = 0;
    vstore16(w_vector, 0, ctx->buffer->mem_32);
#else
    __local uint64_t * l = (__local uint64_t *) ctx->buffer;

    #pragma unroll
    for (int i = 0; i < 8; i++)
        *l++ = 0;
#endif

    ctx->buflen = 0;
}

inline void sha256_digest_move_L(__local sha256_ctx * ctx,
                                 __local uint32_t   * result,
                                 const int size) {

    #pragma unroll
    for (int i = 0; i < size; i++)
        result[i] = SWAP32(ctx->H[i]);
}

inline void sha256_digest_move_G(__local  sha256_ctx * ctx,
                                 __global uint32_t   * result,
                                 const int size) {

    #pragma unroll
    for (int i = 0; i < size; i++)
        result[i] = SWAP32(ctx->H[i]);
}

inline void sha256_digest(__local sha256_ctx * ctx) {

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
                           __local    sha256_password * keys_data,
                           __global   sha256_buffers  * tmp_memory,
                           __local    sha256_buffers  * fast_buffers,
                           __local    sha256_ctx      * ctx) {

#define pass        keys_data->pass->mem_08
#define passlen     keys_data->length
#define salt        salt_data->salt->mem_08
#define saltlen     salt_data->length
#define alt_result  fast_buffers->alt_result
#define temp_result tmp_memory->temp_result
#define p_sequence  tmp_memory->p_sequence

    init_ctx(ctx);

    ctx_update_L(ctx, pass, passlen);
    ctx_update_C(ctx, salt, saltlen);
    ctx_update_L(ctx, pass, passlen);

    sha256_digest(ctx);
    sha256_digest_move_L(ctx, alt_result->mem_32, BUFFER_ARRAY);
    init_ctx(ctx);

    ctx_update_L(ctx, pass, passlen);
    ctx_update_C(ctx, salt, saltlen);
    ctx_update_L(ctx, alt_result->mem_08, passlen);

    for (uint32_t i = passlen; i > 0; i >>= 1) {
        ctx_update_L(ctx, ((i & 1) ? alt_result->mem_08 : pass),
                          ((i & 1) ? 32U :                passlen));
    }
    sha256_digest(ctx);
    sha256_digest_move_L(ctx, alt_result->mem_32, BUFFER_ARRAY);
    init_ctx(ctx);

    for (uint32_t i = 0; i < passlen; i++)
        ctx_update_L(ctx, pass, passlen);

    sha256_digest(ctx);
    sha256_digest_move_G(ctx, p_sequence->mem_32, PLAINTEXT_ARRAY);
    init_ctx(ctx);

    /* For every character in the password add the entire password. */
    for (uint32_t i = 0; i < 16U + alt_result->mem_08[0]; i++)
        ctx_update_C(ctx, salt, saltlen);

    /* Finish the digest. */
    sha256_digest(ctx);
    sha256_digest_move_G(ctx, temp_result->mem_32, SALT_ARRAY);
}
#undef salt
#undef pass
#undef saltlen
#undef passlen
#undef temp_result
#undef p_sequence

inline void sha256_crypt(__local sha256_buffers * fast_buffers,
                         __local sha256_ctx     * ctx,
                         const uint32_t saltlen, const uint32_t passlen,
                         const uint32_t initial, const uint32_t rounds) {

#define temp_result fast_buffers->temp_result
#define p_sequence  fast_buffers->p_sequence

    /* Repeatedly run the collected hash value through SHA256 to burn cycles. */
    for (uint32_t i = initial; i < rounds; i++) {
        init_ctx(ctx);

        ctx_update_L(ctx, ((i & 1) ? p_sequence->mem_08 : alt_result->mem_08),
                          ((i & 1) ? passlen : 32U));

        if (i % 3)
            ctx_update_L(ctx, temp_result->mem_08, saltlen);

        if (i % 7)
            ctx_update_L(ctx, p_sequence->mem_08, passlen);

        ctx_update_L(ctx, ((i & 1) ? alt_result->mem_08 : p_sequence->mem_08),
                          ((i & 1) ? 32U :                passlen));
        sha256_digest(ctx);
        sha256_digest_move_L(ctx, alt_result->mem_32, BUFFER_ARRAY);
    }
}
#undef alt_result
#undef temp_result
#undef p_sequence

__kernel
void kernel_prepare(__constant sha256_salt     * salt,
                    __global   sha256_password * keys_buffer,
                    __global   sha256_buffers  * tmp_memory,
                    __local    sha256_password * fast_keys,
                    __local    sha256_buffers  * fast_buffers,
                    __local    sha256_ctx      * ctx_data) {

    //Get the task to be done
    size_t gid = get_global_id(0);
    size_t lid = get_local_id(0);

    //Transfer host data to faster memory
    get_host_data(&keys_buffer[gid], &fast_keys[lid]);

    //Do the job
    sha256_prepare(salt, &fast_keys[lid], &tmp_memory[gid], &fast_buffers[lid], &ctx_data[lid]);

    //Save results.
    #pragma unroll
    for (int i = 0; i < 8; i++)
        tmp_memory[gid].alt_result[i].mem_32[0] = fast_buffers[lid].alt_result[i].mem_32[0];
}

__kernel
void kernel_crypt(__constant sha256_salt     * salt,
                  __global   sha256_password * keys_buffer,
                  __global   sha256_hash     * out_buffer,
                  __global   sha256_buffers  * tmp_memory,
                  __local    sha256_buffers  * fast_buffers,
                  __local    sha256_ctx      * ctx_data) {

    //Get the task to be done
    size_t gid = get_global_id(0);
    size_t lid = get_local_id(0);

    //Transfer temp data to faster memory
    get_temp_data(&tmp_memory[gid], &fast_buffers[lid]);

    //Do the job
    sha256_crypt(&fast_buffers[lid], &ctx_data[lid],
                 salt->length, keys_buffer[gid].length, 0, HASH_LOOPS);

    //Save results.
    #pragma unroll
    for (int i = 0; i < 8; i++)
        tmp_memory[gid].alt_result[i].mem_32[0] = fast_buffers[lid].alt_result[i].mem_32[0];
}

__kernel
void kernel_final(__constant sha256_salt     * salt,
                  __global   sha256_password * keys_buffer,
                  __global   sha256_hash     * out_buffer,
                  __global   sha256_buffers  * tmp_memory,
                  __local    sha256_buffers  * fast_buffers,
                  __local    sha256_ctx      * ctx_data) {

    //Get the task to be done
    size_t gid = get_global_id(0);
    size_t lid = get_local_id(0);

    //Transfer temp data to faster memory
    get_temp_data(&tmp_memory[gid], &fast_buffers[lid]);

    //Do the job
    sha256_crypt(&fast_buffers[lid], &ctx_data[lid],
                 salt->length, keys_buffer[gid].length, salt->initial, salt->rounds);

    //Send results to the host.
    #pragma unroll
    for (int i = 0; i < 8; i++)
        out_buffer[gid].v[i] = fast_buffers[lid].alt_result[i].mem_32[0];
}