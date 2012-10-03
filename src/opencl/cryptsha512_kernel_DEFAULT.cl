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

#define _OPENCL_COMPILER
#include "opencl_cryptsha512.h"

#if cpu(DEVICE_INFO)
    #define UNROLL
    #define FAST
#endif

#if no_byte_addressable(DEVICE_INFO)
    #define PUT         PUTCHAR
    #define BUFFER      ctx->buffer->mem_32
#else
    #define PUT         ATTRIB
    #define BUFFER      ctx->buffer->mem_08
#endif

__constant uint64_t k[] = {
    0x428a2f98d728ae22UL, 0x7137449123ef65cdUL, 0xb5c0fbcfec4d3b2fUL, 0xe9b5dba58189dbbcUL,
    0x3956c25bf348b538UL, 0x59f111f1b605d019UL, 0x923f82a4af194f9bUL, 0xab1c5ed5da6d8118UL,
    0xd807aa98a3030242UL, 0x12835b0145706fbeUL, 0x243185be4ee4b28cUL, 0x550c7dc3d5ffb4e2UL,
    0x72be5d74f27b896fUL, 0x80deb1fe3b1696b1UL, 0x9bdc06a725c71235UL, 0xc19bf174cf692694UL,
    0xe49b69c19ef14ad2UL, 0xefbe4786384f25e3UL, 0x0fc19dc68b8cd5b5UL, 0x240ca1cc77ac9c65UL,
    0x2de92c6f592b0275UL, 0x4a7484aa6ea6e483UL, 0x5cb0a9dcbd41fbd4UL, 0x76f988da831153b5UL,
    0x983e5152ee66dfabUL, 0xa831c66d2db43210UL, 0xb00327c898fb213fUL, 0xbf597fc7beef0ee4UL,
    0xc6e00bf33da88fc2UL, 0xd5a79147930aa725UL, 0x06ca6351e003826fUL, 0x142929670a0e6e70UL,
    0x27b70a8546d22ffcUL, 0x2e1b21385c26c926UL, 0x4d2c6dfc5ac42aedUL, 0x53380d139d95b3dfUL,
    0x650a73548baf63deUL, 0x766a0abb3c77b2a8UL, 0x81c2c92e47edaee6UL, 0x92722c851482353bUL,
    0xa2bfe8a14cf10364UL, 0xa81a664bbc423001UL, 0xc24b8b70d0f89791UL, 0xc76c51a30654be30UL,
    0xd192e819d6ef5218UL, 0xd69906245565a910UL, 0xf40e35855771202aUL, 0x106aa07032bbd1b8UL,
    0x19a4c116b8d2d0c8UL, 0x1e376c085141ab53UL, 0x2748774cdf8eeb99UL, 0x34b0bcb5e19b48a8UL,
    0x391c0cb3c5c95a63UL, 0x4ed8aa4ae3418acbUL, 0x5b9cca4f7763e373UL, 0x682e6ff3d6b2b8a3UL,
    0x748f82ee5defb2fcUL, 0x78a5636f43172f60UL, 0x84c87814a1f0ab72UL, 0x8cc702081a6439ecUL,
    0x90befffa23631e28UL, 0xa4506cebde82bde9UL, 0xbef9a3f7b2c67915UL, 0xc67178f2e372532bUL,
    0xca273eceea26619cUL, 0xd186b8c721c0c207UL, 0xeada7dd6cde0eb1eUL, 0xf57d4f7fee6ed178UL,
    0x06f067aa72176fbaUL, 0x0a637dc5a2c898a6UL, 0x113f9804bef90daeUL, 0x1b710b35131c471bUL,
    0x28db77f523047d84UL, 0x32caab7b40c72493UL, 0x3c9ebe0a15c9bebcUL, 0x431d67c49c100d4cUL,
    0x4cc5d4becb3e42b6UL, 0x597f299cfc657e2aUL, 0x5fcb6fab3ad6faecUL, 0x6c44198c4a475817UL
};

inline void init_ctx(sha512_ctx * ctx) {
    ctx->H[0] = 0x6a09e667f3bcc908UL;
    ctx->H[1] = 0xbb67ae8584caa73bUL;
    ctx->H[2] = 0x3c6ef372fe94f82bUL;
    ctx->H[3] = 0xa54ff53a5f1d36f1UL;
    ctx->H[4] = 0x510e527fade682d1UL;
    ctx->H[5] = 0x9b05688c2b3e6c1fUL;
    ctx->H[6] = 0x1f83d9abfb41bd6bUL;
    ctx->H[7] = 0x5be0cd19137e2179UL;
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

#ifdef UNROLL
    #pragma unroll
#endif
    for (int i = 0; i < 16; i++)
        w[i] = SWAP64(ctx->buffer->mem_64[i]);

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

#ifdef FAST
    memcpy_R(ctx->buffer->mem_08 + ctx->buflen, string, len);
#else
    for (uint32_t i = 0; i < len; i++)
        PUT(BUFFER, ctx->buflen + i, string[i]);
#endif
    ctx->buflen += len;
}

inline void insert_to_buffer_C(           sha512_ctx    * ctx,
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

inline void insert_to_buffer_G(         sha512_ctx    * ctx,
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

inline void ctx_update_R(sha512_ctx * ctx,
                  uint8_t    * string, uint32_t len) {

    ctx->total += len;
    uint32_t startpos = ctx->buflen;

    insert_to_buffer_R(ctx, string, (startpos + len <= 128 ? len : 128 - startpos));

    if (ctx->buflen == 128) {
        uint32_t offset = 128 - startpos;
        sha512_block(ctx);
        ctx->buflen = 0;
        insert_to_buffer_R(ctx, (string + offset), len - offset);
    }
}

inline void ctx_update_C(           sha512_ctx * ctx,
                  __constant uint8_t    * string, uint32_t len) {

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

inline void ctx_add_length(sha512_ctx * ctx) {

    ctx->buffer[15].mem_64[0] = SWAP64((uint64_t) (ctx->total * 8));
}

inline void finish_ctx(sha512_ctx * ctx) {

    ctx_append_1(ctx);
    ctx_add_length(ctx);
    ctx->buflen = 0;
}

inline void clear_ctx_buffer(sha512_ctx * ctx) {

#ifdef UNROLL
    #pragma unroll
#endif
    for (int i = 0; i < 16; i++)
        ctx->buffer->mem_64[i] = 0;

    ctx->buflen = 0;
}

inline void sha512_digest_move(sha512_ctx * ctx,
                               uint64_t   * result,
                               const int size) {

#ifdef UNROLL
    #pragma unroll
#endif
    for (int i = 0; i < size; i++)
        result[i] = SWAP64(ctx->H[i]);
}

inline void sha512_digest(sha512_ctx * ctx) {

    if (ctx->buflen <= 111) { //data+0x80+datasize fits in one 1024bit block
        finish_ctx(ctx);

    } else {
        bool moved = 1;

        if (ctx->buflen < 128) { //data and 0x80 fits in one block
            ctx_append_1(ctx);
            moved = 0;
        }
        sha512_block(ctx);
        clear_ctx_buffer(ctx);

        if (moved) //append 1,the rest is already clean
            PUT(BUFFER, 0, 0x80);
        ctx_add_length(ctx);
    }
    sha512_block(ctx);
}

inline void sha512_prepare(__constant sha512_salt     * salt_data,
                    __global   sha512_password * keys_data,
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

    ctx_update_G(ctx, pass, passlen);
    ctx_update_C(ctx, salt, saltlen);
    ctx_update_G(ctx, pass, passlen);

    sha512_digest(ctx);
    sha512_digest_move(ctx, alt_result->mem_64, BUFFER_ARRAY);
    init_ctx(ctx);

    ctx_update_G(ctx, pass, passlen);
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
    init_ctx(ctx);

    /* For every character in the password add the entire password. */
    for (uint32_t i = 0; i < 16 + alt_result->mem_08[0]; i++)
        ctx_update_C(ctx, salt, saltlen);

    /* Finish the digest.  */
    sha512_digest(ctx);
    sha512_digest_move(ctx, temp_result->mem_64, SALT_ARRAY);
}
#undef salt
#undef pass
#undef saltlen
#undef passlen

inline void sha512_crypt(sha512_buffers  * fast_buffers,
                  sha512_ctx      * ctx,
                  const uint32_t saltlen, const uint32_t passlen,
                  const uint32_t rounds) {

    /* Repeatedly run the collected hash value through SHA512 to burn cycles. */
    for (uint32_t i = 0; i < rounds; i++) {
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
#undef alt_result
#undef temp_result
#undef p_sequence
#undef ctx

__kernel
void kernel_crypt(__constant sha512_salt     * salt,
                  __global   sha512_password * keys_buffer,
                  __global   sha512_hash     * out_buffer) {

    //Compute buffers (on CPU, better private)
    sha512_buffers fast_buffers;
    sha512_ctx     ctx;

    //Get the task to be done
    size_t gid = get_global_id(0);

    //Do the job
    sha512_prepare(salt, &keys_buffer[gid], &fast_buffers, &ctx);
    sha512_crypt(&fast_buffers, &ctx,
                 salt->length, keys_buffer[gid].length, salt->rounds);

    //Send results to the host.
#ifdef UNROLL
    #pragma unroll
#endif
    for (int i = 0; i < 8; i++)
        out_buffer[gid].v[i] = fast_buffers.alt_result[i].mem_64[0];
}