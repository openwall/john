/*
 * Developed by Claudio André <claudioandre.br at gmail.com> in 2012
 *
 * More information at http://openwall.info/wiki/john/OpenCL-SHA-256
 *
 * Copyright (c) 2012-2014 Claudio André <claudioandre.br at gmail.com>
 * This program comes with ABSOLUTELY NO WARRANTY; express or implied.
 *
 * This is free software, and you are welcome to redistribute it
 * under certain conditions; as expressed here
 * http://www.gnu.org/licenses/gpl-2.0.html
 */

#include "opencl_cryptsha256.h"

#if gpu(DEVICE_INFO) && !amd_gcn(DEVICE_INFO)
    #define VECTOR_USAGE
#endif

///	    *** UNROLL ***
#define STRONG_UNROLL	1

/************************** helper **************************/
inline void init_H(sha256_ctx * ctx) {
    ctx->H[0] = H0;
    ctx->H[1] = H1;
    ctx->H[2] = H2;
    ctx->H[3] = H3;
    ctx->H[4] = H4;
    ctx->H[5] = H5;
    ctx->H[6] = H6;
    ctx->H[7] = H7;
}

inline void init_ctx(sha256_ctx * ctx) {
    ctx->H[0] = H0;
    ctx->H[1] = H1;
    ctx->H[2] = H2;
    ctx->H[3] = H3;
    ctx->H[4] = H4;
    ctx->H[5] = H5;
    ctx->H[6] = H6;
    ctx->H[7] = H7;

    ctx->buffer[0].mem_32[0] = 0;
    ctx->buffer[1].mem_32[0] = 0;
    ctx->buffer[2].mem_32[0] = 0;
    ctx->buffer[3].mem_32[0] = 0;
    ctx->buffer[4].mem_32[0] = 0;
    ctx->buffer[5].mem_32[0] = 0;
    ctx->buffer[6].mem_32[0] = 0;
    ctx->buffer[7].mem_32[0] = 0;
    ctx->buffer[8].mem_32[0] = 0;
    ctx->buffer[9].mem_32[0] = 0;
    ctx->buffer[10].mem_32[0] = 0;
    ctx->buffer[11].mem_32[0] = 0;
    ctx->buffer[12].mem_32[0] = 0;
    ctx->buffer[13].mem_32[0] = 0;
    ctx->buffer[14].mem_32[0] = 0;
    ctx->buffer[15].mem_32[0] = 0;

    ctx->total = 0;
    ctx->buflen = 0;
}

inline void clear_ctx_buffer(sha256_ctx * ctx) {

    ctx->buffer[0].mem_32[0] = 0;
    ctx->buffer[1].mem_32[0] = 0;
    ctx->buffer[2].mem_32[0] = 0;
    ctx->buffer[3].mem_32[0] = 0;
    ctx->buffer[4].mem_32[0] = 0;
    ctx->buffer[5].mem_32[0] = 0;
    ctx->buffer[6].mem_32[0] = 0;
    ctx->buffer[7].mem_32[0] = 0;
    ctx->buffer[8].mem_32[0] = 0;
    ctx->buffer[9].mem_32[0] = 0;
    ctx->buffer[10].mem_32[0] = 0;
    ctx->buffer[11].mem_32[0] = 0;
    ctx->buffer[12].mem_32[0] = 0;
    ctx->buffer[13].mem_32[0] = 0;
    ctx->buffer[14].mem_32[0] = 0;
    ctx->buffer[15].mem_32[0] = 0;

    ctx->buflen = 0;
}

/************************** prepare **************************/
inline void clear_buffer(uint32_t     * destination,
                         const uint32_t len,
                         const uint32_t limit) {

    uint32_t length;

    CLEAR_BUFFER_BE_32(destination, len);

    while (length < limit) {
        destination[length] = 0;
        length++;
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
    uint32_t t;
    uint32_t w[16];

#ifdef VECTOR_USAGE
    uint16  w_vector = vload16(0, ctx->buffer->mem_32);
    vstore16(w_vector, 0, w);
#else
    #pragma unroll
    for (int i = 0; i < 16; i++)
        w[i] = (ctx->buffer[i].mem_32[0]);
#endif

    #pragma unroll
    for (int i = 0; i < 16; i++) {
        t = k[i] + w[i] + h + Sigma1(e) + Ch(e, f, g);

        h = g;
        g = f;
        f = e;
        e = d + t;
        t = t + Maj(a, b, c) + Sigma0(a);
        d = c;
        c = b;
        b = a;
        a = t;
    }

    #pragma unroll
    for (int i = 16; i < 64; i++) {
        w[i & 15] = sigma1(w[(i - 2) & 15]) + sigma0(w[(i - 15) & 15]) + w[(i - 16) & 15] + w[(i - 7) & 15];
        t = k[i] + w[i & 15] + h + Sigma1(e) + Ch(e, f, g);

        h = g;
        g = f;
        f = e;
        e = d + t;
        t = t + Maj(a, b, c) + Sigma0(a);
        d = c;
        c = b;
        b = a;
        a = t;
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

inline void sha256_digest(sha256_ctx * ctx,
                          uint32_t   * result,
                          const uint32_t size) {

    if (ctx->buflen <= 55) { //data+0x80+datasize fits in one 512bit block
	APPEND_BE_SINGLE(ctx->buffer->mem_32, 0x80000000U, ctx->buflen);
	clear_buffer(ctx->buffer->mem_32, ctx->buflen+1, 16);
	ctx->buffer[15].mem_32[0] = ((uint32_t) (ctx->total * 8));
	ctx->buflen = 0;

    } else {
        bool moved = true;

        if (ctx->buflen < 64) { //data and 0x80 fits in one block
	    APPEND_BE_SINGLE(ctx->buffer->mem_32, 0x80000000U, ctx->buflen);
	    clear_buffer(ctx->buffer->mem_32, ctx->buflen+1, 16);
            moved = false;
        }
        sha256_block(ctx);
        clear_ctx_buffer(ctx);

        if (moved) //append 1,the rest is already clean
            ctx->buffer[0].mem_32[0] = 0x80000000U;
        ctx->buffer[15].mem_32[0] = ((uint32_t) (ctx->total * 8));
    }
    sha256_block(ctx);

    for (uint32_t i = 0; i < size; i++)
        result[i] = (ctx->H[i]);
}

inline void insert_to_buffer_R(sha256_ctx    * ctx,
                               const uint8_t * string,
                               const uint32_t len) {

    uint32_t * s = (uint32_t *) string;
    uint32_t tmp, pos;
    tmp = ((ctx->buflen & 3) << 3);
    pos = (ctx->buflen >> 2);

    for (uint32_t i = 0; i < len; i+=4, s++) {
	APPEND_BE_BUFFER_F(ctx->buffer->mem_32, s[0]);
    }
    ctx->buflen += len;

    //A fast clean should be possible.
    clear_buffer(ctx->buffer->mem_32, ctx->buflen, 16);
}

inline void insert_to_buffer_G(         sha256_ctx    * ctx,
                               __global const uint8_t * string,
                               const uint32_t len) {

    __global uint32_t * s = (__global uint32_t *) string;
    uint32_t tmp, pos;
    tmp = ((ctx->buflen & 3) << 3);
    pos = (ctx->buflen >> 2);

    for (uint32_t i = 0; i < len; i+=4, s++) {
	APPEND_BE_BUFFER_F(ctx->buffer->mem_32, s[0]);
    }
    ctx->buflen += len;
    tmp = (ctx->buflen & 3);

    if (tmp) {
	pos = (ctx->buflen >> 2);
	ctx->buffer[pos].mem_32[0] = ctx->buffer[pos].mem_32[0] & clear_mask_be[tmp];
    }
}

inline void insert_to_buffer_C(           sha256_ctx    * ctx,
                               __constant const uint8_t * string,
                               const uint32_t len) {

    __constant uint32_t * s = (__constant uint32_t *) string;
    uint32_t tmp, pos;
    tmp = ((ctx->buflen & 3) << 3);
    pos = (ctx->buflen >> 2);

    for (uint32_t i = 0; i < len; i+=4, s++) {
	APPEND_BE_BUFFER_F(ctx->buffer->mem_32, s[0]);
    }
    ctx->buflen += len;
    tmp = (ctx->buflen & 3);

    if (tmp) {
	pos = (ctx->buflen >> 2);
	ctx->buffer[pos].mem_32[0] = ctx->buffer[pos].mem_32[0] & clear_mask_be[tmp];
    }
}

inline void ctx_update_R(sha256_ctx * ctx,
                         uint8_t    * string,
                         const uint32_t len) {

    ctx->total += len;
    uint32_t startpos = ctx->buflen;

    insert_to_buffer_R(ctx, string, (startpos + len <= 64 ? len : 64 - startpos));

    if (ctx->buflen == 64) {  //Branching.
        sha256_block(ctx);

        uint32_t offset = 64 - startpos;
        ctx->buflen = len - offset;

        //Unaligned memory acess.
	for (uint32_t i = 0; i < ctx->buflen; i++)
	    PUTCHAR_BE_32(BUFFER, i, string[(offset + i) ^ 3]);

	clear_buffer(ctx->buffer->mem_32, ctx->buflen, 16);
    }
}

inline void ctx_update_G(         sha256_ctx * ctx,
                         __global uint8_t    * string, uint32_t len) {

    ctx->total += len;
    uint32_t startpos = ctx->buflen;

    insert_to_buffer_G(ctx, string, (startpos + len <= 64 ? len : 64 - startpos));

    if (ctx->buflen == 64) {  //Branching.
        sha256_block(ctx);

        uint32_t offset = 64 - startpos;
        ctx->buflen = len - offset;

        //Unaligned memory acess.
	for (uint32_t i = 0; i < ctx->buflen; i++)
	    PUTCHAR_BE_32(BUFFER, i, string[(offset + i) ^ 3]);

	clear_buffer(ctx->buffer->mem_32, ctx->buflen, 16);
    }
}

inline void ctx_update_C(           sha256_ctx * ctx,
                         __constant uint8_t    * string, uint32_t len) {

    ctx->total += len;
    uint32_t startpos = ctx->buflen;

    insert_to_buffer_C(ctx, string, (startpos + len <= 64 ? len : 64 - startpos));

    if (ctx->buflen == 64) {  //Branching.
        sha256_block(ctx);

        uint32_t offset = 64 - startpos;
        ctx->buflen = len - offset;

        //Unaligned memory acess.
	for (uint32_t i = 0; i < ctx->buflen; i++)
	    PUTCHAR_BE_32(BUFFER, i, string[(offset + i) ^ 3]);

	clear_buffer(ctx->buffer->mem_32, ctx->buflen, 16);
    }
}

inline void sha256_prepare(__constant sha256_salt     * salt_data,
                           __global   sha256_password * keys_data,
                                      sha256_buffers  * fast_buffers) {

#define pass        keys_data->pass->mem_08
#define passlen     keys_data->length
#define salt        salt_data->salt_be->mem_08
#define saltlen     salt_data->length
#define alt_result  fast_buffers->alt_result
#define temp_result fast_buffers->temp_result
#define p_sequence  fast_buffers->p_sequence

    sha256_ctx     ctx;

    init_ctx(&ctx);

    ctx_update_G(&ctx, pass, passlen);
    ctx_update_C(&ctx, salt, saltlen);
    ctx_update_G(&ctx, pass, passlen);

    sha256_digest(&ctx, alt_result->mem_32, BUFFER_ARRAY);
    init_ctx(&ctx);

    ctx_update_G(&ctx, pass, passlen);
    ctx_update_C(&ctx, salt, saltlen);
    ctx_update_R(&ctx, alt_result->mem_08, passlen);

    for (uint32_t i = passlen; i > 0; i >>= 1) {

        if (i & 1)
            ctx_update_R(&ctx, alt_result->mem_08, 32U);
        else
            ctx_update_G(&ctx, pass, passlen);
    }
    sha256_digest(&ctx, alt_result->mem_32, BUFFER_ARRAY);
    init_ctx(&ctx);

    for (uint32_t i = 0; i < passlen; i++)
        ctx_update_G(&ctx, pass, passlen);

    sha256_digest(&ctx, p_sequence->mem_32, PLAINTEXT_ARRAY);
    init_ctx(&ctx);

    /* For every character in the password add the entire password. */
    for (uint32_t i = 0; i < 16U + alt_result->mem_08[3]; i++)
        ctx_update_C(&ctx, salt, saltlen);

    sha256_digest(&ctx, temp_result->mem_32, SALT_ARRAY);

    /* Assure temp buffers has no trash. */
    clear_buffer(p_sequence->mem_32, passlen, PLAINTEXT_ARRAY);
    clear_buffer(temp_result->mem_32, saltlen, SALT_ARRAY);
}
#undef salt
#undef pass
#undef saltlen
#undef passlen
#undef alt_result
#undef temp_result
#undef p_sequence

__kernel
void kernel_prepare(__constant sha256_salt     * salt,
                    __global   sha256_password * keys_buffer,
                    __global   sha256_buffers  * tmp_memory) {

    //Compute buffers (on Nvidia, better private)
    sha256_buffers fast_buffers;

    //Get the task to be done
    size_t gid = get_global_id(0);

    //Do all computation using BE.
    for (int i = 0; i < PLAINTEXT_ARRAY; i++)
        keys_buffer[gid].pass[i].mem_32[0] = SWAP32(keys_buffer[gid].pass[i].mem_32[0]);

    //Do the job
    sha256_prepare(salt, &keys_buffer[gid], &fast_buffers);

    //Save results.
    for (int i = 0; i < 8; i++)
        tmp_memory[gid].alt_result[i].mem_32[0] = (fast_buffers.alt_result[i].mem_32[0]);

    for (int i = 0; i < SALT_ARRAY; i++)
        tmp_memory[gid].temp_result[i].mem_32[0] = (fast_buffers.temp_result[i].mem_32[0]);

    for (int i = 0; i < PLAINTEXT_ARRAY; i++)
        tmp_memory[gid].p_sequence[i].mem_32[0] = (fast_buffers.p_sequence[i].mem_32[0]);
}

/************************** hashing **************************/
#define temp_result tmp_memory->temp_result
#define p_sequence  tmp_memory->p_sequence
#define alt_result  tmp_memory->alt_result
inline void sha256_crypt(__global sha256_buffers * tmp_memory,
                         const uint32_t saltlen, const uint32_t passlen,
                         const uint32_t initial, const uint32_t rounds) {

    sha256_ctx     ctx;
    buffer_32      result[8];

    //Transfer host global data to a faster memory space.
    #pragma unroll
    for (int i = 0; i < 8; i++)
        result[i].mem_32[0] = alt_result[i].mem_32[0];

    /* Repeatedly run the collected hash value through SHA256 to burn cycles. */
    for (uint32_t i = initial; i < rounds; i++) {
        //Prepare CTX buffer.
        init_ctx(&ctx);

	if (i & 1) {
	    ctx.buffer[0].mem_32[0] = p_sequence[0].mem_32[0];
	    ctx.buffer[1].mem_32[0] = p_sequence[1].mem_32[0];
	    ctx.buffer[2].mem_32[0] = p_sequence[2].mem_32[0];
	    ctx.buffer[3].mem_32[0] = p_sequence[3].mem_32[0];
	    ctx.buffer[4].mem_32[0] = p_sequence[4].mem_32[0];
	    ctx.buffer[5].mem_32[0] = p_sequence[5].mem_32[0];
	    ctx.buflen = passlen;
	    ctx.total = passlen;
	} else {
	    ctx.buffer[0].mem_32[0] = result[0].mem_32[0];
	    ctx.buffer[1].mem_32[0] = result[1].mem_32[0];
	    ctx.buffer[2].mem_32[0] = result[2].mem_32[0];
	    ctx.buffer[3].mem_32[0] = result[3].mem_32[0];
	    ctx.buffer[4].mem_32[0] = result[4].mem_32[0];
	    ctx.buffer[5].mem_32[0] = result[5].mem_32[0];
	    ctx.buffer[6].mem_32[0] = result[6].mem_32[0];
	    ctx.buffer[7].mem_32[0] = result[7].mem_32[0];
	    ctx.buflen = 32U;
	    ctx.total = 32U;
	}

        if (i % 3) {
	    insert_to_buffer_G(&ctx, temp_result->mem_08, saltlen);
	    ctx.total = ctx.buflen;
	}

        if (i % 7) {
            ctx_update_G(&ctx, p_sequence->mem_08, passlen);
	}

	if (i & 1)
            ctx_update_R(&ctx, result->mem_08, 32U);
	else
            ctx_update_G(&ctx, p_sequence->mem_08, passlen);

	sha256_digest(&ctx, result->mem_32, 8);
    }
    //Push results back to global memory.
    #pragma unroll
    for (int i = 0; i < 8; i++)
        alt_result[i].mem_32[0] = (ctx.H[i]);
}
#undef alt_result
#undef temp_result
#undef p_sequence

__kernel
void kernel_crypt(__constant sha256_salt     * salt,
                  __global   sha256_password * keys_buffer,
                  __global   sha256_hash     * out_buffer,
                  __global   sha256_buffers  * tmp_memory) {

    //Get the task to be done
    size_t gid = get_global_id(0);

    //Do the job
    sha256_crypt(&tmp_memory[gid],
                 salt->length, keys_buffer[gid].length, 0, HASH_LOOPS);
}

__kernel
void kernel_final(__constant sha256_salt     * salt,
                  __global   sha256_password * keys_buffer,
                  __global   sha256_hash     * out_buffer,
                  __global   sha256_buffers  * tmp_memory) {

    //Get the task to be done
    size_t gid = get_global_id(0);

    //Do the job
    sha256_crypt(&tmp_memory[gid],
                 salt->length, keys_buffer[gid].length, 0, salt->final);

    //Send results to the host.
    #pragma unroll
    for (int i = 0; i < 8; i++)
        out_buffer[gid].v[i] = SWAP32(tmp_memory[gid].alt_result[i].mem_32[0]);
}
