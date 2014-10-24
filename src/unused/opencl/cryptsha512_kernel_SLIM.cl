/*
 * Developed by Claudio André <claudioandre.br at gmail.com> in 2012
 *
 * More information at http://openwall.info/wiki/john/OpenCL-SHA-512
 *
 * Copyright (c) 2012-2014 Claudio André <claudioandre.br at gmail.com>
 * This program comes with ABSOLUTELY NO WARRANTY; express or implied.
 *
 * This is free software, and you are welcome to redistribute it
 * under certain conditions; as expressed here
 * http://www.gnu.org/licenses/gpl-2.0.html
 */

#include "opencl_cryptsha512.h"

#if gpu(DEVICE_INFO) && !amd_gcn(DEVICE_INFO)
    #define VECTOR_USAGE
#endif

///	    *** UNROLL ***
///AMD: sometimes a bad thing(?).
///NVIDIA: GTX 570 don't allow full unroll.
#if amd_gcn(DEVICE_INFO)
    #define WEAK_UNROLL		1
#elif gpu_amd(DEVICE_INFO)
    #define STRONG_UNROLL	1
#elif cpu(DEVICE_INFO)
    #define STRONG_UNROLL	1
#elif (nvidia_sm_2x(DEVICE_INFO) || nvidia_sm_3x(DEVICE_INFO))
    #define MEDIUM_UNROLL	1
#elif nvidia_sm_5x(DEVICE_INFO)
    #define STRONG_UNROLL	1
#endif

/************************** helper **************************/
inline void init_H(sha512_ctx * ctx) {
    ctx->H[0] = H0;
    ctx->H[1] = H1;
    ctx->H[2] = H2;
    ctx->H[3] = H3;
    ctx->H[4] = H4;
    ctx->H[5] = H5;
    ctx->H[6] = H6;
    ctx->H[7] = H7;
}

inline void init_ctx(sha512_ctx * ctx) {
    ctx->H[0] = H0;
    ctx->H[1] = H1;
    ctx->H[2] = H2;
    ctx->H[3] = H3;
    ctx->H[4] = H4;
    ctx->H[5] = H5;
    ctx->H[6] = H6;
    ctx->H[7] = H7;

    ctx->buffer[0].mem_64[0] = 0;
    ctx->buffer[1].mem_64[0] = 0;
    ctx->buffer[2].mem_64[0] = 0;
    ctx->buffer[3].mem_64[0] = 0;
    ctx->buffer[4].mem_64[0] = 0;
    ctx->buffer[5].mem_64[0] = 0;
    ctx->buffer[6].mem_64[0] = 0;
    ctx->buffer[7].mem_64[0] = 0;
    ctx->buffer[8].mem_64[0] = 0;
    ctx->buffer[9].mem_64[0] = 0;
    ctx->buffer[10].mem_64[0] = 0;
    ctx->buffer[11].mem_64[0] = 0;
    ctx->buffer[12].mem_64[0] = 0;
    ctx->buffer[13].mem_64[0] = 0;
    ctx->buffer[14].mem_64[0] = 0;
    ctx->buffer[15].mem_64[0] = 0;

    ctx->total = 0;
    ctx->buflen = 0;
}

inline void clear_ctx_buffer(sha512_ctx * ctx) {

    ctx->buffer[0].mem_64[0] = 0;
    ctx->buffer[1].mem_64[0] = 0;
    ctx->buffer[2].mem_64[0] = 0;
    ctx->buffer[3].mem_64[0] = 0;
    ctx->buffer[4].mem_64[0] = 0;
    ctx->buffer[5].mem_64[0] = 0;
    ctx->buffer[6].mem_64[0] = 0;
    ctx->buffer[7].mem_64[0] = 0;
    ctx->buffer[8].mem_64[0] = 0;
    ctx->buffer[9].mem_64[0] = 0;
    ctx->buffer[10].mem_64[0] = 0;
    ctx->buffer[11].mem_64[0] = 0;
    ctx->buffer[12].mem_64[0] = 0;
    ctx->buffer[13].mem_64[0] = 0;
    ctx->buffer[14].mem_64[0] = 0;
    ctx->buffer[15].mem_64[0] = 0;

    ctx->buflen = 0;
}

/************************** prepare **************************/
inline void clear_buffer(uint64_t     * destination,
                         const uint32_t len,
                         const uint32_t limit) {

    uint32_t length;

    CLEAR_BUFFER_BE_64(destination, len);

    while (length < limit) {
        destination[length] = 0;
        length++;
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
    uint64_t t;
    uint64_t w[16];

#ifdef VECTOR_USAGE
    ulong16  w_vector = vload16(0, ctx->buffer->mem_64);
    vstore16(w_vector, 0, w);
#else
    #pragma unroll
    for (int i = 0; i < 16; i++)
        w[i] = (ctx->buffer[i].mem_64[0]);
#endif

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

#ifdef AMD_STUPID_BUG_1
    #pragma unroll 4
#endif
    for (int i = 16; i < 80; i++) {
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

inline void sha512_digest(sha512_ctx * ctx,
                          uint64_t   * result,
                          const uint32_t size) {

    if (ctx->buflen <= 111) { //data+0x80+datasize fits in one 1024bit block
	APPEND_BE_SINGLE(ctx->buffer->mem_64, 0x8000000000000000UL, ctx->buflen);
	clear_buffer(ctx->buffer->mem_64, ctx->buflen+1, 16);
	ctx->buffer[15].mem_64[0] = ((uint64_t) (ctx->total * 8));
	ctx->buflen = 0;

    } else {
        bool moved = true;

        if (ctx->buflen < 128) { //data and 0x80 fits in one block
	    APPEND_BE_SINGLE(ctx->buffer->mem_64, 0x8000000000000000UL, ctx->buflen);
	    clear_buffer(ctx->buffer->mem_64, ctx->buflen+1, 16);
            moved = false;
        }
        sha512_block(ctx);
        clear_ctx_buffer(ctx);

        if (moved) //append 1,the rest is already clean
            ctx->buffer[0].mem_64[0] = 0x8000000000000000UL;
        ctx->buffer[15].mem_64[0] = ((uint64_t) (ctx->total * 8));
    }
    sha512_block(ctx);

    for (uint32_t i = 0; i < size; i++)
        result[i] = (ctx->H[i]);
}

inline void insert_to_buffer_R(sha512_ctx    * ctx,
                               const uint8_t * string,
                               const uint32_t len) {

    uint64_t * s = (uint64_t *) string;
    uint32_t tmp, pos;
    tmp = ((ctx->buflen & 7) << 3);
    pos = (ctx->buflen >> 3);

    for (uint32_t i = 0; i < len; i+=8, s++) {
	APPEND_BE_BUFFER_F(ctx->buffer->mem_64, s[0]);
    }
    ctx->buflen += len;

    //A fast clean should be possible.
    clear_buffer(ctx->buffer->mem_64, ctx->buflen, 16);
}

inline void insert_to_buffer_G(         sha512_ctx    * ctx,
                               __global const uint8_t * string,
                               const uint32_t len) {

    __global uint64_t * s = (__global uint64_t *) string;
    uint32_t tmp, pos;
    tmp = ((ctx->buflen & 7) << 3);
    pos = (ctx->buflen >> 3);

    for (uint32_t i = 0; i < len; i+=8, s++) {
	APPEND_BE_BUFFER_F(ctx->buffer->mem_64, s[0]);
    }
    ctx->buflen += len;
    tmp = (ctx->buflen & 7);

    if (tmp) {
	pos = (ctx->buflen >> 3);
	ctx->buffer[pos].mem_64[0] = ctx->buffer[pos].mem_64[0] & clear_mask_be[tmp];
    }
}

inline void insert_to_buffer_C(           sha512_ctx    * ctx,
                               __constant const uint8_t * string,
                               const uint32_t len) {

    __constant uint64_t * s = (__constant uint64_t *) string;
    uint32_t tmp, pos;
    tmp = ((ctx->buflen & 7) << 3);
    pos = (ctx->buflen >> 3);

    for (uint32_t i = 0; i < len; i+=8, s++) {
	APPEND_BE_BUFFER_F(ctx->buffer->mem_64, s[0]);
    }
    ctx->buflen += len;
    tmp = (ctx->buflen & 7);

    if (tmp) {
	pos = (ctx->buflen >> 3);
	ctx->buffer[pos].mem_64[0] = ctx->buffer[pos].mem_64[0] & clear_mask_be[tmp];
    }
}

inline void ctx_update_R(sha512_ctx * ctx,
                         uint8_t    * string,
                         const uint32_t len) {

    ctx->total += len;
    uint32_t startpos = ctx->buflen;

    insert_to_buffer_R(ctx, string, (startpos + len <= 128 ? len : 128 - startpos));

    if (ctx->buflen == 128) {  //Branching.
        sha512_block(ctx);

        uint32_t offset = 128 - startpos;
        ctx->buflen = len - offset;

        //Unaligned memory acess.
	for (uint32_t i = 0; i < ctx->buflen; i++)
	    PUTCHAR_BE_64(BUFFER, i, string[(offset + i) ^ 7]);

	clear_buffer(ctx->buffer->mem_64, ctx->buflen, 16);
    }
}

inline void ctx_update_G(         sha512_ctx * ctx,
                         __global uint8_t    * string, uint32_t len) {

    ctx->total += len;
    uint32_t startpos = ctx->buflen;

    insert_to_buffer_G(ctx, string, (startpos + len <= 128 ? len : 128 - startpos));

    if (ctx->buflen == 128) {  //Branching.
        sha512_block(ctx);

        uint32_t offset = 128 - startpos;
        ctx->buflen = len - offset;

        //Unaligned memory acess.
	for (uint32_t i = 0; i < ctx->buflen; i++)
	    PUTCHAR_BE_64(BUFFER, i, string[(offset + i) ^ 7]);

	clear_buffer(ctx->buffer->mem_64, ctx->buflen, 16);
    }
}

inline void ctx_update_C(           sha512_ctx * ctx,
                         __constant uint8_t    * string, uint32_t len) {

    ctx->total += len;
    uint32_t startpos = ctx->buflen;

    insert_to_buffer_C(ctx, string, (startpos + len <= 128 ? len : 128 - startpos));

    if (ctx->buflen == 128) {  //Branching.
        sha512_block(ctx);

        uint32_t offset = 128 - startpos;
        ctx->buflen = len - offset;

        //Unaligned memory acess.
	for (uint32_t i = 0; i < ctx->buflen; i++)
	    PUTCHAR_BE_64(BUFFER, i, string[(offset + i) ^ 7]);

	clear_buffer(ctx->buffer->mem_64, ctx->buflen, 16);
    }
}

inline void sha512_prepare(__constant sha512_salt     * salt_data,
                           __global   sha512_password * keys_data,
                                      sha512_buffers  * fast_buffers) {

#define pass        keys_data->pass->mem_08
#define passlen     keys_data->length
#define salt        salt_data->salt_be->mem_08
#define saltlen     salt_data->length
#define alt_result  fast_buffers->alt_result
#define temp_result fast_buffers->temp_result
#define p_sequence  fast_buffers->p_sequence

    sha512_ctx     ctx;

    clear_ctx_buffer(&ctx);

    insert_to_buffer_G(&ctx, pass, passlen);
    insert_to_buffer_C(&ctx, salt, saltlen);
    insert_to_buffer_G(&ctx, pass, passlen);

    ctx.total = ctx.buflen;
    init_H(&ctx);

    sha512_digest(&ctx, alt_result->mem_64, BUFFER_ARRAY);
    clear_ctx_buffer(&ctx);

    insert_to_buffer_G(&ctx, pass, passlen);
    insert_to_buffer_C(&ctx, salt, saltlen);
    insert_to_buffer_R(&ctx, alt_result->mem_08, passlen);

    ctx.total = ctx.buflen;
    init_H(&ctx);

    for (uint32_t i = passlen; i > 0; i >>= 1) {

        if (i & 1)
            ctx_update_R(&ctx, alt_result->mem_08, 64U);
        else
            ctx_update_G(&ctx, pass, passlen);
    }
    sha512_digest(&ctx, alt_result->mem_64, BUFFER_ARRAY);
    init_ctx(&ctx);

    for (uint32_t i = 0; i < passlen; i++)
        ctx_update_G(&ctx, pass, passlen);

    sha512_digest(&ctx, p_sequence->mem_64, PLAINTEXT_ARRAY);
    init_ctx(&ctx);

    /* For every character in the password add the entire password. */
    for (uint32_t i = 0; i < 16U + alt_result->mem_08[7]; i++)
        ctx_update_C(&ctx, salt, saltlen);

    sha512_digest(&ctx, temp_result->mem_64, SALT_ARRAY);

    /* Assure temp buffers has no trash. */
    clear_buffer(p_sequence->mem_64, passlen, PLAINTEXT_ARRAY);
    clear_buffer(temp_result->mem_64, saltlen, SALT_ARRAY);
}
#undef salt
#undef pass
#undef saltlen
#undef passlen
#undef alt_result
#undef temp_result
#undef p_sequence

__kernel
void kernel_prepare(__constant sha512_salt     * salt,
                    __global   sha512_password * keys_buffer,
                    __global   sha512_buffers  * tmp_memory) {

    //Compute buffers (on Nvidia, better private)
    sha512_buffers fast_buffers;

    //Get the task to be done
    size_t gid = get_global_id(0);

    //Do all computation using BE.
    for (int i = 0; i < PLAINTEXT_ARRAY; i++)
        keys_buffer[gid].pass[i].mem_64[0] = SWAP64(keys_buffer[gid].pass[i].mem_64[0]);

    //Do the job
    sha512_prepare(salt, &keys_buffer[gid], &fast_buffers);

    //Save results.
    for (int i = 0; i < 8; i++)
        tmp_memory[gid].alt_result[i].mem_64[0] = (fast_buffers.alt_result[i].mem_64[0]);

    for (int i = 0; i < SALT_ARRAY; i++)
        tmp_memory[gid].temp_result[i].mem_64[0] = (fast_buffers.temp_result[i].mem_64[0]);

    for (int i = 0; i < PLAINTEXT_ARRAY; i++)
        tmp_memory[gid].p_sequence[i].mem_64[0] = (fast_buffers.p_sequence[i].mem_64[0]);
}

/************************** hashing **************************/
inline void sha512_block_slim(uint64_t * buffer, uint64_t * H) {
    uint64_t t;
    uint64_t a = H[0];
    uint64_t b = H[1];
    uint64_t c = H[2];
    uint64_t d = H[3];
    uint64_t e = H[4];
    uint64_t f = H[5];
    uint64_t g = H[6];
    uint64_t h = H[7];
    uint64_t w[16];

#ifdef VECTOR_USAGE
    ulong16  w_vector = vload16(0, buffer);
    vstore16(w_vector, 0, w);
#else
    #pragma unroll
    for (int i = 0; i < 16; i++)
        w[i] = buffer[i];
#endif

#ifdef STRONG_UNROLL
    #pragma unroll
#endif
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

#ifdef STRONG_UNROLL
    #pragma unroll
#elif MEDIUM_UNROLL
    #pragma unroll 16
#elif WEAK_UNROLL
    #pragma unroll 8
#endif
    for (int i = 16; i < 80; i++) {
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
    H[0] += a;
    H[1] += b;
    H[2] += c;
    H[3] += d;
    H[4] += e;
    H[5] += f;
    H[6] += g;
    H[7] += h;
}

inline void sha512_digest_slim(sha512_ctx * ctx,
                               const uint32_t size) {

    if (ctx->buflen <= 111) { //data+0x80+datasize fits in one 1024bit block
	APPEND_BE_SINGLE(ctx->buffer->mem_64, 0x8000000000000000UL, ctx->buflen);
	clear_buffer(ctx->buffer->mem_64, ctx->buflen+1, 16);
	ctx->buffer[15].mem_64[0] = ((uint64_t) (ctx->total * 8));
	ctx->buflen = 0;

    } else {
        bool moved = true;

        if (ctx->buflen < 128) { //data and 0x80 fits in one block
	    APPEND_BE_SINGLE(ctx->buffer->mem_64, 0x8000000000000000UL, ctx->buflen);
	    clear_buffer(ctx->buffer->mem_64, ctx->buflen+1, 16);
            moved = false;
        }
        sha512_block_slim(ctx->buffer->mem_64, ctx->H);
        clear_ctx_buffer(ctx);

        if (moved) //append 1,the rest is already clean
            ctx->buffer[0].mem_64[0] = 0x8000000000000000UL;
        ctx->buffer[15].mem_64[0] = ((uint64_t) (ctx->total * 8));
    }
    sha512_block_slim(ctx->buffer->mem_64, ctx->H);
}

#define temp_result tmp_memory->temp_result
#define p_sequence  tmp_memory->p_sequence
#define alt_result  tmp_memory->alt_result
inline void sha512_crypt(__global sha512_buffers * tmp_memory,
                         const uint32_t saltlen, const uint32_t passlen,
                         const uint32_t initial, const uint32_t rounds) {

    sha512_ctx     ctx;

    //Transfer host global data to a faster memory space.
    #pragma unroll
    for (int i = 0; i < 8; i++)
        ctx.H[i] = alt_result[i].mem_64[0];

    /* Repeatedly run the collected hash value through SHA512 to burn cycles. */
    for (uint32_t i = initial; i < rounds; i++) {
        //Prepare CTX buffer.
        clear_ctx_buffer(&ctx);

	if (i & 1) {
	    ctx.buffer[0].mem_64[0] = p_sequence[0].mem_64[0];
	    ctx.buffer[1].mem_64[0] = p_sequence[1].mem_64[0];
	    ctx.buffer[2].mem_64[0] = p_sequence[2].mem_64[0];
	    ctx.buflen = passlen;
	    ctx.total = passlen;
	} else {
	    ctx.buffer[0].mem_64[0] = ctx.H[0];
	    ctx.buffer[1].mem_64[0] = ctx.H[1];
	    ctx.buffer[2].mem_64[0] = ctx.H[2];
	    ctx.buffer[3].mem_64[0] = ctx.H[3];
	    ctx.buffer[4].mem_64[0] = ctx.H[4];
	    ctx.buffer[5].mem_64[0] = ctx.H[5];
	    ctx.buffer[6].mem_64[0] = ctx.H[6];
	    ctx.buffer[7].mem_64[0] = ctx.H[7];
	    ctx.buflen = 64U;
	    ctx.total = 64U;
	}

        if (i % 3) {
	    insert_to_buffer_G(&ctx, temp_result->mem_08, saltlen);
	    ctx.total = ctx.buflen;
	}

        if (i % 7) {
            insert_to_buffer_G(&ctx, p_sequence->mem_08, passlen);
	    ctx.total = ctx.buflen;
	}

	if (i & 1)
            ctx_update_R(&ctx, (uint8_t *) ctx.H, 64U);
	else
            ctx_update_G(&ctx, p_sequence->mem_08, passlen);

	init_H(&ctx);
        sha512_digest_slim(&ctx, BUFFER_ARRAY);
    }
    //Push results back to global memory.
    #pragma unroll
    for (int i = 0; i < 8; i++)
        alt_result[i].mem_64[0] = (ctx.H[i]);
}
#undef alt_result
#undef temp_result
#undef p_sequence

__kernel
void kernel_crypt(__constant sha512_salt     * salt,
                  __global   sha512_password * keys_buffer,
                  __global   sha512_hash     * out_buffer,
                  __global   sha512_buffers  * tmp_memory) {

    //Get the task to be done
    size_t gid = get_global_id(0);

    //Do the job
    sha512_crypt(&tmp_memory[gid],
                 salt->length, keys_buffer[gid].length, 0, HASH_LOOPS);
}

__kernel
void kernel_final(__constant sha512_salt     * salt,
                  __global   sha512_password * keys_buffer,
                  __global   sha512_hash     * out_buffer,
                  __global   sha512_buffers  * tmp_memory) {

    //Get the task to be done
    size_t gid = get_global_id(0);

    //Do the job
    sha512_crypt(&tmp_memory[gid],
                 salt->length, keys_buffer[gid].length, 0, salt->final);

    //Send results to the host.
    #pragma unroll
    for (int i = 0; i < 8; i++)
        out_buffer[gid].v[i] = SWAP64(tmp_memory[gid].alt_result[i].mem_64[0]);
}
