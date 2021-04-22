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

#if (gpu_amd(DEVICE_INFO) && DEV_VER_MAJOR < 1729)
    #define VECTOR_USAGE    1
#endif

#ifndef UNROLL_LOOP
    ///	    *** UNROLL ***
    ///AMD: sometimes a bad thing(?).
    ///NVIDIA: GTX 570 don't allow full unroll.
    #if amd_vliw4(DEVICE_INFO) || amd_vliw5(DEVICE_INFO)
        #define UNROLL_LOOP    33818632
    #elif amd_gcn(DEVICE_INFO) && DEV_VER_MAJOR < 2500
        #define UNROLL_LOOP    132104
    #elif amd_gcn(DEVICE_INFO) && DEV_VER_MAJOR >= 2500
        #define UNROLL_LOOP    132104
    #elif nvidia_sm_2x(DEVICE_INFO)
        #define UNROLL_LOOP    131080
    #elif nvidia_sm_3x(DEVICE_INFO)
        #define UNROLL_LOOP    132104
    #elif nvidia_sm_5x(DEVICE_INFO)
        #define UNROLL_LOOP    132104
    #elif gpu_nvidia(DEVICE_INFO)
        #define UNROLL_LOOP    132104
    #elif gpu_intel(DEVICE_INFO)
        #define UNROLL_LOOP    131586
    #else
        #define UNROLL_LOOP    0
    #endif
#endif

#if (UNROLL_LOOP & (1 << 25))
    #define VECTOR_USAGE    1
#endif

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

    CLEAR_BUFFER_32(destination, len);

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
    uint16  w_vector;
    w_vector = vload16(0, ctx->buffer->mem_32);
    w_vector = SWAP32_V(w_vector);
    vstore16(w_vector, 0, w);
#else
    #pragma unroll
    for (uint i = 0U; i < 16U; i++)
        w[i] = SWAP32(ctx->buffer[i].mem_32[0]);
#endif

    #pragma unroll
    for (uint i = 0U; i < 16U; i++) {
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
    for (uint i = 16U; i < 64U; i++) {
	w[i & 15] = w[(i - 16) & 15] + w[(i - 7) & 15] + sigma1(w[(i - 2) & 15]) + sigma0(w[(i - 15) & 15]);
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

inline void insert_to_buffer_R(sha256_ctx    * ctx,
                               const uint8_t * string,
                               const uint32_t len) {

    uint32_t * s = (uint32_t *) string;
    uint32_t tmp, pos;
    tmp = ((ctx->buflen & 3U) << 3);
    pos = (ctx->buflen >> 2);

    for (uint i = 0U; i < len; i+=4, s++) {
	APPEND_BUFFER_F(ctx->buffer->mem_32, s[0]);
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
    tmp = ((ctx->buflen & 3U) << 3);
    pos = (ctx->buflen >> 2);

    for (uint i = 0U; i < len; i+=4, s++) {
	APPEND_BUFFER_F(ctx->buffer->mem_32, s[0]);
    }
    ctx->buflen += len;
    tmp = (ctx->buflen & 3U);

    if (tmp) {
	pos = (ctx->buflen >> 2);
	ctx->buffer[pos].mem_32[0] = ctx->buffer[pos].mem_32[0] & clear_mask[tmp];
    }
}

inline void insert_to_buffer_C(           sha256_ctx    * ctx,
                               MAYBE_CONSTANT uint8_t * string,
                               const uint32_t len) {

    MAYBE_CONSTANT uint32_t * s = (MAYBE_CONSTANT uint32_t *) string;
    uint32_t tmp, pos;
    tmp = ((ctx->buflen & 3U) << 3);
    pos = (ctx->buflen >> 2);

    for (uint i = 0U; i < len; i+=4, s++) {
	APPEND_BUFFER_F(ctx->buffer->mem_32, s[0]);
    }
    ctx->buflen += len;
    tmp = (ctx->buflen & 3U);

    if (tmp) {
	pos = (ctx->buflen >> 2);
	ctx->buffer[pos].mem_32[0] = ctx->buffer[pos].mem_32[0] & clear_mask[tmp];
    }
}

inline void ctx_update_R(sha256_ctx * ctx,
                         uint8_t    * string,
                         const uint32_t len) {

    ctx->total += len;
    uint32_t startpos = ctx->buflen;

    insert_to_buffer_R(ctx, string, (startpos + len <= 64U ? len : 64U - startpos));

    if (ctx->buflen == 64U) {  //Branching.
        uint32_t offset = 64U - startpos;
        sha256_block(ctx);
        ctx->buflen = len - offset;

        //Unaligned memory acess.
	for (uint i = 0U; i < ctx->buflen; i++)
	    PUT(BUFFER, i, (string + offset)[i]);

	clear_buffer(ctx->buffer->mem_32, ctx->buflen, 16);
    }
}

inline void ctx_update_G(         sha256_ctx * ctx,
                         __global const uint8_t    * string, uint32_t len) {

    ctx->total += len;
    uint32_t startpos = ctx->buflen;

    insert_to_buffer_G(ctx, string, (startpos + len <= 64U ? len : 64U - startpos));

    if (ctx->buflen == 64U) {  //Branching.
        uint32_t offset = 64U - startpos;
        sha256_block(ctx);
        ctx->buflen = len - offset;

        //Unaligned memory acess.
	for (uint i = 0U; i < ctx->buflen; i++)
	    PUT(BUFFER, i, (string + offset)[i]);

	clear_buffer(ctx->buffer->mem_32, ctx->buflen, 16);
    }
}

inline void ctx_update_C(           sha256_ctx * ctx,
                         MAYBE_CONSTANT uint8_t    * string, uint32_t len) {

    ctx->total += len;
    uint32_t startpos = ctx->buflen;

    insert_to_buffer_C(ctx, string, (startpos + len <= 64U ? len : 64U - startpos));

    if (ctx->buflen == 64U) {  //Branching.
        uint32_t offset = 64U - startpos;
        sha256_block(ctx);
        ctx->buflen = len - offset;

        //Unaligned memory acess.
	for (uint i = 0U; i < ctx->buflen; i++)
	    PUT(BUFFER, i, (string + offset)[i]);

	clear_buffer(ctx->buffer->mem_32, ctx->buflen, 16);
    }
}

inline void sha256_digest(sha256_ctx * ctx,
                          uint32_t   * result,
                          const uint32_t size) {

    if (ctx->buflen < 56U) { //data+0x80+datasize fits in one 512bit block
	APPEND_SINGLE(ctx->buffer->mem_32, 0x80U, ctx->buflen);
	ctx->buffer[15].mem_32[0] = SWAP32((uint32_t) (ctx->total * 8));
	ctx->buflen = 0;

    } else {
        bool moved = true;

        if (ctx->buflen < 64U) { //data and 0x80 fits in one block
	    APPEND_SINGLE(ctx->buffer->mem_32, 0x80U, ctx->buflen);
            moved = false;
        }
        sha256_block(ctx);
        clear_ctx_buffer(ctx);

        if (moved) //append 1,the rest is already clean
            ctx->buffer[0].mem_32[0] = 0x80U;
        ctx->buffer[15].mem_32[0] = SWAP32((uint32_t) (ctx->total * 8));
    }
    sha256_block(ctx);

    for (uint i = 0U; i < size; i++)
        result[i] = SWAP32(ctx->H[i]);
}

inline void sha256_prepare(
	MAYBE_CONSTANT sha256_salt     * const __restrict salt_data,
        __global   const sha256_password * const __restrict keys_data,
	                 sha256_buffers  * fast_buffers) {

#define pass        keys_data->pass->mem_08
#define passlen     keys_data->length
#define salt        salt_data->salt->mem_08
#define saltlen     salt_data->length
#define alt_result  fast_buffers->alt_result
#define temp_result fast_buffers->temp_result
#define p_sequence  fast_buffers->p_sequence

    sha256_ctx     ctx;

    clear_ctx_buffer(&ctx);

    insert_to_buffer_G(&ctx, pass, passlen);
    insert_to_buffer_C(&ctx, salt, saltlen);
    insert_to_buffer_G(&ctx, pass, passlen);

    ctx.total = ctx.buflen;
    init_H(&ctx);

    sha256_digest(&ctx, alt_result->mem_32, BUFFER_ARRAY);
    clear_ctx_buffer(&ctx);

    insert_to_buffer_G(&ctx, pass, passlen);
    insert_to_buffer_C(&ctx, salt, saltlen);
    insert_to_buffer_R(&ctx, alt_result->mem_08, passlen);

    ctx.total = ctx.buflen;
    init_H(&ctx);

    for (uint i = passlen; i > 0; i >>= 1) {

        if (i & 1)
            ctx_update_R(&ctx, alt_result->mem_08, 32U);
        else
            ctx_update_G(&ctx, pass, passlen);
    }
    sha256_digest(&ctx, alt_result->mem_32, BUFFER_ARRAY);
    init_ctx(&ctx);

    for (uint i = 0U; i < passlen; i++)
        ctx_update_G(&ctx, pass, passlen);

    sha256_digest(&ctx, p_sequence->mem_32, PLAINTEXT_ARRAY);
    init_ctx(&ctx);

    /* For every character in the password add the entire password. */
    for (uint i = 0U; i < 16U + alt_result->mem_08[0]; i++)
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
void kernel_prepare(
	MAYBE_CONSTANT sha256_salt     * const __restrict salt,
        __global   const sha256_password * const __restrict keys_buffer,
        __global         sha256_buffers  * const __restrict tmp_buffers) {

    //Compute buffers (on Nvidia, better private)
    sha256_buffers fast_buffers;

    //Get the task to be done
    size_t gid = get_global_id(0);

    //Do the job
    sha256_prepare(salt, &keys_buffer[gid], &fast_buffers);

    //Save results.
    #pragma unroll
    for (uint i = 0U; i < 8; i++)
        tmp_buffers[gid].alt_result[i].mem_32[0] = SWAP32(fast_buffers.alt_result[i].mem_32[0]);

    #pragma unroll
    for (uint i = 0U; i < SALT_ARRAY; i++)
        tmp_buffers[gid].temp_result[i].mem_32[0] = SWAP32(fast_buffers.temp_result[i].mem_32[0]);

    #pragma unroll
    for (uint i = 0U; i < PLAINTEXT_ARRAY; i++)
        tmp_buffers[gid].p_sequence[i].mem_32[0] = SWAP32(fast_buffers.p_sequence[i].mem_32[0]);
}

__kernel
void kernel_preprocess(
	MAYBE_CONSTANT sha256_salt     * const __restrict salt,
        __global   const sha256_password * const __restrict keys_buffer,
        __global         sha256_buffers  * const __restrict tmp_buffers,
	__global         uint32_t	 * const __restrict work_memory) {

    //Compute buffers (on Nvidia, better private)
    sha256_buffers fast_buffers;

    //Get the task to be done
    size_t gid = get_global_id(0);

    //Save results.
    #pragma unroll
    for (uint i = 0U; i < 8; i++)
        fast_buffers.alt_result[i].mem_32[0] = (tmp_buffers[gid].alt_result[i].mem_32[0]);

    #pragma unroll
    for (uint i = 0U; i < SALT_ARRAY; i++)
        fast_buffers.temp_result[i].mem_32[0] = (tmp_buffers[gid].temp_result[i].mem_32[0]);

    #pragma unroll
    for (uint i = 0U; i < PLAINTEXT_ARRAY; i++)
        fast_buffers.p_sequence[i].mem_32[0] = (tmp_buffers[gid].p_sequence[i].mem_32[0]);

    //Preload and prepare the temp buffer.
    for (uint i = 0U; i < 8; i++) {
	uint32_t total = 0;
	uint32_t j = generator_index[i];

        #pragma unroll
	for (uint32_t k = 0; k < 8; k++)
	   work_memory[OFFSET(i, k)] = 0;

        if (j & 1) {
	    work_memory[OFFSET(i, 0)] = fast_buffers.p_sequence[0].mem_32[0];
	    work_memory[OFFSET(i, 1)] = fast_buffers.p_sequence[1].mem_32[0];
	    work_memory[OFFSET(i, 2)] = fast_buffers.p_sequence[2].mem_32[0];
	    work_memory[OFFSET(i, 3)] = fast_buffers.p_sequence[3].mem_32[0];
	    work_memory[OFFSET(i, 4)] = fast_buffers.p_sequence[4].mem_32[0];
	    work_memory[OFFSET(i, 5)] = fast_buffers.p_sequence[5].mem_32[0];

            total += keys_buffer[gid].length;
        }

        if (j % 3) {
	    APPEND_BE_SPECIAL(work_memory, fast_buffers.temp_result[0].mem_32[0],
		i, total);
	    APPEND_BE_SPECIAL(work_memory, fast_buffers.temp_result[1].mem_32[0],
		i, total + 4);
	    APPEND_BE_SPECIAL(work_memory, fast_buffers.temp_result[2].mem_32[0],
		i, total + 8);
	    APPEND_BE_SPECIAL(work_memory, fast_buffers.temp_result[3].mem_32[0],
		i, total + 12);
            total += salt->length;
        }

        if (j % 7) {
	    APPEND_BE_SPECIAL(work_memory, fast_buffers.p_sequence[0].mem_32[0],
		i, total);
	    APPEND_BE_SPECIAL(work_memory, fast_buffers.p_sequence[1].mem_32[0],
		i, total + 4);
	    APPEND_BE_SPECIAL(work_memory, fast_buffers.p_sequence[2].mem_32[0],
		i, total + 8);
	    APPEND_BE_SPECIAL(work_memory, fast_buffers.p_sequence[3].mem_32[0],
		i, total + 12);
	    APPEND_BE_SPECIAL(work_memory, fast_buffers.p_sequence[4].mem_32[0],
		i, total + 16);
	    APPEND_BE_SPECIAL(work_memory, fast_buffers.p_sequence[5].mem_32[0],
		i, total + 20);
            total += keys_buffer[gid].length;
        }

        if (! (j & 1)) {
	    APPEND_BE_SPECIAL(work_memory, fast_buffers.p_sequence[0].mem_32[0],
		i, total);
	    APPEND_BE_SPECIAL(work_memory, fast_buffers.p_sequence[1].mem_32[0],
		i, total + 4);
	    APPEND_BE_SPECIAL(work_memory, fast_buffers.p_sequence[2].mem_32[0],
		i, total + 8);
	    APPEND_BE_SPECIAL(work_memory, fast_buffers.p_sequence[3].mem_32[0],
		i, total + 12);
	    APPEND_BE_SPECIAL(work_memory, fast_buffers.p_sequence[4].mem_32[0],
		i, total + 16);
	    APPEND_BE_SPECIAL(work_memory, fast_buffers.p_sequence[5].mem_32[0],
		i, total + 20);
            total += keys_buffer[gid].length;
        }
	work_memory[OFFSET(i, 30)] = total;
    }
}

/************************** hashing **************************/
inline void sha256_block_be(uint32_t * buffer, uint32_t * H) {
    uint32_t t;
    uint32_t a = H[0];
    uint32_t b = H[1];
    uint32_t c = H[2];
    uint32_t d = H[3];
    uint32_t e = H[4];
    uint32_t f = H[5];
    uint32_t g = H[6];
    uint32_t h = H[7];
    uint32_t w[16];

#ifdef VECTOR_USAGE
    uint16  w_vector = vload16(0, buffer);
    vstore16(w_vector, 0, w);
#else
    #pragma unroll
    for (uint i = 0U; i < 16; i++)
        w[i] = buffer[i];
#endif

#if (UNROLL_LOOP & (1 << 1))
    #pragma unroll 1
#elif (UNROLL_LOOP & (1 << 2))
    #pragma unroll 4
#elif (UNROLL_LOOP & (1 << 3))
    #pragma unroll
#endif
    for (uint i = 0U; i < 16U; i++) {
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

#if (UNROLL_LOOP & (1 << 9))
    #pragma unroll 1
#elif (UNROLL_LOOP & (1 << 10))
    #pragma unroll 16
#elif (UNROLL_LOOP & (1 << 11))
    #pragma unroll
#endif
    for (uint i = 16U; i < 64U; i++) {
        w[i & 15] = w[(i - 16) & 15] + w[(i - 7) & 15] + sigma1(w[(i - 2) & 15]) + sigma0(w[(i - 15) & 15]);
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

inline void update_w_G(
	         uint32_t * const w,
	         uint32_t * const H,
        __global uint32_t * const work_memory, const uint32_t loop_index,
                 uint32_t * const position, const uint32_t len) {

    uint32_t startpos = *position;

    {
	uint32_t tmp, pos;
	uint32_t size = (startpos + len <= 64U ? len : 64U - startpos);

	tmp = ((*position & 3U) << 3);
	pos = (*position >> 2);

	for (uint i = 0U; (i << 2) < size; i++) {
	    APPEND_BE_BUFFER_F(w, work_memory[OFFSET(loop_index, (i+8))]);
	}
	*position += size;
    }

    if (*position == 64U) {  //Branching.
        uint32_t offset = 64U - startpos;
        sha256_block_be(w, H);
        *position = len - offset;

	for (uint i = 0U; i < 16; i++)
	    w[i] = 0;

	{
	    uint32_t tmp, pos;
	    tmp = ((offset & 3U) << 3);
	    pos = (offset >> 2);

	    for (uint i = 0U; (i << 2) < *position; i++) {
		w[i] = (work_memory[OFFSET(loop_index, (pos++)+8)] << tmp);
		w[i] = w[i] | (tmp ? (work_memory[OFFSET(loop_index, (pos+8))] >> (32U - tmp)) : 0U);
	    }
	    tmp = (*position & 3U);
	    pos = (*position >> 2);
	    w[pos] = w[pos] & clear_be_mask[tmp];
	}
    }
}

inline void update_w(
	uint32_t * const w,
	uint32_t * const H,
        uint32_t * const string,
        uint32_t * const position, const uint32_t len) {

    uint32_t startpos = *position;

    {
	uint32_t tmp, pos;
	uint32_t size = (startpos + len <= 64U ? len : 64U - startpos);

	tmp = ((*position & 3U) << 3);
	pos = (*position >> 2);

	for (uint i = 0U; (i << 2) < size; i++) {
	    APPEND_BE_BUFFER_F(w, string[i]);
	}
	*position += size;
    }

    if (*position == 64U) {  //Branching.
        uint32_t offset = 64U - startpos;
        sha256_block_be(w, H);
        *position = len - offset;

	for (uint i = 0U; i < 16; i++)
	    w[i] = 0;

	{
	    uint32_t tmp, pos;
	    tmp = ((offset & 3U) << 3);
	    pos = (offset >> 2);

	    for (uint i = 0U; (i << 2) < *position; i++) {
		w[i] = (string[pos++] << tmp);

		if (pos < 16)
		    w[i] = w[i] | (tmp ? (string[pos] >> (32U - tmp)) : 0U);
	    }
	    tmp = (*position & 3U);
	    pos = (*position >> 2);
	    w[pos] = w[pos] & clear_be_mask[tmp];
	}
    }
}

inline void sha256_crypt(
	 __global buffer_32      * const __restrict alt_result,
	 __global uint32_t       * const __restrict work_memory) {

    //To compute buffers.
    uint32_t	    total, buflen;
    uint32_t	    w[16];
    uint32_t	    H[8];

    //Transfer host global data to a faster memory space.
    #pragma unroll
    for (uint i = 0U; i < 8U; i++)
        H[i] = alt_result[i].mem_32[0];

    /* Repeatedly run the collected hash value through SHA256 to burn cycles. */
#if (UNROLL_LOOP & (1 << 17))
    #pragma unroll 1
#elif (UNROLL_LOOP & (1 << 18))
    //Compiler, do the job.
#elif (UNROLL_LOOP & (1 << 19))
    #pragma unroll 2
#endif
    for (uint i = 0U, z = 0U; i < HASH_LOOPS; i++) {
        total = work_memory[OFFSET(loop_index[z], 30)];

        if (i & 1) {
	    #pragma unroll
	    for (uint32_t j = 8U; j < 16U; j++)
		w[j] = 0;

            w[0] = work_memory[OFFSET(loop_index[z], 0)];
            w[1] = work_memory[OFFSET(loop_index[z], 1)];
            w[2] = work_memory[OFFSET(loop_index[z], 2)];
            w[3] = work_memory[OFFSET(loop_index[z], 3)];
            w[4] = work_memory[OFFSET(loop_index[z], 4)];
            w[5] = work_memory[OFFSET(loop_index[z], 5)];
            w[6] = work_memory[OFFSET(loop_index[z], 6)];
            w[7] = work_memory[OFFSET(loop_index[z], 7)];

        } else {
            w[0] = H[0];
            w[1] = H[1];
            w[2] = H[2];
            w[3] = H[3];
            w[4] = H[4];
            w[5] = H[5];
            w[6] = H[6];
            w[7] = H[7];
	    w[8] = work_memory[OFFSET(loop_index[z], 0)];
	    w[9] = work_memory[OFFSET(loop_index[z], 1)];
	    w[10] = work_memory[OFFSET(loop_index[z], 2)];
	    w[11] = work_memory[OFFSET(loop_index[z], 3)];
	    w[12] = work_memory[OFFSET(loop_index[z], 4)];
	    w[13] = work_memory[OFFSET(loop_index[z], 5)];
	    w[14] = work_memory[OFFSET(loop_index[z], 6)];
	    w[15] = work_memory[OFFSET(loop_index[z], 7)];
    }

	if (total > 31) {
	    uint32_t tmp_result[8];

	    #pragma unroll
	    for (uint32_t j = 0U; j < 8U; j++)
		tmp_result[j] = H[j];

	    //Initialize CTX.
	    H[0] = H0;
	    H[1] = H1;
	    H[2] = H2;
	    H[3] = H3;
	    H[4] = H4;
	    H[5] = H5;
	    H[6] = H6;
	    H[7] = H7;

	    buflen = ((i & 1) ? 32U : 64U);
	    update_w_G(w, H, work_memory, loop_index[z], &buflen, (total - 32U));
	    total += 32U;

	    if (i & 1)
		update_w(w, H, tmp_result, &buflen, 32U);

	} else {

	    if (i & 1) {
		uint32_t tmp, pos;
		tmp = ((total & 3U) << 3);
		pos = (total >> 2);

		APPEND_BE_BUFFER(w, H[0]);
		APPEND_BE_BUFFER(w, H[1]);
		APPEND_BE_BUFFER(w, H[2]);
		APPEND_BE_BUFFER(w, H[3]);
		APPEND_BE_BUFFER(w, H[4]);
		APPEND_BE_BUFFER(w, H[5]);
		APPEND_BE_BUFFER(w, H[6]);
		APPEND_BE_BUFFER_F(w, H[7]);
	    }
	    total += 32U;
	    buflen = total;

	    //Initialize CTX.
	    H[0] = H0;
	    H[1] = H1;
	    H[2] = H2;
	    H[3] = H3;
	    H[4] = H4;
	    H[5] = H5;
	    H[6] = H6;
	    H[7] = H7;
	}

        //Do the sha256_digest(ctx);
	if (buflen < 56U) { //data+0x80+datasize fits in one 512bit block
            APPEND_BE_SINGLE(w, 0x80000000U, buflen);
	    w[15] = (total * 8U);

	} else {
            bool moved = true;

            if (buflen < 64U) { //data and 0x80 fits in one block
                APPEND_BE_SINGLE(w, 0x80000000U, buflen);
                moved = false;
            }
	    sha256_block_be(w, H);

	    #pragma unroll
	    for (uint i = 0U; i < 15U; i++)
	        w[i] = 0;

            if (moved) //append 1,the rest is already clean
                w[0] = 0x80000000U;
	    w[15] = (total * 8U);
	}
	sha256_block_be(w, H); //if (i==3) return;

    if (++z == LOOP_SIZE)
        z = 0;
    }
    //Push results back to global memory.
    #pragma unroll
    for (uint i = 0U; i < 8U; i++)
        alt_result[i].mem_32[0] = H[i];
}

inline void sha256_crypt_f(
	const uint32_t rounds,
	__global buffer_32      * const __restrict alt_result,
	__global uint32_t       * const __restrict work_memory) {

    //To compute buffers.
    uint32_t	    total, buflen;
    uint32_t	    w[16];
    uint32_t	    H[8];

    //Transfer host global data to a faster memory space.
    #pragma unroll
    for (uint i = 0U; i < 8U; i++)
        H[i] = alt_result[i].mem_32[0];

    /* Repeatedly run the collected hash value through SHA256 to burn cycles. */
    for (uint i = 0U, z = 0U; i < rounds; i++) {
        total = work_memory[OFFSET(loop_index[z], 30)];

        if (i & 1) {
	    #pragma unroll
	    for (uint32_t j = 8U; j < 16U; j++)
		w[j] = 0;

            w[0] = work_memory[OFFSET(loop_index[z], 0)];
            w[1] = work_memory[OFFSET(loop_index[z], 1)];
            w[2] = work_memory[OFFSET(loop_index[z], 2)];
            w[3] = work_memory[OFFSET(loop_index[z], 3)];
            w[4] = work_memory[OFFSET(loop_index[z], 4)];
            w[5] = work_memory[OFFSET(loop_index[z], 5)];
            w[6] = work_memory[OFFSET(loop_index[z], 6)];
            w[7] = work_memory[OFFSET(loop_index[z], 7)];

        } else {
            w[0] = H[0];
            w[1] = H[1];
            w[2] = H[2];
            w[3] = H[3];
            w[4] = H[4];
            w[5] = H[5];
            w[6] = H[6];
            w[7] = H[7];
	    w[8] = work_memory[OFFSET(loop_index[z], 0)];
	    w[9] = work_memory[OFFSET(loop_index[z], 1)];
	    w[10] = work_memory[OFFSET(loop_index[z], 2)];
	    w[11] = work_memory[OFFSET(loop_index[z], 3)];
	    w[12] = work_memory[OFFSET(loop_index[z], 4)];
	    w[13] = work_memory[OFFSET(loop_index[z], 5)];
	    w[14] = work_memory[OFFSET(loop_index[z], 6)];
	    w[15] = work_memory[OFFSET(loop_index[z], 7)];
        }

	if (total > 31) {
	    uint32_t tmp_result[8];

	    #pragma unroll
	    for (uint32_t j = 0U; j < 8U; j++)
		tmp_result[j] = H[j];

	    //Initialize CTX.
	    H[0] = H0;
	    H[1] = H1;
	    H[2] = H2;
	    H[3] = H3;
	    H[4] = H4;
	    H[5] = H5;
	    H[6] = H6;
	    H[7] = H7;

	    buflen = ((i & 1) ? 32U : 64U);
	    update_w_G(w, H, work_memory, loop_index[z], &buflen, (total - 32U));
	    total += 32U;

	    if (i & 1)
		update_w(w, H, tmp_result, &buflen, 32U);

	} else {

	    if (i & 1) {
		uint32_t tmp, pos;
		tmp = ((total & 3U) << 3);
		pos = (total >> 2);

		APPEND_BE_BUFFER(w, H[0]);
		APPEND_BE_BUFFER(w, H[1]);
		APPEND_BE_BUFFER(w, H[2]);
		APPEND_BE_BUFFER(w, H[3]);
		APPEND_BE_BUFFER(w, H[4]);
		APPEND_BE_BUFFER(w, H[5]);
		APPEND_BE_BUFFER(w, H[6]);
		APPEND_BE_BUFFER_F(w, H[7]);
	    }
	    total += 32U;
	    buflen = total;

	    //Initialize CTX.
	    H[0] = H0;
	    H[1] = H1;
	    H[2] = H2;
	    H[3] = H3;
	    H[4] = H4;
	    H[5] = H5;
	    H[6] = H6;
	    H[7] = H7;
	}

        //Do the sha256_digest(ctx);
	if (buflen < 56U) { //data+0x80+datasize fits in one 512bit block
            APPEND_BE_SINGLE(w, 0x80000000U, buflen);
	    w[15] = (total * 8U);

	} else {
            bool moved = true;

            if (buflen < 64U) { //data and 0x80 fits in one block
                APPEND_BE_SINGLE(w, 0x80000000U, buflen);
                moved = false;
            }
	    sha256_block_be(w, H);

	    #pragma unroll
	    for (uint i = 0U; i < 15U; i++)
	        w[i] = 0;

            if (moved) //append 1,the rest is already clean
                w[0] = 0x80000000U;
	    w[15] = (total * 8U);
	}
	sha256_block_be(w, H);

    if (++z == LOOP_SIZE)
        z = 0;
    }
    //Push results back to global memory.
    #pragma unroll
    for (uint i = 0U; i < 8U; i++)
        alt_result[i].mem_32[0] = H[i];
}

__kernel
void kernel_crypt(
	MAYBE_CONSTANT sha256_salt     * const __restrict salt,
        __global         sha256_hash     * const __restrict out_buffer,
        __global         sha256_buffers  * const __restrict tmp_buffers,
	__global         uint32_t	 * const __restrict work_memory) {

    //Get the task to be done
    size_t gid = get_global_id(0);

    //Get temp alt_result pointer.
    __global buffer_32 * alt_result = tmp_buffers[gid].alt_result;

    //Do the job
    sha256_crypt(alt_result, work_memory);
}

__kernel
void kernel_final(
	MAYBE_CONSTANT sha256_salt     * const __restrict salt,
        __global         sha256_hash     * const __restrict out_buffer,
        __global         sha256_buffers  * const __restrict tmp_buffers,
	__global         uint32_t	 * const __restrict work_memory) {

    //Get the task to be done
    size_t gid = get_global_id(0);

    //Get temp alt_result pointer.
    __global buffer_32 * alt_result = tmp_buffers[gid].alt_result;

    //Do the job
    sha256_crypt_f(MIN(salt->final,  HASH_LOOPS), alt_result, work_memory);

    //SWAP results and put it as hash data.
    #pragma unroll
    for (uint i = 0U; i < 8U; i++)
        out_buffer[gid].v[i] = SWAP32(alt_result[i].mem_32[0]);
}
