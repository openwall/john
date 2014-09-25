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

#if gpu(DEVICE_INFO) && !amd_gcn(DEVICE_INFO)
    #define VECTOR_USAGE
#endif

///	    *** UNROLL ***
///AMD: sometimes a bad thing.
///NVIDIA: GTX 570 don't allow full unroll.
#if amd_gcn(DEVICE_INFO)
    #define WEAK_UNROLL		1
#elif gpu_amd(DEVICE_INFO)
    #define STRONG_UNROLL	1
#elif gpu_nvidia(DEVICE_INFO)
    #define MEDIUM_UNROLL	1
#endif

/// Start documenting bugs.
#if amd_vliw5(DEVICE_INFO)
    #define AMD_STUPID_BUG_1
    ///TODO: can't remove the [unroll]: (at least) AMD driver bug HD 6770.
#endif

/************************** prepare **************************/
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
    uint64_t t;
    uint64_t w[16];

#ifdef VECTOR_USAGE
    ulong16  w_vector;
    w_vector = vload16(0, ctx->buffer->mem_64);
    w_vector = SWAP64_V(w_vector);
    vstore16(w_vector, 0, w);
#else
    for (int i = 0; i < 16; i++)
        w[i] = SWAP64(ctx->buffer[i].mem_64[0]);
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
    #pragma unroll 16
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

inline void insert_to_buffer_R(sha512_ctx    * ctx,
                               const uint8_t * string,
                               const uint32_t len) {

    for (uint32_t i = 0; i < len; i++)
        PUT(BUFFER, ctx->buflen + i, string[i]); ///TODO: consertar

    ctx->buflen += len;
}

inline void insert_to_buffer_G(         sha512_ctx    * ctx,
                               __global const uint8_t * string,
                               const uint32_t len) {
    for (uint32_t i = 0; i < len; i++)
        PUT(BUFFER, ctx->buflen + i, string[i]); ///TODO: consertar

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

inline void ctx_add_length(sha512_ctx * ctx) {

    ctx->buffer[15].mem_64[0] = SWAP64((uint64_t) (ctx->total * 8));
}

inline void finish_ctx(sha512_ctx * ctx) {

    ctx_append_1(ctx);
    ctx_add_length(ctx);
    ctx->buflen = 0;
}

inline void clear_ctx_buffer(sha512_ctx * ctx) {

    #pragma unroll
    for (int i = 0; i < 16; i++)
        ctx->buffer[i].mem_64[0] = 0;

    ctx->buflen = 0;
}

inline void sha512_digest_move(sha512_ctx * ctx,
                               uint64_t   * result,
                               const int size) { //TODO remove me

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

inline void sha512_prepare(__global   sha512_salt     * salt_data,
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
    ctx_update_G(ctx, salt, saltlen);
    ctx_update_G(ctx, pass, passlen);

    sha512_digest(ctx);
    sha512_digest_move(ctx, alt_result->mem_64, BUFFER_ARRAY);
    init_ctx(ctx);

    ctx_update_special(ctx, pass, passlen);
    ctx_update_G(ctx, salt, saltlen);
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
        ctx_update_G(ctx, salt, saltlen);

    /* Finish the digest. */
    sha512_digest(ctx);
    sha512_digest_move(ctx, temp_result->mem_64, SALT_ARRAY);
    clear_buffer(temp_result->mem_64, saltlen, SALT_ARRAY);
}
#undef salt
#undef pass
#undef saltlen
#undef passlen
#undef alt_result
#undef temp_result
#undef p_sequence

inline int get_generator(int matrix_index) {

    switch (matrix_index) {
	case 0:
	    return 0;	/*  0, 000 */
	case 1:
	    return 6;	/*  6, 001 */
	case 2:
	    return 14;	/* 14, 010 */
	case 3:
	    return 2;	/*  2, 011 */
	case 4:
	    return 21;	/* 21, 100 */
	case 5:
	    return 3;	/*  3, 101 */
	case 6:
	    return 7;	/*  7, 110 */
	case 7:
	    return 1;	/*  1, 111 */
    }
    return -1;
}

__kernel
void kernel_prepare(__global   sha512_salt     * salt,
                    __global   sha512_password * keys_buffer,
                    __global   sha512_buffers  * tmp_memory,
		    __global   uint64_t	       * work_memory) {

    //Compute buffers (on Nvidia, better private)
    sha512_buffers fast_buffers;
    sha512_ctx     ctx_data;

    //Get the task to be done
    size_t gid = get_global_id(0);

    //Do the job
    sha512_prepare(salt, &keys_buffer[gid], &tmp_memory[gid], &fast_buffers, &ctx_data);

    //Save results.
    for (int i = 0; i < 8; i++)
        tmp_memory[gid].alt_result[i].mem_64[0] = SWAP64(fast_buffers.alt_result[i].mem_64[0]);

    for (int i = 0; i < SALT_ARRAY; i++)
        tmp_memory[gid].temp_result[i].mem_64[0] = SWAP64(fast_buffers.temp_result[i].mem_64[0]);

    for (int i = 0; i < PLAINTEXT_ARRAY; i++)
        tmp_memory[gid].p_sequence[i].mem_64[0] = SWAP64(fast_buffers.p_sequence[i].mem_64[0]);

     for (int i = 0; i < SALT_ARRAY; i++)
        fast_buffers.temp_result[i].mem_64[0] = SWAP64(fast_buffers.temp_result[i].mem_64[0]);

    for (int i = 0; i < PLAINTEXT_ARRAY; i++)
        fast_buffers.p_sequence[i].mem_64[0] = SWAP64(fast_buffers.p_sequence[i].mem_64[0]);

    //Preload and prepare the temp buffer.
    for (int i = 0; i < 8; i++) {
	uint32_t total = 0;
	int j = get_generator(i);
	__global uint64_t * buf = &work_memory[(gid * (9 * 8)) + (i * 9)];

	for (int k = 0; k < 8; k++)
	   buf[k] = 0;

        if (j & 1) {
	    buf[0] = fast_buffers.p_sequence[0].mem_64[0];
	    buf[1] = fast_buffers.p_sequence[1].mem_64[0];
	    buf[2] = fast_buffers.p_sequence[2].mem_64[0];
            total += keys_buffer[gid].length;
        }
/*
if (j==2) {
printf("\nA1: j:%d, i:%d, %d, %d \n", j, i, total, keys_buffer[gid].length);
for (int k=0; k < 8; k++)
printf("%08x%08x ", buf[k]>>32, buf[k]);
printf("\n");
}
*/
        if (j % 3) {
	    APPEND_BE(buf, fast_buffers.temp_result[0].mem_64[0], total);
	    APPEND_BE(buf, fast_buffers.temp_result[1].mem_64[0], total + 8);
            total += salt->length;
        }
/*
if (j==2) {
printf("\nA1: j:%d, i:%d, %d, %d \n", j, i, total, keys_buffer[gid].length);
////for (int k=0; k < 8; k++)
printf("%08x%08x \n", fast_buffers.p_sequence[0].mem_64[0] >> 32, fast_buffers.p_sequence[0].mem_64[0]);
for (int k=0; k < 8; k++)
printf("%08x%08x ", buf[k]>>32, buf[k]);
printf("\n");
}
*/
        if (j % 7) {
	    APPEND_BE(buf, fast_buffers.p_sequence[0].mem_64[0], total);
	    APPEND_BE(buf, fast_buffers.p_sequence[1].mem_64[0], total + 8);
	    APPEND_BE_F_8(buf, fast_buffers.p_sequence[2].mem_64[0], total + 16);
            total += keys_buffer[gid].length;
/*
if (j==2) {
printf("\nA1: j:%d, i:%d, %d, %d \n", j, i, total, keys_buffer[gid].length);
////for (int k=0; k < 8; k++)
printf("%08x%08x \n", fast_buffers.p_sequence[0].mem_64[0] >> 32, fast_buffers.p_sequence[0].mem_64[0]);

printf("\n");
}
*/
        }

        if (! (j & 1)) {
	    APPEND_BE(buf, fast_buffers.p_sequence[0].mem_64[0], total);
	    APPEND_BE(buf, fast_buffers.p_sequence[1].mem_64[0], total + 8);
	    APPEND_BE_F_8(buf, fast_buffers.p_sequence[2].mem_64[0], total + 16);
            total += keys_buffer[gid].length;
        }

	buf[8] = total;

//if (j==0) {
//printf("\nA1: j:%d, i:%d, %d, %d,  %d ", j, i, total, keys_buffer[gid].length, buf[8]);
////for (int k=0; k < 8; k++)
//printf("%08x%08x \n", fast_buffers.p_sequence[0].mem_64[0] >> 32, fast_buffers.p_sequence[0].mem_64[0]);
//for (int k=0; k < 8; k++)
//printf("%08x%08x ", buf[k]>>32, buf[k]);
//printf("\n");
//}
    }
}

/************************** hashing **************************/
inline void sha512_block_be(uint64_t * buffer, uint64_t * H) {
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

inline void sha512_crypt(const uint32_t saltlen, const uint32_t passlen,
                         const uint32_t initial, const uint32_t rounds,
			 __global	sha512_buffers * tmp_memory,
			 __global	uint64_t       * work_memory) {

    //To compute buffers.
    int		    total,tot;
    uint64_t	    w[16], y[16];
    uint64_t	    H[8];
    buffer_64	    alt_result[8];

    //Transfer host global data to a faster memory space.
    for (int i = 0; i < 8; i++)
        alt_result[i].mem_64[0] = tmp_memory->alt_result[i].mem_64[0];

    /* Repeatedly run the collected hash value through SHA512 to burn cycles. */
    for (int i = 0; i < rounds; i++) {
        __global uint64_t * buf = &work_memory[(get_global_id(0) * (9 * 8)) + (index[i] * 9)];

	for (int j = 0; j < 16; j++)
	   w[j] = 0;

        if (i & 1) {
            w[0] = buf[0];
            w[1] = buf[1];
            w[2] = buf[2];
            w[3] = buf[3];
            w[4] = buf[4];
            w[5] = buf[5];
            w[6] = buf[6];
            w[7] = buf[7];
            total = buf[8];

            APPEND_BE(w, alt_result[0].mem_64[0], total);
            APPEND_BE(w, alt_result[1].mem_64[0], total + 8);
            APPEND_BE(w, alt_result[2].mem_64[0], total + 16);
            APPEND_BE(w, alt_result[3].mem_64[0], total + 24);
            APPEND_BE(w, alt_result[4].mem_64[0], total + 32);
            APPEND_BE(w, alt_result[5].mem_64[0], total + 40);
            APPEND_BE(w, alt_result[6].mem_64[0], total + 48);
            APPEND_BE_F_16(w, alt_result[7].mem_64[0], total + 56);
            total += 64;

        } else {
            w[0] = alt_result[0].mem_64[0];
            w[1] = alt_result[1].mem_64[0];
            w[2] = alt_result[2].mem_64[0];
            w[3] = alt_result[3].mem_64[0];
            w[4] = alt_result[4].mem_64[0];
            w[5] = alt_result[5].mem_64[0];
            w[6] = alt_result[6].mem_64[0];
            w[7] = alt_result[7].mem_64[0];
	    w[8] = buf[0];
	    w[9] = buf[1];
	    w[10] = buf[2];
	    w[11] = buf[3];
	    w[12] = buf[4];
	    w[13] = buf[5];
	    w[14] = buf[6];
	    w[15] = buf[7];
            total = 64 + buf[8];
        }
//---------------------------------------------------------------------------
//printf("*** Valores (%d): %d, %d, %d, %016x *** \n", i, index[i], total, buf[8], w[7]);

#define temp_result tmp_memory->temp_result
#define p_sequence  tmp_memory->p_sequence

//-------------

	for (int j = 0; j < 16; j++)
	   y[j] = 0;

        if (i & 1) {
            y[0] = p_sequence[0].mem_64[0];
            y[1] = p_sequence[1].mem_64[0];
            y[2] = p_sequence[2].mem_64[0];
            tot = passlen;
        } else {
            y[0] = alt_result[0].mem_64[0];
            y[1] = alt_result[1].mem_64[0];
            y[2] = alt_result[2].mem_64[0];
            y[3] = alt_result[3].mem_64[0];
            y[4] = alt_result[4].mem_64[0];
            y[5] = alt_result[5].mem_64[0];
            y[6] = alt_result[6].mem_64[0];
            y[7] = alt_result[7].mem_64[0];
            tot = 64U;
        }

        if (i % 3) {
            APPEND_BE(y, temp_result[0].mem_64[0], tot);
            APPEND_BE(y, temp_result[1].mem_64[0], tot + 8);
            tot += saltlen;
        }

        if (i % 7) {
            APPEND_BE(y, p_sequence[0].mem_64[0], tot);
            APPEND_BE(y, p_sequence[1].mem_64[0], tot + 8);
            APPEND_BE(y, p_sequence[2].mem_64[0], tot + 16);
            tot += passlen;
        }

        if (i & 1) {
            APPEND_BE(y, alt_result[0].mem_64[0], tot);
            APPEND_BE(y, alt_result[1].mem_64[0], tot + 8);
            APPEND_BE(y, alt_result[2].mem_64[0], tot + 16);
            APPEND_BE(y, alt_result[3].mem_64[0], tot + 24);
            APPEND_BE(y, alt_result[4].mem_64[0], tot + 32);
            APPEND_BE(y, alt_result[5].mem_64[0], tot + 40);
            APPEND_BE(y, alt_result[6].mem_64[0], tot + 48);
            APPEND_BE_F_16(y, alt_result[7].mem_64[0], tot + 56);
            tot += 64U;
        } else {
            APPEND_BE(y, p_sequence[0].mem_64[0], tot);
            APPEND_BE(y, p_sequence[1].mem_64[0], tot + 8);
            APPEND_BE_F_16(y, p_sequence[2].mem_64[0], tot + 16);
            tot += passlen;
        }



//---------------------------------------------------------------------------
        //Initialize CTX.
	H[0] = H0;
	H[1] = H1;
	H[2] = H2;
	H[3] = H3;
	H[4] = H4;
	H[5] = H5;
	H[6] = H6;
	H[7] = H7;

        //Do the sha512_digest(ctx);
	APPEND_BE_SINGLE(w, 0x8000000000000000UL, tot);
	APPEND_BE_SINGLE(y, 0x8000000000000000UL, tot);

for (int k=0; k < 16; k++) {
if (w[k] != y[k]) {
printf("\nF: ");
printf("i: %d, k: %d, w:%016x y:%016x w|%016x %d, %d", i, k, w[k], y[k], buf[0], tot, total);
printf("\n");
return;
}
}


if (total != tot) {
printf("\nT: ");
printf("\n Soma: %d, tot: %d, total: %d, veio: %d %d", i, tot, total, buf[8], passlen);
return;
}

//int k =8;
//printf("i: %d, k: %d, w:%08x%08x y:%08x%08x %08x %08x, %d, %d", i, k, w[k]>>32, w[k], y[k]>>32,y[k], work_memory[pos+1]>>32, work_memory[pos+1], tot, total);
//printf("\n");
//return;


	if (total < 112) { //data+0x80+datasize fits in one 1024bit block
	    w[15] = (total * 8);

	} else {
	    sha512_block_be(w, H);

	    for (int i = 0; i < 15; i++)
	       w[i] = 0;
	    w[15] = (total * 8);
	}
	sha512_block_be(w, H);

	for (int j = 0; j < BUFFER_ARRAY; j++) //TODO remover isto.
	    alt_result[j].mem_64[0] = H[j];
    }
    //Push results back to global memory.
    for (int i = 0; i < 8; i++)
        tmp_memory->alt_result[i].mem_64[0] = alt_result[i].mem_64[0];
}

__kernel
void kernel_crypt(__constant sha512_salt     * salt,
                  __global   sha512_password * keys_buffer,
                  __global   sha512_hash     * out_buffer,
                  __global   sha512_buffers  * tmp_memory, //TODO remover, usar apenas alt_result
		  __global   uint64_t	     * work_memory) {

    //Get the task to be done
    size_t gid = get_global_id(0);

    //Do the job
    sha512_crypt(salt->length, keys_buffer[gid].length, 0, HASH_LOOPS,
		 &tmp_memory[gid], work_memory);
}

__kernel
void kernel_final(__constant sha512_salt     * salt,
                  __global   sha512_password * keys_buffer,
                  __global   sha512_hash     * out_buffer,
                  __global   sha512_buffers  * tmp_memory, //TODO remover, usar apenas alt_result
		  __global   uint64_t	     * work_memory) {

    //Get the task to be done
    size_t gid = get_global_id(0);

    //Do the job
    sha512_crypt(salt->length, keys_buffer[gid].length, 0, salt->final,
		 &tmp_memory[gid], work_memory);

    //SWAP results and put it as hash data.
    //Unlikely, but if avoided, could became an optimization.
    for (int i = 0; i < 8; i++)
        out_buffer[gid].v[i] = SWAP64(tmp_memory[gid].alt_result[i].mem_64[0]);
}
