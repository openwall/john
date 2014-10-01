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

#include "opencl_cryptsha256.h"

#if gpu(DEVICE_INFO)
	#define VECTOR_USAGE
#endif

#if !(amd_gcn(DEVICE_INFO))
	#define update_final ctx_update_R
#else
	#define update_final ctx_update_R
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

inline void get_temp_data(__global sha256_buffers * tmp_memory,
				   sha256_buffers * fast_buffers) {

	__global uint64_t * src;
	uint64_t * dst;

	src = (__global uint64_t *) tmp_memory->alt_result;
	dst = (uint64_t *) fast_buffers->alt_result;
	#pragma unroll
	for (int i = 0; i < (8 / 2); i++)
		*dst++ = *src++;

	src = (__global uint64_t *) tmp_memory->temp_result;
	dst = (uint64_t *) fast_buffers->temp_result;
	#pragma unroll
	for (int i = 0; i < (SALT_ARRAY / 2); i++)
		*dst++ = *src++;

	src = (__global uint64_t *) tmp_memory->p_sequence;
	dst = (uint64_t *) fast_buffers->p_sequence;
	#pragma unroll
	for (int i = 0; i < (PLAINTEXT_ARRAY / 2); i++)
		*dst++ = *src++;
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

inline void sha256_block_short(sha256_ctx * ctx) {
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
	for (int i = 0; i < 16; i++)
		w[i] = SWAP32(ctx->buffer->mem_32[i]);
#endif

	/* Do the job. */
	SHA256()

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

inline void insert_to_buffer_R(sha256_ctx	 * ctx,
				   const uint8_t * string,
				   const uint32_t len) {

	for (uint32_t i = 0; i < len; i++)
		PUT(BUFFER, ctx->buflen + i, string[i]);

	ctx->buflen += len;
}

inline void insert_to_buffer_final(sha256_ctx	 * ctx,
				   const uint8_t * string,
				   const uint32_t len) {

	uint32_t * p = (uint32_t *) string;

	for (uint32_t i = 0; i < len; i+=4, p++)
		APPEND_F(ctx->buffer->mem_32, p[0], ctx->buflen + i);

	ctx->buflen += len;
}

inline void insert_to_buffer_C(	      sha256_ctx * ctx,
			__constant const uint8_t * string,
				   const uint32_t len) {

	for (uint32_t i = 0; i < len; i++)
		PUT(BUFFER, ctx->buflen + i, string[i]);

	ctx->buflen += len;
}

inline void insert_to_buffer_G(	 sha256_ctx    * ctx,
			__global const uint8_t * string,
				 const uint32_t len) {

	for (uint32_t i = 0; i < len; i++)
		PUT(BUFFER, ctx->buflen + i, string[i]);

	ctx->buflen += len;
}

inline void ctx_update_R(sha256_ctx * ctx,
			 uint8_t    * string,
			 const uint32_t len) {

	ctx->total += len;
	uint32_t startpos = ctx->buflen;

	insert_to_buffer_R(ctx, string, (startpos + len <= 64 ? len : 64 - startpos));

	if (ctx->buflen == 64) {  //Branching.
		uint32_t offset = 64 - startpos;
		sha256_block(ctx);
		ctx->buflen = 0;
		insert_to_buffer_R(ctx, (string + offset), len - offset);
	}
}

inline void ctx_update_final(sha256_ctx * ctx,
			     uint8_t    * string,
			     const uint32_t len) {

	ctx->total += len;
	uint32_t startpos = ctx->buflen;

	insert_to_buffer_final(ctx, string, (startpos + len <= 64 ? len : 64 - startpos));

	if (ctx->buflen == 64) {  //Branching.
		uint32_t offset = 64 - startpos;
		sha256_block(ctx);
		ctx->buflen = 0;

		#pragma unroll
		for (int j = 0; j < 15; j++)
		    ctx->buffer[j].mem_32[0] = 0;

		insert_to_buffer_R(ctx, (string + offset), len - offset);
	}
}

inline void ctx_update_C(	   sha256_ctx * ctx,
			 __constant uint8_t   * string,
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

inline void ctx_update_G(	 sha256_ctx * ctx,
			 __global uint8_t   * string, uint32_t len) {

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

inline void clear_buffer(uint32_t     * destination,
			 const uint32_t len,
			 const uint32_t limit) {

	uint32_t length;

	CLEAR_BUFFER_32(destination, len);

	uint32_t * l = destination + length;

	while (length < limit) {
		*l++ = 0;
		length++;
	}
}

inline void ctx_append_1(sha256_ctx * ctx) {

	uint32_t length = ctx->buflen;
	PUT(BUFFER, length++, 0x80);

	CLEAR_BUFFER_32(ctx->buffer->mem_32, length)

	uint32_t * l = ctx->buffer->mem_32 + length;

	while (length < 16) {
		*l++ = 0;
		length++;
	}
}

inline void ctx_append_1_short(sha256_ctx * ctx) {

	uint32_t length = ctx->buflen;
	PUT(BUFFER, length++, 0x80);

	CLEAR_BUFFER_32(ctx->buffer->mem_32, length)

	uint32_t * l = ctx->buffer->mem_32 + length;

	while (length < 15) {
		*l++ = 0;
		length++;
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

#ifdef VECTOR_USAGE
	uint16  w_vector = 0;
	vstore16(w_vector, 0, ctx->buffer->mem_32);
#else
	uint64_t * l = (uint64_t *) ctx->buffer;

	#pragma unroll
	for (int i = 0; i < 8; i++)
		*l++ = 0;
#endif

	ctx->buflen = 0;
}

inline void sha256_digest_move_R(sha256_ctx * ctx,
				 uint32_t   * result,
				 const int size) {

	#pragma unroll
	for (int i = 0; i < size; i++)
		result[i] = SWAP32(ctx->H[i]);
}

inline void sha256_digest_move_G(	 sha256_ctx * ctx,
				 __global uint32_t  * result,
				 const int size) {

	#pragma unroll
	for (int i = 0; i < size; i++)
		result[i] = SWAP32(ctx->H[i]);
}

inline void sha256_digest(sha256_ctx * ctx) {

	if (ctx->buflen <= 55) { //data+0x80+datasize fits in one 1024bit block
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

inline void sha256_prepare(__constant sha256_salt	 * salt_data,
			   __global   sha256_password	 * keys_data,
					  sha256_buffers * fast_buffers,
					  sha256_ctx	 * ctx) {

#define pass	    keys_data->pass->mem_08
#define passlen	    keys_data->length
#define salt	    salt_data->salt->mem_08
#define saltlen	    salt_data->length
#define alt_result  fast_buffers->alt_result
#define temp_result fast_buffers->temp_result
#define p_sequence  fast_buffers->p_sequence

	init_ctx(ctx);

	ctx_update_G(ctx, pass, passlen);
	ctx_update_C(ctx, salt, saltlen);
	ctx_update_G(ctx, pass, passlen);

	sha256_digest(ctx);
	sha256_digest_move_R(ctx, alt_result->mem_32, BUFFER_ARRAY);
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
	sha256_digest_move_R(ctx, alt_result->mem_32, BUFFER_ARRAY);
	init_ctx(ctx);

	for (uint32_t i = 0; i < passlen; i++)
		ctx_update_G(ctx, pass, passlen);

	sha256_digest(ctx);
	sha256_digest_move_R(ctx, p_sequence->mem_32, PLAINTEXT_ARRAY);
	clear_buffer(p_sequence->mem_32, passlen, PLAINTEXT_ARRAY);
	init_ctx(ctx);

	/* For every character in the password add the entire password. */
	for (uint32_t i = 0; i < 16U + alt_result->mem_08[0]; i++)
		ctx_update_C(ctx, salt, saltlen);

	/* Finish the digest. */
	sha256_digest(ctx);
	sha256_digest_move_R(ctx, temp_result->mem_32, SALT_ARRAY);
	clear_buffer(temp_result->mem_32, saltlen, SALT_ARRAY);
}
#undef salt
#undef pass
#undef saltlen
#undef passlen
#undef temp_result
#undef p_sequence

inline void sha256_crypt(sha256_buffers * fast_buffers,
			 sha256_ctx	* ctx,
			 const uint32_t saltlen, const uint32_t passlen,
			 const uint32_t initial, const uint32_t rounds) {

#define temp_result fast_buffers->temp_result
#define p_sequence  fast_buffers->p_sequence

	/* Repeatedly run the collected hash value through SHA256 to burn cycles. */
	for (uint32_t i = initial; i < rounds; i++) {
	ctx->H[0] = H0;
	ctx->H[1] = H1;
	ctx->H[2] = H2;
	ctx->H[3] = H3;
	ctx->H[4] = H4;
	ctx->H[5] = H5;
	ctx->H[6] = H6;
	ctx->H[7] = H7;

	#pragma unroll
	for (int j = 6; j < 12; j++)
	   ctx->buffer[j].mem_32[0] = 0;

	if (i & 1) {
		ctx->buffer[0].mem_32[0] = p_sequence[0].mem_32[0];
		ctx->buffer[1].mem_32[0] = p_sequence[1].mem_32[0];
		ctx->buffer[2].mem_32[0] = p_sequence[2].mem_32[0];
		ctx->buffer[3].mem_32[0] = p_sequence[3].mem_32[0];
		ctx->buffer[4].mem_32[0] = p_sequence[4].mem_32[0];
		ctx->buffer[5].mem_32[0] = p_sequence[5].mem_32[0];
		ctx->buflen = passlen;
		ctx->total = passlen;
	} else {
		ctx->buffer[0].mem_32[0] = alt_result[0].mem_32[0];
		ctx->buffer[1].mem_32[0] = alt_result[1].mem_32[0];
		ctx->buffer[2].mem_32[0] = alt_result[2].mem_32[0];
		ctx->buffer[3].mem_32[0] = alt_result[3].mem_32[0];
		ctx->buffer[4].mem_32[0] = alt_result[4].mem_32[0];
		ctx->buffer[5].mem_32[0] = alt_result[5].mem_32[0];
		ctx->buffer[6].mem_32[0] = alt_result[6].mem_32[0];
		ctx->buffer[7].mem_32[0] = alt_result[7].mem_32[0];
		ctx->buflen = 32U;
		ctx->total = 32U;
	}

	if (i % 3) {
		APPEND(ctx->buffer->mem_32, temp_result[0].mem_32[0], ctx->buflen);
		APPEND(ctx->buffer->mem_32, temp_result[1].mem_32[0], ctx->buflen + 4);
		APPEND(ctx->buffer->mem_32, temp_result[2].mem_32[0], ctx->buflen + 8);
		APPEND(ctx->buffer->mem_32, temp_result[3].mem_32[0], ctx->buflen + 12);
		ctx->buflen += saltlen;
		ctx->total += saltlen;
	}

	if (i % 7)
		update_final(ctx, p_sequence->mem_08, passlen);

	update_final(ctx, ((i & 1) ? alt_result->mem_08 : p_sequence->mem_08),
			  ((i & 1) ? 32U :		  passlen));

	//Do: sha256_digest(ctx);
	if (ctx->buflen < 56) { //data+0x80+datasize fits in one 1024bit block
		ctx_append_1_short(ctx);
		ctx->buffer[15].mem_32[0] = SWAP32(ctx->total * 8);
		ctx->buflen = 0;

	} else {
		bool moved = true;

		if (ctx->buflen < 64) { //data and 0x80 fits in one block
			ctx_append_1(ctx);
		moved = false;
		}
		sha256_block_short(ctx);
		clear_ctx_buffer(ctx);

		if (moved) //append 1,the rest is already clean
			ctx->buffer[0].mem_32[0] = 0x80;
		ctx->buffer[15].mem_32[0] = SWAP32(ctx->total * 8);
	}
	sha256_block_short(ctx);

	#pragma unroll
	for (int j = 0; j < BUFFER_ARRAY; j++)
		alt_result[j].mem_32[0] = SWAP32(ctx->H[j]);
	}
}
#undef alt_result
#undef temp_result
#undef p_sequence

__kernel
void kernel_prepare(	__constant sha256_salt	   * salt,
			__global   sha256_password * keys_buffer,
			__global   sha256_buffers  * tmp_memory) {

	//Compute buffers (on Nvidia, better private)
	sha256_buffers fast_buffers;
	sha256_ctx     ctx_data;

	//Get the task to be done
	size_t gid = get_global_id(0);

	//Do the job
	sha256_prepare(salt, &keys_buffer[gid], &fast_buffers, &ctx_data);

	//Save results.
	#pragma unroll
	for (int i = 0; i < 8; i++)
		tmp_memory[gid].alt_result[i].mem_32[0] = (fast_buffers.alt_result[i].mem_32[0]);

	#pragma unroll
	for (int i = 0; i < SALT_ARRAY; i++)
		tmp_memory[gid].temp_result[i].mem_32[0] = (fast_buffers.temp_result[i].mem_32[0]);

	#pragma unroll
	for (int i = 0; i < PLAINTEXT_ARRAY; i++)
		tmp_memory[gid].p_sequence[i].mem_32[0] = (fast_buffers.p_sequence[i].mem_32[0]);
}

__kernel
void kernel_crypt(__constant sha256_salt     * salt,
		  __global   sha256_password * keys_buffer,
		  __global   sha256_hash     * out_buffer,
		  __global   sha256_buffers  * tmp_memory) {

	//Compute buffers (on Nvidia, better private)
	sha256_buffers fast_buffers;
	sha256_ctx     ctx_data;

	//Get the task to be done
	size_t gid = get_global_id(0);

	//Transfer temp data to faster memory
	get_temp_data(&tmp_memory[gid], &fast_buffers);

	//Do the job
	sha256_crypt(&fast_buffers, &ctx_data,
		 salt->length, keys_buffer[gid].length, 0, HASH_LOOPS);

	//Save results.
	#pragma unroll
	for (int i = 0; i < 8; i++)
		tmp_memory[gid].alt_result[i].mem_32[0] = fast_buffers.alt_result[i].mem_32[0];
}

__kernel
void kernel_final(__constant sha256_salt     * salt,
		  __global   sha256_password * keys_buffer,
		  __global   sha256_hash     * out_buffer,
		  __global   sha256_buffers  * tmp_memory) {

	//Compute buffers (on Nvidia, better private)
	sha256_buffers fast_buffers;
	sha256_ctx     ctx_data;

	//Get the task to be done
	size_t gid = get_global_id(0);

	//Transfer temp data to faster memory
	get_temp_data(&tmp_memory[gid], &fast_buffers);

	//Do the job
	sha256_crypt(&fast_buffers, &ctx_data,
		 salt->length, keys_buffer[gid].length, 0, salt->final);

	//Send results to the host.
	#pragma unroll
	for (int i = 0; i < 8; i++)
		out_buffer[gid].v[i] = fast_buffers.alt_result[i].mem_32[0];
}
