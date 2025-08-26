/*
 * This software is Copyright (c) 2016 Agnieszka Bielec <bielecagnieszka8 at gmail.com>,
 * Copyright (c) 2023 magnum,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * merged argon2d and argon2i into a single format file.  JimF.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_argon2;
#elif FMT_REGISTERS_H
john_register_one(&fmt_argon2);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#include "options.h"
#include "memory.h"
#include "argon2.h"
#include "argon2_encoding.h"

#define FORMAT_LABEL            "Argon2"
#define FORMAT_NAME             ""
#define FORMAT_TAG_d            "$argon2d$"
#define FORMAT_TAG_i            "$argon2i$"
#define FORMAT_TAG_id           "$argon2id$"
#define FORMAT_TAG_LEN          (sizeof(FORMAT_TAG_d)-1)
#define FORMAT_TAG_LEN_ID       (sizeof(FORMAT_TAG_id)-1)

#if !defined (JOHN_NO_SIMD) && defined(__AVX512F__)
#define ALGORITHM_NAME          "BlaMka 512/512 AVX512F"
#elif !defined (JOHN_NO_SIMD) && defined(__AVX2__)
#define ALGORITHM_NAME          "BlaMka 256/256 AVX2"
#elif !defined (JOHN_NO_SIMD) && defined(__XOP__)
#define ALGORITHM_NAME          "BlaMka 128/128 XOP"
#elif !defined (JOHN_NO_SIMD) && defined(__AVX__)
#define ALGORITHM_NAME          "BlaMka 128/128 AVX"
#elif !defined (JOHN_NO_SIMD) && defined(__SSSE3__)
#define ALGORITHM_NAME          "BlaMka 128/128 SSSE3"
#elif !defined (JOHN_NO_SIMD) && defined(__SSE2__)
#define ALGORITHM_NAME          "BlaMka 128/128 SSE2"
#else
#define ALGORITHM_NAME          "BlaMka " ARCH_BITS_STR "/" ARCH_BITS_STR
#endif

#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x107
#define PLAINTEXT_LENGTH        125 //only in john
#define BINARY_SIZE             256 //only in john
#define BINARY_ALIGN            sizeof(uint32_t)
#define SALT_SIZE               64  //only in john
#define SALT_ALIGN              sizeof(uint32_t)

#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1

#define OMP_SCALE               1

#ifdef _OPENMP
#define THREAD_NUMBER omp_get_thread_num()
#define NUM_THREADS   omp_get_max_threads()
#else
#define THREAD_NUMBER 0
#define NUM_THREADS   1
#endif

/*
 * Argon2 is a KDF, using a hash function built upon Blake2b (Blake2b_long,
 * variable length and capable of generating up to 2^32 bytes digests).
 *
 * Argon2d maximizes resistance to GPU cracking attacks.  It accesses the
 * memory array in a password dependent order, which reduces the possibility
 * of time–memory trade-off (TMTO) attacks, but introduces possible
 * side-channel attacks.
 *
 * Argon2i is optimized to resist side-channel attacks.  It accesses the
 * memory array in a password independent order.
 *
 * Argon2id is a hybrid version.  It follows the Argon2i approach for the
 * first half pass over memory and the Argon2d approach for subsequent
 * passes.  RFC 9106 recommends using Argon2id if you do not know the
 * difference between the types or you consider side-channel attacks to be
 * a viable threat.
 *
 * v = version, 19 == 0x13 == version 1.3
 * m = memory in KB
 * t = time (a.k.a. i for iterations, or rounds)
 * p = parallelism (a.k.a. threads, lanes)
 *
 * Password (message) length supported by Argon2 is 0..2^32.  This format
 * supports up to 125 due to limitations in core code.
 * Output length (tag length) can be chosen between 4 and 2^32.  This format
 * supports up to 256 but you can just bump BINARY_SIZE above arbitrarily.
 * Salt length supported by Argon2 is 8..2^32.  This format supports up to
 * 64 but that too can be bumped arbitrarily with SALT_SIZE above.
 */
static struct fmt_tests tests[] = {
	{"$argon2d$v=19$m=4096,t=3,p=1$ZGFtYWdlX2RvbmU$w9w3s5/zV8+PcAZlJhnTCOE+vBkZssmZf6jOq3dKv50","password"},
	{"$argon2i$v=19$m=4096,t=3,p=1$ZGFtYWdlX2RvbmU$N59QwnpxDQZRj1/cO6bqm408dD6Z2Z9LKYpwFJSPVKA","password"},
	{"$argon2id$v=19$m=4096,t=3,p=1$U2FMdHNBbFQ$Djwdq8LGcBSmvJAX8TPqELq0N8YVHEdk5bWb4tRy70k", "magnum"},
	{"$argon2d$v=19$m=4096,t=3,p=1$c2hvcnRfc2FsdA$zMrTcOAOUje6UqObRVh84Pe1K6gumcDqqGzRM0ILzYmj","sacrificed"},
	{"$argon2i$v=19$m=4096,t=3,p=1$c2hvcnRfc2FsdA$1l4kAwUdAApoCbFH7ghBEf7bsdrOQzE4axIJ3PV0Ncrd","sacrificed"},
	{"$argon2d$v=19$m=16384,t=3,p=1$c2hvcnRfc2FsdA$TLSTPihIo+5F67Y1vJdfWdB9","blessed_dead"},
	{"$argon2i$v=19$m=16384,t=3,p=1$c2hvcnRfc2FsdA$vvjDVog22A5x9eljmB+2yC8y","blessed_dead"},
	{"$argon2d$v=19$m=16384,t=4,p=3$YW5vdGhlcl9zYWx0$yw93eMxC8REPAwbQ0e/q43jR9+RI9HI/DHP75uzm7tQfjU734oaI3dzcMWjYjHzVQD+J4+MG+7oyD8dN/PtnmPCZs+UZ67E+rkXJ/wTvY4WgXgAdGtJRrAGxhy4rD7d5G+dCpqhrog","death_dying"},
	{"$argon2i$v=19$m=16384,t=4,p=3$YW5vdGhlcl9zYWx0$K7unxwO5aeuZCpnIJ06FMCRKod3eRg8oIRzQrK3E6mGbyqlTvvl47jeDWq/5drF1COJkEF9Ty7FWXJZHa+vqlf2YZGp/4qSlAvKmdtJ/6JZU32iQItzMRwcfujHE+PBjbL5uz4966A","death_dying"},
	{NULL}
};

struct argon2_salt {
	uint32_t t_cost, m_cost, lanes;
	uint32_t hash_size;
	uint32_t salt_length;
	char salt[SALT_SIZE];
	argon2_type type;
};

struct argon2_memory {
	region_t region;
	int used;
	char padding[MEM_ALIGN_CACHE - sizeof(region_t) - sizeof(int)];
};

static struct argon2_salt saved_salt;
static struct argon2_memory *thread_mem;

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *saved_len;

static unsigned char (*crypted)[BINARY_SIZE];

static void *get_salt(char *ciphertext);

static void init(struct fmt_main *self)
{
	int i;

	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(self->params.max_keys_per_crypt, sizeof(*saved_key));
	crypted = mem_calloc(self->params.max_keys_per_crypt, BINARY_SIZE);
	saved_len = mem_calloc(self->params.max_keys_per_crypt, sizeof(int));
	thread_mem = mem_calloc(NUM_THREADS, sizeof(struct argon2_memory));

	for (i = 0; i < NUM_THREADS; i++)
		init_region(&thread_mem[i].region);
}

static void done(void)
{
	int i;

	MEM_FREE(saved_len);
	MEM_FREE(crypted);
	MEM_FREE(saved_key);
	for (i = 0; i < NUM_THREADS; i++)
		free_region(&thread_mem[i].region);
	MEM_FREE(thread_mem);
}

static void ctx_init(argon2_context *ctx)
{
	static uint8_t out[BINARY_SIZE];
	static uint8_t salt[SALT_SIZE];

	memset(ctx, 0, sizeof(argon2_context));
	memset(&out, 0, sizeof(out));
	memset(&salt, 0, sizeof(salt));

	ctx->adlen = 0;
	ctx->saltlen = SALT_SIZE;
	ctx->outlen = BINARY_SIZE;

	ctx->out = out;
	ctx->salt = salt;
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	argon2_context ctx;
	int res;

	ctx_init(&ctx);

	if (!strncmp(ciphertext, FORMAT_TAG_d, FORMAT_TAG_LEN))
		res = argon2_decode_string(&ctx, ciphertext, Argon2_d);
	else if (!strncmp(ciphertext, FORMAT_TAG_i, FORMAT_TAG_LEN))
		res = argon2_decode_string(&ctx, ciphertext, Argon2_i);
	else if (!strncmp(ciphertext, FORMAT_TAG_id, FORMAT_TAG_LEN_ID))
		res = argon2_decode_string(&ctx, ciphertext, Argon2_id);
	else
		return 0;

	return res == ARGON2_OK;
}

static void set_key(char *key, int index)
{
	saved_len[index] = strnzcpyn(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}


static void *get_binary(char *ciphertext)
{
	static uint32_t out[(BINARY_SIZE + 3) / 4];
	argon2_context ctx;

	ctx_init(&ctx);
	if (!strncmp(ciphertext, FORMAT_TAG_d, FORMAT_TAG_LEN))
		argon2_decode_string(&ctx, ciphertext, Argon2_d);
	else if (!strncmp(ciphertext, FORMAT_TAG_i, FORMAT_TAG_LEN))
		argon2_decode_string(&ctx, ciphertext, Argon2_i);
	else
		argon2_decode_string(&ctx, ciphertext, Argon2_id);

	memset(out, 0, BINARY_SIZE);
	memcpy(out, ctx.out, ctx.outlen);

	return out;
}

static void *get_salt(char *ciphertext)
{
	static struct argon2_salt salt;
	argon2_context ctx;

	memset(&salt, 0, sizeof(salt));

	ctx_init(&ctx);
	if (!strncmp(ciphertext, FORMAT_TAG_d, FORMAT_TAG_LEN)) {
		argon2_decode_string(&ctx, ciphertext, Argon2_d);
		salt.type = Argon2_d;
	} else if (!strncmp(ciphertext, FORMAT_TAG_i, FORMAT_TAG_LEN)) {
		argon2_decode_string(&ctx, ciphertext, Argon2_i);
		salt.type = Argon2_i;
	} else {
		argon2_decode_string(&ctx, ciphertext, Argon2_id);
		salt.type = Argon2_id;
	}

	salt.salt_length = ctx.saltlen;
	salt.m_cost = ctx.m_cost;
	salt.t_cost = ctx.t_cost;
	salt.lanes = ctx.lanes;
	salt.hash_size = ctx.outlen;
	memcpy(salt.salt, ctx.salt, ctx.saltlen);

	return (void *)&salt;
}


static void set_salt(void *salt)
{
	memcpy(&saved_salt, salt, sizeof(struct argon2_salt));
}

static int allocate(uint8_t **memory, size_t size)
{
	if (THREAD_NUMBER < 0 || THREAD_NUMBER > NUM_THREADS) {
		fprintf(stderr, "Error: Argon2: Thread number %d out of range\n", THREAD_NUMBER);
		goto fail;
	}
	if (thread_mem[THREAD_NUMBER].used) {
		fprintf(stderr, "Error: Argon2: Thread %d: Memory allocated twice\n", THREAD_NUMBER);
		goto fail;
	}

	if (thread_mem[THREAD_NUMBER].region.aligned_size < size) {
		if (free_region(&thread_mem[THREAD_NUMBER].region) ||
		    !alloc_region(&thread_mem[THREAD_NUMBER].region, size))
			goto fail;
	}

	thread_mem[THREAD_NUMBER].used = 1;
	*memory = thread_mem[THREAD_NUMBER].region.aligned;

	return 0;

fail:
	*memory = NULL;
	return -1;
}

static void deallocate(uint8_t *memory, size_t size)
{
	if (THREAD_NUMBER < 0 || THREAD_NUMBER > NUM_THREADS) {
		fprintf(stderr, "Error: Argon2: Thread number %d out of range\n", THREAD_NUMBER);
		return;
	}

	if (!thread_mem[THREAD_NUMBER].used)
		fprintf(stderr, "Error: Argon2: Thread %d: Freed memory not in use\n", THREAD_NUMBER);

	if (thread_mem[THREAD_NUMBER].region.aligned_size < size)
		fprintf(stderr, "Error: Argon2: Thread %d: Freeing incorrect size %zu, was %zu\n",
		    THREAD_NUMBER, size, thread_mem[THREAD_NUMBER].region.aligned_size);

	thread_mem[THREAD_NUMBER].used = 0;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int failed = 0;
	int i;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (i = 0; i < count; i++) {
		argon2_error_codes error_code;
		argon2_context context = {
			.out = (uint8_t*)crypted[i],
			.outlen = saved_salt.hash_size,
			.pwd = (uint8_t*)saved_key[i],
			.pwdlen = saved_len[i],
			.salt = (uint8_t*)saved_salt.salt,
			.saltlen = saved_salt.salt_length,
			.t_cost = saved_salt.t_cost,
			.m_cost = saved_salt.m_cost,
			.lanes = saved_salt.lanes,
			.threads = saved_salt.lanes,
			.allocate_cbk = &allocate,
			.free_cbk = &deallocate,
			.flags = ARGON2_DEFAULT_FLAGS,
			.version = ARGON2_VERSION_NUMBER
		};
		error_code = argon2_ctx(&context, saved_salt.type);
		if (error_code != ARGON2_OK) {
			failed = -1;
			fprintf(stderr, "Error: Argon2 failed: %s\n", argon2_error_message(error_code));
#ifndef _OPENMP
			break;
#endif
		}
	}

	if (failed) {
#ifdef _OPENMP
		fprintf(stderr, "Error: Argon2 failed in some threads\n");
#endif
		error();
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	int i;

	for (i = 0; i < count; i++) {
		if (!memcmp(binary, crypted[i], saved_salt.hash_size))
			return 1;
	}
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypted[index], saved_salt.hash_size);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

#define COMMON_GET_HASH_VAR crypted
#include "common-get-hash.h"

static int salt_hash(void *_salt)
{
	int i;
	struct argon2_salt *salt = (struct argon2_salt*)_salt;
	unsigned int hash = 0;
	char *p = salt->salt;

	for (i = 0;i < salt->salt_length;i++) {
		hash <<= 1;
		hash += (unsigned char)*p++;
		if (hash >> SALT_HASH_LOG) {
			hash ^= hash >> SALT_HASH_LOG;
			hash &= (SALT_HASH_SIZE - 1);
		}
	}

	hash ^= hash >> SALT_HASH_LOG;
	hash &= (SALT_HASH_SIZE - 1);

	return hash;
}

static unsigned int tunable_cost_t(void *_salt)
{
	struct argon2_salt *salt = (struct argon2_salt *)_salt;
	return salt->t_cost;
}

static unsigned int tunable_cost_m(void *_salt)
{
	struct argon2_salt *salt = (struct argon2_salt *)_salt;
	return salt->m_cost;
}

static unsigned int tunable_cost_p(void *_salt)
{
	struct argon2_salt *salt = (struct argon2_salt *)_salt;
	return salt->lanes;
}

static unsigned int tunable_cost_type(void *_salt)
{
	struct argon2_salt *salt = (struct argon2_salt *)_salt;
	return (int)salt->type;
}

struct fmt_main fmt_argon2 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		sizeof(struct argon2_salt),
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
#ifdef _OPENMP
		FMT_OMP |
#endif
		FMT_CASE | FMT_8_BIT,
		{
			"t",
			"m",
			"p",
			"type [0:Argon2d 1:Argon2i 2:Argon2id]"
		},
		{
			FORMAT_TAG_d,
			FORMAT_TAG_i,
			FORMAT_TAG_id
		},
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
		{
			tunable_cost_t,
			tunable_cost_m,
			tunable_cost_p,
			tunable_cost_type,
		},
		fmt_default_source,
		{
			fmt_default_binary_hash_0,
			fmt_default_binary_hash_1,
			fmt_default_binary_hash_2,
			fmt_default_binary_hash_3,
			fmt_default_binary_hash_4,
			fmt_default_binary_hash_5,
			fmt_default_binary_hash_6
		},
		salt_hash,
		NULL,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
#define COMMON_GET_HASH_LINK
#include "common-get-hash.h"
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif	/* plugin stanza */
