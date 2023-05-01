/*
 * This software is Copyright (c) 2016 Agnieszka Bielec <bielecagnieszka8 at gmail.com>,
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

#include "../arch.h"
#include "../params.h"
#include "../common.h"
#include "../formats.h"
#include "../options.h"
#include "../argon2.h"
#include "../argon2_core.h"
#include "../argon2_encoding.h"

#define FORMAT_LABEL            "argon2"
#define FORMAT_NAME             ""
#define FORMAT_TAG_d            "$argon2d$"
#define FORMAT_TAG_i            "$argon2i$"
#define FORMAT_TAG_LEN          (sizeof(FORMAT_TAG_d)-1)

#if defined (JOHN_NO_SIMD)
#define ALGORITHM_NAME          "Blake2"
#else
#if defined(__XOP__)
#define ALGORITHM_NAME          "Blake2 XOP"
#elif defined(__AVX__)
#define ALGORITHM_NAME          "Blake2 AVX"
#elif defined(__SSSE3__)
#define ALGORITHM_NAME          "Blake2 SSSE3"
#elif defined(__SSE2__)
#define ALGORITHM_NAME          "Blake2 SSE2"
#else
#define ALGORITHM_NAME          "Blake2"
#endif
#endif

#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x107
#define PLAINTEXT_LENGTH        100 //only in john
#define BINARY_SIZE             256 //only in john
#define BINARY_ALIGN            sizeof(uint32_t)
#define SALT_SIZE               64  //only in john
#define SALT_ALIGN              sizeof(uint32_t)

#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      2

#define OMP_SCALE               8 // tuned w/ MKPC for core i7m

#ifdef _OPENMP
#define THREAD_NUMBER omp_get_thread_num()
#else
#define THREAD_NUMBER 1
#endif

static struct fmt_tests tests[] = {
	{"$argon2d$v=19$m=4096,t=3,p=1$ZGFtYWdlX2RvbmU$w9w3s5/zV8+PcAZlJhnTCOE+vBkZssmZf6jOq3dKv50","password"},
	{"$argon2i$v=19$m=4096,t=3,p=1$ZGFtYWdlX2RvbmU$N59QwnpxDQZRj1/cO6bqm408dD6Z2Z9LKYpwFJSPVKA","password"},
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

static struct argon2_salt saved_salt;
static region_t * memory;
static void **pseudo_rands;

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *saved_len;
static int sc_threads = 1;
static size_t saved_mem_size;
static uint32_t saved_segment_length;

static unsigned char (*crypted)[BINARY_SIZE];

static void *get_salt(char *ciphertext);

static void init(struct fmt_main *self)
{
	int i;

	sc_threads = omp_autotune(self, OMP_SCALE);

	saved_key =
	    mem_calloc(self->params.max_keys_per_crypt, sizeof(*saved_key));
	crypted = mem_calloc(self->params.max_keys_per_crypt, (BINARY_SIZE));
	saved_len = mem_calloc(self->params.max_keys_per_crypt, sizeof(int));
	memory=mem_calloc(sc_threads, sizeof(region_t));
	pseudo_rands=mem_calloc(sc_threads,sizeof(void*));

	for (i=0;i<sc_threads;i++)
	{
		init_region_t(&memory[i]);
		pseudo_rands[i]=NULL;
	}

	saved_mem_size=0;
	saved_segment_length=0;
}

static void done(void)
{
	int i;
	for (i=0;i<sc_threads;i++)
	{
		free_region_t(&memory[i]);
		MEM_FREE(pseudo_rands[i]);
	}
	MEM_FREE(memory);
	MEM_FREE(pseudo_rands);
	MEM_FREE(saved_len);
	MEM_FREE(crypted);
	MEM_FREE(saved_key);
}

static void print_memory(double memory)
{
	char s[] = "\0kMGT";
	int i = 0;

	while (memory >= 1024 && s[i + 1]) {
		memory /= 1024;
		i++;
	}
	fprintf(stderr, "memory per hash : %.2lf %cB\n", memory, s[i]);
}

static void reset(struct db_main *db)
{
	static int printed=0;

	if (!printed && options.verbosity > VERB_LEGACY)
	{
		int i;
		uint32_t m_cost, prev_m_cost;
		m_cost=prev_m_cost=0;
		if (!db) {
			for (i = 0; tests[i].ciphertext; i++)
			{
				struct argon2_salt *salt;
				salt=get_salt(tests[i].ciphertext);
				m_cost = MAX(m_cost, salt->m_cost);
				if (i==0)
				{
					printf("\n");
					prev_m_cost=m_cost;
					print_memory(sizeof(block)*m_cost);
				}
			}

			if (prev_m_cost!=m_cost)
			{
				printf("max ");
				print_memory(sizeof(block)*m_cost);
			}
		} else {
			struct db_salt *salts = db->salts;
			while (salts != NULL) {
				struct argon2_salt * salt=salts->salt;
				m_cost = MAX(m_cost, salt->m_cost);
				salts = salts->next;
			}

			printf("\n");
			print_memory(sizeof(block)*m_cost);
		}
	}
}

static void ctx_init(argon2_context *ctx)
{
	//size_t maxadlen = ctx->adlen;
        //size_t maxsaltlen = ctx->saltlen;
        //size_t maxoutlen = ctx->outlen;

	static uint8_t out[BINARY_SIZE];
	static uint8_t salt[SALT_SIZE];

	ctx->adlen=0;
	ctx->saltlen=SALT_SIZE;
	ctx->outlen=BINARY_SIZE;

	ctx->out=out;
	ctx->salt=salt;
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	argon2_context ctx;
	int res;

	ctx_init(&ctx);

	if (!strncmp(ciphertext, FORMAT_TAG_d, FORMAT_TAG_LEN))
		res=argon2_decode_string(&ctx, ciphertext, Argon2_d);
	else if (!strncmp(ciphertext, FORMAT_TAG_i, FORMAT_TAG_LEN))
		res=argon2_decode_string(&ctx, ciphertext, Argon2_i);
	else
		return 0;

	if (res!=ARGON2_OK || ctx.outlen < 8)
	  return 0;

	return 1;
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
	static char out[BINARY_SIZE];
	argon2_context ctx;

	ctx_init(&ctx);
	if (!strncmp(ciphertext, FORMAT_TAG_d, FORMAT_TAG_LEN))
		argon2_decode_string(&ctx, ciphertext, Argon2_d);
	else
		argon2_decode_string(&ctx, ciphertext, Argon2_i);
	memset(out, 0, BINARY_SIZE);
	memcpy(out, ctx.out, ctx.outlen);

	return out;
}

static void *get_salt(char *ciphertext)
{
	static struct argon2_salt salt;
	argon2_context ctx;

	memset(&salt,0,sizeof(salt));

	ctx_init(&ctx);
	if (!strncmp(ciphertext, FORMAT_TAG_d, FORMAT_TAG_LEN)) {
		argon2_decode_string(&ctx, ciphertext, Argon2_d);
		salt.type = Argon2_d;
	} else {
		argon2_decode_string(&ctx, ciphertext, Argon2_i);
		salt.type = Argon2_i;
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
	uint32_t i;
	size_t mem_size;
	uint32_t segment_length, memory_blocks;
	memcpy(&saved_salt,salt,sizeof(struct argon2_salt));


	mem_size=sizeof(block)*saved_salt.m_cost;

	memory_blocks = saved_salt.m_cost;

        if (memory_blocks < 2 * ARGON2_SYNC_POINTS * saved_salt.lanes) {
           memory_blocks = 2 * ARGON2_SYNC_POINTS * saved_salt.lanes;
        }

	segment_length = memory_blocks / (saved_salt.lanes * ARGON2_SYNC_POINTS);

	if (mem_size>saved_mem_size)
	{
		if (saved_mem_size>0)
			for (i=0;i<sc_threads;i++)
				free_region_t(&memory[i]);
		for (i=0;i<sc_threads;i++)
			alloc_region_t(&memory[i],mem_size);

		saved_mem_size=mem_size;
	}

	if (segment_length>saved_segment_length)
	{
		if (saved_segment_length>0)
			for (i=0;i<sc_threads;i++)
				MEM_FREE(pseudo_rands[i]);
		for (i=0;i<sc_threads;i++)
			pseudo_rands[i]=mem_calloc(sizeof(uint64_t), segment_length);

		saved_segment_length=segment_length;
	}
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
	return !memcmp(binary, crypted[index],  saved_salt.hash_size);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int i;
	const int count = *pcount;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (i = 0; i < count; i++) {
		argon2_hash(saved_salt.t_cost, saved_salt.m_cost, saved_salt.lanes, saved_key[i], saved_len[i], saved_salt.salt,
		    saved_salt.salt_length, crypted[i], saved_salt.hash_size, 0, 0, saved_salt.type, ARGON2_VERSION_NUMBER, memory[THREAD_NUMBER%sc_threads].aligned, pseudo_rands[THREAD_NUMBER%sc_threads]);
	}

	return count;
}

#define COMMON_GET_HASH_VAR crypted
#include "../common-get-hash.h"

static int salt_hash(void *_salt)
{
	int i;
	struct argon2_salt *salt = (struct argon2_salt*)_salt;
	unsigned int hash = 0;
	char *p = salt->salt;

	for (i=0;i<salt->salt_length;i++) {
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


#if FMT_MAIN_VERSION > 11

static unsigned int tunable_cost_t(void *_salt)
{
	struct argon2_salt *salt=(struct argon2_salt *)_salt;
	return salt->t_cost;
}

static unsigned int tunable_cost_m(void *_salt)
{
	struct argon2_salt *salt=(struct argon2_salt *)_salt;
	return salt->m_cost;
}

static unsigned int tunable_cost_p(void *_salt)
{
	struct argon2_salt *salt=(struct argon2_salt *)_salt;
	return salt->lanes;
}

static unsigned int tunable_cost_type(void *_salt)
{
	struct argon2_salt *salt=(struct argon2_salt *)_salt;
	return (int)salt->type;
}
#endif

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
			"type [0:Argon2d 1:Argon2i]"
		},
		{0},
		tests
	}, {
		init,
		done,
		reset,
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
#include "../common-get-hash.h"
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif
