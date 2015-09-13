/*
 * This software is Copyright (c) 2015 Agnieszka Bielec <bielecagnieszka8 at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_argon2d;
#elif FMT_REGISTERS_H
john_register_one(&fmt_argon2d);
#else

#include <string.h>

#include "arch.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#include "options.h"
#include "argon2d.h"
#include "memdbg.h"
#ifdef _OPENMP
#include <omp.h>
#endif

#define FORMAT_LABEL			"argon2d"
#define FORMAT_NAME			""

#if defined(__XOP__)
#define ALGORITHM_NAME			"Blake2 XOP"
#elif defined(__AVX__)
#define ALGORITHM_NAME			"Blake2 AVX"
#elif defined(__SSSE3__)
#define ALGORITHM_NAME			"Blake2 SSSE3"
#elif defined(__SSE2__)
#define ALGORITHM_NAME			"Blake2 SSE2"
#else
#define ALGORITHM_NAME			" "
#endif

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0
#define PLAINTEXT_LENGTH		MAX_SECRET
#define CIPHERTEXT_LENGTH		MAX_SECRET*2
#define BINARY_SIZE			256
#define BINARY_ALIGN			1
#define SALT_SIZE			64
#define SALT_ALIGN			1

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1

#define OMP_SCALE 			1

#ifdef _OPENMP
#define THREAD_NUMBER omp_get_thread_num()
#else
#define THREAD_NUMBER 1
#endif

static struct fmt_tests tests[] = {
	{"$argon2d$1$1536$1$damage_done$EE74C39511A1D4C4F71FD17966A1CE1F6D3E1B4E93438636EFEEC9696AD27A6C","white_noise_black_silence"},
	{"$argon2d$1$1536$1$damage_done$EE74C39511A1D4C4F71FD17966A1CE1F6D3E1B4E93438636EFEEC9696AD27A6C","white_noise_black_silence"},
	{"$argon2d$1$1536$5$damage_done$E88EDA0E8949460106F08336776650361C335648A41B54CA6D9239F4D6970836","the_fatalist"},
	{"$argon2d$1$1536$5$damage_done$E88EDA0E8949460106F08336776650361C335648A41B54CA6D9239F4D6970836","the_fatalist"},
	{"$argon2d$3$100$1$salt_salt$30C1116A09CCF4F77CC10C9F07EAD680C2EC7CEC9E3BBDFC58D354BF203A24B0", "one_thought"},
	{"$argon2d$3$100$1$salt_salt$CF71F3376C28CD05EFB51AB523D1FED12384AB64CD42455D7B418078358B3834", "the_wonders_at_your_feets"},
	{"$argon2d$10$10$1$low_costs$0DE62C6FD56B37040EA8D82177BC0C883B051E67689BEA8E6AC54CB9EAA4DD3B", "blind_at_heart"},
	{"$argon2d$5$50$1$another_salt$85EACDF4","her_silent_language"},
	{NULL}
};

struct argon2d_salt {
	uint32_t t_cost,m_cost;
	uint8_t lanes;
	uint32_t hash_size;
	uint32_t salt_length;
	char salt[SALT_SIZE];
};

struct argon2d_salt saved_salt;
static region_t * memory;

static char *saved_key;
static int threads;
static uint64_t saved_mem_size;

int prev_m_cost;

static unsigned char *crypted;

static void *get_salt(char *ciphertext);

static void init(struct fmt_main *self)
{
	int i;
#ifdef _OPENMP
	int omp_t = omp_get_max_threads();
	threads=omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#else
	threads=1;
#endif
	saved_key =
	    malloc(self->params.max_keys_per_crypt * (PLAINTEXT_LENGTH + 1));
	memset(saved_key, 0,
	    self->params.max_keys_per_crypt * (PLAINTEXT_LENGTH + 1));
	crypted = malloc(self->params.max_keys_per_crypt * (BINARY_SIZE));
	memset(crypted, 0, self->params.max_keys_per_crypt * (BINARY_SIZE));

	memory=malloc(threads*sizeof(region_t));
	for(i=0;i<threads;i++)
		init_region(&memory[i]);

	saved_mem_size=0;
}

static void done(void)
{
	int i;
	free(saved_key);
	free(crypted);
	for(i=0;i<threads;i++)
		free_region(&memory[i]);
	free(memory);
}

static void print_memory(double memory)
{
	char s[]="\0kMGT";
	int i=0;
	while(memory>=1024)
	{
		memory/=1024;
		i++;
	}
	printf("memory per hash : %.2lf %cB\n",memory,s[i]);
}

static void reset(struct db_main *db)
{
	static int printed=0;
	if(!printed)
	{
		int i;
		uint32_t m_cost, prev_m_cost;
		m_cost=prev_m_cost=0;
		if (!db) {
			for (i = 0; tests[i].ciphertext; i++)
			{
				struct argon2d_salt *salt;
				salt=get_salt(tests[i].ciphertext);
				m_cost = MAX(m_cost, salt->m_cost);
				if(i==0)
				{
					printf("\n");
					prev_m_cost=m_cost;
					print_memory(m_cost<<10);
				}
			}

			if(prev_m_cost!=m_cost)
			{
				printf("max ");
				print_memory(m_cost<<10);
			}
		} else {
			struct db_salt *salts = db->salts;
			while (salts != NULL) {
				struct argon2d_salt * salt=salts->salt;
				m_cost = MAX(m_cost, salt->m_cost);
				salts = salts->next;
			}

			printf("\n");
			print_memory(m_cost<<10);
		}
	}
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	struct argon2d_salt *salt;
	char *next_dollar;
	char *i;

	if (strncmp(ciphertext, "$argon2d$", 9) &&
	    strncmp(ciphertext, "$argon2d$", 9))
		return 0;
	i = ciphertext + 9;
	//t_cost
	next_dollar = strchr(i, '$');
	if (next_dollar == NULL || next_dollar == i)
		return 0;
	i = next_dollar + 1;
	//m_cost
	next_dollar = strchr(i, '$');
	if (next_dollar == NULL || next_dollar == i)
		return 0;
	i = next_dollar + 1;
	//lanes
	next_dollar = strchr(i, '$');
	if (next_dollar == NULL || next_dollar == i)
		return 0;
	if(atoi(i)>255)
		return 0;
	i = next_dollar + 1;
	//salt
	next_dollar = strchr(i, '$');
	if (next_dollar == NULL || next_dollar - i > SALT_SIZE || next_dollar == i)
		return 0;
	i = next_dollar + 1;
	if (strlen(i) > CIPHERTEXT_LENGTH || strlen(i) == 0)
		return 0;
	while (atoi16[ARCH_INDEX(*i)] != 0x7F)	//
		i++;
	if (*i)
		return 0;

	salt=get_salt(ciphertext);

	//minumum m_cost =8L blocks, where L is the number of lanes
	if (salt->m_cost < 2 * SYNC_POINTS*salt->lanes)
		return 0;
	if (salt->m_cost>MAX_MEMORY)
		return 0;

	salt->m_cost = (salt->m_cost / (salt->lanes*SYNC_POINTS))*(salt->lanes*SYNC_POINTS); //Ensure that all segments have equal length;

	//minimum t_cost =1
	if (salt->t_cost<MIN_TIME)
		return 0;

	if (salt->lanes<MIN_LANES)
		return 0;
	if (salt->lanes>salt->m_cost / BLOCK_SIZE_KILOBYTE)
		return 0;

	return 1;
}

static void set_key(char *key, int index)
{
	int len;
	len = strlen(key);
	if (len > PLAINTEXT_LENGTH)
		len = PLAINTEXT_LENGTH;
	memcpy(saved_key + index * (PLAINTEXT_LENGTH + 1), key, len);
	saved_key[index * (PLAINTEXT_LENGTH + 1) + len] = 0;
}

static char *get_key(int index)
{
	return saved_key + index * (PLAINTEXT_LENGTH + 1);
}

static void char_to_bin(char *in, int char_length, char *bin)
{
	int i;
	for (i = 0; i < char_length; i += 2) {
		char a = in[i];
		char b = in[i + 1];
		if (a >= 65)
			a -= 55;
		else
			a -= 48;
		if (b >= 65)
			b -= 55;
		else
			b -= 48;
		bin[i / 2] = a << 4;
		bin[i / 2] += b;
	}
}

static void *get_binary(char *ciphertext)
{
	char *ii;
	static char out[BINARY_SIZE];
	memset(out, 0, BINARY_SIZE);

	ii = strrchr(ciphertext, '$');
	ii = ii + 1;
	char_to_bin(ii, strlen(ii), out);
	return out;
}

static void *get_salt(char *ciphertext)
{
	static struct argon2d_salt salt;
	char *i = ciphertext + 9;
	char *first_dollar,*second_dollar, *third_dollar;
	char *last_dollar = strrchr(ciphertext, '$');

	memset(salt.salt, 0, sizeof(salt.salt));

	salt.hash_size = strlen(last_dollar + 1) / 2;

	first_dollar = strchr(i, '$');
	second_dollar = strchr(first_dollar + 1, '$');
	third_dollar = strchr(second_dollar + 1, '$');

	salt.salt_length = last_dollar - third_dollar - 1;
	salt.t_cost = atoi(i);
	salt.m_cost = atoi(first_dollar+1);
	salt.lanes = atoi(second_dollar+1);

	memcpy(salt.salt, third_dollar + 1, salt.salt_length);

	return (void *)&salt;
}

static void set_salt(void *salt)
{
	uint32_t i;
	size_t mem_size;
	memcpy(&saved_salt,salt,sizeof(struct argon2d_salt));
	mem_size= saved_salt.m_cost<<10;
	if(mem_size>saved_mem_size)
	{
		if(saved_mem_size>0)
			for(i=0;i<threads;i++)
				free_region(&memory[i]);
		for(i=0;i<threads;i++)
			alloc_region(&memory[i],mem_size);

		saved_mem_size=mem_size;
	}
}

static int cmp_all(void *binary, int count)
{
	int i;
	for (i = 0; i < count; i++) {
		if (!memcmp(binary, crypted + i * BINARY_SIZE, saved_salt.hash_size))
			return 1;
	}
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypted + index * BINARY_SIZE,  saved_salt.hash_size);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static void argon2d(void *out, size_t outlen, const void *in, size_t inlen,
    const void *salt, size_t saltlen, unsigned int t_cost,
    unsigned int m_cost, uint8_t lanes, region_t *memory)
{
#ifdef __SSE2__
	ARGON2d_SSE
#else
	ARGON2d
#endif
		(out, outlen, in, inlen, salt, saltlen, t_cost, m_cost, lanes, memory->aligned);
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int i;
	const int count = *pcount;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (i = 0; i < count; i++) {
		argon2d
		    (crypted + i * BINARY_SIZE, saved_salt.hash_size,
		    saved_key + i * (PLAINTEXT_LENGTH + 1),
		    strlen(saved_key + i * (PLAINTEXT_LENGTH + 1)), saved_salt.salt,
		    saved_salt.salt_length, saved_salt.t_cost, saved_salt.m_cost, 
		    saved_salt.lanes, &memory[THREAD_NUMBER%threads]);
	}
	return count;
}

static int get_hash_0(int index)
{
	ARCH_WORD_32 *crypt = (ARCH_WORD_32 *) (crypted + index * BINARY_SIZE);
	return crypt[0] & 0xF;
}

static int get_hash_1(int index)
{
	ARCH_WORD_32 *crypt = (ARCH_WORD_32 *) (crypted + index * BINARY_SIZE);
	return crypt[0] & 0xFF;
}

static int get_hash_2(int index)
{
	ARCH_WORD_32 *crypt = (ARCH_WORD_32 *) (crypted + index * BINARY_SIZE);
	return crypt[0] & 0xFFF;
}

static int get_hash_3(int index)
{
	ARCH_WORD_32 *crypt = (ARCH_WORD_32 *) (crypted + index * BINARY_SIZE);
	return crypt[0] & 0xFFFF;
}

static int get_hash_4(int index)
{
	ARCH_WORD_32 *crypt = (ARCH_WORD_32 *) (crypted + index * BINARY_SIZE);
	return crypt[0] & 0xFFFFF;
}

static int get_hash_5(int index)
{
	ARCH_WORD_32 *crypt = (ARCH_WORD_32 *) (crypted + index * BINARY_SIZE);
	return crypt[0] & 0xFFFFFF;
}

static int get_hash_6(int index)
{
	ARCH_WORD_32 *crypt = (ARCH_WORD_32 *) (crypted + index * BINARY_SIZE);
	return crypt[0] & 0x7FFFFFF;
}

static int salt_hash(void *_salt)
{
	int i;
	struct argon2d_salt *salt = (struct argon2d_salt*)_salt;
	unsigned int hash = 0;
	char *p = salt->salt;

	for(i=0;i<salt->salt_length;i++) {
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
	struct argon2d_salt *salt=(struct argon2d_salt *)_salt;
	return salt->t_cost;
}

static unsigned int tunable_cost_m(void *_salt)
{
	struct argon2d_salt *salt=(struct argon2d_salt *)_salt;
	return salt->m_cost;
}

static unsigned int tunable_cost_l(void *_salt)
{
	struct argon2d_salt *salt=(struct argon2d_salt *)_salt;
	return salt->lanes;
}

#endif

struct fmt_main fmt_argon2d = {
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
		sizeof(struct argon2d_salt),
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
#ifdef _OPENMP
		FMT_OMP |
#endif
		FMT_CASE | FMT_8_BIT,
#if FMT_MAIN_VERSION > 11
		{
			"t",
			"m",
			"l",
		},
#endif
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
#if FMT_MAIN_VERSION > 11
		{
			tunable_cost_t,
			tunable_cost_m,
			tunable_cost_l
		},
#endif
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
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4,
			get_hash_5,
			get_hash_6
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif
