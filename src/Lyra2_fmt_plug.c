/*
 * This software is Copyright (c) 2015 Agnieszka Bielec <bielecagnieszka8 at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_lyra2;
#elif FMT_REGISTERS_H
john_register_one(&fmt_lyra2);
#else

#include <string.h>

#include "arch.h"
#include "params.h"
#include "common.h"
#include "options.h"
#include "formats.h"
#include "memdbg.h"
#include "Lyra2.h"
#include "Sponge.h"
#include "Sponge_sse.h"
#ifdef _OPENMP
#include <omp.h>
#endif

#define FORMAT_LABEL			"Lyra2"
#define FORMAT_NAME			""

#define ALGORITHM_NAME			"Blake2" LYRA2_SIMD

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0

#define PLAINTEXT_LENGTH		125

#define BINARY_SIZE			256  //BIARY_SIZE in Lyra2 is unlimited

#define CIPHERTEXT_LENGTH		(2*BINARY_SIZE)

#define BINARY_ALIGN			1
#define SALT_SIZE			64

#define SALT_ALIGN			1

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1

#define OMP_SCALE			1

static struct fmt_tests tests[] = {
	{"$Lyra2$8$8$256$2$salt$03cafef9b80e74342b781e0c626db07f4783210c99e94e5271845fd48c8f80af", "password"},
	{"$Lyra2$8$8$256$2$salt2$e61b2fc5a76d234c49188c2d6c234f5b5721382b127bea0177287bf5f765ec1a","password"},
	{"$Lyra2$1$12$256$3$salt$27a195d60ee962293622e2ee8c449102afe0e720e38cb0c4da948cfa1044250a","password"},
	{"$Lyra2$8$8$256$2$salt$23ac37677486f032bf9960968318b53617354e406ac8afcd","password"},
	{"$Lyra2$16$16$256$2$salt$f6ab1f65f93f2d491174f7f3c2a681fb95dadee998a014b90d78aae02bb099", "password"},
	{"$Lyra2$1$8$256$1$one$4b84f7d57b1065f1bd21130152d9f46b71f4537b7f9f31710fac6b87e5f480cb","pass"},
	{NULL}
};

struct lyra2_salt {
	uint32_t t_cost,m_cost;
	uint32_t nCols,nThreads;
	uint32_t hash_size;
	uint32_t salt_length;
	char salt[SALT_SIZE];
};

static struct lyra2_salt saved_salt, prev_saved_salt;
static struct lyra2_allocation *allocated;

static char *saved_key;

static unsigned char *crypted;
static int threads;
static int alloc;

unsigned short N_COLS;
int nCols_is_2_power;

static void *get_salt(char *ciphertext);
static void free_allocated();

static unsigned long size(unsigned long s)
{
	return MAX(s,MEM_ALIGN_CACHE);
}

static void init(struct fmt_main *self)
{
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

	alloc=0;
}

static void done(void)
{
	prev_saved_salt=saved_salt;
	free_allocated();
	free(saved_key);
	free(crypted);
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
		unsigned int i;
		uint32_t M_COST=0;
		uint64_t N_COLS=0;
		uint64_t prev_need=0, need=0;
		if (!db) {
			for (i = 0; tests[i].ciphertext; i++)
			{
				struct lyra2_salt *salt=get_salt(tests[i].ciphertext); 
				M_COST = MAX(M_COST, salt->m_cost);
				N_COLS = MAX(N_COLS, salt->nCols);
				if(i==0)
				{
					printf("\n");
					prev_need=(uint64_t) M_COST * (uint64_t) (BLOCK_LEN_INT64 * N_COLS * 8);
					print_memory(prev_need);
				}
			}
			need=(uint64_t) M_COST * (uint64_t) (BLOCK_LEN_INT64 * N_COLS * 8);
			if(prev_need!=need)
			{
				printf("max ");
				print_memory(need);
			}
		} else {
			struct db_salt *salts = db->salts;
			M_COST = 0;
			while (salts != NULL) {
				struct lyra2_salt *salt=salts->salt;
				M_COST = MAX(M_COST, salt->m_cost);
				N_COLS = MAX(N_COLS, salt->nCols);
				salts = salts->next;
			}
			printf("\n");
			need=(uint64_t) M_COST * (uint64_t) (BLOCK_LEN_INT64 * N_COLS * 8);
			print_memory(need);
		}
		printed=1;
	}
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *next_dollar;
	char *i;
	struct lyra2_salt *salt;

	if (strncmp(ciphertext, "$Lyra2$", 7) &&
	    strncmp(ciphertext, "$lyra2$", 7))
		return 0;
	i = ciphertext + 7;
	//t_cost
	next_dollar = strchr(i, '$');
	if (next_dollar == NULL || next_dollar - i > 4 || next_dollar == i)
		return 0;
	i = next_dollar + 1;
	//m_cost
	next_dollar = strchr(i, '$');
	if (next_dollar == NULL || next_dollar - i > 4 || next_dollar == i)
		return 0;
	i = next_dollar + 1;
	//nCols
	next_dollar = strchr(i, '$');
	if (next_dollar == NULL || next_dollar == i)
		return 0;
	i = next_dollar + 1;
	//nThreads
	next_dollar = strchr(i, '$');
	if (next_dollar == NULL || next_dollar == i)
		return 0;
	i = next_dollar + 1;
	//salt
	next_dollar = strchr(i, '$');
	if (next_dollar == NULL || next_dollar - i > SALT_SIZE || next_dollar == i)
		return 0;
	i = next_dollar + 1;
	if (strlen(i) > CIPHERTEXT_LENGTH || strlen(i) == 0)
		return 0;
	while (atoi16[ARCH_INDEX(*i)] != 0x7F)	
		i++;
	if (*i)
		return 0;
	
	salt=get_salt(ciphertext);

	if (salt->m_cost < 3) 
		return 0;

	if ((salt->m_cost / 2) % salt->nThreads != 0) 
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
		if (a >= 97)
			a -= 87;
		else
			a -= 48;
		if (b >= 97)
			b -= 87;
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
	static struct lyra2_salt salt;
	char *i = ciphertext + 7;
	char *first_dollar,*second_dollar,*third_dollar,*fourth_dollar;
	char *last_dollar = strrchr(ciphertext, '$');

	memset(salt.salt, 0, sizeof(salt.salt));

	salt.hash_size = strlen(last_dollar + 1) / 2;

	first_dollar = strchr(i, '$');
	second_dollar = strchr(first_dollar + 1, '$');
	third_dollar = strchr(second_dollar + 1, '$');
	fourth_dollar = strchr(third_dollar + 1, '$');

	salt.salt_length = last_dollar - fourth_dollar - 1;
	salt.t_cost = atoi(i);
	salt.m_cost = atoi(first_dollar+1);
	salt.nCols = atoi(second_dollar+1);
	salt.nThreads = atoi(third_dollar+1);

	memcpy(salt.salt, fourth_dollar + 1, salt.salt_length);

	return (void *)&salt;
}

static void free_allocated()
{
	int i,threadNumber;

	if(!alloc)
		return;

	alloc=0;

	for(i=0;i<threads;i++)
	{
		free(allocated[i].memMatrix); 
		free(allocated[i].pKeys);

		free(allocated[i].row0);
		free(allocated[i].prev0);
		free(allocated[i].rowP);
		free(allocated[i].prevP);
		free(allocated[i].jP);
		free(allocated[i].kP);
		free(allocated[i].ptrWord);
	
		for(threadNumber=0;threadNumber<prev_saved_salt.nThreads;threadNumber++)
		{
			free_region(&(allocated[i].threadSliceMatrix[threadNumber]));
			free(allocated[i].threadKey[threadNumber]);
			free(allocated[i].threadState[threadNumber]);
		}

		free(allocated[i].threadSliceMatrix); 
		free(allocated[i].threadKey);
		free(allocated[i].threadState);
	}
	free(allocated);
}

static int is_power_of2(unsigned int x)
{
	unsigned int i=1;
	while(i<=x)
	{
		if (i==x)
			return 1;
		i*=2;
	}
	return 0;
}

static void set_salt(void *salt)
{
	int i,threadNumber;
	uint64_t iP;

	prev_saved_salt=saved_salt;
	memcpy(&saved_salt,salt,sizeof(struct lyra2_salt));
	N_COLS=saved_salt.nCols;

	if(prev_saved_salt.m_cost==saved_salt.m_cost && prev_saved_salt.nThreads==saved_salt.nThreads && prev_saved_salt.nCols==saved_salt.nCols)
		return;

	nCols_is_2_power=is_power_of2(N_COLS);

	free_allocated();
	allocated=malloc(threads*(sizeof(struct lyra2_allocation)));

	iP = (uint64_t) ((uint64_t) (saved_salt.m_cost/saved_salt.nThreads) * (uint64_t) (BLOCK_LEN_INT64 * saved_salt.nCols * 8));

	for(i=0;i<threads;i++)
	{
		allocated[i].memMatrix = malloc(size(saved_salt.m_cost * sizeof (uint64_t*)));
    		if (allocated[i].memMatrix == NULL) {
			exit(1);
		}
		allocated[i].pKeys = malloc(size(saved_salt.nThreads * sizeof (unsigned char*)));
		if (allocated[i].pKeys == NULL) {
        		exit(1);
		}
		allocated[i].row0=malloc(size(sizeof(uint64_t)*saved_salt.nThreads));
		allocated[i].prev0=malloc(size(sizeof(uint64_t)*saved_salt.nThreads));
		allocated[i].rowP=malloc(size(sizeof(uint64_t)*saved_salt.nThreads));
		allocated[i].prevP=malloc(size(sizeof(uint64_t)*saved_salt.nThreads));
		allocated[i].jP=malloc(size(sizeof(uint64_t)*saved_salt.nThreads));
		allocated[i].kP=malloc(size(sizeof(uint64_t)*saved_salt.nThreads));
		allocated[i].ptrWord=malloc(size(sizeof(void *)*saved_salt.nThreads));

		allocated[i].threadSliceMatrix=malloc(size(sizeof(region_t)*saved_salt.nThreads));
		for(threadNumber=0;threadNumber<saved_salt.nThreads;threadNumber++)
		{
			init_region(&(allocated[i].threadSliceMatrix[threadNumber]));
		}
		allocated[i].threadKey=malloc(size(sizeof(void *)*saved_salt.nThreads));
		allocated[i].threadState=malloc(size(sizeof(void *)*saved_salt.nThreads));

		for(threadNumber=0;threadNumber<saved_salt.nThreads;threadNumber++)
		{
			alloc_region(&(allocated[i].threadSliceMatrix[threadNumber]),iP);

			allocated[i].threadKey[threadNumber] =  malloc(size(BINARY_SIZE));
			if (allocated[i].threadKey[threadNumber] == NULL) {
        			exit(1);
			}

			allocated[i].threadState[threadNumber] = malloc(size(16 * sizeof (uint64_t)));
			if (allocated[i].threadState[threadNumber] == NULL) {
        			exit(1);
			}
		}
	}

	alloc=0;
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

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int i;
	const int count = *pcount;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (i = 0; i < count; i++) {
		LYRA2
		    (crypted + i * BINARY_SIZE, saved_salt.hash_size,
		    saved_key + i * (PLAINTEXT_LENGTH + 1),
		    strlen(saved_key + i * (PLAINTEXT_LENGTH + 1)), saved_salt.salt,
		    saved_salt.salt_length, saved_salt.t_cost, saved_salt.m_cost,
		    saved_salt.nCols, saved_salt.nThreads, &allocated[i%threads]);
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
	struct lyra2_salt *salt = (struct lyra2_salt*)_salt;
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
	struct lyra2_salt *salt=(struct lyra2_salt *)_salt;
	return salt->t_cost;
}

static unsigned int tunable_cost_m(void *_salt)
{
	struct lyra2_salt *salt=(struct lyra2_salt *)_salt;
	return salt->m_cost;
}

static unsigned int tunable_cost_c(void *_salt)
{
	struct lyra2_salt *salt=(struct lyra2_salt *)_salt;
	return salt->nCols;
}

static unsigned int tunable_cost_p(void *_salt)
{
	struct lyra2_salt *salt=(struct lyra2_salt *)_salt;
	return salt->nThreads;
}

#endif

struct fmt_main fmt_lyra2 = {
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
		sizeof(struct lyra2_salt),
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
			"c",
			"p"
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
			tunable_cost_c,
			tunable_cost_p
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
