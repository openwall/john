/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2011,2012 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#include <string.h>
#include <assert.h>

#include "arch.h"
#include "DES_std.h"
#include "common.h"
#include "formats.h"

#define FORMAT_LABEL			"tripcode"
#define FORMAT_NAME			""

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		8
#define CIPHERTEXT_LENGTH		10

#define SALT_SIZE			0
#define SALT_ALIGN			1

static struct fmt_tests tests[] = {
	{"Rk7VUsDT2U", "simpson"},
	{"3GqYIJ3Obs", "tripcode"},
	{"Id1gMYGA52", "ponytail"},
	{NULL}
};

#if DES_BS

#include "DES_bs.h"

#define ALGORITHM_NAME			DES_BS_ALGORITHM_NAME

#define BINARY_SIZE			sizeof(ARCH_WORD_32)
#define BINARY_ALIGN			sizeof(ARCH_WORD_32)

#define TRIPCODE_SCALE			0x40

#define MIN_KEYS_PER_CRYPT		DES_BS_DEPTH
#define MAX_KEYS_PER_CRYPT		(DES_BS_DEPTH * TRIPCODE_SCALE)

static DES_bs_vector (*crypt_out)[64];
static int block_count;
static int worst_case_block_count;

#if DES_bs_mt
static int *l2g;
#endif

static int (*hash_func)(int index);
static int (*next_hash_func)(int index);

#else

#define ALGORITHM_NAME			DES_STD_ALGORITHM_NAME

#define BINARY_SIZE			ARCH_SIZE
#define BINARY_ALIGN			ARCH_SIZE

#define MIN_KEYS_PER_CRYPT		0x40
#define MAX_KEYS_PER_CRYPT		0x1000

static DES_binary binary_mask;

#endif

static struct {
#if DES_BS
	int block, index, hash;
#else
	union {
		double dummy;
		DES_binary binary;
	} aligned;
#endif
	int next; /* index of next entry with the same salt */
	unsigned int salt;
	char key[PLAINTEXT_LENGTH];
} *buffer;

static unsigned char salt_map[0x100];

struct fmt_main fmt_trip;

static void init(struct fmt_main *self)
{
#if !DES_BS
	char fake_crypt[14];
	ARCH_WORD *alt_binary;
#endif
	int i;

#if DES_BS
	DES_bs_init(0, DES_bs_cpt);
#if DES_bs_mt
	fmt_trip.params.min_keys_per_crypt = DES_bs_min_kpc;
	fmt_trip.params.max_keys_per_crypt = DES_bs_min_kpc * TRIPCODE_SCALE;
#endif

#undef howmany
#define howmany(x, y) (((x) + ((y) - 1)) / (y))
	worst_case_block_count = 0xFFF +
	    howmany(fmt_trip.params.max_keys_per_crypt - 0xFFF, DES_BS_DEPTH);
	crypt_out = mem_alloc_tiny(sizeof(*crypt_out) * worst_case_block_count,
	    MEM_ALIGN_CACHE);
	memset(crypt_out, 0, sizeof(*crypt_out) * worst_case_block_count);

#if DES_bs_mt
	l2g = mem_alloc_tiny(sizeof(*l2g) * DES_bs_max_kpc, MEM_ALIGN_CACHE);
#endif

	hash_func = NULL;
	next_hash_func = NULL;
#else
	DES_std_init();

	memset(fake_crypt, '.', 13);
	fake_crypt[13] = 0;
	memcpy(binary_mask, DES_std_get_binary(fake_crypt),
	    sizeof(binary_mask));

	fake_crypt[2] = 'z';
	alt_binary = DES_std_get_binary(fake_crypt);

	for (i = 0; i < 16 / DES_SIZE; i++) {
		binary_mask[i] ^= ~alt_binary[i];
		binary_mask[i] &= DES_BINARY_MASK;
	}
#endif

	buffer = mem_alloc_tiny(sizeof(*buffer) *
	    fmt_trip.params.max_keys_per_crypt,
	    MEM_ALIGN_CACHE);

	for (i = 0; i < 0x100; i++) {
		char *from = ":;<=>?@[\\]^_`";
		char *to = "ABCDEFGabcdef";
		char *p;
		if (atoi64[i] != 0x7F)
			salt_map[i] = i;
		else if ((p = strchr(from, i)))
			salt_map[i] = to[p - from];
		else
			salt_map[i] = '.';
	}
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *pos;

	for (pos = ciphertext; atoi64[ARCH_INDEX(*pos)] != 0x7F; pos++)
		;
	if (*pos || pos - ciphertext != CIPHERTEXT_LENGTH)
		return 0;

	if (atoi64[ARCH_INDEX(*(pos - 1))] & 3)
		return 0;

	return 1;
}

static void *get_binary(char *ciphertext)
{
	char fake_crypt[14];

	fake_crypt[0] = '.';
	fake_crypt[1] = '.';
	fake_crypt[2] = '.';
	memcpy(&fake_crypt[3], ciphertext, 11);

#if DES_BS
	return DES_bs_get_binary(fake_crypt);
#else
	return DES_std_get_binary(fake_crypt);
#endif
}

#if DES_BS

static int binary_hash_0(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xF;
}

static int binary_hash_1(void *binary)
{
	unsigned int w = *(ARCH_WORD_32 *)binary;
	return ((w >> 1) & 0x80) | (w & 0x7F);
}

static int binary_hash_2(void *binary)
{
	unsigned int w = *(ARCH_WORD_32 *)binary;
	return ((w >> 1) & 0xF80) | (w & 0x7F);
}

static int binary_hash_3(void *binary)
{
	unsigned int w = *(ARCH_WORD_32 *)binary;
	return ((w >> 2) & 0xC000) | ((w >> 1) & 0x3F80) | (w & 0x7F);
}

static int binary_hash_4(void *binary)
{
	unsigned int w = *(ARCH_WORD_32 *)binary;
	return ((w >> 2) & 0xFC000) | ((w >> 1) & 0x3F80) | (w & 0x7F);
}

static int binary_hash_5(void *binary)
{
	unsigned int w = *(ARCH_WORD_32 *)binary;
	return ((w >> 3) & 0xE00000) |
	    ((w >> 2) & 0x1FC000) | ((w >> 1) & 0x3F80) | (w & 0x7F);
}

static int binary_hash_6(void *binary)
{
	unsigned int w = *(ARCH_WORD_32 *)binary;
	return ((w >> 3) & 0x7E00000) |
	    ((w >> 2) & 0x1FC000) | ((w >> 1) & 0x3F80) | (w & 0x7F);
}

static MAYBE_INLINE void blkcpy(DES_bs_vector *dst, DES_bs_vector *src, int n)
{
	memcpy(dst, src, n * sizeof(*dst));
}

static MAYBE_INLINE void blkcpy58(DES_bs_vector *dst, DES_bs_vector *src)
{
	memcpy(dst, src, 7 * sizeof(*dst));
	memcpy(&dst[8], &src[8], 7 * sizeof(*dst));
	memcpy(&dst[16], &src[16], 7 * sizeof(*dst));
	memcpy(&dst[24], &src[24], 15 * sizeof(*dst));
	memcpy(&dst[40], &src[40], 7 * sizeof(*dst));
	memcpy(&dst[48], &src[48], 7 * sizeof(*dst));
	memcpy(&dst[56], &src[56], 8 * sizeof(*dst));
}

#if DES_bs_mt
#define MAYBE_T0 \
	const int t = 0;
#else
#define MAYBE_T0
#endif

#define define_get_hash(NAME, CALL) \
static int NAME(int index) \
{ \
	if (hash_func == CALL) \
		return buffer[index].hash; \
	{ \
		int block = buffer[index].block; \
		MAYBE_T0; \
		blkcpy(DES_bs_all.B, crypt_out[block], 27 + 3); \
		return (next_hash_func = CALL)(buffer[index].index); \
	} \
}

define_get_hash(get_hash_0, DES_bs_get_hash_0)
define_get_hash(get_hash_1, DES_bs_get_hash_1t)
define_get_hash(get_hash_2, DES_bs_get_hash_2t)
define_get_hash(get_hash_3, DES_bs_get_hash_3t)
define_get_hash(get_hash_4, DES_bs_get_hash_4t)
define_get_hash(get_hash_5, DES_bs_get_hash_5t)
define_get_hash(get_hash_6, DES_bs_get_hash_6t)

#else

static int binary_hash_0(void *binary)
{
	return DES_STD_HASH_0(*(ARCH_WORD *)binary);
}

static int binary_hash_1(void *binary)
{
	return DES_STD_HASH_1(*(ARCH_WORD *)binary);
}

static int binary_hash_2(void *binary)
{
	return DES_STD_HASH_2(*(ARCH_WORD *)binary);
}

#define binary_hash_3 NULL
#define binary_hash_4 NULL
#define binary_hash_5 NULL
#define binary_hash_6 NULL

static int get_hash_0(int index)
{
	return DES_STD_HASH_0(buffer[index].aligned.binary[0]);
}

static int get_hash_1(int index)
{
	ARCH_WORD binary;

	binary = buffer[index].aligned.binary[0];
	return DES_STD_HASH_1(binary);
}

static int get_hash_2(int index)
{
	ARCH_WORD binary;

	binary = buffer[index].aligned.binary[0];
	return DES_STD_HASH_2(binary);
}

#define get_hash_3 NULL
#define get_hash_4 NULL
#define get_hash_5 NULL
#define get_hash_6 NULL

#endif

static MAYBE_INLINE void crypt_link_by_salt(int count)
{
	int index;
	int salt_bucket[0x1000];

	memset(salt_bucket, -1, sizeof(salt_bucket));
	for (index = count - 1; index >= 0; index--) {
		char fake_crypt[14];

		if (!buffer[index].key[0]) {
			fake_crypt[0] = '.';
			fake_crypt[1] = '.';
		} else
		if (!buffer[index].key[1]) {
			fake_crypt[0] = 'H';
			fake_crypt[1] = '.';
		} else
		if (!buffer[index].key[2]) {
			fake_crypt[0] =
			    salt_map[ARCH_INDEX(buffer[index].key[1])];
			fake_crypt[1] = 'H';
		} else {
			fake_crypt[0] =
			    salt_map[ARCH_INDEX(buffer[index].key[1])];
			fake_crypt[1] =
			    salt_map[ARCH_INDEX(buffer[index].key[2])];
		}
		fake_crypt[13] = 0;

		{
			unsigned int salt = DES_raw_get_salt(fake_crypt);
#if DES_BS
			buffer[index].salt = salt;
			buffer[index].next = salt_bucket[salt];
#else
			if ((buffer[index].next = salt_bucket[salt]) >= 0)
				buffer[index].salt =
				    buffer[salt_bucket[salt]].salt;
			else
				buffer[index].salt =
				    DES_std_get_salt(fake_crypt);
#endif
			salt_bucket[salt] = index;
		}
	}
}

static MAYBE_INLINE void crypt_traverse_by_salt(int count)
{
	int index;
#if DES_bs_mt
	int block_index;
#endif

#if DES_BS
	block_count = 0;
#endif
	for (index = 0; index < count; index++) {
		int gindex;
#if DES_BS
		int lindex;
#if DES_bs_mt
		int lindex_mod;
#else
		int l2g[DES_BS_DEPTH];
#endif
#endif

		if (buffer[index].salt == 0xFFFFFFFF) /* already processed */
			continue;

		gindex = index;
#if DES_BS
		DES_bs_set_salt(buffer[gindex].salt);
		lindex = 0;
#if DES_bs_mt
		lindex_mod = 0;
		block_index = block_count;
#endif
#else
		DES_std_set_salt(buffer[gindex].salt);
#endif

		do {
#if DES_BS
#if DES_bs_mt
			buffer[gindex].block = block_index;
			buffer[gindex].index = lindex_mod;
			if (++lindex_mod >= DES_BS_DEPTH) {
				lindex_mod = 0;
				block_index++;
			}
#else
			buffer[gindex].block = block_count;
			buffer[gindex].index = lindex;
#endif
			l2g[lindex] = gindex;
			DES_bs_set_key(buffer[gindex].key, lindex++);
#if DES_bs_mt
			if (lindex >= DES_bs_max_kpc ||
			    buffer[gindex].next < 0) {
				int n = howmany(lindex, DES_BS_DEPTH);
				int t;
#else
			if (lindex >= DES_BS_DEPTH ||
			    buffer[gindex].next < 0) {
#endif
				int tindex;
				DES_bs_crypt_25(lindex);
				for_each_t(n) {
					blkcpy58(crypt_out[block_count++],
					    DES_bs_all.B);
					assert(block_count <=
					    worst_case_block_count);
				}
				if (next_hash_func)
				for (tindex = 0; tindex < lindex; tindex++) {
					buffer[l2g[tindex]].hash =
					    next_hash_func(tindex);
				}
				hash_func = next_hash_func;
				lindex = 0;
			}
#else
			unsigned ARCH_WORD *out;

			DES_std_set_key(buffer[gindex].key);

			DES_std_crypt(DES_KS_current,
			    out = buffer[gindex].aligned.binary);

			{
				ARCH_WORD mask;
#if ARCH_BITS < 64
				mask = (out[0] ^ out[1]) & buffer[gindex].salt;
				out[0] ^= mask;
				out[1] ^= mask;
				mask = (out[2] ^ out[3]) & buffer[gindex].salt;
				out[2] ^= mask;
				out[3] ^= mask;
#else
				mask = (out[0] ^ (out[0] >> 32)) &
				    buffer[gindex].salt;
				out[0] ^= mask ^ (mask << 32);
				mask = (out[1] ^ (out[1] >> 32)) &
				    buffer[gindex].salt;
				out[1] ^= mask ^ (mask << 32);
#endif
			}
			out[0] &= binary_mask[0];
#endif

			buffer[gindex].salt = 0xFFFFFFFF;
		} while ((gindex = buffer[gindex].next) >= 0);
	}

#if 0
	printf("%d / %d = %d\n", count, block_count, count / block_count);
#endif
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	crypt_link_by_salt(count);
	crypt_traverse_by_salt(count);
	return count;
}

#if DES_BS
static int cmp_all(void *binary, int count)
{
	int block_index;

	next_hash_func = NULL;

	for (block_index = 0; block_index < block_count; block_index++) {
		MAYBE_T0;
		blkcpy(DES_bs_all.B, crypt_out[block_index], 32);
		if (DES_bs_cmp_all(binary, DES_BS_DEPTH))
			return 1;
	}

	return 0;
}

static int cmp_one(void *binary, int index)
{
	int block = buffer[index].block;
	MAYBE_T0;
	blkcpy(DES_bs_all.B, crypt_out[block], 32);
	return DES_bs_cmp_one((ARCH_WORD_32 *)binary, 32, buffer[index].index);
}

static int cmp_exact(char *source, int index)
{
	int block = buffer[index].block;
	MAYBE_T0;
	blkcpy(DES_bs_all.B, crypt_out[block], 64);
	return DES_bs_cmp_one(get_binary(source), 64, buffer[index].index);
}
#else
static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
	if (*(unsigned ARCH_WORD *)binary == buffer[index].aligned.binary[0])
		return 1;

	return 0;
}

static int cmp_one(void *binary, int index)
{
	return *(unsigned ARCH_WORD *)binary == buffer[index].aligned.binary[0];
}

static int cmp_exact(char *source, int index)
{
	ARCH_WORD *binary;
	int word;

	binary = get_binary(source);

	for (word = 0; word < 16 / DES_SIZE; word++)
	if ((unsigned ARCH_WORD)binary[word] !=
	    (buffer[index].aligned.binary[word] & binary_mask[word]))
		return 0;

	return 1;
}
#endif

static void set_key(char *key, int index)
{
	memcpy(buffer[index].key, key, PLAINTEXT_LENGTH);
}

static char *get_key(int index)
{
	static char out[PLAINTEXT_LENGTH + 1];

	memcpy(out, buffer[index].key, PLAINTEXT_LENGTH);
	out[PLAINTEXT_LENGTH] = 0;

	return out;
}

struct fmt_main fmt_trip = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
#if DES_BS && DES_bs_mt
		FMT_OMP |
#endif
#if DES_BS
		FMT_CASE | FMT_BS,
#else
		FMT_CASE,
#endif
		tests
	}, {
		init,
		fmt_default_done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		fmt_default_salt,
		fmt_default_source,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4,
			binary_hash_5,
			binary_hash_6
		},
		fmt_default_salt_hash,
		fmt_default_set_salt,
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
