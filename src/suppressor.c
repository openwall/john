/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2022 by Solar Designer
 */

#include <stdint.h>

#include "common.h"
#include "memory.h"
#include "cracker.h"
#include "suppressor.h"

#define N 0x400000
#define K 8

static uint64_t (*filter)[K];

static enum {
	MODE_NONE = 0,
	MODE_UPDATING,
	MODE_CHECKING
} mode;

static int (*old_process_key)(char *key);

static int suppressor_process_key(char *key);

void suppressor_init(int update)
{
	if (mode == MODE_NONE) {
		if (!update)
			return;
		filter = mem_calloc_align(N, sizeof(*filter), MEM_ALIGN_CACHE);
	}
	mode = update ? MODE_UPDATING : MODE_CHECKING;
	old_process_key = crk_process_key;
	crk_process_key = suppressor_process_key;
}

/*
 * Generate two hashes from a candidate password:
 * 1. A nearly uniformly distributed 32-bit hash (the return value).
 * 2. A 64-bit password "hash" that is basically the password for lengths up
 * up to 8 inclusive, and a value that is guaranteed not to collide with any
 * short pure 7-bit ASCII password for greater lengths.
 */
static MAYBE_INLINE uint32_t key_hash(const char *key, uint64_t *hash2)
{
	const unsigned char *p = (const unsigned char *)key;
	unsigned char *q = (unsigned char *)hash2;
	uint32_t hash1, extra;

	*hash2 = 1;
	hash1 = extra = 0;

	while (*p) {
		if (q >= (unsigned char *)hash2 + 8) {
			q = (unsigned char *)hash2;
			*hash2 += ((uint64_t)hash1 << 32) | extra;
		}
		q[0] ^= p[0];
		hash1 += p[0];
		hash1 *= 0x5a827999;
		if (!p[1])
			break;
		q[1] ^= p[1];
		extra += p[1];
		extra *= 0x6ed9eba1;
		p += 2; q += 2;
	}

	if (p - (const unsigned char *)key + !!*p > 8) /* different hash than for any short 7-bit */
		*(unsigned char *)hash2 |= 0x80;

	hash1 ^= extra;

	return hash1;
}

static int suppressor_process_key(char *key)
{
	uint64_t hash;
	unsigned int i, j;

	i = ((uint64_t)key_hash(key, &hash) * N) >> 32;

	/* lookup */
	for (j = 0; j < K && filter[i][j]; j++) {
		if (filter[i][j] == hash) {
			if (j < K - 1 && filter[i][j + 1] && mode == MODE_UPDATING) { /* postpone eviction of this hash */
				filter[i][j] = filter[i][j + 1];
				filter[i][j + 1] = hash;
			}
			return 0;
		}
	}

	if (mode == MODE_UPDATING) {
		/* insert */
		if (j == K) { /* on full bucket, evict a hash */
			for (j = 0; j < K - 1; j++)
				filter[i][j] = filter[i][j + 1];
		}
		filter[i][j] = hash;
	}

	return old_process_key(key);
}
