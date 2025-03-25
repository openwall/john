/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2022,2025 by Solar Designer
 */

#include <stdint.h>
#ifdef __unix__
#include <sys/mman.h>
#endif

#include "common.h"
#include "memory.h"
#include "john.h"
#include "cracker.h"
#include "logger.h"
#include "options.h"
#include "status.h"
#include "suppressor.h"

#define DEFAULT_SIZE 256 /* MiB */
#define K 8

static uint32_t N, Klock;
static region_t memory;
static uint64_t (*filter)[K];
static unsigned int flags;

static int (*old_process_key)(char *key);

static int suppressor_process_key(char *key);

void suppressor_init(unsigned int new_flags)
{
	if (flags & SUPPRESSOR_OFF)
		return;

	if (!flags) {
		if (!(new_flags & SUPPRESSOR_UPDATE))
			return;

		int size = options.suppressor_size;
		if (size < 0)
			size = cfg_get_int(SECTION_OPTIONS, ":Suppressor", "Size");
		if (size <= 0) {
			if (size < 0 || (new_flags & SUPPRESSOR_FORCE))
				size = DEFAULT_SIZE;
			else
				return;
		}

		for (;; size = DEFAULT_SIZE) {
			N = ((uint64_t)size << 20) / sizeof(*filter);
			if ((size_t)((uint64_t)N * sizeof(*filter)) == (uint64_t)size << 20)
				break;
		}

		Klock = 0;
		if (cfg_get_bool(SECTION_OPTIONS, ":Suppressor", "LockHalf", 1))
			Klock = K / 2;

		if (john_main_process) {
			const char *msg = "Enabling duplicate candidate password suppressor using ";
			const char *suffix = options.fork ? " per process" : "";
			log_event("%s%d MiB%s", msg, size, suffix);
			fprintf(stderr, "%s%d MiB%s\n", msg, size, suffix);
		}

		init_region(&memory);
		filter = alloc_region(&memory, (size_t)size << 20);
		if (!filter) {
			const char *msg = "Failed to allocate memory for duplicate candidate password suppressor";
			log_event("%s", msg);
			if (NODES > 1)
				fprintf(stderr, "%d: %s\n", NODE, msg);
			else
				fprintf(stderr, "%s\n", msg);
			return;
		}

/*
 * alloc_region() uses mmap() when MAP_ANON is available, so we only have to
 * perform our own zeroization otherwise.
 */
#ifndef MAP_ANON
		memset(filter, 0, (size_t)size << 20);
#endif

		status.suppressor_start = status.cands + 1;
		status.suppressor_start_time = status_get_time();
	}

	flags = new_flags;
	status.suppressor_end = 0;
	status.suppressor_end_time = 0;
	if (crk_process_key != suppressor_process_key) {
		old_process_key = crk_process_key;
		crk_process_key = suppressor_process_key;
	}
}

static void suppressor_done(void)
{
	const char *msg = "Disabling duplicate candidate password suppressor";
	log_event("%s (accepted %llu, rejected %llu)", msg, status.suppressor_miss, status.suppressor_hit);
	if (NODES > 1)
		fprintf(stderr, "%d: %s\n", NODE, msg);
	else
		fprintf(stderr, "%s\n", msg);

	free_region(&memory);

	flags = SUPPRESSOR_OFF;
	status.suppressor_end = status.cands;
	status.suppressor_end_time = status_get_time();
	crk_process_key = old_process_key;
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
		((unsigned char *)hash2)[7] |= 0x80;

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
			if (j >= Klock && j < K - 1 && filter[i][j + 1] && (flags & SUPPRESSOR_UPDATE)) {
				filter[i][j] = filter[i][j + 1];
				filter[i][j + 1] = hash; /* postpone eviction of this hash */
			}
			status.suppressor_hit++;
			return 0;
		}
	}

	if ((flags & SUPPRESSOR_UPDATE)) {
		/* insert */
		if (j == K) { /* on full bucket, evict a hash */
			for (j = Klock; j < K - 1; j++)
				filter[i][j] = filter[i][j + 1];
		}
		filter[i][j] = hash;
	}

	if (!(++status.suppressor_miss & 0x1ffffff) && !(flags & SUPPRESSOR_FORCE)) {
		double ps_rate_threshold = 5000000.0 * status.suppressor_hit / (status.suppressor_hit + status.suppressor_miss);
		static unsigned long long misses_at_non_update;
		if (!(flags & SUPPRESSOR_UPDATE)) {
			if (misses_at_non_update)
				ps_rate_threshold /= 1 + ((status.suppressor_miss - misses_at_non_update) / ((double)N * K));
			else
				misses_at_non_update = status.suppressor_miss;
		}
		if (ps_rate_threshold > 1000000)
			ps_rate_threshold = 1000000;
		unsigned int time = status_get_time() - status.suppressor_start_time;
		if (time > 9 && (status.suppressor_miss / time > ps_rate_threshold ||
		    (status.suppressor_hit + status.suppressor_miss) / time > 2000000))
			suppressor_done();
	}

	return old_process_key(key);
}
