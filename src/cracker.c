/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2003,2006,2010-2013,2015,2017 by Solar Designer
 */

#define NEED_OS_TIMER
#include "os.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "arch.h"
#include "params.h"

#if CRK_PREFETCH && defined(__SSE__)
#include <xmmintrin.h>
#endif

#include "misc.h"
#include "memory.h"
#include "signals.h"
#include "idle.h"
#include "formats.h"
#include "loader.h"
#include "logger.h"
#include "status.h"
#include "recovery.h"
#include "external.h"
#include "john.h"

#ifdef index
#undef index
#endif

static struct db_main *crk_db;
static struct fmt_params crk_params;
static struct fmt_methods crk_methods;
#if CRK_PREFETCH
#if 1
static unsigned int crk_prefetch;
#else
#define crk_prefetch CRK_PREFETCH
#endif
#endif
static int crk_key_index, crk_last_key;
static void *crk_last_salt;
static void (*crk_fix_state)(void);
static struct db_keys *crk_guesses;
static uint64_t *crk_timestamps;
static char crk_stdout_key[PLAINTEXT_BUFFER_SIZE];

static void crk_dummy_set_salt(void *salt)
{
}

static void crk_dummy_fix_state(void)
{
}

static void crk_init_salt(void)
{
	if (!crk_db->salts->next) {
		crk_methods.set_salt(crk_db->salts->salt);
		crk_methods.set_salt = crk_dummy_set_salt;
	}
}

static void crk_help(void)
{
	static int printed = 0;
	if (!john_main_process || printed)
		return;
	fprintf(stderr, "Press 'q' or Ctrl-C to abort, "
	    "almost any other key for status\n");
	printed = 1;
}

void crk_init(struct db_main *db, void (*fix_state)(void),
	struct db_keys *guesses)
{
	char *where;
	size_t size;

/*
 * We should have already called fmt_self_test() from john.c.  This redundant
 * self-test is only to catch some more obscure bugs in debugging builds (it
 * is a no-op in normal builds).  Additionally, we skip it even in debugging
 * builds if we're running in --stdout mode (there's no format involved then)
 * or if the format has a custom reset() method (we've already called reset(db)
 * from john.c, and we don't want to mess with the format's state).
 */
	if (db->loaded && db->format->methods.reset == fmt_default_reset)
	if ((where = fmt_self_test(db->format))) {
		log_event("! Self test failed (%s)", where);
		fprintf(stderr, "Self test failed (%s)\n", where);
		error();
	}

	crk_db = db;
	memcpy(&crk_params, &db->format->params, sizeof(struct fmt_params));
	memcpy(&crk_methods, &db->format->methods, sizeof(struct fmt_methods));

#if CRK_PREFETCH && !defined(crk_prefetch)
	{
		unsigned int m = crk_params.max_keys_per_crypt;
		if (m > CRK_PREFETCH) {
			unsigned int n = (m + CRK_PREFETCH - 1) / CRK_PREFETCH;
			crk_prefetch = (m + n - 1) / n;
			/* CRK_PREFETCH / 2 < crk_prefetch <= CRK_PREFETCH */
		} else {
/* Actual prefetch will be capped to crypt_all() return value anyway, so let's
 * not cap it to max_keys_per_crypt here in case crypt_all() generates more
 * candidates on its own. */
			crk_prefetch = CRK_PREFETCH;
		}
	}
#endif

	if (db->loaded) crk_init_salt();
	crk_last_key = crk_key_index = 0;
	crk_last_salt = NULL;

	if (fix_state)
		(crk_fix_state = fix_state)();
	else
		crk_fix_state = crk_dummy_fix_state;

	crk_guesses = guesses;

	if (db->loaded) {
		size = crk_params.max_keys_per_crypt * sizeof(uint64_t);
		memset(crk_timestamps = mem_alloc(size), -1, size);
	} else
		crk_stdout_key[0] = 0;

	rec_save();

	crk_help();

	idle_init(db->format);
}

/*
 * crk_remove_salt() is called by crk_remove_hash() when it happens to remove
 * the last password hash for a salt.
 */
static void crk_remove_salt(struct db_salt *salt)
{
	struct db_salt **current;

	crk_db->salt_count--;

	current = &crk_db->salts;
	while (*current != salt)
		current = &(*current)->next;
	*current = salt->next;
}

/*
 * Updates the database after a password has been cracked.
 */
static void crk_remove_hash(struct db_salt *salt, struct db_password *pw)
{
	struct db_password **start, **current;
	int hash, count;

	crk_db->password_count--;

	if (!--salt->count) {
		salt->list = NULL; /* "single crack" mode might care */
		crk_remove_salt(salt);
		return;
	}

/*
 * If there's no bitmap for this salt, assume that next_hash fields are unused
 * and don't need to be updated.  Only bother with the list.
 */
	if (!salt->bitmap) {
		current = &salt->list;
		while (*current != pw)
			current = &(*current)->next;
		*current = pw->next;
		pw->binary = NULL;
		return;
	}

	hash = crk_db->format->methods.binary_hash[salt->hash_size](pw->binary);
	count = 0;
	start = current = &salt->hash[hash >> PASSWORD_HASH_SHR];
	do {
		if (crk_db->format->methods.binary_hash[salt->hash_size]
		    ((*current)->binary) == hash)
			count++;
		if (*current == pw) {
/*
 * If we can, skip the write to hash table to avoid unnecessary page
 * copy-on-write when running with "--fork".  We can do this when we're about
 * to remove this entry from the bitmap, which we'd be checking first.
 */
			if (count == 1 && current == start && !pw->next_hash)
				break;
			*current = pw->next_hash;
		} else {
			current = &(*current)->next_hash;
		}
	} while (*current);

	assert(count >= 1);

/*
 * If we have removed the last entry with the exact hash value from this hash
 * bucket (which could also contain entries with nearby hash values in case
 * PASSWORD_HASH_SHR is non-zero), we must also reset the corresponding bit.
 */
	if (count == 1)
		salt->bitmap[hash / (sizeof(*salt->bitmap) * 8)] &=
		    ~(1U << (hash % (sizeof(*salt->bitmap) * 8)));

/*
 * If there's a hash table for this salt, assume that the list is only used by
 * "single crack" mode, so mark the entry for removal by "single crack" mode
 * code if that's what we're running, instead of traversing the list here.
 */
	if (crk_guesses)
		pw->binary = NULL;
}

static int crk_process_guess(struct db_salt *salt, struct db_password *pw,
	int index)
{
	int dupe;
	char *key;

	dupe = crk_timestamps[index] == status.crypts;
	crk_timestamps[index] = status.crypts;

	key = crk_methods.get_key(index);

	log_guess(crk_db->options->flags & DB_LOGIN ? pw->login : "?",
	    dupe ? NULL :
	    crk_methods.source(pw->source, pw->binary), key);

	crk_db->guess_count++;
	status.guess_count++;

	if (crk_guesses && !dupe) {
		strnfcpy(crk_guesses->ptr, key, crk_params.plaintext_length);
		crk_guesses->ptr += crk_params.plaintext_length;
		crk_guesses->count++;
	}

	crk_remove_hash(salt, pw);

	if (!crk_db->salts)
		return 1;

	crk_init_salt();

	return 0;
}

static int crk_process_event(void)
{
	event_pending = 0;

	if (event_save) {
		event_save = 0;
		rec_save();
	}

	if (event_status) {
		event_status = 0;
		status_print();
	}

	if (event_ticksafety) {
		event_ticksafety = 0;
		status_ticks_overflow_safety();
	}

	return event_abort;
}

static int crk_password_loop(struct db_salt *salt)
{
	int count;
	unsigned int match, index;
#if CRK_PREFETCH
	unsigned int target;
#endif

#if !OS_TIMER
	sig_timer_emu_tick();
#endif

	idle_yield();

	if (event_pending && crk_process_event())
		return -1;

	count = crk_key_index;
	match = crk_methods.crypt_all(&count, salt);
	crk_last_key = count;

	status_update_crypts((uint64_t)salt->count * count, count);

	if (!match)
		return 0;

	if (!salt->bitmap) {
		struct db_password *pw = salt->list;
		do {
			if (crk_methods.cmp_all(pw->binary, match))
			for (index = 0; index < match; index++)
			if (crk_methods.cmp_one(pw->binary, index))
			if (crk_methods.cmp_exact(crk_methods.source(
			    pw->source, pw->binary), index)) {
				if (crk_process_guess(salt, pw, index))
					return 1;
				else
					break;
			}
		} while ((pw = pw->next));

		return 0;
	}

#if CRK_PREFETCH
	for (index = 0; index < match; index = target) {
		unsigned int slot, ahead, lucky;
		struct {
			unsigned int i;
			union {
				unsigned int *b;
				struct db_password **p;
			} u;
		} a[CRK_PREFETCH];
		target = index + crk_prefetch;
		if (target > match)
			target = match;
		for (slot = 0, ahead = index; ahead < target; slot++, ahead++) {
			unsigned int h = salt->index(ahead);
			unsigned int *b = &salt->bitmap[h / (sizeof(*salt->bitmap) * 8)];
			a[slot].i = h;
			a[slot].u.b = b;
#ifdef __SSE__
			_mm_prefetch((const char *)b, _MM_HINT_NTA);
#else
			*(volatile unsigned int *)b;
#endif
		}
		lucky = 0;
		for (slot = 0, ahead = index; ahead < target; slot++, ahead++) {
			unsigned int h = a[slot].i;
			if (*a[slot].u.b & (1U << (h % (sizeof(*salt->bitmap) * 8)))) {
				struct db_password **pwp = &salt->hash[h >> PASSWORD_HASH_SHR];
#ifdef __SSE__
				_mm_prefetch((const char *)pwp, _MM_HINT_NTA);
#else
				*(void * volatile *)pwp;
#endif
				a[lucky].i = ahead;
				a[lucky++].u.p = pwp;
			}
		}
#if 1
		if (!lucky)
			continue;
		for (slot = 0; slot < lucky; slot++) {
			struct db_password *pw = *a[slot].u.p;
/*
 * Chances are this will also prefetch the next_hash field and the actual
 * binary (pointed to by the binary field, but likely located right after
 * this struct).
 */
#ifdef __SSE__
			_mm_prefetch((const char *)&pw->binary, _MM_HINT_NTA);
#else
			*(void * volatile *)&pw->binary;
#endif
		}
#endif
		for (slot = 0; slot < lucky; slot++) {
			struct db_password *pw = *a[slot].u.p;
			index = a[slot].i;
			do {
				if (crk_methods.cmp_one(pw->binary, index))
				if (crk_methods.cmp_exact(crk_methods.source(
				    pw->source, pw->binary), index)) {
					if (crk_process_guess(salt, pw, index))
						return 1;
/* After we've successfully cracked and removed a hash, our prefetched bitmap
 * and hash table entries might be stale: some might correspond to the same
 * hash bucket, yet with this removed hash still in there if it was the first
 * one in the bucket.  If so, re-prefetch from the next lucky index if any,
 * yet complete handling of this index first. */
					if (slot + 1 < lucky) {
						struct db_password *first =
						    salt->hash[
						    salt->index(index) >>
						    PASSWORD_HASH_SHR];
						if (pw == first || !first) {
							target = a[slot + 1].i;
							lucky = 0;
						}
					}
				}
			} while ((pw = pw->next_hash));
		}
	}
#else
	for (index = 0; index < match; index++) {
		unsigned int hash = salt->index(index);
		if (salt->bitmap[hash / (sizeof(*salt->bitmap) * 8)] &
		    (1U << (hash % (sizeof(*salt->bitmap) * 8)))) {
			struct db_password *pw =
			    salt->hash[hash >> PASSWORD_HASH_SHR];
			do {
				if (crk_methods.cmp_one(pw->binary, index))
				if (crk_methods.cmp_exact(crk_methods.source(
				    pw->source, pw->binary), index))
				if (crk_process_guess(salt, pw, index))
					return 1;
			} while ((pw = pw->next_hash));
		}
	}
#endif

	return 0;
}

static int crk_salt_loop(void)
{
	int done;
	struct db_salt *salt;

	salt = crk_db->salts;
	do {
		crk_methods.set_salt(salt->salt);
		if ((done = crk_password_loop(salt)))
			break;
	} while ((salt = salt->next));

	if (done >= 0)
		status.cands += crk_key_index;

	if (salt)
		return 1;

	crk_key_index = 0;
	crk_last_salt = NULL;
	crk_fix_state();

	crk_methods.clear_keys();

	if (ext_abort)
		event_abort = 1;

	if (ext_status && !event_abort) {
		ext_status = 0;
		event_status = 0;
		status_print();
	}

	return ext_abort;
}

int crk_process_key(char *key)
{
	if (crk_db->loaded) {
		crk_methods.set_key(key, crk_key_index++);

		if (crk_key_index >= crk_params.max_keys_per_crypt)
			return crk_salt_loop();

		return 0;
	}

#if !OS_TIMER
	sig_timer_emu_tick();
#endif

	if (event_pending)
	if (crk_process_event()) return 1;

	puts(strnzcpy(crk_stdout_key, key, crk_params.plaintext_length + 1));

	status_update_cands(1);

	crk_fix_state();

	if (ext_abort)
		event_abort = 1;

	if (ext_status && !event_abort) {
		ext_status = 0;
		event_status = 0;
		status_print();
	}

	return ext_abort;
}

/* This function is used by single.c only */
int crk_process_salt(struct db_salt *salt)
{
	char *ptr;
	char key[PLAINTEXT_BUFFER_SIZE];
	int count, count_from_guesses, index;

	if (crk_guesses) {
		crk_guesses->count = 0;
		crk_guesses->ptr = crk_guesses->buffer;
	}

	if (crk_last_salt != salt->salt)
		crk_methods.set_salt(crk_last_salt = salt->salt);

	ptr = salt->keys->buffer;
	count = salt->keys->count;
	count_from_guesses = salt->keys->count_from_guesses;
	index = 0;

	crk_methods.clear_keys();

	while (count--) {
		strnzcpy(key, ptr, crk_params.plaintext_length + 1);
		ptr += crk_params.plaintext_length;

		crk_methods.set_key(key, index++);
		if (index >= crk_params.max_keys_per_crypt || !count) {
			int done;
			crk_key_index = index;
			if ((done = crk_password_loop(salt)) >= 0) {
/*
 * The approach we use here results in status.cands growing slower than it
 * ideally should until this loop completes (at which point status.cands has
 * the correct value).  If cracking is interrupted (and then possibly
 * restored), status.cands may be left with a value lower than it should have.
 * An alternative would have been storing per-candidate flags indicating where
 * each candidate came from, but it'd cost.
 */
				int not_from_guesses =
				    index - count_from_guesses;
				if (not_from_guesses > 0) {
					status.cands += not_from_guesses;
					count_from_guesses = 0;
				} else {
					count_from_guesses -= index;
				}
			}
			if (done)
				return 1;
			if (!salt->list)
				return 0;
			index = 0;
		}
	}

	return 0;
}

char *crk_get_key1(void)
{
	if (crk_db->loaded)
		return crk_methods.get_key(0);
	else
		return crk_stdout_key;
}

char *crk_get_key2(void)
{
	if (crk_key_index > 1 && crk_key_index < crk_last_key)
		return crk_methods.get_key(crk_key_index - 1);
	else
	if (crk_last_key > 1)
		return crk_methods.get_key(crk_last_key - 1);
	else
		return NULL;
}

void crk_done(void)
{
	if (crk_db->loaded) {
		if (crk_key_index && crk_db->salts && !event_abort)
			crk_salt_loop();

		MEM_FREE(crk_timestamps);
	}
}
