/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2003,2006,2010-2013 by Solar Designer
 */

#define NEED_OS_TIMER
#include "os.h"

#include <string.h>
#include <assert.h>

#include "arch.h"
#include "misc.h"
#include "math.h"
#include "params.h"
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
static int crk_key_index, crk_last_key;
static void *crk_last_salt;
static void (*crk_fix_state)(void);
static struct db_keys *crk_guesses;
static int64 *crk_timestamps;
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

	if (db->loaded) crk_init_salt();
	crk_last_key = crk_key_index = 0;
	crk_last_salt = NULL;

	if (fix_state)
		(crk_fix_state = fix_state)();
	else
		crk_fix_state = crk_dummy_fix_state;

	crk_guesses = guesses;

	if (db->loaded) {
		size = crk_params.max_keys_per_crypt * sizeof(int64);
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
	struct db_password **current;
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
	current = &salt->hash[hash >> PASSWORD_HASH_SHR];
	do {
		if (crk_db->format->methods.binary_hash[salt->hash_size]
		    ((*current)->binary) == hash)
			count++;
		if (*current == pw)
			*current = pw->next_hash;
		else
			current = &(*current)->next_hash;
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
 * code in case that's what we're running, instead of traversing the list here.
 */
	pw->binary = NULL;
}

static int crk_process_guess(struct db_salt *salt, struct db_password *pw,
	int index)
{
	int dupe;
	char *key;

	dupe = !memcmp(&crk_timestamps[index], &status.crypts, sizeof(int64));
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
	struct db_password *pw;
	int count, match, index;

#if !OS_TIMER
	sig_timer_emu_tick();
#endif

	idle_yield();

	if (event_pending && crk_process_event())
		return -1;

	count = crk_key_index;
	match = crk_methods.crypt_all(&count, salt);
	crk_last_key = count;

	{
		int64 effective_count;
		mul32by32(&effective_count, salt->count, count);
		status_update_crypts(&effective_count, count);
	}

	if (!match)
		return 0;

	if (!salt->bitmap) {
		pw = salt->list;
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
	} else
	for (index = 0; index < match; index++) {
		int hash = salt->index(index);
		if (salt->bitmap[hash / (sizeof(*salt->bitmap) * 8)] &
		    (1U << (hash % (sizeof(*salt->bitmap) * 8)))) {
			pw = salt->hash[hash >> PASSWORD_HASH_SHR];
			do {
				if (crk_methods.cmp_one(pw->binary, index))
				if (crk_methods.cmp_exact(crk_methods.source(
				    pw->source, pw->binary), index))
				if (crk_process_guess(salt, pw, index))
					return 1;
			} while ((pw = pw->next_hash));
		}
	}

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
		add32to64(&status.cands, crk_key_index);

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
					add32to64(&status.cands,
					    not_from_guesses);
					count_from_guesses = 0;
				} else
					count_from_guesses -= index;
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
