/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2003,2006,2010-2012 by Solar Designer
 *
 * ...with a change in the jumbo patch, by JimF
 */

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
#include "options.h"
#include "unicode.h"

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

void crk_init(struct db_main *db, void (*fix_state)(void),
	struct db_keys *guesses)
{
	char *where;
	size_t size;

	if (db->loaded)
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
void crk_remove_hash(struct db_salt *salt, struct db_password *pw)
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
	UTF8 utf8buf_key[PLAINTEXT_BUFFER_SIZE + 1];
	UTF8 utf8login[PLAINTEXT_BUFFER_SIZE + 1];
	char tmp8[PLAINTEXT_BUFFER_SIZE + 1];
	int dupe;
	char *key, *utf8key, *repkey, *replogin;

	dupe = !memcmp(&crk_timestamps[index], &status.crypts, sizeof(int64));
	crk_timestamps[index] = status.crypts;

	repkey = key = crk_methods.get_key(index);
	replogin = pw->login;

	if (options.store_utf8 || options.report_utf8) {
		if (options.utf8)
			utf8key = key;
		else {
			utf8key = (char*)enc_to_utf8_r(key, utf8buf_key, PLAINTEXT_BUFFER_SIZE);
			// Double-check that the conversion was correct. Our
			// fallback is to log, warn and use the original key instead.
			utf8_to_enc_r((UTF8*)utf8key, tmp8, PLAINTEXT_BUFFER_SIZE);
			if (strcmp(tmp8, key)) {
				fprintf(stderr, "Warning, conversion failed %s -> %s -> %s - fallback to codepage\n", key, utf8key, tmp8);
				log_event("Warning, conversion failed %s -> %s -> %s - fallback to codepage", key, utf8key, tmp8);
				utf8key = key;
			}
		}
		if (options.report_utf8) {
			repkey = utf8key;
			if (crk_db->options->flags & DB_LOGIN)
				replogin = (char*)enc_to_utf8_r(pw->login, utf8login, PLAINTEXT_BUFFER_SIZE);
		}
		if (options.store_utf8)
			key = utf8key;
	}

	// Ok, FIX the salt  ONLY if -regen-lost-salts=X was used.
	if (options.regen_lost_salts) {
		if (options.regen_lost_salts == 1)
		{
			// 3 byte PHPS salt, the hash is in $dynamic_6$ format.
			char *cp = pw->source;
			char *cp2 = *(char**)(salt->salt);
			memcpy(cp+11+32+1, cp2+6, 3);
		}
		else if (options.regen_lost_salts == 2)
		{
			// 2 byte osCommerce salt, the hash is in $dynamic_4$ format.
			char *cp = pw->source;
			char *cp2 = *(char**)(salt->salt);
			memcpy(cp+11+32+1, cp2+6, 2);
		}
		else if (options.regen_lost_salts >= 3 && options.regen_lost_salts <= 5)
		{
			// Media wiki.  Salt len is not known, but 5 bytes or less, and WILL fit into pw-source even after being fixed.. $dynamic_9$ format.
			char Buf[256];
			char *cp2 = *(char**)(salt->salt);
			extern void mediawiki_fix_salt(char *Buf, char *source_to_fix, char *salt_rec, int max_salt_len);
			mediawiki_fix_salt(Buf, pw->source, cp2, options.regen_lost_salts+1);
			strcpy(pw->source, Buf);
		}
	}
	log_guess(crk_db->options->flags & DB_LOGIN ? replogin : "?",
		dupe ? NULL : pw->source, repkey, key, crk_db->options->field_sep_char);

	if (options.flags & FLG_CRKSTAT)
		event_pending = event_status = 1;

	crk_db->guess_count++;
	status.guess_count++;

	if (crk_guesses && !dupe) {
		strnfcpy(crk_guesses->ptr, key, crk_params.plaintext_length);
		crk_guesses->ptr += crk_params.plaintext_length;
		crk_guesses->count++;
	}

	if (!(crk_params.flags & FMT_NOT_EXACT))
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
	int index;

#if !OS_TIMER
	sig_timer_emu_tick();
#endif

	idle_yield();

	if (event_pending)
	if (crk_process_event()) return 1;

	crk_methods.crypt_all(crk_key_index);

	{
		int64 effective_count;
		mul32by32(&effective_count, salt->count, crk_key_index);
		status_update_crypts(&effective_count);
	}

	if (!salt->bitmap) {
		pw = salt->list;
		do {
			if (crk_methods.cmp_all(pw->binary, crk_key_index))
			for (index = 0; index < crk_key_index; index++)
			if (crk_methods.cmp_one(pw->binary, index))
			if (crk_methods.cmp_exact(pw->source, index)) {
				if (crk_process_guess(salt, pw, index))
					return 1;
				else {
					if (!(crk_params.flags & FMT_NOT_EXACT))
						break;
				}
			}
		} while ((pw = pw->next));
	} else
	for (index = 0; index < crk_key_index; index++) {
		int hash = salt->index(index);
		if (salt->bitmap[hash / (sizeof(*salt->bitmap) * 8)] &
		    (1U << (hash % (sizeof(*salt->bitmap) * 8)))) {
			pw = salt->hash[hash >> PASSWORD_HASH_SHR];
			do {
				if (crk_methods.cmp_one(pw->binary, index))
				if (crk_methods.cmp_exact(pw->source, index))
				if (crk_process_guess(salt, pw, index))
					return 1;
			} while ((pw = pw->next_hash));
		}
	}

	return 0;
}

static int crk_salt_loop(void)
{
	struct db_salt *salt;

	salt = crk_db->salts;
	do {
		crk_methods.set_salt(salt->salt);
		if (crk_password_loop(salt)) return 1;
	} while ((salt = salt->next));

	crk_last_key = crk_key_index; crk_key_index = 0;
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

	{
		int64 one = {1, 0};
		status_update_crypts(&one);
	}

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

int crk_process_salt(struct db_salt *salt)
{
	char *ptr;
	char key[PLAINTEXT_BUFFER_SIZE];
	int count, index;

	if (crk_guesses) {
		crk_guesses->count = 0;
		crk_guesses->ptr = crk_guesses->buffer;
	}

	if (crk_last_salt != salt->salt)
		crk_methods.set_salt(crk_last_salt = salt->salt);

	ptr = salt->keys->buffer;
	count = salt->keys->count;
	index = 0;

	crk_methods.clear_keys();

	while (count--) {
		strnzcpy(key, ptr, crk_params.plaintext_length + 1);
		ptr += crk_params.plaintext_length;

		crk_methods.set_key(key, index++);
		if (index >= crk_params.max_keys_per_crypt || !count) {
			crk_key_index = index;
			if (crk_password_loop(salt)) return 1;
			if (!salt->list) return 0;
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
	if (crk_key_index > 1)
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
