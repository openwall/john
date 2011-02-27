/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2003,2006,2010,2011 by Solar Designer
 */

#include <string.h>

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

static int crk_process_guess(struct db_salt *salt, struct db_password *pw,
	int index)
{
	int dupe;
	char *key;

	dupe = !memcmp(&crk_timestamps[index], &status.crypts, sizeof(int64));
	crk_timestamps[index] = status.crypts;

	key = crk_methods.get_key(index);

	log_guess(crk_db->options->flags & DB_LOGIN ? pw->login : "?",
		dupe ? NULL : pw->source, key);

	crk_db->guess_count++;
	status.guess_count++;

	if (crk_guesses && !dupe) {
		strnfcpy(crk_guesses->ptr, key, crk_params.plaintext_length);
		crk_guesses->ptr += crk_params.plaintext_length;
		crk_guesses->count++;
	}

	ldr_remove_hash(crk_db, salt, pw);

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

	status_update_crypts(salt->count * crk_key_index);

	if (salt->hash_size < 0) {
		pw = salt->list;
		do {
			if (crk_methods.cmp_all(pw->binary, crk_key_index))
			for (index = 0; index < crk_key_index; index++)
			if (crk_methods.cmp_one(pw->binary, index))
			if (crk_methods.cmp_exact(pw->source, index)) {
				if (crk_process_guess(salt, pw, index))
					return 1;
				else
					break;
			}
		} while ((pw = pw->next));
	} else
	for (index = 0; index < crk_key_index; index++) {
		if ((pw = salt->hash[salt->index(index)]))
		do {
			if (crk_methods.cmp_one(pw->binary, index))
			if (crk_methods.cmp_exact(pw->source, index))
			if (crk_process_guess(salt, pw, index))
				return 1;
		} while ((pw = pw->next_hash));
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

	return 0;
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

	status_update_crypts(1);
	crk_fix_state();

	return 0;
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
