/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-99 by Solar Designer
 */

#include <stdio.h>
#include <string.h>

#include "misc.h"
#include "params.h"
#include "memory.h"
#include "signals.h"
#include "loader.h"
#include "logger.h"
#include "status.h"
#include "recovery.h"
#include "rpp.h"
#include "rules.h"
#include "external.h"
#include "cracker.h"

static int progress = 0;
static int rec_rule;

static struct db_main *single_db;
static int rule_number, rule_count;
static int length, key_count;
static struct db_keys *guessed_keys;
static struct rpp_context *rule_ctx;

static void save_state(FILE *file)
{
	fprintf(file, "%d\n", rec_rule);
}

static int restore_rule_number(void)
{
	if (rule_ctx)
	for (rule_number = 0; rule_number < rec_rule; rule_number++)
	if (!rpp_next(rule_ctx)) return 1;

	return 0;
}

static int restore_state(FILE *file)
{
	if (fscanf(file, "%d\n", &rec_rule) != 1) return 1;

	return restore_rule_number();
}

static int get_progress(void)
{
	if (progress) return progress;

	return rule_number * 100 / (rule_count + 1);
}

static void single_alloc_keys(struct db_keys **keys)
{
	int hash_size = sizeof(struct db_keys_hash) +
		sizeof(struct db_keys_hash_entry) * (key_count - 1);

	if (!*keys) {
		*keys = mem_alloc_tiny(
			sizeof(struct db_keys) - 1 + length * key_count,
			MEM_ALIGN_WORD);
		(*keys)->hash = mem_alloc_tiny(hash_size, MEM_ALIGN_WORD);
	}

	(*keys)->count = 0;
	(*keys)->ptr = (*keys)->buffer;
	(*keys)->rule = rule_number;
	(*keys)->lock = 0;
	memset((*keys)->hash, -1, hash_size);
}

static void single_init(void)
{
	struct db_salt *salt;

	progress = 0;

	length = single_db->format->params.plaintext_length;
	key_count = single_db->format->params.min_keys_per_crypt;
	if (key_count < SINGLE_HASH_MIN) key_count = SINGLE_HASH_MIN;

	if (rpp_init(rule_ctx, SUBSECTION_SINGLE)) {
		fprintf(stderr, "No \"single crack\" mode rules found in %s\n",
			cfg_name);
		error();
	}

	rules_init(length);
	rec_rule = rule_number = 0;
	rule_count = rules_count(rule_ctx, 0);

	status_init(get_progress, !status.pass);

	rec_restore_mode(restore_state);
	rec_init(single_db, save_state);

	log_event("- \"single crack\" mode");

	salt = single_db->salts;
	do {
		single_alloc_keys(&salt->keys);
	} while ((salt = salt->next));

	guessed_keys = NULL;
	single_alloc_keys(&guessed_keys);

	crk_init(single_db, NULL, guessed_keys);
}

static int single_key_hash(char *key)
{
	int pos, hash = 0;

	for (pos = 0; pos < length && *key; pos++) {
		hash <<= 1;
		hash ^= *key++;
	}

	hash ^= hash >> SINGLE_HASH_LOG;
	hash ^= hash >> (2 * SINGLE_HASH_LOG);
	hash &= SINGLE_HASH_SIZE - 1;

	return hash;
}

static int single_add_key(struct db_keys *keys, char *key)
{
	int index, hash;
	struct db_keys_hash_entry *entry;

	if ((index = keys->hash->hash[single_key_hash(key)]) >= 0)
	do {
		entry = &keys->hash->list[index];
		if (!strncmp(key, &keys->buffer[entry->offset], length))
			return 0;
	} while ((index = entry->next) >= 0);

	index = keys->hash->hash[hash = single_key_hash(keys->ptr)];
	if (index == keys->count)
		keys->hash->hash[hash] = keys->hash->list[index].next;
	else
	if (index >= 0) {
		entry = &keys->hash->list[index];
		while ((index = entry->next) >= 0) {
			if (index == keys->count) {
				entry->next = keys->hash->list[index].next;
				break;
			}
			entry = &keys->hash->list[index];
		}
	}

	index = keys->hash->hash[hash = single_key_hash(key)];
	entry = &keys->hash->list[keys->count];
	entry->next = index;
	entry->offset = keys->ptr - keys->buffer;
	keys->hash->hash[hash] = keys->count;

	strnfcpy(keys->ptr, key, length);
	keys->ptr += length;

	return ++(keys->count) >= key_count;
}

static int single_process_buffer(struct db_salt *salt)
{
	struct db_salt *current;
	struct db_keys *keys;
	size_t size;

	if (crk_process_salt(salt)) return 1;

	keys = salt->keys;
	keys->count = 0;
	keys->ptr = keys->buffer;
	keys->lock++;

	if (guessed_keys->count) {
		keys = mem_alloc(size = sizeof(struct db_keys) - 1 +
			length * guessed_keys->count);
		memcpy(keys, guessed_keys, size);

		keys->ptr = keys->buffer;
		do {
			current = single_db->salts;
			do {
				if (current == salt) continue;
				if (!current->list) continue;

				if (single_add_key(current->keys, keys->ptr))
				if (single_process_buffer(current)) return 1;
			} while ((current = current->next));
			keys->ptr += length;
		} while (--keys->count);

		mem_free((void **)&keys);
	}

	keys = salt->keys;
	keys->lock--;
	if (!keys->count && !keys->lock) keys->rule = rule_number;

	return 0;
}

static int single_process_pw(struct db_salt *salt, struct db_password *pw,
	char *rule)
{
	struct db_keys *keys;
	struct list_entry *first, *second;
	int first_number, second_number;
	char pair[RULE_WORD_SIZE];
	int split;
	char *key;
	unsigned int c;

	keys = salt->keys;

	first_number = 0;
	if ((first = pw->words->head))
	do {
		if ((key = rules_apply(first->data, rule, 0)))
		if (ext_filter(key))
		if (single_add_key(keys, key))
		if (single_process_buffer(salt)) return 1;
		if (!salt->list) return 0;

		if (++first_number > SINGLE_WORDS_PAIR_MAX) continue;

		c = (unsigned int)first->data[0] | 0x20;
		if (c < 'a' || c > 'z') continue;

		second_number = 0;
		second = pw->words->head;

		do
		if (first != second) {
			if ((split = strlen(first->data)) < length) {
				strnzcpy(pair, first->data, RULE_WORD_SIZE);
				strnzcat(pair, second->data, RULE_WORD_SIZE);

				if ((key = rules_apply(pair, rule, split)))
				if (ext_filter(key))
				if (single_add_key(keys, key))
				if (single_process_buffer(salt)) return 1;
				if (!salt->list) return 0;
			}

			if (first->data[1]) {
				pair[0] = first->data[0];
				pair[1] = 0;
				strnzcat(pair, second->data, RULE_WORD_SIZE);

				if ((key = rules_apply(pair, rule, 1)))
				if (ext_filter(key))
				if (single_add_key(keys, key))
				if (single_process_buffer(salt)) return 1;
				if (!salt->list) return 0;
			}
		} while (++second_number <= SINGLE_WORDS_PAIR_MAX &&
			(second = second->next));
	} while ((first = first->next));

	return 0;
}

static int single_process_salt(struct db_salt *salt, char *rule)
{
	struct db_keys *keys;
	struct db_password *pw;

	keys = salt->keys;

	pw = salt->list;
	do {
		if (single_process_pw(salt, pw, rule)) return 1;
		if (!salt->list) return 0;
	} while ((pw = pw->next));

	if (keys->count && rule_number - keys->rule > (key_count << 1))
		if (single_process_buffer(salt)) return 1;

	if (!keys->count) keys->rule = rule_number;

	return 0;
}

static void single_run(void)
{
	char *rule;
	struct db_salt *salt;
	int min;

	while ((rule = rpp_next(rule_ctx))) {
		if (!(rule = rules_reject(rule, single_db))) {
			rule_number++;
			continue;
		}

		min = rule_number;

		salt = single_db->salts;
		do {
			if (!salt->list) continue;
			if (single_process_salt(salt, rule)) return;
			if (salt->keys->rule < min) min = salt->keys->rule;
		} while ((salt = salt->next));

		rec_rule = min;
		rule_number++;
	}
}

static void single_done(void)
{
	struct db_salt *salt;

	if (!event_abort) {
		if ((salt = single_db->salts))
		do {
			if (!salt->list) continue;
			if (salt->keys->count)
			if (single_process_buffer(salt)) break;
		} while ((salt = salt->next));

		progress = 100;
	}

	rec_done(event_abort);
}

void do_single_crack(struct db_main *db)
{
	struct rpp_context ctx;

	single_db = db;
	rule_ctx = &ctx;
	single_init();
	single_run();
	single_done();
}
