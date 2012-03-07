/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-99,2003,2004,2006,2010,2012 by Solar Designer
 *
 * ...with changes in the jumbo patch, by JimF.
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
#ifdef HAVE_MPI
#include "john-mpi.h"
#endif
#include "unicode.h"

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

static int get_progress(int *hundth)
{
	if (progress) {
		if (hundth)
			*hundth = 0;
		return progress;
	}

	if (hundth)
		*hundth = (rule_number * 10000 / (rule_count + 1)) % 100;
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
	(*keys)->have_words = 1; /* assume yes; we'll see for real later */
	(*keys)->rule = rule_number;
	(*keys)->lock = 0;
	memset((*keys)->hash, -1, hash_size);
}

static void single_init(void)
{
	struct db_salt *salt;

	log_event("Proceeding with \"single crack\" mode");

	progress = 0;

	length = single_db->format->params.plaintext_length;
	key_count = single_db->format->params.min_keys_per_crypt;
	if (key_count < SINGLE_HASH_MIN)
		key_count = SINGLE_HASH_MIN;
/*
 * We use "short" for buffered key indices and "unsigned short" for buffered
 * key offsets - make sure these don't overflow.
 */
	if (key_count > 0x8000)
		key_count = 0x8000;
	while (key_count > 0xffff / length + 1)
		key_count >>= 1;

	if (rpp_init(rule_ctx, single_db->options->activesinglerules)) {
		log_event("! No \"single crack\" mode rules found");
		fprintf(stderr, "No \"single crack\" mode rules found in %s\n",
			cfg_name);
		error();
	}

	rules_init(length);
	rec_rule = rule_number = 0;
	rule_count = rules_count(rule_ctx, 0);

	log_event("- %d preprocessed word mangling rules", rule_count);

#ifdef HAVE_MPI
	if (mpi_p > 1) {
		log_event("MPI hack active: processsing 1/%d of rules, total %d for "
		    "this node", mpi_p, (rule_count / mpi_p) +
		    (rule_count % mpi_p > mpi_id ? 1 : 0));
		if (mpi_id == 0) fprintf(stderr,"MPI: each node processing 1/%d of %d "
		    "rules. (%seven split)\n",
		    mpi_p, rule_count, rule_count % mpi_p ? "un" : "");
	}
#endif
	status_init(get_progress, 0);

	rec_restore_mode(restore_state);
	rec_init(single_db, save_state);

	salt = single_db->salts;
	do {
		single_alloc_keys(&salt->keys);
	} while ((salt = salt->next));

	if (key_count > 1)
	log_event("- Allocated %d buffer%s of %d candidate passwords%s",
		single_db->salt_count,
		single_db->salt_count != 1 ? "s" : "",
		key_count,
		single_db->salt_count != 1 ? " each" : "");

	guessed_keys = NULL;
	single_alloc_keys(&guessed_keys);

	crk_init(single_db, NULL, guessed_keys);
}

static int single_key_hash(char *key)
{
	unsigned int hash, extra, pos;

	hash = (unsigned char)key[0];
	if (!hash)
		goto out;
	extra = (unsigned char)key[1];
	if (!extra)
		goto out_and;

	pos = 3;
	if (length & 1) {
		while (key[2]) {
			hash += (unsigned char)key[2];
			if (!key[3] || pos >= length) break;
			extra += (unsigned char)key[3];
			key += 2;
			pos += 2;
		}
	} else {
		while (key[2] && pos < length) {
			hash += (unsigned char)key[2];
			if (!key[3]) break;
			extra += (unsigned char)key[3];
			key += 2;
			pos += 2;
		}
	}

	hash -= extra + pos;
#if SINGLE_HASH_LOG > 6
	hash ^= extra << 6;
#endif

out_and:
	hash &= SINGLE_HASH_SIZE - 1;
out:
	return hash;
}

static int single_add_key(struct db_keys *keys, char *key)
{
	int index, new_hash, reuse_hash;
	struct db_keys_hash_entry *entry;

/* Check if this is a known duplicate, and reject it if so */
	if ((index = keys->hash->hash[new_hash = single_key_hash(key)]) >= 0)
	do {
		entry = &keys->hash->list[index];
		if (!strncmp(key, &keys->buffer[entry->offset], length))
			return 0;
	} while ((index = entry->next) >= 0);

/* Update the hash table removing the list entry we're about to reuse */
	index = keys->hash->hash[reuse_hash = single_key_hash(keys->ptr)];
	if (index == keys->count)
		keys->hash->hash[reuse_hash] = keys->hash->list[index].next;
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

/* Add the new entry */
	index = keys->hash->hash[new_hash];
	entry = &keys->hash->list[keys->count];
	entry->next = index;
	entry->offset = keys->ptr - keys->buffer;
	keys->hash->hash[new_hash] = keys->count;

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

/*
 * Flush the keys list (since we've just processed the keys), but not the hash
 * table to allow for more effective checking for duplicates.  We could flush
 * the hash table too, such as by calling single_alloc_keys() here, which would
 * allow us to drop the update-hash-before-list-entry-reuse code from
 * single_add_key().  This would speed things up in terms of this source file's
 * code overhead, however it would allow more duplicates to pass.  The apparent
 * c/s rate (counting duplicates as if they were distinct combinations) would
 * be higher, but the number of passwords cracked per unit of time might be
 * lower or higher depending on many things including the relative speed of
 * password hash computations vs. the "overhead".
 */
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

		MEM_FREE(keys);
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

	if (!(first = pw->words->head))
		return -1;

	keys = salt->keys;

	first_number = 0;
	do {
		if ((key = rules_apply(first->data, rule, 0, NULL)))
		if (ext_filter(key))
		if (single_add_key(keys, key))
		if (single_process_buffer(salt)) return 1;
		if (!salt->list) return 2;
		if (!pw->binary) return 0;

		if (++first_number > SINGLE_WORDS_PAIR_MAX) continue;

		if (!CP_isLetter[(unsigned char)first->data[0]]) continue;

		second_number = 0;
		second = pw->words->head;

		do
		if (first != second) {
			if ((split = strlen(first->data)) < length) {
				strnzcpy(pair, first->data, RULE_WORD_SIZE);
				strnzcat(pair, second->data, RULE_WORD_SIZE);

				if ((key = rules_apply(pair, rule, split, NULL)))
				if (ext_filter(key))
				if (single_add_key(keys, key))
				if (single_process_buffer(salt)) return 1;
				if (!salt->list) return 2;
				if (!pw->binary) return 0;
			}

			if (first->data[1]) {
				pair[0] = first->data[0];
				pair[1] = 0;
				strnzcat(pair, second->data, RULE_WORD_SIZE);

				if ((key = rules_apply(pair, rule, 1, NULL)))
				if (ext_filter(key))
				if (single_add_key(keys, key))
				if (single_process_buffer(salt)) return 1;
				if (!salt->list) return 2;
				if (!pw->binary) return 0;
			}
		} while (++second_number <= SINGLE_WORDS_PAIR_MAX &&
			(second = second->next));
	} while ((first = first->next));

	return 0;
}

static int single_process_salt(struct db_salt *salt, char *rule)
{
	struct db_keys *keys;
	struct db_password *pw, **last;
	int status, have_words = 0;

	keys = salt->keys;

	if (!keys->have_words)
		goto no_own_words;

	last = &salt->list;
	pw = *last;
	do {
/*
 * "binary" is set to NULL on entries marked for removal (so we remove them
 * here) or already removed (yet we might hit them once in some obscure cases).
 */
		if (pw->binary) {
			if (!(status = single_process_pw(salt, pw, rule))) {
				have_words = 1;
				goto next;
			}
			if (status < 0) /* no words for this hash */
				goto next;
			if (status == 2) /* no hashes left for this salt */
				return 0;
			return 1; /* no hashes left to crack for all salts */
		} else {
			*last = pw->next; /* remove */
		}
next:
		last = &pw->next;
	} while ((pw = pw->next));

	if (keys->count && rule_number - keys->rule > (key_count << 1))
		if (single_process_buffer(salt)) return 1;

	if (!keys->count) keys->rule = rule_number;

	if (!have_words) {
		keys->have_words = 0;
no_own_words:
		if (keys->count && single_process_buffer(salt)) return 1;
	}

	return 0;
}

static void single_run(void)
{
	char *prerule, *rule;
	struct db_salt *salt;
	int min, saved_min;
	int have_words;

	saved_min = rec_rule;
	while ((prerule = rpp_next(rule_ctx))) {
#ifdef HAVE_MPI
		// MPI distribution: leapfrog rules
		if (rule_number % mpi_p != mpi_id) {
			rule_number++;
			continue;
		}
#endif
		if (!(rule = rules_reject(prerule, 0, NULL, single_db))) {
			log_event("- Rule #%d: '%.100s' rejected",
				++rule_number, prerule);
			continue;
		}

		if (strcmp(prerule, rule))
			log_event("- Rule #%d: '%.100s' accepted as '%s'",
				rule_number + 1, prerule, rule);
		else
			log_event("- Rule #%d: '%.100s' accepted",
				rule_number + 1, prerule);

		if (saved_min != rec_rule) {
			log_event("- Oldest still in use is now rule #%d",
				rec_rule + 1);
			saved_min = rec_rule;
		}

		have_words = 0;

		min = rule_number;

		salt = single_db->salts;
		do {
			if (!salt->list) continue;
			if (single_process_salt(salt, rule)) return;
			if (!salt->keys->have_words) continue;
			have_words = 1;
			if (salt->keys->rule < min)
				min = salt->keys->rule;
		} while ((salt = salt->next));

		rec_rule = min;
		rule_number++;

		if (have_words) continue;

		log_event("- No information to base%s candidate passwords on",
			rule_number > 1 ? " further" : "");
		return;
	}
}

static void single_done(void)
{
	struct db_salt *salt;

	if (!event_abort) {
		if ((salt = single_db->salts)) {
			log_event("- Processing the remaining buffered "
				"candidate passwords, if any");

			do {
				if (!salt->list) continue;
				if (salt->keys->count)
				if (single_process_buffer(salt)) break;
			} while ((salt = salt->next));
		}

		progress = 100; // For reporting DONE when finished
	}

	rec_done(event_abort || (status.pass && single_db->salts));
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
