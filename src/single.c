/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-99,2003,2004,2006,2010,2012,2013 by Solar Designer
 *
 * ...with changes in the jumbo patch, by magnum & JimF.
 */

#define NEED_OS_FORK
#include "os.h"

#include <stdio.h>
#include <string.h>

#include "misc.h"
#include "params.h"
#include "common.h"
#include "memory.h"
#include "signals.h"
#include "loader.h"
#include "logger.h"
#include "status.h"
#include "recovery.h"
#include "options.h"
#include "rpp.h"
#include "rules.h"
#include "external.h"
#include "cracker.h"
#include "john.h"
#include "unicode.h"
#include "config.h"
#include "opencl_common.h"

/* List with optional global words to add for every salt */
struct list_main *single_seed;

static double progress = 0;
static int rec_rule[2];

static struct db_main *single_db;
static int rule_number, rule_count;
static int length, key_count;
static struct db_keys *guessed_keys;
static struct rpp_context *rule_ctx;

static int words_pair_max;
static int retest_guessed;
static int recurse_depth, max_recursion;
static int orig_max_len, orig_min_kpc;
static int stacked_rule_count = 1;
static rule_stack single_rule_stack;

#if HAVE_OPENCL || HAVE_ZTEX
static int acc_fmt, prio_resume;
#if HAVE_OPENCL
static int ocl_fmt;
#endif /* HAVE_OPENCL */
#endif /* HAVE_OPENCL || HAVE_ZTEX */

static int single_disabled_recursion;

static void save_state(FILE *file)
{
	fprintf(file, "%d\n", rec_rule[0]);
	if (options.rule_stack)
		fprintf(file, "%d\n", rec_rule[1]);
}

static int restore_rule_number(void)
{
	if (rule_ctx)
		for (rule_number = 0; rule_number < rec_rule[0]; rule_number++)
			if (!rpp_next(rule_ctx))
				return 1;

	if (options.rule_stack) {
		single_rule_stack.rule = single_rule_stack.stack_rule->head;
		rules_stacked_number = 0;
		while (rules_stacked_number < rec_rule[1])
			if (!rules_advance_stack(&single_rule_stack, 1))
				return 1;
		log_event("+ Stacked Rule #%u: '%.100s' accepted",
		          rules_stacked_number + 1, single_rule_stack.rule->data);
	}

	return 0;
}

static int restore_state(FILE *file)
{
	if (fscanf(file, "%d\n", &rec_rule[0]) != 1)
		return 1;
	if (options.rule_stack && fscanf(file, "%d\n", &rec_rule[1]) != 1)
		return 1;
	return restore_rule_number();
}

static double get_progress(void)
{
	double tot_rules, tot_rule_number;

	emms();

	tot_rules = rule_count * stacked_rule_count;
	tot_rule_number = rules_stacked_number * rule_count + rule_number;

	return progress ? progress :
		100.0 * tot_rule_number / (tot_rules + 1);
}

static uint64_t calc_buf_size(int length, int min_kpc)
{
	uint64_t res = sizeof(struct db_keys_hash) +
		sizeof(struct db_keys_hash_entry) * (min_kpc - 1);

	res += (sizeof(struct db_keys) - 1 + length * min_kpc);

	return res * single_db->salt_count;
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

	(*keys)->count = (*keys)->count_from_guesses = 0;
	(*keys)->ptr = (*keys)->buffer;
	(*keys)->have_words = 1; /* assume yes; we'll see for real later */
	(*keys)->rule[0] = rule_number;
	(*keys)->rule[1] = rules_stacked_number;
	(*keys)->lock = 0;
	memset((*keys)->hash, -1, hash_size);
}

#undef log2
#define log2 jtr_log2

static uint32_t log2(uint32_t val)
{
	uint32_t res = 0;

	while (val >>= 1)
		res++;

	return res;
}

static void single_init(void)
{
	struct db_salt *salt;
	int lim_kpc, max_buffer_GB;
	int64_t my_buf_share;

#if HAVE_OPENCL || HAVE_ZTEX
	prio_resume = cfg_get_bool(SECTION_OPTIONS, NULL, "SinglePrioResume", 0);

	acc_fmt = strcasestr(single_db->format->params.label, "-opencl") ||
		strcasestr(single_db->format->params.label, "-ztex");
#endif
#if HAVE_OPENCL
	ocl_fmt = acc_fmt && strcasestr(single_db->format->params.label, "-opencl");
#endif

	if (john_main_process) {
		log_event("Proceeding with \"single crack\" mode");

		if ((options.flags & FLG_BATCH_CHK || rec_restored)) {
			fprintf(stderr, "Proceeding with single, rules:");
			if (options.rule_stack)
				fprintf(stderr, "(%s x %s)",
				        options.activesinglerules, options.rule_stack);
			else
				fprintf(stderr, "%s", options.activesinglerules);
			if (options.req_minlength >= 0 || options.req_maxlength)
				fprintf(stderr, ", lengths:%d-%d", options.eff_minlength,
				        options.eff_maxlength);
			fprintf(stderr, "\n");
		}
	}

	/*
	 * Deprecated option --single-retest-guess=BOOL or new option
	 * --[no-]single-retest-guess (tri-state) may override SingleRetestGuessed
	 *
	 * Bodge for deprecated syntax. When dropping it we'll drop this interim variable
	 */
	int option_retest = 0;

	option_retest = parse_bool(options.single_retest_guess);

	if ((retest_guessed = option_retest) == -1) {

		retest_guessed = cfg_get_bool(SECTION_OPTIONS, NULL, "SingleRetestGuessed", 1);

		if (!retest_guessed && single_db->salt_count == 1) {
			retest_guessed = 0;
			if (john_main_process)
				fprintf(stderr, "Note: Ignoring SingleRetestGuessed option because only one salt is loaded.\n"
				                "      You can force it with --single-retest-guess\n");
		}
	}

	if (!retest_guessed && john_main_process)
		fprintf(stderr, "Will not try cracked passwords against other salts\n");

	if (options.seed_per_user && retest_guessed && option_retest == -1)
		fprintf(stderr, "Note: You might want --single-retest-guess when using --single-user-seed\n");

	if ((words_pair_max = options.single_pair_max) < 0)
	if ((words_pair_max = cfg_get_int(SECTION_OPTIONS, NULL, "SingleWordsPairMax")) < 0)
		words_pair_max = SINGLE_WORDS_PAIR_MAX;

	if ((max_recursion = cfg_get_int(SECTION_OPTIONS, NULL,
	                                 "SingleMaxRecursionDepth")) < 0)
		max_recursion = 10000;

	if ((max_buffer_GB = cfg_get_int(SECTION_OPTIONS, NULL,
	                                  "SingleMaxBufferSize")) < 0)
		max_buffer_GB = SINGLE_MAX_WORD_BUFFER;

	if (cfg_get_bool(SECTION_OPTIONS, NULL, "SingleMaxBufferAvailMem", 0)) {
		int64_t avail_mem = host_avail_mem();

		if (avail_mem < 0)
			avail_mem = host_total_mem();

		if (avail_mem > 0)
			max_buffer_GB = avail_mem >> 30;
	}

	my_buf_share = (int64_t)max_buffer_GB << 30;

#if HAVE_MPI
	if (mpi_p_local > 1)
		my_buf_share /= mpi_p_local;
	else
#endif
#if OS_FORK
	if (options.fork)
		my_buf_share /= options.fork;
#endif

	progress = 0;

	length = options.eff_maxlength;
	key_count = single_db->format->params.min_keys_per_crypt;

	/* Do not allocate buffers we'll never use */
	if (options.force_maxkeys && key_count > options.force_maxkeys)
		key_count = options.force_maxkeys;

	if (key_count < SINGLE_HASH_MIN)
		key_count = SINGLE_HASH_MIN;
/*
 * We use "short" for buffered key indices and "unsigned short" for buffered
 * key offsets - make sure these don't overflow.
 *
 * Jumbo now uses SINGLE_KEYS_TYPE and SINGLE_KEYS_UTYPE for this,
 * from params.h and they may (individually) be 32-bit, eg. for OpenCL
 */
	if (key_count > SINGLE_IDX_MAX)
		key_count = SINGLE_IDX_MAX;
	while (key_count > SINGLE_BUF_MAX / length + 1)
#if HAVE_OPENCL
		if (ocl_fmt)
			key_count -= MIN(key_count >> 1, local_work_size * ocl_v_width);
		else
#endif
			key_count >>= 1;

	if (key_count < single_db->format->params.min_keys_per_crypt) {
		if (john_main_process) {
			fprintf(stderr,
"Note: Performance for this format/device may be lower due to single mode\n"
"      constraints. Format wanted %d keys per crypt but was limited to %d.\n",
			        single_db->format->params.min_keys_per_crypt,
			        key_count);
		}
		log_event(
"- Min KPC decreased from %d to %d due to single mode constraints.",
			single_db->format->params.min_keys_per_crypt,
			key_count);
	}

/*
 * For large salt counts, we need to limit total memory use as well.
 */
	lim_kpc = key_count;

	while (key_count >= 2 * SINGLE_HASH_MIN && my_buf_share &&
	       calc_buf_size(length, key_count) > my_buf_share) {
		if (!options.req_maxlength && length >= 32 &&
		    (length >> 1) >= options.eff_minlength)
			length >>= 1;
		else if (!options.req_maxlength && length > 16 &&
		         (length - 1) >= options.eff_minlength)
			length--;
#if HAVE_OPENCL
		else if (ocl_fmt)
			key_count -= MIN(key_count >> 1, local_work_size * ocl_v_width);
#endif
		else
			key_count >>= 1;
	}

	if (length < options.eff_maxlength) {
		if (john_main_process)
			fprintf(stderr,
"Note: Max. length decreased from %d to %d due to single mode buffer size\n"
"      limit of %sB (%sB needed). Use --max-length=N option to override, or\n"
"      increase SingleMaxBufferSize in john.conf (if you have enough RAM).\n",
			        options.eff_maxlength,
			        length,
			        human_prefix(my_buf_share),
			        human_prefix(calc_buf_size(options.eff_maxlength,
			                                   key_count)));
		log_event(
"- Max. length decreased from %d to %d due to buffer size limit of %sB.",
			options.eff_maxlength,
			length,
			human_prefix(my_buf_share));
	}

	if (my_buf_share && calc_buf_size(length, key_count) > my_buf_share) {
		if (john_main_process) {
			fprintf(stderr,
"Note: Can't run single mode with this many salts due to single mode buffer\n"
"      size limit of %sB (%d keys per batch would use %sB, decreased to\n"
"      %d for %sB). To work around this, increase SingleMaxBufferSize in\n"
"      john.conf (if you have enough RAM) or load fewer salts at a time.\n",
			        human_prefix(my_buf_share),
			        lim_kpc,
			        human_prefix(calc_buf_size(length, lim_kpc)),
			        key_count,
			        human_prefix(calc_buf_size(length, key_count)));
		}
		if (lim_kpc < single_db->format->params.min_keys_per_crypt)
			log_event(
"- Min KPC decreased further to %d (%sB), can't meet buffer size limit of %sB.",
			key_count,
			human_prefix(calc_buf_size(length, key_count)),
			human_prefix(my_buf_share));
		else
			log_event(
"- Min KPC decreased from %d to %d (%sB), can't meet buffer size limit of %sB.",
			lim_kpc,
			key_count,
			human_prefix(calc_buf_size(length, key_count)),
			human_prefix(my_buf_share));
		error();
	}

	if (key_count < lim_kpc) {
		if (john_main_process) {
			fprintf(stderr,
"Note: Performance for this many salts may be lower due to single mode buffer\n"
"      size limit of %sB (%d keys per batch would use %sB, decreased to\n"
"      %d for %sB). To work around this, ",
			        human_prefix(my_buf_share),
			        lim_kpc,
			        human_prefix(calc_buf_size(length, lim_kpc)),
			        key_count,
			        human_prefix(calc_buf_size(length, key_count)));
			if (options.eff_maxlength > 8)
				fprintf(stderr, "%s --max-length and/or ",
				        options.req_maxlength ?
				        "decrease" : "use");
			fprintf(stderr,
			        "increase%sSingleMaxBufferSize in john.conf.\n",
			        options.eff_maxlength > 8 ? "\n      " : " ");
		}
		if (lim_kpc < single_db->format->params.min_keys_per_crypt)
			log_event(
"- Min KPC decreased further to %d due to buffer size limit of %sB.",
			key_count,
			human_prefix(my_buf_share));
		else
			log_event(
"- Min KPC decreased from %d to %d due to buffer size limit of %sB.",
			lim_kpc,
			key_count,
			human_prefix(my_buf_share));
	}

	if (rpp_init(rule_ctx, options.activesinglerules)) {
		log_event("! No \"%s\" mode rules found",
		          options.activesinglerules);
		if (john_main_process)
			fprintf(stderr, "No \"%s\" mode rules found in %s\n",
			        options.activesinglerules, cfg_name);
		error();
	}

	/*
	 * Now set our possibly capped figures as global in order to get
	 * proper function and less warnings. We reset them in single_done
	 * for in case we run batch mode
	 */
	orig_max_len = options.eff_maxlength;
	options.eff_maxlength = length;
	orig_min_kpc = single_db->format->params.min_keys_per_crypt;
	single_db->format->params.min_keys_per_crypt = key_count;

	/*
	 * Some auto-increase of words pairing, unless completely disabled.
	 */
	if (words_pair_max && single_seed->count) {
		words_pair_max += single_seed->count;
		log_event("- SingleWordsPairMax increased for %d global seed words",
		          single_seed->count);
	}
	if (words_pair_max && log2(key_count) > words_pair_max) {
		words_pair_max = log2(key_count);
		log_event("- SingleWordsPairMax increased to %d for high KPC (%d)",
		          log2(key_count), key_count);
	}

	if (words_pair_max)
		log_event("- SingleWordsPairMax used is %d", words_pair_max);
	else
		log_event("- Single words pairing disabled");
	log_event("- SingleRetestGuessed = %s",retest_guessed ? "true" : "false");
	if (my_buf_share)
		log_event("- SingleMaxBufferSize = %sB%s", human_prefix(my_buf_share),
#if HAVE_MPI
	          (mpi_p_local > 1 || options.fork)
#elif OS_FORK
	          options.fork
#else
	          0
#endif
	          ? " (per local process)" : "");
	else
		log_event("- SingleMaxBufferSize = unlimited");
#if HAVE_OPENCL || HAVE_ZTEX
	log_event("- SinglePrioResume = %s", prio_resume ?
	          "Y (prioritize resumability over speed)" :
	          "N (prioritize speed over resumability)");
#endif

	rules_init(single_db, length);
	rec_rule[0] = rule_number = 0;
	rec_rule[1] = rules_stacked_number = 0;
	rule_count = rules_count(rule_ctx, 0);

	stacked_rule_count = rules_init_stack(options.rule_stack,
	                                      &single_rule_stack, single_db);

	if (options.rule_stack)
		log_event("- Total %u (%d x %u) preprocessed word mangling rules",
		          rule_count * stacked_rule_count,
		          rule_count, stacked_rule_count);
	else
		log_event("- %d preprocessed word mangling rules", rule_count);

	rules_stacked_after = (stacked_rule_count > 0);

	if (!stacked_rule_count)
		stacked_rule_count = 1;

	status_init(get_progress, 0);

	rec_restore_mode(restore_state);
	rec_init(single_db, save_state);

	salt = single_db->salts;
	do {
		single_alloc_keys(&salt->keys);
	} while ((salt = salt->next));

	if (key_count > 1)
		log_event("- Allocated %d buffer%s of %d candidate passwords"
		          "%s (total %sB)",
		          single_db->salt_count,
		          single_db->salt_count != 1 ? "s" : "",
		          key_count,
		          single_db->salt_count != 1 ? " each" : "",
		          human_prefix(calc_buf_size(length, key_count)));

	guessed_keys = NULL;
	single_alloc_keys(&guessed_keys);

	crk_init(single_db, NULL, guessed_keys);
}

static MAYBE_INLINE int single_key_hash(char *key)
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

static int single_process_buffer(struct db_salt *salt);

static int single_add_key(struct db_salt *salt, char *key, int is_from_guesses)
{
	struct db_keys *keys = salt->keys;
	int index, new_hash, reuse_hash;
	struct db_keys_hash_entry *entry;

	if (options.rule_stack)
		if (!(key = rules_process_stack(key, &single_rule_stack)))
			return 0;

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

	keys->count_from_guesses += is_from_guesses;

	if (++(keys->count) >= key_count)
		return single_process_buffer(salt);

	return 0;
}

static int single_process_buffer(struct db_salt *salt)
{
	struct db_salt *current;
	struct db_keys *keys;
	size_t size;

	if (retest_guessed && ++recurse_depth > max_recursion) {
		log_event("- Disabled SingleRetestGuessed due to deep recursion");
		if (john_main_process)
			fprintf(stderr,
"Warning: Disabled SingleRetestGuessed due to deep recursion. You can run\n"
"         '--loopback --rules=none' later on instead.\n");

		retest_guessed = 0;
		single_disabled_recursion = 1;
	}

	if (crk_process_salt(salt))
		return 1;

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
	keys->count = keys->count_from_guesses = 0;
	keys->ptr = keys->buffer;
	keys->lock++;

	if (retest_guessed)
	if (guessed_keys->count) {
		keys = mem_alloc(size = sizeof(struct db_keys) - 1 +
			length * guessed_keys->count);
		memcpy(keys, guessed_keys, size);

		keys->ptr = keys->buffer;
		do {
			current = single_db->salts;
			do {
				if (current == salt || !current->list)
					continue;

				if (single_add_key(current, keys->ptr, 1)) {
					MEM_FREE(keys);
					return 1;
				}
			} while ((current = current->next));
			keys->ptr += length;
		} while (--keys->count);

		MEM_FREE(keys);
	}

	keys = salt->keys;
	keys->lock--;
	if (!keys->count && !keys->lock) {
		keys->rule[0] = rule_number;
		keys->rule[1] = rules_stacked_number;
	}

	recurse_depth--;
	return 0;
}

static int single_process_pw(struct db_salt *salt, struct db_password *pw,
	char *rule)
{
	struct list_entry *first, *second;
	struct list_entry *global_head = single_seed->head;
	int first_global, second_global;
	int first_number, second_number;
	char pair[RULE_WORD_SIZE];
	int split;
	char *key;

	if (!(first = pw->words->head))
		return -1;

	first_number = first_global = 0;
	do {
		if (first == global_head)
			first_global = 1;
		if ((key = rules_apply(first->data, rule, 0, NULL)))
		if (ext_filter(key))
		if (single_add_key(salt, key, 0))
			return 1;
		if (!salt->list)
			return 2;
		if (!pw->binary)
			return 0;

		if (++first_number > words_pair_max)
			continue;

		if (!CP_isLetter[(unsigned char)first->data[0]])
			continue;

		second_number = second_global = 0;
		second = pw->words->head;

		do {
			if (second == global_head)
				second_global = 1;
			if (first == second || (first_global && second_global))
				continue;
			if ((split = strlen(first->data)) < length) {
				strnzcpy(pair, first->data, RULE_WORD_SIZE);
				strnzcat(pair, second->data, RULE_WORD_SIZE);

				if ((key = rules_apply(pair, rule, split, NULL)))
				if (ext_filter(key))
				if (single_add_key(salt, key, 0))
					return 1;
				if (!salt->list)
					return 2;
				if (!pw->binary)
					return 0;
			}

			if (!first_global && first->data[1]) {
				pair[0] = first->data[0];
				pair[1] = 0;
				strnzcat(pair, second->data, RULE_WORD_SIZE);

				if ((key = rules_apply(pair, rule, 1, NULL)))
				if (ext_filter(key))
				if (single_add_key(salt, key, 0))
					return 1;
				if (!salt->list)
					return 2;
				if (!pw->binary)
					return 0;
			}
		} while (++second_number <= words_pair_max &&
			(second = second->next));
	} while ((first = first->next));

	return 0;
}

#define tot_rule_no (rules_stacked_number * rule_count + rule_number)
#define tot_rule_now (keys->rule[1] * rule_count + keys->rule[0])

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

#if HAVE_OPENCL || HAVE_ZTEX
	if (!acc_fmt || prio_resume)
#endif
	if (keys->count && tot_rule_no - tot_rule_now > (key_count << 1))
		if (single_process_buffer(salt))
			return 1;

	if (!keys->count) {
		keys->rule[0] = rule_number;
		keys->rule[1] = rules_stacked_number;
	}

	if (!have_words) {
		keys->have_words = 0;
no_own_words:
		if (keys->count && single_process_buffer(salt))
			return 1;
	}

	return 0;
}

static void single_run(void)
{
	char *prerule, *rule;
	struct db_salt *salt;
	int min[2], saved_min[2];
	int have_words;

	saved_min[0] = rec_rule[0];
	saved_min[1] = rec_rule[1];
	rpp_real_run = 1;

	do {
		rec_rule[1] = min[1] = rules_stacked_number;
		while ((prerule = rpp_next(rule_ctx))) {
			int sc = single_db->salt_count;

			if (options.node_count && strncmp(prerule, "!!", 2)) {
				int for_node = rule_number % options.node_count + 1;
				if (for_node < options.node_min ||
				    for_node > options.node_max) {
					rule_number++;
					continue;
				}
			}

			if (!(rule = rules_reject(prerule, 0, NULL, single_db))) {
				rule_number++;
				if (options.verbosity >= VERB_DEFAULT &&
				    !rules_mute &&
				    strncmp(prerule, "!!", 2))
					log_event("- Rule #%d: '%.100s' rejected",
					          rule_number, prerule);
				continue;
			}

			if (!rules_mute) {
				if (strcmp(prerule, rule)) {
					log_event("- Rule #%d: '%.100s' accepted as '%.100s'",
					          rule_number + 1, prerule, rule);
				} else {
					log_event("- Rule #%d: '%.100s' accepted",
					          rule_number + 1, prerule);
				}
			}

			if (saved_min[0] != rec_rule[0] || saved_min[1] != rec_rule[1]) {
				if (!rules_mute) {
					if (options.rule_stack)
						log_event("- Oldest still in use rules are now "
						          "base #%d, stacked #%d",
						          rec_rule[0] + 1, rec_rule[1] + 1);
					else
						log_event("- Oldest still in use is now rule #%d",
						          rec_rule[0] + 1);
				}
				saved_min[0] = rec_rule[0];
				saved_min[1] = rec_rule[1];
			}

			have_words = 0;

			min[0] = rule_number;

			/* pot reload might have removed the salt */
			if (!(salt = single_db->salts))
				return;
			do {
				if (!salt->list)
					continue;
				if (single_process_salt(salt, rule))
					return;
				if (!salt->keys->have_words)
					continue;
				have_words = 1;
				if (salt->keys->rule[0] < min[0])
					min[0] = salt->keys->rule[0];
				if (salt->keys->rule[1] < min[1])
					min[1] = salt->keys->rule[1];
			} while ((salt = salt->next));

			if (event_delayed_status || (single_db->salt_count < sc && john_main_process &&
			                             cfg_get_bool(SECTION_OPTIONS, NULL, "ShowSaltProgress", 0))) {
				event_status = event_delayed_status ? event_delayed_status : 1;
				event_delayed_status = 0;
				event_pending = 1;
			}

			if (event_reload && single_db->salts)
				crk_reload_pot();

			rec_rule[0] = min[0];
			rule_number++;

			if (have_words)
				continue;

			log_event("- No information to base%s candidate passwords on",
			          rule_number > 1 ? " further" : "");
			return;
		}

		if (rules_stacked_after) {
			saved_min[0] = rule_number = 0;
			rpp_init(rule_ctx, options.activesinglerules);
			if (!rules_mute && options.verbosity <= VERB_DEFAULT) {
				rules_mute = 1;
				if (john_main_process) {
					log_event(
"- Some rule logging suppressed. Re-enable with --verbosity=%d or greater",
					          VERB_LEGACY);
				}
			}
		}

	} while (rules_stacked_after && rules_advance_stack(&single_rule_stack, 0));
}

static void single_done(void)
{
	struct db_salt *salt;

	if (!event_abort) {
		if ((salt = single_db->salts)) {
			if (john_main_process) {
				log_event("- Processing the remaining buffered "
				          "candidate passwords, if any");

				if (options.verbosity >= VERB_DEFAULT)
					fprintf(stderr, "Almost done: Processing the remaining "
					        "buffered candidate passwords, if any.\n");
			}

			do {
				if (!salt->list)
					continue;
				if (salt->keys->count)
					if (single_process_buffer(salt))
						break;
			} while ((salt = salt->next));
		}

		progress = 100;
	}

	options.eff_maxlength = orig_max_len;
	single_db->format->params.min_keys_per_crypt = orig_min_kpc;

	rec_done(event_abort || (status.pass && single_db->salts));
	crk_done();
}

char* do_single_crack(struct db_main *db)
{
	struct rpp_context ctx;
	int initial_num_salts;

	single_db = db;
	initial_num_salts = db->salt_count;
	rule_ctx = &ctx;
	single_init();
	single_run();
	single_done();
	rule_ctx = NULL; /* Just for good measure */

	if (initial_num_salts > 1 && status.guess_count && !retest_guessed) {
		if (single_disabled_recursion)
			return "Warning: Disabled SingleRetestGuessed due to deep recursion. Consider running '--loopback --rules=none' next.";
		else
			return "Consider running '--loopback --rules=none' next.";
	} else
		return "";
}
