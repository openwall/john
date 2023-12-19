/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2003,2006,2010-2013,2015,2017 by Solar Designer
 *
 * ...with heavy changes in the jumbo patch, by magnum & JimF
 */

#define NEED_OS_TIMER
#include "os.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#if (!AC_BUILT || HAVE_SYS_FILE_H)
#include <sys/file.h>
#endif
#include <time.h>
#if (!AC_BUILT || HAVE_SYS_TIMES_H)
#include <sys/times.h>
#endif
#include <errno.h>
#if (!AC_BUILT || HAVE_UNISTD_H) && !_MSC_VER
#include <unistd.h>
#endif
#if _MSC_VER || HAVE_IO_H
#include <io.h> // open()
#endif

#include "arch.h"
#include "params.h"
#include "base64_convert.h"

#if CRK_PREFETCH && defined(__SSE__)
#include <xmmintrin.h>
#endif

#include "misc.h"
#include "memory.h"
#include "signals.h"
#include "idle.h"
#include "formats.h"
#include "dyna_salt.h"
#include "loader.h"
#include "logger.h"
#include "status.h"
#include "recovery.h"
#include "external.h"
#include "options.h"
#include "config.h"
#include "mask_ext.h"
#include "mask.h"
#include "unicode.h"
#include "cracker.h"
#include "john.h"
#include "fake_salts.h"
#include "sha.h"
#include "john_mpi.h"
#include "path.h"
#include "jumbo.h"
#include "opencl_common.h"
#if HAVE_LIBDL && defined(HAVE_OPENCL)
#include "gpu_common.h"
#endif
#include "rules.h"
#include "tty.h"

#ifdef index
#undef index
#endif

extern long clk_tck;

static int crk_process_key_max_keys;
static struct db_main *crk_db;
static struct fmt_params *crk_params;
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
static struct db_keys *crk_guesses;
static uint64_t *crk_timestamps;
static char crk_stdout_key[PLAINTEXT_BUFFER_SIZE];
static int kpc_warn, kpc_warn_limit, single_running;
static fix_state_fp hybrid_fix_state;

int crk_stacked_rule_count = 1;
rule_stack crk_rule_stack;

int64_t crk_pot_pos;

void (*crk_fix_state)(void);
int (*crk_process_key)(char *key);

static int process_key_stack_rules(char *key);

/* Expose max_keys_per_crypt to the world (needed in recovery.c) */
int crk_max_keys_per_crypt(void)
{
	return options.force_maxkeys ? options.force_maxkeys : crk_params->max_keys_per_crypt;
}

static void crk_dummy_set_salt(void *salt)
{
	/* Refresh salt every 30 seconds in case it was thrashed */
	if (event_refresh_salt > 30) {
		crk_db->format->methods.set_salt(salt);
		event_refresh_salt = 0;
	}
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

	if ((options.flags & FLG_STDOUT) && isatty(fileno(stdout)))
		return;

#ifdef HAVE_MPI
	if (mpi_p > 1 || getenv("OMPI_COMM_WORLD_SIZE"))
#ifdef SIGUSR1
		fprintf(stderr, "Send SIGUSR1 to mpirun for status\n");
#else
		fprintf(stderr, "Send SIGHUP to john process for status\n");
#endif
	else
#endif
	if (tty_has_keyboard())
		fprintf(stderr, "Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status\n");
	else
		fprintf(stderr, "Press Ctrl-C to abort, "
#ifdef SIGUSR1
		        "or send SIGUSR1 to john process for status\n");
#else
		        "or send SIGHUP to john process for status\n");
#endif

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
	if ((where = fmt_self_test(db->format, db))) {
		log_event("! Self test failed (%s)", where);
		fprintf(stderr, "Self test failed (%s)\n", where);
		error();
	}

#if HAVE_OPENCL
	/* This erases the 'spinning wheel' cursor from self-test */
	if (john_main_process && isatty(fileno(stderr)))
		fprintf(stderr, " \b");
#endif

	status.salt_count = db->salt_count;
	status.password_count = db->password_count;

	crk_db = db;
	crk_params = &db->format->params;
	memcpy(&crk_methods, &db->format->methods, sizeof(struct fmt_methods));

#if CRK_PREFETCH && !defined(crk_prefetch)
	{
		unsigned int m = crk_params->max_keys_per_crypt;
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
	crk_process_key_max_keys = 0; /* use slow path at first */
	crk_last_key = crk_key_index = 0;
	crk_last_salt = NULL;

	if (fix_state)
		(crk_fix_state = fix_state)();
	else
		crk_fix_state = crk_dummy_fix_state;

	if (options.flags & FLG_MASK_STACKED)
		mask_fix_state();

	crk_guesses = guesses;

	kpc_warn = crk_params->min_keys_per_crypt;

	if (db->loaded) {
		size = crk_params->max_keys_per_crypt * sizeof(uint64_t);
		memset(crk_timestamps = mem_alloc(size), -1, size);
	} else
		crk_stdout_key[0] = 0;

	rec_save();

	crk_help();

	idle_init(db->format);

	if (options.verbosity < VERB_DEFAULT)
		kpc_warn_limit = 0;
	else
	if ((kpc_warn_limit =
	     cfg_get_int(SECTION_OPTIONS, NULL, "MaxKPCWarnings")) == -1)
		kpc_warn_limit = CRK_KPC_WARN;

	if (!(options.flags & FLG_SINGLE_CHK))
		rules_stacked_after = !!(crk_stacked_rule_count = rules_init_stack(options.rule_stack, &crk_rule_stack, db));
	else
		crk_stacked_rule_count = 0;

	if (crk_stacked_rule_count == 0)
		crk_stacked_rule_count = 1;

	if (rules_stacked_after)
		crk_process_key = process_key_stack_rules;
	else
		crk_process_key = crk_direct_process_key;

	/*
	 * Resetting crk_process_key above disables the suppressor, but it can
	 * possibly be re-enabled by a cracking mode.
	 */
	if (status.suppressor_start) {
		status.suppressor_end = status.cands;
		status.suppressor_end_time = status_get_time();
	}
}

/*
 * crk_remove_salt() is called by crk_remove_hash() when it happens to remove
 * the last password hash for a salt.
 */
static void crk_remove_salt(struct db_salt *salt)
{
	struct db_salt **current;

	crk_db->salt_count--;
	status.salt_count = crk_db->salt_count;

	current = &crk_db->salts;
	while (*current != salt)
		current = &(*current)->next;
	*current = salt->next;

	/* If we kept the salt_hash table, update it */
	if (crk_db->salt_hash) {
		int hash = crk_methods.salt_hash(salt->salt);

		if (crk_db->salt_hash[hash] == salt) {
			if (options.verbosity >= VERB_DEBUG) {
				fprintf(stderr, "Got rid of %s, %s\n", strncasecmp(crk_params->label, "wpapsk", 6) ? "a salt" : (char*)(salt->salt) + 4, crk_loaded_counts());
				status_update_counts();
			}
			if (salt->next &&
			    crk_methods.salt_hash(salt->next->salt) == hash)
				crk_db->salt_hash[hash] = salt->next;
			else
				crk_db->salt_hash[hash] = NULL;
		}
	}

	dyna_salt_remove(salt->salt);
}

/*
 * Updates the database after a password has been cracked.
 */
static void crk_remove_hash(struct db_salt *salt, struct db_password *pw)
{
	struct db_password **start, **current;
	int hash, count;

	assert(salt->count >= 1);

	crk_db->password_count--;
	status.password_count = crk_db->password_count;

	BLOB_FREE(crk_db->format, pw->binary);

	if (!--salt->count) {
		salt->list = NULL; /* "single crack" mode might care */
		crk_remove_salt(salt);
		if (!salt->bitmap)
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
 *
 * Or, if FMT_REMOVE, the format explicitly intends to traverse the list
 * during cracking, and will remove entries at that point.
 */
	if (crk_guesses || (crk_params->flags & FMT_REMOVE))
		pw->binary = NULL;
}

/* Negative index is not counted/reported (got it from pot sync) */
static int crk_process_guess(struct db_salt *salt, struct db_password *pw, int index)
{
	char utf8buf_key[PLAINTEXT_BUFFER_SIZE + 1];
	char utf8login[PLAINTEXT_BUFFER_SIZE + 1];
	char tmp8[PLAINTEXT_BUFFER_SIZE + 1];
	int dupe;
	char *key, *utf8key, *repkey, *replogin, *repuid;

	if (index >= 0 && index < crk_params->max_keys_per_crypt) {
		dupe = crk_timestamps[index] == status.crypts;
		crk_timestamps[index] = status.crypts;
	} else
		dupe = 0;

	repkey = key = index < 0 ? "" : crk_methods.get_key(index);

	if (crk_db->options->flags & DB_LOGIN) {
		replogin = pw->login;
		if (options.show_uid_in_cracks)
			repuid = pw->uid;
		else
			repuid = "";
	} else
		replogin = repuid = "";

	if (index >= 0 && (options.store_utf8 || options.report_utf8)) {
		if (options.target_enc == UTF_8)
			utf8key = key;
		else {
			utf8key = cp_to_utf8_r(key, utf8buf_key,
			                       PLAINTEXT_BUFFER_SIZE);
			// Double-check that the conversion was correct. Our
			// fallback is to log, warn and use the original key
			// instead. If you see it, we have a bug.
			utf8_to_cp_r(utf8key, tmp8,
			             PLAINTEXT_BUFFER_SIZE);
			if (strcmp(tmp8, key)) {
				fprintf(stderr, "Warning, conversion failed %s"
				        " -> %s -> %s - fallback to codepage\n",
				        key, utf8key, tmp8);
				log_event("Warning, conversion failed %s -> %s"
				          " -> %s - fallback to codepage", key,
				          utf8key, tmp8);
				utf8key = key;
			}
		}
		if (options.report_utf8) {
			repkey = utf8key;
			if (options.internal_cp != UTF_8)
				replogin = cp_to_utf8_r(replogin,
					      utf8login, PLAINTEXT_BUFFER_SIZE);
		}
		if (options.store_utf8)
			key = utf8key;
	}

	// Ok, FIX the salt  ONLY if -regen-lost-salts=X was used.
	if (options.regen_lost_salts && (crk_params->flags & FMT_DYNAMIC) == FMT_DYNAMIC)
		crk_guess_fixup_salt(pw->source, *(char**)(salt->salt));

	if (options.max_run_time < 0) {
#if OS_TIMER
		timer_abort = 0 - options.max_run_time;
#else
		timer_abort = status_get_time() - options.max_run_time;
#endif
	}
	if (options.max_cands < 0)
		john_max_cands = status.cands - options.max_cands + crk_params->max_keys_per_crypt;

	/* If we got this crack from a pot sync, don't report or count */
	if (index >= 0) {
		const char *ct;
		char buffer[LINE_BUFFER_SIZE + 1];

		if (dupe && !(crk_params->flags & FMT_BLOB))
			ct = NULL;
		else
			ct = ldr_pot_source(
				crk_methods.source(pw->source, pw->binary),
				buffer);
		log_guess(crk_db->options->flags & DB_LOGIN ? replogin : "?",
		          crk_db->options->flags & DB_LOGIN ? repuid : "",
		          (char*)ct,
		          repkey, key, crk_db->options->field_sep_char, index);

		if (options.crack_status)
			event_pending = event_status = 1;

		crk_db->guess_count++;
		status.guess_count++;

		if (crk_guesses && !dupe) {
			strnfcpy(crk_guesses->ptr, key,
			         crk_params->plaintext_length);
			crk_guesses->ptr += crk_params->plaintext_length;
			crk_guesses->count++;
		}
	}

	if (!(crk_params->flags & FMT_NOT_EXACT))
		crk_remove_hash(salt, pw);

	if (options.regen_lost_salts) {
		/*
		 * salt->list pointer was copied to all salts so if the first
		 * entry was removed, we need to fixup all other salts.  If OTOH
		 * the last hash was removed, we need to drop all salts.
		 */
		struct db_salt *s = crk_db->salts;

		do {
			if (!crk_db->password_count)
				crk_remove_salt(s);
			else if (s->list && s->list->binary == NULL)
				s->list = s->list->next;
		} while ((s = s->next));
	}

	if (!crk_db->salts)
		return 1;

	crk_init_salt();

	return 0;
}

char *crk_loaded_counts(void)
{
	return john_loaded_counts(crk_db, "Remaining");
}

static int crk_remove_pot_entry(char *ciphertext)
{
	struct db_salt *salt;
	struct db_password *pw;
	char argcopy[LINE_BUFFER_SIZE];
	void *pot_salt;

	/*
	 * If the pot entry is truncated from a huge ciphertext, we have
	 * this alternate code path that's slower but aware of the magic.
	 */
	if (ldr_isa_pot_source(ciphertext)) {
		if ((salt = crk_db->salts))
		do {
			if ((pw = salt->list))
			do {
				char *source;

				source = crk_methods.source(pw->source,
				                            pw->binary);

				if (!ldr_pot_source_cmp(ciphertext, source)) {
					if (crk_process_guess(salt, pw, -1))
						return 1;

					if (!(crk_db->options->flags & DB_WORDS))
						break;
				}
			} while ((pw = pw->next));
		}  while ((salt = salt->next));

		return 0;
	}

	/*
	 * We need to copy ciphertext, because the one we got actually
	 * points to a static buffer in split() and we are going to call
	 * that function again and compare the results. Thanks to
	 * Christien Rioux for pointing this out.
	 */
	ciphertext = strnzcpy(argcopy, ciphertext, sizeof(argcopy));
	pot_salt = crk_methods.salt(ciphertext);
	dyna_salt_create(pot_salt);

	/* Do we still have a hash table for salts? */
	if (crk_db->salt_hash) {
		salt = crk_db->salt_hash[crk_methods.salt_hash(pot_salt)];
		if (!salt)
			return 0;
	} else
		salt = crk_db->salts;

	do {
		if (!dyna_salt_cmp(pot_salt, salt->salt, crk_params->salt_size))
			break;
	}  while ((salt = salt->next));

	dyna_salt_remove(pot_salt);
	if (!salt)
		return 0;

	if (!salt->bitmap) {
		if ((pw = salt->list))
		do {
			char *source;

			source = crk_methods.source(pw->source, pw->binary);

			//assert(source != ciphertext);
			if (!strcmp(source, ciphertext)) {
				if (crk_process_guess(salt, pw, -1))
					return 1;

				if (!(crk_db->options->flags & DB_WORDS))
					break;
			}
		} while ((pw = pw->next));
	}
	else {
		int hash;
		char *binary = crk_methods.binary(ciphertext);

		hash = crk_methods.binary_hash[salt->hash_size](binary);
		BLOB_FREE(crk_db->format, binary);
		if (!(salt->bitmap[hash / (sizeof(*salt->bitmap) * 8)] &
		      (1U << (hash % (sizeof(*salt->bitmap) * 8)))))
			return 0;

		if ((pw = salt->hash[hash >> PASSWORD_HASH_SHR]))
		do {
			char *source;

			source = crk_methods.source(pw->source, pw->binary);

			//assert(source != ciphertext);
			if (!strcmp(source, ciphertext)) {
				if (crk_process_guess(salt, pw, -1))
					return 1;

				if (!(crk_db->options->flags & DB_WORDS))
					break;
			}
		} while ((pw = pw->next_hash));
	}

	return 0;
}

int crk_reload_pot(void)
{
	char line[LINE_BUFFER_SIZE];
	FILE *pot_file;
	int passwords = crk_db->password_count;
	int salts = crk_db->salt_count;

	event_reload = 0;

	if (event_abort)
		return 0;

	if (crk_params->flags & FMT_NOT_EXACT)
		return 0;

	if (!(pot_file = fopen(path_expand(options.activepot), "rb")))
		pexit("fopen: %s", path_expand(options.activepot));

	if (crk_pot_pos) {
		if (jtr_fseek64(pot_file, 0, SEEK_END) == -1)
			pexit("fseek to end of pot file");
		if (crk_pot_pos == jtr_ftell64(pot_file)) {
			if (fclose(pot_file))
				pexit("fclose");
			return 0;
		}
		if (crk_pot_pos > jtr_ftell64(pot_file)) {
			if (john_main_process) {
				fprintf(stderr,
				        "Note: pot file shrunk. Recovering.\n");
			}
			log_event("Note: pot file shrunk. Recovering.");
			rewind(pot_file);
			crk_pot_pos = 0;
		}
		if (jtr_fseek64(pot_file, crk_pot_pos, SEEK_SET) == -1) {
			perror("fseek to sync pos. of pot file");
			log_event("fseek to sync pos. of pot file: %s",
			          strerror(errno));
			crk_pot_pos = 0;
			if (fclose(pot_file))
				pexit("fclose");
			return 0;
		}
	}

	ldr_in_pot = 1; /* Mutes some warnings from valid() et al */

	while (fgetl(line, sizeof(line), pot_file)) {
		char *p, *ciphertext = line;
		char *fields[10] = { NULL };

		if (!(p = strchr(ciphertext, options.loader.field_sep_char)))
			continue;
		*p = 0;

		fields[0] = "";
		fields[1] = ciphertext;
		ciphertext = crk_methods.prepare(fields, crk_db->format);
		if (ldr_trunc_valid(ciphertext, crk_db->format)) {
			ciphertext = crk_methods.split(ciphertext, 0,
			                               crk_db->format);
			if (crk_remove_pot_entry(ciphertext))
				break;
		}
	}

	ldr_in_pot = 0;

	crk_pot_pos = jtr_ftell64(pot_file);

	if (fclose(pot_file))
		pexit("fclose");

	passwords -= crk_db->password_count;
	salts -= crk_db->salt_count;

	if (john_main_process && passwords) {
		log_event("+ pot sync removed %d hashes/%d salts; %s",
		          passwords, salts, crk_loaded_counts());

		if (salts && cfg_get_bool(SECTION_OPTIONS, NULL,
		                          "ShowSaltProgress", 0)) {
			fprintf(stderr, "%s after pot sync\n", crk_loaded_counts());
			status_update_counts();
		}
	}

	return (!crk_db->salts);
}

#ifdef HAVE_MPI
static void crk_mpi_probe(void)
{
	static MPI_Status s;
	int flag;

	MPI_Iprobe(MPI_ANY_SOURCE, JOHN_MPI_RELOAD, MPI_COMM_WORLD, &flag, &s);
	if (flag) {
		static MPI_Request r;
		char buf[16];

		event_reload = 1;
		MPI_Irecv(buf, 1, MPI_CHAR, MPI_ANY_SOURCE,
		          JOHN_MPI_RELOAD, MPI_COMM_WORLD, &r);
	}
}
#endif

static void crk_poll_files(void)
{
	struct stat trigger_stat;

	if (options.abort_file &&
	    stat(path_expand(options.abort_file), &trigger_stat) == 0) {
		if (!event_abort && john_main_process)
			fprintf(stderr, "Abort file seen\n");
		log_event("Abort file seen");
		event_pending = event_abort = 1;
	}
	else if (options.pause_file && stat(path_expand(options.pause_file), &trigger_stat) == 0) {
#if !HAVE_SYS_TIMES_H
		clock_t end, start = clock();
#else
		struct tms buf;
		clock_t end, start = times(&buf);
#endif

		status_print(0);
		if (john_main_process)
			fprintf(stderr, "Pause file seen, going to sleep (session saved)\n");
		log_event("Pause file seen, going to sleep");

		/* Better save stuff before going to sleep */
		rec_save();

		do {
			int s = 3;

			do {
				s = sleep(s);
			} while (s);

		} while (stat(path_expand(options.pause_file), &trigger_stat) == 0);

		/* Disregard pause time for stats */
#if !HAVE_SYS_TIMES_H
		end = clock();
#else
		end = times(&buf);
#endif
		status.start_time += (end - start);

		int pause_time = (end - start) / clk_tck;
		log_event("Pause file removed after %d seconds, continuing", pause_time);
		if (john_main_process)
			fprintf(stderr, "Pause file removed after %d seconds, continuing\n", pause_time);
	}
}

static int crk_process_event(void)
{
#ifdef HAVE_MPI
	if (event_mpiprobe) {
		event_mpiprobe = 0;
		crk_mpi_probe();
	}
#endif

	if (event_save) {
		event_save = 0;
		rec_save();
	}

	if (event_help)
		sig_help();

	if (event_status)
		status_print(0);

	if (event_ticksafety) {
		event_ticksafety = 0;
		status_ticks_overflow_safety();
	}

	if (event_poll_files) {
		event_poll_files = 0;
#if HAVE_LIBDL && defined(HAVE_OPENCL)
		gpu_check_temp();
#endif
		crk_poll_files();
	}

	event_pending = event_reload;

	return event_abort;
}

void crk_set_hybrid_fix_state_func_ptr(fix_state_fp fp)
{
	hybrid_fix_state = fp;
}

/*
 * Called from crk_salt_loop for every salt or, when in Single mode, from
 * crk_process_salt with just a specific salt.
 */
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

	/*
	 * magnum, December 2020:
	 * I can't fathom how/why this would be the correct place for this, but
	 * it seems to work and just moving it to the others does break resume
	 * for hybrid external so here it stays, until further research.
	 */
	if (hybrid_fix_state)
		hybrid_fix_state();

	if (kpc_warn_limit && crk_key_index < kpc_warn) {
		static int last_warn_kpc, initial_value;
		int s;
		uint64_t ps = status.cands;

		if ((s = status_get_time()))
			ps /= s;

		if (single_running && crk_db->salt_count)
			ps /= crk_db->salt_count;

		if (!initial_value)
			initial_value = kpc_warn_limit;

		if (kpc_warn > crk_params->min_keys_per_crypt)
			kpc_warn = crk_params->min_keys_per_crypt;

		if (crk_key_index < kpc_warn &&
		    ps <= (kpc_warn - crk_key_index) &&
		    last_warn_kpc != crk_key_index) {

			last_warn_kpc = crk_key_index;
			if (options.node_count)
				fprintf(stderr, "%u: ", NODE);
			fprintf(stderr, "Warning: Only %d%s candidate%s buffered%s, "
			        "minimum %d needed for performance.\n",
			        crk_key_index,
			        mask_int_cand.num_int_cand > 1 ? " base" : "",
			        crk_key_index > 1 ? "s" : "",
			        single_running ? " for the current salt" : "",
			        crk_params->min_keys_per_crypt);

			if (!--kpc_warn_limit) {
				if (options.node_count)
					fprintf(stderr, "%u: ", NODE);
				fprintf(stderr,
				        "Further messages of this type will be suppressed.\n");
				log_event(
"- Saw %d calls to crypt_all() with sub-optimal batch size (stopped counting)",
				          initial_value);
			}
		}
	}

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
			if (crk_methods.cmp_exact(crk_methods.source(pw->source, pw->binary), index)) {
				if (crk_process_guess(salt, pw, index))
					return 1;
				else {
					if (!(crk_params->flags & FMT_NOT_EXACT))
						break;
				}
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

/*
 * When crk_process_key() has a complete batch, it calls this function
 * to run the batch with all salts.
 */
static int crk_salt_loop(void)
{
	int sc = crk_db->salt_count;
	int done;
	struct db_salt *salt;

	single_running = 0;

	if (event_reload && crk_reload_pot())
		return 1;

	salt = crk_db->salts;

	/* on first run, right after restore, this can be non-zero */
	if (status.resume_salt) {
		struct db_salt *s = salt;

		/* clear resume so it only works the first time */
		status.resume_salt = 0;
		while (s)
		{
			if (s->salt_md5[0] == status.resume_salt_md5[0] &&
			    !memcmp(s->salt_md5, status.resume_salt_md5, 16)) {
				/* found it!! */
				salt = s;
				break;
			}
			s = s->next;
		}
	}

	/* Normal loop over all salts */
	do {
		crk_methods.set_salt(salt->salt);
		status.resume_salt_md5 = (crk_db->salt_count > 1) ?
			salt->salt_md5 : NULL;
		if ((done = crk_password_loop(salt)))
			break;
	} while ((salt = salt->next));

	if (event_delayed_status || (crk_db->salt_count < sc && john_main_process &&
	                             cfg_get_bool(SECTION_OPTIONS, NULL, "ShowSaltProgress", 0))) {
		event_status = event_delayed_status ? event_delayed_status : 1;
		event_delayed_status = 0;
		event_pending = 1;
	}

	if (!salt || crk_db->salt_count < 2)
		status.resume_salt_md5 = NULL;

	if (done >= 0)
		status.cands +=
			(uint64_t)crk_key_index * mask_int_cand.num_int_cand;

	if (john_max_cands && !event_abort) {
		if (status.cands >= john_max_cands)
			event_abort = event_pending = 1;
	}

	if (salt)
		return 1;

	crk_process_key_max_keys = 0; /* use slow path next time */
	crk_key_index = 0;
	crk_last_salt = NULL;

	if (event_fix_state) {
		if (options.flags & FLG_MASK_STACKED)
			mask_fix_state();
		else
			crk_fix_state();
		event_fix_state = 0;
	}

	if (ext_abort)
		event_abort = 1;

	if (ext_status && !event_abort) {
		if (ext_status >= event_status)
			event_status = 0;
		status_print(ext_status);
		ext_status = 0;
	}

	return ext_abort;
}

/*
 * Process an incomplete batch; This is used by mask mode before
 * resetting the format with a changed internal mask.
 */
int crk_process_buffer(void)
{
	if (crk_db->loaded && crk_key_index)
		return crk_salt_loop();

	if (event_pending && crk_process_event())
		return 1;

	if (ext_abort)
		event_abort = 1;

	if (ext_status && !event_abort) {
		if (ext_status >= event_status)
			event_status = 0;
		status_print(ext_status);
		ext_status = 0;
	}

	return ext_abort;
}

/*
 * All modes but Single call this function (as crk_process_key)
 * for each candidate.
 */
int crk_direct_process_key(char *key)
{
	if (crk_key_index < crk_process_key_max_keys) {
		crk_methods.set_key(key, crk_key_index++);

		if (crk_key_index >= crk_process_key_max_keys)
			return crk_salt_loop();

		return 0;
	}

	if (crk_db->loaded) {
		int max_keys = crk_params->max_keys_per_crypt;

		if (options.force_maxkeys | status.resume_salt) { /* bitwise OR */
			if (options.force_maxkeys && max_keys > options.force_maxkeys)
				max_keys = options.force_maxkeys;
			if (status.resume_salt && max_keys > status.resume_salt)
				max_keys = status.resume_salt;
		}

		if (crk_key_index == 0)
			crk_methods.clear_keys();

		crk_methods.set_key(key, crk_key_index++);

		if (crk_key_index >= max_keys)
			return crk_salt_loop();

		crk_process_key_max_keys = max_keys; /* use fast path next time */

		return 0;
	}

#if !OS_TIMER
	sig_timer_emu_tick();
#endif

	if (event_pending && crk_process_event())
		return 1;

	strnzcpy(crk_stdout_key, key, crk_params->plaintext_length + 1);
	if (options.verbosity > 1)
		puts(crk_stdout_key);

	status_update_cands(1);

	if (john_max_cands && !event_abort) {
		if (status.cands >= john_max_cands)
			event_abort = event_pending = 1;
	}

	if (event_fix_state) {
		if (options.flags & FLG_MASK_STACKED)
			mask_fix_state();
		else
			crk_fix_state();
		event_fix_state = 0;
	}

	if (ext_abort)
		event_abort = 1;

	if (ext_status && !event_abort) {
		if (ext_status >= event_status)
			event_status = 0;
		status_print(ext_status);
		ext_status = 0;
	}

	return ext_abort;
}

static int process_key_stack_rules(char *key)
{
	int ret = 0;
	char *word;

	while ((word = rules_process_stack_all(key, &crk_rule_stack)))
		if ((ret = crk_direct_process_key(word)))
			break;

	return ret;
}

/* This function is used by single.c only */
int crk_process_salt(struct db_salt *salt)
{
	char *ptr;
	char key[PLAINTEXT_BUFFER_SIZE];
	int count, count_from_guesses, index;

	single_running = 1;

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

	while (count--) {
		strnzcpy(key, ptr, options.eff_maxlength + 1);
		ptr += options.eff_maxlength;

		if (index == 0)
			crk_methods.clear_keys();

		crk_methods.set_key(key, index++);
		if (index >= crk_params->max_keys_per_crypt || !count ||
		    (options.force_maxkeys && index >= options.force_maxkeys)) {
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
					if (john_max_cands && !event_abort &&
					    status.cands >= john_max_cands)
						event_abort = event_pending = 1;
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
	if (options.secure)
		return "";
	else
	if (crk_db->loaded)
		return crk_methods.get_key(0);
	else
		return crk_stdout_key;
}

char *crk_get_key2(void)
{
	if (options.secure)
		return NULL;
	else
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
	c_cleanup();
}
