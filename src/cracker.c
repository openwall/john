/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2003,2006,2010-2013 by Solar Designer
 *
 * ...with heavy changes in the jumbo patch, by magnum & JimF
 */

#define NEED_OS_TIMER
#define NEED_OS_FLOCK
#include "os.h"

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
#if (!AC_BUILT || HAVE_FCNTL_H)
#include <fcntl.h>
#endif
#include <errno.h>
#if (!AC_BUILT || HAVE_UNISTD_H) && !_MSC_VER
#include <unistd.h>
#endif
#if _MSC_VER || HAVE_IO_H
#include <io.h> // open()
#endif

#include "arch.h"
#include "misc.h"
#include "math.h"
#include "params.h"
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
#include "mask_ext.h"
#include "mask.h"
#include "unicode.h"
#include "john.h"
#include "fake_salts.h"
#ifdef HAVE_MPI
#include "john-mpi.h"
#endif
#include "path.h"
#include "jumbo.h"
#if HAVE_LIBDL && defined(HAVE_CUDA) || defined(HAVE_OPENCL)
#include "common-gpu.h"
#endif
#include "memdbg.h"

#ifdef index
#undef index
#endif

#if defined(LOCK_DEBUG) && !defined(POTSYNC_DEBUG)
#define POTSYNC_DEBUG 1
#endif

#ifdef POTSYNC_DEBUG
static clock_t salt_time = 0;
#endif

static struct db_main *crk_db;
static struct fmt_params crk_params;
static struct fmt_methods crk_methods;
static int crk_key_index, crk_last_key;
static void *crk_last_salt;
void (*crk_fix_state)(void);
static struct db_keys *crk_guesses;
static int64 *crk_timestamps;
static char crk_stdout_key[PLAINTEXT_BUFFER_SIZE];
int64_t crk_pot_pos;

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
	if (!john_main_process || printed ||
	    ((options.flags & FLG_STDOUT) && isatty(fileno(stdout))))
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
	if ((options.flags & FLG_STDIN_CHK) || (options.flags & FLG_PIPE_CHK))
		fprintf(stderr, "Press Ctrl-C to abort, "
#ifdef SIGUSR1
		        "or send SIGUSR1 to john process for status\n");
#else
		        "or send SIGHUP to john process for status\n");
#endif
	else
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

#if defined(HAVE_OPENCL) || defined(HAVE_CUDA)
	/* This erases the 'spinning wheel' cursor from self-test */
	if (john_main_process)
		fprintf(stderr, " \b");
#endif

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
		memset(crk_timestamps = mem_alloc_tiny(size, sizeof(int64)),
		       -1, size);
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

	/* If we kept the salt_hash table, update it */
	if (crk_db->salt_hash) {
		int hash = crk_methods.salt_hash(salt->salt);

		if (crk_db->salt_hash[hash] == salt) {
			if (salt->next &&
			    crk_methods.salt_hash(salt->next->salt) == hash)
				crk_db->salt_hash[hash] = salt->next;
			else
				crk_db->salt_hash[hash] = NULL;
		}
	}
#ifdef POTSYNC_DEBUG
	if (options.verbosity >= 2 && crk_params.binary_size &&
	    crk_db->salt_count < crk_db->password_count)
		log_event("- got rid of a salt, %d left", crk_db->salt_count);
#endif
	dyna_salt_remove(salt->salt);
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

/* Negative index is not counted/reported (got it from pot sync) */
static int crk_process_guess(struct db_salt *salt, struct db_password *pw,
	int index)
{
	char utf8buf_key[PLAINTEXT_BUFFER_SIZE + 1];
	char utf8login[PLAINTEXT_BUFFER_SIZE + 1];
	char tmp8[PLAINTEXT_BUFFER_SIZE + 1];
	int dupe;
	char *key, *utf8key, *repkey, *replogin, *repuid;

	if (index >= 0 && index < crk_params.max_keys_per_crypt) {
		dupe = !memcmp(&crk_timestamps[index],
		               &status.crypts, sizeof(int64));
		crk_timestamps[index] = status.crypts;
	} else
		dupe = 0;

	repkey = key = index < 0 ? "" : crk_methods.get_key(index);
	replogin = pw->login;
	repuid = pw->uid;

	if (index >= 0 && (pers_opts.store_utf8 || pers_opts.report_utf8)) {
		if (pers_opts.target_enc == UTF_8)
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
		if (pers_opts.report_utf8) {
			repkey = utf8key;
			if (pers_opts.target_enc != UTF_8)
				replogin = cp_to_utf8_r(pw->login,
					      utf8login, PLAINTEXT_BUFFER_SIZE);
		}
		if (pers_opts.store_utf8)
			key = utf8key;
	}

	// Ok, FIX the salt  ONLY if -regen-lost-salts=X was used.
	if (options.regen_lost_salts && (crk_db->format->params.flags & FMT_DYNAMIC) == FMT_DYNAMIC)
		crk_guess_fixup_salt(pw->source, *(char**)(salt->salt));

	/* If we got this crack from a pot sync, don't report or count */
	if (index >= 0) {
		log_guess(crk_db->options->flags & DB_LOGIN ? replogin : "?",
		          crk_db->options->flags & DB_LOGIN ? repuid : "",
		          dupe ?
		          NULL : crk_methods.source(pw->source, pw->binary),
		          repkey, key, crk_db->options->field_sep_char, index);

		if (options.flags & FLG_CRKSTAT)
			event_pending = event_status = 1;

		crk_db->guess_count++;
		status.guess_count++;

		if (crk_guesses && !dupe) {
			strnfcpy(crk_guesses->ptr, key,
			         crk_params.plaintext_length);
			crk_guesses->ptr += crk_params.plaintext_length;
			crk_guesses->count++;
		}
	}

	if (!(crk_params.flags & FMT_NOT_EXACT))
		crk_remove_hash(salt, pw);

	if (!crk_db->salts)
		return 1;

	crk_init_salt();

	return 0;
}

static char *crk_loaded_counts(void)
{
	static char s_loaded_counts[80];

	if (crk_db->password_count == 0)
		return "No remaining hashes";

	if (crk_db->password_count == 1)
		return "Remaining 1 hash";

	sprintf(s_loaded_counts,
		crk_db->salt_count > 1 ?
		"Remaining %d hashes with %d different salts" :
		"Remaining %d hashes with no different salts",
		crk_db->password_count,
		crk_db->salt_count);

	return s_loaded_counts;
}

static int crk_remove_pot_entry(char *ciphertext)
{
	struct db_salt *salt;
	struct db_password *pw;
	void *pot_salt;
	char *binary = crk_methods.binary(ciphertext);
#ifdef POTSYNC_DEBUG
	struct tms buffer;
	clock_t start = times(&buffer), end;
#endif

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
		if (!dyna_salt_cmp(pot_salt, salt->salt, crk_params.salt_size))
			break;
	}  while ((salt = salt->next));

#ifdef POTSYNC_DEBUG
	end = times(&buffer);
	salt_time += (end - start);
#endif
	dyna_salt_remove(pot_salt);
	if (!salt)
		return 0;

	if (!salt->bitmap) {
		if ((pw = salt->list))
		do {
			char *source;

			source = crk_methods.source(pw->source, pw->binary);

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

		hash = crk_methods.binary_hash[salt->hash_size](binary);
		if (!(salt->bitmap[hash / (sizeof(*salt->bitmap) * 8)] &
		      (1U << (hash % (sizeof(*salt->bitmap) * 8)))))
			return 0;

		if ((pw = salt->hash[hash >> PASSWORD_HASH_SHR]))
		do {
			char *source;

			source = crk_methods.source(pw->source, pw->binary);

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
	int total = crk_db->password_count, others;
#if FCNTL_LOCKS
	struct flock lock;
#endif
#ifdef POTSYNC_DEBUG
	struct tms buffer;
	clock_t start = times(&buffer), end;

	salt_time = 0;
#endif
	event_reload = 0;

	if (crk_params.flags & FMT_NOT_EXACT)
		return 0;

	if (!(pot_file = fopen(path_expand(pers_opts.activepot), "rb")))
		pexit("fopen: %s", path_expand(pers_opts.activepot));

#if OS_FLOCK || FCNTL_LOCKS
#ifdef LOCK_DEBUG
	fprintf(stderr, "%s(%u): Locking potfile...\n", __FUNCTION__, options.node_min);
#endif
#if FCNTL_LOCKS
	memset(&lock, 0, sizeof(lock));
	lock.l_type = F_RDLCK;
	while (fcntl(fileno(pot_file), F_SETLKW, &lock)) {
		if (errno != EINTR)
			pexit("fcntl(F_RDLCK)");
	}
#else
	while (flock(fileno(pot_file), LOCK_SH)) {
		if (errno != EINTR)
			pexit("flock(LOCK_SH)");
	}
#endif
#ifdef LOCK_DEBUG
	fprintf(stderr, "%s(%u): Locked potfile (shared)\n", __FUNCTION__, options.node_min);
#endif
#endif
	if (crk_pot_pos && (jtr_fseek64(pot_file, crk_pot_pos, SEEK_SET) == -1)) {
		perror("fseek");
		rewind(pot_file);
		crk_pot_pos = 0;
	}

	ldr_in_pot = 1; /* Mutes some warnings from valid() et al */

	while (fgetl(line, sizeof(line), pot_file)) {
		char *p, *ciphertext = line;
		char *fields[10] = { NULL };

		if (!(p = strchr(ciphertext, options.loader.field_sep_char)))
			continue;
		*p = 0;

		fields[1] = ciphertext;
		ciphertext = crk_methods.prepare(fields, crk_db->format);
		if (crk_methods.valid(ciphertext, crk_db->format)) {
			ciphertext = crk_methods.split(ciphertext, 0,
			                               crk_db->format);
			if (crk_remove_pot_entry(ciphertext))
				break;
		}
	}

	ldr_in_pot = 0;

	crk_pot_pos = jtr_ftell64(pot_file);
#if OS_FLOCK || FCNTL_LOCKS
#ifdef LOCK_DEBUG
	fprintf(stderr, "%s(%u): Unlocking potfile\n", __FUNCTION__, options.node_min);
#endif
#if FCNTL_LOCKS
	lock.l_type = F_UNLCK;
	if (fcntl(fileno(pot_file), F_SETLK, &lock))
		perror("fcntl(F_UNLCK)");
#else
	if (flock(fileno(pot_file), LOCK_UN))
		perror("flock(LOCK_UN)");
#endif
#endif
	if (fclose(pot_file))
		pexit("fclose");

	others = total - crk_db->password_count;

	if (others)
		log_event("+ pot sync removed %d hashes; %s",
		          others, crk_loaded_counts());

	if (others && options.verbosity > 3) {
		if (options.node_count)
			fprintf(stderr, "%u: %s\n",
			        options.node_min, crk_loaded_counts());
		else
			fprintf(stderr, "%s\n", crk_loaded_counts());
	}

#ifdef POTSYNC_DEBUG
	end = times(&buffer);
#if defined(_SC_CLK_TCK) && !defined(CLK_TCK)
#define CLK_TCK	sysconf(_SC_CLK_TCK)
#endif
	fprintf(stderr, "%s(%u): potsync removed %d hashes in %lu ms (%lu ms finding salts); %s\n", __FUNCTION__, options.node_min, others, 1000UL*(end - start)/CLK_TCK, 1000UL * salt_time / CLK_TCK, crk_loaded_counts());
#endif

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
	else if (options.pause_file &&
	         stat(path_expand(options.pause_file), &trigger_stat) == 0) {
#if !HAVE_SYS_TIMES_H
		clock_t end, start = clock();
#else
		struct tms buf;
		clock_t end, start = times(&buf);
#endif

		status_print();
		if (john_main_process)
			fprintf(stderr, "Pause file seen, going to sleep "
			        "(session saved)\n");
		log_event("Pause file seen, going to sleep");

		/* Better save stuff before going to sleep */
		rec_save();

		do {
			int s = 3;

			do {
				s = sleep(s);
			} while (s);

		} while (stat(path_expand(options.pause_file),
		              &trigger_stat) == 0);

		if (john_main_process)
			fprintf(stderr, "Pause file removed, continuing\n");
		log_event("Pause file removed, continuing");

		/* Disregard pause time for stats */
#if !HAVE_SYS_TIMES_H
		end = clock();
#else
		end = times(&buf);
#endif
		status.start_time -= (start - end);
	}
}

static int crk_process_event(void)
{
	event_pending = 0;

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

	if (event_status) {
		event_status = 0;
		status_print();
	}

	if (event_ticksafety) {
		event_ticksafety = 0;
		status_ticks_overflow_safety();
	}

	if (event_poll_files) {
		event_poll_files = 0;
#if HAVE_LIBDL && defined(HAVE_CUDA) || defined(HAVE_OPENCL)
		gpu_check_temp();
#endif
		crk_poll_files();
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
				else {
					if (!(crk_params.flags & FMT_NOT_EXACT))
						break;
				}
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

	if (event_reload && crk_reload_pot())
		return 1;

	salt = crk_db->salts;
	do {
		crk_methods.set_salt(salt->salt);
		if ((done = crk_password_loop(salt)))
			break;
	} while ((salt = salt->next));

	if (done >= 0) {
#if 1 /* Assumes we'll never overrun 32-bit in one crypt */
		add32to64(&status.cands, crk_key_index *
		          mask_int_cand.num_int_cand);
#else /* Safe for 64-bit */
		int64 totcand;
		mul32by32(&totcand, crk_key_index, mask_int_cand.num_int_cand);
		add64to64(&status.cands, &totcand);
#endif
	}

	if (salt)
		return 1;

	crk_key_index = 0;
	crk_last_salt = NULL;
	if (options.flags & FLG_MASK_STACKED)
		mask_fix_state();
	else
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

int crk_process_key(char *key)
{
	if (crk_db->loaded) {
		if (crk_key_index == 0)
			crk_methods.clear_keys();

		crk_methods.set_key(key, crk_key_index++);

		if (crk_key_index >= crk_params.max_keys_per_crypt ||
		    (options.force_maxkeys &&
		     crk_key_index >= options.force_maxkeys))
			return crk_salt_loop();

		return 0;
	}

#if !OS_TIMER
	sig_timer_emu_tick();
#endif

	if (event_pending)
	if (crk_process_event()) return 1;

	strnzcpy(crk_stdout_key, key, crk_params.plaintext_length + 1);
	if (options.verbosity > 1)
		puts(crk_stdout_key);

	status_update_cands(1);

	if (options.flags & FLG_MASK_STACKED)
		mask_fix_state();
	else
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
		if (index >= crk_params.max_keys_per_crypt || !count ||
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
	}
	c_cleanup();
}
