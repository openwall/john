/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2004,2006,2009-2013,2015 by Solar Designer
 *
 * ...with changes in the jumbo patch, by JimF and magnum (and various others?)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 *
 * Please note that although this main john.c file is under the cut-down BSD
 * license above (so that you may reuse sufficiently generic pieces of code
 * from this file under these relaxed terms), some other source files that it
 * uses are under GPLv2.  For licensing terms for John the Ripper as a whole,
 * see doc/LICENSE.
 */

#if AC_BUILT
#include "autoconfig.h"
#else
#define _GNU_SOURCE 1 /* for strcasestr */
#ifdef __SIZEOF_INT128__
#define HAVE___INT128 1
#endif
#endif

#define NEED_OS_FORK
#define NEED_OS_TIMER
#include "os.h"

#include <stdio.h>
#if HAVE_DIRENT_H && HAVE_SYS_TYPES_H
#include <dirent.h>
#include <sys/types.h>
#elif _MSC_VER || __MINGW32__
#include <windows.h>
char CPU_req_name[48];
#endif
#if (!AC_BUILT || HAVE_UNISTD_H) && !_MSC_VER
#include <unistd.h>
#endif
#include <errno.h>
#if !AC_BUILT
 #include <string.h>
 #ifndef _MSC_VER
  #include <strings.h>
 #endif
#else
 #if STRING_WITH_STRINGS
  #include <string.h>
  #include <strings.h>
 #elif HAVE_STRING_H
  #include <string.h>
 #elif HAVE_STRINGS_H
  #include <strings.h>
 #endif
#endif
#include <stdlib.h>
#include <sys/stat.h>
#if OS_FORK
#include <sys/wait.h>
#include <signal.h>
#endif
#if !AC_BUILT || HAVE_LOCALE_H
#include <locale.h>
#endif

#include "params.h"

#ifdef _OPENMP
#include <omp.h>
static int john_omp_threads_orig = 0;
static int john_omp_threads_new;
#endif

#include "arch.h"
#include "openssl_local_overrides.h"
#include "misc.h"
#include "path.h"
#include "memory.h"
#include "list.h"
#include "tty.h"
#include "signals.h"
#include "common.h"
#include "idle.h"
#include "formats.h"
#include "dyna_salt.h"
#include "loader.h"
#include "logger.h"
#include "status.h"
#include "recovery.h"
#include "options.h"
#include "config.h"
#include "bench.h"
#ifdef HAVE_FUZZ
#include "fuzz.h"
#endif
#include "charset.h"
#include "single.h"
#include "wordlist.h"
#include "prince.h"
#include "inc.h"
#include "mask.h"
#include "mkv.h"
#include "subsets.h"
#include "external.h"
#include "batch.h"
#include "dynamic_compiler.h"
#include "fake_salts.h"
#include "listconf.h"
#include "crc32.h"
#include "john_mpi.h"
#include "regex.h"

#include "unicode.h"
#include "gpu_common.h"
#include "opencl_common.h"
#ifdef HAVE_ZTEX
#include "ztex_common.h"
#endif
#ifdef NO_JOHN_BLD
#define JOHN_BLD "unk-build-type"
#else
#include "john_build_rule.h"
#endif

#if HAVE_MPI
#ifdef _OPENMP
#define _MP_VERSION " MPI + OMP"
#else
#define _MP_VERSION " MPI"
#endif
#else
#ifdef _OPENMP
#define _MP_VERSION " OMP"
#else
#define _MP_VERSION ""
#endif
#endif
#include "omp_autotune.h"

extern int dynamic_Register_formats(struct fmt_main **ptr);

#if CPU_DETECT
extern int CPU_detect(void);
extern char CPU_req_name[];
#endif

extern struct fmt_main fmt_DES, fmt_BSDI, fmt_MD5, fmt_md5crypt_long, fmt_BF;
extern struct fmt_main fmt_scrypt;
extern struct fmt_main fmt_AFS, fmt_LM;
#ifdef HAVE_CRYPT
extern struct fmt_main fmt_crypt;
#endif
extern struct fmt_main fmt_trip;
extern struct fmt_main fmt_dummy;
extern struct fmt_main fmt_NT;
#ifdef HAVE_ZTEX
extern struct fmt_main fmt_ztex_descrypt;
extern struct fmt_main fmt_ztex_bcrypt;
extern struct fmt_main fmt_ztex_sha512crypt;
extern struct fmt_main fmt_ztex_drupal7;
extern struct fmt_main fmt_ztex_sha256crypt;
extern struct fmt_main fmt_ztex_md5crypt;
extern struct fmt_main fmt_ztex_phpass;
#endif

#include "fmt_externs.h"

extern int unshadow(int argc, char **argv);
extern int unafs(int argc, char **argv);
extern int unique(int argc, char **argv);
extern int undrop(int argc, char **argv);

extern int base64conv(int argc, char **argv);
extern int zip2john(int argc, char **argv);
extern int gpg2john(int argc, char **argv);
extern int rar2john(int argc, char **argv);

int john_main_process = 1;
#if OS_FORK
int john_child_count = 0;
int *john_child_pids = NULL;
#endif
char *john_terminal_locale = "C";

uint64_t john_max_cands;

static int children_ok = 1;

static struct db_main database;
static int loaded_extra_pots;
static struct fmt_main dummy_format;

static char *mode_exit_message = "";
static int exit_status = 0;

static void john_register_one(struct fmt_main *format)
{
	if (options.format) {
		if (options.format[0] == '-' && options.format[1]) {
			if (fmt_match(&options.format[1], format, 1))
				return;
		} else if (options.format[0] == '+' && options.format[1]) {
			if (!fmt_match(&options.format[1], format, 0))
				return;
		} else if (!fmt_match(options.format, format, 0))
			return;
	} else if (!options.format_list)
		if (cfg_get_bool(SECTION_DISABLED, SUBSECTION_FORMATS, format->params.label, 0) &&
		    ((options.flags & FLG_TEST_CHK) || options.listconf))
			return;

	fmt_register(format);
}

static void john_register_all(void)
{
#ifndef DYNAMIC_DISABLED
	int i, cnt;
	struct fmt_main *selfs;
#endif

	if (options.format) {
		/* Dynamic compiler format needs case intact and it can't be used with wildcard or lists */
		if (strncasecmp(options.format, "dynamic=", 8)) {
			strlwr(options.format);

			if (options.format[0] != ',' && strchr(options.format, ',')) {
				options.format_list = options.format;
				options.format = NULL;
			}
		}
	}

	/* Let ZTEX formats appear before CPU formats */
#ifdef HAVE_ZTEX
	john_register_one(&fmt_ztex_descrypt);
	john_register_one(&fmt_ztex_bcrypt);
	john_register_one(&fmt_ztex_sha512crypt);
	john_register_one(&fmt_ztex_drupal7);
	john_register_one(&fmt_ztex_sha256crypt);
	john_register_one(&fmt_ztex_md5crypt);
	john_register_one(&fmt_ztex_phpass);
#endif
	john_register_one(&fmt_DES);
	john_register_one(&fmt_BSDI);
	john_register_one(&fmt_MD5);
	john_register_one(&fmt_md5crypt_long);
	john_register_one(&fmt_BF);
	john_register_one(&fmt_scrypt);
	john_register_one(&fmt_LM);
	john_register_one(&fmt_AFS);
	john_register_one(&fmt_trip);

	/* Add all plug-in formats */
#include "fmt_registers.h"

#ifndef DYNAMIC_DISABLED
	/* Add dynamic formats last so they never have precedence */
	cnt = dynamic_Register_formats(&selfs);

	for (i = 0; i < cnt; ++i)
		john_register_one(&(selfs[i]));
#endif

	john_register_one(&fmt_dummy);
#if HAVE_CRYPT
	john_register_one(&fmt_crypt);
#endif

	/* Do we have --format=LIST? If so, re-build fmt_list from it, in requested order. */
	if (options.format_list && !fmt_check_custom_list())
		error_msg("Could not parse format list '%s'\n", options.format_list);

	if (!fmt_list) {
		if (john_main_process) {
			fprintf(stderr, "Error: No format matched requested %s '%s'\n", fmt_type(options.format), options.format);
		}
		error();
	}
}

static void john_log_format(void)
{
	int enc_len, utf8_len;
	char max_len_s[128];

	/* make sure the format is properly initialized */
#if HAVE_OPENCL
	if (!(options.acc_devices->count && options.fork &&
	      strstr(database.format->params.label, "-opencl")))
#endif
	fmt_init(database.format);

	utf8_len = enc_len = database.format->params.plaintext_length;
	if (options.target_enc == UTF_8)
		utf8_len /= 3;

	if (!(database.format->params.flags & FMT_8_BIT) ||
	    options.target_enc != UTF_8) {
		/* Not using UTF-8 so length is not ambiguous */
		snprintf(max_len_s, sizeof(max_len_s), "%d", enc_len);
	} else if (!fmt_raw_len || fmt_raw_len == enc_len) {
		/* Example: Office and thin dynamics */
		snprintf(max_len_s, sizeof(max_len_s),
		         "%d [worst case UTF-8] to %d [ASCII]",
		         utf8_len, enc_len);
	} else if (enc_len == 3 * fmt_raw_len) {
		/* Example: NT */
		snprintf(max_len_s, sizeof(max_len_s), "%d", utf8_len);
	} else {
		/* Example: SybaseASE */
		snprintf(max_len_s, sizeof(max_len_s),
		         "%d [worst case UTF-8] to %d [ASCII]",
		         utf8_len, fmt_raw_len);
	}

	log_event("- Hash type: %.100s%s%.100s (min-len %d, max-len %s%s)",
	    database.format->params.label,
	    database.format->params.format_name[0] ? ", " : "",
	    database.format->params.format_name,
	    database.format->params.plaintext_min_length,
	    max_len_s,
	    (database.format == &fmt_DES || database.format == &fmt_LM) ?
	    ", longer passwords split" : "");

	log_event("- Algorithm: %.100s",
	    database.format->params.algorithm_name);
}

static void john_log_format2(void)
{
	int min_chunk, chunk;

	/* Messages require extra info not available in john_log_format().
		These are delayed until mask_init(), fmt_reset() */
	chunk = min_chunk = database.format->params.max_keys_per_crypt;
	if (options.force_maxkeys && options.force_maxkeys < chunk)
		chunk = min_chunk = options.force_maxkeys;
	if ((options.flags & (FLG_SINGLE_CHK | FLG_BATCH_CHK)) && chunk < SINGLE_HASH_MIN)
		chunk = SINGLE_HASH_MIN;
	if (chunk > 1)
		log_event("- Candidate passwords %s be buffered and tried in chunks of %d",
			min_chunk > 1 ? "will" : "may",
			chunk);
}

#ifdef _OPENMP
static void john_omp_init(void)
{
	john_omp_threads_new = omp_get_max_threads();
	if (!john_omp_threads_orig)
		john_omp_threads_orig = john_omp_threads_new;
}

#if OMP_FALLBACK || defined(OMP_FALLBACK_BINARY)
#if defined(__DJGPP__)
#error OMP_FALLBACK is incompatible with the current DOS code
#endif
#define HAVE_JOHN_OMP_FALLBACK
static void john_omp_fallback(char **argv) {
	if (!getenv("JOHN_NO_OMP_FALLBACK") && john_omp_threads_new <= 1) {
		rec_done(-2);
#ifdef JOHN_SYSTEMWIDE_EXEC
#define OMP_FALLBACK_PATHNAME JOHN_SYSTEMWIDE_EXEC "/" OMP_FALLBACK_BINARY
#else
#define OMP_FALLBACK_PATHNAME path_expand("$JOHN/" OMP_FALLBACK_BINARY)
#endif
		execv(OMP_FALLBACK_PATHNAME, argv);
#ifdef JOHN_SYSTEMWIDE_EXEC
		perror("execv: " OMP_FALLBACK_PATHNAME);
#else
		perror("execv: $JOHN/" OMP_FALLBACK_BINARY);
#endif
	}
}
#endif

static void john_omp_maybe_adjust_or_fallback(char **argv)
{
	if (options.fork && !getenv("OMP_NUM_THREADS")) {
		john_omp_threads_new /= options.fork;
		if (john_omp_threads_new < 1)
			john_omp_threads_new = 1;
		omp_set_num_threads(john_omp_threads_new);
		john_omp_init();
#ifdef HAVE_JOHN_OMP_FALLBACK
		john_omp_fallback(argv);
#endif
	}
}

static void john_omp_show_info(void)
{
	if (options.verbosity >= VERB_DEFAULT)
#if HAVE_MPI
	if (mpi_p == 1)
#endif
	if (database.format && database.format->params.label &&
	        !strstr(database.format->params.label, "-opencl") &&
	        !strstr(database.format->params.label, "-ztex"))
	if (!options.fork && john_omp_threads_orig > 1 &&
	    database.format && database.format != &dummy_format &&
	    !rec_restoring_now) {
		const char *msg = NULL;
		if (!(database.format->params.flags & FMT_OMP))
			msg = "no OpenMP support";
		else if ((database.format->params.flags & FMT_OMP_BAD))
			msg = "poor OpenMP scalability";
		if (msg) {
#if OS_FORK
		if (!(options.flags & (FLG_PIPE_CHK | FLG_STDIN_CHK)))
			fprintf(stderr, "Warning: %s for this hash type, "
			    "consider --fork=%d\n",
			    msg, john_omp_threads_orig);
		else
#endif
			fprintf(stderr, "Warning: %s for this hash type\n",
			    msg);
		}
	}

/*
 * Only show OpenMP info if one of the following is true:
 * - we have a format detected for the loaded hashes and it is OpenMP-enabled;
 * - we're doing --test and no format is specified (so we will test all,
 * including some that are presumably OpenMP-enabled);
 * - we're doing --test and the specified format is OpenMP-enabled.
 */
	{
		int show = 0;
		if (database.format &&
		    (database.format->params.flags & FMT_OMP))
			show = 1;
		else if ((options.flags & (FLG_TEST_CHK | FLG_FORMAT)) ==
		    FLG_TEST_CHK)
			show = 1;
		else if ((options.flags & FLG_TEST_CHK) &&
		    (fmt_list->params.flags & FMT_OMP))
			show = 1;

		if (!show)
			return;
	}

#if HAVE_MPI
	/*
	 * If OMP_NUM_THREADS is set, we assume the user knows what
	 * he is doing. Here's how to pass it to remote hosts:
	 * mpirun -x OMP_NUM_THREADS=4 -np 4 -host ...
	 */
	if (mpi_p > 1) {
		if (getenv("OMP_NUM_THREADS") == NULL &&
		   cfg_get_bool(SECTION_OPTIONS, SUBSECTION_MPI,
		                "MPIOMPmutex", 1)) {
			if (cfg_get_bool(SECTION_OPTIONS, SUBSECTION_MPI,
			                "MPIOMPverbose", 1) && mpi_id == 0)
				fprintf(stderr, "MPI in use, disabling OMP "
				        "(see doc/README.mpi)\n");
			omp_set_num_threads(1);
			john_omp_threads_orig = 0; /* Mute later warning */
		} else if (john_omp_threads_orig > 1 &&
		        cfg_get_bool(SECTION_OPTIONS, SUBSECTION_MPI,
		                "MPIOMPverbose", 1) && mpi_id == 0)
			fprintf(stderr, "Note: Running both MPI and OMP"
			        " (see doc/README.mpi)\n");
	} else
#endif
	if (options.fork) {
#if OS_FORK
		if (john_omp_threads_new > 1)
			fprintf(stderr,
			    "Will run %d OpenMP threads per process "
			    "(%u total across %u processes)\n",
			    john_omp_threads_new,
			    john_omp_threads_new * options.fork, options.fork);
		else if (john_omp_threads_orig > 1)
			fputs("Warning: OpenMP was disabled due to --fork; "
			    "a non-OpenMP build may be faster\n", stderr);
#endif
	} else {
		if (john_omp_threads_new > 1)
			fprintf(stderr,
			    "Will run %d OpenMP threads\n",
			    john_omp_threads_new);
	}

	if (john_omp_threads_orig == 1)
	if (options.verbosity >= VERB_DEFAULT)
	if (john_main_process) {
		const char *format = database.format ?
			database.format->params.label : options.format;
		if (format && strstr(format, "-opencl"))
			fputs("Warning: OpenMP is disabled; "
			      "GPU may be under-utilized\n", stderr);
		else
			fputs("Warning: OpenMP is disabled; "
			      "a non-OpenMP build may be faster\n", stderr);
	}
}
#endif

static void john_set_tristates(void)
{
	/* Config CrackStatus may be overridden by --crack-status tri-state */
	if (options.crack_status == -1)
		options.crack_status = cfg_get_bool(SECTION_OPTIONS, NULL, "CrackStatus", 0);
}

#if OS_FORK
static void john_fork(void)
{
	int i, pid;
	int *pids;

	fflush(stdout);
	fflush(stderr);

#if HAVE_MPI
/*
 * We already initialized MPI before knowing this is actually a fork session.
 * So now we need to tear that "1-node MPI session" down before forking, or
 * all sorts of funny things might happen.
 */
	mpi_teardown();
#endif
/*
 * It may cost less memory to reset john_main_process to 0 before fork()'ing
 * the children than to do it in every child process individually (triggering
 * copy-on-write of the entire page).  We then reset john_main_process back to
 * 1 in the parent, but this only costs one page, not one page per child.
 */
	john_main_process = 0;

	pids = mem_alloc_tiny((options.fork - 1) * sizeof(*pids),
	    sizeof(*pids));

	unsigned int range = options.node_max - options.node_min + 1;
	unsigned int npf = range / options.fork;

	for (i = 1; i < options.fork; i++) {
		switch ((pid = fork())) {
		case -1:
			pexit("fork");

		case 0:
			sig_preinit();
			if (rec_restoring_now) {
				unsigned int save_min = options.node_min;
				unsigned int save_max = options.node_max;
				unsigned int save_count = options.node_count;
				unsigned int save_fork = options.fork;
				options.node_min += i * npf;
				options.node_max = options.node_min + npf - 1;
				rec_done(-2);
				rec_restore_args(1);
				john_set_tristates();
				if (options.node_min != save_min ||
				    options.node_max != save_max ||
				    options.node_count != save_count ||
				    options.fork != save_fork)
					error_msg("Inconsistent crash recovery file: %s\n", rec_name);
			}
			options.node_min += i * npf;
			options.node_max = options.node_min + npf - 1;
#if HAVE_OPENCL
			/* Poor man's multi-device support */
			if (options.acc_devices->count &&
			    strstr(database.format->params.label, "-opencl")) {
				/* Postponed format init in forked process */
				fmt_init(database.format);
			}
#endif
#if HAVE_ZTEX
			if (strstr(database.format->params.label, "-ztex")) {
				list_init(&ztex_use_list);
				list_extract_list(ztex_use_list, ztex_detected_list,
					i * ztex_devices_per_fork, ztex_devices_per_fork);
				ztex_fork_num = i;
				usleep(i * 100000);
			}
#endif
			sig_init_child();
			return;

		default:
			pids[i - 1] = pid;
		}
	}

	options.node_max = options.node_min + npf - 1;

#if HAVE_OPENCL
	/* Poor man's multi-device support */
	if (options.acc_devices->count &&
	    strstr(database.format->params.label, "-opencl")) {
		/* Postponed format init in mother process */
		fmt_init(database.format);
	}
#endif
#if HAVE_ZTEX
	if (strstr(database.format->params.label, "-ztex")) {
		list_init(&ztex_use_list);
		list_extract_list(ztex_use_list, ztex_detected_list,
			0, ztex_devices_per_fork);
	}
#endif
	john_main_process = 1;
	john_child_pids = pids;
	john_child_count = options.fork - 1;
}

/*
 * This is the "equivalent" of john_fork() for MPI runs. We are mostly
 * mimicing a -fork run, especially for resuming a session.
 */
#if HAVE_MPI
static void john_set_mpi(void)
{
	unsigned int range = options.node_max - options.node_min + 1;
	unsigned int npf = range / mpi_p;

	if (mpi_p > 1) {
		if (!john_main_process) {
			if (rec_restoring_now) {
				unsigned int save_min = options.node_min;
				unsigned int save_max = options.node_max;
				unsigned int save_count = options.node_count;
				unsigned int save_fork = options.fork;
				options.node_min += mpi_id * npf;
				options.node_max = options.node_min + npf - 1;
				rec_done(-2);
				rec_restore_args(1);
				john_set_tristates();
				if (options.node_min != save_min ||
				    options.node_max != save_max ||
				    options.node_count != save_count ||
				    options.fork != save_fork)
					error_msg("Inconsistent crash recovery file: %s\n", rec_name);
			}
		}
	}
	options.node_min += mpi_id * npf;
	options.node_max = options.node_min + npf - 1;

	fflush(stdout);
	fflush(stderr);
}
#endif

static void john_wait(void)
{
	log_flush();

	/* Tell our friends there is nothing more to crack! */
	if (!database.password_count && !options.reload_at_crack &&
	    cfg_get_bool(SECTION_OPTIONS, NULL, "ReloadAtDone", 1))
		raise(SIGUSR2);

	if (!john_main_process)
		return;

	int waiting_for = john_child_count;

	log_event("Waiting for %d child%s to terminate",
	    waiting_for, waiting_for == 1 ? "" : "ren");
	fprintf(stderr, "Waiting for %d child%s to terminate\n",
	    waiting_for, waiting_for == 1 ? "" : "ren");

/*
 * Although we may block on wait(2), we still have signal handlers and a timer
 * in place, so we're relaying keypresses to child processes via signals.
 */
	while (waiting_for) {
		int i, status;
		int pid = wait(&status);
		if (pid == -1) {
			if (errno != EINTR)
				perror("wait");
		} else
		for (i = 0; i < john_child_count; i++) {
			if (john_child_pids[i] == pid) {
				john_child_pids[i] = 0;
				waiting_for--;
				children_ok = children_ok &&
				    WIFEXITED(status) && !WEXITSTATUS(status);
				break;
			}
		}
	}

/* Close and possibly remove our .rec file now */
	rec_done((children_ok && !event_abort) ? -1 : -2);
}
#endif

#if HAVE_MPI
static void john_mpi_wait(void)
{
	if (!database.password_count && !options.reload_at_crack) {
		int i;

		for (i = 0; i < mpi_p; i++) {
			if (i == mpi_id)
				continue;
			if (mpi_req[i] == NULL)
				mpi_req[i] = mem_alloc_tiny(sizeof(MPI_Request),
				                            MEM_ALIGN_WORD);
			else
				if (*mpi_req[i] != MPI_REQUEST_NULL)
					continue;
			MPI_Isend("r", 1, MPI_CHAR, i, JOHN_MPI_RELOAD,
			          MPI_COMM_WORLD, mpi_req[i]);
		}
	}

	if (john_main_process) {
		log_event("Waiting for other node%s to terminate",
		          mpi_p > 2 ? "s" : "");
		fprintf(stderr, "Waiting for other node%s to terminate\n",
		        mpi_p > 2 ? "s" : "");
		mpi_teardown();
	}

/* Close and possibly remove our .rec file now */
	rec_done(!event_abort ? -1 : -2);
}
#endif

char *john_loaded_counts(struct db_main *db, char *prelude)
{
	static char buf[128];
	char nbuf[24];

	if (db->password_count == 0)
		return "No remaining hashes";

	if (db->password_count == 1 && !options.regen_lost_salts) {
		sprintf(buf, "%s 1 password hash", prelude);
		return buf;
	}

	int salt_count = db->salt_count;

	/* At the time we say "Loaded xx hashes", the regen code hasn't yet updated the salt_count */
	if (options.regen_lost_salts && salt_count == 1)
		salt_count = regen_salts_count;

	int p = sprintf(buf, "%s %d password hash%s with %s %s salts", prelude, db->password_count,
	                db->password_count > 1 ? "es" : "",
	                salt_count > 1 ? jtr_itoa(salt_count, nbuf, 24, 10) : "no",
	                (salt_count > 1 && options.regen_lost_salts) ? "possible" : "different");

	if (p >= 0) {
		if (options.regen_lost_salts && db->password_count < salt_count) {
			int bf_penalty = 10 * salt_count / db->password_count;

			if (bf_penalty > 10)
				sprintf(buf + p, " (%d.%dx salt BF penalty)", bf_penalty / 10, bf_penalty % 10);
		} else {
			int bf_penalty = options.regen_lost_salts ? regen_salts_count : 1;
			int boost = (10 * bf_penalty * db->password_count + (salt_count / 2)) / salt_count;

			if (salt_count > 1 && boost > 10)
				sprintf(buf + p, " (%d.%dx same-salt boost)", boost / 10, boost % 10);
		}
	}

	return buf;
}

static void john_load_conf(void)
{
	int internal, target;

	if (!(options.flags & FLG_VERBOSITY)) {
		options.verbosity = cfg_get_int(SECTION_OPTIONS, NULL,
		                                "Verbosity");

		/* If it doesn't exist in john.conf it ends up as -1 */
		if (options.verbosity == -1)
			options.verbosity = VERB_DEFAULT;

		if (options.verbosity < 1 || options.verbosity > VERB_DEBUG) {
			if (john_main_process)
				fprintf(stderr, "Invalid verbosity level in "
				        "config file, use 1-%u (default %u)"
				        " or %u for debug\n",
				        VERB_MAX, VERB_DEFAULT, VERB_DEBUG);
			error();
		}
	}

	if (options.activepot == NULL) {
		if (options.secure)
			options.activepot = str_alloc_copy(SEC_POT_NAME);
		else
			options.activepot = str_alloc_copy(POT_NAME);
	}

	if (options.activewordlistrules == NULL)
		if (!(options.activewordlistrules =
		      cfg_get_param(SECTION_OPTIONS, NULL,
		                    "BatchModeWordlistRules")))
			options.activewordlistrules =
				str_alloc_copy(SUBSECTION_WORDLIST);

	if (options.activesinglerules == NULL)
		if (!(options.activesinglerules =
		      cfg_get_param(SECTION_OPTIONS, NULL,
		                    "SingleRules")))
			options.activesinglerules =
				str_alloc_copy(SUBSECTION_SINGLE);

	if ((options.flags & FLG_LOOPBACK_CHK) &&
	    !(options.flags & FLG_RULES_CHK)) {
		if ((options.activewordlistrules =
		     cfg_get_param(SECTION_OPTIONS, NULL,
		                   "LoopbackRules")))
			options.flags |= FLG_RULES_CHK;
	}

	if ((options.flags & FLG_WORDLIST_CHK) &&
	    !(options.flags & FLG_RULES_CHK)) {
		if ((options.activewordlistrules =
		     cfg_get_param(SECTION_OPTIONS, NULL,
		                   "WordlistRules")))
		{
			if (strlen(options.activewordlistrules) == 0)
				options.activewordlistrules = NULL;
			else
				options.flags |= FLG_RULES_CHK;
		}
	}

	/* EmulateBrokenEncoding feature */
	options.replacement_character = 0;
	if (cfg_get_bool(SECTION_OPTIONS, NULL, "EmulateBrokenEncoding", 0)) {
		const char *value;

		value = cfg_get_param(SECTION_OPTIONS, NULL, "ReplacementCharacter");
		if (value != NULL)
			options.replacement_character = value[0];
	}

	options.secure = cfg_get_bool(SECTION_OPTIONS, NULL, "SecureMode", 0);
	options.show_uid_in_cracks = cfg_get_bool(SECTION_OPTIONS, NULL, "ShowUIDinCracks", 0);
	options.reload_at_crack =
		cfg_get_bool(SECTION_OPTIONS, NULL, "ReloadAtCrack", 0);
	options.reload_at_save =
		cfg_get_bool(SECTION_OPTIONS, NULL, "ReloadAtSave", 1);
	options.abort_file = cfg_get_param(SECTION_OPTIONS, NULL, "AbortFile");
	options.pause_file = cfg_get_param(SECTION_OPTIONS, NULL, "PauseFile");

#if HAVE_OPENCL
	if (cfg_get_bool(SECTION_OPTIONS, SUBSECTION_OPENCL, "ForceScalar", 0))
		options.flags |= FLG_SCALAR;
#endif

	options.loader.log_passwords = options.secure ||
		cfg_get_bool(SECTION_OPTIONS, NULL, "LogCrackedPasswords", 0);

	if (!options.input_enc && !(options.flags & FLG_TEST_CHK)) {
		if ((options.flags & FLG_LOOPBACK_CHK) &&
		    cfg_get_bool(SECTION_OPTIONS, NULL, "UnicodeStoreUTF8", 0))
			options.input_enc = UTF_8;
		else {
			options.input_enc =
				cp_name2id(cfg_get_param(SECTION_OPTIONS, NULL, "DefaultEncoding"), 1);
		}
		options.default_enc = options.input_enc;
	}

	/* Pre-init in case some format's prepare() needs it */
	internal = options.internal_cp;
	target = options.target_enc;
	initUnicode(UNICODE_UNICODE);
	options.internal_cp = internal;
	options.target_enc = target;
	options.unicode_cp = CP_UNDEF;
}

static void john_load_conf_db(void)
{
	if (options.flags & FLG_STDOUT) {
		/* john.conf alternative for --internal-codepage */
		if (!options.internal_cp && options.target_enc == UTF_8 &&
		    (options.flags & (FLG_RULES_IN_USE | FLG_BATCH_CHK | FLG_MASK_CHK)))
			if (!(options.internal_cp =
			      cp_name2id(cfg_get_param(SECTION_OPTIONS, NULL, "DefaultInternalCodepage"), 1)))
				options.internal_cp =
					cp_name2id(cfg_get_param(SECTION_OPTIONS, NULL, "DefaultInternalEncoding"), 1);
	}

	if (!options.unicode_cp)
		initUnicode(UNICODE_UNICODE);

	options.report_utf8 = cfg_get_bool(SECTION_OPTIONS,
	                                     NULL, "AlwaysReportUTF8", 0);

	/* Unicode (UTF-16) formats may lack encoding support. We
	   must stop the user from trying to use it because it will
	   just result in false negatives. */
	if (database.format && options.target_enc != ENC_RAW && options.target_enc != ISO_8859_1 &&
	    database.format->params.flags & FMT_UNICODE && !(database.format->params.flags & FMT_ENC)) {
		if (john_main_process)
			fprintf(stderr, "This format does not yet support"
			        " other encodings than ISO-8859-1\n");
		error();
	}

	if (database.format && database.format->params.flags & FMT_UNICODE)
		options.store_utf8 = cfg_get_bool(SECTION_OPTIONS,
		                                  NULL, "UnicodeStoreUTF8", 0);
	else
		options.store_utf8 = options.target_enc != ENC_RAW && cfg_get_bool(SECTION_OPTIONS, NULL, "CPstoreUTF8", 0);

	if (options.target_enc != options.input_enc &&
	    options.input_enc != UTF_8) {
		if (john_main_process)
			fprintf(stderr, "Target encoding can only be specified"
			        " if input encoding is UTF-8\n");
		error();
	}

	if (john_main_process)
	if (!(options.flags & FLG_SHOW_CHK) && !options.loader.showuncracked) {
		if (options.flags & (FLG_PASSWD | FLG_WORDLIST_CHK |
		                     FLG_STDIN_CHK | FLG_PIPE_CHK))
		if (options.default_enc && options.input_enc != ENC_RAW)
			fprintf(stderr, "Using default input encoding: %s\n",
			        cp_id2name(options.input_enc));

		if (options.target_enc != options.input_enc &&
		    (!database.format ||
		     !(database.format->params.flags & FMT_UNICODE))) {
			if (options.default_target_enc)
				fprintf(stderr, "Using default target "
				        "encoding: %s\n",
				        cp_id2name(options.target_enc));
			else
				fprintf(stderr, "Target encoding: %s\n",
				        cp_id2name(options.target_enc));
		}

		if (options.input_enc != options.internal_cp)
		if (database.format &&
		    (database.format->params.flags & FMT_UNICODE))
			fprintf(stderr, "Rules/masks using %s\n",
			        cp_id2name(options.internal_cp));
	}
}

static void load_extra_pots(struct db_main *db, void (*process_file)(struct db_main *db, char *name))
{
	struct cfg_list *list;
	struct cfg_line *line;

	if ((list = cfg_get_list("List.Extra:", "Potfiles")))
	if ((line = list->head))
	do {
		struct stat s;
		char *name = (char*)path_expand(line->data);

		loaded_extra_pots = 1;

		if (!stat(name, &s) && s.st_mode & S_IFREG)
			process_file(db, name);
#if HAVE_DIRENT_H && HAVE_SYS_TYPES_H
		else if (s.st_mode & S_IFDIR) {
			DIR *dp;

			dp = opendir(name);
			if (dp != NULL) {
				struct dirent *ep;

				while ((ep = readdir(dp))) {
					char dname[2 * PATH_BUFFER_SIZE];
					char *p;

					if (!(p = strrchr(ep->d_name, '.')) ||
					    strcmp(p, ".pot"))
						continue;

					snprintf(dname, sizeof(dname), "%s/%s",
					         name, ep->d_name);

					if (!stat(dname, &s) &&
					    s.st_mode & S_IFREG)
						process_file(db, dname);
				}
				(void)closedir(dp);
			}
		}
#elif _MSC_VER || __MINGW32__
		else if (s.st_mode & S_IFDIR) {
			WIN32_FIND_DATA f;
			HANDLE h;
			char dname[PATH_BUFFER_SIZE];

			snprintf(dname, sizeof(dname), "%s/*.pot", name);
			h = FindFirstFile(dname, &f);

			if (h != INVALID_HANDLE_VALUE)
			do {
				snprintf(dname, sizeof(dname), "%s/%s",
				         name, f.cFileName);
				process_file(db, dname);
			} while (FindNextFile(h, &f));

			FindClose(h);
		}
#endif
	} while ((line = line->next));
}

static void john_load(void)
{
	struct list_entry *current;

#ifndef _MSC_VER
	umask(077);
#endif

	if (options.flags & FLG_EXTERNAL_CHK)
		ext_init(options.external, NULL);

	if (options.flags & FLG_MAKECHR_CHK) {
		options.loader.flags |= DB_CRACKED;
		ldr_init_database(&database, &options.loader);

		if (options.flags & FLG_PASSWD) {
			ldr_show_pot_file(&database, options.activepot);

			database.options->flags |= DB_PLAINTEXTS;
			if ((current = options.passwd->head))
			do {
				ldr_show_pw_file(&database, current->data);
			} while ((current = current->next));
		} else {
			database.options->flags |= DB_PLAINTEXTS;
			ldr_show_pot_file(&database, options.activepot);
		}

		return;
	}

	if (options.flags & FLG_STDOUT) {
		ldr_init_database(&database, &options.loader);
		database.format = &dummy_format;
		memset(&dummy_format, 0, sizeof(dummy_format));
		dummy_format.params.plaintext_length = options.length;
		dummy_format.params.flags = FMT_CASE | FMT_8_BIT | FMT_TRUNC;
		if (options.report_utf8 || options.target_enc == UTF_8)
			dummy_format.params.flags |= FMT_ENC;
		dummy_format.params.label = "stdout";
		dummy_format.methods.reset = &fmt_default_reset;
		dummy_format.methods.clear_keys = &fmt_default_clear_keys;

		if (!options.target_enc || options.input_enc != UTF_8)
			options.target_enc = options.input_enc;

		if (!(options.flags & FLG_LOOPBACK_CHK) &&
		    options.req_maxlength > options.length) {
			fprintf(stderr, "Can't set max length larger than %u "
			        "for stdout format\n", options.length);
			error();
		}
		if (options.verbosity <= 1)
			if (john_main_process)
				fprintf(stderr, "Warning: Verbosity decreased to minimum, candidates will not be printed!\n");
		john_load_conf_db();
	}

	if (options.flags & FLG_PASSWD) {
		int total;
		int i = 0;

		if (options.flags & FLG_SHOW_CHK) {
			options.loader.flags |= DB_CRACKED;
			ldr_init_database(&database, &options.loader);

			if (!options.loader.showformats) {
				ldr_show_pot_file(&database, options.activepot);
/*
 * Load optional extra (read-only) pot files. If an entry is a directory,
 * we read all files in it. We currently do NOT recurse.
 */
				load_extra_pots(&database, &ldr_show_pot_file);
			}

			if ((current = options.passwd->head))
			do {
				ldr_show_pw_file(&database, current->data);
			} while ((current = current->next));

			if (john_main_process && options.loader.showinvalid)
			fprintf(stderr,
			        "%d valid hash%s, %d invalid hash%s\n",
			        database.guess_count,
			        database.guess_count != 1 ? "es" : "",
			        database.password_count,
			        database.password_count != 1 ? "es" : "");
			else
			if (john_main_process && !options.loader.showformats)
			printf("%s%d password hash%s cracked, %d left\n",
				database.guess_count ? "\n" : "",
				database.guess_count,
				database.guess_count != 1 ? "es" : "",
				database.password_count -
				database.guess_count);

			if (options.loader.showformats &&
			    !options.loader.showformats_old)
				puts("]");

			fmt_all_done();

			return;
		}

		if (options.flags & (FLG_SINGLE_CHK | FLG_BATCH_CHK) &&
		    status.pass <= 1)
			options.loader.flags |= DB_WORDS;
		else
		if (mem_saving_level) {
			options.loader.flags &= ~DB_LOGIN;
			options.show_uid_in_cracks = 0;
		}

		if (mem_saving_level >= 2)
			options.max_wordfile_memory = 1;

		ldr_init_database(&database, &options.loader);

		if ((current = options.passwd->head))
		do {
			ldr_load_pw_file(&database, current->data);
		} while ((current = current->next));

		/* Process configuration options that depend on db/format */
		john_load_conf_db();

		if ((options.flags & FLG_CRACKING_CHK) &&
		    database.password_count) {
			log_init(LOG_NAME, NULL, options.session);
			if (john_main_process) {
				if (status_restored_time)
					log_event("Continuing an interrupted session");
				else
					log_event("Starting a new session");
				log_event("%s", john_loaded_counts(&database,
				                                   "Loaded a total of"));
			}
			/* only allow --device for OpenCL or ZTEX formats */
#if HAVE_OPENCL || HAVE_ZTEX
			if (options.acc_devices->count &&
			  !(strstr(database.format->params.label, "-opencl") ||
			    strstr(database.format->params.label, "-ztex"))) {
				if (john_main_process)
					fprintf(stderr,
					        "The \"--devices\" option is valid only for OpenCL or ZTEX formats\n");
				error();
			}
#endif

#if HAVE_OPENCL
			if (!strstr(database.format->params.label, "-opencl")) {
				if (options.lws) {
					if (john_main_process)
						fprintf(stderr,
						        "The \"--lws\" option is valid only for OpenCL formats\n");
					error();
				}
				if (options.gws) {
					if (john_main_process)
						fprintf(stderr,
						        "The \"--gws\" option is valid only for OpenCL formats\n");
					error();
				}
				if (options.flags & (FLG_SCALAR | FLG_VECTOR)) {
					if (john_main_process)
						fprintf(stderr,
						        "The \"--force-scalar\" and \"--force-vector\" options are valid only for OpenCL formats\n");
					error();
				}
			}
#endif

#if HAVE_ZTEX
			if (strstr(database.format->params.label, "-ztex")
					&& options.fork) {
				if (ztex_detected_list->count == 1) {
					fprintf(stderr, "Number of ZTEX devices must be "
						"a multiple of forks. "
						"With 1 device \"--fork\" is useless.\n");
					error();
				}
				if (ztex_detected_list->count % options.fork) {
					fprintf(stderr, "Number of ZTEX devices must be "
						"a multiple of forks. "
						"Suggesting to use \"--fork=%d\".\n",
						ztex_detected_list->count);
					error();
				}
				ztex_devices_per_fork
					= ztex_detected_list->count / options.fork;
			}
#endif
			/* make sure the format is properly initialized */
#if HAVE_OPENCL
			if (!(options.acc_devices->count && options.fork &&
			      strstr(database.format->params.label, "-opencl")))
#endif
			fmt_init(database.format);
			if (john_main_process)
			printf("%s (%s%s%s [%s])\n",
			    john_loaded_counts(&database, "Loaded"),
			    database.format->params.label,
			    database.format->params.format_name[0] ? ", " : "",
			    database.format->params.format_name,
			    database.format->params.algorithm_name);
		}

		total = database.password_count;

		ldr_load_pot_file(&database, options.activepot);

/*
 * Load optional extra (read-only) pot files. If an entry is a directory,
 * we read all files in it. We currently do NOT recurse.
 */
		load_extra_pots(&database, &ldr_load_pot_file);

		ldr_fix_database(&database);

		if (database.password_count && options.regen_lost_salts)
			build_fake_salts_for_regen_lost(&database);

		if (john_main_process && database.password_count < total) {
			int count = total - database.password_count;
			printf("Cracked %d password hash%s%s%s%s, use \"--show\"\n",
			    count, count != 1 ? "es" : "",
			    loaded_extra_pots ? "" : (count != 1 ? " (are in " : " (is in "),
			    loaded_extra_pots ? "" : path_expand(options.activepot),
			    loaded_extra_pots ? "" : ")");
		}

		if (!database.password_count) {
			log_discard();
			if (john_main_process)
			printf("No password hashes %s (see FAQ)\n",
			    total ? "left to crack" : "loaded");
			/* skip tunable cost reporting if no hashes were loaded */
			i = FMT_TUNABLE_COSTS;
		} else
		if (john_main_process && database.password_count < total) {
			log_event("%s", john_loaded_counts(&database, "Remaining"));
			printf("%s\n", john_loaded_counts(&database, "Remaining"));
		}

		if (john_main_process)
		for ( ; i < FMT_TUNABLE_COSTS &&
			      database.format->methods.tunable_cost_value[i] != NULL; i++) {
			if (database.min_cost[i] < database.max_cost[i]) {
				const char *loaded = database.password_count < total ? "Remaining" : "Loaded";
				log_event("%s hashes with cost %d (%s) varying from %u to %u",
				          loaded, i+1, database.format->params.tunable_cost_name[i],
				          database.min_cost[i], database.max_cost[i]);
				printf("%s hashes with cost %d (%s) varying from %u to %u\n",
				       loaded, i+1, database.format->params.tunable_cost_name[i],
				       database.min_cost[i], database.max_cost[i]);
			}
			else {	// if (database.min_cost[i] == database.max_cost[i]) {
				const char *loaded = database.password_count < total ? "remaining" : "loaded";
				log_event("Cost %d (%s) is %u for all %s hashes",
				          i+1, database.format->params.tunable_cost_name[i], database.min_cost[i], loaded);
				if (options.verbosity >= VERB_DEFAULT)
				printf("Cost %d (%s) is %u for all %s hashes\n",
				       i+1, database.format->params.tunable_cost_name[i], database.min_cost[i], loaded);
			}
		}

		if ((options.flags & FLG_PWD_REQ) && !database.salts)
			exit(0);
	}

/*
 * For --loopback mode:  Call the code normally used for --show, assembling
 * any password halves and producing a list of passwords that are later
 * processed in wordlist.c.  This code *only* fetches assembled passwords,
 * any single-hash words are fetched later by trivially reading the pot file.
 */
	if (options.flags & FLG_LOOPBACK_CHK) {
		struct db_main loop_db;
		struct fmt_main *saved_LM_next, *saved_DES_next, *saved_list;
		char *loop_pot = options.wordlist ? options.wordlist : options.activepot;

		/* This is a bit of hack, we need to restore these afterwards. */
		saved_list = fmt_list;
		saved_LM_next = fmt_LM.next;
		saved_DES_next = fmt_DES.next;

		/*
		 * For performance, build a temporary format list with
		 * only the "split formats".  We'll restore it later.
		 */
		fmt_list = &fmt_LM;
		fmt_list->next = &fmt_DES;
		fmt_list->next->next = NULL;

		options.loader.flags |= DB_CRACKED;
		ldr_init_database(&loop_db, &options.loader);

		ldr_show_pot_file(&loop_db, loop_pot);
		load_extra_pots(&loop_db, &ldr_show_pot_file);

		loop_db.options->flags |= DB_PLAINTEXTS;

		if ((current = options.passwd->head))
		do {
			ldr_show_pw_file(&loop_db, current->data);
		} while ((current = current->next));

		if (loop_db.plaintexts->count) {
			log_event("- Reassembled %d split passwords for "
			          "loopback", loop_db.plaintexts->count);
			if (john_main_process &&
			    options.verbosity >= VERB_DEFAULT)
				fprintf(stderr,
				        "Reassembled %d split passwords for "
				        "loopback\n",
				        loop_db.plaintexts->count);
		}
		database.plaintexts = loop_db.plaintexts;

		/* Restore anything we messed with (needed or not) */
		options.loader.flags &= ~DB_CRACKED;
		fmt_list = saved_list;
		fmt_DES.next = saved_DES_next;
		fmt_LM.next = saved_LM_next;

		ldr_free_db(&loop_db, 0);
	}

#ifdef _OPENMP
	john_omp_show_info();
#endif

	if (options.node_count) {
		if (john_main_process && options.node_min != options.node_max) {
			log_event("- Node numbers %u-%u of %u%s",
			    options.node_min, options.node_max,
#ifndef HAVE_MPI
			    options.node_count, options.fork ? " (fork)" : "");
#else
			    options.node_count, options.fork ? " (fork)" :
				    mpi_p > 1 ? " (MPI)" : "");
#endif
			fprintf(stderr, "Node numbers %u-%u of %u%s\n",
			    options.node_min, options.node_max,
#ifndef HAVE_MPI
			    options.node_count, options.fork ? " (fork)" : "");
#else
			    options.node_count, options.fork ? " (fork)" :
				    mpi_p > 1 ? " (MPI)" : "");
#endif
		} else if (john_main_process) {
			log_event("- Node number %u of %u",
			    options.node_min, options.node_count);
			fprintf(stderr, "Node number %u of %u\n",
			    options.node_min, options.node_count);
		}

#if OS_FORK
		if (options.fork) {
			/*
			 * flush before forking, to avoid multiple log entries
			 */
			log_flush();
			john_fork();
		}
#endif
#if HAVE_MPI
		if (mpi_p > 1)
			john_set_mpi();
#endif
	}
#if HAVE_OPENCL
	/*
	 * Check if the --devices list contains more OpenCL devices than the
	 * number of forks or MPI processes.
	 * Exception: mscash2-OpenCL has built-in multi-device support.
	 */
#if OS_FORK
	if (database.format &&
	    strstr(database.format->params.label, "-opencl") &&
	    !strstr(database.format->params.label, "mscash2-opencl") &&
#if HAVE_MPI
	    (mpi_p_local ? mpi_p_local : mpi_p) *
#endif
	    (options.fork ? options.fork : 1) < get_number_of_requested_devices())
	{
		int dev_as_number = 1;
		struct list_entry *current;

		if ((current = options.acc_devices->head)) {
			do {
				if (current->data[0] < '0' ||
				    current->data[0] > '9')
					dev_as_number = 0;
			} while ((current = current->next));
		}

		if (john_main_process)
		fprintf(stderr, "%s: To fully use the %d devices %s, "
		        "you must specify --fork=%d\n"
#if HAVE_MPI
		        "or run %d MPI processes per node "
#endif
		        "(see doc/README-OPENCL)\n",
		        dev_as_number ? "Error" : "Warning",
		        get_number_of_requested_devices(),
		        dev_as_number ? "requested" : "available",
#if HAVE_MPI
		        get_number_of_requested_devices(),
#endif
		        get_number_of_requested_devices());

		if (dev_as_number)
			error();
	}
#else
	if (database.format &&
	    strstr(database.format->params.label, "-opencl") &&
	    !strstr(database.format->params.label, "mscash2-opencl") &&
	    get_number_of_devices_in_use() > 1) {
		fprintf(stderr, "The usage of multiple OpenCL devices at once "
		      "is unsupported in this build for the selected format\n");
		error();
	}
#endif /* OS_FORK */
#endif /* HAVE_OPENCL */
}

#if CPU_DETECT
static void CPU_detect_or_fallback(char **argv, int make_check)
{
	if (!getenv("CPUID_DISABLE"))
	if (!CPU_detect()) {
#if CPU_REQ
#if CPU_FALLBACK || defined(CPU_FALLBACK_BINARY)
#if defined(__DJGPP__)
#error CPU_FALLBACK is incompatible with the current DOS code
#endif
		if (!make_check) {
#ifdef JOHN_SYSTEMWIDE_EXEC
#define CPU_FALLBACK_PATHNAME JOHN_SYSTEMWIDE_EXEC "/" CPU_FALLBACK_BINARY
#else
#define CPU_FALLBACK_PATHNAME path_expand("$JOHN/" CPU_FALLBACK_BINARY)
#endif
			execv(CPU_FALLBACK_PATHNAME, argv);
#ifdef JOHN_SYSTEMWIDE_EXEC
			perror("execv: " CPU_FALLBACK_PATHNAME);
#else
			perror("execv: $JOHN/" CPU_FALLBACK_BINARY);
#endif
		}
#endif
		fprintf(stderr, "Sorry, %s is required for this build\n",
		    CPU_req_name);
		if (make_check)
			exit(0);
		error();
#endif
	}

	/*
	 * Init the crc table here, so that tables are fully setup for any
	 * ancillary program
	 */
	CRC32_Init_tab();

}
#else
#define CPU_detect_or_fallback(argv, make_check) CRC32_Init_tab()
#endif

static void john_init(char *name, int argc, char **argv)
{
	int make_check = (argc == 2 && !strcmp(argv[1], "--make_check"));
	if (make_check)
		argv[1] = "--test=0";

	CPU_detect_or_fallback(argv, make_check);

#ifdef _OPENMP
	john_omp_init();
#endif

	if (!make_check) {
#ifdef HAVE_JOHN_OMP_FALLBACK
		john_omp_fallback(argv);
#endif
	}

#if HAVE_MPI
	mpi_setup(argc, argv);
#else
	if (getenv("OMPI_COMM_WORLD_SIZE") && atoi(getenv("OMPI_COMM_WORLD_SIZE")) > 1)
		error_msg("ERROR: Running under MPI, but this is not an MPI build of John.\n");
#endif

#if (!AC_BUILT || HAVE_LOCALE_H)
	if (setlocale(LC_CTYPE, "")) {
		char *parsed = setlocale(LC_CTYPE, NULL);

		if (parsed) {
			char *p;

			john_terminal_locale = str_alloc_copy(parsed);
			if ((p = strchr(john_terminal_locale, '.')))
				parsed = ++p;
			if (strcmp(parsed, "C"))
				options.terminal_enc = cp_name2id(parsed, 0);
		}
#if HAVE_OPENCL
		if (options.terminal_enc)
			sprintf(gpu_degree_sign, "%ls", DEGREE_SIGN);
#endif
		/* We misuse ctype macros so this must be reset */
		setlocale(LC_CTYPE, "C");
	}
#endif

	status_init(NULL, 1);
	opt_init(name, argc, argv);

	if (options.listconf)
		listconf_parse_early();

	if (!make_check) {
		if (options.config) {
			cfg_init(options.config, 0);
#if JOHN_SYSTEMWIDE
			cfg_init(CFG_PRIVATE_FULL_NAME, 1);
#endif
			cfg_init(CFG_FULL_NAME, 1);
		}
		else {
#if JOHN_SYSTEMWIDE
			cfg_init(CFG_PRIVATE_FULL_NAME, 1);
#endif
			cfg_init(CFG_FULL_NAME, 0);
		}
	}

#if HAVE_OPENCL
	gpu_id = NO_GPU;
	engaged_devices[0] = engaged_devices[1] = DEV_LIST_END;
#endif
	/* Process configuration options that depend on cfg_init() */
	john_load_conf();

	/* Stuff that need to be reset again after rec_restore_args */
	john_set_tristates();

#ifdef _OPENMP
	john_omp_maybe_adjust_or_fallback(argv);
#endif
	omp_autotune_init();
	if (!(options.flags & FLG_STDOUT))
		john_register_all(); /* maybe restricted to one format by options */
	common_init();
	sig_preinit();
	sig_init();

	if (!make_check && !(options.flags & (FLG_SHOW_CHK | FLG_STDOUT))) {
		fflush(stdout);
#ifdef _MSC_VER
		/* VC allows 2<=len<=INT_MAX and be a power of 2. A debug build will
		 * assert if len=0. Release fails setvbuf, but execution continues */
		setvbuf(stdout, NULL, _IOLBF, 256);
#else
		setvbuf(stdout, NULL, _IOLBF, 0);
#endif
	}

	john_load();

	/* Init the Unicode system */
	if (options.internal_cp) {
		if (options.internal_cp != options.input_enc &&
		    options.input_enc != UTF_8) {
			if (john_main_process)
			fprintf(stderr, "-internal-codepage can only be "
			        "specified if input encoding is UTF-8\n");
			error();
		}
	}

	if (!options.unicode_cp)
		initUnicode(UNICODE_UNICODE);

	if ((options.subformat && !strcasecmp(options.subformat, "list")) ||
	    options.listconf)
		listconf_parse_late();

	/* Log the expanded command line used for this session. */
	if (john_main_process) {
		int i;
		size_t s = 1;
		char *cl;

		for (i = 0; i < argc; i++)
			s += strlen(argv[i]) + 1;
		cl = mem_alloc(s);

		s = 0;
		for (i = 0; i < argc; i++)
			s += sprintf(cl + s, "%s ", argv[i]);

		log_event("Command line: %s", cl);
		MEM_FREE(cl);
	}

#if HAVE_MPI
	if (mpi_p > 1)
		log_event("- MPI: Node %u/%u running on %s",
		          mpi_id + 1, mpi_p, mpi_name);
#endif
#if defined(HAVE_OPENCL)
	gpu_log_temp();
#endif

	if (john_main_process && options.target_enc != ENC_RAW) {
		log_event("- %s input encoding enabled",
		          cp_id2name(options.input_enc));

		if (!options.secure) {
			if (options.report_utf8 &&
			    options.loader.log_passwords)
				log_event("- Passwords in this logfile are "
				    "UTF-8 encoded");

			if (options.store_utf8)
				log_event("- Passwords will be stored UTF-8 "
				    "encoded in .pot file");
		}
	}

	if (!(options.flags & FLG_SHOW_CHK) && !options.loader.showuncracked)
	if (john_main_process && options.target_enc != options.input_enc &&
	    (!database.format ||
	     !(database.format->params.flags & FMT_UNICODE))) {
		log_event("- Target encoding: %s",
		          cp_id2name(options.target_enc));
	}

	if (!(options.flags & FLG_SHOW_CHK) && !options.loader.showuncracked)
	if (john_main_process && options.input_enc != options.internal_cp) {
		log_event("- Rules/masks using %s",
		          cp_id2name(options.internal_cp));
	}
}

static void john_run(void)
{
	struct stat trigger_stat;

	if (options.flags & FLG_TEST_CHK)
		exit_status = benchmark_all() ? 1 : 0;
#ifdef HAVE_FUZZ
	else
	if (options.flags & FLG_FUZZ_CHK || options.flags & FLG_FUZZ_DUMP_CHK) {
		/*
		 * Suppress dupe hash check because fuzzed ones often result in
		 * too many partial hash collisions.
		 */
		options.loader.flags |= DB_WORDS;
		list_init(&single_seed); /* Required for DB_WORDS */

		exit_status = fuzz(&database);
	}
#endif
	else
	if (options.flags & FLG_MAKECHR_CHK)
		do_makechars(&database, options.charset);
	else
	if (options.flags & FLG_CRACKING_CHK) {
		int remaining = database.password_count;

		if (options.abort_file &&
		    stat(path_expand(options.abort_file), &trigger_stat) == 0) {
			if (john_main_process)
			fprintf(stderr, "Abort file %s present, "
			        "refusing to start\n", options.abort_file);
			error();
		}

		if (!(options.flags & FLG_STDOUT)) {
			struct db_main *test_db = 0;
			char *where;

			if (!(options.flags & FLG_NOTESTS))
				test_db = ldr_init_test_db(database.format,
				                           &database);
			else
				test_db = &database;
			where = fmt_self_test(database.format, test_db);
			if (!(options.flags & FLG_NOTESTS))
				ldr_free_db(test_db, 1);
			if (where) {
				fprintf(stderr, "Self test failed (%s)\n",
				    where);
				error();
			}
			log_init(LOG_NAME, options.activepot,
			         options.session);
			status_init(NULL, 1);
			if (john_main_process) {
				john_log_format();
				if (idle_requested(database.format))
					log_event("- Configured to use otherwise idle "
					          "processor cycles only");
				/*
				 * flush log entries to make sure they appear
				 * before the "Proceeding with ... mode" entries
				 * of other processes
				 */
				log_flush();
			}
		}
		tty_init(options.flags & (FLG_STDIN_CHK | FLG_PIPE_CHK));

		/* Format supports internal (eg. GPU-side) mask */
		if (database.format->params.flags & FMT_MASK &&
		    !(options.flags & FLG_MASK_CHK) && john_main_process)
			fprintf(stderr, "Note: This format may be a lot faster with --mask acceleration (see doc/MASK).\n");

		/* Some formats truncate at max. length */
		if (!(database.format->params.flags & FMT_TRUNC) &&
		    !options.force_maxlength)
			options.force_maxlength =
			    database.format->params.plaintext_length;

		if (john_main_process && options.force_maxlength)
			log_event("- Will reject candidates longer than %d %s",
				  options.force_maxlength,
				  (options.target_enc == UTF_8) ?
				  "bytes" : "characters");

		options.eff_minlength = options.req_minlength >= 0 ?
			options.req_minlength :
			database.format->params.plaintext_min_length;
		options.eff_maxlength = options.req_maxlength ?
			MIN(options.req_maxlength,
			    database.format->params.plaintext_length) :
			database.format->params.plaintext_length;

		/* Tell External our max length */
		if (options.flags & FLG_EXTERNAL_CHK)
			ext_init(options.external, &database);

		/* Some formats have a minimum plaintext length */
		if (options.eff_maxlength < options.eff_minlength) {
			if (john_main_process)
				fprintf(stderr, "Invalid option: "
				        "--max-length smaller than "
				        "minimum length\n");
			error();
		}
		if (options.req_minlength >= 0) {
			if (options.req_minlength <
			    database.format->params.plaintext_min_length) {
				if (john_main_process)
					fprintf(stderr, "Note: --min-length set smaller than "
					        "normal minimum length for format\n");
			}
		} else if (database.format->params.plaintext_min_length)
			if (john_main_process)
				fprintf(stderr,
				        "Note: Minimum length forced to %d "
				        "by format\n",
				        options.eff_minlength);

		if (options.flags & FLG_MASK_CHK)
			mask_init(&database, options.mask);

		omp_autotune_run(&database);

		clock_t before = status_get_raw_time();

		database.format->methods.reset(&database);

		clock_t after = status_get_raw_time();

		/* Disregard OpenCL build & autotune time, for stable ETA and speed figures */
		status.start_time += (after - before);

		if (!(options.flags & FLG_STDOUT) && john_main_process) {
			john_log_format2();
			log_flush();
		}

		if (options.flags & FLG_MASK_CHK)
			mask_crk_init(&database);

		/* Start our timers */
		sig_init_late();

		/* Start a resumed session by emitting a status line. */
		if (rec_restored)
			event_pending = event_status = 1;

		if (options.flags & FLG_SINGLE_CHK)
			mode_exit_message = do_single_crack(&database);
		else
		if (options.flags & FLG_WORDLIST_CHK)
			do_wordlist_crack(&database, options.wordlist,
				(options.flags & FLG_RULES_CHK) != 0);
#if HAVE_LIBGMP || HAVE_INT128 || HAVE___INT128 || HAVE___INT128_T
		else
		if (options.flags & FLG_PRINCE_CHK)
			do_prince_crack(&database, options.wordlist,
			                (options.flags & FLG_RULES_CHK) != 0);
#endif
		else
		if (options.flags & FLG_INC_CHK)
			do_incremental_crack(&database, options.charset);
		else
		if (options.flags & FLG_MKV_CHK)
			do_markov_crack(&database, options.mkv_param);
		else
		if (options.flags & FLG_SUBSETS_CHK)
			do_subsets_crack(&database, options.subset_full);
		else
#if HAVE_REXGEN
		if ((options.flags & FLG_REGEX_CHK) &&
		    !(options.flags & FLG_REGEX_STACKED))
			do_regex_crack(&database, options.regex);
		else
#endif
		if ((options.flags & FLG_MASK_CHK) &&
		    !(options.flags & FLG_MASK_STACKED))
			do_mask_crack(NULL);
		else
		if (options.flags & FLG_EXTERNAL_CHK)
			do_external_crack(&database);
		else
		if (options.flags & FLG_BATCH_CHK)
			do_batch_crack(&database);

		if (options.flags & FLG_MASK_CHK)
			mask_done();

		status_print(0);

		if (options.flags & FLG_MASK_CHK)
			mask_destroy();

#if OS_FORK
		if (options.fork)
			john_wait();
#endif

#if HAVE_MPI
		if (mpi_p > 1)
			john_mpi_wait();
#endif

		tty_done();

		if (options.verbosity > 1)
		if (john_main_process && database.password_count < remaining) {
			char *might = "Warning: passwords printed above might";
			char *partial = " be partial";
			char *not_all = " not be all those cracked";
			switch (database.options->flags &
			    (DB_SPLIT | DB_NODUP)) {
			case DB_SPLIT:
				fprintf(stderr, "%s%s\n", might, partial);
				break;
			case DB_NODUP:
				fprintf(stderr, "%s%s\n", might, not_all);
				break;
			case (DB_SPLIT | DB_NODUP):
				fprintf(stderr, "%s%s and%s\n",
				    might, partial, not_all);
			}
			if (database.format->methods.prepare !=
			    fmt_default_prepare)
				fprintf(stderr,
				        "Use the \"--show --format=%s\" options"
				        " to display all of the cracked "
				        "passwords reliably\n",
				        database.format->params.label);
			else
				fputs("Use the \"--show\" option to display all"
				      " of the cracked passwords reliably\n",
				      stderr);
		}
	}
}

static void john_done(void)
{
	if ((options.flags & (FLG_CRACKING_CHK | FLG_STDOUT)) ==
	    FLG_CRACKING_CHK) {
		if (!event_abort && mask_iter_warn) {
			log_event("Warning: Incremental mask started at length %d",
			          mask_iter_warn);
			if (john_main_process)
				fprintf(stderr,
				        "Warning: incremental mask started at length %d"
				        " - try the CPU format for shorter lengths.\n",
				        mask_iter_warn);
		}
		if (event_abort && options.catchup && john_max_cands && status.cands >= john_max_cands) {
			event_abort = 0;
			log_event("Done catching up with '%s'", options.catchup);
			if (john_main_process)
				fprintf(stderr, "Done catching up with '%s'\n", options.catchup);
		}
		if (event_abort) {
			char *abort_msg = (aborted_by_timer) ?
			          "Session stopped (max run-time reached)" :
			          "Session aborted";

			if (john_max_cands) {
				if (status.cands >= john_max_cands)
					abort_msg =
						"Session stopped (max candidates reached)";
			}

			/* We already printed to stderr from signals.c */
			log_event("%s", abort_msg);
		} else if (children_ok) {
			log_event("Session completed");
			if (john_main_process) {
				fprintf(stderr, "Session completed. %s\n", mode_exit_message);
			}
		} else {
			const char *msg =
			    "Main process session completed, "
			    "but some child processes failed";
			log_event("%s", msg);
			fprintf(stderr, "%s\n", msg);
			exit_status = 1;
		}
		fmt_done(database.format);
	}
#if defined(HAVE_OPENCL)
	gpu_log_temp();
#endif
	log_done();
#if HAVE_OPENCL
	if (!(options.flags & FLG_FORK) || john_main_process)
		opencl_done();
#endif

	path_done();

	ldr_free_db(&database, 0);
	cleanup_tiny_memory();
	check_abort(0);
}

#ifdef HAVE_LIBFUZZER
int main_dummy(int argc, char **argv)
#else
int main(int argc, char **argv)
#endif
{
	char *name;

#ifdef __DJGPP__
	if (--argc <= 0) return 1;
	if ((name = strrchr(argv[0], '/')))
		strcpy(name + 1, argv[1]);
	name = argv[1];
	argv[1] = argv[0];
	argv++;
#else
	if (!argv[0])
		name = "john";
	else
	if ((name = strrchr(argv[0], '/')))
		name++;
#if HAVE_WINDOWS_H
	else
	if ((name = strrchr(argv[0], '\\')))
		name++;
#endif
	else
		name = argv[0];
#endif

#if defined(__CYGWIN__) || defined (__MINGW32__) || defined (_MSC_VER)
	strlwr(name);
	if (strlen(name) > 4 && !strcmp(name + strlen(name) - 4, ".exe"))
		name[strlen(name) - 4] = 0;
#endif

#ifdef _MSC_VER
/*
 * Ok, I am making a simple way to debug external programs. in VC.  Prior to
 * this, I would set break point below, right where the external name is, and
 * then would modify IP to put me into the block that calls main() from the
 * external.  Now, in VC mode, if the first command is:
 * -external_command=COMMAND, then I set name == COMMAND, and pop the command
 * line args off, just like the first one was not there.  So if the command was
 * "-external_command=gpg2john secring.gpg" then we will be setup in gpg2john
 * mode with command line arg of secring.gpg
 */
	if (argc > 2 && !strncmp(argv[1], "-external_command=", 18)) {
		int i;
		name = &argv[1][18];
		for (i = 1; i < argc; ++i) {
			argv[i] = argv[i+1];
		}
		--argc;
	}
#endif

#if CPU_FALLBACK || OMP_FALLBACK || defined(CPU_FALLBACK_BINARY) || defined(OMP_FALLBACK_BINARY)
	/* Needed before CPU fallback */
	path_init(argv);
#endif

	if (!strcmp(name, "unshadow")) {
		CPU_detect_or_fallback(argv, 0);
		return unshadow(argc, argv);
	}

	if (!strcmp(name, "unafs")) {
		CPU_detect_or_fallback(argv, 0);
		return unafs(argc, argv);
	}

	if (!strcmp(name, "undrop")) {
		CPU_detect_or_fallback(argv, 0);
		return undrop(argc, argv);
	}

	if (!strcmp(name, "unique")) {
		CPU_detect_or_fallback(argv, 0);
		return unique(argc, argv);
	}

	if (!strcmp(name, "rar2john")) {
		CPU_detect_or_fallback(argv, 0);
		return rar2john(argc, argv);
	}

	if (!strcmp(name, "gpg2john")) {
		CPU_detect_or_fallback(argv, 0);
		return gpg2john(argc, argv);
	}

	if (!strcmp(name, "zip2john")) {
		CPU_detect_or_fallback(argv, 0);
		return zip2john(argc, argv);
	}

	if (!strcmp(name, "base64conv")) {
		CPU_detect_or_fallback(argv, 0);
		return base64conv(argc, argv);
	}

#if !(CPU_FALLBACK || OMP_FALLBACK || defined(CPU_FALLBACK_BINARY) || defined(OMP_FALLBACK_BINARY))
	path_init(argv);
#endif

	john_init(name, argc, argv);

	if (options.max_cands) {
		if (options.node_count) {
			long long orig_max_cands = options.max_cands;

			/* Split between nodes */
			options.max_cands /= options.node_count;
			if (options.node_min == 1)
				options.max_cands +=
					orig_max_cands % options.node_count;
		}

		/* Allow resuming, for another set of N candidates */
		john_max_cands = status.cands + llabs(options.max_cands);
	}

	john_run();
	john_done();

	return exit_status;
}

#ifdef HAVE_LIBFUZZER

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	return 1;
}

// dummy fuzzing target
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)  // size is actually the length of Data
{
	static uint8_t buffer[8192];

	if (size > sizeof(buffer) - 1) {
		fprintf(stderr, "size (-max_len) is greater than supported value, aborting!\n");
		exit(-1);
	}
	memcpy(buffer, data, size);
	buffer[size] = 0;
	jtr_basename((const char*)buffer);

	return 0;
}
#endif
