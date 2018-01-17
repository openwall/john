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
#include "external.h"
#include "batch.h"
#include "dynamic.h"
#include "dynamic_compiler.h"
#include "fake_salts.h"
#include "listconf.h"
#include "crc32.h"
#if HAVE_MPI
#include "john-mpi.h"
#endif
#include "regex.h"

#include "unicode.h"
#if HAVE_OPENCL
#include "common-gpu.h"
#endif
#if HAVE_OPENCL
#include "common-opencl.h"
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
#include "memdbg.h"

#if CPU_DETECT
extern int CPU_detect(void);
extern char CPU_req_name[];
#endif

extern struct fmt_main fmt_DES, fmt_BSDI, fmt_MD5, fmt_BF;
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
char *john_terminal_locale ="C";

unsigned long long john_max_cands;

static int children_ok = 1;

static struct db_main database;
static struct fmt_main dummy_format;

static int exit_status = 0;

static void john_register_one(struct fmt_main *format)
{
	static int override_disable = 0;

	if (options.format && !strcasecmp(options.format, "all")) {
		override_disable = 1;
		options.format = NULL;
	} else
	if (options.format && !strncasecmp(options.format, "all-", 4)) {
		override_disable = 1;
		options.format += 4;
	}

	if (options.format) {
		char *pos = strchr(options.format, '*');

		if (!strncasecmp(options.format, "dynamic=", 8))
			pos = NULL;
		else
		if (pos != strrchr(options.format, '*')) {
			if (john_main_process)
			fprintf(stderr, "Only one wildcard allowed in format "
			        "name\n");
			error();
		}

		if (pos) {
			/* Wildcard, as in --format=office* */
			if (strncasecmp(format->params.label, options.format,
			                (int)(pos - options.format)))
				return;
			/* Trailer wildcard, as in *office or raw*ng */
			if (pos[1]) {
				int wild_len = strlen(++pos);
				int label_len = strlen(format->params.label);
				const char *p;

				if (wild_len > label_len)
					return;

				p = &format->params.label[label_len - wild_len];

				if (strcasecmp(p, pos))
					return;
			}
		} else if (strncasecmp(options.format, "dynamic=", 8) &&
		           (pos = strchr(options.format, '@'))) {
			char *reject, *algo = strdup(++pos);

			/* Rejections */
			if ((reject = strcasestr(algo, "-dynamic"))) {
				if (format->params.flags & FMT_DYNAMIC) {
					MEM_FREE (algo);
					return;
				}
				memmove(reject, reject + 8, strlen(reject + 7));
			}
			if ((reject = strcasestr(algo, "-opencl"))) {
				if (strstr(format->params.label, "-opencl")) {
					MEM_FREE (algo);
					return;
				}
				memmove(reject, reject + 7, strlen(reject + 6));
			}
			/* Algo match, eg. --format=@xop or --format=@sha384 */
			if (!strcasestr(format->params.algorithm_name, algo)) {
				MEM_FREE (algo);
				return;
			}
			MEM_FREE (algo);
		}
		else if (!strcasecmp(options.format, "dynamic") ||
			 !strcasecmp(options.format, "dynamic-all")) {
			if ((format->params.flags & FMT_DYNAMIC) == 0)
				return;
		}
		else if (!strcasecmp(options.format, "cpu")) {
			if (strstr(format->params.label, "-opencl"))
				return;
		}
		else if (!strcasecmp(options.format, "cpu-dynamic")) {
			if (strstr(format->params.label, "-opencl"))
				return;
			if (format->params.flags & FMT_DYNAMIC)
				return;
		}
		else if (!strcasecmp(options.format, "opencl")) {
			if (!strstr(format->params.label, "-opencl"))
				return;
		}
#ifdef _OPENMP
		else if (!strcasecmp(options.format, "omp")) {
			if ((format->params.flags & FMT_OMP) != FMT_OMP)
				return;
		}
		else if (!strcasecmp(options.format, "cpu+omp")) {
			if ((format->params.flags & FMT_OMP) != FMT_OMP)
				return;
			if (strstr(format->params.label, "-opencl"))
				return;
		}
		else if (!strcasecmp(options.format, "cpu+omp-dynamic")) {
			if ((format->params.flags & FMT_OMP) != FMT_OMP)
				return;
			if (strstr(format->params.label, "-opencl"))
				return;
			if (format->params.flags & FMT_DYNAMIC)
				return;
		}
#endif
		else if (strcasecmp(options.format, format->params.label)) {
#ifndef DYNAMIC_DISABLED
			if (!strncasecmp(options.format, "dynamic=", 8) &&
			    !strcasecmp(format->params.label, "dynamic=")) {
				DC_HANDLE H;
				if (!dynamic_compile(options.format, &H)) {
					if (dynamic_assign_script_to_format(
						    H, format))
						return;
				} else
					return;
			} else
#endif
				return;
		}
	}

	/* Format disabled in john.conf */
	if (!override_disable &&
	    cfg_get_bool(SECTION_DISABLED, SUBSECTION_FORMATS,
	                 format->params.label, 0)) {
#ifdef DEBUG
		if (format->params.flags & FMT_DYNAMIC) {
			/* in debug mode, we 'allow' dyna */
		} else
#else
		if (options.format &&
		    !strcasecmp(options.format, "dynamic-all") &&
		    (format->params.flags & FMT_DYNAMIC)) {
			/* allow dyna if '-format=dynamic-all' was selected */
		} else
#endif
		if (options.format &&
		    !strcasecmp(options.format, format->params.label)) {
			/* allow if specifically requested */
		} else
			return;
	}

	fmt_register(format);
}

static void john_register_all(void)
{
#ifndef DYNAMIC_DISABLED
	int i, cnt;
	struct fmt_main *selfs;
#endif

	if (options.format) {
	/* The case of the expression for this format is significant */
		if (strncasecmp(options.format, "dynamic=", 8))
			strlwr(options.format);
	}

	/* Let ZTEX format appear before CPU format */
#ifdef HAVE_ZTEX
	john_register_one(&fmt_ztex_descrypt);
	john_register_one(&fmt_ztex_bcrypt);
#endif
	john_register_one(&fmt_DES);
	john_register_one(&fmt_BSDI);
	john_register_one(&fmt_MD5);
	john_register_one(&fmt_BF);
	john_register_one(&fmt_scrypt);
	john_register_one(&fmt_LM);
	john_register_one(&fmt_AFS);
	john_register_one(&fmt_trip);

	/* Add all plug-in formats */
#include "fmt_registers.h"

	/* This format is deprecated so registers after plug-in NT formats */
	john_register_one(&fmt_NT);

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

	if (!fmt_list) {
		if (john_main_process)
		fprintf(stderr, "Unknown ciphertext format name requested\n");
		error();
	}
}

static void john_log_format(void)
{
	int min_chunk, chunk;
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

	chunk = min_chunk = database.format->params.max_keys_per_crypt;
	if (options.flags & (FLG_SINGLE_CHK | FLG_BATCH_CHK) &&
	    chunk < SINGLE_HASH_MIN)
			chunk = SINGLE_HASH_MIN;
	if (chunk > 1)
		log_event("- Candidate passwords %s be buffered and "
			"tried in chunks of %d",
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

#if OMP_FALLBACK
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
#if HAVE_MPI
		mpi_teardown();
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
	if (john_main_process)
		fputs("Warning: OpenMP is disabled; "
		    "a non-OpenMP build may be faster\n", stderr);
}
#endif

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

	for (i = 1; i < options.fork; i++) {
		switch ((pid = fork())) {
		case -1:
			pexit("fork");

		case 0:
			sig_preinit();
			options.node_min += i;
			options.node_max = options.node_min;
#if HAVE_OPENCL
			/* Poor man's multi-device support */
			if (options.acc_devices->count &&
			    strstr(database.format->params.label, "-opencl")) {
				/* Pick device to use for this child */
				opencl_preinit();
				gpu_id =
				    requested_devices[i % get_number_of_requested_devices()];
				platform_id = get_platform_id(gpu_id);

				/* Hide any other devices from list */
				gpu_device_list[0] = gpu_id;
				gpu_device_list[1] = -1;

				/* Postponed format init in forked process */
				fmt_init(database.format);
			}
#endif
			if (rec_restoring_now) {
				unsigned int node_id = options.node_min;
				rec_done(-2);
				rec_restore_args(1);
				if (node_id != options.node_min + i)
					fprintf(stderr,
					    "Inconsistent crash recovery file:"
					    " %s\n", rec_name);
				options.node_min = options.node_max = node_id;
			}
			sig_init_child();
			return;

		default:
			pids[i - 1] = pid;
		}
	}

#if HAVE_OPENCL
	/* Poor man's multi-device support */
	if (options.acc_devices->count &&
	    strstr(database.format->params.label, "-opencl")) {
		/* Pick device to use for mother process */
		opencl_preinit();
		gpu_id = gpu_device_list[0];
		platform_id = get_platform_id(gpu_id);

		/* Hide any other devices from list */
		gpu_device_list[1] = -1;

		/* Postponed format init in mother process */
		fmt_init(database.format);
	}
#endif
	john_main_process = 1;
	john_child_pids = pids;
	john_child_count = options.fork - 1;

	options.node_max = options.node_min;
}

/*
 * This is the "equivalent" of john_fork() for MPI runs. We are mostly
 * mimicing a -fork run, especially for resuming a session.
 */
#if HAVE_MPI
static void john_set_mpi(void)
{
	options.node_min += mpi_id;
	options.node_max = options.node_min;

	if (mpi_p > 1) {
		if (!john_main_process) {
			if (rec_restoring_now) {
				unsigned int node_id = options.node_min;
				rec_done(-2);
				rec_restore_args(1);
				if (node_id != options.node_min + mpi_id)
					fprintf(stderr,
					    "Inconsistent crash recovery file:"
					    " %s\n", rec_name);
				options.node_min = options.node_max = node_id;
			}
		}
	}
	fflush(stdout);
	fflush(stderr);
}
#endif

static void john_wait(void)
{
	int waiting_for = john_child_count;

	log_event("Waiting for %d child%s to terminate",
	    waiting_for, waiting_for == 1 ? "" : "ren");
	log_flush();
	fprintf(stderr, "Waiting for %d child%s to terminate\n",
	    waiting_for, waiting_for == 1 ? "" : "ren");

	log_flush();

	/* Tell our friends there is nothing more to crack! */
	if (!database.password_count && !options.reload_at_crack &&
	    cfg_get_bool(SECTION_OPTIONS, NULL, "ReloadAtDone", 0))
		raise(SIGUSR2);

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

static char *john_loaded_counts(void)
{
	static char s_loaded_counts[80];
	char nbuf[24];

	if (database.password_count == 1)
		return "1 password hash";

	sprintf(s_loaded_counts,
		"%d password hashes with %s different salts",
		database.password_count,
		database.salt_count > 1 ?
		jtr_itoa(database.salt_count, nbuf, 24, 10) : "no");

	return s_loaded_counts;
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

		if (options.verbosity < 1 || options.verbosity > VERB_MAX) {
			if (john_main_process)
				fprintf(stderr, "Invalid verbosity level in "
				        "config file, use 1-%u\n", VERB_MAX);
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
	    !(options.flags & FLG_RULES)) {
		if ((options.activewordlistrules =
		     cfg_get_param(SECTION_OPTIONS, NULL,
		                   "LoopbackRules")))
			options.flags |= FLG_RULES;
	}

	if ((options.flags & FLG_WORDLIST_CHK) &&
	    !(options.flags & FLG_RULES)) {
		if ((options.activewordlistrules =
		     cfg_get_param(SECTION_OPTIONS, NULL,
		                   "WordlistRules")))
			options.flags |= FLG_RULES;
	}

	/* EmulateBrokenEncoding feature */
	options.replacement_character = 0;
	if (cfg_get_bool(SECTION_OPTIONS, NULL, "EmulateBrokenEncoding", 0)) {
		char *value;

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

	/* This is --crack-status. We toggle here, so if it's enabled in
	   john.conf, we can disable it using the command line option */
	if (cfg_get_bool(SECTION_OPTIONS, NULL, "CrackStatus", 0))
		options.flags ^= FLG_CRKSTAT;

#if HAVE_OPENCL
	if (cfg_get_bool(SECTION_OPTIONS, SUBSECTION_OPENCL, "ForceScalar", 0))
		options.flags |= FLG_SCALAR;
#endif

	options.loader.log_passwords = options.secure ||
		cfg_get_bool(SECTION_OPTIONS, NULL, "LogCrackedPasswords", 0);

	if (!options.input_enc && !(options.flags & FLG_TEST_CHK)) {
		if ((options.flags & FLG_LOOPBACK_CHK) &&
		    cfg_get_bool(SECTION_OPTIONS, NULL, "UnicodeStoreUTF8", 0))
			options.input_enc = cp_name2id("UTF-8");
		else {
			options.input_enc =
				cp_name2id(cfg_get_param(SECTION_OPTIONS, NULL,
				                          "DefaultEncoding"));
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
		if (!options.internal_cp &&
		    options.target_enc == UTF_8 && options.flags &
		    (FLG_RULES | FLG_SINGLE_CHK | FLG_BATCH_CHK | FLG_MASK_CHK))
			if (!(options.internal_cp =
			    cp_name2id(cfg_get_param(SECTION_OPTIONS, NULL,
			    "DefaultInternalCodepage"))))
			options.internal_cp =
				cp_name2id(cfg_get_param(SECTION_OPTIONS, NULL,
			            "DefaultInternalEncoding"));
	}

	if (!options.unicode_cp)
		initUnicode(UNICODE_UNICODE);

	options.report_utf8 = cfg_get_bool(SECTION_OPTIONS,
	                                     NULL, "AlwaysReportUTF8", 0);

	/* Unicode (UTF-16) formats may lack encoding support. We
	   must stop the user from trying to use it because it will
	   just result in false negatives. */
	if (database.format && options.target_enc != ASCII &&
	    options.target_enc != ISO_8859_1 &&
	    database.format->params.flags & FMT_UNICODE &&
	    !(database.format->params.flags & FMT_UTF8)) {
		if (john_main_process)
			fprintf(stderr, "This format does not yet support"
			        " other encodings than ISO-8859-1\n");
		error();
	}

	if (database.format && database.format->params.flags & FMT_UNICODE)
		options.store_utf8 = cfg_get_bool(SECTION_OPTIONS,
		                                  NULL, "UnicodeStoreUTF8", 0);
	else
		options.store_utf8 = options.target_enc != ASCII &&
			cfg_get_bool(SECTION_OPTIONS, NULL, "CPstoreUTF8", 0);

	if (options.target_enc != options.input_enc &&
	    options.input_enc != UTF_8) {
		if (john_main_process)
			fprintf(stderr, "Target encoding can only be specified"
			        " if input encoding is UTF-8\n");
		error();
	}

	if (john_main_process)
	if (!(options.flags & FLG_SHOW_CHK) && !options.loader.showuncracked) {
		if (options.flags & (FLG_PASSWD | FLG_STDIN_CHK))
		if (options.default_enc && options.input_enc != ASCII)
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
		char *name = path_expand(line->data);

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

static void db_main_free(struct db_main *db)
{
	if (db->format &&
		(db->format->params.flags & FMT_DYNA_SALT) == FMT_DYNA_SALT) {
		struct db_salt *psalt = db->salts;
		while (psalt) {
			dyna_salt_remove(psalt->salt);
			psalt = psalt->next;
		}
	}
	MEM_FREE(db->salt_hash);
	MEM_FREE(db->cracked_hash);
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
			dummy_format.params.flags |= FMT_UTF8;
		dummy_format.params.label = "stdout";
		dummy_format.methods.clear_keys = &fmt_default_clear_keys;

		if (!options.target_enc || options.input_enc != UTF_8)
			options.target_enc = options.input_enc;

		if (options.req_maxlength > options.length) {
			fprintf(stderr, "Can't set max length larger than %u "
			        "for stdout format\n", options.length);
			error();
		}
		john_load_conf_db();
	}

	if (options.flags & FLG_PASSWD) {
		int total;
		int i = 0;

		if (options.flags & FLG_SHOW_CHK) {
			options.loader.flags |= DB_CRACKED;
			ldr_init_database(&database, &options.loader);

			if (!options.loader.showtypes) {
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
			if (john_main_process && !options.loader.showtypes)
			printf("%s%d password hash%s cracked, %d left\n",
				database.guess_count ? "\n" : "",
				database.guess_count,
				database.guess_count != 1 ? "es" : "",
				database.password_count -
				database.guess_count);

			if (options.loader.showtypes_json)
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
			if (status_restored_time)
				log_event("Continuing an interrupted session");
			else
				log_event("Starting a new session");
			log_event("Loaded a total of %s", john_loaded_counts());
			/* make sure the format is properly initialized */
#if HAVE_OPENCL
			if (!(options.acc_devices->count && options.fork &&
			      strstr(database.format->params.label, "-opencl")))
#endif
			fmt_init(database.format);
			if (john_main_process)
			printf("Loaded %s (%s%s%s [%s])\n",
			    john_loaded_counts(),
			    database.format->params.label,
			    database.format->params.format_name[0] ? ", " : "",
			    database.format->params.format_name,
			    database.format->params.algorithm_name);

			/* Tell External our max length */
			if (options.flags & FLG_EXTERNAL_CHK)
				ext_init(options.external, &database);
		}

		total = database.password_count;

		ldr_load_pot_file(&database, options.activepot);

/*
 * Load optional extra (read-only) pot files. If an entry is a directory,
 * we read all files in it. We currently do NOT recurse.
 */
		load_extra_pots(&database, &ldr_load_pot_file);

		ldr_fix_database(&database);

		if (!database.password_count) {
			log_discard();
			if (john_main_process)
			printf("No password hashes %s (see FAQ)\n",
			    total ? "left to crack" : "loaded");
			/* skip tunable cost reporting if no hashes were loaded */
			i = FMT_TUNABLE_COSTS;
		} else
		if (database.password_count < total) {
			log_event("Remaining %s", john_loaded_counts());
			if (john_main_process)
			printf("Remaining %s\n", john_loaded_counts());
		}

		for ( ; i < FMT_TUNABLE_COSTS &&
			      database.format->methods.tunable_cost_value[i] != NULL; i++) {
			if (database.min_cost[i] < database.max_cost[i]) {
				log_event("Loaded hashes with cost %d (%s)"
				          " varying from %u to %u",
				          i+1, database.format->params.tunable_cost_name[i],
				          database.min_cost[i], database.max_cost[i]);
				if (john_main_process)
					printf("Loaded hashes with cost %d (%s)"
					       " varying from %u to %u\n",
					       i+1, database.format->params.tunable_cost_name[i],
					        database.min_cost[i], database.max_cost[i]);
			}
			else {	// if (database.min_cost[i] == database.max_cost[i]) {
				log_event("Cost %d (%s) is %u for all loaded hashes",
				          i+1, database.format->params.tunable_cost_name[i],
				          database.min_cost[i]);
				if (options.verbosity >= VERB_DEFAULT &&
				    john_main_process)
				printf("Cost %d (%s) is %u for all loaded "
				       "hashes\n", i+1,
				       database.format->params.tunable_cost_name[i],
				       database.min_cost[i]);
			}
		}
		if ((options.flags & FLG_PWD_REQ) && !database.salts) exit(0);

		if (options.regen_lost_salts)
			build_fake_salts_for_regen_lost(database.salts);
	}

	/*
	 * Nefarious hack and memory leak. Among other problems, we'd want
	 * ldr_drop_database() after this, but it's built with mem_alloc_tiny()
	 * so it's not trivial. Works like a champ though, except with
	 * DEScrypt. I have no idea why, maybe because LM and DES share code?
	 */
	if (options.flags & FLG_LOOPBACK_CHK &&
	    database.format != &fmt_LM && database.format != &fmt_DES) {
		struct db_main loop_db;
		struct fmt_main *save_list = fmt_list;
		char *loop_pot = options.wordlist ?
			options.wordlist : options.activepot;

		fmt_list = &fmt_LM;

		options.loader.flags |= DB_CRACKED;
		ldr_init_database(&loop_db, &options.loader);

		ldr_show_pot_file(&loop_db, loop_pot);
/*
 * Load optional extra (read-only) pot files. If an entry is a directory,
 * we read all files in it. We currently do NOT recurse.
 */
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
		options.loader.flags &= ~DB_CRACKED;
		fmt_list = save_list;
		db_main_free(&loop_db);
	}

#ifdef _OPENMP
	john_omp_show_info();
#endif

	if (options.node_count) {
		if (options.node_min != options.node_max) {
			log_event("- Node numbers %u-%u of %u%s",
			    options.node_min, options.node_max,
#ifndef HAVE_MPI
			    options.node_count, options.fork ? " (fork)" : "");
#else
			    options.node_count, options.fork ? " (fork)" :
				    mpi_p > 1 ? " (MPI)" : "");
#endif
			if (john_main_process)
			fprintf(stderr, "Node numbers %u-%u of %u%s\n",
			    options.node_min, options.node_max,
#ifndef HAVE_MPI
			    options.node_count, options.fork ? " (fork)" : "");
#else
			    options.node_count, options.fork ? " (fork)" :
				    mpi_p > 1 ? " (MPI)" : "");
#endif
		} else {
			log_event("- Node number %u of %u",
			    options.node_min, options.node_count);
			if (john_main_process)
			fprintf(stderr, "Node number %u of %u\n",
			    options.node_min, options.node_count);
		}

#if OS_FORK
		if (options.fork)
		{
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
}

#if CPU_DETECT
static void CPU_detect_or_fallback(char **argv, int make_check)
{
	if (!getenv("CPUID_DISABLE"))
	if (!CPU_detect()) {
#if CPU_REQ
#if CPU_FALLBACK
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
	int show_usage = 0;
	int make_check = (argc == 2 && !strcmp(argv[1], "--make_check"));
	if (make_check)
		argv[1] = "--test=0";

	CPU_detect_or_fallback(argv, make_check);

#if HAVE_MPI
	mpi_setup(argc, argv);
#else
	if (getenv("OMPI_COMM_WORLD_SIZE"))
	if (atoi(getenv("OMPI_COMM_WORLD_SIZE")) > 1) {
		fprintf(stderr, "ERROR: Running under MPI, but this is NOT an"
		        " MPI build of John.\n");
		error();
	}
#endif
#ifdef _OPENMP
	john_omp_init();
#endif

	if (!make_check) {
#ifdef HAVE_JOHN_OMP_FALLBACK
		john_omp_fallback(argv);
#endif
	}

#if (!AC_BUILT || HAVE_LOCALE_H)
	if (setlocale(LC_ALL, "")) {
		john_terminal_locale = str_alloc_copy(setlocale(LC_ALL, NULL));
#if HAVE_OPENCL
		if (strchr(john_terminal_locale, '.'))
			sprintf(gpu_degree_sign, "%ls", DEGREE_SIGN);
#endif
		/* We misuse ctype macros so this must be reset */
		setlocale(LC_CTYPE, "C");
	}
#endif

	status_init(NULL, 1);
	if (argc < 2 ||
            (argc == 2 &&
             (!strcasecmp(argv[1], "--help") ||
              !strcasecmp(argv[1], "-h") ||
              !strcasecmp(argv[1], "-help"))))
	{
		john_register_all(); /* for printing by opt_init() */
		show_usage = 1;
	}
	opt_init(name, argc, argv, show_usage);

	if (options.listconf)
		listconf_parse_early();

	if (!make_check) {
		if (options.config) {
			path_init_ex(options.config);
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
	gpu_id = -1;
#endif
#if HAVE_OPENCL
	gpu_device_list[0] = gpu_device_list[1] = -1;
#endif
	/* Process configuration options that depend on cfg_init() */
	john_load_conf();

#ifdef _OPENMP
	john_omp_maybe_adjust_or_fallback(argv);
#endif
	omp_autotune_init();
	if (!(options.flags & FLG_STDOUT))
		john_register_all(); /* maybe restricted to one format by options */
	common_init();
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
	{
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

	if (options.target_enc != ASCII) {
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
	if (options.target_enc != options.input_enc &&
	    (!database.format ||
	     !(database.format->params.flags & FMT_UNICODE))) {
		log_event("- Target encoding: %s",
		          cp_id2name(options.target_enc));
	}

	if (!(options.flags & FLG_SHOW_CHK) && !options.loader.showuncracked)
	if (options.input_enc != options.internal_cp) {
		log_event("- Rules/masks using %s",
		          cp_id2name(options.internal_cp));
	}
}

static void john_run(void)
{
	struct stat trigger_stat;
	int trigger_reset = 0;

	if (options.flags & FLG_TEST_CHK)
		exit_status = benchmark_all() ? 1 : 0;
#ifdef HAVE_FUZZ
	else
	if (options.flags & FLG_FUZZ_CHK || options.flags & FLG_FUZZ_DUMP_CHK) {
		ldr_init_database(&database, &options.loader);
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
				ldr_free_test_db(test_db);
			if (where) {
				fprintf(stderr, "Self test failed (%s)\n",
				    where);
				error();
			}
			trigger_reset = 1;
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

		if (john_main_process &&
		    database.format->params.flags & FMT_NOT_EXACT) {
			if (options.flags & FLG_KEEP_GUESSING)
				fprintf(stderr, "Note: Will keep guessing even after finding a possible candidate.\n");
			else
				fprintf(stderr, "Note: This format may emit false positives, so it will keep trying even after\nfinding a possible candidate.\n");
		}

		/* Some formats truncate at (our) max. length */
		if (!(database.format->params.flags & FMT_TRUNC) &&
		    !options.force_maxlength)
			options.force_maxlength =
			    database.format->params.plaintext_length;

		if (options.force_maxlength)
			log_event("- Will reject candidates longer than %d %s",
				  options.force_maxlength,
				  (options.target_enc == UTF_8) ?
				  "bytes" : "characters");

		/* Some formats have a minimum plaintext length */
		if (options.req_minlength >= 0 && options.req_minlength <
		    database.format->params.plaintext_min_length) {
			if (john_main_process)
				fprintf(stderr, "Invalid option: "
				        "--min-length smaller than "
				        "minimum length for format\n");
			error();
		}
		if (database.format->params.plaintext_min_length &&
		    options.req_minlength == -1) {
			options.req_minlength =
				database.format->params.plaintext_min_length;
			if (john_main_process)
				fprintf(stderr,
				        "Note: minimum length forced to %d\n",
				        options.req_minlength);

			/* Now we need to re-check this */
			if (options.req_maxlength &&
			    options.req_maxlength < options.req_minlength) {
				if (john_main_process)
					fprintf(stderr, "Invalid option: "
					        "--max-length smaller than "
					        "minimum length for format\n");
				error();
			}
		}

		if (options.flags & FLG_MASK_CHK)
			mask_init(&database, options.mask);

		omp_autotune_run(&database);

		if (trigger_reset)
			database.format->methods.reset(&database);

		if (options.flags & FLG_MASK_CHK)
			mask_crk_init(&database);

		/* Placed here to disregard load time. */
		sig_init_late();

		/* Start a resumed session by emitting a status line. */
		if (rec_restored)
			event_pending = event_status = 1;

		if (options.flags & FLG_SINGLE_CHK)
			do_single_crack(&database);
		else
		if (options.flags & FLG_WORDLIST_CHK)
			do_wordlist_crack(&database, options.wordlist,
				(options.flags & FLG_RULES) != 0);
#if HAVE_LIBGMP || HAVE_INT128 || HAVE___INT128 || HAVE___INT128_T
		else
		if (options.flags & FLG_PRINCE_CHK)
			do_prince_crack(&database, options.wordlist,
			                (options.flags & FLG_RULES) != 0);
#endif
		else
		if (options.flags & FLG_INC_CHK)
			do_incremental_crack(&database, options.charset);
		else
		if (options.flags & FLG_MKV_CHK)
			do_markov_crack(&database, options.mkv_param);
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

		status_print();

#if OS_FORK
		if (options.fork && john_main_process)
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
			fputs("Use the \"--show\" option to display all of "
			    "the cracked passwords reliably\n", stderr);
		}
	}
}

static void john_done(void)
{
	if ((options.flags & (FLG_CRACKING_CHK | FLG_STDOUT)) ==
	    FLG_CRACKING_CHK) {
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
			if (john_main_process)
				fprintf(stderr, "Session completed\n");
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

/*
 * This may not be the correct place to free this, it likely
 * can be freed much earlier, but it works here
 */
	db_main_free(&database);
	cleanup_tiny_memory();
	check_abort(0);
}

//#define TEST_MEMDBG_LOGIC

#ifdef HAVE_LIBFUZZER
int main_dummy(int argc, char **argv)
#else
int main(int argc, char **argv)
#endif
{
	char *name;

#ifdef TEST_MEMDBG_LOGIC
	int i,j;
	char *cp[260];
	for (i = 1; i < 257; ++i) {
		cp[i] = mem_alloc_align(43,i);
		for (j = 0; j < 43; ++j)
			cp[i][j] = 'x';
		printf("%03d offset %x  %x %x\n", i, cp[i], (unsigned)(cp[i])%i, (((unsigned)(cp[i]))/i)%i);
	}
	for (i = 1; i < 257; ++i)
		MEM_FREE(cp[i]);
	MEMDBG_PROGRAM_EXIT_CHECKS(stderr);
	exit(0);
#endif

	sig_preinit(); /* Mitigate race conditions */
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

        /* Needed before CPU fallback */
	path_init(argv);

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

	MEMDBG_PROGRAM_EXIT_CHECKS(stderr);

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
