/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2003,2005,2006,2009,2010,2013,2017 by Solar Designer
 *
 * ...with changes in the jumbo patch, by JimF and magnum.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#if !(__FreeBSD__ || __APPLE__)
/* On FreeBSD, defining this precludes the declaration of u_int, which
 * FreeBSD's own <sys/file.h> needs. */
#if !AC_BUILT && _XOPEN_SOURCE < 500
#undef _XOPEN_SOURCE
#define _XOPEN_SOURCE 500 /* for fdopen(3), fileno(3), fsync(2), ftruncate(2) */
#define _XPG6
#endif
#endif

#include <stdio.h>
#include <stdlib.h>
#if (!AC_BUILT || HAVE_UNISTD_H) && !_MSC_VER
#include <unistd.h>
#endif
#ifdef _MSC_VER
#include <io.h>
#pragma warning ( disable : 4996 )
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#if !AC_BUILT || HAVE_SYS_FILE_H
#include <sys/file.h>
#endif

#include "arch.h"
#include "misc.h"
#include "params.h"
#include "path.h"
#include "memory.h"
#include "config.h"
#include "options.h"
#include "loader.h"
#include "cracker.h"
#include "logger.h"
#include "status.h"
#include "recovery.h"
#include "external.h"
#include "regex.h"
#include "john.h"
#include "mask.h"
#include "unicode.h"
#include "john_mpi.h"
#include "signals.h"
#include "jumbo.h"
#include "opencl_common.h"

char *rec_name = RECOVERY_NAME;
int rec_name_completed = 0;
int rec_version = 0;
int rec_argc = 0;
char **rec_argv;
unsigned int rec_check;
int rec_restoring_now = 0;
int rec_restored;

static int rec_fd;
static FILE *rec_file = NULL;
static struct db_main *rec_db;
static void (*rec_save_mode)(FILE *file);
static void (*rec_save_mode2)(FILE *file);
static void (*rec_save_mode3)(FILE *file);

extern int crk_max_keys_per_crypt();

static void rec_name_complete(void)
{
	if (rec_name_completed)
		return;

#ifndef HAVE_MPI
	if (options.fork && !john_main_process) {
#else
	if (!john_main_process && options.node_min) {
#endif
		char suffix[1 + 20 + sizeof(RECOVERY_SUFFIX)];
		sprintf(suffix, ".%u%s", options.node_min, RECOVERY_SUFFIX);
		rec_name = path_session(rec_name, suffix);
	} else {
		rec_name = path_session(rec_name, RECOVERY_SUFFIX);
	}

	rec_name_completed = 1;
}

#if !(__MINGW32__ || _MSC_VER)
/*
 * Foot Gun Warning: This is ridiculously tricky to get right.
 *
 * 1. Non-MPI builds always do a non-blocking write lock (even in case
 *    of fork: We haven't yet forked when resuming the session).
 *
 * 2. At resume, MPI code path in options.c calls rec_restore_args(mpi_p)
 *    which in turn calls rec_lock(mpi_p) relying on anything > 1 meaning
 *    read lock because at this time *all* nodes read the root session file.
 *
 * 3. rec_init() may call rec_lock(1), meaning normal behavior except
 *    for the root node. *After* restore of a multi-node job, the root node
 *    must do a *blocking* write lock, in case some other node has not yet
 *    closed the root session file.
 */
static void rec_lock(int shared)
{
	int cmd = F_SETLK, type = F_WRLCK; /* non-blocking write lock */

#if HAVE_MPI
	if (shared > 1)
		type = F_RDLCK; /* non-blocking read lock */
	else if (rec_restored && mpi_p > 1 && mpi_id == 0)
		cmd = F_SETLKW; /* blocking write lock */
#endif

	if (jtr_lock(rec_fd, cmd, type, path_expand(rec_name))) {
		const char *msg = "Crash recovery file is locked (maybe use \"--session\"): ";
#if HAVE_MPI
		fprintf(stderr, "Node %d@%s: %s%s\n", NODE, mpi_name, msg, path_expand(rec_name));
#else
		fprintf(stderr, "%s%s\n", msg, path_expand(rec_name));
#endif
		error();
	}
}

static void rec_unlock(void)
{
	jtr_lock(rec_fd, F_SETLK, F_UNLCK, rec_name);
}
#else
#define rec_lock(shared) \
	{}
#define rec_unlock() \
	{}
#endif /* !(__MINGW32__ || _MSC_VER) */

static int is_default(char *name)
{
	if (john_main_process)
		return !strcmp(rec_name, RECOVERY_NAME RECOVERY_SUFFIX);
	else {
		char def_name[sizeof(RECOVERY_NAME) + 20 +
		              sizeof(RECOVERY_SUFFIX)];

		sprintf(def_name, "%s.%u%s", RECOVERY_NAME, options.node_min,
		        RECOVERY_SUFFIX);
		return !strcmp(rec_name, def_name);
	}
}

void rec_init(struct db_main *db, void (*save_mode)(FILE *file))
{
	static int check_done;
	const char *protect;

	rec_done(1);

	if (!rec_argc) return;

	rec_name_complete();

	if (!(protect = cfg_get_param(SECTION_OPTIONS, NULL,
	    "SessionFileProtect")))
		protect = "Disabled";

	if (!rec_restored && !check_done++ &&
	    (((!strcasecmp(protect, "Named")) && !is_default(rec_name)) ||
	    (!strcasecmp(protect, "Always")))) {
		struct stat st;

		if (!stat(path_expand(rec_name), &st)) {
			fprintf(stderr,
			    "ERROR: SessionFileProtect enabled in john.conf, and %s exists\n",
			    path_expand(rec_name));
			error();
		}
	}

	if ((rec_fd = open(path_expand(rec_name), O_RDWR | O_CREAT, 0600)) < 0)
		pexit("open: %s", path_expand(rec_name));
#if __DJGPP__ || _MSC_VER || __MINGW32__ || __MINGW64__ || __CYGWIN__ || HAVE_WINDOWS_H
	// works around bug in cygwin, that has file locking problems with a handle
	// from a just created file.  If we close and reopen, cygwin does not seem
	// to have any locking problems.  Go figure???
	// Note, changed from just __CYGWIN__ to all 'Dos/Windows' as the OS environments
	// likely this is a Win32 'issue'
	close(rec_fd);
	if ((rec_fd = open(path_expand(rec_name), O_RDWR | O_CREAT, 0600)) < 0)
		pexit("open: %s", path_expand(rec_name));
#endif
	rec_lock(1);
	if (!(rec_file = fdopen(rec_fd, "w"))) pexit("fdopen");

	rec_db = db;
	rec_save_mode = save_mode;

	if (options.catchup)
		john_max_cands = rec_read_cands(options.catchup);
}

static void save_salt_state()
{
	int i;
	char md5_buf[33], *p=md5_buf;
	unsigned char *h = (unsigned char*)status.resume_salt_md5;

	if (!status.resume_salt_md5)
		return;

	for (i = 0; i < 16; ++i) {
		*p++ = itoa16[*h >> 4];
		*p++ = itoa16[*h & 0xF];
		++h;
	}
	*p = 0;
	fprintf(rec_file, "slt-v2\n%s\n", md5_buf);
	fprintf(rec_file, "%d\n", crk_max_keys_per_crypt());
}

void rec_save(void)
{
	int save_format;
#if HAVE_MPI
	int fake_fork;
#endif
	int add_argc = 0, add_enc = 1, add_2nd_enc = 1;
	int add_mkv_stats = (options.mkv_stats ? 1 : 0);
	long size;
	char **opt;
#if HAVE_OPENCL
	int add_lws, add_gws;

	add_gws = add_lws =
		(options.format && strcasestr(options.format, "-opencl") &&
		 cfg_get_bool(SECTION_OPTIONS, SUBSECTION_OPENCL,
		              "ResumeWS", 0));
#endif
	log_flush();

	if (!rec_file) return;

	if (fseek(rec_file, 0, SEEK_SET)) pexit("fseek");

	/* Always save the ultimately selected format (could be eg. class or wildcard). */
	save_format = rec_db->loaded;

#if HAVE_MPI
	fake_fork = (mpi_p > 1);
#endif
	opt = rec_argv;
	while (*++opt) {
		/********* Re-write deprecated options *********/
		if (!strncmp(*opt, "--internal-encoding", 19))
			memcpy(*opt, "--internal-codepage", 19);
		else
		if (!strcmp(*opt, "--nolog"))
			*opt = "--no-log";
		else
		if (!strncmp(*opt, "--single-retest-guess=", 22)) {
			if (parse_bool(*opt + 22))
				(*opt)[21] = 0;
			else
				*opt = "--no-single-retest-guess";
		}
		else
		if (!strncmp(*opt, "--fix-state-delay", 17)) {
			char **o = opt;
			do
				*o = o[1];
			while (*++o);
			rec_argc--;
		}
		/***********************************************/
		else
		if (save_format && !strncmp(*opt, "--format=", 9)) {
			char **o = opt;
			do
				*o = o[1];
			while (*++o);
			rec_argc--;
		}
		else
#if HAVE_MPI
		if (fake_fork && !strncmp(*opt, "--fork", 6))
			fake_fork = 0;
		else
#endif
#if HAVE_OPENCL
		if (add_lws && !strncmp(*opt, "--lws", 5))
			add_lws = 0;
		else
		if (add_gws && !strncmp(*opt, "--gws", 5))
			add_gws = 0;
		else
#endif
		if (add_enc &&
		    (!strncmp(*opt, "--encoding", 10) ||
		     !strncmp(*opt, "--input-encoding", 16)))
			add_enc = 0;
		else if (add_2nd_enc &&
		         (!strncmp(*opt, "--internal-codepage", 19) ||
		          !strncmp(*opt, "--target-encoding", 17)))
			add_2nd_enc = 0;
		else if (add_mkv_stats && !strncmp(*opt, "--mkv-stats", 11))
			add_mkv_stats = 0;
	}

	if (add_2nd_enc && (options.flags & FLG_STDOUT) &&
	    (options.input_enc != UTF_8 || options.target_enc != UTF_8))
		add_2nd_enc = 0;

	add_argc = add_enc + add_2nd_enc + add_mkv_stats;
#if HAVE_MPI
	add_argc += fake_fork;
#endif
#if HAVE_OPENCL
	add_argc += add_lws + add_gws;
#endif
	fprintf(rec_file, RECOVERY_V "\n%d\n",
		rec_argc + (save_format ? 1 : 0) + add_argc);

	opt = rec_argv;
	while (*++opt)
	{
		/* Add defaults as if they were actually on **argv */
		if (options.wordlist &&
		    !(strcmp(*opt, "--wordlist") && strcmp(*opt, "--loopback")))
			fprintf(rec_file, "%s=%s\n", *opt, options.wordlist);
		else if (!strcmp(*opt, "--rules"))
			fprintf(rec_file, "%s=%s\n", *opt,
			        options.activewordlistrules);
		else if (!strcmp(*opt, "--single"))
			fprintf(rec_file, "%s=%s\n", *opt,
			        options.activesinglerules);
		else if (!strcmp(*opt, "--incremental"))
			fprintf(rec_file, "%s=%s\n", *opt,
			        options.charset);
		else if (!strcmp(*opt, "--markov"))
			fprintf(rec_file, "%s=%s\n", *opt,
			        options.mkv_param);
		else
			fprintf(rec_file, "%s\n", *opt);
	}

	if (save_format)
		fprintf(rec_file, "--format=%s\n",
		    rec_db->format->params.label);

	if (add_enc)
		fprintf(rec_file, "--input-encoding=%s\n",
		        cp_id2name(options.input_enc));

	if (add_2nd_enc && options.input_enc == UTF_8 &&
	    options.target_enc == UTF_8)
		fprintf(rec_file, "--internal-codepage=%s\n",
		        cp_id2name(options.internal_cp));
	else if (add_2nd_enc)
		fprintf(rec_file, "--target-encoding=%s\n",
		        cp_id2name(options.target_enc));

	if (add_mkv_stats)
		fprintf(rec_file, "--mkv-stats=%s\n", options.mkv_stats);
#if HAVE_MPI
	if (fake_fork)
		fprintf(rec_file, "--fork=%d\n", mpi_p);
#endif
#if HAVE_OPENCL
	if (add_lws)
		fprintf(rec_file, "--lws="Zu"\n", local_work_size);
	if (add_gws)
		fprintf(rec_file, "--gws="Zu"\n", global_work_size);
#endif

	fprintf(rec_file, "%u\n%u\n%x\n%x\n%x\n%x\n%x\n%x\n%x\n"
	    "%d\n%d\n%d\n%x\n",
	    status_get_time() + 1,
	    status.guess_count,
	    (unsigned int)(status.combs & 0xffffffffU),
	    (unsigned int)(status.combs >> 32),
	    status.combs_ehi,
	    (unsigned int)(status.crypts & 0xffffffffU),
	    (unsigned int)(status.crypts >> 32),
	    (unsigned int)(status.cands & 0xffffffffU),
	    (unsigned int)(status.cands >> 32),
	    status.compat,
	    status.pass,
	    status_get_progress ? (int)status_get_progress() : -1,
	    rec_check);

	if (rec_save_mode) rec_save_mode(rec_file);
	/* these are 'appended' resume blocks */
	save_salt_state();
	if (rec_save_mode2) rec_save_mode2(rec_file);
	if (rec_save_mode3) rec_save_mode3(rec_file);
	if (options.flags & FLG_MASK_STACKED)
		mask_save_state(rec_file);

	if (ferror(rec_file)) pexit("fprintf");

	if ((size = ftell(rec_file)) < 0) pexit("ftell");
	if (fflush(rec_file)) pexit("fflush");
#ifndef _MSC_VER
	if (ftruncate(rec_fd, size)) pexit("ftruncate");
#else
	if (_chsize(rec_fd, size)) pexit("ftruncate");
#endif
#if defined (_MSC_VER) || defined (__MINGW32__) || defined (__MINGW64__)
	_close(_dup(rec_fd));
#else
	if (!options.fork && fsync(rec_fd))
		pexit("fsync");
#endif
	sig_reset_timer();
}

void rec_init_hybrid(void (*save_mode)(FILE *file)) {
	if (!rec_save_mode2)
		rec_save_mode2 = save_mode;
	else if (!rec_save_mode3)
		rec_save_mode3 = save_mode;
}

/* See the comment in recovery.h on how the "save" parameter is used */
void rec_done(int save)
{
	if (!rec_file)
		return;

/*
 * If we're the main process for a --fork'ed group of children, leave our .rec
 * file around until the children terminate (at which time we may be called
 * again with save < 0, meaning forced non-saving).
 */
#ifndef HAVE_MPI
	if (!save && options.fork && john_main_process) {
#else
	if (!save && (options.fork || mpi_p > 1) && john_main_process) {
#endif
		rec_save();
		return;
	}

	if (save > 0)
		rec_save();
	else
		log_flush();

/*
 * In Jumbo we close [releasing the lock] *after* unlinking, avoiding
 * race conditions. Except we can't do this on b0rken systems.
 */
#if __DJGPP__ || _MSC_VER || __MINGW32__ || __MINGW64__ || __CYGWIN__ || HAVE_WINDOWS_H
	if (fclose(rec_file))
		pexit("fclose");
	rec_file = NULL;
#endif

	if ((!save || save == -1) && unlink(path_expand(rec_name)))
		pexit("unlink: %s", path_expand(rec_name));

	if (rec_file) {
		if (fclose(rec_file))
			pexit("fclose");
		rec_file = NULL;
	}
}

static void rec_format_error(char *fn)
{
	path_done();
	cleanup_tiny_memory();

	if (fn && errno && ferror(rec_file))
		pexit("%s", fn);
	else {
		fprintf(stderr, "Incorrect crash recovery file: %s\n",
			path_expand(rec_name));
		error();
	}
}

void rec_restore_args(int lock)
{
	char line[LINE_BUFFER_SIZE];
	int index, argc;
	char **argv;
	char *save_rec_name;
	unsigned int combs_lo, combs_hi;

	rec_name_complete();
	if (!(rec_file = fopen(path_expand(rec_name), "r+"))) {
#ifndef HAVE_MPI
		if (options.fork && !john_main_process && errno == ENOENT) {
#else
		if (options.node_min > 1 && errno == ENOENT) {
#endif
			fprintf(stderr, "%u Session completed\n", NODE);
			if (options.flags & FLG_STATUS_CHK)
				return;
			log_event("No crash recovery file, terminating");
			log_done();
#if HAVE_MPI
			if (strstr(options.format, "opencl")) {
#if RACE_CONDITION_DEBUG || MPI_DEBUG
				if (options.verbosity == VERB_DEBUG)
					fprintf(stderr, "Node %d reached %s() MPI \"build\" barrier\n",
					        NODE, __FUNCTION__);
#endif
				/* This compensates for the barrier in opencl_build_kernel() */
				MPI_Barrier(MPI_COMM_WORLD);
			}
			mpi_teardown();
#endif
			exit(0);
		}
#if HAVE_MPI
		if (mpi_p > 1) {
			fprintf(stderr, "%u@%s: fopen: %s: %s\n",
				NODE, mpi_name,
				path_expand(rec_name), strerror(errno));
			error();
		}
#endif
		pexit("fopen: %s", path_expand(rec_name));
	}
	rec_fd = fileno(rec_file);

	if (lock) rec_lock(lock);

	if (!fgetl(line, sizeof(line), rec_file)) rec_format_error("fgets");

	rec_version = 0;
	if (!strcmp(line, RECOVERY_V4)) rec_version = 4; else
	if (!strcmp(line, RECOVERY_V3)) rec_version = 3; else
	if (!strcmp(line, RECOVERY_V2)) rec_version = 2; else
	if (!strcmp(line, RECOVERY_V1)) rec_version = 1; else
	if (strcmp(line, RECOVERY_V0)) rec_format_error(NULL);

	if (fscanf(rec_file, "%d\n", &argc) != 1)
		rec_format_error("fscanf");
	if (argc < 2 || argc > 11000000)
		rec_format_error(NULL);
	argv = mem_alloc_tiny(sizeof(char *) * (argc + 1), MEM_ALIGN_WORD);

	argv[0] = "john";

	for (index = 1; index < argc; index++)
	if (fgetl(line, sizeof(line), rec_file))
		argv[index] = str_alloc_copy(line);
	else
		rec_format_error("fgets");

	argv[argc] = NULL;

	save_rec_name = rec_name;
	opt_init(argv[0], argc, argv);
	rec_name = save_rec_name;
	rec_name_completed = 1;

	if (fscanf(rec_file, "%u\n%u\n%x\n%x\n",
	    &status_restored_time,
	    &status.guess_count,
	    &combs_lo, &combs_hi) != 4)
		rec_format_error("fscanf");
	status.combs = ((uint64_t)combs_hi << 32) | combs_lo;
	if (!status_restored_time)
		status_restored_time = 1;

	if (rec_version >= 4) {
		unsigned int crypts_lo, crypts_hi, cands_lo, cands_hi;
		if (fscanf(rec_file, "%x\n%x\n%x\n%x\n%x\n%d\n",
		    &status.combs_ehi,
		    &crypts_lo, &crypts_hi,
		    &cands_lo, &cands_hi,
		    &status.compat) != 6)
			rec_format_error("fscanf");
		status.crypts = ((uint64_t)crypts_hi << 32) | crypts_lo;
		status.cands = ((uint64_t)cands_hi << 32) | cands_lo;
	} else {
/* Historically, we were reusing what became the combs field for candidates
 * count when in --stdout mode */
		status.cands = status.combs;
		status.compat = 1;
	}

	if (rec_version == 0) {
		status.pass = 0;
		status.progress = -1;
	} else
	if (fscanf(rec_file, "%d\n%d\n", &status.pass, &status.progress) != 2)
		rec_format_error("fscanf");
	if (status.pass < 0 || status.pass > 3)
		rec_format_error(NULL);

	if (rec_version < 3)
		rec_check = 0;
	else
	if (fscanf(rec_file, "%x\n", &rec_check) != 1)
		rec_format_error("fscanf");

	rec_restoring_now = 1;
}

static void restore_salt_state(int type)
{
	char buf[34];
	char buf2[48];
	static uint32_t hash[4];
	unsigned char *h = (unsigned char*)hash;
	int i;

	fgetl(buf, sizeof(buf), rec_file);
	if (type == 2) {
		fgetl(buf2, sizeof(buf2), rec_file);
	}
	if (strlen(buf) != 32 || !ishex(buf))
		rec_format_error("multi-salt");
	if (type == 2) {
		// the first crack, we seek to the above salt, BUT initially
		// capping effective max_keys_per_crypt to what it was before
		status.resume_salt = strtoul(buf2, NULL, 10);
	} else if (type == 1) {
		// tells cracker to ignore the check, since this information was not
		// available in v1 slt records. v1 salt will NOT resume in cracker.c
		status.resume_salt = 0;
	}
	for (i = 0; i < 16; ++i) {
		h[i] = atoi16[ARCH_INDEX(buf[i*2])] << 4;
		h[i] += atoi16[ARCH_INDEX(buf[i*2+1])];
	}
	status.resume_salt_md5 = hash;
}

void rec_restore_mode(int (*restore_mode)(FILE *file))
{
	char buf[128];

	rec_name_complete();

	if (!rec_file) return;

	if (restore_mode)
	if (restore_mode(rec_file)) rec_format_error("fscanf");

	if (options.flags & FLG_MASK_STACKED)
	if (mask_restore_state(rec_file)) rec_format_error("fscanf");

	/* we may be pointed at appended hybrid records.  If so, then process them */
	fgetl(buf, sizeof(buf), rec_file);
	while (!feof(rec_file)) {
		if (!strncmp(buf, "ext-v", 5)) {
			if (ext_restore_state_hybrid(buf, rec_file))
				rec_format_error("external-hybrid");
		}
#if HAVE_REXGEN
		else if (!strncmp(buf, "rex-v", 5)) {
			if (rexgen_restore_state_hybrid(buf, rec_file))
				rec_format_error("rexgen-hybrid");
		}
#endif
		if (!strcmp(buf, "slt-v1")) {
			restore_salt_state(1);
		}
		if (!strcmp(buf, "slt-v2")) {
			restore_salt_state(2);
		}
		fgetl(buf, sizeof(buf), rec_file);
	}

/*
 * Unlocking the file explicitly is normally not necessary since we're about to
 * close it anyway (which would normally release the lock).  However, when
 * we're the main process running with --fork, our newborn children may hold a
 * copy of the fd for a moment (until they close the fd themselves).  Thus, if
 * we don't explicitly remove the lock, there may be a race condition between
 * our children closing the fd and us proceeding to re-open and re-lock it.
 */
	rec_unlock();

	if (fclose(rec_file)) pexit("fclose");
	rec_file = NULL;

	rec_restoring_now = 0;
}

uint64_t rec_read_cands(char *session)
{
	char line[LINE_BUFFER_SIZE];
	char *other_name;
	FILE *other_file = NULL;
	int index, argc;

	if (!john_main_process && options.node_min) {
		char suffix[1 + 20 + sizeof(RECOVERY_SUFFIX)];

		sprintf(suffix, ".%u%s", options.node_min, RECOVERY_SUFFIX);
		other_name = path_session(session, suffix);
	} else {
		other_name = path_session(session, RECOVERY_SUFFIX);
	}

	if (!strcmp(other_name, rec_name))
		error_msg("New session name can't be same as catch-up session\n");

	if (!(other_file = fopen(other_name, "r")))
		pexit("fopen catch-up file: '%s'", other_name);

#if !(__MINGW32__ || _MSC_VER)
	int other_fd = fileno(other_file);

	if (jtr_lock(other_fd, F_SETLK, F_RDLCK, other_name))
		error_msg("Catch-Up session file '%s' is locked\n", other_name);
#endif

	if (!fgetl(line, sizeof(line), other_file))
		error_msg("fgets (%s)", other_name);
	if (strcmp(line, RECOVERY_V))
		error_msg("Catch-Up session file '%s' version mismatch\n", other_name);
	if (fscanf(other_file, "%d\n", &argc) != 1 || argc < 2)
		error_msg("Catch-Up session file '%s' corrupt\n", other_name);

	int other_fork = 1;

	for (index = 1; index < argc; index++) {
		if (!fgetl(line, sizeof(line), other_file))
			error_msg("Catch-Up session file '%s' corrupt\n", other_name);
		if (!strncmp(line, "--fork=", 6))
			other_fork = atoi(&line[7]);
	}

	if (NODES != other_fork)
		error_msg("Catch-Up session file '%s' fork/MPI count mismatch (our %d, other %d)\n",
		          other_name, NODES, other_fork);

	unsigned int cands_lo, cands_hi;
	if (fscanf(other_file, "%*u\n%*u\n%*x\n%*x\n%*x\n%*x\n%*x\n%x\n%x\n%*d\n", &cands_lo, &cands_hi) != 2)
		error_msg("Catch-Up session file '%s' corrupt\n", other_name);

	uint64_t ret = ((uint64_t)cands_hi << 32) | cands_lo;

	if (ret == 0)
		error_msg("Error: Catch-up session file '%s' had zero cands count\n", other_name);

	return ret;
}
