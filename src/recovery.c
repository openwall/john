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

#ifndef __FreeBSD__
/* On FreeBSD, defining this precludes the declaration of u_int, which
 * FreeBSD's own <sys/file.h> needs. */
#if _XOPEN_SOURCE < 500
#undef _XOPEN_SOURCE
#define _XOPEN_SOURCE 500 /* for fdopen(3), fileno(3), fsync(2), ftruncate(2) */
#endif
#endif

#define NEED_OS_FLOCK
#include "os.h"

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
#if (!AC_BUILT || HAVE_FCNTL_H)
#include <fcntl.h>
#endif
#if !AC_BUILT || HAVE_SYS_FILE_H
#include <sys/file.h>
#endif
#include <errno.h>
#include <string.h>

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
#ifdef HAVE_MPI
#include "john-mpi.h"
#include "signals.h"
#endif
#include "memdbg.h"

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

extern int cracker_max_keys_per_crypt();

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

#if OS_FLOCK || FCNTL_LOCKS
static void rec_lock(int shared)
{
	int lockmode;
#if FCNTL_LOCKS
	int blockmode;
	struct flock lock;
#endif

	/*
	 * In options.c, MPI code path call rec_restore_args(mpi_p)
	 * relying on anything >1 meaning LOCK_SH. After restore, the
	 * root node must block, in case some other node has not yet
	 * closed the original file
	 */
	if (shared == 1) {
#if FCNTL_LOCKS
		lockmode = F_WRLCK;
		blockmode = F_SETLKW;
#else
		lockmode = LOCK_EX;
#endif
#ifdef HAVE_MPI
		if (!rec_restored || mpi_id || mpi_p == 1)
#endif
#if FCNTL_LOCKS
			blockmode = F_SETLK;
#else
			lockmode |= LOCK_NB;
#endif
	} else
#if FCNTL_LOCKS
	{
		lockmode = F_RDLCK;
		blockmode = F_SETLK;
	}

#else
		lockmode = LOCK_SH | LOCK_NB;
#endif

#ifdef LOCK_DEBUG
	fprintf(stderr, "%s(%u): Locking session file...\n", __FUNCTION__, options.node_min);
#endif
#if FCNTL_LOCKS
	memset(&lock, 0, sizeof(lock));
	lock.l_type = lockmode;
	if (fcntl(rec_fd, blockmode, &lock)) {
		if (errno == EAGAIN || errno == EACCES) {
#else
	if (flock(rec_fd, lockmode)) {
		if (errno == EWOULDBLOCK) {
#endif
#ifdef HAVE_MPI
			fprintf(stderr, "Node %d@%s: Crash recovery file is"
			        " locked: %s\n", mpi_id + 1, mpi_name,
			        path_expand(rec_name));
#else
			fprintf(stderr, "Crash recovery file is locked: %s\n",
				path_expand(rec_name));
#endif
			error();
		} else
#if FCNTL_LOCKS
			pexit("fcntl()");
#else
			pexit("flock()");
#endif
	}
#ifdef LOCK_DEBUG
	fprintf(stderr, "%s(%u): Locked session file (%s)\n", __FUNCTION__, options.node_min, shared == 1 ? "exclusive" : "shared");
#endif
}

static void rec_unlock(void)
{
#if FCNTL_LOCKS
	struct flock lock = { 0 };
	lock.l_type = F_UNLCK;
#endif
#ifdef LOCK_DEBUG
	fprintf(stderr, "%s(%u): Unlocking session file\n", __FUNCTION__, options.node_min);
#endif
#if FCNTL_LOCKS
	if (fcntl(rec_fd, F_SETLK, &lock))
		pexit("fcntl(F_UNLCK)");
#else
	if (flock(rec_fd, LOCK_UN))
		pexit("flock(LOCK_UN)");
#endif
}
#else
#define rec_lock(lock) \
	{}
#define rec_unlock() \
	{}
#endif

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
	// bug found in original salt-restore.  if the cracks per loop value is NOT the same,
	// then we end up skipping processing some data. So we save this value, and then
	// when we resume IF this value is not the same, we ignore the salt resume, and just
	// start from salt zero.
	fprintf(rec_file, "%d\n", cracker_max_keys_per_crypt());
}

void rec_save(void)
{
	int save_format;
#ifdef HAVE_MPI
	int fake_fork;
#endif
	int add_argc = 0, add_enc = 1, add_2nd_enc = 1;
	int add_mkv_stats = (options.mkv_stats ? 1 : 0);
	long size;
	char **opt;

	log_flush();

	if (!rec_file) return;

	if (fseek(rec_file, 0, SEEK_SET)) pexit("fseek");

	save_format = !options.format && rec_db->loaded;

#ifdef HAVE_MPI
	fake_fork = (mpi_p > 1);
#endif
	opt = rec_argv;
	while (*++opt) {
		if (!strncmp(*opt, "--internal-encoding", 19))
			memcpy(*opt, "--internal-codepage", 19);
#ifdef HAVE_MPI
		if (!strncmp(*opt, "--fork", 6))
			fake_fork = 0;
		else
#endif
		if (!strncmp(*opt, "--encoding", 10) ||
			!strncmp(*opt, "--input-encoding", 16))
			add_enc = 0;
		else if (!strncmp(*opt, "--internal-codepage", 19) ||
		         !strncmp(*opt, "--target-encoding", 17))
			add_2nd_enc = 0;
		else if (!strncmp(*opt, "--mkv-stats", 11))
			add_mkv_stats = 0;
	}

	if (add_2nd_enc && (options.flags & FLG_STDOUT) &&
	    (options.input_enc != UTF_8 || options.target_enc != UTF_8))
		add_2nd_enc = 0;

	add_argc = add_enc + add_2nd_enc + add_mkv_stats;
#ifdef HAVE_MPI
	add_argc += fake_fork;
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
#ifdef HAVE_MPI
	if (fake_fork)
		fprintf(rec_file, "--fork=%d\n", mpi_p);
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

	/*
	 * MEMDBG_PROGRAM_EXIT_CHECKS() would cause the output
	 *     At Program Exit
	 *     MemDbg_Validate level 0 checking Passed
	 * to be writen prior to the
	 *     Incorrect crash recovery file: ...
	 * output.
	 * Not sure if we want this.
	 */
	// MEMDBG_PROGRAM_EXIT_CHECKS(stderr); // FIXME

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
			fprintf(stderr, "%u Session completed\n",
			    options.node_min);
			if (options.flags & FLG_STATUS_CHK)
				return;
			log_event("No crash recovery file, terminating");
			log_done();
#ifdef HAVE_MPI
			mpi_teardown();
#endif
			exit(0);
		}
#ifdef HAVE_MPI
		if (mpi_p > 1) {
			fprintf(stderr, "%u@%s: fopen: %s: %s\n",
				mpi_id + 1, mpi_name,
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
	if (argc < 2)
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
	opt_init(argv[0], argc, argv, 0);
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
		// the first crack, we seek to the above salt, BUT only if we
		// still have exactly same count of max_crypts_per  If the max
		// changes, then we simply start over at salt#1 to avoid any
		// salt records NOT being processed. properly.
		status.resume_salt_crypts_per = strtoul(buf2, NULL, 10);
	} else if (type == 1) {
		// tells cracker to ignore the check, since this information was not
		// available in v1 slt records. v1 salt will NOT resume in cracker.c
		status.resume_salt_crypts_per = -1;
	}
	for (i = 0; i < 16; ++i) {
		h[i] = atoi16[ARCH_INDEX(buf[i*2])] << 4;
		h[i] += atoi16[ARCH_INDEX(buf[i*2+1])];
	}
	status.resume_salt_md5 = hash;
	status.resume_salt = 1;
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
