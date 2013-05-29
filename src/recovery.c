/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2003,2005,2006,2009,2010,2013 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#ifndef __FreeBSD__
#define _XOPEN_SOURCE 500 /* for fdopen(3), fileno(3), fsync(2), ftruncate(2) */
#endif

#define NEED_OS_FLOCK
#include "os.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/file.h>
#include <errno.h>
#include <string.h>

#if defined(__CYGWIN32__) && !defined(__CYGWIN__)
extern int ftruncate(int fd, size_t length);
#endif

#include "arch.h"
#include "misc.h"
#include "params.h"
#include "path.h"
#include "memory.h"
#include "options.h"
#include "loader.h"
#include "logger.h"
#include "status.h"
#include "recovery.h"
#include "john.h"

char *rec_name = RECOVERY_NAME;
int rec_name_completed = 0;
int rec_version = 0;
int rec_argc = 0;
char **rec_argv;
unsigned int rec_check;
int rec_restoring_now = 0;

static int rec_fd;
static FILE *rec_file = NULL;
static struct db_main *rec_db;
static void (*rec_save_mode)(FILE *file);

static void rec_name_complete(void)
{
	if (rec_name_completed)
		return;

	if (options.fork && !john_main_process) {
		char *suffix = mem_alloc(1 + 20 + strlen(RECOVERY_SUFFIX) + 1);
		sprintf(suffix, ".%u%s", options.node_min, RECOVERY_SUFFIX);
		rec_name = path_session(rec_name, suffix);
		MEM_FREE(suffix);
	} else {
		rec_name = path_session(rec_name, RECOVERY_SUFFIX);
	}

	rec_name_completed = 1;
}

#if OS_FLOCK
static void rec_lock(void)
{
	if (flock(rec_fd, LOCK_EX | LOCK_NB)) {
		if (errno == EWOULDBLOCK) {
			fprintf(stderr, "Crash recovery file is locked: %s\n",
				path_expand(rec_name));
			error();
		} else
			pexit("flock(LOCK_EX)");
	}
}
static void rec_unlock(void)
{
	if (flock(rec_fd, LOCK_UN))
		perror("flock(LOCK_UN)");
}
#else
#define rec_lock() \
	{}
#define rec_unlock() \
	{}
#endif

void rec_init(struct db_main *db, void (*save_mode)(FILE *file))
{
	rec_done(1);

	if (!rec_argc) return;

	rec_name_complete();

	if ((rec_fd = open(path_expand(rec_name), O_RDWR | O_CREAT, 0600)) < 0)
		pexit("open: %s", path_expand(rec_name));
	rec_lock();
	if (!(rec_file = fdopen(rec_fd, "w"))) pexit("fdopen");

	rec_db = db;
	rec_save_mode = save_mode;
}

void rec_save(void)
{
	int save_format;
	long size;
	char **opt;

	log_flush();

	if (!rec_file) return;

	if (fseek(rec_file, 0, SEEK_SET)) pexit("fseek");
#ifdef __CYGWIN32__
	if (ftruncate(rec_fd, 0)) pexit("ftruncate");
#endif

	save_format = !options.format && rec_db->loaded;

	fprintf(rec_file, RECOVERY_V "\n%d\n",
	    rec_argc + (save_format ? 1 : 0));

	opt = rec_argv;
	while (*++opt)
		fprintf(rec_file, "%s\n", *opt);

	if (save_format)
		fprintf(rec_file, "--format=%s\n",
		    rec_db->format->params.label);

	fprintf(rec_file, "%u\n%u\n%x\n%x\n%x\n%x\n%x\n%x\n%x\n"
	    "%d\n%d\n%d\n%x\n",
	    status_get_time() + 1,
	    status.guess_count,
	    status.combs.lo,
	    status.combs.hi,
	    status.combs_ehi,
	    status.crypts.lo,
	    status.crypts.hi,
	    status.cands.lo,
	    status.cands.hi,
	    status.compat,
	    status.pass,
	    status_get_progress ? status_get_progress() : -1,
	    rec_check);

	if (rec_save_mode) rec_save_mode(rec_file);

	if (ferror(rec_file)) pexit("fprintf");

	if ((size = ftell(rec_file)) < 0) pexit("ftell");
	if (fflush(rec_file)) pexit("fflush");
	if (ftruncate(rec_fd, size)) pexit("ftruncate");
#ifndef __CYGWIN32__
	if (!options.fork && fsync(rec_fd))
		pexit("fsync");
#endif
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
	if (!save && options.fork && john_main_process) {
		rec_save();
		return;
	}

	if (save > 0)
		rec_save();
	else
		log_flush();

	if (fclose(rec_file))
		pexit("fclose");
	rec_file = NULL;

	if ((!save || save == -1) && unlink(path_expand(rec_name)))
		pexit("unlink: %s", path_expand(rec_name));
}

static void rec_format_error(char *fn)
{
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

	rec_name_complete();
	if (!(rec_file = fopen(path_expand(rec_name), "r+"))) {
		if (options.fork && !john_main_process && errno == ENOENT) {
			fprintf(stderr, "%u Session completed\n",
			    options.node_min);
			if (options.flags & FLG_STATUS_CHK)
				return;
			log_event("No crash recovery file, terminating");
			log_done();
			exit(0);
		}
		pexit("fopen: %s", path_expand(rec_name));
	}
	rec_fd = fileno(rec_file);

	if (lock) rec_lock();

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
	opt_init(argv[0], argc, argv);
	rec_name = save_rec_name;
	rec_name_completed = 1;

	if (fscanf(rec_file, "%u\n%u\n%x\n%x\n",
	    &status_restored_time,
	    &status.guess_count,
	    &status.combs.lo,
	    &status.combs.hi) != 4)
		rec_format_error("fscanf");
	if (!status_restored_time)
		status_restored_time = 1;

	if (rec_version >= 4) {
		if (fscanf(rec_file, "%x\n%x\n%x\n%x\n%x\n%d\n",
		    &status.combs_ehi,
		    &status.crypts.lo,
		    &status.crypts.hi,
		    &status.cands.lo,
		    &status.cands.hi,
		    &status.compat) != 6)
			rec_format_error("fscanf");
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

void rec_restore_mode(int (*restore_mode)(FILE *file))
{
	rec_name_complete();

	if (!rec_file) return;

	if (restore_mode)
	if (restore_mode(rec_file)) rec_format_error("fscanf");

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
