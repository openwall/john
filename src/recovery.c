/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001 by Solar Designer
 */

#include <stdio.h>
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

char *rec_name = RECOVERY_NAME;
int rec_version = 0;
int rec_argc = 0;
char **rec_argv;

static int rec_fd;
static FILE *rec_file = NULL;
static struct db_main *rec_db;
static void (*rec_save_mode)(FILE *file);

#if defined(LOCK_EX) && OS_FLOCK
static void rec_lock(void)
{
	if (flock(rec_fd, LOCK_EX | LOCK_NB)) {
		if (errno == EWOULDBLOCK) {
			fprintf(stderr, "Crash recovery file is locked: %s\n",
				path_expand(rec_name));
			error();
		} else
			pexit("flock");
	}
}
#else
#define rec_lock() \
	{}
#endif

void rec_init(struct db_main *db, void (*save_mode)(FILE *file))
{
	rec_done(1);

	if (!rec_argc) return;

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

	fprintf(rec_file, RECOVERY_VERSION_CURRENT "\n%d\n",
		rec_argc + (save_format ? 1 : 0));

	opt = rec_argv;
	while (*++opt)
		fprintf(rec_file, "%s\n", *opt);

	if (save_format)
		fprintf(rec_file, "-format:%s\n",
			rec_db->format->params.label);

	fprintf(rec_file, "%u\n%u\n%08x\n%08x\n%d\n%d\n",
		status_get_time() + 1,
		status.guess_count,
		status.crypts.lo,
		status.crypts.hi,
		status.pass,
		status_get_progress ? status_get_progress() : -1);

	if (rec_save_mode) rec_save_mode(rec_file);

	if (ferror(rec_file)) pexit("fprintf");

	if ((size = ftell(rec_file)) < 0) pexit("ftell");
	if (fflush(rec_file)) pexit("fflush");
	if (ftruncate(rec_fd, size)) pexit("ftruncate");
#ifndef __CYGWIN32__
	if (fsync(rec_fd)) pexit("fsync");
#endif
}

void rec_done(int aborted)
{
	if (!rec_file) return;

	if (aborted) rec_save();

	if (fclose(rec_file)) pexit("fclose");
	rec_file = NULL;

	if (!aborted && (!status.pass || status.pass == 3))
	if (unlink(path_expand(rec_name)))
		pexit("unlink: %s", path_expand(rec_name));
}

static void rec_format_error(char *fn)
{
	if (ferror(rec_file)) pexit(fn); else {
		fprintf(stderr, "Incorrect crash recovery file format: %s\n",
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

	if (!(rec_file = fopen(path_expand(rec_name), "r+")))
		pexit("fopen: %s", path_expand(rec_name));
	rec_fd = fileno(rec_file);

	if (lock) rec_lock();

	if (!fgetl(line, sizeof(line), rec_file)) rec_format_error("fgets");

	rec_version = 0;
	if (!strcmp(line, RECOVERY_VERSION_2)) rec_version = 2; else
	if (!strcmp(line, RECOVERY_VERSION_1)) rec_version = 1; else
	if (strcmp(line, RECOVERY_VERSION_0)) rec_format_error("fgets");

	if (fscanf(rec_file, "%d\n", &argc) != 1) rec_format_error("fscanf");
	argv = mem_alloc_tiny(sizeof(char *) * (argc + 1), MEM_ALIGN_WORD);

	argv[0] = "";

	for (index = 1; index < argc; index++)
	if (fgetl(line, sizeof(line), rec_file))
		argv[index] = str_alloc_copy(line);
	else
		rec_format_error("fgets");

	argv[argc] = NULL;

	save_rec_name = rec_name;
	opt_init(argc, argv);
	rec_name = save_rec_name;

	if (fscanf(rec_file, "%u\n%u\n%x\n%x\n",
		&status_restored_time,
		&status.guess_count,
		&status.crypts.lo,
		&status.crypts.hi) != 4) rec_format_error("fscanf");
	if (!status_restored_time) status_restored_time = 1;

	if (rec_version == 0) {
		status.pass = 0;
		status.progress = -1;
	} else
	if (fscanf(rec_file, "%d\n%d\n", &status.pass, &status.progress) != 2)
		rec_format_error("fscanf");
}

void rec_restore_mode(int (*restore_mode)(FILE *file))
{
	if (!rec_file) return;

	if (restore_mode)
	if (restore_mode(rec_file)) rec_format_error("fscanf");

	if (fclose(rec_file)) pexit("fclose");
	rec_file = NULL;
}
