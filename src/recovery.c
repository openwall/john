/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2003,2005,2006,2009,2010 by Solar Designer
 *
 * ...with changes in the jumbo patch, by JimF.
 */

#ifndef __FreeBSD__
/* On FreeBSD, defining this precludes the declaration of u_int, which
 * FreeBSD's own <sys/file.h> needs. */
#define _XOPEN_SOURCE 500 /* for fdopen(3), fileno(3), fsync(2), ftruncate(2) */
#endif

#include <stdio.h>
#ifndef _MSC_VER
#include <unistd.h>
#else
#include <io.h>
#pragma warning ( disable : 4996 )
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifndef _MSC_VER
#include <sys/file.h>
#endif
#include <errno.h>
#include <string.h>
#ifdef HAVE_MPI
#include "john-mpi.h"
#include "signals.h"
#endif

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
#ifdef HAVE_MPI
int rec_name_completed = 0;
#else
int rec_name_completed = 1;
#endif
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
#ifdef HAVE_MPI
	char *mpi_suffix;
#endif
	if (rec_name_completed) return;
#ifdef HAVE_MPI
	mpi_suffix = mem_alloc_tiny(strlen(id2string()) + 1 +
	    strlen(RECOVERY_SUFFIX) + 1, MEM_ALIGN_NONE);
	mpi_suffix[0] = 0;
	if (mpi_p > 1) {
		strcat(mpi_suffix, ".");
		strcat(mpi_suffix, id2string());
	}
	strcat(mpi_suffix, RECOVERY_SUFFIX);

	rec_name = path_session(rec_name, mpi_suffix);
#else
	rec_name = path_session(rec_name, RECOVERY_SUFFIX);
#endif
	rec_name_completed = 1;
}

#if defined(LOCK_EX) && OS_FLOCK
static void rec_lock(void)
{
	if (flock(rec_fd, LOCK_EX | LOCK_NB)) {
		if (errno == EWOULDBLOCK) {
#ifdef HAVE_MPI
			fprintf(stderr, "Node %d@%s: Crash recovery file is locked: %s\n",
			        mpi_id, mpi_name, path_expand(rec_name));
#else
			fprintf(stderr, "Crash recovery file is locked: %s\n",
				path_expand(rec_name));
#endif
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
	int save_format, hund;
	long size;
	char **opt;

	log_flush();

	if (!rec_file) return;

	if (fseek(rec_file, 0, SEEK_SET)) pexit("fseek");
#ifdef _MSC_VER
	if (_write(fileno(rec_file), "", 0)) pexit("ftruncate");
#elif __CYGWIN32__
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

	fprintf(rec_file, "%u\n%u\n%08x\n%08x\n%d\n%d\n%08x\n",
		status_get_time() + 1,
		status.guess_count,
		status.crypts.lo,
		status.crypts.hi,
		status.pass,
		status_get_progress ? status_get_progress(&hund) : -1,
		rec_check);

	if (rec_save_mode) rec_save_mode(rec_file);

	if (ferror(rec_file)) pexit("fprintf");

	if ((size = ftell(rec_file)) < 0) pexit("ftell");
	if (fflush(rec_file)) pexit("fflush");
#ifndef _MSC_VER
	if (ftruncate(rec_fd, size)) pexit("ftruncate");
#endif
#if !defined(__CYGWIN32__) && !defined(__MINGW32__) && !defined (_MSC_VER)
	if (fsync(rec_fd)) pexit("fsync");
#endif
}

void rec_done(int save)
{
	if (!rec_file) return;

	if (save)
		rec_save();
	else
#ifdef HAVE_MPI
	{
		log_flush();
		if (mpi_p > 1) {
			if (rec_db->password_count) {
#ifdef JOHN_MPI_BARRIER
				int time = status_get_time();
				if (nice(20) < 0) fprintf(stderr, "nice() failed\n");
				fprintf(stderr, "Node %d finished at %u:%02u:%02u:%02u.\n", mpi_id, time / 86400, time % 86400 / 3600, time % 3600 / 60, time % 60);
				MPI_Barrier(MPI_COMM_WORLD);
#endif
			} else {
#ifdef JOHN_MPI_ABORT
				int time = status_get_time();
				fprintf(stderr, "Node %d: All hashes cracked at %u:%02u:%02u:%02u! Aborting other nodes.\n", mpi_id, time / 86400, time % 86400 / 3600, time % 3600 / 60, time % 60);
				MPI_Abort(MPI_COMM_WORLD, 0);
#else
				fprintf(stderr, "Node %d: All hashes cracked! Abort the other nodes manually!\n", mpi_id);
#endif
			}
		}
	}
#else
	log_flush();
#endif

	if (fclose(rec_file)) pexit("fclose");
	rec_file = NULL;

	if (!save && unlink(path_expand(rec_name)))
		pexit("unlink: %s", path_expand(rec_name));
}

static void rec_format_error(char *fn)
{
	if (fn && errno && ferror(rec_file))
		pexit("%s", fn);
	else {
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

	rec_name_complete();
	if (!(rec_file = fopen(path_expand(rec_name), "r+")))
		pexit("fopen: %s", path_expand(rec_name));
	rec_fd = fileno(rec_file);

	if (lock) rec_lock();

	if (!fgetl(line, sizeof(line), rec_file)) rec_format_error("fgets");

	rec_version = 0;
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
		&status.crypts.lo,
		&status.crypts.hi) != 4) rec_format_error("fscanf");
	if (!status_restored_time) status_restored_time = 1;

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
	if (!rec_file) return;

	if (restore_mode)
	if (restore_mode(rec_file)) rec_format_error("fscanf");

	if (fclose(rec_file)) pexit("fclose");
	rec_file = NULL;

	rec_restoring_now = 0;
}
