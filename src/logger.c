/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-99,2003,2004,2010,2013 by Solar Designer
 *
 * ...with changes in the jumbo patch, by JimF and magnum.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE /* for fileno(3) and fsync(2) */
#endif

#define NEED_OS_FLOCK
#include "os.h"

#include <stdio.h>
#if (!AC_BUILT || HAVE_UNISTD_H) && !_MSC_VER
#include <unistd.h>
#endif
#if !AC_BUILT || HAVE_SYS_FILE_H
#include <sys/file.h>
#endif
#if _MSC_VER
#include <io.h>
#pragma warning ( disable : 4996 )
#define S_IRUSR _S_IREAD
#define S_IWUSR _S_IWRITE
#endif
#include <sys/types.h>
#include <sys/stat.h>
#if (!AC_BUILT || HAVE_FCNTL_H)
#include <fcntl.h>
#endif
#include <errno.h>
#include <time.h>
#include <stdarg.h>
#include <string.h>
#include <signal.h>

#include "arch.h"
#include "misc.h"
#include "params.h"
#include "path.h"
#include "memory.h"
#include "status.h"
#include "options.h"
#include "config.h"
#include "recovery.h"
#include "unicode.h"
#include "dynamic.h"
#ifdef HAVE_MPI
#include "john-mpi.h"
#endif
#include "cracker.h"
#include "signals.h"
#include "memdbg.h"

static int cfg_beep;
static int cfg_log_passwords;
static int cfg_showcand;
static char *LogDateFormat;
static char *LogDateStderrFormat;
static int LogDateFormatUTC=0;
static char *log_perms;
static char *pot_perms;

#ifdef _MSC_VER
// I am not sure if there would be other systems which do know know about mode_t
typedef unsigned mode_t;
#endif

// windows does not have these unix specific constants.
#ifndef S_ISUID
#define S_ISUID 0004000
#endif
#ifndef S_IXUSR
#define S_IXUSR 0000100
#endif
#ifndef S_IXGRP
#define S_IXGRP 0000010
#endif
#ifndef S_IXOTH
#define S_IXOTH 0000001
#endif

static mode_t perms_t;

/*
 * Note: the file buffer is allocated as (size + LINE_BUFFER_SIZE) bytes
 * and (ptr - buffer) may actually exceed size by up to LINE_BUFFER_SIZE.
 * As long as log_file_write() is called after every write to the buffer,
 * there's always room for at least LINE_BUFFER_SIZE bytes to be added.
 */
struct log_file {
	char *name;
	char *buffer, *ptr;
	int size;
	int fd;
};

#ifdef _MSC_VER
// In release mode, the log() function gets in the way of our log struct object
#define log local_log_struct
#endif

static struct log_file log = {NULL, NULL, NULL, 0, -1};
static struct log_file pot = {NULL, NULL, NULL, 0, -1};

static int in_logger = 0;

static void log_file_init(struct log_file *f, char *name, char *perms, int size)
{
	perms_t = strtoul(perms, NULL, 8);

	if ((perms_t & (S_IXUSR | S_IXGRP | S_IXOTH | S_ISUID)) ||
	    ((perms_t & (S_IRUSR | S_IWUSR)) != (S_IRUSR | S_IWUSR))) {
		fprintf(stderr, "%sFilePerms %s invalid\n",
		        (f == &log) ? "Log" : "Pot", perms);
		error();
	}

	if (f == &log && (options.flags & FLG_NOLOG)) return;
	f->name = name;

	if (chmod(path_expand(name), perms_t) && (errno != ENOENT)) {
		if (errno == EPERM && cfg_get_bool(SECTION_OPTIONS, NULL,
		                                   "IgnoreChmodErrors", 0))
			fprintf(stdout, "Note: chmod of %s to %s failed\n",
			        path_expand(name), perms);
		else
			pexit("chmod: %s", path_expand(name));
	}

#ifndef _MSC_VER
    umask(000);
#endif

	if ((f->fd = open(path_expand(name),
	    O_WRONLY | O_CREAT | O_APPEND, perms_t)) < 0)
		pexit("open: %s", path_expand(name));

#ifndef _MSC_VER
    umask(077);
#endif

	/*
	 * plain will now always be < LINE_BUFFER_SIZE. We add some extra bytes
	 * so that there is ALWAYS enough buffer to write our line, and we no
	 * longer have to check length before a write (.pot or .log file).
	 * The "64" comes from core.
	 */
	f->ptr = f->buffer =
		mem_alloc(size + LINE_BUFFER_SIZE + PLAINTEXT_BUFFER_SIZE + 64);
	f->size = size;
}

static void log_file_flush(struct log_file *f)
{
	int count;
	long int pos_b4 = 0;
#if FCNTL_LOCKS
	struct flock lock;
#endif

	if (f->fd < 0) return;

	count = f->ptr - f->buffer;
	if (count <= 0) return;

#if OS_FLOCK || FCNTL_LOCKS
#ifdef LOCK_DEBUG
	fprintf(stderr, "%s(%u): Locking %s...\n",
	        __FUNCTION__, options.node_min, f->name);
#endif
#if FCNTL_LOCKS
	memset(&lock, 0, sizeof(lock));
	lock.l_type = F_WRLCK;
	while (fcntl(f->fd, F_SETLKW, &lock)) {
		if (errno != EINTR)
			pexit("fcntl(F_WRLCK)");
	}
#else
	while (flock(f->fd, LOCK_EX)) {
		if (errno != EINTR)
			pexit("flock(LOCK_EX)");
	}
#endif
#ifdef LOCK_DEBUG
	fprintf(stderr, "%s(%u): Locked %s exclusively\n",
	        __FUNCTION__, options.node_min, f->name);
#endif
#endif

	if (f == &pot) {
		pos_b4 = (long int)lseek(f->fd, 0, SEEK_END);
#if defined(LOCK_DEBUG)
		fprintf(stderr,
		        "%s(%u): writing %d at %ld, ending at %ld to file %s\n",
		        __FUNCTION__, options.node_min, count, pos_b4,
		        pos_b4+count, f->name);
#endif
	}

	if (write_loop(f->fd, f->buffer, count) < 0) pexit("write");
	f->ptr = f->buffer;

	if (f == &pot && pos_b4 == crk_pot_pos)
		crk_pot_pos += count;

#if OS_FLOCK || FCNTL_LOCKS
#ifdef LOCK_DEBUG
	fprintf(stderr, "%s(%u): Unlocking %s\n",
	        __FUNCTION__, options.node_min, f->name);
#endif
#if FCNTL_LOCKS
	lock.l_type = F_UNLCK;
	fcntl(f->fd, F_SETLK, &lock);
#else
	if (flock(f->fd, LOCK_UN))
		pexit("flock(LOCK_UN)");
#endif
#endif

#ifdef SIGUSR2
	/* We don't really send a sync trigger "at crack" but
	   after it's actually written to the pot file. That is, now. */
	if (f == &pot && !event_abort && options.reload_at_crack) {
#ifdef HAVE_MPI
		if (mpi_p > 1) {
			int i;

			for (i = 0; i < mpi_p; i++) {
				if (i == mpi_id)
					continue;
				if (mpi_req[i] == NULL)
					mpi_req[i] = mem_alloc_tiny(
						sizeof(MPI_Request),
						MEM_ALIGN_WORD);
				else
					if (*mpi_req[i] != MPI_REQUEST_NULL)
						continue;
				MPI_Isend("r", 1, MPI_CHAR, i, JOHN_MPI_RELOAD,
				          MPI_COMM_WORLD, mpi_req[i]);
			}
		} else
#endif
		if (options.fork)
			raise(SIGUSR2);
	}
#endif
}

static int log_file_write(struct log_file *f)
{
	if (f->fd < 0) return 0;
	if (f->ptr - f->buffer > f->size) {
		log_file_flush(f);
		return 1;
	}

	return 0;
}

static void log_file_fsync(struct log_file *f)
{
	if (f->fd < 0) return;

	log_file_flush(f);
#if !HAVE_WINDOWS_H
	if (fsync(f->fd)) pexit("fsync");
#endif
}

static void log_file_done(struct log_file *f, int do_sync)
{
	if (f->fd < 0) return;

	if (do_sync)
		log_file_fsync(f);
	else
		log_file_flush(f);
	if (close(f->fd)) pexit("close");
	f->fd = -1;

	MEM_FREE(f->buffer);
}

static int log_time(void)
{
	int count1, count2;
	unsigned int Time;

	count1 = 0;

	Time = pot.fd >= 0 ? status_get_time() : status_restored_time;

	if (LogDateFormat) {
		struct tm *t_m;
		char Buf[128];
		time_t t;

		t = time(0);
		if (LogDateFormatUTC)
			t_m = gmtime(&t);
		else
			t_m = localtime(&t);
		strftime(Buf, sizeof(Buf), LogDateFormat, t_m);
		count2 = (int)sprintf(log.ptr + count1, "%s ", Buf);
		if (count2 < 0)
			return count2;
		count1 += count2;
	}

#ifndef HAVE_MPI
	if (options.fork) {
#else
	if (options.fork || mpi_p > 1) {
#endif
		count2 = (int)sprintf(log.ptr + count1,
		                      "%u ", options.node_min);
		if (count2 < 0)
			return count2;
		count1 += count2;
	}

	count2 = (int)sprintf(log.ptr + count1, "%u:%02u:%02u:%02u ",
	    Time / 86400, Time % 86400 / 3600,
	    Time % 3600 / 60, Time % 60);
	if (count2 < 0)
		return count2;

	return count1 + count2;
}

void log_init(char *log_name, char *pot_name, char *session)
{
	in_logger = 1;

	if (log_name && log.fd < 0) {
		if (session)
			log_name = path_session(session, LOG_SUFFIX);
		if (!rec_restored && !(options.flags & FLG_NOLOG)) {
			const char *protect;
			if (!(protect = cfg_get_param(SECTION_OPTIONS, NULL,
			                              "LogFileProtect")))
				protect = "Disabled";
			if (((!strcasecmp(protect, "Named")) &&
			     strcmp(log_name, LOG_NAME)) ||
			    (!strcasecmp(protect, "Always"))) {
				struct stat st;
				if (!stat(path_expand(log_name), &st)) {
					fprintf(stderr,
					        "ERROR: LogFileProtect enabled in john.conf, and %s exists\n",
					        path_expand(log_name));
					error();
				}
			}
		}
		if (!(log_perms = cfg_get_param(SECTION_OPTIONS, NULL,
						"LogFilePermissions")))
			log_perms = "0600";

		log_file_init(&log, log_name, log_perms , LOG_BUFFER_SIZE);
	}

	if (pot_name && pot.fd < 0) {
                if (!(pot_perms = cfg_get_param(SECTION_OPTIONS, NULL,
						"PotFilePermissions")))
			pot_perms = "0600";

		log_file_init(&pot, pot_name, pot_perms, POT_BUFFER_SIZE);

		cfg_beep = cfg_get_bool(SECTION_OPTIONS, NULL, "Beep", 0);
	}

	cfg_log_passwords = cfg_get_bool(SECTION_OPTIONS, NULL,
	                                 "LogCrackedPasswords", 0);
	cfg_showcand = cfg_get_bool(SECTION_OPTIONS, NULL,
	                            "StatusShowCandidates", 0);
	LogDateFormat = cfg_get_param(SECTION_OPTIONS, NULL,
			            "LogDateFormat");
	LogDateFormatUTC = cfg_get_bool(SECTION_OPTIONS, NULL,
	                            "LogDateFormatUTC", 0);
	LogDateStderrFormat = cfg_get_param(SECTION_OPTIONS, NULL,
			            "LogDateStderrFormat");
	in_logger = 0;
}

static char *components(char *string, int len)
{
	static char out[16];
	unsigned char *p = (unsigned char*)string;
	unsigned char c;
	int l, u, d, s, h;

	l = u = d = s = h = 0;

	while ((c = *p++)) {
		if (c >= 'a' && c <= 'z')
			l = 1;
		else if (c >= 'A' && c <= 'Z')
			u = 1;
		else if (c >= '0' && c <= '9')
			d = 1;
		else if (c < 128)
			s = 1;
		else
			h = 1;
	}

	sprintf(out, "L%d-%s%s%s%s%s", len, l ? "?l" : "", d ? "?d" : "",
	        u ? "?u" : "", s ? "?s" : "", h ? "?h" : "");

	return out;
}

void log_guess(char *login, char *uid, char *ciphertext, char *rep_plain,
               char *store_plain, char field_sep, int index)
{
	int count1, count2;
	int len;
	char spacer[] = "                ";
	char *secret = "";
	char uid_sep[2] = { 0 };
	char *uid_out = "";

/* This is because printf("%-16s") does not line up multibyte UTF-8.
   We need to count characters, not octets. */
	if (options.target_enc == UTF_8 || options.report_utf8)
		len = strlen8((UTF8*)rep_plain);
	else
		len = strlen(rep_plain);

	if (options.show_uid_in_cracks && uid && *uid) {
		uid_sep[0] = field_sep;
		uid_out = uid;
	}

	if (options.verbosity > 1) {
		if (options.secure) {
			secret = components(rep_plain, len);
			printf("%-16s (%s%s%s)\n",
			       secret, login, uid_sep, uid_out);
		} else {
			spacer[len > 16 ? 0 : 16 - len] = 0;

			printf("%s%s (%s%s%s)\n",
			       rep_plain, spacer, login, uid_sep, uid_out);

			if (options.fork)
				fflush(stdout);
		}
	}

	in_logger = 1;

	if (pot.fd >= 0 && ciphertext ) {
#ifndef DYNAMIC_DISABLED
		if (!strncmp(ciphertext, "$dynamic_", 9))
			ciphertext = dynamic_FIX_SALT_TO_HEX(ciphertext);
#endif
		if (options.secure) {
			secret = components(store_plain, len);
			count1 = (int)sprintf(pot.ptr,
				                "%s%c%s\n",
				                ciphertext,
				                field_sep,
				                secret);
		} else
			count1 = (int)sprintf(pot.ptr,
				                "%s%c%s\n", ciphertext,
				                field_sep, store_plain);
		if (count1 > 0) pot.ptr += count1;
	}

	if (log.fd >= 0) {
		count1 = log_time();
		if (count1 > 0) {
			log.ptr += count1;
			count2 = (int)sprintf(log.ptr, "+ Cracked %s%s%s",
			                      login, uid_sep, uid_out);

			if (options.secure) {
				secret = components(rep_plain, len);
				count2 += (int)sprintf(log.ptr + count2,
				                       ": %s", secret);
			} else
			if (cfg_log_passwords)
				count2 += (int)sprintf(log.ptr + count2,
				                       ": %s", rep_plain);
			if (cfg_showcand)
				count2 += (int)sprintf(log.ptr + count2,
				                       " as candidate #%"PRIu64,
				                       status.cands +
				                       index + 1);
			count2 += (int)sprintf(log.ptr + count2, "\n");

			if (count2 > 0)
				log.ptr += count2;
			else
				log.ptr -= count1;
		}
	}

/* Try to keep the two files in sync */
	if (log_file_write(&pot))
		log_file_flush(&log);
	else
	if (log_file_write(&log))
		log_file_flush(&pot);

	in_logger = 0;

	if (cfg_beep)
		write_loop(fileno(stderr), "\007", 1);
}

void log_event(const char *format, ...)
{
	va_list args;
	int count1, count2;

	if (options.flags & FLG_LOG_STDERR) {
		unsigned int Time;

		if (LogDateStderrFormat) {
			struct tm *t_m;
			char Buf[128];
			time_t t;

			t = time(0);
			if (LogDateFormatUTC)
				t_m = gmtime(&t);
			else
				t_m = localtime(&t);
			strftime(Buf, sizeof(Buf), LogDateStderrFormat, t_m);
			fprintf(stderr, "%s ", Buf);
		}

#ifndef HAVE_MPI
		if (options.fork)
#else
		if (options.fork || mpi_p > 1)
#endif
			fprintf(stderr, "%u ", options.node_min);

		Time = pot.fd >= 0 ? status_get_time() : status_restored_time;

		fprintf(stderr, "%u:%02u:%02u:%02u ",
		        Time / 86400, Time % 86400 / 3600,
		        Time % 3600 / 60, Time % 60);

		va_start(args, format);
		vfprintf(stderr, format, args);
		va_end(args);
		fprintf(stderr, "\n");
		if (options.flags & FLG_NOLOG)
			return;
	}

	if (log.fd < 0) return;

/*
 * Handle possible recursion:
 * log_*() -> ... -> pexit() -> ... -> log_event()
 */
	if (in_logger) return;
	in_logger = 1;

	count1 = log_time();
	if (count1 > 0 &&
	    count1 + strlen(format) < LINE_BUFFER_SIZE - 500 - 1) {
		log.ptr += count1;

		va_start(args, format);
		count2 = (int)vsprintf(log.ptr, format, args);
		va_end(args);

		if (count2 > 0) {
			log.ptr += count2;
			*log.ptr++ = '\n';
		} else
			log.ptr -= count1;

		if (log_file_write(&log))
			log_file_flush(&pot);
	}

	in_logger = 0;
}

void log_discard(void)
{
	if ((options.flags & FLG_NOLOG)) return;
	log.ptr = log.buffer;
}

void log_flush(void)
{
	in_logger = 1;

	if (options.fork)
		log_file_flush(&log);
	else
		log_file_fsync(&log);
	log_file_fsync(&pot);

	in_logger = 0;
}

void log_done(void)
{
/*
 * Handle possible recursion:
 * log_*() -> ... -> pexit() -> ... -> log_done()
 */
	if (in_logger) return;
	in_logger = 1;

	log_file_done(&log, !options.fork);
	log_file_done(&pot, 1);

	in_logger = 0;
}
