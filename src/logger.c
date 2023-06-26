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

#if !AC_BUILT && !defined(_XOPEN_SOURCE)
#define _XOPEN_SOURCE 500 /* for fileno(3) and fsync(2) */
#define _XPG6
#endif
#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* for strcasestr */
#endif

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
#include <errno.h>
#include <sys/time.h> /* for struct timeval */
#include <time.h>
#include <stdarg.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>

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
#include "john_mpi.h"
#include "cracker.h"
#include "signals.h"
#include "logger.h"

static int cfg_beep;
static int cfg_log_passwords;
static int cfg_showcand;
static const char *LogDateFormat;
static const char *LogDateStderrFormat;
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

static char *admin_start, *admin_end, *admin_string, *terminal_reset;
static char *other_start, *other_end;
static int in_logger, show_admins;

#if !(__MINGW32__ || _MSC_VER)

/*
 * Shared helper for locking a file. Caller uses jtr_lock(fd, cmd, type, name)
 * with fcntl syntax for cmd and type. jtr_lock is actually a macro adding
 * __FUNCTION__, __FILE__ and __LINE__ to params and calling log_lock.
 */
int log_lock(int fd, int cmd, int type, const char *name,
             const char *function, const char *source_file, int line)
{
	struct flock lock;

	memset(&lock, 0, sizeof(lock));
#ifdef LOCK_DEBUG
	fprintf(stderr, "%u: %s(): Locking %s (%s, %s)...\n",
	        NODE, function, name,
	        type == F_RDLCK ? "F_RDLCK" : type == F_WRLCK ? "F_WRLCK"
	        : type == F_UNLCK ? "F_UNLCK" : "",
	        cmd == F_SETLKW ? "F_SETLKW" : cmd == F_SETLK ? "F_SETLK"
	        : cmd == F_UNLCK ? "F_UNLCK" : "");
#endif

	lock.l_type = type;
	while (fcntl(fd, cmd, &lock)) {
		if (errno == EAGAIN) {
			static int warned;
			struct timeval t;

			if (cmd == F_SETLK)
				return -1;

			if (!warned++) {
				log_event("Got EAGAIN despite F_SETLKW (only logged once per node) %s:%d %s", source_file, line, function);
				fprintf(stderr, "Node %d: File locking apparently exhausted, check ulimits and any NFS server limits. This is recoverable but will harm performance (muting further of these messages from same node)\n", NODE);
				srand(NODE);
			}

			/* Sleep for a random time of max. ~260 ms */
			t.tv_sec = 0; t.tv_usec = (rand() & 1023) << 8;
			select(0, NULL, NULL, NULL, &t);
			continue;
		} else if (errno != EINTR)
			pexit("%s:%d %s() fcntl(%s, %s, %s)",
			      source_file, line, function, name,
			      type == F_RDLCK ? "F_RDLCK" : type == F_WRLCK ? "F_WRLCK"
			      : type == F_UNLCK ? "F_UNLCK" : "",
			      cmd == F_SETLKW ? "F_SETLKW" : cmd == F_SETLK ? "F_SETLK"
			      : cmd == F_UNLCK ? "F_UNLCK" : "");
	}

#ifdef LOCK_DEBUG
	fprintf(stderr, "%u: %s(): Locked %s\n", NODE, function, name);
#endif
	return 0;
}
#endif /* !(__MINGW32__ || _MSC_VER) */

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

	if (f->fd < 0) return;

	count = f->ptr - f->buffer;
	if (count <= 0) return;

	jtr_lock(f->fd, F_SETLKW, F_WRLCK, f->name);

	if (f == &pot)
		pos_b4 = (long int)lseek(f->fd, 0, SEEK_END);


	if (write_loop(f->fd, f->buffer, count) < 0) pexit("write");
	f->ptr = f->buffer;

	if (f == &pot && pos_b4 == crk_pot_pos)
		crk_pot_pos += count;

	jtr_lock(f->fd, F_SETLK, F_UNLCK, f->name);

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

	if (LogDateFormat && *LogDateFormat) {
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
		                      "%u ", NODE);
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

/*
 * Change of "^" in passed string to ANSI Escape.
 * If input is a NULL pointer or feature is disabled, return a null string.
 */
static char *parse_esc(const char *string)
{
	char *out = str_alloc_copy(string);
	char *s = out;

	if (!show_admins || !s)
		return "";

	while (*s) {
		if (*s == '^')
			*s = 0x1b;
		s++;
	}

	return out;
}

void log_init(char *log_name, char *pot_name, char *session)
{
	in_logger = 1;

	show_admins = cfg_get_bool(SECTION_OPTIONS, NULL, "MarkAdminCracks", 0);

	if (isatty(fileno(stdout))) {
		admin_start = parse_esc(cfg_get_param(SECTION_OPTIONS, NULL,
		                                      "MarkAdminStart"));
		admin_end = parse_esc(cfg_get_param(SECTION_OPTIONS, NULL,
		                                    "MarkAdminEnd"));
		other_start = parse_esc(cfg_get_param(SECTION_OPTIONS, NULL,
		                                      "MarkOtherStart"));
		other_end = parse_esc(cfg_get_param(SECTION_OPTIONS, NULL,
		                                    "MarkOtherEnd"));
		terminal_reset = parse_esc(cfg_get_param(SECTION_OPTIONS, NULL,
		                                         "TerminalReset"));
	} else
		admin_start = admin_end = other_start = other_end = terminal_reset = "";

	admin_string = parse_esc(cfg_get_param(SECTION_OPTIONS, NULL,
	                                       "MarkAdminString"));

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
		if (!(log_perms = (char*)cfg_get_param(SECTION_OPTIONS, NULL,
						"LogFilePermissions")))
			log_perms = "0600";

		log_file_init(&log, log_name, log_perms , LOG_BUFFER_SIZE);
	}

	if (pot_name && pot.fd < 0) {
                if (!(pot_perms = (char*)cfg_get_param(SECTION_OPTIONS, NULL,
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

/* Quick'n'dirty guess of whether user is an administrator or not */
static int is_admin(char *login, char *uid)
{
	if (login) {
		char *s;

		if (strcasestr(login, "admin") || strcasestr(login, "root") ||
		    strcasestr(login, "super") || strcasestr(login, "sysadm") ||
		    !strcasecmp(login, "toor") || !strcasecmp(login, "sa"))
			return 1;

		/* Avoid false positives for this short substring */
		if ((s = strcasestr(login, "adm"))) {
			char c;

			if (s > login) {
				c = s[-1];

				if (c < 'A' || c > 'z' ||
				    (c > 'Z' && c < 'a'))
					return 1;
			}

			c = s[3];
			if (c < 'A' || c > 'z' || (c > 'Z' && c < 'a'))
				return 1;
		}
	}

	if (!uid)
		return 0;

	if (!strcmp(uid, "0"))
		return 1;

	if (!options.format || !strncasecmp(options.format, "nt", 2) ||
	    !strncasecmp(options.format, "lm", 2))
		if (!strcmp(uid, "500"))
			return 1;

	return 0;
}

#define ADM_START admin ? admin_start : other_start
#define ADM_END   admin ? admin_end : other_end

void log_guess(char *login, char *uid, char *ciphertext, char *rep_plain,
               char *store_plain, char field_sep, int index)
{
	int count1, count2;
	int len;
	char *secret = "";
	char uid_sep[2] = { 0 };
	char *uid_out = "";
	int admin = is_admin(login, uid);

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

	if (options.verbosity > 2 || (admin && options.verbosity > 1)) {
		if (options.secure) {
			secret = components(rep_plain, len);
			printf("%-16s (%s%s%s%s%s)     \n", secret,
			       ADM_START, login, uid_sep, uid_out, ADM_END);
		} else {
			char spacer[] = "                ";

			spacer[len > 16 ? 0 : 16 - len] = 0;

			printf("%s%s%s%s (%s%s%s%s%s%s)     \n", ADM_START, rep_plain, ADM_END,
			       spacer, ADM_START, login, ADM_END,
			       uid_sep, uid_out, terminal_reset);

			if (options.fork)
				fflush(stdout);
		}
	}

	in_logger = 1;

	if (pot.fd >= 0 && ciphertext ) {
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
			if (admin && *admin_string)
				count2 += (int)sprintf(log.ptr + count2,
				                       " %s", admin_string);
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

	if (options.log_stderr) {
		unsigned int Time;

		if (LogDateStderrFormat && *LogDateStderrFormat) {
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
			fprintf(stderr, "%u ", NODE);

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
