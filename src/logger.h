/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-99,2003 by Solar Designer
 *
 * ...with field_sep introduced in the jumbo patch, by JimF.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

/*
 * Event logging routines.
 */

#ifndef _JOHN_LOGGER_H
#define _JOHN_LOGGER_H

#include <fcntl.h>

#if defined(F_SETLK) && defined(F_SETLKW) && defined(F_UNLCK)	  \
	&& defined(F_RDLCK) && defined(F_WRLCK)
/*
 * File locking helper. Always use the macro!
 * Return 0 on success, -1 on failure
 */
#define jtr_lock(fd, cmd, type, name)	  \
	log_lock(fd, cmd, type, name, __FUNCTION__, __FILE__, __LINE__)

extern int log_lock(int fd, int cmd, int type, const char *name,
                    const char *function, const char *file, int line);
#else

/*
 * This clause likely only used on MinGW and MSVC.
 *
 * Surely someone should be able to write a trivial fcntl emulator for
 * windows supporting locks, no?!  This is 2019, I simply can't believe
 * there is none. However, *I* am not going to find or write one.
 */
#define jtr_lock(...)

#define F_SETLK
#define F_SETLKW
#define F_UNLCK
#define F_RDLCK
#define F_WRLCK

#endif /* #if defined(F_SETLK) && defined(F_SETLKW) && defined(F_UNLCK)
		&& defined(F_RDLCK) && defined(F_WRLCK) */

/*
 * Macro for warning/notice AND logging.  Arguments are like to fprintf_color
 * but with no ending linefeed (will be added here to screen but not to log).
 */
#define WARN_AND_LOG(color, stream, ...)	  \
	do { \
		fprintf_color(color, stream, __VA_ARGS__); \
		fputc('\n', stream); \
		if (stream == stdout) \
			fflush(stdout); \
		log_event(__VA_ARGS__); \
	} while (0)

/*
 * Macro to only log something once per session.
 */
#define LOG_ONCE(...)	  \
	do { \
		static int warned; \
		if (!warned) { \
			log_event(__VA_ARGS__); \
			warned = 1; \
		} \
	} while (0)

/*
 * Like WARN_AND_LOG, but once per session.
 */
#define WARN_AND_LOG_ONCE(color, stream, ...)	  \
	do { \
		static int warned; \
		if (!warned) { \
			WARN_AND_LOG(color, stream, __VA_ARGS__); \
			warned = 1; \
		} \
	} while (0)

/*
 * Initializes the logger (opens john.pot and a log file).
 */
extern void log_init(char *log_name, char *pot_name, char *session);

/*
 * Prints a guessed password to stdout and logs it to john.pot (unless
 * ciphertext is NULL) and other related information to the log file.
 */
extern void log_guess(char *login, char *uid, char *ciphertext, char *rep_plain,
                      char *store_plain, char field_sep, int index);

/*
 * Logs an arbitrary event.
 *
 * The caller must make sure that any conversion specifiers in the
 * format string expand to no more than 500 characters.
 */
extern
#if (__GNUC__ == 4 && __GNUC_MINOR >= 4) || __GNUC__ > 4
	__attribute__ ((format (gnu_printf, 1, 2)))
#elif __GNUC__
	__attribute__ ((format (printf, 1, 2)))
#endif
void log_event(const char *format, ...);

/*
 * Discards any buffered log data.
 */
extern void log_discard(void);

/*
 * Flushes the john.pot and log file buffers to disk.
 */
extern void log_flush(void);

/*
 * Closes john.pot and the log file.
 */
extern void log_done(void);

#endif
