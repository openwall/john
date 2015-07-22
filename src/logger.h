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
