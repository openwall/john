/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-99,2003 by Solar Designer
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
extern void log_guess(char *login, char *ciphertext, char *plaintext);

/*
 * Logs an arbitrary event.
 */
extern void log_event(char *event);

/*
 * Flushes the john.pot and log file buffers to disk.
 */
extern void log_flush(void);

/*
 * Closes john.pot and the log file.
 */
extern void log_done(void);

#endif
