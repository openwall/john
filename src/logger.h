/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-99 by Solar Designer
 */

/*
 * Guess logging routines.
 */

#ifndef _JOHN_LOGGER_H
#define _JOHN_LOGGER_H

/*
 * Initializes the logger for a file.
 */
extern void log_init(char *name);

/*
 * Prints a guessed password to stdout and logs it to the file (unless
 * ciphertext is NULL).
 */
extern void log_guess(char *login, char *ciphertext, char *plaintext);

/*
 * Writes the log file buffer to disk.
 */
extern void log_flush(void);

/*
 * Closes the log file.
 */
extern void log_done(void);

#endif
