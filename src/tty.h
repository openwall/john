/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-99 by Solar Designer
 */

/*
 * Terminal support routines.
 */

#ifndef _JOHN_TTY_H
#define _JOHN_TTY_H

/*
 * Initializes the terminal for unbuffered non-blocking input. Also registers
 * tty_done() via atexit().
 */
extern void tty_init(void);

/*
 * Reads a character, returns -1 if no data available or on error.
 */
extern int tty_getchar(void);

/*
 * Restores the terminal parameters and closes the file descriptor.
 */
extern void tty_done(void);

#endif
