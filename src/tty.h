/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-99,2010 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

/*
 * Terminal support routines.
 */

#ifndef _JOHN_TTY_H
#define _JOHN_TTY_H

/*
 * Initializes the terminal for unbuffered non-blocking input. Also registers
 * tty_done() via atexit().
 * stdin_mode indicates whether we're running with "--stdin" (reading candidate
 * passwords from stdin) or not.
 */
extern void tty_init(int stdin_mode);

/*
 * Reads a character, returns -1 if no data available or on error.
 */
extern int tty_getchar(void);

/*
 * Restores the terminal parameters and closes the file descriptor.
 */
extern void tty_done(void);

#endif
