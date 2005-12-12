/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2005 by Solar Designer
 */

/*
 * Crash recovery routines.
 */

#ifndef _JOHN_RECOVERY_H
#define _JOHN_RECOVERY_H

#include <stdio.h>

#include "loader.h"

/*
 * Crash recovery file name.
 */
extern char *rec_name;

/*
 * Crash recovery file format version number.
 */
extern int rec_version;

/*
 * Original command line arguments.
 */
extern int rec_argc;
extern char **rec_argv;

/*
 * Checksum (or equivalent) of the file(s) being processed by the current
 * cracking mode.
 */
extern unsigned int rec_check;

/*
 * Opens the crash recovery file for writing, and sets a function that will
 * be called to save cracking mode specific information.
 */
extern void rec_init(struct db_main *db, void (*save_mode)(FILE *file));

/*
 * Saves the command line arguments and cracking mode specific information.
 */
extern void rec_save(void);

/*
 * Closes the crash recovery file.
 * If the session is complete the file is unlinked.
 */
extern void rec_done(int aborted);

/*
 * Opens the file and restores command line arguments. Leaves the file open.
 */
extern void rec_restore_args(int lock);

/*
 * Restores cracking mode specific information and closes the file.
 */
extern void rec_restore_mode(int (*restore_mode)(FILE *file));

#endif
