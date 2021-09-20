/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2005,2006,2010,2013 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

/*
 * Crash recovery routines.
 */

#ifndef _JOHN_RECOVERY_H
#define _JOHN_RECOVERY_H

#include <stdio.h>

#include "loader.h"

/*
 * Crash recovery file name and whether it has been "completed" (by adding
 * the filename suffix to the session name).
 */
extern char *rec_name;
extern int rec_name_completed;

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
 * Are we a restored session?
 */
extern int rec_restored;

/*
 * Are we between a rec_restore_args() and a rec_restore_mode()?
 */
extern int rec_restoring_now;

/*
 * Opens the crash recovery file for writing, and sets a function that will
 * be called to save cracking mode specific information.
 */
extern void rec_init(struct db_main *db, void (*save_mode)(FILE *file));

/*
 * Sets a 'hybrid' save function. These are called after calling the 'main'
 * save function.
 */
extern void rec_init_hybrid(void (*save_mode)(FILE *file));

/*
 * Saves the command line arguments and cracking mode specific information.
 */
extern void rec_save(void);

/*
 * Calls log_flush(), optionally calls rec_save(), optionally closes the crash
 * recovery file (which unlocks it), and finally optionally removes the file.
 *
 * The "save" parameter is interpreted as follows:
 *
 * "save == 1" means to call rec_save(), close the file, and keep it around;
 *
 * "save == 0" means to skip the rec_save() call and to close and remove the
 * file, unless we're the main process of a --fork'ed group of children, in
 * which case rec_save() is called and the file is left opened and non-removed;
 *
 * "save == -1" means to skip the rec_save() call and to close and remove the
 * file (unconditionally);
 *
 * "save == -2" means to skip the rec_save() call and to close the file, yet
 * leave it around.
 *
 * "save == 1" and "save == 0" are used from cracking-mode specific code,
 * in the form of calling rec_done(event_abort) or similar.  If we're aborting
 * a session, we want to update its crash recovery file and keep the file
 * around.  If the session has completed, we want to remove the file, unless
 * we're the main process and we need to wait for children (in which case our
 * file is still needed to be able to restart and wait for those children again
 * upon --restore).
 *
 * "save == -1" and "save == -2" are only used by the main process when and as
 * appropriate, such as to complete the unfinished work of rec_done(0).
 */
extern void rec_done(int save);

/*
 * Opens the file and restores command line arguments. Leaves the file open.
 * MPI code path call rec_restore_args(mpi_p) which in turn calls rec_lock()
 * with same argument - relying on anything >1 meaning LOCK_SH.
 */
extern void rec_restore_args(int lock);

/*
 * Restores cracking mode specific information and closes the file.
 */
extern void rec_restore_mode(int (*restore_mode)(FILE *file));

/*
 * Reads status.cands from other session's file and returns it.
 */
extern uint64_t rec_read_cands(char *session);

#endif
