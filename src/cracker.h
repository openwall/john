/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-99 by Solar Designer
 */

/*
 * Cracking routines.
 */

#ifndef _JOHN_CRACKER_H
#define _JOHN_CRACKER_H

#include "loader.h"

/*
 * Initializes the cracker for a password database (should not be empty).
 * If fix_state() is not NULL, it will be called when key buffer becomes
 * empty, its purpose is to save current state for possible recovery in
 * the future. If guesses is not NULL, the cracker will save guessed keys
 * in there (the caller must make sure there's room).
 */
extern void crk_init(struct db_main *db, void (*fix_state)(void),
	struct db_keys *guesses);

/*
 * Tries the key against all passwords in the database (should not be empty).
 * The return value is non-zero if aborted or everything got cracked (the
 * event_abort flag can be used to find out which of these has happened).
 */
extern int crk_process_key(char *key);

/*
 * Resets the guessed keys buffer and processes all the buffered keys for
 * this salt. The return value is the same as for crk_process_key().
 */
extern int crk_process_salt(struct db_salt *salt);

/*
 * Return current keys range, crk_get_key2() may return NULL if there's only
 * one key. Note: these functions may share a static result buffer.
 */
extern char *crk_get_key1(void);
extern char *crk_get_key2(void);

/*
 * Processes all the buffered keys (unless aborted).
 */
extern void crk_done(void);

#endif
