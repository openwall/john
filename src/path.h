/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2000 by Solar Designer
 */

/*
 * Path name expansion routines.
 */

#ifndef _JOHN_PATH_H
#define _JOHN_PATH_H

/*
 * Initializes the home directory path based on argv[0].
 */
extern void path_init(char **argv);

/*
 * Expands "$JOHN/" and "~/" in a path name.
 */
extern char *path_expand(char *name);

/*
 * Frees the memory allocated in path_init().
 */
extern void path_done(void);

#endif
