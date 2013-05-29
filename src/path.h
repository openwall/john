/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2000,2010 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
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
 * The returned buffer might be overwritten with subsequent calls.
 */
extern char *path_expand(char *name);

/*
 * Generates a filename for the given session name and filename suffix.
 * Memory for the resulting filename is allocated with mem_alloc_tiny().
 */
extern char *path_session(char *session, char *suffix);

/*
 * Frees the memory allocated in path_init().
 */
extern void path_done(void);

#endif
