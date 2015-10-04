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
 * Thread safe path_expand()
 */
extern char *path_expand_safe(char *name);

/*
 * these 2 are used when -conf=path is used.  Here, we have a 'base'
 * directory other than where john ran from (or likely can). Thus we
 * want to base file names from there. Since we have added #include
 * to the john.conf processing, we do want to look in the same
 * dir where we loaded the john.conf file, if -conf= arg is used.
 */
extern void path_init_ex(const char *name);
extern char *path_expand_ex(char *name);


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
