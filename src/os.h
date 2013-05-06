/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2013 by Solar Designer
 */

/*
 * OS-specific parameters.
 */

#ifndef _JOHN_OS_H
#define _JOHN_OS_H

#if defined(__CYGWIN32__) || defined(__BEOS__)
#define OS_TIMER			0
#else
#define OS_TIMER			1
#endif

#define OS_FLOCK			1

#endif
