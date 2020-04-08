/*
 * Copyright (c) 2020, magnum
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#ifndef _JTR_MEM_MAP_H
#define _JTR_MEM_MAP_H

#if _MSC_VER || __MINGW32__ || __MINGW64__ || __CYGWIN__ || HAVE_WINDOWS_H
#include "win32_memmap.h"
#undef MEM_FREE
#endif

#if defined(HAVE_MMAP)

#include <sys/mman.h>

#elif (_MSC_VER || HAVE_WINDOWS_H) && !defined(__CYGWIN__) && !defined(__MINGW64__) && !defined(__MINGW32__)

#define HAVE_MMAP			1
#define PROT_READ			0x1
#define PROT_WRITE			0x2
/* This flag is only available in WinXP+ */
#ifdef FILE_MAP_EXECUTE
#define PROT_EXEC			0x4
#else
#define PROT_EXEC			0x0
#define FILE_MAP_EXECUTE	0
#endif

#define MAP_SHARED			0x01
#define MAP_PRIVATE			0x02
#define MAP_ANONYMOUS		0x20
#define MAP_ANON			MAP_ANONYMOUS
#define MAP_FAILED			((void *) -1)

#endif

#endif /* _JTR_MEM_MAP_H */
