/*
 * Modified for JtR, (c) magnum 2012. This code use a memory buffer instead
 * of a file handle, and decrypts while reading. It does not store inflated
 * data, it just CRC's it. Support for older RAR versions was stripped.
 * Autoconf stuff was removed.
 *
 *  Copyright (C) 2015, 2017 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007 Sourcefire, Inc.
 *
 *  The unRAR sources may be used in any software to handle RAR
 *  archives without limitations free of charge, but cannot be used
 *  to re-create the RAR compression algorithm, which is proprietary.
 *  Distribution of modified unRAR sources in separate form or as a
 *  part of other software is permitted, provided that it is clearly
 *  stated in the documentation and source comments that the code may
 *  not be used to develop a RAR (WinRAR) compatible archiver.
 */

#include <stdio.h>
#include <stdlib.h>

#include "jumbo.h"
#include "unrarhlp.h"

#ifdef RAR_HIGH_DEBUG
#define rar_dbgmsg printf
#else
//static void rar_dbgmsg(const char* fmt,...){(void)fmt;}
#endif

#define RAR_MAX_ALLOCATION 184549376

void *rar_malloc(size_t size)
{
	if (!size || size > (size_t)RAR_MAX_ALLOCATION) {
		return NULL;
	}
	//rar_dbgmsg("%s() allocating "Zu" bytes\n", __FUNCTION__, size);

	return mem_alloc(size);
}

void *rar_realloc2(void *ptr, size_t size)
{
	void *alloc;

    if (!size || size > RAR_MAX_ALLOCATION) {
	//rar_dbgmsg("UNRAR: rar_realloc2(): Attempt to allocate "Zu" bytes. Please report to http://bugs.clamav.net\n", size);
	return NULL;
    }

    alloc = realloc(ptr, size);

    if (!alloc) {
	fprintf(stderr, "UNRAR: rar_realloc2(): Can't allocate memory ("Zu" bytes).\n", size);
	MEM_FREE(ptr);
	return NULL;
    }

    // //rar_dbgmsg("%s: reallocated %p to "Zu" bytes at %p\n", __FUNCTION__, ptr, size, alloc); // realloc invalidates ptr

    return alloc;
}
