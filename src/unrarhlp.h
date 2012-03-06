/*
 * Modified for JtR, (c) magnum 2012. This code use a memory buffer instead
 * of a file handle. It does not store the inflated data, it just CRC's it.
 * Support for older RAR versions was stripped. Autoconf stuff was removed.
 *
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

#ifndef __UNRARHLP_H
#define __UNRARHLP_H

#include "arch.h"

//#define RAR_HIGH_DEBUG

void *rar_malloc(size_t size);
void *rar_realloc2(void *ptr, size_t size);

#endif /* __UNRARHLP_H */
