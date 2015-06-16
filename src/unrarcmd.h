/*
 * Extract RAR archives
 *
 * Modified for JtR, (c) magnum 2012. This code use a memory buffer instead
 * of a file handle, and decrypts while reading. It does not store inflated
 * data, it just CRC's it. Support for older RAR versions was stripped.
 * Autoconf stuff was removed.
 *
 * Copyright (C) 2005-2006 trog@uncon.org
 *
 * This code is based on the work of Alexander L. Roshal (C)
 *
 * The unRAR sources may be used in any software to handle RAR
 * archives without limitations free of charge, but cannot be used
 * to re-create the RAR compression algorithm, which is proprietary.
 * Distribution of modified unRAR sources in separate form or as a
 * part of other software is permitted, provided that it is clearly
 * stated in the documentation and source comments that the code may
 * not be used to develop a RAR (WinRAR) compatible archiver.
 *
 */


#ifndef RAR_CMD_ARRAY_H
#define RAR_CMD_ARRAY_H

#include <stdlib.h>

#include "unrarvm.h"

typedef struct rar_cmd_array_tag
{
	struct rarvm_prepared_command *array;
	size_t num_items;
} rar_cmd_array_t;

void rar_cmd_array_init(rar_cmd_array_t *cmd_a);
void rar_cmd_array_reset(rar_cmd_array_t *cmd_a);
int rar_cmd_array_add(rar_cmd_array_t *cmd_a, int num);

#endif
