/*
 * Copyright (c) 2020, magnum (I didn't write the original but whoever did it didn't tell).
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include "os.h"
#if HAVE_WINDOWS_H
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#define IPC_MM_MAX_WORDS (2048*1024+43660)
#define IPC_MM_DAT_LEN   (24*1024*1024)

typedef struct IPC_Item {
	// if 0, then that is a signal to JtR that we are DONE. Otherwise it is a count of how many word pointers are 'valid'
	unsigned n;
	unsigned char WordOff[IPC_MM_MAX_WORDS]; // delta to next word.
	char Data[IPC_MM_DAT_LEN];
} IPC_Item;

// sizeof(IPCData) is 8191994 which is 9999.9932*8192 so this takes an even 10000 'pages' in the swap space.
typedef struct IPCData {
	int bLoading[3];		// 0 empty, 1 loading, 2 loaded
	int bProcessing[3];		// 0 not processing, 1 processing.
	IPC_Item Items[3];
} IPCData;

void init_sharedmem(char *ipc_fname);
void shutdown_sharedmem();
IPC_Item *next_sharedmem_object();
void release_sharedmem_object(IPC_Item *p);

#endif
