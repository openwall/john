#include "os.h"
#if HAVE_WINDOWS_H

#include <stdio.h>
#include <stdlib.h>
#include "win32_memmap.h"
#include "misc.h"

//#pragma comment(lib, "user32.lib")

static HANDLE hMutex;
static HANDLE hMapFile;
static IPCData *pData;
static int idx;

void init_sharedmem(char *ipc_fname) {
	char FName[256];
	sprintf(FName, "Local\\john_IPC_%s", ipc_fname);

	hMapFile = OpenFileMapping(FILE_MAP_ALL_ACCESS, FALSE, FName);
	if (hMapFile == NULL) {
		fprintf(stderr, "ERROR, the memory mapped file: %s could not be opened\n", FName);
		error();
	}
	pData = (IPCData*) MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(IPCData));
	if (pData == NULL) {
		fprintf(stderr, "ERROR, the memory mapped file: %s could not have its data properly mapped\n", FName);
		error();
	}
	sprintf(FName, "john_mutext_%s", ipc_fname);

	hMutex = CreateMutex(NULL, 0, FName);
}

void shutdown_sharedmem() {
	UnmapViewOfFile(pData);
	CloseHandle(hMapFile);
	CloseHandle(hMutex);
}

IPC_Item *next_sharedmem_object() {
	int cnt=0;
	DWORD d;
DoAgain:;
	d = WaitForSingleObject(hMutex, 1000);
	if (d == WAIT_OBJECT_0) {
		if (pData->bLoading[idx] == 2) {
			IPC_Item *p = &pData->Items[idx];
			pData->bLoading[idx] = 0;
			pData->bProcessing[idx] = 1;
			idx++;
			idx %= 3;
			ReleaseMutex(hMutex);
			return p;
		}
		fprintf(stderr, "Got a %X, cnt=%d\n", (unsigned)d, cnt);
		if (++cnt == 500) {
			fprintf(stderr, "ERROR, no data prepared for us to get!\n");
			ReleaseMutex(hMutex);
			return NULL;
		}
		ReleaseMutex(hMutex);
		Sleep(100);
		goto DoAgain;
	}
	if (d == WAIT_ABANDONED) {
		fprintf(stderr, "ERROR, The mutex is gone, so we need to exit.!\n");
		return NULL;
	}
	if (++cnt == 5) {
		fprintf(stderr, "ERROR, no data prepared for us to get!\n");
		return NULL;
	}
	Sleep(100);
	goto DoAgain;
}

void release_sharedmem_object(IPC_Item *p) {
	int i;
	int cnt=0;
	DWORD d;
	if (!p) return;
DoAgain1:;
	d = WaitForSingleObject(hMutex, 1000);
	if (d != WAIT_OBJECT_0) {
		if (++cnt == 5) {
			fprintf(stderr, "Error trying to release IPC object (could not get mutex)\n");
			ReleaseMutex(hMutex);
			error();
		}
		goto DoAgain1;
	}
	for (i = 0; i < 3; ++i) {
		if (p == &pData->Items[i]) {
			pData->bProcessing[i] = 0;
			pData->bLoading[i] = 0;
			break;
		}
	}
	ReleaseMutex(hMutex);
}

#endif
