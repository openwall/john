/* mmap() replacement for Windows
 *
 * Author: Mike Frysinger <vapier@gentoo.org>
 * Placed into the public domain
 *
 * File edited by JimF, for proper integration into JtR
 * edits placed into public domain.
 */

/* References:
 * CreateFileMapping: http://msdn.microsoft.com/en-us/library/aa366537(VS.85).aspx
 * CloseHandle:       http://msdn.microsoft.com/en-us/library/ms724211(VS.85).aspx
 * MapViewOfFile:     http://msdn.microsoft.com/en-us/library/aa366761(VS.85).aspx
 * UnmapViewOfFile:   http://msdn.microsoft.com/en-us/library/aa366882(VS.85).aspx
 */

#ifndef _MMAP_WIN
#define _MMAP_WIN

#if (_MSC_VER || HAVE_WINDOWS_H) && !defined(__CYGWIN__) && !defined(__MINGW64__) && !defined(__MINGW32__)

#include <io.h>
#include <windows.h>
#include <sys/types.h>

#include "mem_map.h"

#ifdef __USE_FILE_OFFSET64
 #define DWORD_HI(x) (x >> 32)
 #define DWORD_LO(x) ((x) & 0xffffffff)
#else
 #define DWORD_HI(x) (0)
 #define DWORD_LO(x) (x)
#endif

static void *mmap(void *start, size_t length, int prot, int flags, int fd, off_t offset)
{
	DWORD flProtect;
	off_t end;
	HANDLE mmap_fd, h;
	DWORD dwDesiredAccess;
	void *ret;

	if (prot & ~(PROT_READ | PROT_WRITE | PROT_EXEC))
		return 0;
	if (fd == -1) {
		if (!(flags & MAP_ANON) || offset)
			return 0;
	} else if (flags & MAP_ANON)
		return 0;

	if (prot & PROT_WRITE) {
		if (prot & PROT_EXEC)
			flProtect = PAGE_EXECUTE_READWRITE;
		else
			flProtect = PAGE_READWRITE;
	} else if (prot & PROT_EXEC) {
		if (prot & PROT_READ)
			flProtect = PAGE_EXECUTE_READ;
		else if (prot & PROT_EXEC)
			flProtect = PAGE_EXECUTE;
	} else
		flProtect = PAGE_READONLY;

	end = length + offset;
	if (fd == -1)
		mmap_fd = INVALID_HANDLE_VALUE;
	else
		mmap_fd = (HANDLE)_get_osfhandle(fd);
	h = CreateFileMapping(mmap_fd, NULL, flProtect, DWORD_HI(end), DWORD_LO(end), NULL);
	//h = CreateFileMapping(mmap_fd, NULL, flProtect, 0, 0, NULL);
	if (h == NULL) {
        /* we will log this at some time, once I know PROPER fixes */
		DWORD x = GetLastError();
		fprintf(stderr, "Error, CreateFileMapping failed, Error code %x\n", (unsigned)x);
		return 0;
	}

	if (prot & PROT_WRITE)
		dwDesiredAccess = FILE_MAP_WRITE;
	else
		dwDesiredAccess = FILE_MAP_READ;
	if (prot & PROT_EXEC)
		dwDesiredAccess |= FILE_MAP_EXECUTE;
	if (flags & MAP_PRIVATE)
		dwDesiredAccess |= FILE_MAP_COPY;

	ret = MapViewOfFile(h, dwDesiredAccess, DWORD_HI(offset), DWORD_LO(offset), length);
	//ret = MapViewOfFile(h, dwDesiredAccess, 0, 0, length);
	if (ret == NULL)  {
		/* we will log this at some time, once I know PROPER fixes */
		DWORD x = GetLastError();
		fprintf(stderr, "Error, MapViewOfFile failed, Error code %x\n", (unsigned)x);
		CloseHandle(h);
		ret = 0;
	}
	return ret;
}

static void munmap(void *addr, size_t length)
{
	UnmapViewOfFile(addr);
	/* ruh-ro, we leaked handle from CreateFileMapping() ... */
}

#undef DWORD_HI
#undef DWORD_LO

#endif /* (_MSC_VER || HAVE_WINDOWS_H) && !defined(__CYGWIN__) && !defined(__MINGW64__) && !defined(__MINGW32__) */

#endif /* _MMAP_WIN */
