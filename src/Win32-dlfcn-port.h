/*
 * This file is part of John the Ripper password cracker.
 *
 * This is a port of dlfcn.h functions dlopen dlsym and dlclose
 * to Win32 (vc and mingw). They do NOT have -ldl.  But they have
 * ways to load dynamic libs.
 */

#if defined (__MINGW32__) || defined (__MINGW64__) || defined (_MSC_VER)

#include <windows.h>

#define RTLD_LAZY     0
#define RTLD_NOW      0
#define RTLD_GLOBAL   0
#define RTLD_LOCAL    0
#define RTLD_NODELETE 0
#define RTLD_NOLOAD   0
#define RTLD_DEEPBIND 0
#define RTLD_DEFAULT  0

static void *dlsym(void *handle, const char *symbol) {
	return GetProcAddress((HANDLE)handle, symbol);
}

#if !JTR_DLSYM_ONLY

static void *dlopen(const char *filename, int flag) {
	// Ok, we have to translate this into LoadLibrary
	return LoadLibrary(filename);

}

static int dlclose(void *handle) {
	return FreeLibrary((HANDLE)handle);
}

static char * dlerror() {
	DWORD err = GetLastError();
	static char Buf[256];
	sprintf(Buf, "GetLastError returned this Win32 error:  0x%lX", err);
	return Buf;
}

#endif /* !JTR_DLSYM_ONLY */

#endif /* defined (__MINGW32__) (...) */
