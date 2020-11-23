/*
 * This file is part of John the Ripper password cracker.
 *
 * Some Jumbo-specific tweaks go here. This file must not introduce further
 * dependenices within the Jumbo tree (except jumbo.o). Use misc.[ho] for
 * such things (the latter depends on memory.o, logger.o and so on).
 *
 * This file is Copyright (c) 2013-2014 magnum, Lukasz and JimF,
 * and is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modifications, are permitted.
 *
 * For Linux' lseek64, ensure you're defining  _LARGEFILE64_SOURCE before
 * including sys/types.h and unistd.h. Preferably globally (we do it in
 * ./configure)
 */
#ifndef _JTR_JUMBO_H
#define _JTR_JUMBO_H

#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#include "arch.h"
#include <stdio.h>
#include <errno.h>
#if !AC_BUILT || HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if (!AC_BUILT || HAVE_UNISTD_H) && !_MSC_VER
#include <unistd.h>
#endif
#if !AC_BUILT || HAVE_STRING_H
#include <string.h>
#endif

#if !AC_BUILT && (_MSC_VER || __MINGW32__ || __MINGW64__)
#define HAVE__ATOI64 1
#endif

#include <stdint.h>
#if (!AC_BUILT || HAVE_INTTYPES_H) && ! defined(_MSC_VER)
#include <inttypes.h>
#else
#ifndef PRIx64
#define PRIx64    "llx"
#endif
#ifndef PRIu64
#define PRIu64    "llu"
#endif
#ifndef PRId64
#define PRId64    "lld"
#endif
#endif

/******************************************/
/* here we try to 'find' a usable fseek64 */
/******************************************/
#if SIZEOF_LONG == 8
#define jtr_fseek64 fseek

#elif HAVE_FSEEK64 /* Various */
// int fseek64 (FILE *stream, long long offset, int whence);
#define jtr_fseek64 fseek64

#elif HAVE_FSEEKO64 /* Various */
// int fseeko64 (FILE *stream, long long offset, int whence);
#define jtr_fseek64 fseeko64

#elif defined (HAVE__FSEEKI64) || defined (_MSC_VER) /* Windows */
// int _fseeki64(FILE *stream, __int64 offset, int origin);
#define jtr_fseek64 _fseeki64

#elif SIZEOF_OFF_T == 8 && HAVE_FSEEKO /* Other LLP64 */
// int _fseeko(FILE *stream, __int64 offset, int origin);
#define jtr_fseek64 fseeko

#elif HAVE_LSEEK64 /* Linux 32-bit or X32 */
// off64_t lseek64(int fd, off64_t offset, int whence);
//   !!!WARNING, we may need to flush, if file open for reading
//      for this to work right, especially in SEEK_END mode
#define jtr_fseek64(s,o,w) lseek64(fileno(s),o,w);

#elif SIZEOF_OFF_T == 8 && HAVE_LSEEK /* POSIX.1 */
// off_t lseek(int fildes, off_t offset, int whence);
//   !!!WARNING, we may need to flush, if file open for reading
//      for this to work right, especially in SEEK_END mode
#define jtr_fseek64(s,o,w) lseek(fileno(s),o,w)

#else
// at this point, we have NO easy workaround for a seek64 function.
// we can code things for specific environments, OR simply fall
// back to using fseek (and warn the user)
#if defined (__CYGWIN32__) && !defined (__CYGWIN64__)
   extern  int fseeko64 (FILE* stream, int64_t offset, int whence);
  #define jtr_fseek64 fseeko64
#elif defined (__CYGWIN64__)
   extern  int fseeko (FILE* stream, int64_t offset, int whence);
  #define jtr_fseek64 fseeko
#else
  #if defined(__GNUC__) && defined (AC_BUILT)
    #warning Using 32-bit fseek(). Files larger than 2GB will be handled unreliably
  #endif
  #define jtr_fseek64 fseek
#endif

#endif /* fseek */


/******************************************/
/* here we try to 'find' a usable ftell64 */
/******************************************/
#if SIZEOF_LONG == 8
#define jtr_ftell64 ftell

#elif HAVE_FTELL64 /* Linux and others */
// long long ftell64(FILE *stream)
#define jtr_ftell64 ftell64

#elif HAVE_FTELLO64 /* Solaris */
// integer*8 function ftello64 (lunit) (Solaris)
#define jtr_ftell64 ftello64

#elif defined (HAVE__FTELLI64) || defined (_MSC_VER) /* Windows */
// __int64 _ftelli64(FILE *stream);
#define jtr_ftell64 _ftelli64

#elif SIZEOF_OFF_T == 8 && HAVE_FTELLO /* Other LLP64 */
// off_t ftello(FILE *stream);
#define jtr_ftell64 ftello

#else
// at this point, we have NO easy workaround for a tell64 function.
// we can code things for specific environments, OR simply fall
// back to using ftell (and warn the user)
#if defined (__CYGWIN32__) && !defined (__CYGWIN64__)
   extern  int64_t ftello64 (FILE* stream);
  #define jtr_ftell64 ftello64
#elif defined (__CYGWIN64__)
   extern  int64_t ftello (FILE* stream);
  #define jtr_ftell64 ftello
#else
  #if defined(__GNUC__) && defined (AC_BUILT)
    #warning Using 32-bit ftell(). Files larger than 2GB will be handled unreliably
  #endif
  #define jtr_ftell64 ftell
#endif

#endif /* ftell */

/*************************************************/
/* here we figure out if we use fopen or fopen64 */
/*************************************************/
#if SIZEOF_LONG == 8
  #define jtr_fopen fopen
#elif HAVE_FOPEN64
  #define jtr_fopen fopen64
#elif HAVE__FOPEN64
  #define jtr_fopen _fopen64
#else
  #define jtr_fopen fopen
#endif
#if __CYGWIN32__ || _MSC_VER
   extern  FILE *_fopen64 (const char *Fname, const char *type);
#endif

#ifndef O_LARGEFILE
#define O_LARGEFILE 0
#endif

/*
 * Portable basename() function.  DO NOT USE basename().  Use this
 * proper working equivalent.  The _r version is thread safe. In the
 * _r version, pass in a buffer that is at least strlen(name)+1 bytes
 * long, however, PATH_BUFFER_SIZE+1 can also be used.
 *
 *  here is what defined:
 *    if name is null, or points to a null string (0 byte), then a '.' is returned.
 *    if name is all / chars (or \ chars), then a single / (or \) is returned.
 *    DOS drive letters are ignored.
 *    / or \ chars are properly handled.
 *    Trailing / (or \) are removed, IF there was real path data in there.
 *
 *  here are some examples:
 *    jtr_basename("/user/lib")      == lib
 *    jtr_basename("/user/")         == user
 *    jtr_basename("/")              == /
 *    jtr_basename("//")             == /
 *    jtr_basename("///")            == /
 *    jtr_basename("//user//lib//")  == lib
 *    jtr_basename("c:\\txt.doc")    == txt.doc
 *    jtr_basename("c:txt.doc")      == txt.doc
 *    jtr_basename("c:b/c\\txt.doc/")== txt.doc
 *    jtr_basename("c:\\txt.doc\\")  == txt.doc
 *    jtr_basename("c:")             == .
 *    jtr_basename("")               == .
 *    jtr_basename(NULL)             == .
 *    jtr_basename("\\user\\lib")    == lib
 *    jtr_basename("\\user\\")       == user
 *    jtr_basename("\\")             == \
 *    jtr_basename("\\\\")           == \
 *    jtr_basename("one")            == one
 */
extern char *jtr_basename(const char *name);
extern char *jtr_basename_r(const char *name, char *buf);
#undef basename
#define basename(a) jtr_basename(a)

/*
 * Removes suffixes from src.
 */
extern char *strip_suffixes(const char *src, const char *suffixes[], int count);

#if !HAVE_MEMMEM

#undef memmem
#define memmem	jtr_memmem

/* Return the first occurrence of NEEDLE in HAYSTACK. */
extern void *memmem(const void *haystack, size_t haystack_len,
                        const void *needle, size_t needle_len);

#endif /* HAVE_!MEMMEM */

// We configure search for unix sleep(seconds) function, MSVC and MinGW do not have this,
// so we replicate it with Win32 Sleep(ms) function.
#if (AC_BUILT && !HAVE_SLEEP) || (!AC_BUILT && (_MSC_VER || __MINGW32__ || __MINGW64__))
extern unsigned int sleep(unsigned int i);
#endif

#if !AC_BUILT
#if _MSC_VER
#define strcasecmp _stricmp
#endif
#else
#if !HAVE_STRCASECMP
#if HAVE__STRICMP
#define strcasecmp _stricmp
#elif HAVE__STRCMPI
#define strcasecmp _strcmpi
#elif HAVE_STRICMP
#define strcasecmp stricmp
#elif HAVE_STRCMPI
#define strcasecmp strcmpi
#else
#define NEED_STRCASECMP_NATIVE 1
extern int strcasecmp(const char *dst, const char *src);
#endif
#endif
#endif

#if !AC_BUILT
#if _MSC_VER
#define strncasecmp _strnicmp
#endif
#else
#if !HAVE_STRNCASECMP
#if HAVE__STRNICMP
#define strncasecmp _strnicmp
#elif HAVE__STRNCMPI
#define strncasecmp _strncmpi
#elif HAVE_STRNICMP
#define strncasecmp strnicmp
#elif HAVE_STRNCMPI
#define strncasecmp strncmpi
#else
#define NEED_STRNCASECMP_NATIVE 1
extern int strncasecmp(const char *dst, const char *src, size_t count);
#endif
#endif
#endif

#if (AC_BUILT && HAVE__STRUPR && HAVE_STRUPR) || (!AC_BUILT && _MSC_VER)
#define strupr _strupr
#endif

#if (AC_BUILT && HAVE__STRLWR && HAVE_STRLWR) || (!AC_BUILT && _MSC_VER)
#define strlwr _strlwr
#endif

#if (AC_BUILT && !HAVE_STRLWR) || (!AC_BUILT && !_MSC_VER)
extern char *strlwr(char *s);
#endif
#if (AC_BUILT && !HAVE_STRUPR) || (!AC_BUILT && !_MSC_VER)
extern char *strupr(char *s);
#endif

#if !HAVE_ATOLL
#if HAVE__ATOI64
#define atoll _atoi64
#else
#define NEED_ATOLL_NATIVE 1
#undef atoll
#define atoll jtr_atoll
extern long long jtr_atoll(const char *);
#endif
#endif

void memcpylwr(char *, const char *, size_t);

#if (__MINGW32__ || __MINGW64__) && __STRICT_ANSI__
// since we added -std=c99 for Mingw builds (to handle printf/scanf %xxx specifiers better),
// we had to make some 'changes'. Mostly, some of the string types are undeclared (but will
// link properly). Also, sys/file, sys/stat, fcntl.h will not include properly, due to
// off64_t missing.
extern char *strdup(const char *);
extern char *strlwr(char *);
extern char *strupr(char *);
//extern int _strnicmp(const char*, const char *, int);
extern int _strncmp(const char*, const char *);
//extern int _stricmp(const char*, const char *);
extern FILE *fopen64(const char *, const char *);
extern FILE *fdopen(int, const char *);
//extern int ftruncate(int, int);
extern long long ftello64(FILE *);
extern int fseeko64(FILE *, long long, int);
extern int fileno(FILE *);
//extern int _exit(int);
#define off64_t long long
#undef __STRICT_ANSI__
#include <sys/file.h>
#include <sys/stat.h>
#include <fcntl.h>
#define __STRICT_ANSI__ 1
#endif

#ifdef _MSC_VER
#undef inline
#define inline _inline
#define strupr _strupr
#define strlwr _strlwr
#define open _open
#define fdopen _fdopen
#pragma warning(disable: 4244) // possible loss of data
#pragma warning(disable: 4334) // 32 bit shift implictly converted to 64 bits
#pragma warning(disable: 4133) // function imcompatible types
#pragma warning(disable: 4146) // unary minus applied to unsigned
#pragma warning(disable: 4715) // not all control paths return a value
#endif

#if (AC_BUILT && !HAVE_SNPRINTF && HAVE_SPRINTF_S) || (!AC_BUILT && _MSC_VER)
#undef  snprintf
#define snprintf sprintf_s
#endif

#if _MSC_VER
// I tried adding these to autoconf, BUT I ended up with systems where
// the function can be linked to, but it was not in headers. SO, I simply
// blindly use these for VC.  For VC, they are used to work around many
// red-herring compiler warnings
#undef snprintf
#if _MSC_VER < 1900
// note, in VC 2015, snprintf was fixed to be POSIX compliant. The legacy _snprintf function
// starting at at VC 2015 is no longer the same as snprintf (as it was prior).  The _snprintf
// was kept at the legacy problematic manner, while snprintf now 'works' properly.
// _MSC_VER == 1900 is the key for VC 2015
#define snprintf(str, size, ...) vc_fixed_snprintf((str), (size), __VA_ARGS__)
extern int vc_fixed_snprintf(char *Dest, size_t max_cnt, const char *Fmt, ...);
#endif
#undef alloca
#define alloca _alloca
#undef unlink
#define unlink _unlink
#undef fileno
#define fileno _fileno
#pragma warning (disable : 4018 297 )
#endif

// NOTE, this still will fail on REALLY old systems, where you can only
// do a setenv by getting the pointer in getenv and mofifying the results.
// old Borland C (DOS days), was this way, as was a few others. This should
// hopefully NOT be an issue any more, and systems will either have setenv
// putenv or both. This code handles builds of ONLY putenv (VC, Mingw)
#if (AC_BUILT && !HAVE_SETENV && HAVE_PUTENV) || \
    (!AC_BUILT && (_MSC_VER || __MINGW32__ || __MINGW64__))
extern int setenv(const char *name, const char *val, int overwrite);
#endif

#if (__MINGW32__ && !__MINGW64__) || _MSC_VER
// Later versions of MSVC can handle %lld but some older
// ones can only handle %I64d.  Easiest to simply use
// %I64d then all versions of MSVC will handle it just fine
#define LLu "%I64u"
#define LLd "%I64d"
#define LLx "%I64x"
#define Zu  "%u"
#define Zd  "%d"
#else
#define LLu "%llu"
#define LLd "%lld"
#define LLx "%llx"
#define Zu  "%zu"
#define Zd  "%zd"
#endif

#if (AC_BUILT && !HAVE_STRREV) ||(!AC_BUILT && !_MSC_VER)
char *strrev(char *str);
#endif

// Start handing these (some we may not be able to, or are too hard to 'care', and we should
// simply #ifdef around the logic where the functions are used, or find some other way.
//HAVE_ATEXIT
//HAVE_ENDPWENT  (no mingw)
//HAVE_FLOOR
//HAVE_FTRUNCATE
//HAVE_GETHOSTBYNAME  (no mingw)
//HAVE_GETTIMEOFDAY
//HAVE_INET_NTOA   (no mingw)
//HAVE_ISASCII     (no mingw)
//HAVE_MKDIR
//HAVE_RMDIR
//HAVE_STRRCHR
//HAVE_STRCSPN
//HAVE_STRSPN
//HAVE_STRTOL
//HAVE_STRTOUL

/*
 * Like strlen but will not scan past max, so will return at most max.
 */
#if AC_BUILT && !HAVE_STRNLEN
#undef strnlen
#define strnlen jtr_strnlen
extern size_t strnlen(const char *s, size_t max);
#endif

#if AC_BUILT && !HAVE_STRCASESTR || !AC_BUILT && defined(__MINGW__)
char *strcasestr(const char *haystack, const char *needle);
#endif

/*
 * Standard PKCS padding check. On success, returns net length.
 * On failure, returns -1.
 */
extern int check_pkcs_pad(const unsigned char* data, size_t len, int blocksize);

/*
 * Replace, in-place, any instance of 'c' within string with 'n'.
 * If 'n' is null, skip any 'c' but continue copying.
 */
extern char *replace(char *string, char c, char n);

#endif /* _JTR_JUMBO_H */
