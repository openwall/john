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

#include "arch.h"
#include <stdio.h>
#include <errno.h>
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif

#include "stdint.h"

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
#ifdef __CYGWIN32__
   extern  int fseeko64 (FILE* stream, int64_t offset, int whence);
#  define jtr_fseek64 fseeko64
#else
#  if defined(__GNUC__)
#    warning Using 32-bit fseek(). Files larger than 2GB will be handled unreliably
#  endif
#  define jtr_fseek64 fseek
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

#elif defined (HAVE__FTELLI64) || defined (_MSC_VER) /* Windows */
// __int64 _ftelli64(FILE *stream);
#define jtr_ftell64 _ftelli64

#elif HAVE_FTELLO64 /* Solaris */
// integer*8 function ftello64 (lunit) (Solaris)
#define jtr_ftell64 ftello64

#elif SIZEOF_OFF_T == 8 && HAVE_FTELLO /* Other LLP64 */
// off_t ftello(FILE *stream);
#define jtr_ftell64 ftello

#else
// at this point, we have NO easy workaround for a tell64 function.
// we can code things for specific environments, OR simply fall
// back to using ftell (and warn the user)
#ifdef __CYGWIN32__
   extern  int64_t ftello64 (FILE* stream);
#  define jtr_ftell64 ftello64
#else
#  if defined(__GNUC__)
#    warning Using 32-bit ftell(). Files larger than 2GB will be handled unreliably
#  endif
#  define jtr_ftell64 ftell
#endif

#endif /* ftell */


/*
 * Portable basename() function.  DO NOT USE basename().  Use this
 * proper working equivelent.  The _r version is thread safe. In the
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
 * Removes suffixes frome src.
 */
extern char *strip_suffixes(const char *src, const char *suffixes[], int count);

#if !HAVE_MEMMEM

#undef memmem
#define memmem	jtr_memmem

/* Return the first occurrence of NEEDLE in HAYSTACK. */
extern void *memmem(const void *haystack, size_t haystack_len,
                        const void *needle, size_t needle_len);

#endif /* HAVE_!MEMMEM */

#endif /* _JTR_JUMBO_H */
