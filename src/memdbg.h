/*  ****** NOTE ******
 *  This header file should be the LAST header file included within every
 *  .c file within the project.   If there are .h files that have actual
 *  code in them, then this header should be the last include within that
 *  .h file, and that .h file should be the last one included within the
 *  .c file.
 *  ****** NOTE *****
 */
#if !defined (__MEM_DBG_H_)
#define __MEM_DBG_H_

// values to use within the MemDbg_Validate() function.
#define MEMDBG_VALIDATE_MIN     0
#define MEMDBG_VALIDATE_DEEP    1
#define MEMDBG_VALIDATE_DEEPER  2
#define MEMDBG_VALIDATE_DEEPEST 3

#include <stdio.h>
#include <stdlib.h>
#include "os.h"
#if (!AC_BUILT || HAVE_UNISTD_H) && !_MSC_VER
#include <unistd.h>
#endif
#include <string.h>
#include "memory.h"

#if defined (MEMDBG_ON)

/*
 * This software was written by Jim Fougeron jfoug AT cox dot net
 * in 2013. No copyright is claimed, and the software is hereby
 * placed in the public domain. In case this attempt to disclaim
 * copyright and place the software in the public domain is deemed
 * null and void, then the software is Copyright (c) 2013 Jim Fougeron
 * and it is hereby released to the general public under the following
 * terms:
 *
 * This software may be modified, redistributed, and used for any
 * purpose, in source and binary forms, with or without modification.
 */

/*
 *  memdbg.h
 *  Memory management debugging (at runtime)
 *
 *   memdbg contains routines detect, and report memory
 *   problems, such as double frees, passing bad pointers to
 *   free, most buffer overwrites.  Also, tracking of non-freed
 *   data, showing memory leaks, can also be shown.
 *
 *  Compilation Options (provided from Makefile CFLAGS)
 *
 *   MEMDBG_ON     If this is NOT defined, then memdbg will
 *       get out of your way, and most normal memory functions
 *       will be called with no overhead at all.
 */

/* these functions can be called by client code. Normally Memdbg_Used() and
 * MemDbg_Display() would be called at program exit. That will dump a list
 * of any memory that was not released.  The MemDbg_Validate() can be called
 * pretty much any time.  That function will walk the memory allocation linked
 * lists, and sqwack if there are problems, such as overwrites, freed memory that
 * has been written to, etc.  It would likely be good to call MemDbg_Validate()
 * within benchmarking, after every format is tested.
 *
 *  TODO:  Add a handle that can be passed to the MemDbg_Used() and MemDbg_Display()
 *  and a function to get the 'current' state of memory as a handle.  Thus, a
 *  format self test could get a handle BEFORE starting, and then check after, and
 *  ONLY show leaked memory from the time the handle was obtained, which was at the
 *  start of the self test. Thus it would only show leaks from that format test.
 *
 *  These functions are NOT thread safe. Do not call them within OMP blocks of code.
 *  Normally, these would be called at program exit, or within things like format
 *  self test code, etc, and not within OMP.  But this warning is here, so that
 *  it is known NOT to call within OMP.
 */
extern size_t	MemDbg_Used(int show_freed);
extern void		MemDbg_Display(FILE *);
extern void		MemDbg_Validate(int level);
extern void		MemDbg_Validate_msg(int level, const char *pMsg);
extern void		MemDbg_Validate_msg2(int level, const char *pMsg, int bShowExData);

/* these functions should almost NEVER be called by any client code. They
 * are listed here, because the macros need to know their names. Client code
 * should almost ALWAYS call malloc() like normal, vs calling MEMDBG_alloc()
 * If MEMDBG_alloc() was called, and MEMDBG_ON was not defined, then this
 * function would not be declared here, AND at link time, the function would
 * not be found.
 * NOTE, these functions should be thread safe in OMP builds (using #pragma omp atomic)
 * also note, memory allocation within OMP blocks SHOULD be avoided if possible. It is
 * very slow, and the thread safety required makes it even slow. This is not only talking
 * about these functions here, BUT malloc/free in general in OMP blocks. AVOID doing that
 * at almost all costs, and performance will usually go up.
 */
extern void *MEMDBG_alloc(size_t, char *, int);
extern void *MEMDBG_alloc_align(size_t, int, char *, int);
extern void *MEMDBG_calloc(size_t count, size_t, char *, int);
extern void *MEMDBG_realloc(void *, size_t, char *, int);
extern void MEMDBG_free(const void *, char *, int);
extern char *MEMDBG_strdup(const char *, char *, int);

#if !defined(__MEMDBG_C_FILE__)
/* we get here on every file compiled EXCEPT memdbg.c */
#undef malloc
#undef realloc
#undef free
#undef strdup
#undef libc_free
#undef libc_calloc
#undef libc_malloc
#define libc_free(a)    MEMDBG_libc_free(a)
#define libc_malloc(a)   MEMDBG_libc_alloc(a)
#define libc_calloc(a,b) MEMDBG_libc_calloc(a,b)
#define malloc(a)     MEMDBG_alloc((a),__FILE__,__LINE__)
#define calloc(a,b)   MEMDBG_calloc(a,b,__FILE__,__LINE__)
#define realloc(a,b)  MEMDBG_realloc((a),(b),__FILE__,__LINE__)
#define free(a)       MEMDBG_free((a),__FILE__,__LINE__)
#define strdup(a)     MEMDBG_strdup((a),__FILE__,__LINE__)

#endif /* !defined __MEMDBG_C_FILE__ */

/* pass the file handle to write to (normally stderr) */
#define MEMDBG_PROGRAM_EXIT_CHECKS(a) do { \
    if (MemDbg_Used(0) > 0 || getenv("MEMDBG")) MemDbg_Display(a); \
    MemDbg_Validate_msg2(MEMDBG_VALIDATE_DEEPEST, "At Program Exit", 1); } while(0)

typedef struct MEMDBG_HANDLE_t {
	unsigned id;
	unsigned alloc_cnt;
	size_t mem_size;
} MEMDBG_HANDLE;

/*
 * these functions give a caller some of the INSIDE information about the
 * allocated object. We simply return data from inside the memdbg header.
 * NOTE, if fence post is not valid, we still return something, BUT will
 * also return something in the err_msg stating this may not be valid.
 */

/* The count 'id' of an allocated block. Same as used in leak report */
unsigned    MEMDBG_get_cnt (const void *ptr, const char **err_msg);
/* the size allocated of the contained block */
size_t      MEMDBG_get_size(const void *ptr, const char **err_msg);
/* what file (source) did the allocation */
const char *MEMDBG_get_file(const void *ptr, const char **err_msg);
/* what file (source) line number did the allocation */
unsigned    MEMDBG_get_line(const void *ptr, const char **err_msg);


/*
 * these functions allow taking a memory snapshot, calling some code, then validating that memory
 * is the same after the code.  This will help catch memory leaks and other such problems, within
 * formats and such.  Simply get the snapshot, run self tests (or other), when it exits, check
 * the snapshot to make sure nothing leaked.
 */

/* returning a struct (or passing as params it not super efficient but this is done so infrequently that this is not an issue. */
MEMDBG_HANDLE MEMDBG_getSnapshot(int id);
/* will not exit on leaks.  Does exit, on memory overwrite corruption. */
void MEMDBG_checkSnapshot(MEMDBG_HANDLE);
/* same as MEMDBG_checkSnapshot() but if exit_on_any_leaks is true, will also exit if leaks found. */
void MEMDBG_checkSnapshot_possible_exit_on_error(MEMDBG_HANDLE, int exit_on_any_leaks);
/*
 * the allocations from mem_alloc_tiny() must call this function to flag the memory they allocate
 * so it is not flagged as a leak, by these HANDLE snapshot functions. 'tiny' memory is expected
 * to leak, until program exit.  At that time, any that was not freed, will be shown as leaked.
 * THIS function is also thread safe. The other checkSnapshot functions are NOT thread safe.
 */

void MEMDBG_tag_mem_from_alloc_tiny(void *);

extern void MEMDBG_libc_free(void *);
extern void *MEMDBG_libc_alloc(size_t size);
extern void *MEMDBG_libc_calloc(size_t count, size_t size);

#else

#define libc_alloc alloc
#define libc_calloc calloc
#define libc_malloc malloc
#define libc_free free

#define MemDbg_Used(a) 0
#define MemDbg_Display(a)
#define MemDbg_Validate(a)
#define MemDbg_Validate_msg(a,b)
#define MemDbg_Validate_msg2(a,b,c)
#define MEMDBG_PROGRAM_EXIT_CHECKS(a)
#define MEMDBG_tag_mem_from_alloc_tiny(a)

#define MEMDBG_HANDLE int
#define MEMDBG_getSnapshot(a) 0
#define MEMDBG_checkSnapshot(a) if (a) printf(" \b")
#define MEMDBG_checkSnapshot_possible_exit_on_error(a, b) if (a) printf(" \b")

#endif /* MEMDBG_ON */

#endif /* __MEMDBG_H_ */
