/*
 * This software was written by Jim Fougeron jfoug AT cox dot net
 * in 2014. No copyright is claimed, and the software is hereby
 * placed in the public domain. In case this attempt to disclaim
 * copyright and place the software in the public domain is deemed
 * null and void, then the software is Copyright (c) 2014 Jim Fougeron
 * and it is hereby released to the general public under the following
 * terms:
 *
 * This software may be modified, redistributed, and used for any
 * purpose, in source and binary forms, with or without modification.
 */

/*
 * This is a dynamic salt structure.  In a hash that has salts which
 * vary in size. To make a local salt structure usable by dyna_salt
 * code in John, simply place an instance of a dyna_salt structure as
 * the FIRST member of your salt structure, and then properly fill in
 * the members of that structure.  This will make your structure 'look'
 * just like a dyna_salt_john_core structure. That is the structure
 * that john core code uses, so john core can access your structure,
 * without having to know its full internal structure. Then define the
 * rest of the salt structure to be the 'real' salt structure you need
 * for the runtime of your hash.  In your format structure, set the salt_size
 * to be sizeof(dyna_salt*)  and set the FMT_DYNA_SALT format flag. See
 * zip format for an example of how to properly use dyna_salt's.
 */

#if !defined (_DYNA_SALT_H__)
#define _DYNA_SALT_H__

#include <stddef.h>
#include <stdint.h>

//#define DYNA_SALT_DEBUG

/************************************************************************
 * NOTE if changing this struct, also copy the changes to opencl_misc.h *
 ************************************************************************/
typedef struct dyna_salt_t {
	size_t salt_cmp_size;
	struct { /* bit field stealing one bit of the size_t */
		size_t salt_alloc_needs_free : 1; /* 1 if if malloc/calloc used */
		size_t salt_cmp_offset : (sizeof(size_t) * 8 - 1);
	};
} dyna_salt;

/* this IS the signature that is required for ALL formats
 *  which use dyna_salt to have
 */
typedef struct dyna_salt_john_core_t {
	dyna_salt dyna_salt;
} dyna_salt_john_core;

// call with SALT_CMP_SIZE(struct, first comp. member, blob member, extra_bytes)
#define SALT_CMP_SIZE(a,b,c,d) (offsetof(a,c)-offsetof(a,b)+d)
// call with SALT_CMP_OFF(struct, member)
#define SALT_CMP_OFF(a,b) (offsetof(a,b))

/*
 * MUST be called prior to other functions, and reset
 * each time a format change happens, during self test
 * and loading. There are times where other functions
 * are called, where we do not have a format structure.
 * Returns the format previously set (may be NULL)
 */
struct fmt_main;
struct fmt_main *dyna_salt_init(struct fmt_main *format);

/*
 * NOTE, will compare dyna and non-dyna salts.
 */
int dyna_salt_cmp(void *p1, void *p2, int comp_size);

/*
 * NOTE, will do the MD5 salt hashing for either non or dyna-salts.
 */
void dyna_salt_md5(struct db_salt *p, int comp_size);

//#define DYNA_SALT_DEBUG

#ifdef DYNA_SALT_DEBUG
void dyna_salt_created_fp(void *a, char *fname, int line);
#define dyna_salt_create(a) dyna_salt_created_fp(a,__FILE__,__LINE__)
void dyna_salt_remove_fp(void *a, char *fname, int line);
#define dyna_salt_remove(a) dyna_salt_remove_fp(a,__FILE__,__LINE__)
#else
#define dyna_salt_create(a) do {} while (0)
void dyna_salt_remove_fp(void *a);
#define dyna_salt_remove(a) dyna_salt_remove_fp(a)
#endif

//#undef DYNA_SALT_DEBUG

/* These 2 used in self test code. Put here to hide the ugly details */
void dyna_salt_smash(void *p, char c);
int dyna_salt_smash_check(void *p, unsigned char c);

#endif // _DYNA_SALT_H__
