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

#include <stddef.h>
#include "formats.h"
#include "memory.h"
#include "dyna_salt.h"
#include "loader.h"
#include "md5.h"

static struct fmt_main *format;
#ifdef DYNA_SALT_DEBUG
static int salt_count;
#endif

struct fmt_main *dyna_salt_init(struct fmt_main *_format) {
	struct fmt_main *p = format;
	format=_format;
	return p;
}

#ifdef DYNA_SALT_DEBUG
void dyna_salt_remove_fp(void *p, char *fname, int line)
#else
void dyna_salt_remove_fp(void *p)
#endif
{
	if (p && (!format || /* get_salt() for dynamic format called from within valid() */
	          (format->params.flags & FMT_DYNA_SALT) == FMT_DYNA_SALT)) {
		dyna_salt_john_core *p1 = *((dyna_salt_john_core**)p);
		if (p1 && p1->dyna_salt.salt_alloc_needs_free == 1) {
#ifdef DYNA_SALT_DEBUG
			printf("-- Freeing a salt    #%d  from: %s line %d\n", --salt_count, fname, line);
#endif
			MEM_FREE(p1);
		}
	}
}

#ifdef DYNA_SALT_DEBUG
void dyna_salt_created_fp(void *p, char *fname, int line) {
	if ((format->params.flags & FMT_DYNA_SALT) == FMT_DYNA_SALT) {
		printf("++ Allocating a salt #%d  from: %s line %d\n", ++salt_count, fname, line);
	}
}
#endif

int dyna_salt_cmp(void *_p1, void *_p2, int comp_size) {
	if ((format->params.flags & FMT_DYNA_SALT) == FMT_DYNA_SALT) {
		dyna_salt_john_core *p1 = *((dyna_salt_john_core**)_p1);
		dyna_salt_john_core *p2 = *((dyna_salt_john_core**)_p2);
#ifdef DYNA_SALT_DEBUG
		dump_stuff_msg("dyna_salt_cmp\np1", &((unsigned char*)p1)[p1->dyna_salt.salt_cmp_offset], p1->dyna_salt.salt_cmp_size>48?48:p1->dyna_salt.salt_cmp_size);
		dump_stuff_msg("p2", &((unsigned char*)p2)[p2->dyna_salt.salt_cmp_offset], p2->dyna_salt.salt_cmp_size>48?48:p2->dyna_salt.salt_cmp_size);
#endif
		if (p1->dyna_salt.salt_cmp_offset == p2->dyna_salt.salt_cmp_offset &&
		    p1->dyna_salt.salt_cmp_size == p2->dyna_salt.salt_cmp_size &&
		    !memcmp( &((unsigned char*)p1)[p1->dyna_salt.salt_cmp_offset],
		             &((unsigned char*)p2)[p2->dyna_salt.salt_cmp_offset],
		             p1->dyna_salt.salt_cmp_size))
			return 0;
		return 1;
	}
#ifdef DYNA_SALT_DEBUG
	dump_stuff_msg("salt_cmp\np1", _p1, comp_size>48?48:comp_size);
	dump_stuff_msg("p2", _p2, comp_size>48?48:comp_size);
#endif
	// non-dyna salt compare.
	return memcmp(_p1, _p2, comp_size);
}

void dyna_salt_md5(struct db_salt *p, int comp_size) {
	MD5_CTX ctx;

	MD5_Init(&ctx);
	if ((format->params.flags & FMT_DYNA_SALT) == FMT_DYNA_SALT) {
		dyna_salt_john_core *ds = *((dyna_salt_john_core**)p->salt);
		MD5_Update(&ctx, &((unsigned char*)ds)[ds->dyna_salt.salt_cmp_offset],
		           ds->dyna_salt.salt_cmp_size);
	} else
		MD5_Update(&ctx, (unsigned char*)p->salt, comp_size);
	MD5_Final((unsigned char *)p->salt_md5, &ctx);
}

void dyna_salt_smash(void *p, char c) {
	dyna_salt_john_core *p1 = *((dyna_salt_john_core**)p);
	memset(&((unsigned char*)p1)[p1->dyna_salt.salt_cmp_offset], 0xAF, p1->dyna_salt.salt_cmp_size);
}
int dyna_salt_smash_check(void *p, unsigned char c) {
	dyna_salt_john_core *p1 = *((dyna_salt_john_core**)p);
	return (((unsigned char*)p1)[p1->dyna_salt.salt_cmp_offset+p1->dyna_salt.salt_cmp_size-1] == c);
}
