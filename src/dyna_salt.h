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
 * vary in size, make your local salt structure use the first 2 varianbles
 * from this salt structure, EXACTLY like they are here. Then define the
 * rest of the salt structure to be the 'real' salt structure you need
 * for the runtime of your hash.  Within the salt() function, allocate
 * your salt structure, setting the 2 values properly, the return a pointer
 * to your allocated salt record.  In your format structure, set the salt_size
 * to be sizeof(dyna_salt*)  and set the FMT_DYNA_SALT format flag. See
 * zip format for an example of how to properly use this.
 */

#include <stddef.h>

typedef struct dyna_salt_t {
	size_t salt_cmp_size;
	size_t salt_cmp_offset;
	unsigned char buffer[1];
} dyna_salt;

// call with SALT_CMP_SIZE(struct, member, extra_bytes)
#define SALT_CMP_SIZE(a,b,c) (sizeof(a)-offsetof(a,b)+c-1)
// call with SALT_CMP_OFF(struct, member)
#define SALT_CMP_OFF(a,b) (offsetof(a,b))

/* an example would be:
struct my_salt {
	size_t salt_cmp_size;
	size_t salt_cmp_offset;
	void *some_unused_item;
	int count;				// we start out salt compare here.
	int something_else;
	char buffer[1];
} *saltp;

then something like this:

void *salt() {
	struct my_salt *p;
	// compute size of buffer. We will say buf_size variable has this computed
	p = mem_alloc_tiny(sizeof(struct my_salt)+buf_size-1);
	p->salt_comp_size = SALT_CMP_SIZE(struct my_salt, count, buf_size);
	p->salt_comp_offset = SALT_CMP_OFF(struct my_salt, count);
	memcpy(p->buffer, data, buf_size);
	return p;
}

then in the fmt structure

   salt_size = sizeof(struct my_salt);
   salt_align = sizeof(struct my_salt);
*/