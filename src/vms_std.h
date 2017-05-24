/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2000,2003 by Solar Designer
 */
/*
 * OpenVMS Purdy-based password hash implementation.
 */

#ifndef _JOHN_VMS_STD_H
#define _JOHN_VMS_STD_H

#include "arch.h"
#include "common.h"

typedef uint32_t VMS_word;

/*
 * Include defnitions for uaf_encode.c functions.
 */
#include "uaf_encode.h"

/*
 * Various structures for internal use.
 */

#define VMS_ALGORITHM_NAME		"32/" ARCH_BITS_STR
/*
 * Global variables shared between vms_std and vms_fmt.  HINT_GENERATION_MASK
 * defines portion of seen[] value that holds generation number, remainder
 * of bits <HINT_GENMASK_BITS:31> hold index of matching password or 0xff if
 * multiple matches.
 */
extern int VMS_dbg_flag;
#ifndef SAVE_LIMIT
#define SAVE_LIMIT 240*7	   /* divisible by 2,3,4,5,6,8,12,15,20,30,40,60,80 */
#define HINT_GENMASK_BITS 21
#define HINT_GENERATION_MASK 0x01fffff		/* field to hold generation # */
#endif
struct result_hint {
    void *lock_vp;				/* serialization object */
    uaf_lword seq;				/* crypt_all generation number */
    uaf_lword nxtseq;
    uaf_lword mask;				/* must be power of 2 minus 1 */
    uaf_lword seen[1];				/* variably sized, power of 2 */
};
extern struct result_hint *VMS_std_hint;

struct result_hash {
    struct uaf_hash_info info;
    char cache_line[64-sizeof(struct uaf_hash_info)];
};
extern struct result_hash *VMS_std_crypt_out;
/*
 * Initializes the internal structures.
 */
extern void VMS_std_init(void);
/*
 * Sets a salt for VMS_std_crypt().
 */
extern void VMS_std_set_salt(void *salt);

/*
 * Sets a key for VMS_std_crypt().
 * Currently only supports keys up to 15 characters long.
 */
extern int VMS_std_set_key(char *key, int index);
extern char *VMS_std_get_key ( int position, int index );

/*
 * Returns the salt for VMS_std_set_salt().
 */
extern char *VMS_std_get_salt(char *ciphertext);

/*
 * Converts an ASCII ciphertext to binary.
 */
extern VMS_word *VMS_std_get_binary(char *ciphertext);

#endif
