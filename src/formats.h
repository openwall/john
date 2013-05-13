/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2005,2010-2013 by Solar Designer
 */

/*
 * Supported ciphertext formats management.
 */

#ifndef _JOHN_FORMATS_H
#define _JOHN_FORMATS_H

#include "params.h"

/*
 * Some format methods accept pointers to these, yet we can't just include
 * loader.h here because that would be a circular dependency.
 */
struct db_main;
struct db_salt;

/*
 * Format property flags.
 */
/* Uses case-sensitive passwords */
#define FMT_CASE			0x00000001
/* Supports 8-bit characters in passwords (does not ignore the 8th bit) */
#define FMT_8_BIT			0x00000002
/* Uses a bitslice implementation */
#define FMT_BS				0x00010000
/* The split() method unifies the case of characters in hash encodings */
#define FMT_SPLIT_UNIFIES_CASE		0x00020000
#ifdef _OPENMP
/* Parallelized with OpenMP */
#define FMT_OMP				0x01000000
/* Poor OpenMP scalability */
#define FMT_OMP_BAD			0x02000000
#else
#define FMT_OMP				0
#define FMT_OMP_BAD			0
#endif
/* We've already warned the user about hashes of this type being present */
#define FMT_WARNED			0x80000000

/*
 * A password to test the methods for correct operation.
 */
struct fmt_tests {
	char *ciphertext, *plaintext;
	char *fields[10];
};

/*
 * Parameters of a hash function and its cracking algorithm.
 */
struct fmt_params {
/* Label to refer to this format (any alphabetical characters in it must be
 * lowercase). */
	char *label;

/* Ciphertext format name */
	char *format_name;

/* Cracking algorithm name */
	char *algorithm_name;

/* Comment about the benchmark (can be empty) */
	char *benchmark_comment;

/* Benchmark for short/long passwords instead of for one/many salts */
	int benchmark_length;

/* Maximum length of a plaintext password */
	int plaintext_length;

/* Size and alignment of binary ciphertext, in bytes */
	int binary_size;
	int binary_align;

/* Size and alignment of internal salt representation, in bytes */
	int salt_size;
	int salt_align;

/* Number of plaintexts hashed by a single crypt_all() method call */
	int min_keys_per_crypt;
	int max_keys_per_crypt;

/* Properties of this format */
	unsigned int flags;

/* Some passwords to test the methods for correct operation (or NULL for no
 * self test, and no benchmark), terminated with a NULL ciphertext. */
	struct fmt_tests *tests;
};

/*
 * fmt_main is declared for real further down this file, but we refer to it in
 * function prototypes in fmt_methods.
 */
struct fmt_main;

/*
 * Functions to implement a cracking algorithm.
 */
struct fmt_methods {
/* Initializes the algorithm's internal structures.
 * prepare(), valid(), and split() are the only methods that are allowed to be
 * called before a call to init().
 * Note that initializing an algorithm might de-initialize some others (if a
 * shared underlying resource is used). */
	void (*init)(struct fmt_main *self);

/* De-initializes this format, which must have been previously initialized */
	void (*done)(void);

/* Called whenever the set of password hashes being cracked changes, such as
 * after self-test, but before actual cracking starts.  When called before a
 * self-test or benchmark rather than before actual cracking, db may be NULL.
 * Normally, this is a no-op since a format implementation shouldn't mess with
 * the database unnecessarily.  However, when there is a good reason to do so
 * this may e.g. transfer the salts and hashes onto a GPU card. */
	void (*reset)(struct db_main *db);

/* Extracts the ciphertext string out of the input file fields.  Normally, this
 * will simply return field[1], but in some special cases it may use another
 * field (e.g., when the hash type is commonly used with PWDUMP rather than
 * /etc/passwd format files) or/and it may also extract and include the
 * username, etc. */
	char *(*prepare)(char *fields[10], struct fmt_main *self);

/* Checks if an ASCII ciphertext is valid for this format.  Returns zero for
 * invalid ciphertexts, or the number of parts the ciphertext should be split
 * into (up to 9, will usually be 1). */
	int (*valid)(char *ciphertext, struct fmt_main *self);

/* Splits a ciphertext into several pieces and returns the piece with given
 * index, starting from 0 (will usually return the ciphertext unchanged).
 * For hex-encoded hashes which are compared by the target system/application
 * irrespective of the case of characters (upper/lower/mixed) used in their
 * encoding, split() must unify the case (e.g., convert to all-lowercase)
 * and FMT_SPLIT_UNIFIES_CASE must be set. */
	char *(*split)(char *ciphertext, int index, struct fmt_main *self);

/* Converts an ASCII ciphertext to binary, possibly using the salt */
	void *(*binary)(char *ciphertext);

/* Converts an ASCII salt to its internal representation */
	void *(*salt)(char *ciphertext);

/* Reconstructs the ASCII ciphertext from its binary (saltless only).
 * Alternatively, in the simplest case simply returns "source" as-is. */
	char *(*source)(char *source, void *binary);

/* These functions calculate a hash out of a binary ciphertext. To be used
 * for hash table initialization. One of them should be selected depending
 * on the hash table size. */
	int (*binary_hash[PASSWORD_HASH_SIZES])(void *binary);

/* Calculates a hash out of a salt (given in internal representation). To be
 * used by the password file loader. */
	int (*salt_hash)(void *salt);

/* Sets a salt for the crypt_all() method */
	void (*set_salt)(void *salt);

/* Sets a plaintext, with index from 0 to fmt_params.max_keys_per_crypt - 1 */
	void (*set_key)(char *key, int index);

/* Returns a plaintext previously set with and potentially altered by
 * set_key() (e.g., converted to all-uppercase and truncated at 7 for LM
 * hashes).  The plaintext may also have been generated or altered by
 * crypt_all().  Depending on crypt_all() implementation, the index used here
 * does not have to match an index previously used with set_key(), although
 * for most formats it does.  See the description of crypt_all() below. */
	char *(*get_key)(int index);

/* Allow the previously set keys to be dropped if that would help improve
 * performance and/or reduce the impact of certain hardware faults. After
 * a call to clear_keys() the keys are undefined. */
	void (*clear_keys)(void);

/* Computes the ciphertexts for given salt and plaintexts.
 * For implementation reasons, this may happen to always compute at least
 * min_keys_per_crypt ciphertexts even if the requested count is lower,
 * although it is preferable for implementations to obey the count whenever
 * practical and also for callers not to call crypt_all() with fewer than
 * min_keys_per_crypt keys whenever practical.
 * Returns the last output index for which there might be a match (against the
 * supplied salt's hashes) plus 1.  A return value of zero indicates no match.
 * Note that output indices don't have to match input indices (although they
 * may and usually do).  The indices passed to get_key(), get_hash[](),
 * cmp_one(), and cmp_exact() must be in the 0 to crypt_all() return value
 * minus 1 range, although for infrequent status reporting get_key() may also
 * be called on indices previously supplied to set_key() as well as on indices
 * up to the updated *count minus 1 even if they're beyond this range.
 * The count passed to cmp_all() must be equal to crypt_all()'s return value.
 * If an implementation does not use the salt parameter or if salt is NULL
 * (as it may be during self-test and benchmark), the return value must always
 * match *count the way it is after the crypt_all() call.
 * The count is passed by reference and must be updated by crypt_all() if it
 * computes other than the requested count (such as if it generates additional
 * candidate passwords on its own).  The updated count is used for c/s rate
 * calculation.  The return value is thus in the 0 to updated *count range. */
	int (*crypt_all)(int *count, struct db_salt *salt);

/* These functions calculate a hash out of a ciphertext that has just been
 * generated with the crypt_all() method. To be used while cracking. */
	int (*get_hash[PASSWORD_HASH_SIZES])(int index);

/* Compares a given ciphertext against all the crypt_all() method outputs and
 * returns zero if no matches detected. A non-zero return value means that
 * there might be matches, and more checks are needed. */
	int (*cmp_all)(void *binary, int count);

/* Same as the above, except the comparison is done against only one of the
 * crypt_all() method outputs. */
	int (*cmp_one)(void *binary, int index);

/* Compares an ASCII ciphertext against a particular crypt_all() output */
	int (*cmp_exact)(char *source, int index);
};

/*
 * Private fields for formats management.
 */
struct fmt_private {
	int initialized;
};

/*
 * A structure to keep a list of supported ciphertext formats.
 */
struct fmt_main {
	struct fmt_params params;
	struct fmt_methods methods;
	struct fmt_private private;
	struct fmt_main *next;
};

/*
 * Linked list of registered formats.
 */
extern struct fmt_main *fmt_list;

/*
 * Format registration function.
 */
extern void fmt_register(struct fmt_main *format);

/*
 * Initializes the format's internal structures unless already initialized.
 */
extern void fmt_init(struct fmt_main *format);

/*
 * De-initializes this format if it was previously initialized.
 */
extern void fmt_done(struct fmt_main *format);

/*
 * Tests the format's methods for correct operation. Returns NULL on
 * success, method name on error.
 */
extern char *fmt_self_test(struct fmt_main *format);

/*
 * Default methods.
 */
extern void fmt_default_init(struct fmt_main *self);
extern void fmt_default_done(void);
extern void fmt_default_reset(struct db_main *db);
extern char *fmt_default_prepare(char *fields[10], struct fmt_main *self);
extern char *fmt_default_split(char *ciphertext, int index,
    struct fmt_main *self);
extern void *fmt_default_binary(char *ciphertext);
extern void *fmt_default_salt(char *ciphertext);
extern char *fmt_default_source(char *source, void *binary);
extern int fmt_default_binary_hash(void *binary);
extern int fmt_default_salt_hash(void *salt);
extern void fmt_default_set_salt(void *salt);
extern void fmt_default_clear_keys(void);
extern int fmt_default_get_hash(int index);

/*
 * Dummy hash function to use for salts with no hash table.
 */
#define fmt_dummy_hash fmt_default_get_hash

#endif
