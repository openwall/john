/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2005,2010,2011 by Solar Designer
 */

/*
 * Supported ciphertext formats management.
 */

#ifndef _JOHN_FORMATS_H
#define _JOHN_FORMATS_H

#include "params.h"

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
/* Parallelized with OpenMP */
#ifdef _OPENMP
#define FMT_OMP				0x01000000
#else
#define FMT_OMP				0
#endif
/* We've already warned the user about hashes of this type being present */
#define FMT_WARNED			0x80000000

/*
 * A password to test the methods for correct operation.
 */
struct fmt_tests {
	char *ciphertext, *plaintext;
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

/* Size of binary ciphertext used for fast comparison, in bytes */
	int binary_size;

/* Size of internal salt representation, in bytes */
	int salt_size;

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
 * Functions to implement a cracking algorithm.
 *
 * When passing binary ciphertexts or salts in internal representation, these
 * should be word aligned; the functions may assume such alignment.
 */
struct fmt_methods {
/* Initializes the algorithm's internal structures; valid() and split() are
 * the only methods that are allowed to be called before a call to init().
 * Note that initializing an algorithm might de-initialize some others (if
 * a shared underlying resource is used). */
	void (*init)(void);

/* Checks if an ASCII ciphertext is valid for this format. Returns zero for
 * invalid ciphertexts, or a number of parts the ciphertext should be split
 * into (up to 9, will usually be 1). */
	int (*valid)(char *ciphertext);

/* Splits a ciphertext into several pieces and returns the piece with given
 * index, starting from 0 (will usually return the ciphertext unchanged).
 * For hex-encoded hashes which are compared by the target system/application
 * irrespective of the case of characters (upper/lower/mixed) used in their
 * encoding, split() must unify the case (e.g., convert to all-lowercase)
 * and FMT_SPLIT_UNIFIES_CASE must be set. */
	char *(*split)(char *ciphertext, int index);

/* Converts an ASCII ciphertext to binary, possibly using the salt */
	void *(*binary)(char *ciphertext);

/* Converts an ASCII salt to its internal representation */
	void *(*salt)(char *ciphertext);

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

/* Returns a plaintext previously set with set_key() */
	char *(*get_key)(int index);

/* Allow the previously set keys to be dropped if that would help improve
 * performance and/or reduce the impact of certain hardware faults. After
 * a call to clear_keys() the keys are undefined. */
	void (*clear_keys)(void);

/* Calculates the ciphertexts for given salt and plaintexts. This may
 * always calculate at least min_keys_per_crypt ciphertexts regardless of
 * the requested count, for some formats. */
	void (*crypt_all)(int count);

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
 * Tests the format's methods for correct operation. Returns NULL on
 * success, method name on error.
 */
extern char *fmt_self_test(struct fmt_main *format);

/*
 * Default methods.
 */
extern void fmt_default_init(void);
extern int fmt_default_valid(char *ciphertext);
extern char *fmt_default_split(char *ciphertext, int index);
extern void *fmt_default_binary(char *ciphertext);
extern void *fmt_default_salt(char *ciphertext);
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
