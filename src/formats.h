/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2005,2010-2013,2015 by Solar Designer
 *
 * ...with a change in the jumbo patch, by JimF
 */

/*
 * Supported ciphertext formats management.
 */

#ifndef _JOHN_FORMATS_H
#define _JOHN_FORMATS_H

#include "params.h"
#include "misc.h"

/*
 * For now, you can just revert FMT_MAIN_VERSION to 11
 * in case of any problem with the new additions
 * (tunable cost parameters)
 * (format signatures, #14)
 */
#define FMT_MAIN_VERSION 14	/* change if structure fmt_main changes */

/*
 * fmt_main is declared for real further down this file, but we refer to it in
 * function prototypes in fmt_methods.
 */
struct fmt_main;

/*
 * Maximum number of different tunable cost parameters
 * that can be reported for a single format
 */
#define FMT_TUNABLE_COSTS	4

/*
 * Maximum number of different signatures
 * that can be reported for a single format
 */
#define FMT_SIGNATURES	4

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
/*
 * This flag must be set for formats that do UCS-2, UTF-16 or some other wide
 * encoding internally (eg. most Microsoft formats). The most common problem
 * with formats not fully Unicode-aware is when a format like this is hard-coded
 * to convert from ISO-8859-1 (ie. by just inserting 0x00, effectively just
 * casting every char to a short). Such formats MUST set FMT_UNICODE and MUST
 * NOT set FMT_ENC, or users will get false negatives when using UTF-8 or
 * codepages.
 */
#define FMT_UNICODE			0x00000004
/*
 * Honors the --encoding=NAME option. This means it can handle codepages (like
 * cp1251) as well as UTF-8.
 */
#define FMT_ENC				0x00000008
/*
 * This hash type is known to actually use UTF-8 encoding of password, so
 * trying legacy target encodings should be pointless.
 */
#define FMT_UTF8			0x00000010
/*
 * Mark password->binary = NULL immediately after a hash is cracked. Must be
 * set for formats that read salt->list in crypt_all for the purpose of
 * identification of uncracked hashes for this salt.
 */
#define FMT_REMOVE			0x00000020
/*
 * Format has false positive matches. Thus, do not remove hashes when
 * a likely PW is found.  This should only be set for formats where a
 * false positive will actually not work IRL (eg. 7z),  as opposed to
 * ones that has actual collisions (eg. oldoffice).  The latter group
 * of formats may instead be run with --keep-guessing if/when wanted.
 */
#define FMT_NOT_EXACT			0x00000100
/*
 * This format uses a dynamic sized salt, and its salt structure
 * 'derives' from the dyna_salt type defined in dyna_salt.h
 */
#define FMT_DYNA_SALT			0x00000200
/*
 * This format supports huge ciphertexts (longer than MAX_CIPHERTEXT_SIZE,
 * currently 896 bytes) and will consequently truncate its pot lines with
 * $SOURCE_HASH$ to end up fitting within LINE_BUFFER_SIZE.
 */
#define FMT_HUGE_INPUT			0x00000400
/* Uses a bitslice implementation */
#define FMT_BS				0x00010000
/* The split() method unifies the case of characters in hash encodings */
#define FMT_SPLIT_UNIFIES_CASE		0x00020000
/* A dynamic_x format (or a 'thin' format using dynamic code) */
#define FMT_DYNAMIC			0x00100000
/* This format originally truncates at our max. length (eg. descrypt) */
#define FMT_TRUNC			0x00200000
/* Format can do "internal mask" (eg. GPU-side mask)? */
#define FMT_MASK			0x00400000
#ifdef _OPENMP
/* Parallelized with OpenMP */
#define FMT_OMP				0x01000000
/* Poor OpenMP scalability */
#define FMT_OMP_BAD			0x02000000
#else
#define FMT_OMP				0
#define FMT_OMP_BAD			0
#endif
/* Non-hash format. If used, binary_size must be sizeof(fmt_data) */
#define FMT_BLOB			0x04000000
/* We've already warned the user about hashes of this type being present */
#define FMT_WARNED			0x80000000

/* Format's length before calling init() */
extern int fmt_raw_len;

/*
 * A password to test the methods for correct operation.
 */
struct fmt_tests {
	char *ciphertext, *plaintext;
	char *fields[10];
};

#if BLOB_DEBUG

/* Magic signature stuffed in flags for debugging */
#include <assert.h>
#define FMT_DATA_MAGIC	((sizeof(size_t) < 8) ? 0x0babe500 : \
					0x00c007000babe500ULL)
#define BLOB_ASSERT(b)	assert((((fmt_data*)(b))->flags & ~3) == FMT_DATA_MAGIC)

#else

#define BLOB_ASSERT(b)
#define FMT_DATA_MAGIC	0

#endif /* BLOB_DEBUG */

/*
 * Flags for fmt_data.
 */
/* Blob portion is tiny-alloc. */
#define FMT_DATA_TINY			(FMT_DATA_MAGIC | 0x01)
/* Blob portion is malloc, so needs to be freed when done with it. */
#define FMT_DATA_ALLOC			(FMT_DATA_MAGIC | 0x02)

/*
 * Variable size data for non-hashes (formerly stored in "salt").
 * "size" is the size of blob only. Size of data returned is always
 * just sizeof(fmt_data). The blob is either mem_alloc_tiny and flag
 * is FMT_DATA_TINY, or alloced and flag is FMT_DATA_ALLOC.
 * The latter needs free when we're done with it. Regardless, the
 * loader never copies it - just this struct. The cracker uses the
 * pointer and size (and frees the pointer when appropriate).
 */
typedef struct {
	size_t flags;
	size_t size;
	void *blob;
} fmt_data;

/* Helper macros */
#define BLOB_BINARY(f, b) (((f)->params.flags & FMT_BLOB) ?	\
                        (((fmt_data*)(b))->blob) : (b))

#define BLOB_SIZE(f, b) (((f)->params.flags & FMT_BLOB) ?	  \
                      (((fmt_data*)(b))->size) : ((f)->params.binary_size))

#define BLOB_FREE(f, b) do {	  \
		if ((f)->params.flags & FMT_BLOB) { \
			BLOB_ASSERT(b); \
			if ((b) && \
			    (((fmt_data*)(b))->flags == FMT_DATA_ALLOC)) \
				MEM_FREE(((fmt_data*)(b))->blob); \
		} \
	} while (0)

/*
 * Parameters of a hash function and its cracking algorithm.
 */
struct fmt_params {
/* Label to refer to this format (any alphabetical characters in it must be
 * lowercase). */
	const char *label;

/* Ciphertext format name */
	const char *format_name;

/* Cracking algorithm name */
	const char *algorithm_name;

/* Comment about the benchmark (can be empty) */
	const char *benchmark_comment;

/* Benchmark for this password length.  Can also add one of:
 * + 0x100 Force "Raw" benchmark even for a salted format
 * + 0x200 Benchmark for short/long passwords instead of for one/many salts
 * + 0x500 Make "Raw" behave like "Only one salt", not "Many salts" */
	int benchmark_length;

/* Minimum length of a plaintext password */
	int plaintext_min_length;

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

/*
 * Descriptions (names) of tunable cost parameters for this format
 *
 * These names shouldn't contain ',', because ", " is used
 * as a separator when listing tunable cost parameters
 * in --list=format-details and --list=format-all-details.
 * The sequence of names should match the sequence of functions
 * returning tunable cost values.
 */
	char *tunable_cost_name[FMT_TUNABLE_COSTS];

/*
 * format signatures (such as $NT$, etc).
 *
 * This is used in loader to see if a line read from a .pot file is a
 * 'chopped' line, that was shortened before being written to .pot.
 */
	char *signature[FMT_SIGNATURES];

/*
 * Some passwords to test the methods for correct operation (or NULL for no
 * self test, and no benchmark), terminated with a NULL ciphertext.
 */
	struct fmt_tests *tests;
};

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
 * self-test or benchmark rather than before actual cracking, db may be made
 * out of test vectors.
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
/* Or, converts an ASCII non-hash data blob to a fmt_data struct */
	void *(*binary)(char *ciphertext);

/* Converts an ASCII salt to its internal representation */
	void *(*salt)(char *ciphertext);

/*
 * These functions return the value of a tunable cost parameter
 * for a given salt.
 * The sequence of of functions returning the vaules of tunable costs
 * parameters has to match the sequence of their descriptions in
 * tunable_cost_name[FMT_TUNABLE_COSTS].
 * The format implementation has to decide which tunable cost parameters
 * are most significant for CPU time and/or memory requirements.
 * If possible, the reported values should be linear to the real cost,
 * even if in the format the parameter is the dual logarithm of the real cost,
 * e.g., the real iteration count is 2^(t_cost) for parameter t_cost.
 */
	unsigned int (*tunable_cost_value[FMT_TUNABLE_COSTS])(void *salt);

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

/* Compare function used for sorting salts */
	int (*salt_compare)(const void *x, const void *y);

/* Sets a salt for the crypt_all() method */
	void (*set_salt)(void *salt);

/* Sets a plaintext, with index from 0 to fmt_params.max_keys_per_crypt - 1.
 * The string is NUL-terminated, but set_key() may over-read it until up to
 * PLAINTEXT_BUFFER_SIZE total read (thus, the caller's buffer must be at least
 * this large).  Empty string may be passed as fmt_null_key. */
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
 * a call to clear_keys() the keys are undefined.  Jumbo guarantees this
 * will be called before set_key(0). */
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
	void *data;
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
 * Empty key that is safe to pass to the set_key() method, given that it may
 * over-read the empty string for up to PLAINTEXT_BUFFER_SIZE.
 */
extern char fmt_null_key[PLAINTEXT_BUFFER_SIZE];

/*
 * List of valid format classes for this build
 */
extern char fmt_class_list[];

/* Self-test is running */
extern int self_test_running;

/* Benchmark is running */
extern int benchmark_running;

/* Self-test or benchmark is running */
#define bench_or_test_running	(self_test_running || benchmark_running)

/*
 * Linked list of registered formats.
 */
extern struct fmt_main *fmt_list;

/*
 * Format registration function.
 */
extern void fmt_register(struct fmt_main *format);

/*
 * Returns true if name is a format class such as "opencl" or "dynamic"
 */
extern int fmt_is_class(char *name);

/* Returns "class", "wildcard" or "name" */
extern char* fmt_type(char *name);

/*
 * Match req_format to format, supporting wildcards/groups/classes etc.
 */
extern int fmt_match(const char *req_format, struct fmt_main *format, int override_disable);

/*
 * Check for --format=LIST and if so, re-populate fmt_list from it.
 */
extern int fmt_check_custom_list(void);

/*
 * Initializes the format's internal structures unless already initialized.
 */
extern void fmt_init(struct fmt_main *format);

/*
 * De-initializes this format if it was previously initialized.
 */
extern void fmt_done(struct fmt_main *format);

/*
 * De-initializes all initialized formats.
 */
extern void fmt_all_done(void);

/*
 * Tests the format's methods for correct operation. Returns NULL on
 * success, method name on error.
 */
extern char *fmt_self_test(struct fmt_main *format, struct db_main *db);

/*
 * Compare the real binary, whatever it is:
 * If this is not FMT_BLOB we do a plain memcmp. If it is, we
 * memcmp the pointed-to binaries, with correct sizes.
 */
extern int fmt_bincmp(void *b1, void *b2, struct fmt_main *format);

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
/* this is a salt_hash default specifically for dyna_salt type formats */
extern int fmt_default_dyna_salt_hash(void *salt);

/*
 * Default binary_hash_N methods
 */
extern int fmt_default_binary_hash_0(void * binary);
extern int fmt_default_binary_hash_1(void * binary);
extern int fmt_default_binary_hash_2(void * binary);
extern int fmt_default_binary_hash_3(void * binary);
extern int fmt_default_binary_hash_4(void * binary);
extern int fmt_default_binary_hash_5(void * binary);
extern int fmt_default_binary_hash_6(void * binary);

/*
 * Dummy hash function to use for salts with no hash table.
 */
#define fmt_dummy_hash fmt_default_get_hash

/*
 * This is for all formats that want to use omp_autotune()
 */
#include "omp_autotune.h"

#endif
