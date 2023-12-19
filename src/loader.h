/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-98,2010-2013,2015 by Solar Designer
 *
 * ...with changes in the jumbo patch, by various authors
 */

/*
 * Password database management.
 */

#ifndef _JOHN_LOADER_H
#define _JOHN_LOADER_H

#include <stdint.h>
#include "params.h"
#ifndef BENCH_BUILD
#include "list.h"
#include "formats.h"
#endif

/*
 * Password hash list entry (with a fixed salt).
 */
struct db_password {
/* Pointer to next password hash with the same salt */
	struct db_password *next;

/* Hot portion of or full binary ciphertext for fast comparison (aligned).
 * Alternatively, for non-hash formats: Non-salt data (that we used to
 * incorrectly store in a "salt"). */
	void *binary;

/* After loading is completed: pointer to next password hash with the same salt
 * and hash-of-hash.
 * While loading: pointer to next password hash with the same hash-of-hash. */
	struct db_password *next_hash;

/* ASCII ciphertext for exact comparison and saving with cracked passwords.
 * Alternatively, when the source() method is non-default this field is either
 * unused or this pointer may be reused to hold the binary value above. */
	char *source;

/* Login field from the password file, with ":1" or ":2" appended if the
 * ciphertext was split into two parts. */
	char *login;

/* uid field from the password file */
	char *uid;

/* Words from the GECOS field (loaded for "single crack" mode only) */
	struct list_main *words;
};

/*
 * Buffered keys hash table entry.
 */
struct db_keys_hash_entry {
/* Index of next key with the same hash, or -1 if none */
	SINGLE_KEYS_TYPE next;

/* Byte offset of this key in the buffer */
	SINGLE_KEYS_UTYPE offset;
};

/*
 * Buffered keys hash.
 */
struct db_keys_hash {
/* The hash table, maps to indices for the list below; -1 means empty bucket */
	SINGLE_KEYS_TYPE hash[SINGLE_HASH_SIZE];

/* List of keys with the same hash, allocated as min_keys_per_crypt entries */
	struct db_keys_hash_entry list[1];
};

/*
 * Buffered keys.
 */
struct db_keys {
/* Keys hash table, for fast dupe checking */
	struct db_keys_hash *hash;

/* &buffer[count * plaintext_length] */
	char *ptr;

/* Number of keys currently in the buffer */
	int count;

/* Number of keys currently in the buffer that came from successful guesses
 * for other salts and thus are being tried for all salts */
	int count_from_guesses;

/* Whether we have words to base candidate passwords on or not.
 * Even if not, we need this keys buffer anyway to hold other salts' successful
 * guesses for testing against this salt's hashes. */
	int have_words;

/* Number of last processed rule ([0]) and stacked rule ([1]) */
	int rule[2];

/* Number of recursive calls for this salt */
	int lock;

/* The keys, allocated as (plaintext_length * min_keys_per_crypt) bytes */
	char buffer[1];
};

/*
 * Salt list entry.
 */
struct db_salt {
/* Pointer to next salt in the list */
	struct db_salt *next;

/* Salt in internal representation */
	void *salt;

/* md5 of the salt 'data'. Used to find the salt in resume session logic */
	uint32_t salt_md5[4];

/* Bitmap indicating whether a computed hash is potentially present in the list
 * and hash table below.  Normally, the bitmap is large enough that most of its
 * bits are zero. */
	unsigned int *bitmap;

/* Pointer to a hash function to get the bit index into the bitmap above for
 * the crypt_all() method output with given index.  The function always returns
 * zero if there's no bitmap for this salt. */
	int (*index)(int index);

/* List of passwords with this salt */
	struct db_password *list;

/* Password hash table for this salt, or a pointer to the list field */
	struct db_password **hash;

/* Hash table size code, negative for none */
	int hash_size;

/* Number of passwords with this salt */
	int count;

/*
 * Sequential id for a given salt. Sequential id does not change even if some
 * salts are removed during cracking (except possibly if a FMT_REMOVE format
 * renumbers the salts while re-iterating them).
 */
	int sequential_id;

#ifndef BENCH_BUILD
/* Tunable costs */
	unsigned int cost[FMT_TUNABLE_COSTS];
#endif

/* Buffered keys, allocated for "single crack" mode only */
/* THIS MUST BE LAST IN THE STRUCT */
	struct db_keys *keys;
};

/*
 * Structure to hold a cracked password.
 */
struct db_cracked {
/* Pointer to next password with the same hash */
	struct db_cracked *next;

/* Data from the pot file */
	char *ciphertext, *plaintext;
};

/*
 * Password database contents flags.
 */
/* Login fields loaded */
#define DB_LOGIN			0x00000001
/* Words from GECOS fields loaded */
#define DB_WORDS			0x00000002
/* Some hashed passwords were split into several entries */
#define DB_SPLIT			0x00000010
/* Duplicate hashes were seen and excluded */
#define DB_NODUP			0x00000020
/* Some entries are marked for removal */
#define DB_NEED_REMOVAL			0x00000080
/* Cracked passwords only (ciphertext, plaintext) */
#define DB_CRACKED			0x00000100
/* Cracked plaintexts list */
#define DB_PLAINTEXTS			0x00000200

/*
 * Password database options.
 */
struct db_options {
/* Contents flags bitmask */
	unsigned int flags;

/* Filters to use while loading */
	struct list_main *users, *groups, *shells;

/* Requested passwords per salt (load salts having at least [M:]N hashes) */
	int min_pps, max_pps;

/* If this is true, min/max_pps refers to "best counts" (load the [M-]N most used salts) */
	int best_pps;

#ifndef BENCH_BUILD
/* Requested cost values */
	unsigned int min_cost[FMT_TUNABLE_COSTS];
	unsigned int max_cost[FMT_TUNABLE_COSTS];
#endif

/* if --show=left is used, john dumps the non-cracked hashes */
	int showuncracked;

/* if --show=formats is used, show all hashes in JSON form */
	int showformats;

/* if --show=types is used, john shows all hashes in machine readable form */
	int showformats_old;

/* if --show=invalid is used, john shows all hashes which fail valid() */
	int showinvalid;

/* Field separator (normally ':') */
	char field_sep_char;

/* Write cracked passwords to log (default is just username) */
	int log_passwords;
};

/*
 * Main password database.
 */
struct db_main {
/* Are hashed passwords loaded into this database? */
	int loaded;

/* Base allocation sizes for "struct db_password" and "struct db_salt" as
 * possibly adjusted by ldr_init_database() given options->flags and such. */
	size_t pw_size, salt_size;

/* Options */
	struct db_options *options;

/* Salt list */
	struct db_salt *salts;

/* Salt and password hash tables, used while loading */
	struct db_salt **salt_hash;
	struct db_password **password_hash;

/* binary_hash function used by the loader itself */
	int (*password_hash_func)(void *binary);

/* Cracked passwords */
	struct db_cracked **cracked_hash;

/* Cracked plaintexts list */
	struct list_main *plaintexts;

/* Number of salts, passwords and guesses */
	int salt_count, password_count, guess_count;

#ifndef BENCH_BUILD
/* min. and max. tunable costs */
	unsigned int min_cost[FMT_TUNABLE_COSTS];
	unsigned int max_cost[FMT_TUNABLE_COSTS];
#endif

/* Ciphertext format */
	struct fmt_main *format;

/*
 * Pointer to real db. NULL if there is none. If this db *is* the real db
 * this points back to ourself (db->real == db).
 */
	struct db_main *real;
};

/* Non-zero while the loader is processing the pot file */
extern int ldr_in_pot;

/*
 * Initializes the database before loading.
 */
extern void ldr_init_database(struct db_main *db, struct db_options *options);

#ifdef HAVE_FUZZ
/*
 * Loads a line into the database.
 */
extern void ldr_load_pw_line(struct db_main *db, char *line);
#endif

/*
 * Loads a password file into the database.
 */
extern void ldr_load_pw_file(struct db_main *db, char *name);

/*
 * Marks for removal from the database hashes cracked in previous sessions.
 */
extern void ldr_load_pot_file(struct db_main *db, char *name);

/*
 * Finalizes the database after loading, which includes removal of salts and
 * hashes that don't meet criteria, as well as of hashes marked as previously
 * cracked.  Returns the number of hashes that were in the database after
 * removal of those not meeting criteria, but before removal of those cracked.
 */
extern int ldr_fix_database(struct db_main *db);

/*
 * Create a fake database from a format's test vectors and return a pointer
 * to it.
 */
extern struct db_main *ldr_init_test_db(struct fmt_main *format,
                                        struct db_main *real);

/*
 * Destroy a database. If 'base' is true, then also frees the db pointer
 */
extern void ldr_free_db(struct db_main *db, int base);

/*
 * Loads cracked passwords into the database.
 */
extern void ldr_show_pot_file(struct db_main *db, char *name);

/*
 * Shows cracked passwords.
 */
extern void ldr_show_pw_file(struct db_main *db, char *name);

/* Compare a possibly truncated pot source with a full one */
extern int ldr_pot_source_cmp(const char *pot_entry, const char *full_source);

/*
 * This returns the line to write to a .pot file. It may be shorter than the
 * original source (with some extra tags added).
 */
extern const char *ldr_pot_source(const char *full_source,
                                  char buffer[LINE_BUFFER_SIZE+1]);

/*
 * this function simply returns true of false if this is a chopped pot line
 */
extern int ldr_isa_pot_source(const char *ciphertext);

/* Common code for determining valid when loading a chopped .pot line */
extern int ldr_trunc_valid(char *ciphertext, struct fmt_main *format);

/*
 * This function is for ldr_split_line(), and shared for showformats_regular()
 */
extern void ldr_set_encoding(struct fmt_main *format);

#endif
