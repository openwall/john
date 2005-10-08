/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2005 by Solar Designer
 */

/*
 * Some global parameters.
 */

#ifndef _JOHN_PARAMS_H
#define _JOHN_PARAMS_H

#include <limits.h>

/*
 * John's version number.
 */
#define JOHN_VERSION			"1.6.39.1"

/*
 * Is this a system-wide installation? *BSD ports and Linux distributions
 * will probably want to set this to 1 for their builds of John.
 */
#ifndef JOHN_SYSTEMWIDE
#define JOHN_SYSTEMWIDE			0
#endif

#if JOHN_SYSTEMWIDE
#define JOHN_SYSTEMWIDE_EXEC		"/usr/libexec/john"
#define JOHN_SYSTEMWIDE_HOME		"/usr/share/john"
#define JOHN_PRIVATE_HOME		"~/.john"
#endif

/*
 * Crash recovery file format version strings.
 */
#define RECOVERY_VERSION_0		"REC0"
#define RECOVERY_VERSION_1		"REC1"
#define RECOVERY_VERSION_2		"REC2"
#define RECOVERY_VERSION_CURRENT	RECOVERY_VERSION_2

/*
 * Charset file format version string.
 */
#define CHARSET_VERSION			"CHR1"

/*
 * Timer interval in seconds.
 */
#define TIMER_INTERVAL			1

/*
 * Default crash recovery file saving delay in timer intervals.
 */
#define TIMER_SAVE_DELAY		(600 / TIMER_INTERVAL)

/*
 * Benchmark time in seconds, per cracking algorithm.
 */
#define BENCHMARK_TIME			5

/*
 * Number of salts to assume when benchmarking.
 */
#define BENCHMARK_MANY			0x100

/*
 * File names.
 */
#define CFG_FULL_NAME			"$JOHN/john.conf"
#define CFG_ALT_NAME			"$JOHN/john.ini"
#if JOHN_SYSTEMWIDE
#define CFG_PRIVATE_FULL_NAME		JOHN_PRIVATE_HOME "/john.conf"
#define CFG_PRIVATE_ALT_NAME		JOHN_PRIVATE_HOME "/john.ini"
#define POT_NAME			JOHN_PRIVATE_HOME "/john.pot"
#define LOG_NAME			JOHN_PRIVATE_HOME "/john.log"
#define RECOVERY_NAME			JOHN_PRIVATE_HOME "/john.rec"
#else
#define POT_NAME			"$JOHN/john.pot"
#define LOG_NAME			"$JOHN/john.log"
#define RECOVERY_NAME			"$JOHN/john.rec"
#endif
#define LOG_SUFFIX			".log"
#define RECOVERY_SUFFIX			".rec"
#define WORDLIST_NAME			"$JOHN/password.lst"

/*
 * Configuration file section names.
 */
#define SECTION_OPTIONS			"Options"
#define SECTION_RULES			"List.Rules:"
#define SUBSECTION_SINGLE		"Single"
#define SUBSECTION_WORDLIST		"Wordlist"
#define SECTION_INC			"Incremental:"
#define SECTION_EXT			"List.External:"

/*
 * Hash table sizes. These are also hardcoded into the hash functions.
 */
#define SALT_HASH_SIZE			0x400
#define PASSWORD_HASH_SIZE_0		0x10
#define PASSWORD_HASH_SIZE_1		0x100
#define PASSWORD_HASH_SIZE_2		0x1000

/*
 * Password hash table thresholds. These are the counts of entries required
 * to enable the corresponding hash table size.
 */
#define PASSWORD_HASH_THRESHOLD_0	(PASSWORD_HASH_SIZE_0 / 2)
#define PASSWORD_HASH_THRESHOLD_1	(PASSWORD_HASH_SIZE_1 / 4)
#define PASSWORD_HASH_THRESHOLD_2	(PASSWORD_HASH_SIZE_2 / 4)

/*
 * Tables of the above values.
 */
extern int password_hash_sizes[3];
extern int password_hash_thresholds[3];

/*
 * Cracked password hash size, used while loading.
 */
#define CRACKED_HASH_LOG		10
#define CRACKED_HASH_SIZE		(1 << CRACKED_HASH_LOG)

/*
 * Password hash function to use while loading.
 */
#define LDR_HASH_SIZE	(PASSWORD_HASH_SIZE_2 * sizeof(struct db_password *))
#define LDR_HASH_FUNC	(format->methods.binary_hash[2])

/*
 * Buffered keys hash size, used for "single crack" mode.
 */
#define SINGLE_HASH_LOG			5
#define SINGLE_HASH_SIZE		(1 << SINGLE_HASH_LOG)

/*
 * Minimum buffered keys hash size, used if min_keys_per_crypt is even less.
 */
#define SINGLE_HASH_MIN			8

/*
 * Shadow file entry table hash size, used by unshadow.
 */
#define SHADOW_HASH_LOG			8
#define SHADOW_HASH_SIZE		(1 << SHADOW_HASH_LOG)

/*
 * Hash and buffer sizes for unique.
 */
#define UNIQUE_HASH_LOG			17
#define UNIQUE_HASH_SIZE		(1 << UNIQUE_HASH_LOG)
#define UNIQUE_BUFFER_SIZE		0x800000

/*
 * Maximum number of GECOS words per password to load.
 */
#define LDR_WORDS_MAX			0x10

/*
 * Maximum number of GECOS words to try in pairs.
 */
#define SINGLE_WORDS_PAIR_MAX		4

/*
 * Charset parameters.
 * Be careful if you change these, ((SIZE ** LENGTH) * SCALE) should fit
 * into 64 bits. You can reduce the SCALE if required.
 */
#define CHARSET_MIN			' '
#define CHARSET_MAX			0x7E
#define CHARSET_SIZE			(CHARSET_MAX - CHARSET_MIN + 1)
#define CHARSET_LENGTH			8
#define CHARSET_SCALE			0x100

/*
 * Compiler parameters.
 */
#define C_TOKEN_SIZE			0x100
#define C_UNGET_SIZE			(C_TOKEN_SIZE + 4)
#define C_EXPR_SIZE			0x100
#define C_STACK_SIZE			((C_EXPR_SIZE + 4) * 4)
#define C_ARRAY_SIZE			0x1000000
#define C_DATA_SIZE			0x8000000

/*
 * Buffer size for rules.
 */
#define RULE_BUFFER_SIZE		0x100

/*
 * Maximum number of character ranges for rules.
 */
#define RULE_RANGES_MAX			16

/*
 * Buffer size for words while applying rules, should be at least as large
 * as PLAINTEXT_BUFFER_SIZE.
 */
#define RULE_WORD_SIZE			0x80

/*
 * Buffer size for plaintext passwords.
 */
#define PLAINTEXT_BUFFER_SIZE		0x80

/*
 * Buffer size for fgets().
 */
#define LINE_BUFFER_SIZE		0x400

/*
 * john.pot and log file buffer sizes, can be zero.
 */
#define POT_BUFFER_SIZE			0x1000
#define LOG_BUFFER_SIZE			0x1000

/*
 * Buffer size for path names.
 */
#ifdef PATH_MAX
#define PATH_BUFFER_SIZE		PATH_MAX
#else
#define PATH_BUFFER_SIZE		0x400
#endif

#endif
