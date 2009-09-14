/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2009 by Solar Designer
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
#define JOHN_VERSION			"1.7.3.4"

/*
 * Notes to packagers of John for *BSD "ports", Linux distributions, etc.:
 *
 * You do need to set JOHN_SYSTEMWIDE to 1, but you do not need to patch
 * this file for that.  Instead, you can pass -DJOHN_SYSTEMWIDE=1 in CFLAGS.
 * You also do not need to patch the Makefile for that since you can pass
 * the CFLAGS via "make" command line.  Similarly, you do not need to patch
 * anything to change JOHN_SYSTEMWIDE_EXEC and JOHN_SYSTEMWIDE_HOME
 * (although the defaults for these should be fine).
 *
 * JOHN_SYSTEMWIDE_EXEC should be set to the _directory_ where John will
 * look for its "CPU fallback" program binary (which should be another
 * build of John itself).  This is only activated when John is compiled
 * with -DCPU_FALLBACK=1.  The fallback program binary name is defined
 * with CPU_FALLBACK_BINARY in architecture-specific header files such as
 * x86-mmx.h (and the default should be fine - no need to patch it).
 * Currently, this is used to transparently fallback to a non-MMX build of
 * John when an MMX build is run on older x86 processors.  Please do make
 * use of this functionality in your package if it is built for x86 (yes,
 * you need to do two builds of John for a single binary package).
 *
 * "$JOHN" is supposed to be expanded at runtime.  Please do not replace
 * it with a specific path, neither in this file nor in the default
 * john.conf, if at all possible.
 */

/*
 * Is this a system-wide installation?  *BSD "ports" and Linux distributions
 * will want to set this to 1 for their builds of John - please refer to the
 * notes above.
 */
#ifndef JOHN_SYSTEMWIDE
#define JOHN_SYSTEMWIDE			0
#endif

#if JOHN_SYSTEMWIDE
#ifndef JOHN_SYSTEMWIDE_EXEC /* please refer to the notes above */
#define JOHN_SYSTEMWIDE_EXEC		"/usr/libexec/john"
#endif
#ifndef JOHN_SYSTEMWIDE_HOME
#define JOHN_SYSTEMWIDE_HOME		"/usr/share/john"
#endif
#define JOHN_PRIVATE_HOME		"~/.john"
#endif

/*
 * Crash recovery file format version strings.
 */
#define RECOVERY_V0			"REC0"
#define RECOVERY_V1			"REC1"
#define RECOVERY_V2			"REC2"
#define RECOVERY_V3			"REC3"
#define RECOVERY_V			RECOVERY_V3

/*
 * Charset file format version string.
 */
#define CHARSET_V1			"CHR1"
#define CHARSET_V2			"CHR2"
#define CHARSET_V			CHARSET_V2

/*
 * Timer interval in seconds.
 */
#define TIMER_INTERVAL			1

/*
 * Default crash recovery file saving delay in timer intervals.
 */
#define TIMER_SAVE_DELAY		(600 / TIMER_INTERVAL)

/*
 * Default benchmark time in seconds (per cracking algorithm).
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
 * Hash table sizes.  These are also hardcoded into the hash functions.
 */
#define SALT_HASH_SIZE			0x400
#define PASSWORD_HASH_SIZE_0		0x10
#define PASSWORD_HASH_SIZE_1		0x100
#define PASSWORD_HASH_SIZE_2		0x1000

/*
 * Password hash table thresholds.  These are the counts of entries required
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
#define CRACKED_HASH_LOG		11
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
 *
 * Please note that certain intermediate values computed in charset.c while
 * generating a new charset file should fit in 64 bits.  As long as
 * ((SIZE ** LENGTH) * SCALE) fits in 64 bits you're definitely safe, although
 * the exact requirement, which you can see in charset.c: charset_self_test(),
 * is a bit less strict.  John will refuse to generate a charset file if the
 * values would overflow, so rather than do the math yourself you can simply
 * let John test the values for you.  You can reduce the SCALE if required.
 *
 * Also, please note that changes to these parameters make your build of John
 * incompatible with charset files generated with other builds.
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
