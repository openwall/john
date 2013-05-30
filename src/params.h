/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2013 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

/*
 * Some global parameters.
 */

#ifndef _JOHN_PARAMS_H
#define _JOHN_PARAMS_H

#include <limits.h>

#include "arch.h"

/*
 * John's version number.
 */
#define JOHN_VERSION			"1.8.0"

/*
 * Notes to packagers of John for *BSD "ports", Linux distributions, etc.:
 *
 * You do need to set JOHN_SYSTEMWIDE to 1, but you do not need to patch this
 * file for that.  Instead, you can pass -DJOHN_SYSTEMWIDE=1 in CFLAGS.  You
 * also do not need to patch the Makefile for that since you can pass the
 * CFLAGS via "make" command line.  Similarly, you do not need to patch
 * anything to change JOHN_SYSTEMWIDE_EXEC and JOHN_SYSTEMWIDE_HOME (although
 * the defaults for these should be fine).
 *
 * JOHN_SYSTEMWIDE_EXEC should be set to the _directory_ where John will look
 * for its "CPU fallback" program binary (which should be another build of John
 * itself).  This is activated when John is compiled with -DCPU_FALLBACK=1.
 * The fallback program binary name is defined with CPU_FALLBACK_BINARY in
 * architecture-specific header files such as x86-64.h (and the default should
 * be fine - no need to patch it).  On x86-64, this may be used to
 * transparently fallback from a -64-xop build to -64-avx, then to plain -64
 * (which implies SSE2).  On 32-bit x86, this may be used to fallback from -xop
 * to -avx, then to -sse2, then to -mmx, and finally to -any.  Please do make
 * use of this functionality in your package if it is built for x86-64 or
 * 32-bit x86 (yes, you may need to make five builds of John for a single
 * 32-bit x86 binary package).
 *
 * Similarly, -DOMP_FALLBACK=1 activates fallback to OMP_FALLBACK_BINARY in the
 * JOHN_SYSTEMWIDE_EXEC directory when an OpenMP-enabled build of John
 * determines that it would otherwise run only one thread, which would often
 * be less optimal than running a non-OpenMP build.
 *
 * CPU_FALLBACK and OMP_FALLBACK may be used together, but in that case you
 * need to override some of the default fallback binary filenames such that you
 * can have both OpenMP-enabled and non-OpenMP fallback binaries that use the
 * same CPU instruction set extensions.  You can do these overrides with
 * options like -DOMP_FALLBACK_BINARY='"john-non-omp-non-avx"' (leaving
 * CPU_FALLBACK_BINARY at its default of "john-non-avx") or
 * -DOMP_FALLBACK_BINARY='"john-sse2"' and
 * -DCPU_FALLBACK_BINARY='"john-omp-sse2"' as fallbacks from an OpenMP-enabled
 * -avx build.  Please note that you do not need to patch any John files for
 * this, not even the Makefile.  For an example of passing these settings from
 * an RPM spec file, please refer to john.spec used in Owl.
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

#ifndef OMP_FALLBACK
#define OMP_FALLBACK			0
#endif

#if OMP_FALLBACK && !defined(OMP_FALLBACK_BINARY)
#define OMP_FALLBACK_BINARY		"john-non-omp"
#endif

/*
 * Crash recovery file format version strings.
 */
#define RECOVERY_V0			"REC0"
#define RECOVERY_V1			"REC1"
#define RECOVERY_V2			"REC2"
#define RECOVERY_V3			"REC3"
#define RECOVERY_V4			"REC4"
#define RECOVERY_V			RECOVERY_V4

/*
 * Charset file format version string.
 */
#define CHARSET_V3			"CHR3"
#define CHARSET_V			CHARSET_V3

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
#define RECOVERY_NAME			JOHN_PRIVATE_HOME "/john"
#else
#define POT_NAME			"$JOHN/john.pot"
#define LOG_NAME			"$JOHN/john.log"
#define RECOVERY_NAME			"$JOHN/john"
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
 * Number of different password hash table sizes.
 * This is not really configurable, but we define it here in order to have
 * the number hard-coded in fewer places.
 */
#define PASSWORD_HASH_SIZES		7

/*
 * Which hash table size (out of those listed below) the loader should use for
 * its own purposes.  This does not affect password cracking speed after the
 * loading is complete.
 */
#define PASSWORD_HASH_SIZE_FOR_LDR	4

/*
 * Hash table sizes.  These may also be hardcoded into the hash functions.
 */
#define SALT_HASH_LOG			12
#define SALT_HASH_SIZE			(1 << SALT_HASH_LOG)
#define PASSWORD_HASH_SIZE_0		0x10
#define PASSWORD_HASH_SIZE_1		0x100
#define PASSWORD_HASH_SIZE_2		0x1000
#define PASSWORD_HASH_SIZE_3		0x10000
#define PASSWORD_HASH_SIZE_4		0x100000
#define PASSWORD_HASH_SIZE_5		0x1000000
#define PASSWORD_HASH_SIZE_6		0x8000000

/*
 * Password hash table thresholds.  These are the counts of entries required
 * to enable the corresponding bitmap size.  The corresponding hash table size
 * may be smaller as determined by PASSWORD_HASH_SHR.
 */
#define PASSWORD_HASH_THRESHOLD_0	3
#define PASSWORD_HASH_THRESHOLD_1	3
#define PASSWORD_HASH_THRESHOLD_2	(PASSWORD_HASH_SIZE_1 / 25)
#define PASSWORD_HASH_THRESHOLD_3	(PASSWORD_HASH_SIZE_2 / 20)
#define PASSWORD_HASH_THRESHOLD_4	(PASSWORD_HASH_SIZE_3 / 10)
#define PASSWORD_HASH_THRESHOLD_5	(PASSWORD_HASH_SIZE_4 / 15)
#define PASSWORD_HASH_THRESHOLD_6	(PASSWORD_HASH_SIZE_5 / 5)

/*
 * Tables of the above values.
 */
extern int password_hash_sizes[PASSWORD_HASH_SIZES];
extern int password_hash_thresholds[PASSWORD_HASH_SIZES];

/*
 * How much smaller should the hash tables be than bitmaps in terms of entry
 * count.  Setting this to 0 will result in them having the same number of
 * entries, 1 will make the hash tables twice smaller than bitmaps, etc.
 * 5 or 6 will make them the same size in bytes on systems with 32-bit or
 * 64-bit pointers, respectively.
 */
#define PASSWORD_HASH_SHR		2

/*
 * Cracked password hash size, used while loading.
 */
#define CRACKED_HASH_LOG		16
#define CRACKED_HASH_SIZE		(1 << CRACKED_HASH_LOG)

/*
 * Buffered keys hash size, used for "single crack" mode.
 */
#if defined(_OPENMP) && DES_BS && !DES_BS_ASM
#define SINGLE_HASH_LOG			10
#else
#define SINGLE_HASH_LOG			7
#endif
#define SINGLE_HASH_SIZE		(1 << SINGLE_HASH_LOG)

/*
 * Minimum buffered keys hash size, used if min_keys_per_crypt is even less.
 */
#define SINGLE_HASH_MIN			8

/*
 * Shadow file entry hash table size, used by unshadow.
 */
#define SHADOW_HASH_LOG			18
#define SHADOW_HASH_SIZE		(1 << SHADOW_HASH_LOG)

/*
 * Hash and buffer sizes for unique.
 */
#define UNIQUE_HASH_LOG			20
#define UNIQUE_HASH_SIZE		(1 << UNIQUE_HASH_LOG)
#define UNIQUE_BUFFER_SIZE		0x4000000

/*
 * Maximum number of GECOS words per password to load.
 */
#define LDR_WORDS_MAX			0x10

/*
 * Maximum number of partial hash collisions in a db->password_hash[] bucket.
 * If this limit is hit, we print a warning and disable detection of duplicate
 * hashes (since it could be too slow).
 */
#define LDR_HASH_COLLISIONS_MAX		1000

/*
 * Maximum number of GECOS words to try in pairs.
 */
#define SINGLE_WORDS_PAIR_MAX		4

/*
 * Charset parameters.
 *
 * Please note that changes to these parameters make your build of John
 * incompatible with charset files generated with other builds.
 */
#define CHARSET_MIN			0x01
#define CHARSET_MAX			0xff
#define CHARSET_LENGTH			24

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
#define POT_BUFFER_SIZE			0x8000
#define LOG_BUFFER_SIZE			0x8000

/*
 * Buffer size for path names.
 */
#ifdef PATH_MAX
#define PATH_BUFFER_SIZE		PATH_MAX
#else
#define PATH_BUFFER_SIZE		0x400
#endif

#endif
