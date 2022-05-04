/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-98,2003,2006,2013 by Solar Designer
 *
 * ...with changes in the jumbo patch, by JimF and magnum (and various others?)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

/*
 * John's command line options definition.
 */

#ifndef _JOHN_OPTIONS_H
#define _JOHN_OPTIONS_H

#if AC_BUILT
#include "autoconfig.h"
#endif

#include "list.h"
#include "loader.h"
#include "getopt.h"
#include "john_mpi.h"

/* An action requested */
#define FLG_ACTION			0x0000000000000001ULL
/* Password files specified */
#define FLG_PASSWD			0x0000000000000002ULL
/* An option supports password files */
#define FLG_PWD_SUP			0x0000000000000004ULL
/* An option requires password files */
#define FLG_PWD_REQ			(0x0000000000000008ULL | FLG_PWD_SUP)
/*
 * getopt.h defines FLG_MULTI to 0x0000000000000010
 */
/* A cracking mode enabled */
#define FLG_CRACKING_CHK		0x0000000000000020ULL
#define FLG_CRACKING_SUP		0x0000000000000040ULL
#define FLG_CRACKING_SET \
	(FLG_CRACKING_CHK | FLG_CRACKING_SUP | FLG_ACTION | FLG_PWD_REQ)
/* Wordlist mode enabled, options.wordlist is set to the file name, or
 * we get it from john.conf */
#define FLG_WORDLIST_CHK		0x0000000000000080ULL
#define FLG_WORDLIST_SET \
	(FLG_WORDLIST_CHK | FLG_CRACKING_SET | FLG_RULES_ALLOW)
/* Wordlist mode enabled, reading from stdin */
#define FLG_STDIN_CHK			0x0000000000000100ULL
#define FLG_STDIN_SET			(FLG_STDIN_CHK | FLG_WORDLIST_SET)
/* Wordlist rules enabled */
#define FLG_RULES_CHK			0x0000000000000200ULL
#define FLG_RULES_SET			(FLG_RULES_CHK | FLG_RULES_IN_USE)
/* "Single crack" mode enabled */
#define FLG_SINGLE_CHK			0x0000000000000400ULL
#define FLG_SINGLE_SET			(FLG_SINGLE_CHK | FLG_CRACKING_SET)
/* Incremental mode enabled */
#define FLG_INC_CHK			0x0000000000000800ULL
#define FLG_INC_SET			(FLG_INC_CHK | FLG_CRACKING_SET)
/* Mask mode enabled (might be hybrid) */
#define FLG_MASK_CHK			0x0000000000001000ULL
#define FLG_MASK_SET \
	(FLG_MASK_CHK | FLG_ACTION | FLG_CRACKING_SUP | FLG_PWD_SUP)
/* External mode or word filter enabled */
#define FLG_EXTERNAL_CHK		0x0000000000002000ULL
#define FLG_EXTERNAL_SET \
	(FLG_EXTERNAL_CHK | FLG_ACTION | FLG_CRACKING_SUP | FLG_PWD_SUP)
/* Batch cracker */
#define FLG_BATCH_CHK			0x0000000000004000ULL
#define FLG_BATCH_SET			(FLG_BATCH_CHK | FLG_CRACKING_SET)
/* Stdout mode */
#define FLG_STDOUT			0x0000000000008000ULL
/* Restoring an interrupted session */
#define FLG_RESTORE_CHK			0x0000000000010000ULL
#define FLG_RESTORE_SET			(FLG_RESTORE_CHK | FLG_ACTION)
/* A session name is set */
#define FLG_SESSION			0x0000000000020000ULL
/* Print status of a session */
#define FLG_STATUS_CHK			0x0000000000040000ULL
#define FLG_STATUS_SET			(FLG_STATUS_CHK | FLG_ACTION)
/* Make a charset */
#define FLG_MAKECHR_CHK			0x0000000000080000ULL
#define FLG_MAKECHR_SET \
	(FLG_MAKECHR_CHK | FLG_ACTION | FLG_PWD_SUP)
/* Show cracked passwords */
#define FLG_SHOW_CHK			0x0000000000100000
#define FLG_SHOW_SET \
	(FLG_SHOW_CHK | FLG_ACTION | FLG_PWD_REQ)
/* Perform a benchmark */
#define FLG_TEST_CHK			0x0000000000200000ULL
#define FLG_TEST_SET \
	(FLG_TEST_CHK | FLG_CRACKING_SUP | FLG_ACTION)
#ifdef HAVE_FUZZ
/* Perform a fuzzing */
#define FLG_FUZZ_CHK			0x0000000000400000ULL
#define FLG_FUZZ_SET \
	(FLG_FUZZ_CHK | FLG_CRACKING_SUP | FLG_ACTION)
/* Dump fuzzed hashes */
#define FLG_FUZZ_DUMP_CHK		0x0000000000800000ULL
#define FLG_FUZZ_DUMP_SET \
	(FLG_FUZZ_DUMP_CHK | FLG_CRACKING_SUP | FLG_ACTION)
#endif
/* Ciphertext format forced */
#define FLG_FORMAT			0x0000000001000000ULL
/* Memory saving enabled */
#define FLG_SAVEMEM			0x0000000002000000ULL
/* fork() requested, and process count specified */
#define FLG_FORK			0x0000000004000000ULL

/* .pot file used as wordlist, options.wordlist is set to the file name, or
 * we use the active .pot file */
#define FLG_LOOPBACK_CHK		0x0000000008000000ULL
#define FLG_LOOPBACK_SET	  \
	(FLG_LOOPBACK_CHK | FLG_WORDLIST_SET | FLG_CRACKING_SET)
/* pipe mode enabled, reading from stdin with rules support */
#define FLG_PIPE_CHK			0x0000000010000000ULL
#define FLG_PIPE_SET			(FLG_PIPE_CHK | FLG_WORDLIST_SET)

/*
 * Note that 0x0000000020000000 is taken for OPT_BOOL,
 *           0x0000000040000000 is taken for OPT_TRISTATE, and
 *           0x0000000080000000 is taken for OPT_REQ_PARAM, see getopt.h
 *
 * These are available for using!
 *		0x0000100000000000ULL
 *		0x0000200000000000ULL
 */

/* Markov mode enabled */
#define FLG_MKV_CHK			0x0000000400000000ULL
#define FLG_MKV_SET			(FLG_MKV_CHK | FLG_CRACKING_SET)
/* Wordlist dupe suppression */
#define FLG_DUPESUPP			0x0000000800000000ULL
/* Force scalar mode */
#define FLG_SCALAR			0x0000001000000000ULL
#define FLG_VECTOR			0x0000002000000000ULL
/* Reject printable binaries */
#define FLG_REJECT_PRINTABLE		0x0000004000000000ULL
/* Skip self tests */
#define FLG_NOTESTS			0x0000008000000000ULL
/* Regex cracking mode */
#define FLG_REGEX_CHK			0x0000010000000000ULL
#define FLG_REGEX_SET	  \
	(FLG_REGEX_CHK | FLG_ACTION | FLG_CRACKING_SUP | FLG_PWD_SUP)
/* Encodings. You can only give one of --internal-enc or --target-enc */
#define FLG_INPUT_ENC			0x0000020000000000ULL
#define FLG_SECOND_ENC			0x0000040000000000ULL
/* --verbosity */
#define FLG_VERBOSITY			0x0000080000000000ULL
/* Loops self-test forever */
#define FLG_LOOPTEST_CHK		0x0000400000000000ULL
#define FLG_LOOPTEST_SET		(FLG_LOOPTEST_CHK | FLG_TEST_SET)
/* Mask mode is stacked */
#define FLG_MASK_STACKED		0x0000800000000000ULL
/* Stacking modes */
#define FLG_STACKING			(FLG_MASK_CHK | FLG_REGEX_CHK)
/* Any stacking mode is active */
#define FLG_STACKED			(FLG_MASK_STACKED | FLG_REGEX_STACKED)
/* PRINCE mode enabled, options.wordlist is set to the file name, or
 * we get it from john.conf */
#define FLG_PRINCE_CHK			0x0001000000000000ULL
#define FLG_PRINCE_SET \
	(FLG_PRINCE_CHK | FLG_CRACKING_SET | FLG_RULES_ALLOW)
#define FLG_PRINCE_DIST			0x0002000000000000ULL
#define FLG_PRINCE_KEYSPACE		0x0004000000000000ULL
#define FLG_PRINCE_CASE_PERMUTE		0x0008000000000000ULL
#define FLG_PRINCE_LOOPBACK		0x0010000000000000ULL
#define FLG_PRINCE_MMAP			0x0020000000000000ULL
#define FLG_RULES_ALLOW			0x0040000000000000ULL
#define FLG_REGEX_STACKED		0x0080000000000000ULL
/* Rain cracking mode */
#define FLG_RAIN_CHK			0x0100000000000000ULL
#define FLG_RAIN_SET			(FLG_RAIN_CHK | FLG_CRACKING_SET)
#define FLG_RULES_STACK_CHK		0x0200000000000000ULL
#define FLG_RULES_STACK_SET		(FLG_RULES_STACK_CHK | FLG_RULES_IN_USE)
#define FLG_RULES_IN_USE		0x0400000000000000ULL
/* Ignore NOP rules */
#define FLG_RULE_SKIP_NOP		0x0800000000000000ULL
#define FLG_NO_MASK_BENCH		0x1000000000000000ULL
/* Configure terminal for reading keystrokes even if we're not the foreground process */
#define FLG_FORCE_TTY			0x2000000000000000ULL
/* Turn off logging */
#define FLG_NOLOG				0x4000000000000000ULL

/*
 * Macro for getting correct node number regardless of if MPI or not
 */
#if HAVE_MPI
#define NODE (mpi_p > 1 ? mpi_id + 1 : options.node_min)
#else
#define NODE options.node_min
#endif

/*
 * Macro for getting correct total processes regardless of if MPI or fork
 */
#if HAVE_MPI
#define NODES (mpi_p > 1 ? mpi_p : options.fork ? options.fork : 1)
#else
#define NODES (options.fork ? options.fork : 1)
#endif

/*
 * Structure with option flags and all the parameters.
 */
struct options_main {
/* Option flags */
	opt_flags flags;

/* Password files */
	struct list_main *passwd;

/* Password file loader options */
	struct db_options loader;

/* Session name */
	char *session;

/* Ciphertext format name */
	char *format;

/* Ciphertext format list, as a comma-separated string */
	char *format_list;

/* Wordlist file name */
	char *wordlist;

/* Incremental mode name or charset file name */
	const char *charset;

/* External mode or word filter name */
	char *external;

/* Maximum plaintext length for stdout mode */
	int length;

/* Parallel processing options */
	char *node_str;
	unsigned int node_min, node_max, node_count, fork;

/*
 * ---- Jumbo options below this point ----
 * Do NOT place any new Jumbo stuff above 'subformat'. It's used to
 * calculate offset for a memset at resuming a session.
 */

/* Ciphertext subformat name */
	char *subformat;

/* Single mode global seed word(s) (--single-seed) */
	char *seed_word;

/* Single mode global seed wordlist file name(s) (--single-wordlist) */
	struct list_main *seed_files;

/* Single mode wordlist per username (--single-user-seed) */
	char *seed_per_user;

/*
 * Override words_pair_max (--single-pair-max=N tri-state). The actual negated
 * version is --no-single-pair-max but we list it as --no-single-pair to avoid
 * confusion.
 */
	int single_pair_max;
/*
 * --[no-]single-retest-guess tri-state option (vs. deprecated config option)
 */
	char *single_retest_guess;

/*
 * --[no-]loader-dupe-check option tri-state option (vs. deprecated config option)
 */
	int loader_dupecheck;

/* Configuration file name */
	char *config;

/* Markov stuff */
	char *mkv_param;
	char *mkv_stats;

#ifdef HAVE_FUZZ
/* Fuzz dictionary file name */
	char *fuzz_dic;

/* Fuzz dump hashes between from and to */
	char *fuzz_dump;
#endif

/* Mask mode's requested mask (as given) */
	char *mask;

/* Mask mode's effective mask (as used, may be default from john.conf etc.) */
	char *eff_mask;

/* Can't use HAVE_WINDOWS_H here so the below need to be maintained */
#if defined (_MSC_VER) || defined (__MINGW32__) || defined (__CYGWIN32__)
/* if built for Win32, then the pipe/stdin is VERY slow.  We allow special
 * processing to use the pipe command, but in a -pipe=sharedmemoryfilename
 * so that the producer app, and JtR can be written to work properly with
 * named shared memory, which is MUCH faster than using a pipe to xfer data
 * between the 2 apps. */
	char *sharedmemoryfilename;
#endif

/* Maximum size of a wordlist file to be 'preloaded' into memory  */
	size_t max_wordfile_memory;

/* number of times fix_state_delay is called in wordlist.c before  any fseek()
   is done. */
	unsigned int max_fix_state_delay;

/* In general, an encoding of 0 (CP_UNDEF) means no conversion and we will
   behave more or less like core John. */

/* Currently initialized non-utf8 encoding */
	int unicode_cp;

/* Input encoding for word lists, and/or pot file clear-texts. */
	int input_enc;

/* Replacement character for "EmulateBrokenEncoding" feature. */
	unsigned char replacement_character;

/* True if encoding was set from john.conf as opposed to command line. */
	int default_enc;
	int default_target_enc;

/* Output encoding. This must match what the hash origin used. An exception
   is UTF-16 formats like NT, which can use any codepage (or UTF-8) if FMT_ENC
   is set, or ISO-8859-1 only if FMT_ENC is false. */
	int target_enc;

/* Terminal encoding, as parsed from LC_ALL or LC_CTYPE */
	int terminal_enc;

/* If different from target_enc, this is an intermediate encoding only
   used within rules/mask processing. This is only applicable for the case
   "UTF-8 -> rules -> UTF-8" or "mask -> UTF-8". Since the rules engine can't
   do proper case conversion etc. in UTF-8, we can pick this intermediate
   encoding (use one that matches most input) but the double conversions may
   come with a speed penalty. */
	int internal_cp;

/* Store UTF-8 in pot file. Default is no conversion. */
	int store_utf8;

/* Show/log/report UTF-8. Default is no conversion. */
	int report_utf8;

/* Pot file used (default is $JOHN/john.pot) */
	char *activepot;

/* the wordlist rules section (default if none entered is Wordlist) */
	const char *activewordlistrules;

/* the 'single' rules section (default if none entered is Single) */
	const char *activesinglerules;

/* Stacked rules applied within cracker.c for any mode */
	char *rule_stack;

/* Salt brute-force */
	int regen_lost_salts;

/* Requested max_keys_per_crypt (for testing purposes) */
	int force_maxkeys;

/* Requested min/max plaintext_length. if options weren't used, req_min == -1
 * and/or req_maxlength == 0. req_length is used for both or 0 if not used */
	int req_minlength, req_maxlength, req_length;

/* Effective min/max plaintext_length. Always set. If hybrid mask is used,
 * mask_add_len is subtracted from them so parents should use these as-is */
	int eff_minlength, eff_maxlength;

/* Forced MaxLen (if set, we will reject longer candidates unless FMT_TRUNC) */
	int force_maxlength;

/*
 * Graceful exit after this many seconds of cracking. If the number is
 * negative, we exit after that many seconds of not cracking anything.
 */
	int max_run_time;

/*
 * Graceful exit after this many candidates tried. If the number is
 * negative, we reset the count on any successful crack.
 */
	long long max_cands;

/* Emit a status line every N seconds */
	int status_interval;

/* Resync pot file when saving */
	int reload_at_save;

/* Send a resync trigger (to others) when new cracks are written to pot */
	int reload_at_crack;

/* Pause/abort on trigger files */
	const char *pause_file;
	const char *abort_file;

/* Force dynamic format to always treat bare hashes as valid. If not set
   then dynamic format only uses bare hashes if -form=dynamic_xxx is used.
   If this is 'N', then original logic used.  If 'Y' or 'y' then we always
   use bare hashes as valid in dynamic. */
	char dynamic_bare_hashes_always_valid;

#ifdef HAVE_OPENCL
/* Vector width of OpenCL kernel */
	unsigned int v_width;

/* GPU Worksizes */
	size_t lws, gws;
#endif
#if defined(HAVE_OPENCL) || defined(HAVE_ZTEX)
/* Allow to set and select OpenCL device(s) or ztex boards */
	struct list_main *acc_devices;
#endif
/* -list=WHAT Get a config list (eg. a list of incremental modes available) */
	char *listconf;
/* Verbosity level, 1-5. Three is normal for jumbo, four is "legacy". */
	int verbosity;
/* Secure mode. Do not output, log or store cracked passwords. */
	int secure;
/* Mode that appended the uid to the user name (on display) */
	int show_uid_in_cracks;
/* regular expression */
	char *regex;
/* Custom masks */
	char *custom_mask[MAX_NUM_CUST_PLHDR];
/* Tune options */
	char *tune;
/* Incremental CharCount override */
	int charcount;
/* --[no-]keep-guessing tri-state option (vs. format's FMT_NOT_EXACT) */
	int keep_guessing;
/* --log-stderr */
	int log_stderr;
/* Emit a status line for every password cracked */
	int crack_status;
/* Inc2 full charsets */
	char *posfreq_full;
/* --catch-up=oldsession */
	char *catchup;
#if defined(HAVE_OPENCL) || defined(HAVE_ZTEX)
/* --mask-internal-target=N */
	int req_int_cand_target;
#endif
/* --dupe-suppression[=SIZE] */
	int suppressor_size;
};

extern struct options_main options;

/*
 * Initializes the options structure.
 */
extern void opt_init(char *name, int argc, char **argv);
extern void opt_usage();

#endif
