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

#include "list.h"
#include "loader.h"
#include "getopt.h"

/*
 * Core Option flags bitmasks (low 32 bits):
 */
/* An action requested */
#define FLG_ACTION			0x00000001
/* Password files specified */
#define FLG_PASSWD			0x00000002
/* An option supports password files */
#define FLG_PWD_SUP			0x00000004
/* An option requires password files */
#define FLG_PWD_REQ			(0x00000008 | FLG_PWD_SUP)
/* Some option that doesn't have its own flag is specified */
#define FLG_NONE			0x00000010
/* A cracking mode enabled */
#define FLG_CRACKING_CHK		0x00000020
#define FLG_CRACKING_SUP		0x00000040
#define FLG_CRACKING_SET \
	(FLG_CRACKING_CHK | FLG_CRACKING_SUP | FLG_ACTION | FLG_PWD_REQ)
/* Wordlist mode enabled, options.wordlist is set to the file name, or
 * we get it from john.conf */
#define FLG_WORDLIST_CHK		0x00000080
#define FLG_WORDLIST_SET		(FLG_WORDLIST_CHK | FLG_CRACKING_SET)
/* Wordlist mode enabled, reading from stdin */
#define FLG_STDIN_CHK			0x00000100
#define FLG_STDIN_SET			(FLG_STDIN_CHK | FLG_WORDLIST_SET)
/* Wordlist rules enabled */
#define FLG_RULES			0x00000200
/* "Single crack" mode enabled */
#define FLG_SINGLE_CHK			0x00000400
#define FLG_SINGLE_SET			(FLG_SINGLE_CHK | FLG_CRACKING_SET)
/* Incremental mode enabled */
#define FLG_INC_CHK			0x00000800
#define FLG_INC_SET			(FLG_INC_CHK | FLG_CRACKING_SET)
/* Mask mode enabled */
#define FLG_MASK_CHK			0x00001000
#define FLG_MASK_SET			(FLG_MASK_CHK | FLG_CRACKING_SET)
/* External mode or word filter enabled */
#define FLG_EXTERNAL_CHK		0x00002000
#define FLG_EXTERNAL_SET \
	(FLG_EXTERNAL_CHK | FLG_ACTION | FLG_CRACKING_SUP | FLG_PWD_SUP)
/* Batch cracker */
#define FLG_BATCH_CHK			0x00004000
#define FLG_BATCH_SET			(FLG_BATCH_CHK | FLG_CRACKING_SET)
/* Stdout mode */
#define FLG_STDOUT			0x00008000
/* Restoring an interrupted session */
#define FLG_RESTORE_CHK			0x00010000
#define FLG_RESTORE_SET			(FLG_RESTORE_CHK | FLG_ACTION)
/* A session name is set */
#define FLG_SESSION			0x00020000
/* Print status of a session */
#define FLG_STATUS_CHK			0x00040000
#define FLG_STATUS_SET			(FLG_STATUS_CHK | FLG_ACTION)
/* Make a charset */
#define FLG_MAKECHR_CHK			0x00100000
#define FLG_MAKECHR_SET \
	(FLG_MAKECHR_CHK | FLG_ACTION | FLG_PWD_SUP)
/* Show cracked passwords */
#define FLG_SHOW_CHK			0x00200000
#define FLG_SHOW_SET \
	(FLG_SHOW_CHK | FLG_ACTION | FLG_PWD_REQ)
/* Perform a benchmark */
#define FLG_TEST_CHK			0x00400000
#define FLG_TEST_SET \
	(FLG_TEST_CHK | FLG_CRACKING_SUP | FLG_ACTION)
/* Passwords per salt requested */
#define FLG_SALTS			0x01000000
/* Ciphertext format forced */
#define FLG_FORMAT			0x02000000
/* Memory saving enabled */
#define FLG_SAVEMEM			0x04000000
/* Node number(s) specified */
#define FLG_NODE			0x10000000
/* fork() requested, and process count specified */
#define FLG_FORK			0x20000000

/* Note that 0x80000000 is taken for OPT_REQ_PARAM, see getopt.h */

/*
 * Jumbo Options flags bitmasks (high 32 bits)
 *
 * Tip: For your private patches, pick first free from MSB. When
 * sharing your patch, pick first free from LSB of high 32 bits.
 */
/* .pot file used as wordlist, options.wordlist is set to the file name, or
 * we use the active .pot file */
#define FLG_LOOPBACK_CHK		0x0000000100000000ULL
#define FLG_LOOPBACK_SET	  \
	(FLG_LOOPBACK_CHK | FLG_WORDLIST_SET | FLG_CRACKING_SET | FLG_DUPESUPP)
/* pipe mode enabled, reading from stdin with rules support */
#define FLG_PIPE_CHK			0x0000000200000000ULL
#define FLG_PIPE_SET			(FLG_PIPE_CHK | FLG_WORDLIST_SET)
/* Dynamic load of foreign format module */
#define FLG_DYNFMT			0x0000000400000000ULL
/* Turn off logging */
#define FLG_NOLOG			0x0000000800000000ULL
/* Log to stderr */
#define FLG_LOG_STDERR			0x0000001000000000ULL
/* Markov mode enabled */
#define FLG_MKV_CHK			0x0000002000000000ULL
#define FLG_MKV_SET			(FLG_MKV_CHK | FLG_CRACKING_SET)
/* Emit a status line for every password cracked */
#define FLG_CRKSTAT			0x0000004000000000ULL
/* Wordlist dupe suppression */
#define FLG_DUPESUPP			0x0000008000000000ULL
/* Force scalar mode */
#define FLG_SCALAR			0x0000010000000000ULL
#define FLG_VECTOR			0x0000020000000000ULL
/* Reject printable binaries */
#define FLG_REJECT_PRINTABLE		0x0000040000000000ULL
/* Skip self tests */
#define FLG_NOTESTS			0x0000080000000000ULL
/* Regex cracking mode */
#define FLG_REGEX_CHK			0x0000100000000000ULL
#define FLG_REGEX_SET			(FLG_REGEX_CHK | FLG_CRACKING_SET)
/* Encodings. You can only give one of --intermediate-enc or --target-enc */
#define FLG_INPUT_ENC			0x0000200000000000ULL
#define FLG_SECOND_ENC			0x0000400000000000ULL
/* Old Jumbo options. They can do without the flags but options parsing
   would not catch duplicate options, leading to undefined behavior. */
#define FLG_POT				0x0000800000000000ULL
#define FLG_SUBFORMAT			0x0001000000000000ULL
#define FLG_MEM_FILE_SIZE		0x0002000000000000ULL
#define FLG_FIELDSEP			0x0004000000000000ULL
#define FLG_CONFIG			0x0008000000000000ULL
#define FLG_MKPC			0x0010000000000000ULL
#define FLG_MINLEN			0x0020000000000000ULL
#define FLG_MAXLEN			0x0040000000000000ULL
#define FLG_MAXRUN			0x0080000000000000ULL
#define FLG_PROGRESS			0x0100000000000000ULL
#define FLG_REGEN			0x0200000000000000ULL
#define FLG_BARE			0x0400000000000000ULL
#define FLG_VERBOSITY			0x0800000000000000ULL
#define FLG_PLATFORM			0x1000000000000000ULL
#define FLG_DEVICE			0x2000000000000000ULL

/* Tunable cost ranges requested */
#define FLG_COSTS			0x4000000000000000ULL

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

/* Ciphertext subformat name */
	char *subformat;

/* Wordlist file name */
	char *wordlist;

/* Incremental mode name or charset file name */
	char *charset;

/* Mask mode's mask */
	char *mask;

/* External mode or word filter name */
	char *external;

/* Markov stuff */
	char *mkv_param;
	char *mkv_stats;

/* Maximum plaintext length for stdout mode */
	int length;

/* Parallel processing options */
	char *node_str;
	unsigned int node_min, node_max, node_count, fork;

/* Configuration file name */
	char *config;

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

/* number of times fix_state_delay is called in wordfile.c before  any fseek()
   is done. */
	unsigned int max_fix_state_delay;

/* the wordlist rules section (default if none entered is Wordlist) */
	char *activewordlistrules;

/* the 'single' rules section (default if none entered is Single) */
	char *activesinglerules;

/* This is a 'special' flag.  It causes john to add 'extra' code to search for
 * some salted types, when we have only the hashes.  The only type supported is
 * PHPS (at this time.).  So PHPS will set this to a 1. OTherwise it will
 * always be zero.  LIKELY we will add the same type logic for the OSC
 * (mscommerse) type, which has only a 2 byte salt.  That will set this field
 * to be a 2.  If we add other types, then we will have other values which can
 * be assigned to this variable.  This var is set by the undocummented
 * --regen_lost_salts=#   */
	int regen_lost_salts;

#ifdef HAVE_DL
/* List of dll files to load for additional formats */
	struct list_main *fmt_dlls;
#endif

/* Requested max_keys_per_crypt (for testing purposes) */
	int force_maxkeys;

/* Requested MinLen (min plaintext_length) */
	int force_minlength;

/* Requested MaxLen (max plaintext_length) */
	int force_maxlength;

/* Graceful exit after this many seconds of cracking */
	int max_run_time;

/* Emit a status line every N seconds */
	int status_interval;

/* Resync pot file when saving */
	int reload_at_save;

/* Send a resync trigger (to others) when new cracks are written to pot */
	int reload_at_crack;

/* Pause/abort on trigger files */
	char *pause_file;
	char *abort_file;

/* Force dynamic format to always treat bare hashes as valid. If not set
   then dynamic format only uses bare hashes if -form=dynamic_xxx is used.
   If this is 'N', then original logic used.  If 'Y' or 'y' then we always
   use bare hashes as valid in dynamic. */
	char dynamic_bare_hashes_always_valid;

#ifdef HAVE_OPENCL
	char *ocl_platform;

/* Vector width of OpenCL kernel */
	unsigned int v_width;
#endif
#if defined(HAVE_OPENCL) || defined(HAVE_CUDA)
	struct list_main *gpu_devices;
#endif
/* -list=WHAT Get a config list (eg. a list of incremental modes available) */
	char *listconf;
/* Verbosity level, 1-5. Three is normal, lower is more quiet. */
	int verbosity;
/* Secure mode. Do not output, log or store cracked passwords. */
	int secure;
/* regular expression */
  char *regex;
};

extern struct options_main options;

/* "Persistant" options. Unlike the options struct above, this one is not
   reset by the children upon resuming a session. That behavior gave me
   gray hairs. */

/* In general, an encoding of 0 (CP_UNDEF) means no conversion and we will
   behave more or less like core John. */
struct pers_opts {
/* Currently initialized non-utf8 encoding */
	int unicode_cp;

/* Input encoding for word lists, and/or pot file clear-texts. */
	int input_enc;

/* True if encoding was set from john.conf defaults. */
	int default_enc;
	int default_target_enc;

/* Output encoding. This must match what the hash origin used. An exception
   is UTF-16 formats like NT, which can use any codepage (or UTF-8) if FMT_UTF8
   is set, or ISO-8859-1 only if FMT_UTF8 is false. */
	int target_enc;

/* If different from target_enc, this is an intermediate encoding only
   used within rules processing. This is only applicable for the case
   "UTF-8 -> rules -> UTF-8". Since the rules engine can't do proper case
   conversion etc. in UTF-8, we can pick this intermediate encoding (use
   one that matches most input) but the double conversions may come with
   a speed penalty. */
	int intermediate_enc;

/* Store UTF-8 in pot file. Default is no conversion. */
	int store_utf8;

/* Show/log/report UTF-8. Default is no conversion. */
	int report_utf8;
};

extern struct pers_opts pers_opts;

/*
 * Initializes the options structure.
 */
extern void opt_init(char *name, int argc, char **argv, int show_usage);

/*
 * Prints the "hidden" options usage
 */
extern void opt_print_hidden_usage(void);

#endif
