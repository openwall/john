/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2022 by Solar Designer
 *
 * ...with changes in the jumbo patch, by JimF and magnum (and various others?)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#define NEED_OS_FORK
#undef _GNU_SOURCE
#define _GNU_SOURCE 1 /* for strcasestr in legacy builds */

#include "os.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

#include "arch.h"
#include "misc.h"
#include "params.h"
#include "memory.h"
#include "list.h"
#include "loader.h"
#include "logger.h"
#include "status.h"
#include "recovery.h"
#include "options.h"
#include "bench.h"
#include "external.h"
#include "john.h"
#include "dynamic.h"
#include "unicode.h"
#include "fake_salts.h"
#include "path.h"
#include "regex.h"
#include "john_mpi.h"
#ifdef HAVE_MPI
#define _PER_NODE "per node "
#else
#define _PER_NODE ""
#endif
#include "opencl_common.h"
#if HAVE_LIBGMP || HAVE_INT128 || HAVE___INT128 || HAVE___INT128_T
#include "prince.h"
#endif
#include "version.h"
#include "listconf.h" /* must be included after version.h and misc.h */
#include "jumbo.h"

struct options_main options;
static char *field_sep_char_str, *show_uncracked_str, *salts_str;
static char *encoding_str, *target_enc_str, *internal_cp_str;
static char *costs_str;

/* Common req_clr for use with any options using FLG_ONCE or FLG_MULTI */
#define USUAL_REQ_CLR (FLG_STATUS_CHK | FLG_RESTORE_CHK)

/* Common req_clr for --test, --test-full and --stress-test */
#define TEST_REQ_CLR (~FLG_TEST_SET & ~FLG_FORMAT & ~FLG_SAVEMEM & ~FLG_MASK_CHK & ~FLG_NO_MASK_BENCH & \
                      ~FLG_VERBOSITY & ~FLG_INPUT_ENC & ~FLG_SECOND_ENC & ~GETOPT_FLAGS & ~FLG_NOTESTS & \
                      ~FLG_SCALAR & ~FLG_VECTOR)

static struct opt_entry opt_list[] = {
	{"", FLG_PASSWD, 0, 0, 0, OPT_FMT_ADD_LIST, &options.passwd},
	{"single", FLG_SINGLE_SET, FLG_CRACKING_CHK, 0, FLG_STACKING, OPT_FMT_STR_ALLOC, &options.activesinglerules},
/*
 * single-retest-guess=<bool> is deprecated, drop support after releasing 1.9.0-Jumbo-2
 * and instead use format NULL and change options.single_retest_guess to an int
 */
	{"single-retest-guess", FLG_ONCE, 0, FLG_SINGLE_CHK, OPT_TRISTATE, OPT_FMT_STR_ALLOC, &options.single_retest_guess},
	{"single-seed", FLG_ONCE, 0, FLG_SINGLE_CHK, OPT_REQ_PARAM, OPT_FMT_STR_ALLOC, &options.seed_word},
	{"single-wordlist", FLG_MULTI, 0, FLG_SINGLE_CHK, OPT_REQ_PARAM, OPT_FMT_ADD_LIST_MULTI, &options.seed_files},
	{"single-user-seed", FLG_ONCE, 0, FLG_SINGLE_CHK, OPT_REQ_PARAM, OPT_FMT_STR_ALLOC, &options.seed_per_user},
	{"single-pair-max", FLG_ONCE, 0, FLG_SINGLE_CHK, OPT_TRISTATE | OPT_REQ_PARAM, "%d", &options.single_pair_max},
	{"wordlist", FLG_WORDLIST_SET, FLG_CRACKING_CHK, 0, 0, OPT_FMT_STR_ALLOC, &options.wordlist},
	{"loopback", FLG_LOOPBACK_SET, FLG_CRACKING_CHK, 0, 0, OPT_FMT_STR_ALLOC, &options.wordlist},
#if HAVE_LIBGMP || HAVE_INT128 || HAVE___INT128 || HAVE___INT128_T
	{"prince", FLG_PRINCE_SET, FLG_CRACKING_CHK, 0, 0, OPT_FMT_STR_ALLOC, &options.wordlist},
	{"prince-loopback", FLG_PRINCE_SET | FLG_PRINCE_LOOPBACK | FLG_DUPESUPP, FLG_CRACKING_CHK, 0, 0, OPT_FMT_STR_ALLOC, &options.wordlist},
	{"prince-elem-cnt-min", FLG_ONCE, 0, FLG_PRINCE_CHK, OPT_REQ_PARAM, "%d", &prince_elem_cnt_min},
	{"prince-elem-cnt-max", FLG_ONCE, 0, FLG_PRINCE_CHK, OPT_REQ_PARAM, "%d", &prince_elem_cnt_max},
	{"prince-skip", FLG_ONCE, 0, FLG_PRINCE_CHK, OPT_REQ_PARAM, OPT_FMT_STR_ALLOC, &prince_skip_str},
	{"prince-limit", FLG_ONCE, 0, FLG_PRINCE_CHK, OPT_REQ_PARAM, OPT_FMT_STR_ALLOC, &prince_limit_str},
	{"prince-wl-dist-len", FLG_PRINCE_DIST, 0, FLG_PRINCE_CHK, 0},
	{"prince-wl-max", FLG_ONCE, 0, FLG_PRINCE_CHK, OPT_REQ_PARAM, "%d", &prince_wl_max},
	{"prince-case-permute", FLG_PRINCE_CASE_PERMUTE, 0, FLG_PRINCE_CHK, FLG_PRINCE_MMAP},
	{"prince-keyspace", FLG_PRINCE_KEYSPACE | FLG_STDOUT, 0, FLG_PRINCE_CHK, FLG_RULES_IN_USE},
	{"prince-mmap", FLG_PRINCE_MMAP, 0, FLG_PRINCE_CHK, FLG_PRINCE_CASE_PERMUTE},
#endif
	/* -enc is an alias for -input-enc for logic reasons, never deprecated */
	{"encoding", FLG_INPUT_ENC, FLG_INPUT_ENC, 0, OPT_REQ_PARAM, OPT_FMT_STR_ALLOC, &encoding_str},
	{"input-encoding", FLG_INPUT_ENC, FLG_INPUT_ENC, 0, OPT_REQ_PARAM, OPT_FMT_STR_ALLOC, &encoding_str},
	{"internal-codepage", FLG_SECOND_ENC, FLG_SECOND_ENC, 0, OPT_REQ_PARAM, OPT_FMT_STR_ALLOC, &internal_cp_str},
	/* -internal-encoding is a deprecated alias for -internal-codepage. Remove after releasing 1.9.0-Jumbo-2 */
	{"internal-encoding", FLG_SECOND_ENC, FLG_SECOND_ENC, 0, OPT_REQ_PARAM, OPT_FMT_STR_ALLOC, &internal_cp_str},
	{"target-encoding", FLG_SECOND_ENC, FLG_SECOND_ENC, 0, OPT_REQ_PARAM, OPT_FMT_STR_ALLOC, &target_enc_str},
	{"stdin", FLG_STDIN_SET, FLG_CRACKING_CHK},
#if HAVE_WINDOWS_H
	{"pipe", FLG_PIPE_SET, FLG_CRACKING_CHK, 0, 0, OPT_FMT_STR_ALLOC, &options.sharedmemoryfilename},
#else
	{"pipe", FLG_PIPE_SET, FLG_CRACKING_CHK},
#endif
	{"rules", FLG_RULES_SET, FLG_RULES_CHK, FLG_RULES_ALLOW, FLG_STDIN_CHK, OPT_FMT_STR_ALLOC, &options.activewordlistrules},
	{"rules-stack", FLG_RULES_STACK_SET, FLG_RULES_STACK_CHK, 0, OPT_REQ_PARAM, OPT_FMT_STR_ALLOC, &options.rule_stack},
	{"rules-skip-nop", FLG_RULE_SKIP_NOP, FLG_RULE_SKIP_NOP, FLG_RULES_IN_USE},
	{"incremental", FLG_INC_SET, FLG_CRACKING_CHK, 0, 0, OPT_FMT_STR_ALLOC, &options.charset},
	{"incremental-charcount", FLG_ONCE, 0, FLG_INC_CHK, OPT_REQ_PARAM, "%u", &options.charcount},
	{"rain", FLG_RAIN_SET, FLG_CRACKING_CHK, 0, 0},
	{"no-mask", FLG_NO_MASK_BENCH, FLG_NO_MASK_BENCH, FLG_TEST_CHK, FLG_MASK_CHK},
	{"mask", FLG_MASK_SET, FLG_MASK_CHK, 0, 0, OPT_FMT_STR_ALLOC, &options.mask},
	{"1", FLG_ONCE, 0, FLG_MASK_CHK, OPT_REQ_PARAM, OPT_FMT_STR_ALLOC, &options.custom_mask[0]},
	{"2", FLG_ONCE, 0, FLG_MASK_CHK, OPT_REQ_PARAM, OPT_FMT_STR_ALLOC, &options.custom_mask[1]},
	{"3", FLG_ONCE, 0, FLG_MASK_CHK, OPT_REQ_PARAM, OPT_FMT_STR_ALLOC, &options.custom_mask[2]},
	{"4", FLG_ONCE, 0, FLG_MASK_CHK, OPT_REQ_PARAM, OPT_FMT_STR_ALLOC, &options.custom_mask[3]},
	{"5", FLG_ONCE, 0, FLG_MASK_CHK, OPT_REQ_PARAM, OPT_FMT_STR_ALLOC, &options.custom_mask[4]},
	{"6", FLG_ONCE, 0, FLG_MASK_CHK, OPT_REQ_PARAM, OPT_FMT_STR_ALLOC, &options.custom_mask[5]},
	{"7", FLG_ONCE, 0, FLG_MASK_CHK, OPT_REQ_PARAM, OPT_FMT_STR_ALLOC, &options.custom_mask[6]},
	{"8", FLG_ONCE, 0, FLG_MASK_CHK, OPT_REQ_PARAM, OPT_FMT_STR_ALLOC, &options.custom_mask[7]},
	{"9", FLG_ONCE, 0, FLG_MASK_CHK, OPT_REQ_PARAM, OPT_FMT_STR_ALLOC, &options.custom_mask[8]},
	{"markov", FLG_MKV_SET, FLG_CRACKING_CHK, 0, 0, OPT_FMT_STR_ALLOC, &options.mkv_param},
	{"mkv-stats", FLG_ONCE, 0, FLG_MKV_CHK, OPT_REQ_PARAM, OPT_FMT_STR_ALLOC, &options.mkv_stats},
	{"external", FLG_EXTERNAL_SET, FLG_EXTERNAL_CHK, 0, OPT_REQ_PARAM, OPT_FMT_STR_ALLOC, &options.external},
#if HAVE_REXGEN
	{"regex", FLG_REGEX_SET, FLG_REGEX_CHK, 0, OPT_REQ_PARAM, OPT_FMT_STR_ALLOC, &options.regex},
#endif
	{"stdout", FLG_STDOUT, FLG_STDOUT, FLG_CRACKING_SUP, FLG_SINGLE_CHK | FLG_BATCH_CHK, "%u", &options.length},
	{"restore", FLG_RESTORE_SET, FLG_RESTORE_CHK, 0, ~FLG_RESTORE_SET & ~GETOPT_FLAGS, OPT_FMT_STR_ALLOC, &options.session},
	{"session", FLG_SESSION, FLG_SESSION, FLG_CRACKING_SUP, OPT_REQ_PARAM, OPT_FMT_STR_ALLOC, &options.session},
	{"catch-up", FLG_ONCE, 0, 0, OPT_REQ_PARAM, OPT_FMT_STR_ALLOC, &options.catchup},
	{"status", FLG_STATUS_SET, FLG_STATUS_CHK, 0, ~FLG_STATUS_SET & ~GETOPT_FLAGS, OPT_FMT_STR_ALLOC, &options.session},
	{"make-charset", FLG_MAKECHR_SET, FLG_MAKECHR_CHK, 0, FLG_CRACKING_CHK | FLG_SESSION | OPT_REQ_PARAM, OPT_FMT_STR_ALLOC, &options.charset},
	{"show", FLG_SHOW_SET, FLG_SHOW_CHK, 0, FLG_CRACKING_SUP | FLG_MAKECHR_CHK, OPT_FMT_STR_ALLOC, &show_uncracked_str},
	{"test", FLG_TEST_SET, FLG_TEST_CHK, 0, TEST_REQ_CLR, "%d", &benchmark_time},
	{"test-full", FLG_TEST_SET, FLG_TEST_CHK, 0, TEST_REQ_CLR | OPT_REQ_PARAM, "%d", &benchmark_level},
	{"stress-test", FLG_LOOPTEST_SET, FLG_LOOPTEST_CHK, 0, ~FLG_LOOPTEST_SET & TEST_REQ_CLR, "%d", &benchmark_time},
#ifdef HAVE_FUZZ
	{"fuzz", FLG_FUZZ_SET, FLG_FUZZ_CHK, 0, ~FLG_FUZZ_DUMP_SET & ~FLG_FUZZ_SET & ~FLG_FORMAT & ~FLG_SAVEMEM & ~FLG_NOLOG & ~GETOPT_FLAGS, OPT_FMT_STR_ALLOC, &options.fuzz_dic},
	{"fuzz-dump", FLG_FUZZ_DUMP_SET, FLG_FUZZ_DUMP_CHK, 0, ~FLG_FUZZ_SET & ~FLG_FUZZ_DUMP_SET & ~FLG_FORMAT & ~FLG_SAVEMEM & ~FLG_NOLOG & ~GETOPT_FLAGS, OPT_FMT_STR_ALLOC, &options.fuzz_dump},
#endif
	{"users", FLG_MULTI, 0, FLG_PASSWD, OPT_REQ_PARAM, OPT_FMT_ADD_LIST_MULTI, &options.loader.users},
	{"groups", FLG_MULTI, 0, FLG_PASSWD, OPT_REQ_PARAM, OPT_FMT_ADD_LIST_MULTI, &options.loader.groups},
	{"shells", FLG_MULTI, 0, FLG_PASSWD, OPT_REQ_PARAM, OPT_FMT_ADD_LIST_MULTI, &options.loader.shells},
	{"salts", FLG_ONCE, 0, FLG_PASSWD, OPT_REQ_PARAM, OPT_FMT_STR_ALLOC, &salts_str},
	{"save-memory", FLG_SAVEMEM, FLG_SAVEMEM, 0, OPT_REQ_PARAM, "%u", &mem_saving_level},
	{"node", FLG_ONCE, 0, FLG_CRACKING_CHK, OPT_REQ_PARAM, OPT_FMT_STR_ALLOC, &options.node_str},
#if OS_FORK
	{"fork", FLG_FORK, FLG_FORK, FLG_CRACKING_CHK, FLG_STDIN_CHK | FLG_STDOUT | FLG_PIPE_CHK | OPT_REQ_PARAM, "%u", &options.fork},
#endif
	{"pot", FLG_ONCE, 0, FLG_PWD_SUP, OPT_REQ_PARAM, OPT_FMT_STR_ALLOC, &options.activepot},
	{"format", FLG_FORMAT, FLG_FORMAT, 0, FLG_STDOUT | OPT_REQ_PARAM, OPT_FMT_STR_ALLOC, &options.format},
	{"subformat", FLG_ONCE, 0, 0, USUAL_REQ_CLR | FLG_STDOUT | OPT_REQ_PARAM, OPT_FMT_STR_ALLOC, &options.subformat},
	{"list", FLG_ONCE, 0, 0, USUAL_REQ_CLR | FLG_STDOUT | OPT_REQ_PARAM, OPT_FMT_STR_ALLOC, &options.listconf},
	{"mem-file-size", FLG_ONCE, 0, FLG_WORDLIST_CHK, FLG_STDIN_CHK | FLG_PIPE_CHK | OPT_REQ_PARAM, Zu, &options.max_wordfile_memory},
	{"dupe-suppression", FLG_DUPESUPP, FLG_DUPESUPP, FLG_RULES_ALLOW, 0, "%d", &options.suppressor_size},
/*
 * --fix-state-delay=N is deprecated and ignored, drop support after releasing 1.9.0-Jumbo-2
 */
	{"fix-state-delay", FLG_ONCE, 0, FLG_CRACKING_CHK, OPT_REQ_PARAM, "%u", &options.max_fix_state_delay},
	{"field-separator-char", FLG_ONCE, 0, FLG_PWD_SUP, OPT_REQ_PARAM, OPT_FMT_STR_ALLOC, &field_sep_char_str},
	{"config", FLG_ONCE, 0, 0, USUAL_REQ_CLR | OPT_REQ_PARAM, OPT_FMT_STR_ALLOC, &options.config},
	{"loader-dupe-check", FLG_ONCE, 0, FLG_CRACKING_CHK, OPT_TRISTATE, NULL, &options.loader_dupecheck},
	{"no-log", FLG_NOLOG, FLG_NOLOG, 0, FLG_TEST_CHK},
	{"log-stderr", FLG_ONCE, 0, 0, USUAL_REQ_CLR | OPT_BOOL, NULL, &options.log_stderr},
	{"crack-status", FLG_ONCE, 0, FLG_CRACKING_CHK, OPT_TRISTATE, NULL, &options.crack_status},
	{"mkpc", FLG_ONCE, 0, FLG_CRACKING_CHK, OPT_REQ_PARAM, "%d", &options.force_maxkeys},
	{"min-length", FLG_ONCE, 0, FLG_CRACKING_CHK, OPT_REQ_PARAM, "%u", &options.req_minlength},
	{"max-length", FLG_ONCE, 0, FLG_CRACKING_CHK, OPT_REQ_PARAM, "%u", &options.req_maxlength},
	{"length", FLG_ONCE, 0, FLG_CRACKING_CHK, OPT_REQ_PARAM, "%u", &options.req_length},
	{"max-candidates", FLG_ONCE, 0, FLG_CRACKING_CHK, USUAL_REQ_CLR | OPT_REQ_PARAM, "%lld", &options.max_cands},
	{"max-run-time", FLG_ONCE, 0, FLG_CRACKING_CHK, USUAL_REQ_CLR | OPT_REQ_PARAM, "%d", &options.max_run_time},
	{"progress-every", FLG_ONCE, 0, FLG_CRACKING_CHK, USUAL_REQ_CLR | OPT_REQ_PARAM, "%u", &options.status_interval},
	{"regen-lost-salts", FLG_ONCE, 0, FLG_PWD_REQ, USUAL_REQ_CLR | OPT_REQ_PARAM, OPT_FMT_STR_ALLOC, &regen_salts_options},
	{"bare-always-valid", FLG_ONCE, 0, FLG_PWD_REQ, OPT_REQ_PARAM, "%c", &options.dynamic_bare_hashes_always_valid},
	{"reject-printable", FLG_REJECT_PRINTABLE, FLG_REJECT_PRINTABLE},
	{"verbosity", FLG_VERBOSITY, FLG_VERBOSITY, 0, OPT_REQ_PARAM, "%u", &options.verbosity},
#ifdef HAVE_OPENCL
	{"force-scalar", FLG_SCALAR, FLG_SCALAR, 0, FLG_VECTOR},
	{"force-vector-width", FLG_VECTOR, FLG_VECTOR, 0, FLG_SCALAR | OPT_REQ_PARAM, "%u", &options.v_width},
	{"lws", FLG_ONCE, 0, 0, USUAL_REQ_CLR | FLG_STDOUT | OPT_REQ_PARAM, Zu, &options.lws},
	{"gws", FLG_ONCE, 0, 0, USUAL_REQ_CLR | FLG_STDOUT | OPT_REQ_PARAM, Zu, &options.gws},
#endif
#if defined(HAVE_OPENCL) || defined(HAVE_ZTEX)
	{"mask-internal-target", FLG_ONCE, 0, 0, USUAL_REQ_CLR | FLG_STDOUT | OPT_REQ_PARAM, "%d", &options.req_int_cand_target},
	{"devices", FLG_ONCE, 0, 0, USUAL_REQ_CLR | FLG_STDOUT | OPT_REQ_PARAM, OPT_FMT_ADD_LIST_MULTI, &options.acc_devices},
#endif
	{"skip-self-tests", FLG_NOTESTS, FLG_NOTESTS, 0, USUAL_REQ_CLR | FLG_STDOUT},
	{"costs", FLG_ONCE, 0, 0, USUAL_REQ_CLR | OPT_REQ_PARAM, OPT_FMT_STR_ALLOC, &costs_str},
	{"keep-guessing", FLG_ONCE, 0, FLG_CRACKING_CHK, USUAL_REQ_CLR | FLG_STDOUT | OPT_TRISTATE, NULL, &options.keep_guessing},
	{"tune", FLG_ONCE, 0, 0, USUAL_REQ_CLR | FLG_STDOUT | OPT_REQ_PARAM, OPT_FMT_STR_ALLOC, &options.tune},
	{"force-tty", FLG_FORCE_TTY, FLG_FORCE_TTY, FLG_CRACKING_CHK},
	{NULL}
};

#define JOHN_COPYRIGHT \
	"Solar Designer and others"

// the 2 DJ_DOS builds currently set this (and do not build the header). If other environs
// can not build the header, then they will also have this value set.
#ifdef NO_JOHN_BLD
#define JOHN_BLD "unk-build-type"
#else
#include "john_build_rule.h"
#endif

#if OS_FORK
#define JOHN_USAGE_FORK \
"--fork=N                   Fork N processes\n"
#else
#define JOHN_USAGE_FORK ""
#endif

#if HAVE_REXGEN
#define JOHN_USAGE_REGEX \
"--regex=REGEXPR            Regular expression mode (see doc/README.librexgen)\n"
#else
#define JOHN_USAGE_REGEX ""
#endif

#if HAVE_LIBGMP || HAVE_INT128 || HAVE___INT128 || HAVE___INT128_T
#define PRINCE_USAGE \
"--prince[=FILE]            PRINCE mode, read words from FILE\n" \
"--prince-loopback[=FILE]   Fetch words from a .pot file\n" \
"--prince-elem-cnt-min=N    Minimum number of elements per chain (1)\n" \
"--prince-elem-cnt-max=[-]N Maximum number of elements per chain (negative N is\n" \
"                           relative to word length) (8)\n" \
"--prince-skip=N            Initial skip\n" \
"--prince-limit=N           Limit number of candidates generated\n" \
"--prince-wl-dist-len       Calculate length distribution from wordlist\n" \
"--prince-wl-max=N          Load only N words from input wordlist\n" \
"--prince-case-permute      Permute case of first letter\n" \
"--prince-mmap              Memory-map infile (not available with case permute)\n" \
"--prince-keyspace          Just show total keyspace that would be produced\n" \
"                           (disregarding skip and limit)\n"
#else
#define PRINCE_USAGE ""
#endif

#ifdef HAVE_FUZZ
#define FUZZ_USAGE \
"--fuzz[=DICTFILE]          Fuzz formats' prepare(), valid() and split()\n" \
"--fuzz-dump[=FROM,TO]      Dump the fuzzed hashes between FROM and TO to file\n" \
"                           pwfile.format\n"
#else
#define FUZZ_USAGE ""
#endif

#define JOHN_BANNER	  \
"John the Ripper " JTR_GIT_VERSION _MP_VERSION DEBUG_STRING ASAN_STRING UBSAN_STRING " [" JOHN_BLD "]\n" \
"Copyright (c) 1996-2022 by " JOHN_COPYRIGHT "\n" \
"Homepage: https://www.openwall.com/john/\n" \
"\n" \
"Usage: %s [OPTIONS] [PASSWORD-FILES]\n\n"

#define JOHN_USAGE \
"--help                     Print usage summary\n" \
"--single[=SECTION[,..]]    \"Single crack\" mode, using default or named rules\n" \
"--single=:rule[,..]        Same, using \"immediate\" rule(s)\n" \
"--single-seed=WORD[,WORD]  Add static seed word(s) for all salts in single mode\n" \
"--single-wordlist=FILE     *Short* wordlist with static seed words/morphemes\n" \
"--single-user-seed=FILE    Wordlist with seeds per username (user:password[s]\n" \
"                           format)\n" \
"--single-pair-max=N        Override max. number of word pairs generated (%u)\n" \
"--no-single-pair           Disable single word pair generation\n" \
"--[no-]single-retest-guess Override config for SingleRetestGuess\n" \
"--wordlist[=FILE] --stdin  Wordlist mode, read words from FILE or stdin\n" \
"                  --pipe   like --stdin, but bulk reads, and allows rules\n" \
"--rules[=SECTION[,..]]     Enable word mangling rules (for wordlist or PRINCE\n" \
"                           modes), using default or named rules\n" \
"--rules=:rule[;..]]        Same, using \"immediate\" rule(s)\n" \
"--rules-stack=SECTION[,..] Stacked rules, applied after regular rules or to\n" \
"                           modes that otherwise don't support rules\n" \
"--rules-stack=:rule[;..]   Same, using \"immediate\" rule(s)\n" \
"--rules-skip-nop           Skip any NOP \":\" rules (you already ran w/o rules)\n" \
"--loopback[=FILE]          Like --wordlist, but extract words from a .pot file\n" \
"--mem-file-size=SIZE       Size threshold for wordlist preload (default %u MB)\n" \
"--dupe-suppression[=SIZE]  Opportunistic dupe suppression for wordlist+rules\n" \
"--incremental[=MODE]       \"Incremental\" mode [using section MODE]\n" \
"--incremental-charcount=N  Override CharCount for incremental mode\n" \
"--external=MODE            External mode or word filter\n" \
"--mask[=MASK]              Mask mode using MASK (or default from john.conf)\n" \
"--markov[=OPTIONS]         \"Markov\" mode (see doc/MARKOV)\n" \
"--mkv-stats=FILE           \"Markov\" stats file\n" \
PRINCE_USAGE \
JOHN_USAGE_REGEX \
"--rain[=CHARSET]        \"RAIN\" mode (see TODO doc/RAIN)\n" \
"--stdout[=LENGTH]          just output candidate passwords [cut at LENGTH]\n" \
"--restore[=NAME]           restore an interrupted session [called NAME]\n" \
"--session=NAME             give a new session the NAME\n" \
"--status[=NAME]            print status of a session [called NAME]\n" \
"--make-charset=FILE        make a charset file. It will be overwritten\n" \
"--reject-printable         reject printable binaries\n" \
"--show[=left]              show cracked passwords [if =left, then uncracked]\n" \
"--show=formats             show information about hashes in a file (JSON)\n" \
"--show=invalid             show lines that are not valid for selected format(s)\n" \
"--test[=TIME]              run tests and benchmarks for TIME seconds each\n" \
"--make-charset=FILE        Make a charset, FILE will be overwritten\n" \
"--stdout[=LENGTH]          Just output candidate passwords [cut at LENGTH]\n" \
"--session=NAME             Give a new session the NAME\n" \
"--status[=NAME]            Print status of a session [called NAME]\n" \
"--restore[=NAME]           Restore an interrupted session [called NAME]\n" \
"--[no-]crack-status        Emit a status line whenever a password is cracked\n" \
"--progress-every=N         Emit a status line every N seconds\n" \
"--show[=left]              Show cracked passwords [if =left, then uncracked]\n" \
"--show=formats             Show information about hashes in a file (JSON)\n" \
"--show=invalid             Show lines that are not valid for selected format(s)\n" \
"--test[=TIME]              Run tests and benchmarks for TIME seconds each\n" \
"                           (if TIME is explicitly 0, test w/o benchmark)\n" \
"--stress-test[=TIME]       Loop self tests forever\n" \
"--test-full=LEVEL          Run more thorough self-tests\n" \
"--no-mask                  Used with --test for alternate benchmark w/o mask\n" \
"--skip-self-tests          Skip self tests\n" \
"--users=[-]LOGIN|UID[,..]  [Do not] load this (these) user(s) only\n" \
"--groups=[-]GID[,..]       Load users [not] of this (these) group(s) only\n" \
"--shells=[-]SHELL[,..]     Load users with[out] this (these) shell(s) only\n" \
"--salts=[-]COUNT[:MAX]     Load salts with[out] COUNT [to MAX] hashes, or\n" \
"--salts=#M[-N]             Load M [to N] most populated salts\n" \
"--costs=[-]C[:M][,...]     Load salts with[out] cost value Cn [to Mn]. For\n" \
"                           tunable cost parameters, see doc/OPTIONS\n" \
JOHN_USAGE_FORK \
"--node=MIN[-MAX]/TOTAL     This node's number range out of TOTAL count\n" \
"--save-memory=LEVEL        Enable memory saving, at LEVEL 1..3\n" \
"--log-stderr               Log to screen instead of file\n"             \
"--verbosity=N              Change verbosity (1-%u or %u for debug, default %u)\n" \
"--no-log                   Disables creation and writing to john.log file\n"  \
"--bare-always-valid=Y      Treat bare hashes as valid (Y/N)\n" \
"--catch-up=NAME            Catch up with existing (paused) session NAME\n" \
"--config=FILE              Use FILE instead of john.conf or john.ini\n" \
"--encoding=NAME            Input encoding (eg. UTF-8, ISO-8859-1). See also\n" \
"                           doc/ENCODINGS.\n" \
"--input-encoding=NAME      Input encoding (alias for --encoding)\n" \
"--internal-codepage=NAME   Codepage used in rules/masks (see doc/ENCODINGS)\n" \
"--target-encoding=NAME     Output encoding (used by format)\n" \
"--force-tty                Set up terminal for reading keystrokes even if we're\n" \
"                           not the foreground process\n" \
"--field-separator-char=C   Use 'C' instead of the ':' in input and pot files\n" \
FUZZ_USAGE \
"--[no-]keep-guessing       Try finding plaintext collisions\n" \
"--list=WHAT                List capabilities, see --list=help or doc/OPTIONS\n" \
"--length=N                 Shortcut for --min-len=N --max-len=N\n" \
"--min-length=N             Request a minimum candidate length in bytes\n" \
"--max-length=N             Request a maximum candidate length in bytes\n" \
"--max-candidates=[-]N      Gracefully exit after this many candidates tried.\n" \
"                           (if negative, reset count on each crack)\n" \
"--max-run-time=[-]N        Gracefully exit after this many seconds (if negative,\n" \
"                           reset timer on each crack)\n" \
"--mkpc=N                   Request a lower max. keys per crypt\n" \
"--no-loader-dupe-check     Disable the dupe checking when loading hashes\n" \
"--pot=NAME                 Pot file to use\n" \
"--regen-lost-salts=N       Brute force unknown salts (see doc/OPTIONS)\n" \
"--reject-printable         Reject printable binaries\n" \
"--tune=HOW                 Tuning options (auto/report/N)\n" \

#define JOHN_USAGE_FORMAT \
"--subformat=FORMAT         Pick a benchmark format for --format=crypt\n" \
"--format=[NAME|CLASS][,..] Force hash of type NAME. The supported formats can\n" \
"                           be seen with --list=formats and --list=subformats.\n" \
"                           See also doc/OPTIONS for more advanced selection of\n" \
"                           format(s), including using classes and wildcards.\n"

#if defined(HAVE_OPENCL)
#define JOHN_USAGE_GPU \
"\nOpenCL options:\n" \
"--devices=N[,..]           Set OpenCL device(s) (see --list=opencl-devices)\n" \
"--mask-internal-target=N   Request a specific internal mask target\n" \
"--force-scalar             Force scalar mode\n" \
"--force-vector-width=N     Force vector width N\n" \
"--lws=N                    Force local worksize N\n" \
"--gws=N                    Force global worksize N\n\n"
#define JOHN_USAGE_ZTEX \
"                           or set ZTEX device(s) by its(their) serial number(s)\n"
#elif defined(HAVE_ZTEX)
#define JOHN_USAGE_ZTEX \
"--devices=N[,..]           Set ZTEX device(s) by its(their) serial number(s)\n" \
"--mask-internal-target=N   Request a specific internal mask target\n"
#endif

static void opt_banner(char *name)
{
	printf(JOHN_BANNER, name);
}

void opt_usage()
{
	printf(JOHN_USAGE, SINGLE_WORDS_PAIR_MAX, WORDLIST_BUFFER_DEFAULT / 1000000,
		   VERB_MAX, VERB_DEBUG, VERB_DEFAULT);
#if defined(HAVE_OPENCL)
	printf("%s", JOHN_USAGE_GPU);
#endif
#if defined(HAVE_ZTEX)
	printf("%s", JOHN_USAGE_ZTEX);
#endif
	printf("%s", JOHN_USAGE_FORMAT);
}

void opt_init(char *name, int argc, char **argv)
{
	if (argc == 2 &&
	     (!strcasecmp(argv[1], "--help") ||
	      !strcasecmp(argv[1], "-h") ||
	      !strcasecmp(argv[1], "-help")))
	{
		if (john_main_process) {
			opt_banner(name);
			opt_usage();
		}
		exit(0);
	} else if (argc < 2) {
		if (john_main_process) {
			opt_banner(name);
			printf("Use --help to list all available options.\n");
		}
		exit(0);
	} else if (argc > 10000000 && !rec_restored) {
		if (john_main_process)
			fprintf(stderr, "Too many command-line arguments\n");
		error();
	}

	/*
	 * When resuming, we can't clear the last part of this struct
	 * (in Jumbo) because some options are already set by complicated
	 * mechanisms (defaults vs. format vs. command-line options vs.
	 * john.conf settings).
	 */
	memset(&options, 0, offsetof(struct options_main, subformat));

	options.loader.field_sep_char = ':';
	options.max_wordfile_memory = WORDLIST_BUFFER_DEFAULT;
	options.req_minlength = -1;

	if (!options.verbosity)
		options.verbosity = VERB_DEFAULT;

	list_init(&options.passwd);

	options.loader.flags = DB_LOGIN;
	list_init(&options.loader.users);
	list_init(&options.loader.groups);
	list_init(&options.loader.shells);
#if defined(HAVE_OPENCL) || defined(HAVE_ZTEX)
	list_init(&options.acc_devices);

	options.req_int_cand_target = -1;
#endif

	options.length = -1;
	options.suppressor_size = -1;

	opt_process(opt_list, &options.flags, argv);

	if ((options.flags & FLG_TEST_CHK) && benchmark_time &&
	    !(options.flags & FLG_NO_MASK_BENCH))
		options.flags |= FLG_MASK_SET;

	if ((options.flags & (FLG_TEST_CHK | FLG_NOTESTS)) == (FLG_TEST_CHK | FLG_NOTESTS) && !benchmark_time) {
		if (john_main_process)
			fprintf(stderr, "Can't run a self-test-only while also skipping self-test!\n");
		error();
	}

#if HAVE_REXGEN
	/* We allow regex as parent for hybrid mask, not vice versa */
	if ((options.flags & FLG_REGEX_CHK) && (options.flags & FLG_MASK_CHK)) {
		if (!(options.flags & FLG_CRACKING_CHK))
			options.flags |= (FLG_CRACKING_SET | FLG_MASK_STACKED);
		else
			options.flags |= (FLG_REGEX_STACKED | FLG_MASK_STACKED);
	} else
#endif
	if (options.flags & FLG_MASK_CHK) {
		options.eff_mask = options.mask;
		if (options.flags & FLG_TEST_CHK) {
			options.flags &= ~FLG_PWD_SUP;
			if (options.mask && strcasestr(options.mask, "?w"))
				options.flags |= FLG_MASK_STACKED;

			if (!benchmark_time) {
				fprintf(stderr, "Currently can't self-test with mask\n");
				error();
			}

			if (benchmark_time == 1)
				benchmark_time = 2;
		} else {
			if (options.mask && strcasestr(options.mask, "?w") &&
			    (options.flags & FLG_EXTERNAL_CHK))
				options.flags |= FLG_MASK_STACKED;
			if (!(options.flags & FLG_MASK_STACKED)) {
				if (options.flags & FLG_CRACKING_CHK)
					options.flags |= FLG_MASK_STACKED;
				else
					options.flags |= FLG_CRACKING_SET;
			}
		}
	}
#if HAVE_REXGEN
	if (options.flags & FLG_REGEX_CHK) {
		if (options.regex && strstr(options.regex, "\\0")) {
			if ((options.flags & FLG_EXTERNAL_CHK) &&
			    !(options.flags & FLG_CRACKING_CHK))
				options.flags |= FLG_REGEX_STACKED;
			else if (!(options.flags & FLG_CRACKING_CHK)) {
				fprintf(stderr, "\\0 is only used with hybrid regex\n");
				error();
			}
		}
		if (!(options.flags & FLG_REGEX_STACKED)) {
			if (options.flags & FLG_CRACKING_CHK) {
				if (!(options.flags & FLG_MASK_STACKED))
					options.flags |= FLG_REGEX_STACKED;
			} else
				options.flags |= FLG_CRACKING_SET;
		}
	}
#endif
	ext_flags = 0;
	if (options.flags & FLG_EXTERNAL_CHK) {
		if (options.flags & (FLG_CRACKING_CHK | FLG_MAKECHR_CHK)) {
			ext_flags = EXT_REQ_FILTER | EXT_USES_FILTER;
		} else {
			options.flags |= FLG_CRACKING_SET;
			ext_flags = EXT_REQ_GENERATE | EXT_USES_RESTORE |
			    EXT_USES_GENERATE | EXT_USES_FILTER;
			if (rec_restored)
				ext_flags |= EXT_REQ_RESTORE;
		}
	}

	/* Bodge for bash completion of e.g. "john -stdout -list=..." */
	if (options.listconf != NULL && options.fork == 0)
		options.flags |= (FLG_CRACKING_SUP | FLG_STDIN_SET);

	if (!(options.flags & FLG_ACTION))
		options.flags |= FLG_BATCH_SET;

	opt_check(opt_list, options.flags, argv);

	if (benchmark_level >= 0)
		benchmark_time = 0;

#if HAVE_OPENCL
	if (options.format && strcasestr(options.format, "opencl") &&
	    (options.flags & FLG_FORK) && options.acc_devices->count == 0) {
		list_add(options.acc_devices, "best");
	}
#endif

	if (options.session) {
#if OS_FORK
		char *p = strrchr(options.session, '.');
		int bad = 0;
		if (p) {
			while (*++p) {
				if (*p < '0' || *p > '9') {
					bad = 0;
					break;
				}
				bad = 1;
			}
		}
		if (bad) {
			fprintf(stderr,
			    "Invalid session name: all-digits suffix\n");
			error();
		}
#endif
		rec_name = options.session;
		rec_name_completed = 0;
	}

#ifdef HAVE_MPI
	if (mpi_p > 1) {
		if (options.flags & FLG_RESTORE_CHK || rec_restored) {
			if (options.fork && options.fork != mpi_p) {
				if (john_main_process)
				fprintf(stderr,
				        "Node count in session file is %d.\n",
				        options.fork);
				error();
			}
			options.fork = 0;
			options.flags &= ~FLG_FORK;
		} else
		if (options.fork) {
			if (john_main_process)
				fprintf(stderr, "Can't use --fork with MPI.\n");
			error();
		}
	}
#endif

	if (options.flags & FLG_RESTORE_CHK) {
#if OS_FORK || defined(HAVE_MPI)
		char *rec_name_orig = rec_name;
#endif
		rec_restored = 1;
#ifndef HAVE_MPI
		rec_restore_args(1);
#else
		rec_restore_args(mpi_p);
#endif
#if OS_FORK || defined(HAVE_MPI)
#ifndef HAVE_MPI
		if (options.fork) {
#else
		if (options.fork || mpi_p > 1) {
#endif
			rec_name = rec_name_orig;
			rec_name_completed = 0;
		}
#endif
		return;
	}

	if (options.catchup && options.max_cands)
		error_msg("Can't combine --max-candidates and --catch-up options\n");

	if (options.flags & FLG_STATUS_CHK) {
#if OS_FORK
		char *rec_name_orig = rec_name;
#endif
		rec_restore_args(0);
		options.flags |= FLG_STATUS_SET;
		status_init(NULL, 1);
		status_print(0);
#if OS_FORK
		if (options.fork) {
			unsigned int node_max = options.node_max;
			unsigned int range = node_max - options.node_min + 1;
			unsigned int npf = range / options.fork;
			unsigned int i = options.node_min;
			while ((i += npf) <= node_max) {
				rec_name = rec_name_orig;
				rec_name_completed = 0;
				rec_restoring_now = 0;
				options.node_min = options.node_max = i;
				john_main_process = 0;
				rec_restore_args(0);
				john_main_process = 1;
				options.node_min = options.node_max = i;
				options.flags |= FLG_STATUS_SET;
				if (rec_restoring_now)
					status_print(0);
			}
		}
#endif
		path_done();
		cleanup_tiny_memory();
		exit(0);
	}
	if (costs_str) {
		/*
		 * costs_str: [-]COST1[:MAX1][,[-]COST2[:MAX2]][...,[-]COSTn[:MAXn]]
		 *            but not --costs=,2:9 or --costs=,-99
		 *            istead use --costs=:,2:9 or --costs=:,-99
		 *            if you want to specify values for the 2nd cost param.
		 */
		int i;
		char *range[FMT_TUNABLE_COSTS] = { 0 };
		char *dummy;

		for ( i = 0; i < FMT_TUNABLE_COSTS; i++) {
			if (i)
				range[i] = strtok(NULL, ",");
			else
				range[i] = strtok(costs_str, ",");

			options.loader.min_cost[i] = 0;
			options.loader.max_cost[i] = UINT_MAX;
		}
		dummy = strtok(NULL, ",");
		if (dummy) {
			if (john_main_process)
				fprintf(stderr, "max. %d different tunable cost parameters"
				                " supported\n", FMT_TUNABLE_COSTS);
			error();
		}
		for ( i = 0; i < FMT_TUNABLE_COSTS; i++) {
			int negative;
			int two_values;

			if (range[i] == NULL)
				break;
			if (range[i][0] == '-') {
				negative = 1;
				range[i]++;
			}
			else {
				negative = 0;
			}
			if (range[i][0] != '\0') {
				two_values = 0;
				if (sscanf(range[i], "%u:%u",
				           &options.loader.min_cost[i], &options.loader.max_cost[i]) == 2)
					two_values = 1;
				if (two_values && negative) {
					if (john_main_process)
						fprintf(stderr, "Usage of negative --cost is not valid"
						                " for cost range (min:max)\n");
					error();
				}
				if (!two_values)
					sscanf(range[i], "%u", &options.loader.min_cost[i]);
				if (negative && options.loader.min_cost[i] == 0) {
					if (john_main_process)
						fprintf(stderr, "Usage of negative --cost is not valid"
								" for value 0\n");
					error();
				}
				if (!two_values) {
					if (negative) {
						options.loader.max_cost[i] = options.loader.min_cost[i] - 1;
						options.loader.min_cost[i] = 0;
					}
					else {
						options.loader.max_cost[i] = UINT_MAX;
					}
				}
				if (options.loader.max_cost[i] < options.loader.min_cost[i]) {
					if (john_main_process)
						fprintf(stderr, "Max. cost value must be >= min. cost value\n");
					error();
				}
			}
		}
	}
	else {
		int i;

		for ( i = 0; i < FMT_TUNABLE_COSTS; i++) {
			options.loader.min_cost[i] = 0;
			options.loader.max_cost[i] = UINT_MAX;
		}
	}

	if (options.tune) {
		if (strcmp(options.tune, "auto") &&
		    strcmp(options.tune, "report") &&
		    !isdec(options.tune))
			error_msg("Allowed arguments to --tune is auto, report or N, where N is a positive number");
	}

	if (salts_str) {
		int two_salts = 0;

		if (salts_str[0] == '#') {
			options.loader.best_pps = 1;
			salts_str++;
		}

		if (options.loader.best_pps &&
		    sscanf(salts_str, "%d-%d", &options.loader.min_pps, &options.loader.max_pps) == 2)
			two_salts = 1;
		else if (sscanf(salts_str, "%d:%d", &options.loader.min_pps, &options.loader.max_pps) == 2)
			two_salts = 1;
		else if (sscanf(salts_str, "%d,%d", &options.loader.min_pps, &options.loader.max_pps) == 2)
			two_salts = 1;

		if (!two_salts) {
			sscanf(salts_str, "%d", &options.loader.min_pps);
			if (options.loader.best_pps)
				options.loader.max_pps = options.loader.min_pps;
			else if (options.loader.min_pps < 0) {
				options.loader.max_pps = -1 - options.loader.min_pps;
				options.loader.min_pps = 0;
			}
			else
				options.loader.max_pps = 0x7fffffff;
		} else if (options.loader.min_pps < 0) {
			if (john_main_process)
				fprintf(stderr, "Usage of negative -salt min "
				        "is not 'valid' if using Min and Max "
				        "salt range of values\n");
			error();
		}
		if (options.loader.min_pps > options.loader.max_pps) {
			if (john_main_process)
				fprintf(stderr, "Min number salts wanted is "
				        "less than Max salts wanted\n");
			error();
		}
	}

	if (john_main_process && options.flags & FLG_VERBOSITY &&
	    (options.verbosity < 1 || options.verbosity > VERB_DEBUG)) {
		fprintf(stderr, "Invalid --verbosity level, use 1-"
		        "%u (default %u) or %u for debug\n",
		        VERB_MAX, VERB_DEFAULT, VERB_DEBUG);
		error();
	}
	if (options.length < 0)
		options.length = PLAINTEXT_BUFFER_SIZE - 3;
	else
	if (options.length < 1 || options.length > PLAINTEXT_BUFFER_SIZE - 3) {
		if (john_main_process)
			fprintf(stderr, "Invalid plaintext length requested\n");
		error();
	}
	if (options.req_length) {
		if (!rec_restored &&
		    (options.req_minlength != -1 || options.req_maxlength != 0)) {
			if (john_main_process)
				fprintf(stderr, "Invalid options: --length can't be used together with --min/max-length\n");
			error();
		}
		options.req_minlength = options.req_maxlength = options.req_length;
	}
	if (options.req_maxlength && options.req_maxlength < options.req_minlength) {
		if (john_main_process)
			fprintf(stderr, "Invalid options: --min-length larger "
			        "than --max-length\n");
		error();
	}
	if (options.req_maxlength < 0 || options.req_maxlength > PLAINTEXT_BUFFER_SIZE - 3) {
		if (john_main_process)
			fprintf(stderr, "Invalid max length requested\n");
		error();
	}
	if (options.force_maxkeys != 0 && options.force_maxkeys < 1) {
		if (john_main_process)
			fprintf(stderr,
			        "Invalid options: --mkpc must be at least 1\n");
		error();
	}

	/*
	 * If max length came from --max-len, these are set the same.
	 * If max length later comes from FMT_TRUNC, only force_maxlength
	 * will be set.
	 */
	options.force_maxlength = options.req_maxlength;

	/*
	 * Defaults until limited by format or other options
	 */
	options.eff_minlength = MAX(options.req_minlength, 0);
	options.eff_maxlength =
		options.req_maxlength ? options.req_maxlength : 125;

	if (options.flags & FLG_STDOUT) options.flags &= ~FLG_PWD_REQ;

#if OS_FORK
	if ((options.flags & FLG_FORK) &&
	    (options.fork < 2 || options.fork > 1024)) {
		fprintf(stderr, "--fork number must be between 2 and 1024\n");
		error();
	}
#endif

	if (options.node_str) {
		const char *msg = NULL;
		int n;
		if ((n = sscanf(options.node_str, "%u-%u/%u",
		    &options.node_min, &options.node_max,
		    &options.node_count)) != 3) {
			n = sscanf(options.node_str, "%u/%u",
			    &options.node_min, &options.node_count);
			options.node_max = options.node_min;
#if OS_FORK
			if (options.fork)
				options.node_max += options.fork - 1;
#endif
#ifdef HAVE_MPI
			if (mpi_p > 1)
				options.node_max += mpi_p - 1;
#endif
		}
		unsigned int range = options.node_max - options.node_min + 1;
		if (n < 2)
			msg = "valid syntax is MIN-MAX/TOTAL or N/TOTAL";
		else if (!options.node_min)
			msg = "valid node numbers start from 1";
		else if (options.node_min > options.node_max)
			msg = "range start can't exceed range end";
		else if (options.node_count < 2)
			msg = "node count must be at least 2";
		else if (options.node_max > options.node_count)
			msg = "node numbers can't exceed node count";
#if OS_FORK
		else if (options.fork && range % options.fork)
			msg = "node range must be divisible by fork count";
#endif
#ifdef HAVE_MPI
		else if (mpi_p > 1 && range % mpi_p)
			msg = "node range must be divisible by MPI node count";
#endif
		else if (!options.fork &&
#ifdef HAVE_MPI
		    mpi_p == 1 &&
#endif
		    range == options.node_count)
			msg = "node numbers can't span the whole range";
		if (msg) {
			if (john_main_process)
			fprintf(stderr, "Invalid node specification: %s: %s\n",
			    options.node_str, msg);
			error();
		}
#if OS_FORK
	} else if (options.fork) {
		options.node_min = 1;
		options.node_max = options.node_min + options.fork - 1;
		options.node_count = options.node_max;
#endif
	}
#ifdef HAVE_MPI
	else if (mpi_p > 1) {
		options.node_min = 1;
		options.node_max = options.node_min + mpi_p - 1;
		options.node_count = options.node_max;
	}
#endif

	/*
	 * By default we are setup in 7 bit ascii mode (for rules) and
	 * ISO-8859-1 codepage (for Unicode conversions).  We can change
	 * that in john.conf or with the --encoding option.
	 */
	if ((encoding_str && !strcasecmp(encoding_str, "list")) ||
	    (internal_cp_str &&
	     !strcasecmp(internal_cp_str, "list")) ||
	    (target_enc_str && !strcasecmp(target_enc_str, "list"))) {
		listEncodings(stdout);
		exit(EXIT_SUCCESS);
	}

	if (encoding_str)
		options.input_enc = cp_name2id(encoding_str, 1);

	if (target_enc_str)
		options.target_enc = cp_name2id(target_enc_str, 1);

	if (internal_cp_str)
		options.internal_cp = cp_name2id(internal_cp_str, 1);

	if (options.input_enc && options.input_enc != UTF_8) {
		if (!options.target_enc)
			options.target_enc = options.input_enc;
		if (!options.internal_cp)
			options.internal_cp = options.input_enc;
	}

#ifdef HAVE_OPENCL
	if (options.flags & FLG_SCALAR)
		options.v_width = 1;
	else if (options.v_width) {
		if (options.v_width != 1 && options.v_width != 2 &&
		    options.v_width != 3 && options.v_width != 4 &&
		    options.v_width != 8 && options.v_width != 16) {
			if (john_main_process)
				fprintf(stderr, "Vector width must be one of"
				        " 1, 2, 3, 4, 8 or 16\n");
			error();
		}
		if (options.v_width == 3 && john_main_process)
			fprintf(stderr, "Warning: vector width 3 is not "
			        "expected to work well with all formats\n");
	}
#endif
	/*
	 * This line is not a bug - it extends the next conditional.
	 * It's from commit 90a8caee.
	 */
	if (!(options.subformat && !strcasecmp(options.subformat, "list")) &&
	    (!options.listconf))
	if ((options.flags & (FLG_PASSWD | FLG_PWD_REQ)) == FLG_PWD_REQ) {
		if (john_main_process)
			fprintf(stderr, "Password files required, "
			        "but none specified\n");
		error();
	}

	if ((options.flags & (FLG_PASSWD | FLG_PWD_SUP)) == FLG_PASSWD) {
		if (john_main_process)
			fprintf(stderr, "Password files specified, "
			        "but no option would use them\n");
		error();
	}

	if ( (options.flags & FLG_SHOW_CHK) && show_uncracked_str) {
		if (!strcasecmp(show_uncracked_str, "left"))  {
			options.loader.showuncracked = 1;
			// Note we 'do' want the pot file to load normally, but during that load,
			// we print out hashes left. At the end of the load, john exits.  However
			// we do NOT want the 'special' -SHOW_CHK logic to happen (which happens
			// instead of normal loading if we are in 'normal' show mode)
			options.flags &= ~FLG_SHOW_CHK;
		}
		else if (!strcasecmp(show_uncracked_str, "formats")) {
			options.loader.showformats = 1;
		}
		else if (!strcasecmp(show_uncracked_str, "types")) {
			options.loader.showformats = 1;
			options.loader.showformats_old = 1;
		}
		else if (!strcasecmp(show_uncracked_str, "invalid")) {
			options.loader.showinvalid = 1;
		}
		else {
			fprintf(stderr, "Invalid option in --show switch. Valid options:\n"
			        "--show, --show=left, --show=formats, --show=types, --show=invalid\n");
			error();
		}
	}

	if (options.dynamic_bare_hashes_always_valid == 'Y' || options.dynamic_bare_hashes_always_valid == 'y' ||
		options.dynamic_bare_hashes_always_valid == '1' || options.dynamic_bare_hashes_always_valid == 't' || options.dynamic_bare_hashes_always_valid == 'T')
		options.dynamic_bare_hashes_always_valid = 'Y';
	else if (options.dynamic_bare_hashes_always_valid == 'N' || options.dynamic_bare_hashes_always_valid == 'n' ||
		options.dynamic_bare_hashes_always_valid == '0' || options.dynamic_bare_hashes_always_valid == 'f' || options.dynamic_bare_hashes_always_valid == 'F')
		options.dynamic_bare_hashes_always_valid = 'N';

	options.regen_lost_salts = regen_lost_salt_parse_options();

	/*
	 * The format should never have been a parameter to --regen-lost-salts but now that we have to live with it:
	 * If --regen-lost-salts=TYPE:hash_sz:mask and no --format option was given, infer --format=TYPE.
	 * If on the other hand --format=TYPE *was* given, require that they actually match.
	 */
	if (options.regen_lost_salts) {
		char *s = str_alloc_copy(regen_salts_options);
		char *e = strchr(s + 1, ':');

		if (e > s + 8) {
			if (*s == '@') {
				s++;
				e--;
			}
			*e = 0;
			if (!options.format)
				options.format = s;
			else if (strcmp(options.format, s))
				error_msg("Error: --regen-lost-salts parameter not matching --format option\n");
		}
	}

	if (field_sep_char_str) {
		// Literal tab or TAB will mean 0x09 tab character
		if (!strcasecmp(field_sep_char_str, "tab"))
			field_sep_char_str = "\x09";
		if (strlen(field_sep_char_str) == 1)
			options.loader.field_sep_char = *field_sep_char_str;
		else if (field_sep_char_str[0] == '\\' &&
		         (field_sep_char_str[1]=='x' ||
		          field_sep_char_str[1]=='X')) {
			unsigned xTmp=0;

			sscanf(&field_sep_char_str[2], "%x", &xTmp);
			if (!xTmp || xTmp > 255) {
				if (john_main_process)
					fprintf(stderr, "trying to use an "
					         "invalid field separator char:"
					         " %s\n",
					         field_sep_char_str);
				error();
			}
			options.loader.field_sep_char = (char)xTmp;
		} else {
				if (john_main_process)
					fprintf(stderr, "trying to use an "
					         "invalid field separator char:"
					         " %s (must be single byte "
					         "character)\n",
					         field_sep_char_str);
				error();
		}

		if (options.loader.field_sep_char != ':')
			if (john_main_process)
				fprintf(stderr, "using field sep char '%c' "
				         "(0x%02x)\n", options.loader.field_sep_char,
				         options.loader.field_sep_char);
	}

	rec_argc = argc; rec_argv = argv;
	rec_check = 0;
}
