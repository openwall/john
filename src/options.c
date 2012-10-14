/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2011 by Solar Designer
 *
 * ...with changes in the jumbo patch, by JimF and magnum (and various others?)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
#include "dynamic.h"
#include "unicode.h"
#ifdef HAVE_MPI
#include "john-mpi.h"
#ifdef _OPENMP
#define _MP_VERSION "_mpi+omp"
#else
#define _MP_VERSION "_mpi"
#endif
#define _PER_NODE "per node "
#else
#ifdef _OPENMP
#define _MP_VERSION "_omp"
#else
#define _MP_VERSION ""
#endif
#define _PER_NODE ""
#endif
#ifdef CL_VERSION_1_0
#include "common-opencl.h"
#endif
#if defined(HAVE_CUDA)
extern int cuda_gpu_id;
#endif

struct options_main options;
static char *field_sep_char_string;

static struct opt_entry opt_list[] = {
	{"", FLG_PASSWD, 0, 0, 0, OPT_FMT_ADD_LIST, &options.passwd},
	{"single", FLG_SINGLE_SET, FLG_CRACKING_CHK, 0, 0,
		OPT_FMT_STR_ALLOC, &options.loader.activesinglerules},
	{"wordlist", FLG_WORDLIST_SET, FLG_CRACKING_CHK,
		0, 0, OPT_FMT_STR_ALLOC, &options.wordlist},
	{"loopback", FLG_LOOPBACK_SET | FLG_DUPESUPP, FLG_CRACKING_CHK,
		0, 0, OPT_FMT_STR_ALLOC, &options.wordlist},
	{"encoding", FLG_NONE, FLG_NONE,
		0, 0, OPT_FMT_STR_ALLOC, &options.encoding},
	{"stdin", FLG_STDIN_SET, FLG_CRACKING_CHK},
#if defined (_MSC_VER) || defined (__MINGW32__) || defined (__CYGWIN32__)
	{"pipe", FLG_PIPE_SET, FLG_CRACKING_CHK,
		0, 0, OPT_FMT_STR_ALLOC, &options.loader.sharedmemoryfilename},
#else
	{"pipe", FLG_PIPE_SET, FLG_CRACKING_CHK},
#endif
	{"rules", FLG_RULES, FLG_RULES, FLG_WORDLIST_CHK, FLG_STDIN_CHK,
		OPT_FMT_STR_ALLOC, &options.loader.activewordlistrules},
	{"incremental", FLG_INC_SET, FLG_CRACKING_CHK,
		0, 0, OPT_FMT_STR_ALLOC, &options.charset},
	{"markov", FLG_MKV_SET, FLG_CRACKING_CHK,
		0, 0, OPT_FMT_STR_ALLOC, &options.mkv_param},
	{"external", FLG_EXTERNAL_SET, FLG_EXTERNAL_CHK,
		0, OPT_REQ_PARAM, OPT_FMT_STR_ALLOC, &options.external},
	{"stdout", FLG_STDOUT, FLG_STDOUT,
		FLG_CRACKING_SUP, FLG_SINGLE_CHK | FLG_BATCH_CHK,
		"%u", &options.length},
	{"restore", FLG_RESTORE_SET, FLG_RESTORE_CHK,
		0, ~FLG_RESTORE_SET & ~OPT_REQ_PARAM,
		OPT_FMT_STR_ALLOC, &options.session},
	{"session", FLG_SESSION, FLG_SESSION,
		FLG_CRACKING_SUP, OPT_REQ_PARAM,
		OPT_FMT_STR_ALLOC, &options.session},
	{"status", FLG_STATUS_SET, FLG_STATUS_CHK,
		0, ~FLG_STATUS_SET & ~OPT_REQ_PARAM & ~FLG_DYNFMT,
		OPT_FMT_STR_ALLOC, &options.session},
	{"make-charset", FLG_MAKECHR_SET, FLG_MAKECHR_CHK,
		0, FLG_CRACKING_CHK | FLG_SESSION | OPT_REQ_PARAM,
		OPT_FMT_STR_ALLOC, &options.charset},
	{"show", FLG_SHOW_SET, FLG_SHOW_CHK,
		0, FLG_CRACKING_SUP | FLG_MAKECHR_CHK,
		OPT_FMT_STR_ALLOC, &options.showuncracked_str},
	{"test", FLG_TEST_SET, FLG_TEST_CHK,
		0, ~FLG_TEST_SET & ~FLG_FORMAT & ~FLG_SAVEMEM & ~FLG_DYNFMT &
		~OPT_REQ_PARAM & ~FLG_NOLOG, "%u", &benchmark_time},
	{"users", FLG_NONE, 0, FLG_PASSWD, OPT_REQ_PARAM,
		OPT_FMT_ADD_LIST_MULTI, &options.loader.users},
	{"groups", FLG_NONE, 0, FLG_PASSWD, OPT_REQ_PARAM,
		OPT_FMT_ADD_LIST_MULTI, &options.loader.groups},
	{"shells", FLG_NONE, 0, FLG_PASSWD, OPT_REQ_PARAM,
		OPT_FMT_ADD_LIST_MULTI, &options.loader.shells},
	{"salts", FLG_SALTS, FLG_SALTS, FLG_PASSWD, OPT_REQ_PARAM,
		OPT_FMT_STR_ALLOC, &options.salt_param},
	{"save-memory", FLG_SAVEMEM, FLG_SAVEMEM, 0, OPT_REQ_PARAM,
		"%u", &mem_saving_level},
	{"pot", FLG_NONE, FLG_NONE, 0, OPT_REQ_PARAM,
	    OPT_FMT_STR_ALLOC, &options.loader.activepot},
	{"format", FLG_FORMAT, FLG_FORMAT,
		0, FLG_STDOUT | OPT_REQ_PARAM,
		OPT_FMT_STR_ALLOC, &options.format},
	{"subformat", FLG_NONE, FLG_NONE,
		0, FLG_STDOUT | OPT_REQ_PARAM,
		OPT_FMT_STR_ALLOC, &options.subformat},
	{"list", FLG_NONE, FLG_NONE, 0, OPT_REQ_PARAM,
		OPT_FMT_STR_ALLOC, &options.listconf},
#ifdef HAVE_DL
	{"plugin", FLG_DYNFMT, 0, 0, OPT_REQ_PARAM,
		OPT_FMT_ADD_LIST_MULTI,	&options.fmt_dlls},
#endif
	{"mem-file-size", FLG_NONE, FLG_NONE, FLG_WORDLIST_CHK, FLG_DUPESUPP |
		FLG_SAVEMEM | FLG_STDIN_CHK | FLG_PIPE_CHK | OPT_REQ_PARAM,
		"%u", &options.loader.max_wordfile_memory},
	{"dupe-suppression", FLG_DUPESUPP, FLG_DUPESUPP, FLG_WORDLIST_CHK,
		FLG_SAVEMEM | FLG_STDIN_CHK | FLG_PIPE_CHK},
	{"fix-state-delay", FLG_NONE, FLG_NONE, 0, OPT_REQ_PARAM,
		"%u", &options.loader.max_fix_state_delay},
	{"field-separator-char", FLG_NONE, FLG_NONE, 0, OPT_REQ_PARAM,
		OPT_FMT_STR_ALLOC, &field_sep_char_string},
	{"config", FLG_NONE, FLG_NONE, 0, OPT_REQ_PARAM,
		OPT_FMT_STR_ALLOC, &options.config},
	{"nolog", FLG_NOLOG, FLG_NOLOG},
	{"log-stderr", FLG_LOG_STDERR | FLG_NOLOG, FLG_LOG_STDERR},
	{"crack-status", FLG_CRKSTAT, FLG_CRKSTAT},
	{"mkpc", FLG_NONE, FLG_NONE, 0, OPT_REQ_PARAM,
		"%u", &options.force_maxkeys},
	{"length", FLG_NONE, FLG_NONE, 0, FLG_STDOUT | OPT_REQ_PARAM,
		"%u", &options.force_maxlength},
	{"max-run-time", FLG_NONE, FLG_NONE, 0, OPT_REQ_PARAM,
		"%u", &options.max_run_time},
	{"progress-every", FLG_NONE, FLG_NONE, 0, OPT_REQ_PARAM,
		"%u", &options.status_interval},
	{"regen-lost-salts", FLG_NONE, FLG_NONE, 0, OPT_REQ_PARAM,
		"%u", &options.regen_lost_salts},
	{"raw-always-valid", FLG_NONE, FLG_NONE, 0, OPT_REQ_PARAM,
		"%c", &options.dynamic_raw_hashes_always_valid},
#ifdef CL_VERSION_1_0
	{"platform", FLG_NONE, FLG_NONE, 0, OPT_REQ_PARAM,
		OPT_FMT_STR_ALLOC, &options.ocl_platform},
#endif
#if defined(CL_VERSION_1_0) || defined(HAVE_CUDA)
	{"device", FLG_NONE, FLG_NONE, 0, OPT_REQ_PARAM,
		OPT_FMT_STR_ALLOC, &options.gpu_device},
#endif
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

#define JOHN_USAGE \
"John the Ripper password cracker, ver: " JOHN_VERSION _MP_VERSION " [" JOHN_BLD "]\n" \
"Copyright (c) 1996-2012 by " JOHN_COPYRIGHT "\n" \
"Homepage: http://www.openwall.com/john/\n" \
"\n" \
"Usage: %s [OPTIONS] [PASSWORD-FILES]\n" \
"--config=FILE             use FILE instead of john.conf or john.ini\n" \
"--single[=SECTION]        \"single crack\" mode\n" \
"--wordlist[=FILE] --stdin wordlist mode, read words from FILE or stdin\n" \
"                  --pipe  like --stdin, but bulk reads, and allows rules\n" \
"--loopback[=FILE]         like --wordlist, but fetch words from a .pot file\n" \
"--dupe-suppression        suppress all dupes in wordlist (and force preload)\n" \
"--encoding=NAME           input data is non-ascii (eg. UTF-8, ISO-8859-1).\n" \
"                          For a full list of NAME use --list=encodings\n" \
"--rules[=SECTION]         enable word mangling rules for wordlist modes\n" \
"--incremental[=MODE]      \"incremental\" mode [using section MODE]\n" \
"--markov[=OPTIONS]        \"Markov\" mode (see doc/MARKOV)\n" \
"--external=MODE           external mode or word filter\n" \
"--stdout[=LENGTH]         just output candidate passwords [cut at LENGTH]\n" \
"--restore[=NAME]          restore an interrupted session [called NAME]\n" \
"--session=NAME            give a new session the NAME\n" \
"--status[=NAME]           print status of a session [called NAME]\n" \
"--make-charset=FILE       make a charset file. It will be overwritten\n" \
"--show[=LEFT]             show cracked passwords [if =LEFT, then uncracked]\n" \
"--test[=TIME]             run tests and benchmarks for TIME seconds each\n" \
"--users=[-]LOGIN|UID[,..] [do not] load this (these) user(s) only\n" \
"--groups=[-]GID[,..]      load users [not] of this (these) group(s) only\n" \
"--shells=[-]SHELL[,..]    load users with[out] this (these) shell(s) only\n" \
"--salts=[-]COUNT[:MAX]    load salts with[out] COUNT [to MAX] hashes\n" \
"--pot=NAME                pot file to use\n" \
"--format=NAME             force hash type NAME:"

#define JOHN_USAGE_INDENT \
"                         " // formats are prepended with a space

#define JOHN_USAGE_TAIL \
"--list=WHAT               list capabilities, see --list=help or doc/OPTIONS\n" \
"--save-memory=LEVEL       enable memory saving, at LEVEL 1..3\n" \
"--mem-file-size=SIZE      size threshold for wordlist preload (default 5 MB)\n" \
"--nolog                   disables creation and writing to john.log file\n" \
"--crack-status            emit a status line whenever a password is cracked\n" \
"--max-run-time=N          gracefully exit after this many seconds\n" \
"--regen-lost-salts=N      regenerate lost salts (see doc/OPTIONS)\n"

#define JOHN_USAGE_PLUGIN \
"--plugin=NAME[,..]        load this (these) dynamic plugin(s)\n"

#if defined(CL_VERSION_1_0) && defined(HAVE_CUDA)
#define JOHN_USAGE_GPU \
"--platform=N              set OpenCL platform (list using --list=opencl-devices)\n" \
"--device=N                set OpenCL or CUDA device\n"
#elif defined(CL_VERSION_1_0)
#define JOHN_USAGE_GPU \
"--platform=N              set OpenCL platform\n" \
"--device=N                set OpenCL device (list using --list=opencl-devices)\n"
#elif defined (HAVE_CUDA)
#define JOHN_USAGE_GPU \
"--device=N                set CUDA device\n"
#endif

static int qcmpstr(const void *p1, const void *p2)
{
	return strcmp(*(const char**)p1, *(const char**)p2);
}

static void print_usage(char *name)
{
	int column;
	struct fmt_main *format;
	int i, dynamics = 0;
	char **formats_list;

	i = 0;
	format = fmt_list;
	while ((format = format->next))
		i++;

	formats_list = malloc(sizeof(char*) * i);

	i = 0;
	format = fmt_list;
	do {
		char *label = format->params.label;
		if (!strncmp(label, "dynamic", 7)) {
			if (dynamics++)
				continue;
			else
				label = "dynamic_n";
		}
		formats_list[i++] = label;
	} while ((format = format->next));
	formats_list[i] = NULL;

	qsort(formats_list, i, sizeof(formats_list[0]), qcmpstr);

	printf(JOHN_USAGE, name);
	column = strrchr(JOHN_USAGE, '\0') - strrchr(JOHN_USAGE, '\n') - 1;
	i = 0;
	do {
		int length;
		char *label = formats_list[i++];
		length = strlen(label) + 1;
		column += length;
		if (column > 79) { /* silly Redmond Bug[tm] if we use 80 */
			printf("\n" JOHN_USAGE_INDENT);
			column = strlen(JOHN_USAGE_INDENT) + length;
		}
		printf(" %s%s", label, formats_list[i] ? "" : "\n");
	} while (formats_list[i]);
	MEM_FREE(formats_list);

	printf("%s", JOHN_USAGE_TAIL);
#ifdef HAVE_DL
	printf("%s", JOHN_USAGE_PLUGIN);
#endif

#if defined(CL_VERSION_1_0) || defined(HAVE_CUDA)
	printf("%s", JOHN_USAGE_GPU);
#endif
	exit(0);
}

void opt_init(char *name, int argc, char **argv, int show_usage)
{
	if (show_usage)
		print_usage(name);

	memset(&options, 0, sizeof(options));

	options.loader.field_sep_char = options.field_sep_char = ':';
	options.loader.regen_lost_salts = options.regen_lost_salts = 0;
	options.loader.max_fix_state_delay = 0;
	options.loader.max_wordfile_memory = WORDLIST_BUFFER_DEFAULT;
	options.force_maxkeys = options.force_maxlength = 0;
	options.max_run_time = options.status_interval = -2;
	options.dynamic_raw_hashes_always_valid = 0;

	list_init(&options.passwd);

	options.loader.flags = DB_LOGIN;
	list_init(&options.loader.users);
	list_init(&options.loader.groups);
	list_init(&options.loader.shells);
#ifdef HAVE_DL
	list_init(&options.fmt_dlls);
#endif

	options.length = -1;

	opt_process(opt_list, &options.flags, argv);

	ext_flags = 0;
	if (options.flags & FLG_EXTERNAL_CHK) {
		if (options.flags & (FLG_CRACKING_CHK | FLG_MAKECHR_CHK)) {
			ext_flags = EXT_REQ_FILTER | EXT_USES_FILTER;
		} else {
			options.flags |= FLG_CRACKING_SET;
			ext_flags = EXT_REQ_GENERATE |
			    EXT_USES_GENERATE | EXT_USES_FILTER;
		}
	}

	if (!(options.flags & FLG_ACTION))
		options.flags |= FLG_BATCH_SET;

	opt_check(opt_list, options.flags, argv);

	if (options.session) {
		rec_name = options.session;
		rec_name_completed = 0;
	}

	if (options.flags & FLG_RESTORE_CHK) {
		rec_restore_args(1);
		return;
	}

#ifdef CL_VERSION_1_0
	if (options.ocl_platform)
		platform_id = atoi(options.ocl_platform);
	if (options.gpu_device)
		ocl_gpu_id = atoi(options.gpu_device);
#endif
#ifdef HAVE_CUDA
	if (options.gpu_device)
		cuda_gpu_id = atoi(options.gpu_device);
#endif
	if (options.flags & FLG_STATUS_CHK) {
		rec_restore_args(0);
		options.flags |= FLG_STATUS_SET;
		status_init(NULL, 1);
		status_print();
		exit(0);
	}

	if (options.flags & FLG_SALTS)
	{
		int two_salts = 0;
		if (sscanf(options.salt_param, "%d:%d", &options.loader.min_pps, &options.loader.max_pps) == 2)
			two_salts = 1;
		if (!two_salts && sscanf(options.salt_param, "%d,%d", &options.loader.min_pps, &options.loader.max_pps) == 2)
			two_salts = 1;
		if (!two_salts){
			sscanf(options.salt_param, "%d", &options.loader.min_pps);
			if (options.loader.min_pps < 0) {
				options.loader.max_pps = -1 - options.loader.min_pps;
				options.loader.min_pps = 0;
			}
			else
				options.loader.max_pps = 0x7fffffff;
		} else if (options.loader.min_pps < 0) {
#ifdef HAVE_MPI
			if (mpi_id == 0)
#endif
			fprintf(stderr, "Usage of negative -salt min is not 'valid' if using Min and Max salt range of values\n");
			error();
		}
		if (options.loader.min_pps > options.loader.max_pps) {
#ifdef HAVE_MPI
			if (mpi_id == 0)
#endif
			fprintf(stderr, "Min number salts wanted is less than Max salts wanted\n");
			error();
		}
	}

	if (options.length < 0)
		options.length = PLAINTEXT_BUFFER_SIZE - 3;
	else
	if (options.length < 1 || options.length > PLAINTEXT_BUFFER_SIZE - 3) {
#ifdef HAVE_MPI
		if (mpi_id == 0)
#endif
		fprintf(stderr, "Invalid plaintext length requested\n");
		error();
	}

	if (options.flags & FLG_STDOUT) options.flags &= ~FLG_PWD_REQ;

	if (options.encoding && !strcasecmp(options.encoding, "list")) {
		listEncodings();
		exit(0);
	}

	if (!(options.subformat && !strcasecmp(options.subformat, "list")) &&
	    (!options.listconf))
	if ((options.flags & (FLG_PASSWD | FLG_PWD_REQ)) == FLG_PWD_REQ) {
#ifdef HAVE_MPI
		if (mpi_id == 0)
#endif
		fprintf(stderr, "Password files required, "
			"but none specified\n");
		error();
	}

	if ((options.flags & (FLG_PASSWD | FLG_PWD_SUP)) == FLG_PASSWD) {
#ifdef HAVE_MPI
		if (mpi_id == 0)
#endif
		fprintf(stderr, "Password files specified, "
			"but no option would use them\n");
		error();
	}

#ifdef HAVE_MPI
	if (options.flags & (FLG_STDIN_CHK | FLG_SHOW_CHK | FLG_MAKECHR_CHK ) && (mpi_p > 1)) {
		if (mpi_id == 0) fprintf(stderr, "Chosen mode not suitable for running on multiple nodes\n");
		error();
	}
#endif

	if ( (options.flags & FLG_SHOW_SET) && options.showuncracked_str) {
		if (!strcasecmp( options.showuncracked_str, "left"))  {
			options.loader.showuncracked = 1;
			// Note we 'do' want the pot file to load normally, but during that load,
			// we print out hashes left. At the end of the load, john exits.  However
			// we do NOT want the 'special' -SHOW_CHK logic to happen (which happens
			// instead of normal loading if we are in 'normal' show mode)
			options.flags &= ~FLG_SHOW_CHK;
		}
		else {
			fprintf(stderr, "Invalid option in --show switch.\nOnly --show or --show=left are valid\n");
			error();
		}
	}

	if (options.loader.activepot == NULL)
		options.loader.activepot = str_alloc_copy(POT_NAME);

	if (options.loader.activewordlistrules == NULL)
		options.loader.activewordlistrules = str_alloc_copy(SUBSECTION_WORDLIST);

	if (options.loader.activesinglerules == NULL)
		options.loader.activesinglerules = str_alloc_copy(SUBSECTION_SINGLE);

	if (options.dynamic_raw_hashes_always_valid == 'Y' || options.dynamic_raw_hashes_always_valid == 'y' || 
		options.dynamic_raw_hashes_always_valid == '1' || options.dynamic_raw_hashes_always_valid == 't' || options.dynamic_raw_hashes_always_valid == 'T')
		options.dynamic_raw_hashes_always_valid = 'Y';
	else if (options.dynamic_raw_hashes_always_valid == 'N' || options.dynamic_raw_hashes_always_valid == 'n' || 
		options.dynamic_raw_hashes_always_valid == '0' || options.dynamic_raw_hashes_always_valid == 'f' || options.dynamic_raw_hashes_always_valid == 'F')
		options.dynamic_raw_hashes_always_valid = 'N';

	options.loader.regen_lost_salts = options.regen_lost_salts;

	if (field_sep_char_string != NULL)
	{
		if (!strcasecmp(field_sep_char_string, "tab")) // Literal tab or TAB will mean 0x09 tab character
			field_sep_char_string = "\x09";
		if (strlen(field_sep_char_string) == 1)
			options.field_sep_char = *field_sep_char_string;
		else if (field_sep_char_string[0] == '\\' && (field_sep_char_string[1]=='x'||field_sep_char_string[1]=='X'))
		{
			unsigned xTmp=0;
			sscanf(&field_sep_char_string[2], "%x", &xTmp);
			if (!xTmp || xTmp > 255)
			{
#ifdef HAVE_MPI
				if (mpi_id == 0)
#endif
				fprintf (stderr, "trying to use an invalid field separator char:  %s\n", field_sep_char_string);
				error();
			}
			options.field_sep_char = (char)xTmp;
		}

		options.loader.field_sep_char = options.field_sep_char;
		if (options.loader.field_sep_char != ':')
#ifdef HAVE_MPI
			if (mpi_id == 0)
#endif
			fprintf (stderr, "using field sep char '%c' (0x%02x)\n", options.field_sep_char, options.field_sep_char);
	}

	rec_argc = argc; rec_argv = argv;
	rec_check = 0;
}
