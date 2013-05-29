/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2013 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#define NEED_OS_FORK
#include "os.h"

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
#include "john.h"

struct options_main options;

static struct opt_entry opt_list[] = {
	{"", FLG_PASSWD, 0, 0, 0, OPT_FMT_ADD_LIST, &options.passwd},
	{"single", FLG_SINGLE_SET, FLG_CRACKING_CHK},
	{"wordlist", FLG_WORDLIST_SET, FLG_CRACKING_CHK,
		0, OPT_REQ_PARAM, OPT_FMT_STR_ALLOC, &options.wordlist},
	{"stdin", FLG_STDIN_SET, FLG_CRACKING_CHK},
	{"rules", FLG_RULES, FLG_RULES, FLG_WORDLIST_CHK, FLG_STDIN_CHK},
	{"incremental", FLG_INC_SET, FLG_CRACKING_CHK,
		0, 0, OPT_FMT_STR_ALLOC, &options.charset},
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
		0, ~FLG_STATUS_SET & ~OPT_REQ_PARAM,
		OPT_FMT_STR_ALLOC, &options.session},
	{"make-charset", FLG_MAKECHR_SET, FLG_MAKECHR_CHK,
		0, FLG_CRACKING_CHK | FLG_SESSION | OPT_REQ_PARAM,
		OPT_FMT_STR_ALLOC, &options.charset},
	{"show", FLG_SHOW_SET, FLG_SHOW_CHK,
		0, FLG_CRACKING_SUP | FLG_MAKECHR_CHK},
	{"test", FLG_TEST_SET, FLG_TEST_CHK,
		0, ~FLG_TEST_SET & ~FLG_FORMAT & ~FLG_SAVEMEM & ~OPT_REQ_PARAM,
		"%u", &benchmark_time},
	{"users", FLG_NONE, 0, FLG_PASSWD, OPT_REQ_PARAM,
		OPT_FMT_ADD_LIST_MULTI, &options.loader.users},
	{"groups", FLG_NONE, 0, FLG_PASSWD, OPT_REQ_PARAM,
		OPT_FMT_ADD_LIST_MULTI, &options.loader.groups},
	{"shells", FLG_NONE, 0, FLG_PASSWD, OPT_REQ_PARAM,
		OPT_FMT_ADD_LIST_MULTI, &options.loader.shells},
	{"salts", FLG_SALTS, FLG_SALTS, FLG_PASSWD, OPT_REQ_PARAM,
		"%d", &options.loader.min_pps},
	{"save-memory", FLG_SAVEMEM, FLG_SAVEMEM, 0, OPT_REQ_PARAM,
		"%u", &mem_saving_level},
	{"node", FLG_NODE, FLG_NODE, FLG_CRACKING_CHK, OPT_REQ_PARAM,
		OPT_FMT_STR_ALLOC, &options.node_str},
#if OS_FORK
	{"fork", FLG_FORK, FLG_FORK,
		FLG_CRACKING_CHK, FLG_STDIN_CHK | FLG_STDOUT | OPT_REQ_PARAM,
		"%u", &options.fork},
#endif
	{"format", FLG_FORMAT, FLG_FORMAT,
		0, FLG_STDOUT | OPT_REQ_PARAM,
		OPT_FMT_STR_ALLOC, &options.format},
	{NULL}
};

#define JOHN_COPYRIGHT "Solar Designer"

#if OS_FORK
#define JOHN_USAGE_FORK \
"--fork=N                   fork N processes\n"
#else
#define JOHN_USAGE_FORK ""
#endif

#define JOHN_USAGE \
"John the Ripper password cracker, version " JOHN_VERSION "\n" \
"Copyright (c) 1996-2013 by " JOHN_COPYRIGHT "\n" \
"Homepage: http://www.openwall.com/john/\n" \
"\n" \
"Usage: %s [OPTIONS] [PASSWORD-FILES]\n" \
"--single                   \"single crack\" mode\n" \
"--wordlist=FILE --stdin    wordlist mode, read words from FILE or stdin\n" \
"--rules                    enable word mangling rules for wordlist mode\n" \
"--incremental[=MODE]       \"incremental\" mode [using section MODE]\n" \
"--external=MODE            external mode or word filter\n" \
"--stdout[=LENGTH]          just output candidate passwords [cut at LENGTH]\n" \
"--restore[=NAME]           restore an interrupted session [called NAME]\n" \
"--session=NAME             give a new session the NAME\n" \
"--status[=NAME]            print status of a session [called NAME]\n" \
"--make-charset=FILE        make a charset, FILE will be overwritten\n" \
"--show                     show cracked passwords\n" \
"--test[=TIME]              run tests and benchmarks for TIME seconds each\n" \
"--users=[-]LOGIN|UID[,..]  [do not] load this (these) user(s) only\n" \
"--groups=[-]GID[,..]       load users [not] of this (these) group(s) only\n" \
"--shells=[-]SHELL[,..]     load users with[out] this (these) shell(s) only\n" \
"--salts=[-]N               load salts with[out] at least N passwords only\n" \
"--save-memory=LEVEL        enable memory saving, at LEVEL 1..3\n" \
"--node=MIN[-MAX]/TOTAL     this node's number range out of TOTAL count\n" \
JOHN_USAGE_FORK \
"--format=NAME              force hash type NAME: "

#define JOHN_USAGE_INDENT \
"                           "

static void print_usage(char *name)
{
	int column;
	struct fmt_main *format;

	printf(JOHN_USAGE, name);

	column = strrchr(JOHN_USAGE, '\0') - strrchr(JOHN_USAGE, '\n') - 1;
	format = fmt_list;
	do {
		char *label = format->params.label;
		int length = strlen(label) + (format->next != NULL);
		column += length;
		if (column > 80) {
			printf("\n" JOHN_USAGE_INDENT);
			column = strlen(JOHN_USAGE_INDENT) + length;
		}
		printf("%s%c", label, format->next ? '/' : '\n');
	} while ((format = format->next));

	exit(0);
}

void opt_init(char *name, int argc, char **argv)
{
	if (argc < 2)
		print_usage(name);

	memset(&options, 0, sizeof(options));

	list_init(&options.passwd);

	options.loader.flags = DB_LOGIN;
	list_init(&options.loader.users);
	list_init(&options.loader.groups);
	list_init(&options.loader.shells);

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
#if OS_FORK
		char *rec_name_orig = rec_name;
#endif
		rec_restore_args(1);
#if OS_FORK
		if (options.fork) {
			rec_name = rec_name_orig;
			rec_name_completed = 0;
		}
#endif
		return;
	}

	if (options.flags & FLG_STATUS_CHK) {
#if OS_FORK
		char *rec_name_orig = rec_name;
#endif
		rec_restore_args(0);
		options.flags |= FLG_STATUS_SET;
		status_init(NULL, 1);
		status_print();
#if OS_FORK
		if (options.fork) {
			unsigned int i;
			for (i = 2; i <= options.fork; i++) {
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
					status_print();
			}
		}
#endif
		exit(0);
	}

	if (options.flags & FLG_SALTS)
	if (options.loader.min_pps < 0) {
		options.loader.max_pps = -1 - options.loader.min_pps;
		options.loader.min_pps = 0;
	}

	if (options.length < 0)
		options.length = PLAINTEXT_BUFFER_SIZE - 3;
	else
	if (options.length < 1 || options.length > PLAINTEXT_BUFFER_SIZE - 3) {
		fprintf(stderr, "Invalid plaintext length requested\n");
		error();
	}

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
		}
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
		else if (options.fork &&
		    options.node_max - options.node_min + 1 != options.fork)
			msg = "range must be consistent with --fork number";
#endif
		else if (!options.fork &&
		    options.node_max - options.node_min + 1 ==
		    options.node_count)
			msg = "node numbers can't span the whole range";
		if (msg) {
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

	if ((options.flags & (FLG_PASSWD | FLG_PWD_REQ)) == FLG_PWD_REQ) {
		fprintf(stderr, "Password files required, "
			"but none specified\n");
		error();
	}

	if ((options.flags & (FLG_PASSWD | FLG_PWD_SUP)) == FLG_PASSWD) {
		fprintf(stderr, "Password files specified, "
			"but no option would use them\n");
		error();
	}

	rec_argc = argc; rec_argv = argv;
	rec_check = 0;
}
