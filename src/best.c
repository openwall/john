/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-99,2003,2006,2011-2013,2017 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

/*
 * Benchmark to detect the best algorithm for a particular architecture.
 */

#define NEED_OS_FORK
#include "os.h"

#include <stdint.h>
#include <stdio.h>
#include <time.h>

#include "params.h"
#include "common.h"
#include "formats.h"
#include "bench.h"

extern struct fmt_main fmt_DES, fmt_MD5, fmt_BF;

int john_main_process = 0;
#if OS_FORK
int john_child_count = 0;
int *john_child_pids = NULL;
#endif

int main(int argc, char **argv)
{
	struct fmt_main *format;
	struct bench_results results;
	unsigned long virtual;
	char s_real[64], s_virtual[64];

	if (argc != 2) return 1;

	switch (argv[1][0]) {
	case '1':
		format = &fmt_DES;
		break;

	case '2':
		format = &fmt_MD5;
		break;

	case '3':
		format = &fmt_BF;
		break;

	default:
		return 1;
	}

	fprintf(stderr, "Benchmarking: %s%s%s%s [%s]... ",
	    format->params.label,
	    format->params.format_name[0] ? ", " : "",
	    format->params.format_name,
	    format->params.benchmark_comment,
	    format->params.algorithm_name);

	common_init();

	if (benchmark_format(format, BENCHMARK_MANY, &results, NULL)) {
		virtual = 0;

		fprintf(stderr, "FAILED\n");
	} else {
#ifdef _OPENMP
		virtual = results.crypts * clk_tck * 10 / results.real;
#else
		virtual = results.crypts * clk_tck * 10 / results.virtual;
#endif

		benchmark_cps(results.crypts, results.real, s_real);
		benchmark_cps(results.crypts, results.virtual, s_virtual);

		fprintf(stderr, "%s c/s real, %s c/s virtual\n",
			s_real, s_virtual);
	}

	fmt_done(format);

	printf("%lu\n", virtual);

	return virtual ? 0 : 1;
}
