/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-99,2006,2009,2011,2012,2017 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

/*
 * Cracking algorithm benchmark.
 */

#ifndef _JOHN_BENCH_H
#define _JOHN_BENCH_H

#include <stdint.h>
#include <time.h>

#include "arch.h"
#include "formats.h"

/*
 * Structure used to return benchmark results.
 */
struct bench_results {
/* Elapsed real and processor time */
	clock_t real, virtual;

/* Number of ciphertexts computed */
	uint64_t crypts;

/* Number of salts actually tested */
	int salts_done;
};

/*
 * Clock ticks per second - either as obtained via sysconf(_SC_CLK_TCK)
 * or the constant CLK_TCK or (MinGW/MVC) CLOCKS_PER_SEC
 */
extern long clk_tck;

/*
 * Initializes clk_tck on the first invocation; does nothing afterwards.
 */
extern void clk_tck_init(void);

/*
 * Benchmark time in seconds (per cracking algorithm).
 */
extern int benchmark_time;
extern int benchmark_level;  /* for full test */

/*
 * Benchmarks the supplied cracking algorithm. Returns NULL on success,
 * an error message if the self-test fails or there are no test vectors
 * for this algorithm, or an empty string if aborted.
 */
extern char *benchmark_format(struct fmt_main *format, int salts,
	struct bench_results *results, struct db_main *db);

/*
 * Converts benchmarked c/s into an ASCII string.
 */
extern void benchmark_cps(uint64_t crypts, clock_t time, char *buffer);

/*
 * Benchmarks all the registered cracking algorithms and prints the results
 * to stdout. Returns zero on success, non-zero if any tests failed or were
 * aborted.
 */
extern int benchmark_all(void);

#endif
