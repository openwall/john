/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-99 by Solar Designer
 */

/*
 * Cracking algorithm benchmark.
 */

#ifndef _JOHN_BENCH_H
#define _JOHN_BENCH_H

#include <time.h>

#include "arch.h"
#include "formats.h"

/*
 * Structure used to return benchmark results.
 */
struct bench_results {
/* Elapsed real and processor time */
	clock_t real, virtual;

/* Number of passwords tried */
	unsigned ARCH_WORD count;
};

/*
 * Benchmarks the supplied cracking algorithm. Returns NULL on success,
 * an error message if the self test fails or there're no test vectors
 * for this algorithm, or an empty string if aborted.
 */
extern char *benchmark_format(struct fmt_main *format, int salts,
	struct bench_results *results);

/*
 * Converts benchmarked c/s into an ASCII string.
 */
extern void benchmark_cps(unsigned ARCH_WORD count, clock_t time,
	char *buffer);

/*
 * Benchmarks all the registered cracking algorithms and prints the results
 * to stdout.
 */
extern void benchmark_all(void);

#endif
