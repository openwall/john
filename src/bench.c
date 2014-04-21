/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2003,2004,2006,2008-2012 by Solar Designer
 *
 * ...with changes in the jumbo patch, by JimF and magnum
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#define _BSD_SOURCE /* for setenv() */

#if defined (__MINGW32__) || defined (_MSC_VER)
#define SIGALRM SIGFPE
#endif

#ifdef __ultrix__
#define __POSIX
#define _POSIX_SOURCE
#endif

#define NEED_OS_TIMER
#include "os.h"

#ifdef _SCO_C_DIALECT
#include <limits.h>
#endif
#include <stdio.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>
#include <signal.h>
#include <time.h>
#if HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#if HAVE_SYS_TIMES_H
#include <sys/times.h>
#endif
#include <stdlib.h> /* setenv */

#include "times.h"

#include "arch.h"
#include "misc.h"
#include "math.h"
#include "params.h"
#include "memory.h"
#include "signals.h"
#include "formats.h"
#include "bench.h"
#include "john.h"
#include "unicode.h"

#ifndef BENCH_BUILD
#include "options.h"
#endif

#ifdef HAVE_MPI
#include "john-mpi.h"
#include "config.h"
#endif /* HAVE_MPI */

#ifdef _OPENMP
#include <omp.h>
#endif /* _OPENMP */
#include "memdbg.h"

long clk_tck = 0;

void clk_tck_init(void)
{
	if (clk_tck) return;

#if defined(_SC_CLK_TCK) || !defined(CLK_TCK)
	clk_tck = sysconf(_SC_CLK_TCK);
#else
	clk_tck = CLK_TCK;
#endif
}

unsigned int benchmark_time = BENCHMARK_TIME;

volatile int bench_running;

static void bench_install_handler(void);

static void bench_handle_timer(int signum)
{
	bench_running = 0;
#ifndef SA_RESTART
	bench_install_handler();
#endif
}

static void bench_install_handler(void)
{
#ifdef SA_RESTART
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = bench_handle_timer;
	sa.sa_flags = SA_RESTART;
	sigaction(SIGALRM, &sa, NULL);
#else
	signal(SIGALRM, bench_handle_timer);
#endif
}

static void bench_set_keys(struct fmt_main *format,
	struct fmt_tests *current, int cond)
{
	char *plaintext;
	int index, length;

	format->methods.clear_keys();

	length = format->params.benchmark_length;
	for (index = 0; index < format->params.max_keys_per_crypt; index++) {
		do {
			if (!current->ciphertext)
				current = format->params.tests;
			plaintext = current->plaintext;
			current++;

			if (cond > 0) {
				if ((int)strlen(plaintext) > length) break;
			} else
			if (cond < 0) {
				if ((int)strlen(plaintext) <= length) break;
			} else
				break;
		} while (1);

		format->methods.set_key(plaintext, index);
	}
}

char *benchmark_format(struct fmt_main *format, int salts,
	struct bench_results *results)
{
	static void *binary = NULL;
	static int binary_size = 0;
	static char s_error[128];
	char *TmpPW[1024];
	int pw_mangled=0;
	char *where;
	struct fmt_tests *current;
	int cond;
#if OS_TIMER
	struct itimerval it;
#endif
	clock_t start_real, end_real;
#if !defined (__MINGW32__) && !defined (_MSC_VER)
	clock_t start_virtual, end_virtual;
	struct tms buf;
#endif
	int64 crypts;
	char *ciphertext;
	void *salt, *two_salts[2];
	int index, max;

	clk_tck_init();

	if (!(current = format->params.tests)) return "FAILED (no data)";
	if ((where = fmt_self_test(format))) {
		sprintf(s_error, "FAILED (%s)\n", where);
		return s_error;
	}
	if (!current->ciphertext && !current->plaintext)  return "FAILED (no data)";

	if (format->params.binary_size > binary_size) {
		binary_size = format->params.binary_size;
		binary = mem_alloc_tiny(binary_size, MEM_ALIGN_WORD);
		memset(binary, 0x55, binary_size);
	}

	for (index = 0; index < 2; index++) {
		two_salts[index] = mem_alloc(format->params.salt_size);

		if ((ciphertext = format->params.tests[index].ciphertext)) {
			char **fields = format->params.tests[index].fields;
			if (!fields[1])
				fields[1] = ciphertext;
			ciphertext = format->methods.split(
			    format->methods.prepare(fields, format), 0, format);
			salt = format->methods.salt(ciphertext);
		} else
			salt = two_salts[0];

		memcpy(two_salts[index], salt, format->params.salt_size);
	}
	format->methods.set_salt(two_salts[0]);

	if (format->params.benchmark_length > 0) {
		cond = (salts == 1) ? 1 : -1;
		salts = 1;
	} else {
		cond = 0;
		if (format->params.benchmark_length < -950) {
			/* smash the passwords */
			struct fmt_tests *current = format->params.tests;
			int i=0;
			pw_mangled = 1;
			while (current->ciphertext) {
				if (current->plaintext[0]) {
					TmpPW[i] = str_alloc_copy(current->plaintext);
					TmpPW[i][0] ^= 5;
					current->plaintext = TmpPW[i++];
				}
				++current;
			}
			/* -1001 turns into -1 and -1000 turns into 0 , and -999 turns into 1 for benchmark length */
			format->params.benchmark_length += 1000;
			if (format->params.benchmark_length > 0) {
				cond = (salts == 1) ? 1 : -1;
				salts = 1;
			}
		}
	}

	bench_set_keys(format, current, cond);

#if OS_TIMER
	memset(&it, 0, sizeof(it));
	if (setitimer(ITIMER_REAL, &it, NULL)) pexit("setitimer");
#endif

	bench_running = 1;
	bench_install_handler();

/* Cap it at a sane value to hopefully avoid integer overflows below */
	if (benchmark_time > 3600)
		benchmark_time = 3600;

#if OS_TIMER
	if (!(it.it_value.tv_sec = benchmark_time)) {
/* Use exactly one tick for reasonable precision, but no less than 1 ms */
		if ((it.it_value.tv_usec = 1000000 / clk_tck) < 1000)
			it.it_value.tv_usec = 1000; /* 1 ms */
	}
	if (setitimer(ITIMER_REAL, &it, NULL)) pexit("setitimer");
#else
	sig_timer_emu_init(benchmark_time * clk_tck);
#endif

#if defined (__MINGW32__) || defined (_MSC_VER)
	start_real = clock();
#else
	start_real = times(&buf);
	start_virtual = buf.tms_utime + buf.tms_stime;
	start_virtual += buf.tms_cutime + buf.tms_cstime;
#endif
	crypts.lo = crypts.hi = 0;

	index = salts;
	max = format->params.max_keys_per_crypt;
	do {
		int count = max;

		if (!--index) {
			index = salts;
			if (!(++current)->ciphertext)
				current = format->params.tests;
			bench_set_keys(format, current, cond);
		}

		if (salts > 1) format->methods.set_salt(two_salts[index & 1]);
		format->methods.cmp_all(binary,
		    format->methods.crypt_all(&count, NULL));

		add32to64(&crypts, count);
#if !OS_TIMER
		sig_timer_emu_tick();
#endif
	} while (bench_running && !event_abort);

#if defined (__MINGW32__) || defined (_MSC_VER)
	end_real = clock();
#else
	end_real = times(&buf);
	if (end_real == start_real) end_real++;

	end_virtual = buf.tms_utime + buf.tms_stime;
	end_virtual += buf.tms_cutime + buf.tms_cstime;
	if (end_virtual == start_virtual) end_virtual++;
	results->virtual = end_virtual - start_virtual;
#endif

	results->real = end_real - start_real;
	results->crypts = crypts;

	// if left at 0, we get a / by 0 later.  I have seen this happen on -test=0 runs.
	if (results->real == 0)
		results->real = 1;
#if defined (__MINGW32__) || defined (_MSC_VER)
	results->virtual = results->real;
#endif

	for (index = 0; index < 2; index++)
		MEM_FREE(two_salts[index]);

	/* unsmash the passwords */
	if (pw_mangled) {
		struct fmt_tests *current = format->params.tests;
		int i=0;
		while (current->ciphertext) {
			if (current->plaintext[0]) {
				TmpPW[i][0] ^= 5;
				current->plaintext = TmpPW[i++];
			}
			++current;
		}
		/* -1001 turns into -1 and -1000 turns into 0 , and -999 turns into 1 for benchmark length */
		format->params.benchmark_length -= 1000;
	}

	return event_abort ? "" : NULL;
}

void benchmark_cps(int64 *crypts, clock_t time, char *buffer)
{
	unsigned long long cps;

	cps = ((unsigned long long)crypts->hi << 32) + crypts->lo;
	cps *= clk_tck;
	cps /= time;

	if (cps >= 1000000000000ULL)
		sprintf(buffer, "%lluG", cps / 1000000000ULL);
	if (cps >= 1000000000)
		sprintf(buffer, "%lluM", cps / 1000000);
	else
	if (cps >= 1000000)
		sprintf(buffer, "%lluK", cps / 1000);
	else
	if (cps >= 100)
		sprintf(buffer, "%llu", cps);
	else {
		cps = ((unsigned long long)crypts->hi << 32) + crypts->lo;
		cps *= clk_tck * 10;
		cps /= time;
		sprintf(buffer, "%llu.%llu", cps / 10, cps % 10);
	}
}

#ifdef HAVE_MPI
void gather_results(struct bench_results *results)
{
	struct bench_results combined;

	MPI_Reduce(&results->real, &combined.real, 1, MPI_LONG,
		MPI_SUM, 0, MPI_COMM_WORLD);
	MPI_Reduce(&results->virtual, &combined.virtual, 1, MPI_LONG,
		MPI_SUM, 0, MPI_COMM_WORLD);
	MPI_Reduce(&results->crypts.lo, &combined.crypts.lo, 1, MPI_UNSIGNED,
		MPI_SUM, 0, MPI_COMM_WORLD);
	MPI_Reduce(&results->crypts.hi, &combined.crypts.hi, 1, MPI_UNSIGNED,
		MPI_SUM, 0, MPI_COMM_WORLD);
	if (mpi_id == 0) {
		combined.real /= mpi_p;
		combined.virtual /= mpi_p;
		memcpy(results, &combined, sizeof(struct bench_results));
	}
}
#endif

int benchmark_all(void)
{
	struct fmt_main *format;
	char *result, *msg_1, *msg_m;
	struct bench_results results_1, results_m;
	char s_real[64], s_virtual[64];
	unsigned int total, failed;
	MEMDBG_HANDLE memHand;

#ifdef _OPENMP
	int ompt;
	int ompt_start = omp_get_max_threads();
#endif

#if defined(HAVE_OPENCL) || defined(HAVE_CUDA)
	if (!benchmark_time) {
		/* This will make the majority of OpenCL formats
		   also do "quick" benchmarking. But if LWS or
		   GWS was already set, we do not overwrite. */
		setenv("LWS", "7", 0);
		setenv("GWS", "49", 0);
		setenv("BLOCKS", "7", 0);
		setenv("THREADS", "7", 0);
	}
#endif

	total = failed = 0;
#ifndef BENCH_BUILD
	options.loader.field_sep_char = 31;
#endif
	if ((format = fmt_list))
	do {
		memHand = MEMDBG_getSnapshot(0);
#ifndef BENCH_BUILD
/* Silently skip formats for which we have no tests, unless forced */
		if (!format->params.tests && format != fmt_list)
			continue;

/* Just test the encoding-aware formats if --encoding was used explicitly */
		if (!pers_opts.default_enc && pers_opts.target_enc != ASCII &&
		    pers_opts.target_enc != ISO_8859_1 &&
		    !(format->params.flags & FMT_UTF8)) {
			if (options.format == NULL ||
			    strcasecmp(format->params.label, options.format))
				continue;
			else {
				if (format->params.flags & FMT_UNICODE) {
					if (john_main_process)
						printf("The %s format does not yet support encodings other than ISO-8859-1\n\n", format->params.label);
					continue;
				}
			}
		}
#endif

		fmt_init(format);
#ifdef _OPENMP
		// format's init() or MPIOMPmutex may have capped the number of threads
		ompt = omp_get_max_threads();
#endif /* _OPENMP */

#ifdef HAVE_MPI
		if (john_main_process)
#endif
		printf("%s: %s%s%s%s [%s]%s... ",
		    benchmark_time ? "Benchmarking" : "Testing",
		    format->params.label,
		    format->params.format_name[0] ? ", " : "",
		    format->params.format_name,
		    format->params.benchmark_comment,
		    format->params.algorithm_name,
#ifndef BENCH_BUILD
			(pers_opts.target_enc == UTF_8 &&
			 format->params.flags & FMT_UNICODE) ?
		        " in UTF-8 mode" : "");
#else
			"");
#endif
		fflush(stdout);

#ifdef HAVE_MPI
		if (john_main_process) {
			if (mpi_p > 1) {
				printf("(%uxMPI", mpi_p);
#ifdef _OPENMP
				if (format->params.flags & FMT_OMP) {
					if (ompt > 1)
						printf(", %dxOMP", ompt);
				}
#endif /* _OPENMP */
				printf(") ");
#ifdef _OPENMP
			} else {
				if (format->params.flags & FMT_OMP && ompt > 1)
					printf("(%dxOMP) ", ompt);
#endif /* _OPENMP */
			}
			fflush(stdout);
		}
#else /* HAVE_MPI */
#ifdef _OPENMP
#ifdef HAVE_MPI
		if (john_main_process)
#endif
		if (format->params.flags & FMT_OMP && ompt > 1)
			printf("(%dxOMP) ", ompt);
		fflush(stdout);
#endif /* _OPENMP */
#endif /* HAVE_MPI */
		switch (format->params.benchmark_length) {
		case 0:
		case -1000:
			if (format->params.tests[1].ciphertext) {
				msg_m = "Many salts";
				msg_1 = "Only one salt";
				break;
			}
			/* fall through */

		case -1:
		case -1001:
			msg_m = "Raw";
			msg_1 = NULL;
			break;

		default:
			msg_m = "Short";
			msg_1 = "Long";
		}

		total++;

		if ((result = benchmark_format(format,
		    format->params.salt_size ? BENCHMARK_MANY : 1,
		    &results_m))) {
			puts(result);
			failed++;
			goto next;
		}

		if (msg_1)
		if ((result = benchmark_format(format, 1, &results_1))) {
			puts(result);
			failed++;
			goto next;
		}

#ifdef HAVE_MPI
		if (john_main_process)
#endif
			puts(benchmark_time ? "DONE" : "PASS");
#ifdef _OPENMP
		// reset this in case format capped it (we may be testing more formats)
		omp_set_num_threads(ompt_start);
#endif

#ifdef HAVE_MPI
		if (mpi_p > 1) {
			gather_results(&results_m);
			gather_results(&results_1);
		}
#endif
		benchmark_cps(&results_m.crypts, results_m.real, s_real);
		benchmark_cps(&results_m.crypts, results_m.virtual, s_virtual);
#if !defined(__DJGPP__) && !defined(__BEOS__) && !defined(__MINGW32__) && !defined (_MSC_VER)
#ifdef HAVE_MPI
		if (john_main_process)
#endif
		if (benchmark_time)
		printf("%s:\t%s c/s real, %s c/s virtual\n",
			msg_m, s_real, s_virtual);
#else
#ifdef HAVE_MPI
		if (john_main_process)
#endif
		if (benchmark_time)
		printf("%s:\t%s c/s\n",
			msg_m, s_real);
#endif

		if (!msg_1) {
#ifdef HAVE_MPI
			if (john_main_process)
#endif
			if (benchmark_time)
			putchar('\n');
			goto next;
		}

		benchmark_cps(&results_1.crypts, results_1.real, s_real);
		benchmark_cps(&results_1.crypts, results_1.virtual, s_virtual);
#ifdef HAVE_MPI
		if (john_main_process)
#endif
#if !defined(__DJGPP__) && !defined(__BEOS__) && !defined(__MINGW32__) && !defined (_MSC_VER)
		if (benchmark_time)
		printf("%s:\t%s c/s real, %s c/s virtual\n\n",
			msg_1, s_real, s_virtual);
#else
		if (benchmark_time)
		printf("%s:\t%s c/s\n\n",
			msg_1, s_real);
#endif

next:
		fmt_done(format);
		MEMDBG_checkSnapshot_possible_exit_on_error(memHand, 0);

#ifndef BENCH_BUILD
		/* In case format changed it */
		initUnicode(UNICODE_UNICODE);
#endif
	} while ((format = format->next) && !event_abort);

	if (failed && total > 1 && !event_abort)
		printf("%u out of %u tests have FAILED\n", failed, total);
	else if (total > 1 && !event_abort)
		if (john_main_process)
			printf("All %u formats passed self-tests!\n", total);

	return failed || event_abort;
}
