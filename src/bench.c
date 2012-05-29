/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2003,2004,2006,2008-2010,2011 by Solar Designer
 *
 * ...with changes in the jumbo patch, by JimF and magnum
 */

#define _XOPEN_SOURCE 500 /* for setitimer(2) */

#if defined (__MINGW32__) || defined (_MSC_VER)
#define SIGALRM SIGFPE
#endif

#ifdef __ultrix__
#define __POSIX
#define _POSIX_SOURCE
#endif

#ifdef _SCO_C_DIALECT
#include <limits.h>
#endif
#include <stdio.h>
#ifndef _MSC_VER
#include <unistd.h>
#endif
#include <string.h>
#include <signal.h>
#include <time.h>
#ifndef _MSC_VER
#include <sys/time.h>
#endif
#if !defined (__MINGW32__) && !defined (_MSC_VER)
#include <sys/times.h>
#endif

#include "times.h"

#include "arch.h"
#include "misc.h"
#include "math.h"
#include "params.h"
#include "memory.h"
#include "signals.h"
#include "formats.h"
#include "bench.h"

#ifndef _JOHN_BENCH_TMP
#include "options.h"
#endif

#ifdef HAVE_MPI
#include "john-mpi.h"
#include "config.h"
#endif /* HAVE_MPI */

#ifdef _OPENMP
#include <omp.h>
#endif /* _OPENMP */

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

static volatile int bench_running;

static void bench_handle_timer(int signum)
{
	bench_running = 0;
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
	static char s_error[64];
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
	int64 count;
	char *ciphertext;
	void *salt, *two_salts[2];
	int index, max;

	clk_tck_init();

	if (!(current = format->params.tests)) return "FAILED (no data)";
	if ((where = fmt_self_test(format))) {
		sprintf(s_error, "FAILED (%s)", where);
		return s_error;
	}

	if (format->params.binary_size > binary_size) {
		binary_size = format->params.binary_size;
		binary = mem_alloc_tiny(binary_size, MEM_ALIGN_WORD);
		memset(binary, 0x55, binary_size);
	}

	for (index = 0; index < 2; index++) {
		two_salts[index] = mem_alloc(format->params.salt_size);

		if ((ciphertext = format->params.tests[index].ciphertext)) {
			char *prepared;
			current->flds[1] = current->ciphertext;
			prepared = format->methods.prepare(current->flds, format);
			ciphertext = format->methods.split(prepared, 0);
			salt = format->methods.salt(ciphertext);
		}
		else
			salt = two_salts[0];

		memcpy(two_salts[index], salt, format->params.salt_size);
	}

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
	signal(SIGALRM, bench_handle_timer);

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
	count.lo = count.hi = 0;

	index = salts;
	max = format->params.max_keys_per_crypt;
	do {
		if (!--index) {
			index = salts;
			if (!(++current)->ciphertext)
				current = format->params.tests;
			bench_set_keys(format, current, cond);
		}

		if (salts > 1) format->methods.set_salt(two_salts[index & 1]);
		format->methods.crypt_all(max);
		format->methods.cmp_all(binary, max);

		add32to64(&count, max);
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
	results->count = count;

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

void benchmark_cps(int64 *count, clock_t time, char *buffer)
{
	unsigned int cps_hi, cps_lo;
	int64 tmp;

	tmp = *count;
	mul64by32(&tmp, clk_tck);
	cps_hi = div64by32lo(&tmp, time);

	if (cps_hi >= 1000000000)
		sprintf(buffer, "%uM", cps_hi / 1000000);
	else
	if (cps_hi >= 1000000)
		sprintf(buffer, "%uK", cps_hi / 1000);
	else
	if (cps_hi >= 100)
		sprintf(buffer, "%u", cps_hi);
	else {
		mul64by32(&tmp, 10);
		cps_lo = div64by32lo(&tmp, time) % 10;
		sprintf(buffer, "%u.%u", cps_hi, cps_lo);
	}
}

#ifdef HAVE_MPI
void gather_results(struct bench_results *results)
{
	struct bench_results combined;
	MPI_Reduce(&results->real, &combined.real, 1, MPI_LONG,
		MPI_MAX, 0, MPI_COMM_WORLD);
	MPI_Reduce(&results->virtual, &combined.virtual, 1, MPI_LONG,
		MPI_MAX, 0, MPI_COMM_WORLD);
	MPI_Reduce(&results->count, &combined.count, 1, MPI_UNSIGNED_LONG,
		MPI_SUM, 0, MPI_COMM_WORLD);
	if (mpi_id == 0)
		memcpy(results, &combined, sizeof(struct bench_results));
}
#endif

int benchmark_all(void)
{
	struct fmt_main *format;
	char *result, *msg_1, *msg_m;
	struct bench_results results_1, results_m;
	char s_real[64], s_virtual[64];
	unsigned int total, failed;
#ifdef _OPENMP
	int ompt;
	int ompt_start = omp_get_max_threads();
#ifdef HAVE_MPI
	static int haveWarned = 0;
#endif
#endif

	if (!benchmark_time)
		puts("Warning: doing quick benchmarking - "
		    "the performance numbers will be inaccurate");

	total = failed = 0;
#ifndef _JOHN_BENCH_TMP
	options.field_sep_char = 31;
#endif
	if ((format = fmt_list))
	do {
#ifndef _JOHN_BENCH_TMP
/* Silently skip DIGEST-MD5 (for which we have no tests), unless forced */
		if (!format->params.tests && format != fmt_list)
			continue;

/* Just test the UTF-8 aware formats if --encoding=utf8 */
		if ((options.utf8) && !(format->params.flags & FMT_UTF8)) {
			if (options.format == NULL)
				continue;
			else {
				if (format->params.flags & FMT_UNICODE) {
					printf("The %s format does not yet support UTF-8 conversion.\n\n", format->params.label);
					continue;
				}
				else {
					printf("The %s format does not use internal charset conversion (--encoding=utf8 option).\n\n", format->params.label);
					continue;
				}
			}
		}
#endif

#if defined(HAVE_MPI) && defined(_OPENMP)
		if (format->params.flags & FMT_OMP &&
		    ompt_start > 1 && mpi_p > 1 && haveWarned++ == 0) {
			if(cfg_get_bool(SECTION_OPTIONS, SUBSECTION_MPI, "MPIOMPmutex", 1)) {
				omp_set_num_threads(1);
				ompt_start = 1;
				if(cfg_get_bool(SECTION_OPTIONS, SUBSECTION_MPI, "MPIOMPverbose", 1) &&
				   mpi_id == 0) {
					printf("MPI in use, disabling OMP (see doc/README.mpi)\n\n");
				}
			} else {
				if(cfg_get_bool(SECTION_OPTIONS, SUBSECTION_MPI, "MPIOMPverbose", 1) &&
				   mpi_id == 0) {
					printf("Note: Running both MPI and OMP (see doc/README.mpi)\n\n");
				}
			}
		}
#endif
		fmt_init(format);
#ifdef _OPENMP
		// format's init() or MPIOMPmutex may have capped the number of threads
		ompt = omp_get_max_threads();
#endif /* _OPENMP */

		printf("Benchmarking: %s%s [%s]%s... ",
			format->params.format_name,
			format->params.benchmark_comment,
			format->params.algorithm_name,
#ifndef _JOHN_BENCH_TMP
			(options.utf8) ? " in UTF-8 mode" : "");
#else
			"");
#endif
		fflush(stdout);

#ifdef HAVE_MPI
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
#else /* HAVE_MPI */
#ifdef _OPENMP
		if (format->params.flags & FMT_OMP && ompt > 1)
			printf("(%dxOMP) ", ompt);
		fflush(stdout);
#endif /* _OPENMP */
#endif /* HAVE_MPI */
		switch (format->params.benchmark_length) {
		case -1:
		case -1001:
			msg_m = "Raw";
			msg_1 = NULL;
			break;

		case 0:
		case -1000:
			msg_m = "Many salts";
			msg_1 = "Only one salt";
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
			continue;
		}

		if (msg_1)
		if ((result = benchmark_format(format, 1, &results_1))) {
			puts(result);
			failed++;
			continue;
		}

		puts("DONE");
#ifdef _OPENMP
		// reset this in case format capped it (we may be running more formats)
		omp_set_num_threads(ompt_start);
#endif

#ifdef HAVE_MPI
		if (mpi_p > 1) {
			gather_results(&results_m);
			gather_results(&results_1);
		}
#endif
		benchmark_cps(&results_m.count, results_m.real, s_real);
		benchmark_cps(&results_m.count, results_m.virtual, s_virtual);
#if !defined(__DJGPP__) && !defined(__BEOS__) && !defined(__MINGW32__) && !defined (_MSC_VER)
		printf("%s:\t%s c/s real, %s c/s virtual\n",
			msg_m, s_real, s_virtual);
#else
		printf("%s:\t%s c/s\n",
			msg_m, s_real);
#endif

		if (!msg_1) {
			putchar('\n');
			continue;
		}

		benchmark_cps(&results_1.count, results_1.real, s_real);
		benchmark_cps(&results_1.count, results_1.virtual, s_virtual);
#if !defined(__DJGPP__) && !defined(__BEOS__) && !defined(__MINGW32__) && !defined (_MSC_VER)
		printf("%s:\t%s c/s real, %s c/s virtual\n\n",
			msg_1, s_real, s_virtual);
#else
		printf("%s:\t%s c/s\n\n",
			msg_1, s_real);
#endif
	} while ((format = format->next) && !event_abort);

	if (failed && total > 1 && !event_abort)
		printf("%u out of %u tests have FAILED\n", failed, total);

	return failed || event_abort;
}
