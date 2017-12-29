/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2003,2004,2006,2008-2012,2015,2017 by Solar Designer
 *
 * ...with changes in the jumbo patch, by JimF and magnum
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#define _BSD_SOURCE /* for setenv() */
#define _DEFAULT_SOURCE 1 /* for setenv() */

#if defined (__MINGW32__) || defined (_MSC_VER)
#define SIGALRM SIGFPE
#endif

#define NEED_OS_TIMER
#include "os.h"

#include <stdint.h>
#include <stdio.h>
#if (!AC_BUILT || HAVE_UNISTD_H) && !_MSC_VER
#include <unistd.h>
#endif
#include <string.h>
#include <signal.h>
#include <time.h>
#include <assert.h>
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
#include "params.h"
#include "memory.h"
#include "signals.h"
#include "formats.h"
#include "dyna_salt.h"
#include "bench.h"
#include "john.h"
#include "unicode.h"
#include "config.h"
#include "common-gpu.h"
#include "mask.h"

#ifndef BENCH_BUILD
#include "options.h"
#else
/*
 * This code was copied from loader.c.  It has been stripped to bare bones
 * to get what is 'needed' for the bench executable to run.
 */

static void _ldr_init_database(struct db_main *db) {
	db->loaded = 0;
	db->real = db;
	db->pw_size = sizeof(struct db_password);
	db->salt_size = sizeof(struct db_salt);
	db->pw_size -= sizeof(struct list_main *);
	db->pw_size -= sizeof(char *) * 2;
	db->salt_size -= sizeof(struct db_keys *);
	db->options = mem_calloc(sizeof(struct db_options), 1);
	db->salts = NULL;
	db->password_hash = NULL;
	db->password_hash_func = NULL;
	db->salt_hash = mem_alloc(
		SALT_HASH_SIZE * sizeof(struct db_salt *));
	memset(db->salt_hash, 0,
		SALT_HASH_SIZE * sizeof(struct db_salt *));
	db->cracked_hash = NULL;
	db->salt_count = db->password_count = db->guess_count = 0;
	db->format = NULL;
}

struct db_main *ldr_init_test_db(struct fmt_main *format, struct db_main *real)
{
	struct fmt_main *real_list = fmt_list;
	struct fmt_main fake_list;
	struct db_main *testdb;
	struct fmt_tests *current;

	if (!(current = format->params.tests))
		return NULL;

	memcpy(&fake_list, format, sizeof(struct fmt_main));
	fake_list.next = NULL;
	fmt_list = &fake_list;
	testdb = mem_alloc(sizeof(struct db_main));
	fmt_init(format);

	//ldr_init_database(testdb, &options.loader);
	_ldr_init_database(testdb);
	testdb->options->field_sep_char = ':';
	testdb->real = real;
	testdb->format = format;

	//ldr_init_password_hash(testdb);
	testdb->password_hash_func = fmt_default_binary_hash;
	testdb->password_hash = mem_alloc(password_hash_sizes[0] * sizeof(struct db_password *));
	memset(testdb->password_hash, 0, password_hash_sizes[0] * sizeof(struct db_password *));
	while (current->ciphertext) {
		char line[LINE_BUFFER_SIZE];
		int i, pos = 0;
		char *piece;
		void *salt;
		struct db_salt *current_salt, *last_salt;
		int salt_hash;
		if (!current->fields[0])
			current->fields[0] = "?";
		if (!current->fields[1])
			current->fields[1] = current->ciphertext;
		for (i = 0; i < 10; i++)
			if (current->fields[i])
				pos += sprintf(&line[pos], "%s%c",
				               current->fields[i],
				               testdb->options->field_sep_char);

		//ldr_load_pw_line(testdb, line);
		piece = format->methods.split(line, 0, format);
		salt = format->methods.salt(piece);
		salt_hash = format->methods.salt_hash(salt);
		if ((current_salt = testdb->salt_hash[salt_hash])) {
			do {
				if (!dyna_salt_cmp(current_salt->salt, salt, format->params.salt_size))
					break;
			}  while ((current_salt = current_salt->next));
		}
		if (!current_salt) {
			last_salt = testdb->salt_hash[salt_hash];
			current_salt = testdb->salt_hash[salt_hash] =
				mem_alloc_tiny(testdb->salt_size, MEM_ALIGN_WORD);
			current_salt->next = last_salt;
			current_salt->salt = mem_alloc_copy(salt,
				format->params.salt_size,
				format->params.salt_align);
			current_salt->index = fmt_dummy_hash;
			current_salt->bitmap = NULL;
			current_salt->list = NULL;
			current_salt->hash = &current_salt->list;
			current_salt->hash_size = -1;
			current_salt->count = 0;
			testdb->salt_count++;
		}
		current_salt->count++;
		testdb->password_count++;
		current++;
	}
	//ldr_fix_database(testdb);
	fmt_list = real_list;
	return testdb;
}

// lol, who cares about memory leaks here.  This is just the benchmark builder
void ldr_free_test_db(struct db_main *db)
{
}
#endif

#ifdef HAVE_MPI
#include "john-mpi.h"
#endif /* HAVE_MPI */

#ifdef _OPENMP
#include <omp.h>
#endif /* _OPENMP */
#include "memdbg.h"

#define MAX_COST_MSG_LEN 256
#ifndef BENCH_BUILD
/* the + 24 is for a little 'extra' text wrapping each line */
static char cost_msg[ (MAX_COST_MSG_LEN+24) * FMT_TUNABLE_COSTS];
#endif

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

int benchmark_time = BENCHMARK_TIME;
int benchmark_level = -1;

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
#ifndef BENCH_BUILD
	int len = format->params.plaintext_length;

	if ((len -= mask_add_len) < 0 || !(options.flags & FLG_MASK_STACKED))
		len = 0;
#endif

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

#ifndef BENCH_BUILD
		if (options.flags & FLG_MASK_CHK) {
			plaintext[len] = 0;
			if (do_mask_crack(len ? plaintext : NULL))
				return;
		} else
#endif
			format->methods.set_key(plaintext, index);
	}
}

#ifndef BENCH_BUILD
static unsigned int get_cost(struct fmt_main *format, int index, int cost_idx)
{
	void *salt;
	int value;
	char *ciphertext = format->params.tests[index].ciphertext;
	char **fields = format->params.tests[index].fields;

	if (!fields[1])
		fields[1] = ciphertext;
	ciphertext = format->methods.split(
		format->methods.prepare(fields, format), 0, format);
	salt = format->methods.salt(ciphertext);
	dyna_salt_create(salt);
	value = format->methods.tunable_cost_value[cost_idx](salt);
	dyna_salt_remove(salt);
	return value;
}
#endif

char *benchmark_format(struct fmt_main *format, int salts,
	struct bench_results *results, struct db_main *test_db)
{
	static void *binary = NULL;
	static int binary_size = 0;
	static char s_error[128];
	static int wait_salts = 0;
	char *TmpPW[1024];
	int pw_mangled = 0;
	char *where;
	struct fmt_tests *current;
	int cond;
#if OS_TIMER
	struct itimerval it;
#endif
	clock_t start_real, end_real;
	clock_t start_virtual, end_virtual;
#if !defined (__MINGW32__) && !defined (_MSC_VER)
	struct tms buf;
#endif
	uint64_t crypts;
	char *ciphertext;
	void *salt, *two_salts[2];
	int index, max, i;
#ifndef BENCH_BUILD
	unsigned int t_cost[2][FMT_TUNABLE_COSTS];
	int ntests, pruned;
#endif
	int salts_done = 0;
	int wait = 0;
	int dyna_copied = 0;

	clk_tck_init();

	if (!(current = format->params.tests) || !current->ciphertext)
		return "FAILED (no data)";

#ifndef BENCH_BUILD
	dyna_salt_init(format);

	pruned = 0;
	for (i = 0; i < FMT_TUNABLE_COSTS; i++)
	if (options.loader.min_cost[i] > 0 ||
	    options.loader.max_cost[i] < UINT_MAX) {
		unsigned int cost;

		if (format->methods.tunable_cost_value[i] == NULL) {
			sprintf(s_error,
			        "FAILED (cost %d not defined for format)\n", i);
			return s_error;
		}

		ntests = 0;
		current = format->params.tests;
		while ((current++)->ciphertext)
			ntests++;

		current = format->params.tests;
		for (index = 0; index < ntests; index++) {
			cost = get_cost(format, index, i);
			if (cost >= options.loader.min_cost[i] &&
			    cost <= options.loader.max_cost[i])
				memcpy(current++,
				       &format->params.tests[index],
				       sizeof(struct fmt_tests));
			else
				pruned++;
		}
		memset(current, 0, sizeof(struct fmt_tests));
	}

	if (pruned && !format->params.tests->ciphertext) {
		sprintf(s_error, "FAILED (--cost pruned all %d test vectors)\n",
		        pruned);
		return s_error;
	}
#endif
	if (!(current = format->params.tests) || !current->ciphertext)
		return "FAILED (no data)";
	if ((where = fmt_self_test(format, test_db))) {
		snprintf(s_error, sizeof(s_error), "FAILED (%s)\n", where);
		return s_error;
	}
	if (!current->ciphertext)
		return "FAILED (no ciphertext in test vector)";
	if (!current->plaintext)
		return "FAILED (no plaintext in test vector)";

	if (format->params.binary_size > binary_size) {
		binary_size = format->params.binary_size;
		binary = mem_alloc_tiny(binary_size, MEM_ALIGN_SIMD);
		memset(binary, 0x55, binary_size);
	}

	for (index = 0; index < 2; index++) {
		two_salts[index] = mem_alloc_align(format->params.salt_size,
		                                   format->params.salt_align);

		if ((ciphertext = format->params.tests[index].ciphertext)) {
			char **fields = format->params.tests[index].fields;
			if (!fields[1])
				fields[1] = ciphertext;
			ciphertext = format->methods.split(
			    format->methods.prepare(fields, format), 0, format);
			salt = format->methods.salt(ciphertext);
			dyna_salt_create(salt);
		} else {
			assert(index > 0);
/* If we have exactly one test vector, reuse its salt in two_salts[1] */
			salt = two_salts[0];
			dyna_copied = 1;
		}

/* mem_alloc()'ed two_salts[index] may be NULL if salt_size is 0 */
		if (format->params.salt_size)
			memcpy(two_salts[index], salt,
			    format->params.salt_size);
#ifndef BENCH_BUILD
		for (i = 0; i < FMT_TUNABLE_COSTS &&
		     format->methods.tunable_cost_value[i] != NULL; i++)
			t_cost[index][i] =
				format->methods.tunable_cost_value[i](salt);
#endif
	}
	format->methods.set_salt(two_salts[0]);

#ifndef BENCH_BUILD
	*cost_msg = 0;
	for (i = 0; i < FMT_TUNABLE_COSTS &&
		     format->methods.tunable_cost_value[i] != NULL; i++) {
		char msg[MAX_COST_MSG_LEN];

		if (t_cost[0][i] == t_cost[1][i])
			snprintf(msg, sizeof(msg), "cost %d (%s) of %u", i + 1,
			        format->params.tunable_cost_name[i],
			        t_cost[0][i]);
		else
			snprintf(msg, sizeof(msg), "cost %d (%s) of %u and %u",
			        i + 1, format->params.tunable_cost_name[i],
			        t_cost[0][i], t_cost[1][i]);

		if (i == 0)
			sprintf(cost_msg, "Speed for ");
		else
			strcat(cost_msg, ", ");
		strcat(cost_msg, msg);
	}
#endif

/* Smashed passwords: -1001 turns into -1 and -1000 turns into 0, and
   -999 turns into 1 for benchmark length. */
	if (format->params.benchmark_length < -950) {
		pw_mangled = 1;
		format->params.benchmark_length += 1000;
	}

/* Ensure we use a buffer that can be read past end of word
   (eg. SIMD optimizations). */
	i = 0;
	current = format->params.tests;
	while (current->ciphertext && i < 1024) {
		TmpPW[i] = current->plaintext;
		current->plaintext =
			strnzcpy(mem_alloc(PLAINTEXT_BUFFER_SIZE),
			         TmpPW[i++], PLAINTEXT_BUFFER_SIZE);

		/* Smash passwords! */
		if (current->plaintext[0] && pw_mangled == 1)
			current->plaintext[0] ^= 5;

		++current;
	}

	if (format->params.benchmark_length > 0) {
		cond = (salts == 1) ? 1 : -1;
		salts = 1;
	} else
		cond = 0;

	current = format->params.tests;
	bench_set_keys(format, current, cond);

#if OS_TIMER
	memset(&it, 0, sizeof(it));
	if (setitimer(ITIMER_REAL, &it, NULL)) pexit("setitimer");
#endif

	bench_running = 1;
	bench_install_handler();

/*
 * A hack. A negative time means "at least this many seconds, but wait until
 * "Many salts" have completed".
 */
	if (benchmark_time < 0) {
		wait_salts = 1;
		benchmark_time *= -1;
	}
	wait = format->params.benchmark_length ? 0 : wait_salts;

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
	start_virtual = start_real = clock();
#else
	start_real = times(&buf);
	start_virtual = buf.tms_utime + buf.tms_stime;
	start_virtual += buf.tms_cutime + buf.tms_cstime;
#endif
	crypts = 0;

	index = salts;
	max = format->params.max_keys_per_crypt;
	do {
		int count = max;

#if defined(HAVE_OPENCL)
		if (!bench_running)
			advance_cursor();
#endif
		if (!--index) {
			index = salts;
			if (!(++current)->ciphertext)
				current = format->params.tests;
			bench_set_keys(format, current, cond);
		}

		if (salts > 1) format->methods.set_salt(two_salts[index & 1]);
#ifndef BENCH_BUILD
		format->methods.cmp_all(binary,
		    format->methods.crypt_all(&count, test_db->salts));
#else
		format->methods.cmp_all(binary,
		    format->methods.crypt_all(&count, 0));
#endif

		crypts += count;
#if !OS_TIMER
		sig_timer_emu_tick();
#endif
		salts_done++;
	} while (benchmark_time &&
		 (((wait && salts_done < salts) ||
	          bench_running) && !event_abort));

#if defined (__MINGW32__) || defined (_MSC_VER)
	end_real = clock();
#else
	end_real = times(&buf);
#endif
	if (end_real == start_real) end_real++;

#if defined (__MINGW32__) || defined (_MSC_VER)
	end_virtual = end_real;
#else
	end_virtual = buf.tms_utime + buf.tms_stime;
	end_virtual += buf.tms_cutime + buf.tms_cstime;
	if (end_virtual == start_virtual) end_virtual++;
#endif

	results->real = end_real - start_real;
	results->virtual = end_virtual - start_virtual;
	results->crypts = crypts;
	results->salts_done = salts_done;

	for (index = 0; index < 2; index++) {
		if (index == 0 || !dyna_copied)
			dyna_salt_remove(two_salts[index]);
		MEM_FREE(two_salts[index]);
	}

	/* Unsmash/unbuffer the passwords. */
	i = 0;
	current = format->params.tests;
	while (current->ciphertext && i < 1024) {
		MEM_FREE(current->plaintext);
		current->plaintext = TmpPW[i++];
		++current;
	}

	if (pw_mangled)
		format->params.benchmark_length -= 1000;

	return event_abort ? "" : NULL;
}

void benchmark_cps(uint64_t crypts, clock_t time, char *buffer)
{
	unsigned int cps = crypts * clk_tck / time;
	uint64_t cpsl = crypts * clk_tck / time;

	if (cpsl >= 1000000000000ULL) {
		sprintf(buffer, "%uG", (uint32_t)(cpsl / 1000000000ULL));
	} else if (cpsl >= 1000000000) {
		sprintf(buffer, "%uM", (uint32_t)(cpsl / 1000000));
	} else
	if (cps >= 1000000) {
		sprintf(buffer, "%uK", cps / 1000);
	} else if (cps >= 100) {
		sprintf(buffer, "%u", cps);
	} else {
		unsigned int frac = crypts * clk_tck * 10 / time % 10;
		sprintf(buffer, "%u.%u", cps, frac);
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
#ifdef MPI_UNSIGNED_LONG_LONG
	MPI_Reduce(&results->crypts, &combined.crypts, 1,
	           MPI_UNSIGNED_LONG_LONG, MPI_SUM, 0, MPI_COMM_WORLD);
#else
	{
		uint32_t c_hi, r_hi = results->crypts >> 32;
		uint32_t c_lo, r_lo = results->crypts & 0xffffffffU;

		/* Bug: We'd need carry here! */
		MPI_Reduce(&r_lo, &c_lo, 1, MPI_UNSIGNED,
		           MPI_SUM, 0, MPI_COMM_WORLD);
		MPI_Reduce(&r_hi, &c_hi, 1, MPI_UNSIGNED,
		           MPI_SUM, 0, MPI_COMM_WORLD);

		combined.crypts = (uint64_t)c_hi << 32 | (uint64_t)c_lo;
	}
#endif
	MPI_Reduce(&results->salts_done, &combined.salts_done, 1, MPI_INT,
		MPI_MIN, 0, MPI_COMM_WORLD);
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
#if defined(HAVE_OPENCL)
	char s_gpu[16 * MAX_GPU_DEVICES] = "";
	int i;
#else
	const char *s_gpu = "";
#endif
	unsigned int total, failed;
	MEMDBG_HANDLE memHand;
	struct db_main *test_db;
#ifdef _OPENMP
	int ompt;
	int ompt_start = omp_get_max_threads();
#endif

#if defined(HAVE_OPENCL)
	if (!benchmark_time) {
		/* This will make the majority of OpenCL formats
		   also do "quick" benchmarking. But if LWS or
		   GWS was already set, we do not overwrite. */
		setenv("LWS", "7", 0);
		setenv("GWS", "49", 0);
	}
#endif

#ifndef BENCH_BUILD
AGAIN:
#endif
	total = failed = 0;
#if defined(WITH_ASAN) || defined(WITH_UBSAN) || defined(DEBUG)
	if (benchmark_time)
		puts("NOTE: This is a debug build, speed will be lower than normal");
#endif
#ifndef BENCH_BUILD
	options.loader.field_sep_char = 31;
#endif
	if ((format = fmt_list))
	do {
#if defined(HAVE_OPENCL)
		int n = 0;
#endif
		memHand = MEMDBG_getSnapshot(0);
#ifndef BENCH_BUILD
/* Silently skip formats for which we have no tests, unless forced */
		if (!format->params.tests && format != fmt_list)
			continue;

/* Just test the encoding-aware formats if --encoding was used explicitly */
		if (!options.default_enc && options.target_enc != ASCII &&
		    options.target_enc != ISO_8859_1 &&
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

		/* FIXME: Kludge for thin dynamics, and OpenCL formats */
		/* c3_fmt also added, since it is a somewhat dynamic   */
		/* format and needs init called to change the name     */
		if ((format->params.flags & FMT_DYNAMIC) ||
		    strstr(format->params.label, "-opencl") ||
		    !strcmp(format->params.label, "crypt"))
			fmt_init(format);

		/* GPU-side mask mode benchmark */
		if (options.flags & FLG_MASK_CHK) {
			static struct db_main fakedb;

			fakedb.format = format;
			mask_init(&fakedb, options.mask);
		}
#endif

#ifdef _OPENMP
		// MPIOMPmutex may have capped the number of threads
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
			(options.target_enc == UTF_8 &&
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

		/* (Ab)used to mute some messages from source() */
		bench_running = 1;
		test_db = ldr_init_test_db(format, NULL);
		bench_running = 0;

		if ((result = benchmark_format(format,
		    format->params.salt_size ? BENCHMARK_MANY : 1,
		    &results_m, test_db))) {
			puts(result);
			failed++;
			goto next;
		}

		if (msg_1)
		if ((result = benchmark_format(format, 1, &results_1,
		    test_db))) {
			puts(result);
			failed++;
			goto next;
		}

#if defined(HAVE_OPENCL)
		if (benchmark_time > 1)
		for (i = 0; i < MAX_GPU_DEVICES &&
			     gpu_device_list[i] != -1; i++) {
			int dev = gpu_device_list[i];
			int fan, temp, util, cl, ml;

			fan = temp = util = cl = ml = -1;

			if (dev_get_temp[dev])
				dev_get_temp[dev](temp_dev_id[dev],
				                  &temp, &fan, &util, &cl, &ml);
#if 1
			if (util <= 0)
				continue;
#endif
			if (i == 0)
				n += sprintf(s_gpu + n, ", GPU util:");
			else
				n += sprintf(s_gpu + n, ", GPU%d:", i);

			if (util > 0)
				n += sprintf(s_gpu + n, "%u%%", util);
			else
				n += sprintf(s_gpu + n, "n/a");
		}
#endif
#ifdef HAVE_MPI
		if (john_main_process)
#endif
			printf(benchmark_time ? "DONE%s\n" : "PASS%s\n", s_gpu);
#ifdef _OPENMP
		// reset this in case format capped it (we may be testing more formats)
		omp_set_num_threads(ompt_start);
#endif

#ifndef BENCH_BUILD
		if (john_main_process && benchmark_time &&
		    *cost_msg && options.verbosity >= VERB_DEFAULT)
			puts(cost_msg);
#endif
#ifdef HAVE_MPI
		if (mpi_p > 1) {
			gather_results(&results_m);
			gather_results(&results_1);
		}
#endif
		if (msg_1 && format->params.salt_size &&
		    results_m.salts_done < BENCHMARK_MANY &&
		    john_main_process && benchmark_time) {
			printf("Warning: \"Many salts\" test limited: %d/%d\n",
			       results_m.salts_done, BENCHMARK_MANY);
		}

		benchmark_cps(results_m.crypts, results_m.real, s_real);
		benchmark_cps(results_m.crypts, results_m.virtual, s_virtual);
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

		benchmark_cps(results_1.crypts, results_1.real, s_real);
		benchmark_cps(results_1.crypts, results_1.virtual, s_virtual);
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
		fflush(stdout);
		ldr_free_test_db(test_db);
		fmt_done(format);
#ifndef BENCH_BUILD
		if (options.flags & FLG_MASK_CHK)
			mask_done();
#endif
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

#ifndef BENCH_BUILD
	if (options.flags & FLG_LOOPTEST && !event_abort)
		goto AGAIN;
#endif

	return failed || event_abort;
}
