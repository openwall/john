/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2003,2004,2006,2008-2012,2015,2017,2019 by Solar Designer
 *
 * ...with changes in the jumbo patch, by JimF and magnum
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

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
#include <stdlib.h> /* system(3) */

#include "times.h"

#include "arch.h"
#include "misc.h"
#include "params.h"
#include "memory.h"
#include "signals.h"
#include "formats.h"
#include "dyna_salt.h"
#include "config.h"
#include "bench.h"
#include "john.h"
#include "unicode.h"
#include "config.h"
#include "gpu_common.h"
#include "opencl_common.h"
#include "mask.h"
#include "mask_ext.h"
#include "aligned.h"

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
void ldr_free_db(struct db_main* foo, int bar)
{
}
#endif

#include "john_mpi.h"

#ifdef _OPENMP
#include <omp.h>
#endif /* _OPENMP */

#define MAX_COST_MSG_LEN 256
#ifndef BENCH_BUILD
/* the + 24 is for a little 'extra' text wrapping each line */
static char cost_msg[ (MAX_COST_MSG_LEN+24) * FMT_TUNABLE_COSTS];
#endif

long clk_tck = 0;

void clk_tck_init(void)
{
	if (clk_tck) return;

#if defined (__MINGW32__) || defined (_MSC_VER)
	clk_tck = CLOCKS_PER_SEC;
#elif defined(_SC_CLK_TCK) || !defined(CLK_TCK)
	clk_tck = sysconf(_SC_CLK_TCK);
#else
	clk_tck = CLK_TCK;
#endif
}

int benchmark_time = BENCHMARK_TIME;
int benchmark_level = -1;

static volatile int bench_running;

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

#define PARENT_KEY ((options.flags & FLG_MASK_STACKED) ? plaintext : NULL)

static void bench_set_keys(struct fmt_main *format,
	struct fmt_tests *current, int pass)
{
	unsigned int flags = format->params.benchmark_length;
	unsigned int length = flags & 0xff;
	int max = format->params.max_keys_per_crypt;
	int index;
#ifndef BENCH_BUILD
	int mask_mult = MAX(1, mask_tot_cand);
	int mask_key_len = MAX(0, (int)length - mask_add_len);
#endif

	format->methods.clear_keys();

	if (!current) {
		JTR_ALIGN(MEM_ALIGN_WORD)
			static char plaintext[PLAINTEXT_BUFFER_SIZE];
		static int warn;

		if ((flags & 0x200) && pass >= 2)
			length += 1 + (flags >> 16);

		if (!(pass & 1)) {
			memset(plaintext, 0x41, length);
			plaintext[length] = 0;
			warn = 0;
		}

		index = 0;

		if (length)
		while (index < max) {
			int pos = length - 1;
			while (++plaintext[pos] > 0x60) {
				plaintext[pos] = 0x21;
				if (!pos--) {
					warn |= 1;
					break;
				}
			}
#ifndef BENCH_BUILD
			if ((options.flags & FLG_MASK_CHK) && ((options.flags & FLG_MASK_STACKED) || mask_mult > 1)) {
				plaintext[mask_key_len] = 0;
				if (do_mask_crack(PARENT_KEY))
					return;
				index += mask_mult;
			} else
#endif
				format->methods.set_key(plaintext, index++);
		}

		if (warn == 1) {
			fprintf(stderr, "Warning: not enough candidates under "
			    "benchmark length %d\n", length);
			warn = 2;
		}

		return;
	}

	/* Legacy benchmark mode for performance regression testing */
	for (index = 0; index < max; index++) {
		char *plaintext;
		do {
			if (!current->ciphertext)
				current = format->params.tests;
			plaintext = current->plaintext;
			current++;

			if (flags & 0x200) {
				int current_length = strlen(plaintext);
				if (pass >= 2) {
					if (current_length > length)
						break;
				} else  {
					if (current_length <= length)
						break;
				}
			} else {
				break;
			}
		} while (1);

#ifndef BENCH_BUILD
		if (options.flags & FLG_MASK_CHK) {
			plaintext[mask_key_len] = 0;
			if (do_mask_crack(PARENT_KEY))
				return;
			index += (mask_mult - 1);
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
	static int wait_salts = 0;
	struct fmt_tests *current;
	int pass;
#if OS_TIMER
	struct itimerval it;
#endif
#if !defined (__MINGW32__) && !defined (_MSC_VER)
	struct tms buf;
#endif
	clock_t start_real, start_virtual, end_real, end_virtual;
	uint64_t crypts;
	char *ciphertext;
	void *salt, *two_salts[2];
	int index, max;
#ifndef BENCH_BUILD
	struct db_salt *two_salts_db[2];
	unsigned int t_cost[2][FMT_TUNABLE_COSTS];
	int i;
#endif
	int salts_done = 0;
	int wait = 0;
	int dyna_copied = 0;

	clk_tck_init();

	if (!(current = format->params.tests) || !current->ciphertext)
		return "FAILED (no data)";

	benchmark_running = 1;
#ifndef BENCH_BUILD
	dyna_salt_init(format);

	current = format->params.tests;
#endif
#ifdef BENCH_BUILD
	const char *where;
	if ((where = fmt_self_test(format, test_db))) {
		static char s_error[128];
		snprintf(s_error, sizeof(s_error), "FAILED (%s)\n", where);
		return s_error;
	}
#endif
	if (!current->ciphertext)
		return "FAILED (no ciphertext in test vector)";
	if (!current->plaintext)
		return "FAILED (no plaintext in test vector)";

	if (format->params.binary_size > binary_size) {
		binary_size = format->params.binary_size;
		binary = mem_alloc_tiny(binary_size, MEM_ALIGN_SIMD);
	}
	memset(binary, 0x55, binary_size);
	if (format->params.flags & FMT_BLOB)
		memcpy(binary,
		       format->methods.binary(format->params.tests[0].ciphertext),
		       format->params.binary_size);

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
/* ... but disable (fake) multi-salt benchmark anyway */
			salts = 0;
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

		struct db_salt *dbsalt = test_db->salts;
		if (format->params.salt_size)
		while (dbsalt && dyna_salt_cmp(dbsalt->salt, two_salts[index], format->params.salt_size))
			dbsalt = dbsalt->next;
		if (dbsalt) {
			two_salts_db[index] = dbsalt;
			if (dbsalt->count > 1) {
				dbsalt->list->next = NULL;
				dbsalt->count = 1;
				dbsalt->bitmap = NULL;
				dbsalt->hash = NULL;
			}
		} else {
			puts("Warning: Could not find salt in db");
			two_salts_db[index] = test_db->salts;
		}
#endif
	}

	/*
	 * Core john doesn't have this set_salt at all, only later under
	 * "if (salts > 1)". I first added it only "if (salts == 1)" but
	 * for some odd reason that lead to severe problems.
	 */
	format->methods.set_salt(two_salts[0]);

#ifndef BENCH_BUILD
	*cost_msg = 0;
	for (i = 0; i < FMT_TUNABLE_COSTS &&
		     format->methods.tunable_cost_value[i] != NULL; i++) {
		char msg[MAX_COST_MSG_LEN];

		if (t_cost[0][i] == t_cost[1][i] ||
		    (format->params.benchmark_length & 0x400))
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

	if (salts) {
		pass = 2;
	} else {
		pass = 0;
		salts = 1;
	}

	if (!cfg_get_bool(SECTION_DEBUG, NULL, "Benchmarks_1_8", 0))
		current = NULL;
#ifndef BENCH_BUILD
	else if (options.flags & FLG_MASK_CHK)
		error_msg("\nLegacy benchmark is not supported with --mask option\n");
#endif

	bench_set_keys(format, current, pass++);

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
	wait = format->params.benchmark_length < 0x100 ? wait_salts : 0;

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
	start_real = start_virtual = clock();
#else
	start_real = times(&buf);
	start_virtual = buf.tms_utime + buf.tms_stime;
	start_virtual += buf.tms_cutime + buf.tms_cstime;
#endif
	crypts = 0;

#ifndef BENCH_BUILD
	if (salts <= 1)
		two_salts_db[1] = two_salts_db[0];
#endif

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
			if (current) {
				if (!(++current)->ciphertext)
					current = format->params.tests;
			}
			bench_set_keys(format, current, pass);
		}

		if (salts > 1)
			format->methods.set_salt(two_salts[index & 1]);
#ifndef BENCH_BUILD
		int match = format->methods.crypt_all(&count, two_salts_db[index & 1]);
#else
		int match = format->methods.crypt_all(&count, NULL);
#endif
		if (match)
			format->methods.cmp_all(binary, match);

		crypts += (uint32_t)count;
#if !OS_TIMER
		sig_timer_emu_tick();
#endif
		salts_done++;
	} while (benchmark_time && !event_abort &&
	         (bench_running ||
	          (salts_done < (wait ? salts : MIN(salts, 2))) ||
	          (10 * salts_done > 9 * salts && salts_done < salts)));

	benchmark_running = 0;

	BLOB_FREE(format, binary);

#if defined (__MINGW32__) || defined (_MSC_VER)
	end_real = clock();
#else
	end_real = times(&buf);
#endif

#if defined (__MINGW32__) || defined (_MSC_VER)
	end_virtual = end_real;
#else
	end_virtual = buf.tms_utime + buf.tms_stime;
	end_virtual += buf.tms_cutime + buf.tms_cstime;
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

	return event_abort ? "" : NULL;
}

void benchmark_cps(uint64_t crypts, clock_t time, char *buffer)
{
	if (!time) {
		strcpy(buffer, "UNKNOWN");
		return;
	}

	uint64_t cps = crypts * clk_tck / time;

	if (cps >= 1000000000000ULL) {
		sprintf(buffer, "%uG", (unsigned int)(cps / 1000000000ULL));
	} else if (cps >= 1000000000) {
		sprintf(buffer, "%uM", (unsigned int)(cps / 1000000));
	} else if (cps >= 1000000) {
		sprintf(buffer, "%uK", (unsigned int)cps / 1000);
	} else if (cps >= 100) {
		sprintf(buffer, "%u", (unsigned int)cps);
	} else if (cps >= 10) {
		unsigned int frac = crypts * clk_tck * 10 / time % 10;
		sprintf(buffer, "%u.%u", (unsigned int)cps, frac);
	} else {
		unsigned int frac = crypts * clk_tck * 100 / time % 100;
		sprintf(buffer, "%u.%02u", (unsigned int)cps, frac);
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
#if defined(HAVE_OPENCL)
	char s_gpu[16 * MAX_GPU_DEVICES] = "";
	char s_gpu1[16 * MAX_GPU_DEVICES] = "";
#else
	const char *s_gpu = "";
	const char *s_gpu1 = "";
#endif
#ifndef BENCH_BUILD
	int i;
	unsigned int loop_fail = 0, loop_total = 1;
	int nvidia_mem = 0;
#endif
	unsigned int total, failed;
	struct db_main *test_db;
#ifdef _OPENMP
	int ompt;
	int ompt_start = omp_get_max_threads();
#endif
	const char *opencl_was_skipped = "";

#ifndef BENCH_BUILD
#if defined(WITH_ASAN) || defined(WITH_UBSAN) || defined(DEBUG)
	if (benchmark_time)
		puts("NOTE: This is a debug build, speed will be lower than normal");
#endif

	if ((options.flags & FLG_LOOPTEST_CHK) && system("which nvidia-smi >/dev/null") == 0) {
		nvidia_mem = 1;
		fprintf(stderr, "GPU memory at start: ");
		if (system("nvidia-smi --query-gpu=memory.used --format=csv,noheader"))
			nvidia_mem = 0;
	}
AGAIN:
	options.loader.field_sep_char = 31;
#endif
	total = failed = 0;

	if ((format = fmt_list))
	do {
		int salts;
		char *result, *msg_1, *msg_m;
		struct bench_results results_1, results_m;
		char s_real[64], s_virtual[64];

#ifndef BENCH_BUILD
/* Silently skip formats for which we have no tests, unless forced */
		if (!format->params.tests && format != fmt_list)
			continue;

/* Hack for scripting raw/one/many tests, only test salted formats */
		if (cfg_get_bool(SECTION_DEBUG, NULL, "BenchmarkMany", 0)) {
			if (!format->params.salt_size ||
			    (format->params.flags & FMT_DYNAMIC))
				continue;
			format->params.benchmark_length &= ~0x500;
		}

/* Just test the encoding-aware formats if --encoding was used explicitly */
		if (!options.default_enc && options.target_enc != ENC_RAW &&
		    options.target_enc != ISO_8859_1 && !(format->params.flags & FMT_ENC)) {
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
		    strstr(format->params.label, "-ztex") ||
		    !strcmp(format->params.label, "crypt")) {
#ifdef HAVE_OPENCL
/*
 * Allow OpenCL build's "--test" to run on no-OpenCL systems.
 * It is a hack, but it is necessary since OpenCL must be started
 * to get the number of devices. OpenCL initialization (enumeration
 * of platforms and devices, option parsing) is performed only once.
*/
			if (strstr(format->params.label, "-opencl")) {
				opencl_load_environment();

				if (get_number_of_available_devices() == 0)
					continue;
			}
#endif
			fmt_init(format);
		}

		/* [GPU-side] mask mode benchmark */
		if (options.mask) {
			static char benchmark_comment[16];
			int bl = format->params.benchmark_length & 0x7f;
			int el = mask_calc_len(options.mask);

			if (options.flags & FLG_MASK_STACKED)
				el = MAX(el, bl);

			sprintf(benchmark_comment, " (length %d)", el);
			format->params.benchmark_comment =
				benchmark_comment;
		}
#endif

#ifdef _OPENMP
		// MPIOMPmutex may have capped the number of threads
		ompt = omp_get_max_threads();
#endif /* _OPENMP */

#ifndef BENCH_BUILD
		if ((options.flags & FLG_LOOPTEST_CHK) && john_main_process)
			printf("#%u ", loop_total);
#endif
#if defined(HAVE_OPENCL) || defined(HAVE_ZTEX)
		int using_int_mask = (format->params.flags & FMT_MASK) && (options.flags & FLG_MASK_CHK) &&
			options.req_int_cand_target != 0 && mask_int_cand_target;
#elif !defined(BENCH_BUILD)
		int using_int_mask = 0;
#endif

		if (john_main_process)
		printf("%s: %s%s%s%s [%s%s%s%s]... ",
		    benchmark_time ? "Benchmarking" : "Testing",
		    format->params.label,
		    format->params.format_name[0] ? ", " : "",
		    format->params.format_name,
		    format->params.benchmark_comment,
		    format->params.algorithm_name,
#ifndef BENCH_BUILD
#define ENC_SET (!options.default_enc && options.target_enc != ENC_RAW && options.target_enc != ISO_8859_1)

		    (benchmark_time && using_int_mask) ? "/mask accel" : "",
		    ENC_SET ? ", " : "",
		    ENC_SET ? cp_id2name(options.target_enc) : "");
#else
		    "", "", "");
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
		if (john_main_process)
		if (format->params.flags & FMT_OMP && ompt > 1)
			printf("(%dxOMP) ", ompt);
		fflush(stdout);
#endif /* _OPENMP */
#endif /* HAVE_MPI */

		salts = 0;
		if (!format->params.salt_size ||
		    (format->params.benchmark_length & 0x100)) {
			if (format->params.salt_size &&
			    !(format->params.benchmark_length & 0x400))
				salts = BENCHMARK_MANY;
			msg_m = "Raw";
			msg_1 = NULL;
		} else if (format->params.benchmark_length & 0x200) {
			msg_m = "Short";
			msg_1 = "Long";
		} else {
			salts = BENCHMARK_MANY;
			msg_m = "Many salts";
			msg_1 = "Only one salt";
		}

		total++;

		test_db = ldr_init_test_db(format, NULL);

#ifndef BENCH_BUILD
		if ((result = fmt_self_test(format, test_db))) {
			printf("FAILED (%s)\n", result);
			failed++;
			goto next;
		}

		if (john_main_process && !(options.flags & FLG_NOTESTS)) {
			if (!benchmark_time)
				printf("PASS\n");
			else if (options.verbosity >= VERB_MAX)
				printf("PASS, ");
			fflush(stdout);
		}

		if (!benchmark_time)
			goto next;

		/* Re-init with mask mode if applicable */
		if (options.flags & FLG_MASK_CHK)
			mask_init(test_db, options.mask);

		/* Prune test vectors for benchmark to honor --cost option */
		struct fmt_tests *current;
		int index, ntests, pruned = 0;

		for (i = 0; i < FMT_TUNABLE_COSTS; i++) {
			if (options.loader.min_cost[i] > 0 || options.loader.max_cost[i] < UINT_MAX) {
				unsigned int cost;

				if (format->methods.tunable_cost_value[i] == NULL) {
					printf("FAILED (cost %d not defined for format)\n\n", i);
					failed++;
					goto next;
				}

				ntests = 0;
				current = format->params.tests;
				while ((current++)->ciphertext)
					ntests++;

				current = format->params.tests;
				for (index = 0; index < ntests; index++) {
					cost = get_cost(format, index, i);
					if (cost >= options.loader.min_cost[i] && cost <= options.loader.max_cost[i])
						memcpy(current++, &format->params.tests[index], sizeof(struct fmt_tests));
					else
						pruned++;
				}
				memset(current, 0, sizeof(struct fmt_tests));
			}
		}

		if (pruned && !format->params.tests->ciphertext) {
			printf("FAILED (--cost pruned all %d test vectors)\n\n", pruned);
			failed++;
			goto next;
		}

		/*
		 * Re-init for benchmark.  While the self-tests were done with very
		 * low work sizes, we now need a proper auto-tune for benchmark, with
		 * internal mask if applicable.
		 */
		benchmark_running = 1;
		format->methods.reset(test_db);
#endif
		if ((result = benchmark_format(format, salts, &results_m, test_db))) {
			puts(result);
			failed += !event_abort;
			goto next;
		}
#if HAVE_OPENCL
		int n = 0;

		s_gpu[0] = 0;
		for (i = 0; i < MAX_GPU_DEVICES &&
			     engaged_devices[i] != DEV_LIST_END; i++) {
			int dev = engaged_devices[i];
			int fan, temp, util, cl, ml;

			fan = temp = util = cl = ml = -1;

			if (dev_get_temp[dev])
				dev_get_temp[dev](temp_dev_id[dev],
				                  &temp, &fan, &util, &cl, &ml);
			if (util <= 0)
				continue;
			if (i == 0)
				n += sprintf(s_gpu + n, ", Dev#%d util: ", dev + 1);
			else
				n += sprintf(s_gpu + n, ", Dev#%d: ", dev + 1);

			if (util > 0)
				n += sprintf(s_gpu + n, "%u%%", util);
			else
				n += sprintf(s_gpu + n, "n/a");
		}
#endif

		if (msg_1) {
			if ((result = benchmark_format(format, 1, &results_1, test_db))) {
				puts(result);
				failed++;
				goto next;
			}
#if HAVE_OPENCL
			int n = 0;

			s_gpu1[0] = 0;
			for (i = 0; i < MAX_GPU_DEVICES &&
				     engaged_devices[i] != DEV_LIST_END; i++) {
				int dev = engaged_devices[i];
				int fan, temp, util, cl, ml;

				fan = temp = util = cl = ml = -1;

				if (dev_get_temp[dev])
					dev_get_temp[dev](temp_dev_id[dev],
					                  &temp, &fan, &util, &cl, &ml);
				if (util <= 0)
					continue;
				if (i == 0)
					n += sprintf(s_gpu1 + n, ", Dev#%d util: ", dev + 1);
				else
					n += sprintf(s_gpu1 + n, ", Dev#%d: ", dev + 1);

				if (util > 0)
					n += sprintf(s_gpu1 + n, "%u%%", util);
				else
					n += sprintf(s_gpu1 + n, "n/a");
			}
#endif
		}

		if (john_main_process && benchmark_time)
			puts("DONE");
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
		if (john_main_process && benchmark_time) {
#if !defined(__DJGPP__) && !defined(__BEOS__) && !defined(__MINGW32__) && !defined (_MSC_VER)
			if (results_m.virtual)
				printf("%s:\t%s c/s real, %s c/s virtual%s\n",
				       msg_m, s_real, s_virtual, s_gpu);
			else
#endif
				printf("%s:\t%s c/s%s\n",
				       msg_m, s_real, s_gpu);
		}

		if (!msg_1) {
			if (john_main_process)
			if (benchmark_time)
			putchar('\n');
			goto next;
		}

		benchmark_cps(results_1.crypts, results_1.real, s_real);
		benchmark_cps(results_1.crypts, results_1.virtual, s_virtual);

		if (john_main_process && benchmark_time) {
#if !defined(__DJGPP__) && !defined(__BEOS__) && !defined(__MINGW32__) && !defined (_MSC_VER)
			if (results_1.virtual)
				printf("%s:\t%s c/s real, %s c/s virtual%s\n\n",
				       msg_1, s_real, s_virtual, s_gpu1);
			else
#endif
				printf("%s:\t%s c/s%s\n\n",
				       msg_1, s_real, s_gpu1);
		}

next:
#ifndef BENCH_BUILD
		if (nvidia_mem && system("nvidia-smi --query-gpu=memory.used --format=csv,noheader"))
			error();
#endif
		fflush(stdout);
		ldr_free_db(test_db, 1);
		fmt_done(format);
#ifndef BENCH_BUILD
		if (options.flags & FLG_MASK_CHK) {
			mask_done();
			mask_destroy();
		}
#endif

#ifndef BENCH_BUILD
		/* In case format changed it */
		initUnicode(UNICODE_UNICODE);
#endif
	} while ((format = format->next) && !event_abort);

#ifdef HAVE_OPENCL
/*
 * Allow OpenCL build's "--test" to run on no-OpenCL systems.
 * Print a message about no OpenCL at the end of the run.
 */
	if (opencl_unavailable)
		opencl_was_skipped = " (OpenCL formats skipped)";
#endif

	if (failed && total > 1)
		printf("%u out of %u tests have FAILED%s\n", failed, total, opencl_was_skipped);
	else if (total > 1 && john_main_process) {
		const char *all = event_abort ? "" : "All ";
		const char *not = event_abort ? ", last one aborted" : "";
#ifndef BENCH_BUILD
		if (benchmark_time)
			printf("%s%u formats benchmarked%s%s\n", all, total, not, opencl_was_skipped);
		else
#endif
			printf("%s%u formats passed self-tests%s\n", all, total, opencl_was_skipped);
	}

#ifndef BENCH_BUILD
	if (options.flags & FLG_LOOPTEST_CHK) {
		loop_total++;
		if (event_abort) {
			uint32_t p = 100 * loop_fail / loop_total;
			uint32_t pp = 10000 * loop_fail / loop_total - p * 100;

			printf("Tested %u times, %u failed (%u.%02u%%)\n",
			       loop_total, loop_fail, p, pp);
		} else {
			if (failed)
				loop_fail++;
			goto AGAIN;
		}
	}
#endif

	return failed || event_abort;
}
