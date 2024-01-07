/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2004,2006,2010-2013,2017 by Solar Designer
 *
 * ...with changes in the jumbo patch, by JimF and magnum.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#include <stdint.h>
#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <time.h>
#include "os.h"
#if HAVE_SYS_TIMES_H
#include <sys/times.h>
#endif

#include "times.h"

#if defined(__GNUC__) && defined(__i386__)
#include "arch.h" /* for CPU_REQ */
#endif

#include "misc.h"
#include "params.h"
#include "cracker.h"
#include "options.h"
#include "status.h"
#include "bench.h"
#include "config.h"
#include "unicode.h"
#include "signals.h"
#include "mask.h"
#include "subsets.h"
#include "john.h"
#include "john_mpi.h"
#include "gpu_common.h"

struct status_main status;
unsigned int status_restored_time = 0;
static const char* timeFmt = NULL;
static const char* timeFmt24 = NULL;
static int showcand, last_count;
double (*status_get_progress)(void) = NULL;

clock_t status_get_raw_time(void)
{
#if !HAVE_SYS_TIMES_H
	return clock();
#else
	struct tms buf;

	return times(&buf);
#endif
}

void status_update_counts(void)
{
	last_count = status.guess_count;
}

void status_init(double (*get_progress)(void), int start)
{
	if (start) {
		if (!status_restored_time)
			memset(&status, 0, sizeof(status));
		status.start_time = status_get_raw_time();
	}

	status_get_progress = get_progress;

	if (!(timeFmt = cfg_get_param(SECTION_OPTIONS, NULL, "TimeFormat")))
		timeFmt = "%Y-%m-%d %H:%M";

	if (!(timeFmt24 = cfg_get_param(SECTION_OPTIONS, NULL, "TimeFormat24")))
		timeFmt24 = "%H:%M:%S";

	showcand = cfg_get_bool(SECTION_OPTIONS, NULL, "StatusShowCandidates", 0);

	clk_tck_init();

	status_update_counts();
}

void status_ticks_overflow_safety(void)
{
	unsigned int time;
	clock_t ticks;

	ticks = status_get_raw_time() - status.start_time;
	if (ticks > ((clock_t)1 << (sizeof(clock_t) * 8 - 2))) {
		time = ticks / clk_tck;
		status_restored_time += time;
		status.start_time += (clock_t)time * clk_tck;
	}
}

void status_update_crypts(uint64_t combs, unsigned int crypts)
{
	uint64_t saved = status.crypts;
	status.crypts += crypts;
	if ((status.crypts ^ saved) & ~(uint64_t)0xfffff)
		status_ticks_overflow_safety();

	status.combs += combs;
	if (status.combs < combs)
		status.combs_ehi++;
}

void status_update_cands(unsigned int cands)
{
	uint64_t saved = status.cands;
	status.cands += cands;
	if ((status.cands ^ saved) & ~(uint64_t)0xfffff)
		status_ticks_overflow_safety();
}

unsigned int status_get_time(void)
{
	return status_restored_time + (status_get_raw_time() - status.start_time) / clk_tck;
}

static double status_get_timef(void)
{
	return status_restored_time + (double)(status_get_raw_time() - status.start_time) / clk_tck;
}

static char *status_get_cps(char *buffer, uint64_t c, unsigned int c_ehi, double time_override)
{
	double time = time_override ? time_override : status_get_timef();
	if (!time)
		time = 1.0 / clk_tck;

	double cpsf = (((double)2 * (1ULL << 63)) * c_ehi + c) / time;
	uint64_t cps = cpsf;

	if (cps >= 1000000000000000ULL) {
		sprintf(buffer, "%uT", (unsigned int)(cps / 1000000000000ULL));
	} else if (cps >= (uint64_t)1000000 * 1000000) {
		sprintf(buffer, "%uG", (unsigned int)(cps / 1000000000));
	} else if (cps >= 1000000000) {
		sprintf(buffer, "%uM", (unsigned int)(cps / 1000000));
	} else if (cps >= 1000000) {
		sprintf(buffer, "%uK", (unsigned int)(cps / 1000));
	} else if (cps >= 1000 || cpsf < 1e-6) {
		sprintf(buffer, "%u", (unsigned int)cps);
	} else {
		int width = 6;
		if (cpsf >= 100)
			width = 1;
		else if (cpsf >= 10)
			width = 2;
		else if (cpsf >= 1)
			width = 3;
		else if (cpsf >= 0.1)
			width = 4;
		else if (cpsf >= 0.01)
			width = 5;
		sprintf(buffer, "%.*f", width, cpsf);
	}

	return buffer;
}

static char *status_get_ETA(double percent, unsigned int secs_done)
{
	static char s_ETA[128+1];
	char ETA[128];
	double sec_left;
	time_t t_ETA;
	struct tm *pTm;

	/* Compute the ETA for this run.  Assumes even run time for
	   work currently done and work left to do, and that the CPU
	   utilization of work done and work to do will stay same
	   which may not always be valid assumptions */
	if (status.pass)
		sprintf(s_ETA, " %d/3", status.pass);
	else
	if (mask_increments_len)
		sprintf(s_ETA, " (%d)", mask_cur_len);
	else
	if (subsets_cur_len)
		sprintf(s_ETA, " (%d)", subsets_cur_len);
	else
		s_ETA[0] = 0;

	if (percent <= 0)
		return s_ETA;  /* dont show ETA if no valid percentage. */
	else
	{
		double chk;

		t_ETA = time(NULL);
		if (percent >= 100.0) {
			pTm = localtime(&t_ETA);
			strncat(s_ETA, " (", sizeof(s_ETA) - 1);
			strftime(ETA, sizeof(ETA), timeFmt, pTm);
			strncat(s_ETA, ETA, sizeof(s_ETA) - 1);
			strncat(s_ETA, ")", sizeof(s_ETA) - 1);
			return s_ETA;
		}
		percent /= 100;
		sec_left = secs_done;
		sec_left /= percent;
		sec_left -= secs_done;
		/* Note, many localtime() will fault if given a time_t
		   later than Jan 19, 2038 (i.e. 0x7FFFFFFFF). We
		   check for that here, and if so, this run will
		   not end anyway, so simply tell user to not hold
		   her breath */
		chk = sec_left;
		chk += t_ETA;
		if (chk > 0x7FFFF000) { /* slightly less than 'max' 32 bit time_t, for safety */
			if (100 * (int)percent > 0)
				strncat(s_ETA, " (ETA: never)",
				        sizeof(s_ETA) - 1);
			return s_ETA;
		}
		t_ETA += sec_left;
		pTm = localtime(&t_ETA);
		strncat(s_ETA, " (ETA: ", sizeof(s_ETA) - 1);
		if (sec_left < 24 * 3600)
			strftime(ETA, sizeof(ETA), timeFmt24, pTm);
		else
			strftime(ETA, sizeof(ETA), timeFmt, pTm);
		strncat(s_ETA, ETA, sizeof(s_ETA) - 1);
		strncat(s_ETA, ")", sizeof(s_ETA) - 1);
	}
	return s_ETA;
}

#if defined(HAVE_OPENCL)
static void status_print_cracking(char *p, double percent, char *gpustat)
#else
static void status_print_cracking(char *p, double percent)
#endif
{
	unsigned int time = status_get_time();
	char *key1, key2[PLAINTEXT_BUFFER_SIZE];
	char t1buf[PLAINTEXT_BUFFER_SIZE + 1];
	char s_gps[32], s_pps[32], s_crypts_ps[32], s_combs_ps[32];
	char sc[32];
	int n;
	char progress_string[128];
	char *eta_string;

	key1 = NULL;
	key2[0] = 0;
	if (!(options.flags & FLG_STATUS_CHK) && status.crypts) {
		char *key = crk_get_key2();
		if (key)
			strnzcpy(key2, key, sizeof(key2));
		key1 = crk_get_key1();

		if (options.report_utf8 && options.target_enc != UTF_8) {
			char t2buf[PLAINTEXT_BUFFER_SIZE + 1];
			char *t;

			key1 = cp_to_utf8_r(key1, t1buf, PLAINTEXT_BUFFER_SIZE);
			t = cp_to_utf8_r(key2, t2buf, PLAINTEXT_BUFFER_SIZE);
			strnzcpy(key2, t, sizeof(key2));
		}
	}

#ifndef HAVE_MPI
	if (options.fork) {
#else
	if (options.fork || mpi_p > 1) {
#endif
		n = sprintf(p, "%u ", options.node_min);
		if (n > 0)
			p += n;
	}

	if (showcand)
		sprintf(sc, " %"PRIu64"p", status.cands);

	eta_string = status_get_ETA(percent, time);

	//fprintf(stderr, "Raw percent %f%%%s\n", percent, eta_string);
	if ((int)(100 * percent) <= 0 && !strstr(eta_string, "ETA"))
		strcpy(progress_string, eta_string);
	else if (percent < 100.0)
		sprintf(progress_string, "%.02f%%%s", percent, eta_string);
	else if ((int)percent == 100)
		sprintf(progress_string, "DONE%s", eta_string);
	else
		sprintf(progress_string, "N/A");

	n = sprintf(p,
	    "%ug%s %u:%02u:%02u:%02u %s %.31sg/s ",
	    status.guess_count,
	    showcand ? sc : "",
	    time / 86400, time % 86400 / 3600, time % 3600 / 60, time % 60,
	    progress_string,
	    status_get_cps(s_gps, status.guess_count, 0, 0));
	if (n > 0)
		p += n;

	if (!status.compat) {
		n = sprintf(p,
		    "%.31sp/s %.31sc/s ",
		    status_get_cps(s_pps, status.cands, 0, 0),
		    status_get_cps(s_crypts_ps, status.crypts, 0, 0));
		if (n > 0)
			p += n;
	}

#if defined(HAVE_OPENCL)
	n = sprintf(p, "%.31sC/s%s%s%.200s%s%.200s\n",
	    status_get_cps(s_combs_ps, status.combs, status.combs_ehi, 0),
	    gpustat,
	    key1 ? " " : "", key1 ? key1 : "", key2[0] ? ".." : "", key2);
#else
	n = sprintf(p, "%.31sC/s%s%.200s%s%.200s\n",
	    status_get_cps(s_combs_ps, status.combs, status.combs_ehi, 0),
	    key1 ? " " : "", key1 ? key1 : "", key2[0] ? ".." : "", key2);
#endif
	if (n > 0)
		p += n;

	if (john_main_process && status.guess_count > last_count &&
	    cfg_get_bool(SECTION_OPTIONS, NULL, "ShowRemainOnStatus", 0)) {
		n = sprintf(p, "%s\n", crk_loaded_counts());
		if (n > 0)
			p += n;
		status_update_counts();
	}

	*p = 0;
}

static char *status_get_c(char *buffer, uint64_t c, unsigned int c_ehi)
{
	char *p;

	if (c_ehi)
		return "OVERFLOW";

	p = buffer + 31;
	*p = 0;
	do {
		*--p = c % 10 + '0';
	} while ((c /= 10));

	return p;
}

static void status_print_stdout(char *p, double percent)
{
	unsigned int time = status_get_time();
	char *key;
	char s_pps[32], s_p[32];

	key = NULL;
	if (!(options.flags & FLG_STATUS_CHK) && status.cands)
		key = crk_get_key1();

	sprintf(p,
	    "%sp %u:%02u:%02u:%02u %.02f%%%s %sp/s%s%s\n",
	    status_get_c(s_p, status.cands, 0),
	    time / 86400, time % 86400 / 3600, time % 3600 / 60, time % 60,
	        percent < 0 ? 0 : percent,
	    status_get_ETA(percent, time),
	    status_get_cps(s_pps, status.cands, 0, 0),
	    key ? " " : "", key ? key : "");
}

void status_print(int level)
{
	if (!level) {
		level = event_status;
		event_status = 0;
	}

	emms();

	double percent_value;
#if defined(HAVE_OPENCL)
	char s_gpu[64 * MAX_GPU_DEVICES] = "";

	if (!(options.flags & FLG_STDOUT) &&
	    cfg_get_bool(SECTION_OPTIONS, SUBSECTION_GPU, "SensorsStatus", 1)) {
		int i;
		int n = 0;

		for (i = 0; i < MAX_GPU_DEVICES &&
			     engaged_devices[i] != DEV_LIST_END; i++) {
			int dev = engaged_devices[i];

			if (dev_get_temp[dev]) {
				int fan, temp, util, cl, ml;

				fan = temp = util = cl = ml = -1;
				dev_get_temp[dev](temp_dev_id[dev],
				                  &temp, &fan, &util, &cl, &ml);
				if (temp >= 0 &&
				    (options.verbosity > VERB_LEGACY ||
				    cfg_get_bool(SECTION_OPTIONS,
				                 SUBSECTION_GPU,
				                 "TempStatus", 1))) {
					n += sprintf(s_gpu + n,
					             " Dev#%d:%u%sC",
					             dev + 1, temp,
					             gpu_degree_sign);
				}
				if (util > 0 &&
				    (options.verbosity > VERB_LEGACY ||
				    cfg_get_bool(SECTION_OPTIONS,
				                 SUBSECTION_GPU,
				                 "UtilStatus", 0)))
					n += sprintf(s_gpu + n,
					             " util:%u%%", util);
				if (fan >= 0 &&
				    (options.verbosity > VERB_LEGACY ||
				    cfg_get_bool(SECTION_OPTIONS,
				                 SUBSECTION_GPU,
				                 "FanStatus", 0)))
					n += sprintf(s_gpu + n,
					             " fan:%u%%", fan);
			}
		}
	}
#endif

	percent_value = -1;
	if (options.flags & FLG_STATUS_CHK)
		percent_value = status.progress;
	else
	if (options.catchup && john_max_cands) {
		percent_value = 100.0 * status.cands / john_max_cands;
	} else
	if (status_get_progress)
		percent_value = status_get_progress();

	char s_line[1024];
	if (options.flags & FLG_STDOUT)
		status_print_stdout(s_line, percent_value);
	else
#if defined(HAVE_OPENCL)
		status_print_cracking(s_line, percent_value, s_gpu);
#else
		status_print_cracking(s_line, percent_value);
#endif

	if (level < 2) {
		fputs(s_line, stderr);
		return;
	}

	static struct status_main prev;
	static double prev_time;
	double time = status_get_timef();
	double new_time = time - prev_time;
	char s_gps[32], s_pps[32], s_crypts_ps[32], s_combs_ps[32];
	char s_combs[32], s_combs_new[32];
	char s_when[64], s_mps[32], s_hps[32], s_tps[32];
	s_when[0] = 0;
	if (status.suppressor_start) {
		sprintf(s_when, " since accepted candidate %llu", status.suppressor_start);
		if (status.suppressor_end)
			sprintf(s_when + strlen(s_when), " until ~%llu", status.suppressor_end);

	}
	unsigned long long suppressor_total = status.suppressor_hit + status.suppressor_miss;
	unsigned int suppressor_time = (status.suppressor_end ? status.suppressor_end_time : time);
	if (suppressor_time <= status.suppressor_start_time)
		suppressor_time = 1;
	else
		suppressor_time -= status.suppressor_start_time;
	fprintf(stderr,
	    "%s"
	    "Remaining hashes    %u (%u removed)\n"
	    "Remaining salts     %u (%u removed)\n"
	    "Time in seconds     %.2f (%.2f new)\n"
	    "Successful guesses  %u (%u new, %s g/s)\n"
	    "Passwords tested    %llu (%llu new, %s p/s)\n"
	    " dupe suppressor    %ss %sabled%s\n"
	    " and it accepted    %llu (%.2f%%, %s p/s)\n"
	    "        rejected    %llu (%.2f%%, %s p/s)\n"
	    "    out of total    %llu (%s p/s)\n"
	    "Hash computations   %llu (%llu new, %s c/s)\n"
	    "Hash combinations   %s (%s new, %s C/s)\n",
	    s_line,
	    status.password_count, prev.password_count ? prev.password_count - status.password_count : 0,
	    status.salt_count, prev.salt_count ? prev.salt_count - status.salt_count : 0,
	    time, new_time,
	    status.guess_count, status.guess_count - prev.guess_count,
	    status_get_cps(s_gps, status.guess_count - prev.guess_count, 0, new_time),
	    (unsigned long long)status.cands, (unsigned long long)(status.cands - prev.cands),
	    status_get_cps(s_pps, status.cands - prev.cands, 0, new_time),
	    status.suppressor_end ? "wa" : "i", (status.suppressor_start | status.suppressor_end) ? "en" : "dis", s_when,
	    status.suppressor_miss, 100.0 * status.suppressor_miss / (suppressor_total ? suppressor_total : 1),
	    status_get_cps(s_mps, status.suppressor_miss, 0, suppressor_time),
	    status.suppressor_hit, 100.0 * status.suppressor_hit / (suppressor_total ? suppressor_total : 1),
	    status_get_cps(s_hps, status.suppressor_hit, 0, suppressor_time),
	    suppressor_total,
	    status_get_cps(s_tps, suppressor_total, 0, suppressor_time),
	    (unsigned long long)status.crypts, (unsigned long long)(status.crypts - prev.crypts),
	    status_get_cps(s_crypts_ps, status.crypts - prev.crypts, 0, new_time),
	    status_get_c(s_combs, status.combs, status.combs_ehi),
	    status.combs_ehi ? "N/A" : status_get_c(s_combs_new, status.combs - prev.combs, 0),
	    status.combs_ehi ? "N/A" : status_get_cps(s_combs_ps, status.combs - prev.combs, 0, new_time));
	prev = status;
	prev_time = time;
}
