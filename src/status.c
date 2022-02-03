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
	return status_restored_time +
		(status_get_raw_time() - status.start_time) / clk_tck;
}

static char *status_get_cps(char *buffer, uint64_t c, unsigned int c_ehi, unsigned long time_override, clock_t ticks_override)
{
	int use_ticks;
	clock_t ticks;
	unsigned long time;
	uint64_t cps;

	if (!c && !c_ehi)
		return "0";

	use_ticks = (c <= 0xffffffffU && !c_ehi && !status_restored_time);

	ticks = ticks_override ? ticks_override : status_get_raw_time() - status.start_time;
	if (use_ticks)
		time = ticks;
	else
		time = time_override ? time_override : status_restored_time + ticks / clk_tck;
	if (!time)
		time = 1;

	cps = c;
	if (c_ehi)
		cps = ((uint64_t)c_ehi << 32) | (c >> 32);
	if (use_ticks)
		cps *= clk_tck;
	cps /= time;
	if (c_ehi)
		cps <<= 32;

	if (cps >= 1000000000000000ULL) {
		sprintf(buffer, "%uT", (unsigned int)(cps / 1000000000000ULL));
	} else
	if (cps >= (uint64_t)1000000 * 1000000) {
		sprintf(buffer, "%uG", (unsigned int)(cps / 1000000000));
	} else if (cps >= 1000000000) {
		sprintf(buffer, "%uM", (unsigned int)(cps / 1000000));
	} else if (cps >= 1000000) {
		sprintf(buffer, "%uK", (unsigned int)(cps / 1000));
	} else if (cps >= 1000) {
		sprintf(buffer, "%u", (unsigned int)cps);
	} else {
		const char *fmt;
		unsigned int div, frac;
		fmt = "%u.%06u"; div = 1000000;
		if (cps >= 100) {
			fmt = "%u.%u"; div = 10;
		} else if (cps >= 10) {
			fmt = "%u.%02u"; div = 100;
		} else if (cps >= 1) {
			fmt = "%u.%03u"; div = 1000;
		}
		frac = (use_ticks ? (c * clk_tck) : c) * div / time;
		if (div == 1000000) {
			if (frac >= 100000) {
				fmt = "%u.%04u"; div = 10000; frac /= 100;
			} else if (frac >= 10000) {
				fmt = "%u.%05u"; div = 100000; frac /= 10;
			}
		}
		frac %= div;
		sprintf(buffer, fmt, (unsigned int)cps, frac);
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
static void status_print_cracking(double percent, char *gpustat)
#else
static void status_print_cracking(double percent)
#endif
{
	unsigned int time = status_get_time();
	char *key1, key2[PLAINTEXT_BUFFER_SIZE];
	char t1buf[PLAINTEXT_BUFFER_SIZE + 1];
	char s_gps[32], s_pps[32], s_crypts_ps[32], s_combs_ps[32];
	char s[1024], *p;
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

	p = s;
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
	    status_get_cps(s_gps, status.guess_count, 0, 0, 0));
	if (n > 0)
		p += n;

	if (!status.compat) {
		n = sprintf(p,
		    "%.31sp/s %.31sc/s ",
		    status_get_cps(s_pps, status.cands, 0, 0, 0),
		    status_get_cps(s_crypts_ps, status.crypts, 0, 0, 0));
		if (n > 0)
			p += n;
	}

#if defined(HAVE_OPENCL)
	n = sprintf(p, "%.31sC/s%s%s%.200s%s%.200s\n",
	    status_get_cps(s_combs_ps, status.combs, status.combs_ehi, 0, 0),
	    gpustat,
	    key1 ? " " : "", key1 ? key1 : "", key2[0] ? ".." : "", key2);
#else
	n = sprintf(p, "%.31sC/s%s%.200s%s%.200s\n",
	    status_get_cps(s_combs_ps, status.combs, status.combs_ehi, 0, 0),
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

	fwrite(s, p - s, 1, stderr);
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

static void status_print_stdout(double percent)
{
	unsigned int time = status_get_time();
	char *key;
	char s_pps[32], s_p[32];

	key = NULL;
	if (!(options.flags & FLG_STATUS_CHK) && status.cands)
		key = crk_get_key1();

	fprintf(stderr,
	    "%sp %u:%02u:%02u:%02u %.02f%%%s %sp/s%s%s\n",
	    status_get_c(s_p, status.cands, 0),
	    time / 86400, time % 86400 / 3600, time % 3600 / 60, time % 60,
	        percent < 0 ? 0 : percent,
	    status_get_ETA(percent, time),
	    status_get_cps(s_pps, status.cands, 0, 0, 0),
	    key ? " " : "", key ? key : "");
}

void status_print(int level)
{
	if (!level) {
		level = event_status;
		event_status = 0;
	}

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

	if (options.flags & FLG_STDOUT)
		status_print_stdout(percent_value);
	else
#if defined(HAVE_OPENCL)
		status_print_cracking(percent_value, s_gpu);
#else
		status_print_cracking(percent_value);
#endif

	if (level < 2)
		return;

	static struct status_main prev;
	static clock_t prev_raw_time;
	static unsigned int prev_time;
	clock_t raw_time = status_get_raw_time() - status.start_time;
	unsigned int time = status_restored_time + raw_time / clk_tck;
	unsigned int new_time = time - prev_time;
	clock_t new_raw_time = raw_time - prev_raw_time;
	char s_gps[32], s_pps[32], s_crypts_ps[32], s_combs_ps[32];
	char s_combs[32], s_combs_new[32];
	fprintf(stderr,
	    "Remaining hashes    %u (%u removed)\n"
	    "Remaining salts     %u (%u removed)\n"
	    "Time in seconds     %u (%.*f new)\n"
	    "Successful guesses  %u (%u new, %s g/s)\n"
	    "Password candidates %llu (%llu new, %s p/s)\n"
	    "Hash computations   %llu (%llu new, %s c/s)\n"
	    "Hash combinations   %s (%s new, %s C/s)\n",
	    status.password_count, prev.password_count ? prev.password_count - status.password_count : 0,
	    status.salt_count, prev.salt_count ? prev.salt_count - status.salt_count : 0,
	    time,
	    status_restored_time ? 0 : 2,
	    status_restored_time ? new_time : (double)new_raw_time / clk_tck,
	    status.guess_count, status.guess_count - prev.guess_count,
	    status_get_cps(s_gps, status.guess_count - prev.guess_count, 0, new_time, new_raw_time),
	    (unsigned long long)status.cands, (unsigned long long)(status.cands - prev.cands),
	    status_get_cps(s_pps, status.cands - prev.cands, 0, new_time, new_raw_time),
	    (unsigned long long)status.crypts, (unsigned long long)(status.crypts - prev.crypts),
	    status_get_cps(s_crypts_ps, status.crypts - prev.crypts, 0, new_time, new_raw_time),
	    status_get_c(s_combs, status.combs, status.combs_ehi),
	    status.combs_ehi ? "N/A" : status_get_c(s_combs_new, status.combs - prev.combs, 0),
	    status.combs_ehi ? "N/A" : status_get_cps(s_combs_ps, status.combs - prev.combs, 0, new_time, new_raw_time));
	prev = status;
	prev_raw_time = raw_time;
	prev_time = time;
}
