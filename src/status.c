/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2004,2006,2010-2012 by Solar Designer
 *
 * ...with changes in the jumbo patch, by JimF.
 */

#ifdef __ultrix__
#define __POSIX
#define _POSIX_SOURCE
#endif

#ifdef _SCO_C_DIALECT
#include <limits.h>
#endif
#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <time.h>
#if !defined (__MINGW32__) && !defined (_MSC_VER)
#include <sys/times.h>
#endif

#include "times.h"

#if defined(__GNUC__) && defined(__i386__)
#include "arch.h" /* for CPU_REQ */
#endif

#include "misc.h"
#include "math.h"
#include "params.h"
#include "cracker.h"
#include "options.h"
#include "status.h"
#include "bench.h"
#include "config.h"
#include "unicode.h"
#include "signals.h"

#ifdef HAVE_MPI
#include "logger.h"
#include "john-mpi.h"
#endif

struct status_main status;
unsigned int status_restored_time = 0;
static char* timeformat = NULL;
static double ETAthreshold = 0.05;
static int showcand;
int (*status_get_progress)(int *) = NULL;

#if CPU_REQ && defined(__GNUC__) && defined(__i386__)
/* ETA reporting would be wrong when cracking some hash types at least on a
 * Pentium 3 without this... */
#define emms() \
	__asm__ __volatile__("emms");
#else
#define emms()
#endif

static clock_t get_time(void)
{
#if defined (__MINGW32__) || defined (_MSC_VER)
	return clock();
#else
	struct tms buf;

	return times(&buf);
#endif
}

void status_init(int (*get_progress)(int *), int start)
{
	char *cfg_threshold;
	if (start) {
		if (!status_restored_time)
			memset(&status, 0, sizeof(status));
		status.start_time = get_time();
	}

	status_get_progress = get_progress;

	if (!(timeformat = cfg_get_param(SECTION_OPTIONS, NULL, "TimeFormat")))
		timeformat = "%c";

	if ((cfg_threshold = cfg_get_param(SECTION_OPTIONS, NULL, "ETAthreshold")))
		if ((ETAthreshold = atof(cfg_threshold)) < 0.01)
			ETAthreshold = 0.01;

	showcand = cfg_get_bool(SECTION_OPTIONS, NULL, "StatusShowCandidates", 0);

	clk_tck_init();
}

void status_ticks_overflow_safety(void)
{
	unsigned int time;
	clock_t ticks;

	ticks = get_time() - status.start_time;
	if (ticks > ((clock_t)1 << (sizeof(clock_t) * 8 - 2))) {
		time = ticks / clk_tck;
		status_restored_time += time;
		status.start_time += (clock_t)time * clk_tck;
	}
}

void status_update_crypts(int64 *count)
{
	unsigned int saved_hi;

	saved_hi = status.crypts.hi;
	add64to64(&status.crypts, count);

	if (status.crypts.hi != saved_hi &&
	    !count->hi && count->lo <= 0x00100000)
		status_ticks_overflow_safety();
}

unsigned int status_get_time(void)
{
	return status_restored_time +
		(get_time() - status.start_time) / clk_tck;
}

static char *status_get_cps(char *buffer)
{
	int use_ticks;
	clock_t ticks;
	unsigned long time;
	int64 tmp, cps;
	unsigned int cps_100;

	use_ticks = !status.crypts.hi && !status_restored_time;

	ticks = get_time() - status.start_time;
	if (use_ticks)
		time = ticks;
	else
		time = status_restored_time + ticks / clk_tck;
	if (!time) time = 1;

	cps = status.crypts;
	if (use_ticks) mul64by32(&cps, clk_tck);
	div64by32(&cps, time);

	if (cps.hi > 232 || (cps.hi == 232 && cps.lo >= 3567587328U))
		sprintf(buffer, "%uG", div64by32lo(&cps, 1000000000));
	else
	if (cps.hi || cps.lo >= 1000000000)
		sprintf(buffer, "%uM", div64by32lo(&cps, 1000000));
	else
	if (cps.lo >= 1000000)
		sprintf(buffer, "%uK", div64by32lo(&cps, 1000));
	else
	if (cps.lo >= 100)
		sprintf(buffer, "%u", cps.lo);
	else {
		tmp = status.crypts;
		if (use_ticks) mul64by32(&tmp, clk_tck);
		mul64by32(&tmp, 100);
		cps_100 = div64by32lo(&tmp, time) % 100;
		sprintf(buffer, "%u.%02u", cps.lo, cps_100);
	}

	return buffer;
}

static char *status_get_ETA(char *percent, unsigned int secs_done)
{
	static char s_ETA[128];
	char *cp;
	double sec_left, percent_left;
	time_t t_ETA;
	struct tm *pTm;

	emms();

	/* Compute the ETA for this run.  Assumes even run time for
	   work currently done and work left to do, and that the CPU
	   utilization of work done and work to do will stay same
	   which may not always a valid assumtions */
	cp = percent;
	while (cp && *cp && isspace(((unsigned char)(*cp))))
		++cp;
	if (!cp || *cp == 0 || !isdigit(((unsigned char)(*cp))))
		return "";  /* dont show ETA if no valid percentage. */
	else
	{
		double chk;
		percent_left = atof(percent);
		t_ETA = time(NULL);
		if (percent_left >= 100.0) {
			pTm = localtime(&t_ETA);
			strcpy(s_ETA, " (");
			strftime(&s_ETA[2], sizeof(s_ETA)-3, timeformat, pTm);
			strcat(s_ETA, ")");
			return s_ETA;
		}
		if (percent_left == 0 || percent_left < ETAthreshold)
			return "";  /* mute ETA if too little progress */
		percent_left /= 100;
		sec_left = secs_done;
		sec_left /= percent_left;
		sec_left -= secs_done;
		/* Note, many localtime() will fault if given a time_t
		   later than Jan 19, 2038 (i.e. 0x7FFFFFFFF). We
		   check for that here, and if so, this run will
		   not end anyway, so simply tell user to not hold
		   her breath */
		chk = sec_left;
		chk += t_ETA;
		if (chk > 0x7FFFF000) { /* slightly less than 'max' 32 bit time_t, for safety */
			strcpy(s_ETA, " (ETA: never)");
			return s_ETA;
		}
		t_ETA += sec_left;
		pTm = localtime(&t_ETA);
		strcpy(s_ETA, " (ETA: ");
		strftime(&s_ETA[7], sizeof(s_ETA)-10, timeformat, pTm);
		strcat(s_ETA, ")");
	}
	return s_ETA;
}

#ifdef HAVE_MPI
static char *status_get_totalcps(char *buffer)
{
	int use_ticks, bufcat = 0;
	clock_t ticks;
	unsigned long time, sumtime;
	unsigned long long cps;
	double crypts, sumcrypts;
	unsigned cps_100;

	emms();

	use_ticks = !status.crypts.hi && !status_restored_time;

	ticks = get_time() - status.start_time;
	if (use_ticks)
		time = ticks;
	else
		time = status_restored_time + ticks / clk_tck;

	crypts = ((long long)status.crypts.hi << 32) + status.crypts.lo;

	// This calculates the total cps figure (total crypts / avg run time).
	// It will show optimistic if the nodes don't finish at the same time
	MPI_Reduce(&time, &sumtime, 1, MPI_UNSIGNED_LONG, MPI_SUM, 0, MPI_COMM_WORLD);
	MPI_Reduce(&crypts, &sumcrypts, 1, MPI_DOUBLE, MPI_SUM, 0, MPI_COMM_WORLD);
	time = sumtime / mpi_p;
	crypts = sumcrypts;

	if (use_ticks) crypts *= clk_tck;
	cps = crypts / (time ? time : 1);

	if (cps >= 1000000000000LL)
		bufcat = sprintf(buffer, "%lluG", (cps / 1000000000));
	else
	if (cps >= 1000000000)
		bufcat = sprintf(buffer, "%lluM", (cps / 1000000));
	else
	if (cps >= 1000000)
		bufcat = sprintf(buffer, "%lluK", (cps / 1000));
	else
	if (cps >= 100)
		bufcat = sprintf(buffer, "%llu", cps);
	else {
		cps_100 = (unsigned)((unsigned long long)(crypts * 100 / (time ? time : 1)) % 100);
		bufcat = sprintf(buffer, "%llu.%02u", cps, cps_100);
	}

	cps = crypts / mpi_p / (time ? time : 1);

	if (cps >= 1000000000000LL)
		sprintf(&buffer[bufcat], " avg %lluG", (cps / 1000000000));
	else
	if (cps >= 1000000000)
		sprintf(&buffer[bufcat], " avg %lluM", (cps / 1000000));
	else
	if (cps >= 1000000)
		sprintf(&buffer[bufcat], " avg %lluK", (cps / 1000));
	else
	if (cps >= 100)
		sprintf(&buffer[bufcat], " avg %llu", cps);
	else {
		cps_100 = (unsigned)((unsigned long long)(crypts * 100 / mpi_p / (time ? time : 1)) % 100);
		sprintf(&buffer[bufcat], " avg%llu.%02u", cps, cps_100);
	}
	return buffer;
}

static char *status_get_totalETA(char *percent, unsigned int secs_done)
{
	static char s_ETA[128];
	char *cp;
	double sec_left, percent_left, max_sec_left;
	time_t t_ETA;
	struct tm *pTm;

	emms();

	cp = percent;
	while (cp && *cp && isspace(*cp))
		++cp;
	if (!cp || *cp == 0 || !isdigit(*cp)) {
		// We must report to MPI_Allreduce anyway
		sec_left = 0;
		MPI_Allreduce(&sec_left, &max_sec_left, 1, MPI_DOUBLE, MPI_MAX, MPI_COMM_WORLD);
		return "";  /* dont show ETA if no valid percentage. */
	}
	else
	{
		double chk;
		percent_left = atof(percent);
		t_ETA = time(NULL);
		if (percent_left >= 100.0) {
			// We must report to MPI_Allreduce anyway
			sec_left = 0;
			MPI_Allreduce(&sec_left, &max_sec_left, 1, MPI_DOUBLE, MPI_MAX, MPI_COMM_WORLD);
			pTm = localtime(&t_ETA);
			strcpy(s_ETA, " (");
			strftime(&s_ETA[2], sizeof(s_ETA)-3, timeformat, pTm);
			strcat(s_ETA, ")");
			return s_ETA;
		}
		if (percent_left == 0 || percent_left < ETAthreshold) {
			// We must report to MPI_Allreduce anyway
			sec_left = 0;
			MPI_Allreduce(&sec_left, &max_sec_left, 1, MPI_DOUBLE, MPI_MAX, MPI_COMM_WORLD);
			return "";  /* mute ETA if too little progress */
		}
		percent_left /= 100;
		sec_left = secs_done;
		sec_left /= percent_left;
		sec_left -= secs_done;
		// Reports the worst ETA for all nodes
		MPI_Allreduce(&sec_left, &max_sec_left, 1, MPI_DOUBLE, MPI_MAX, MPI_COMM_WORLD);
		sec_left = max_sec_left;

		chk = sec_left;
		chk += t_ETA;
		if (chk > 0x7FFFF000) { /* slightly less than 'max' 32 bit time_t, for safety */
			strcpy(s_ETA, " (ETA: never)");
			return s_ETA;
		}
		t_ETA += sec_left;
		pTm = localtime(&t_ETA);
		strcpy(s_ETA, " (ETA: ");
		strftime(&s_ETA[7], sizeof(s_ETA)-10, timeformat, pTm);
		strcat(s_ETA, ")");
	}
	return s_ETA;
}

static void status_print_total(char *totpercent)
{
	unsigned int max_time, time = status_get_time();
	char s_cps[64];
	char *tot_ETA;
	unsigned int sum_guess;

	MPI_Reduce(&status.guess_count, &sum_guess, 1, MPI_UNSIGNED, MPI_SUM, 0, MPI_COMM_WORLD);
	MPI_Allreduce(&time, &max_time, 1, MPI_UNSIGNED, MPI_MAX, MPI_COMM_WORLD);
	tot_ETA = status_get_totalETA(totpercent, max_time);
	status_get_totalcps(s_cps);
	if (mpi_id == 0) {
		fprintf(stderr,
		        "SUM: guesses: %u "
		        "time: %u:%02u:%02u:%02u"
		        "%s%s "
		        "c/s: %s\n",
		        sum_guess,
		        max_time / 86400, max_time % 86400 / 3600, max_time % 3600 / 60, max_time % 60,
		        strncmp(totpercent, " 100", 4) ? totpercent : " DONE",
		        tot_ETA,
		        s_cps);
	}
}
#endif

static void status_print_stdout(char *percent)
{
	unsigned int time = status_get_time();
	char s_wps[64];
	char s_words[32];
	int64 current, next, rem;
	char *s_words_ptr;

	s_words_ptr = &s_words[sizeof(s_words) - 1];
	*s_words_ptr = 0;

	current = status.crypts;
	do {
		next = current;
		div64by32(&next, 10);
		rem = next;
		mul64by32(&rem, 10);
		neg64(&rem);
		add64to64(&rem, &current);
		*--s_words_ptr = rem.lo + '0';
		current = next;
	} while (current.lo || current.hi);

	fprintf(stderr,
		"words: %s  "
		"time: %u:%02u:%02u:%02u"
		"%s%s  "
		"w/s: %s",
		s_words_ptr,
		time / 86400, time % 86400 / 3600, time % 3600 / 60, time % 60,
		strncmp(percent, " 100", 4) ? percent : " DONE",
		status_get_ETA(percent, time),
		status_get_cps(s_wps));

	if ((options.flags & FLG_STATUS_CHK) ||
	    !(status.crypts.lo | status.crypts.hi))
		fputc('\n', stderr);
	else
		fprintf(stderr,
			"  current: %s\n",
			crk_get_key1());
}

static void status_print_cracking(char *percent)
{
	unsigned int time = status_get_time();
	char *key, saved_key[PLAINTEXT_BUFFER_SIZE] = "";
	char s_cps[64], cand[32] = "";

	emms();

	if (!(options.flags & FLG_STATUS_CHK))
		if ((key = crk_get_key2()))
			strnzcpy(saved_key, key, PLAINTEXT_BUFFER_SIZE);

	if (showcand)
		sprintf(cand, "/%.0f", (double)((long long)status.crypts.hi << 32) + status.crypts.lo);

#ifdef HAVE_MPI
	// we need to print until cr in one call, otherwise output gets interleaved
	char nodeid[11] = "";
	if (mpi_p > 1)
		snprintf(nodeid, sizeof(nodeid), "%3d: ", mpi_id);
	nodeid[sizeof(nodeid)-1] = 0;
	char trying[256];
	if ((options.flags & FLG_STATUS_CHK) ||
	    !(status.crypts.lo | status.crypts.hi))
		trying[0] = 0;
	else {
		UTF8 t1buf[PLAINTEXT_BUFFER_SIZE + 1];
		UTF8 t2buf[PLAINTEXT_BUFFER_SIZE + 1];
		char *t1, *t2;
		if (options.report_utf8 && !options.utf8) {
			t1 = (char*)enc_to_utf8_r(crk_get_key1(), t1buf, PLAINTEXT_BUFFER_SIZE);
			t2 = (char*)enc_to_utf8_r(saved_key, t2buf, PLAINTEXT_BUFFER_SIZE);
		} else {
			t1 = crk_get_key1();
			t2 = saved_key;
		}
		snprintf(trying, sizeof(trying),
		         "%strying: %s%s%s",
		         mpi_p > 1 ? " " : "  ",
		         t1, t2[0] ? " - " : "", t2);
	}

	fprintf(stderr,
	        "%s"
	        "guesses: %u%s%s"
	        "time: %u:%02u:%02u:%02u"
	        "%s%s%s"
	        "c/s: %s"
	        "%s\n",
	        nodeid,
	        status.guess_count, cand,
	        mpi_p > 1 ? " " : "  ",
	        time / 86400, time % 86400 / 3600, time % 3600 / 60, time % 60,
	        strncmp(percent, " 100", 4) ? percent : " DONE",
	        status_get_ETA(percent,time),
	        mpi_p > 1 ? " " : "  ",
	        status_get_cps(s_cps),
	        trying);
#else
	fprintf(stderr,
		"guesses: %u%s  "
		"time: %u:%02u:%02u:%02u"
		"%s%s  "
		"c/s: %s",
		status.guess_count, cand,
		time / 86400, time % 86400 / 3600, time % 3600 / 60, time % 60,
		strncmp(percent, " 100", 4) ? percent : " DONE",
		status_get_ETA(percent,time),
		status_get_cps(s_cps));

	if ((options.flags & FLG_STATUS_CHK) ||
	    !(status.crypts.lo | status.crypts.hi))
		fputc('\n', stderr);
	else {
		UTF8 t1buf[PLAINTEXT_BUFFER_SIZE + 1];
		UTF8 t2buf[PLAINTEXT_BUFFER_SIZE + 1];
		char *t1, *t2;
		if (options.report_utf8 && !options.utf8) {
			t1 = (char*)enc_to_utf8_r(crk_get_key1(), t1buf, PLAINTEXT_BUFFER_SIZE);
			t2 = (char*)enc_to_utf8_r(saved_key, t2buf, PLAINTEXT_BUFFER_SIZE);
		} else {
			t1 = crk_get_key1();
			t2 = saved_key;
		}
		fprintf(stderr,	"  trying: %s%s%s\n",
		        t1, t2[0] ? " - " : "", t2);
	}
#endif
}

void status_print(void)
{
	int percent_value, hund_percent = 0;
	char s_percent[32];

	percent_value = -1;
	if (options.flags & FLG_STATUS_CHK)
		percent_value = status.progress;
	else
	if (status_get_progress)
		percent_value = status_get_progress(&hund_percent);

	s_percent[0] = 0;
	if (percent_value >= 0 && hund_percent >= 0)
		sprintf(s_percent, status.pass ? " %d.%02d%% (%d)" : " %d.%02d%%",
			percent_value, hund_percent, status.pass);
	else
	if (status.pass)
		sprintf(s_percent, " (%d)", status.pass);

	if (options.flags & FLG_STDOUT)
		status_print_stdout(s_percent);
#ifdef HAVE_MPI
	else {
		status_print_cracking(s_percent);
		if (mpi_p > 1 && (options.flags & FLG_STATUS_CHK)) {
			int sum_percent;
			percent_value = 100 * percent_value + hund_percent;
			MPI_Allreduce(&percent_value, &sum_percent, 1, MPI_INT, MPI_SUM, MPI_COMM_WORLD);
			hund_percent = (sum_percent / mpi_p) % 100;
			percent_value = (sum_percent / mpi_p) / 100;

			s_percent[0] = 0;
			if (percent_value >= 0 && hund_percent >= 0)
				sprintf(s_percent, status.pass ? " %d.%02d%% (%d)" : " %d.%02d%%",
				        percent_value, hund_percent, status.pass);
			else
				if (status.pass)
					sprintf(s_percent, " (%d)", status.pass);

			status_print_total(s_percent);
		}
	}
#else
	else
		status_print_cracking(s_percent);
#endif
}
