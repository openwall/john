/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2004,2006,2010,2011 by Solar Designer
 */

#ifdef __ultrix__
#define __POSIX
#define _POSIX_SOURCE
#endif

#ifdef _SCO_C_DIALECT
#include <limits.h>
#endif
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/times.h>

#include "times.h"

#include "misc.h"
#include "math.h"
#include "params.h"
#include "cracker.h"
#include "options.h"
#include "status.h"
#include "bench.h"

struct status_main status;
unsigned int status_restored_time = 0;
int (*status_get_progress)(void) = NULL;

static clock_t get_time(void)
{
	struct tms buf;

	return times(&buf);
}

void status_init(int (*get_progress)(void), int start)
{
	if (start) {
		if (!status_restored_time)
			memset(&status, 0, sizeof(status));
		status.start_time = get_time();
	}

	status_get_progress = get_progress;

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

void status_update_crypts(unsigned int count)
{
	unsigned int saved_hi;

	saved_hi = status.crypts.hi;
	add32to64(&status.crypts, count);

	if (status.crypts.hi != saved_hi)
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
		"%s  "
		"w/s: %s",
		s_words_ptr,
		time / 86400, time % 86400 / 3600, time % 3600 / 60, time % 60,
		percent,
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
	char *key, saved_key[PLAINTEXT_BUFFER_SIZE];
	char s_cps[64];

	if (!(options.flags & FLG_STATUS_CHK)) {
		if ((key = crk_get_key2()))
			strnzcpy(saved_key, key, PLAINTEXT_BUFFER_SIZE);
		else
			saved_key[0] = 0;
	}

	fprintf(stderr,
		"guesses: %u  "
		"time: %u:%02u:%02u:%02u"
		"%s  "
		"c/s: %s",
		status.guess_count,
		time / 86400, time % 86400 / 3600, time % 3600 / 60, time % 60,
		percent,
		status_get_cps(s_cps));

	if ((options.flags & FLG_STATUS_CHK) ||
	    !(status.crypts.lo | status.crypts.hi))
		fputc('\n', stderr);
	else
		fprintf(stderr,
			"  trying: %s%s%s\n",
			crk_get_key1(), saved_key[0] ? " - " : "", saved_key);
}

void status_print(void)
{
	int percent_value;
	char s_percent[32];

	percent_value = -1;
	if (options.flags & FLG_STATUS_CHK)
		percent_value = status.progress;
	else
	if (status_get_progress)
		percent_value = status_get_progress();

	s_percent[0] = 0;
	if (percent_value >= 0)
		sprintf(s_percent, status.pass ? " %d%% (%d)" : " %d%%",
			percent_value, status.pass);
	else
	if (status.pass)
		sprintf(s_percent, " (%d)", status.pass);

	if (options.flags & FLG_STDOUT)
		status_print_stdout(s_percent);
	else
		status_print_cracking(s_percent);
}
