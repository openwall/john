/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2004,2006,2010-2013,2017 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/times.h>

#include "times.h"

#include "misc.h"
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
		(get_time() - status.start_time) / clk_tck;
}

static char *status_get_cps(char *buffer, uint64_t c, unsigned int c_ehi)
{
	int use_ticks;
	clock_t ticks;
	unsigned long time;
	uint64_t cps;

	if (!c && !c_ehi)
		return "0";

	use_ticks = (c <= 0xffffffffU && !c_ehi && !status_restored_time);

	ticks = get_time() - status.start_time;
	if (use_ticks)
		time = ticks;
	else
		time = status_restored_time + ticks / clk_tck;
	if (!time) time = 1;

	cps = c;
	if (c_ehi)
		cps = ((uint64_t)c_ehi << 32) | (c >> 32);
	if (use_ticks)
		cps *= clk_tck;
	cps /= time;
	if (c_ehi)
		cps <<= 32;

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

static void status_print_cracking(char *percent)
{
	unsigned int time = status_get_time();
	char *key1, key2[PLAINTEXT_BUFFER_SIZE];
	char s_gps[32], s_pps[32], s_crypts_ps[32], s_combs_ps[32];
	char s[1024], *p;
	int n;

	key1 = NULL;
	key2[0] = 0;
	if (!(options.flags & FLG_STATUS_CHK) && status.crypts) {
		char *key = crk_get_key2();
		if (key)
			strnzcpy(key2, key, sizeof(key2));
		key1 = crk_get_key1();
	}

	p = s;
	if (options.fork) {
		n = sprintf(p, "%u ", options.node_min);
		if (n > 0)
			p += n;
	}

	n = sprintf(p,
	    "%ug %u:%02u:%02u:%02u%.100s %.31sg/s ",
	    status.guess_count,
	    time / 86400, time % 86400 / 3600, time % 3600 / 60, time % 60,
	    percent,
	    status_get_cps(s_gps, status.guess_count, 0));
	if (n > 0)
		p += n;

	if (!status.compat) {
		n = sprintf(p,
		    "%.31sp/s %.31sc/s ",
		    status_get_cps(s_pps, status.cands, 0),
		    status_get_cps(s_crypts_ps, status.crypts, 0));
		if (n > 0)
			p += n;
	}

	n = sprintf(p, "%.31sC/s%s%.200s%s%.200s\n",
	    status_get_cps(s_combs_ps, status.combs, status.combs_ehi),
	    key1 ? " " : "", key1 ? key1 : "", key2[0] ? ".." : "", key2);
	if (n > 0)
		p += n;

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

static void status_print_stdout(char *percent)
{
	unsigned int time = status_get_time();
	char *key;
	char s_pps[32], s_p[32];

	key = NULL;
	if (!(options.flags & FLG_STATUS_CHK) && status.cands)
		key = crk_get_key1();

	fprintf(stderr,
	    "%sp %u:%02u:%02u:%02u%s %sp/s%s%s\n",
	    status_get_c(s_p, status.cands, 0),
	    time / 86400, time % 86400 / 3600, time % 3600 / 60, time % 60,
	    percent,
	    status_get_cps(s_pps, status.cands, 0),
	    key ? " " : "", key ? key : "");
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
		sprintf(s_percent, status.pass ? " %d%% %d/3" : " %d%%",
		    percent_value, status.pass);
	else
	if (status.pass)
		sprintf(s_percent, " %d/3", status.pass);

	if (options.flags & FLG_STDOUT)
		status_print_stdout(s_percent);
	else
		status_print_cracking(s_percent);
}
