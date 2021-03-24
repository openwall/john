/*
 * This software is Copyright (c) 2018 magnum
 * and is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modifications, are permitted.
 */

#ifdef _OPENMP
#include <omp.h>
#endif

#include "john.h"
#include "options.h"
#include "logger.h"
#include "formats.h"
#include "timer.h"
#include "config.h"

#define CONF_SECTION SECTION_OPTIONS, ":CPUtune"

static int use_preset, max_no_progress;
static double req_gain, max_tune_time;
static uint64_t sample_time;
static struct fmt_main *fmt;
static int omp_autotune_running;
static int mkpc;
static int omp_scale;
static int report;
static int fmt_preset;
static int tune_preset;
static int scale = 1;

void omp_autotune_init(void)
{
	int ci;

#if __i386__ || __x86_64__ || __MIC__
	use_preset = cfg_get_bool(CONF_SECTION, "UsePreset", 1);
#else
	// Our presets are from intel[tm] CPUs. Anything else should autotune
	use_preset = 0;
#endif
	if ((ci = cfg_get_int(CONF_SECTION, "AutoTuneSampleTime")) < 0)
		ci = 10;
	sample_time = ci * 1000000ULL;
	if ((ci = cfg_get_int(CONF_SECTION, "AutoTuneReqGain")) < 0)
		ci = 5;
	req_gain = (double)ci / 100.0 + 1.0;
	if ((ci = cfg_get_int(CONF_SECTION, "AutoTuneMaxDuration")) < 0)
		ci = 100;
	max_tune_time = (double)ci / 1000.0;
	if ((max_no_progress =
	     cfg_get_int(CONF_SECTION, "AutoTuneMaxNoProgress")) < 0)
		max_no_progress = 3;

	if (options.tune) {
		if (!strcmp(options.tune, "auto"))
			use_preset = 0;
		else if (!strcmp(options.tune, "report")) {
			use_preset = 0;
			report = 1;
		} else {
			use_preset = 1;
			tune_preset = atoi(options.tune);
		}
	}
}

int omp_autotune(struct fmt_main *format, int preset)
{
#ifdef _OPENMP
	int threads = (format->params.flags & FMT_OMP) ? omp_get_max_threads() : 1;
#else
	int threads = 1;
#endif
	int ret_scale;

	fmt_preset = preset;

	omp_scale = tune_preset ? tune_preset : (use_preset ? preset : 0);
	ret_scale = tune_preset ? tune_preset : (threads == 1 ? 1 : (omp_scale ? omp_scale : 1));

	if (omp_autotune_running)
		return threads * scale;

	if (!use_preset || !preset) {
		fmt = format;
		mkpc = format->params.max_keys_per_crypt;
	}
	format->params.min_keys_per_crypt *= threads;
	format->params.max_keys_per_crypt *= threads * ret_scale;

	return threads * ret_scale;
}

void omp_autotune_run(struct db_main *db)
{
#ifdef _OPENMP
	int threads =
		fmt ? ((fmt->params.flags & FMT_OMP) ? omp_get_max_threads() : 1) : 1;
#else
	int threads = 1;
#endif
	int best_scale = 1;
	int best_cps = 0;
	int no_progress = 0;
	int min_crypts = 0;
	int tune_cost;
	void *salt;
	char key[PLAINTEXT_BUFFER_SIZE] = "tUne0000";
	uint64_t start, end;
	double duration;

	if (!fmt || omp_scale == 1 || tune_preset)
		goto cleanup;

	if (john_main_process && (options.flags & FLG_TEST_CHK) &&
	    ((options.tune && !strcmp(options.tune, "report")) ||
	     options.verbosity > VERB_DEFAULT))
		printf("\n");

	scale = 1;
	omp_autotune_running = 1;

	// Find most expensive salt, for auto-tune
	{
		struct db_salt *s = db->salts;

		tune_cost = MIN(db->max_cost[0], options.loader.max_cost[0]);

		while (s->next && s->cost[0] < tune_cost)
			s = s->next;
		salt = s->salt;
	}

	if (john_main_process && options.verbosity >= VERB_MAX) {
		printf("%s %s autotune using %s db",
		       fmt->params.label, threads > 1 ? "OMP" : "MKPC",
		       db->real ? "real" : "test");
		if (fmt->methods.tunable_cost_value[0])
			printf(" with %s of %d\n",
			       fmt->params.tunable_cost_name[0], tune_cost);
		printf("\n");
	}

	do {
		int i;
		int min_kpc = fmt->params.min_keys_per_crypt;
		int this_kpc = mkpc * threads * scale;
		int cps, crypts = 0;

		if (threads == 1)
			this_kpc = min_kpc * scale; // We're tuning MKPC

		fmt->params.max_keys_per_crypt = this_kpc;

		// Release old buffers
		fmt->methods.done();

		// Set up buffers for this test
		fmt->methods.init(fmt);

		// Format may have bumped kpc in init()
		this_kpc = fmt->params.max_keys_per_crypt;

		// Load keys
		fmt->methods.clear_keys();
		for (i = 0; i < this_kpc; i++) {
			key[4] = '0' + (i / 1000) % 10;
			key[5] = '0' + (i / 100) % 10;
			key[6] = '0' + (i / 10) % 10;
			key[7] = '0' + i % 10;
			fmt->methods.set_key(key, i);
		}

		// Set the salt we picked earlier
		fmt->methods.set_salt(salt);

		// Tell format this is a speed test
		benchmark_running++;

		start = john_get_nano();
		do {
			int count = this_kpc;

			fmt->methods.crypt_all(&count, NULL);
			crypts += count;
			end = john_get_nano();
		} while (crypts < min_crypts || (end - start) < sample_time);

		benchmark_running--;

		duration = (end - start) / 1E9;
		cps = crypts / duration;

		if (john_main_process && options.verbosity >= VERB_MAX) {
			if (threads > 1)
				printf("OMP scale %d: %d crypts (%dx%d) in %ss, %s",
				       scale, crypts, crypts / this_kpc, this_kpc, human_prefix_small(duration),
				       human_speed(cps));
			else
				printf("MKPC %d: %d crypts (%dx%d) in %ss, %s",
				       this_kpc, crypts, crypts / this_kpc, this_kpc, human_prefix_small(duration),
				       human_speed(cps));
		}

		if (cps >= (best_cps * req_gain)) {
			if (john_main_process && options.verbosity >= VERB_MAX)
				printf(" +\n");
			best_cps = cps;
			best_scale = scale;
			no_progress = 0;
		}
		else {
			if (john_main_process && options.verbosity >= VERB_MAX)
				printf("\n");
			no_progress++;
		}

		min_crypts = crypts;

		if (duration > max_tune_time || no_progress >= max_no_progress)
			break;

		if (threads == 1 && min_kpc == 1) {
			int quick_move = 1;

			while (crypts / this_kpc / quick_move > 8192) {
				quick_move *= 2;
				scale *= 2;
			}
		}

		// Double each time
		scale *= 2;
	} while (1);

	if (options.tune && !strcmp(options.tune, "report")) {
		if (threads == 1) {
			if (best_scale * fmt->params.min_keys_per_crypt != mkpc)
				printf("Autotuned MKPC %d, preset is %d\n",
				       best_scale * fmt->params.min_keys_per_crypt, mkpc);
		} else {
			if (best_scale != fmt_preset)
				printf("Autotuned OMP scale %d, preset is %d\n",
				       best_scale, fmt_preset);
		}
	} else {
		if (threads == 1) {
			if (john_main_process && options.verbosity > VERB_DEFAULT)
				printf("Autotune found best speed at MKPC of %d (%d * %d)\n",
				       best_scale * fmt->params.min_keys_per_crypt,
				       best_scale, fmt->params.min_keys_per_crypt);
			log_event("Autotune found best speed at MKPC of %d (%d * %d)",
			          best_scale * fmt->params.min_keys_per_crypt,
			          best_scale, fmt->params.min_keys_per_crypt);
		} else {
			if (john_main_process && options.verbosity > VERB_DEFAULT)
				printf("Autotune found best speed at OMP scale of %d\n",
				       best_scale);
			log_event("Autotune found best speed at OMP scale of %d", best_scale);
		}
	}

	if (best_scale != scale) {
		scale = best_scale;

		// Release old buffers
		fmt->methods.done();

		// Set up buffers for chosen scale
		fmt->methods.init(fmt);
	}

cleanup:
	omp_autotune_running = 0;
	fmt = NULL;
	omp_scale = 0;
	mkpc = 0;
	scale = 1;

	return;
}
