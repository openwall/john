/*
 * Developed by Claudio André <claudioandre.br at gmail.com> in 2012
 *
 *
 * Copyright (c) 2012-2015 Claudio André <claudioandre.br at gmail.com>
 * This program comes with ABSOLUTELY NO WARRANTY; express or implied.
 *
 * This is free software, and you are welcome to redistribute it
 * under certain conditions; as expressed here
 * http://www.gnu.org/licenses/gpl-2.0.html
 */

#ifndef _COMMON_TUNE_H
#define _COMMON_TUNE_H

#include "config.h"
#include "logger.h"
#include "mask_ext.h"
#include "john.h"
#include "recovery.h"
#include "opencl_common.h"

/* Step size for work size enumeration. Zero will double. */
#ifndef STEP
#define STEP	0
#endif

/* Start size for GWS enumeration */
#ifndef SEED
#define SEED	128
#endif

//Necessary definitions. Each format have to have each one of them.
static size_t get_task_max_work_group_size();
static void create_clobj(size_t gws, struct fmt_main *self);
static void release_clobj(void);

/* Keeps track of whether we already tuned */
static int autotuned;

/* ------- Externals ------- */
/* Can be used to select a 'good' default gws size */
size_t autotune_get_task_max_size(int multiplier, int keys_per_core_cpu,
	int keys_per_core_gpu, cl_kernel crypt_kernel);

/* Can be used to select a 'good' default lws size */
size_t autotune_get_task_max_work_group_size(int use_local_memory,
	int local_memory_size, cl_kernel crypt_kernel);

/* --
  This function could be used to calculated the best num
  of keys per crypt for the given format
-- */
void autotune_find_best_gws(int sequential_id, unsigned int rounds, int step,
	int max_duration, int have_lws);

/* --
  This function could be used to calculated the best local
  group size for the given format
-- */
void autotune_find_best_lws(size_t group_size_limit,
	int sequential_id, cl_kernel crypt_kernel);

/* ------- Try to find the best configuration ------- */
/* --
  This function could be used to calculated the best num
  for the workgroup
  Work-items that make up a work-group (also referred to
  as the size of the work-group)
-- */
static void find_best_lws(struct fmt_main *self, int sequential_id)
{
	//Call the default function.
	autotune_find_best_lws(
		get_task_max_work_group_size(), sequential_id, crypt_kernel
	);
}

/* --
  This function could be used to calculated the best num
  of keys per crypt for the given format
-- */
static void find_best_gws(struct fmt_main *self, int sequential_id,
	unsigned int rounds, int max_duration, int have_lws)
{
	//Call the common function.
	autotune_find_best_gws(sequential_id, rounds, STEP, max_duration, have_lws);

	create_clobj(global_work_size, self);
}

static void autotune_run(struct fmt_main *self, unsigned int rounds,
	size_t gws_limit, int max_duration);

/* --
  This function does the common part of auto-tune adjustments,
  preparation and execution. It is shared code to be inserted
  in each format file.
-- */
static void autotune_run_extra(struct fmt_main *self, unsigned int rounds,
	size_t gws_limit, int max_duration, cl_uint lws_is_power_of_two)
{
	int need_best_lws, need_best_gws, needed_best_gws;

	ocl_autotune_running = 1;

#if SIZEOF_SIZE_T > 4
	/* We can't process more than 4G keys per crypt() */
	while (gws_limit * mask_int_cand.num_int_cand > 0xffffffffUL)
		gws_limit >>= 1;
#endif

	/* Read LWS/GWS prefs from config or environment */
	opencl_get_user_preferences(FORMAT_LABEL);

	if (!global_work_size && !getenv("GWS"))
		global_work_size = 0;

	need_best_lws = !local_work_size && !getenv("LWS");
	if (need_best_lws) {
		int cfg_lws;

		cfg_lws = cfg_get_int(SECTION_OPTIONS, SUBSECTION_OPENCL,
		                      "AutotuneLWS");

		switch (cfg_lws) {
		case 0:
			// Use NULL (OpenCL implementation will decide)
			local_work_size = 0;
			break;

		case 1:
			// Set from OpenCL query (warp size)
			local_work_size =
				get_kernel_preferred_multiple(gpu_id, crypt_kernel);
			break;

		default:
			if (cfg_lws < 0) {
				fprintf(stderr,
				    "Error: AutotuneLWS must be a positive number (now set to %d)\n",
				    cfg_lws);
				error();
			}
			if (cpu(device_info[gpu_id]))
				local_work_size =
					get_platform_vendor_id(platform_id) == DEV_INTEL ?
					8 : 1;
			else {
				// 1st run with fixed figure
				local_work_size = cfg_lws;
			}
			break;
		}
	}

	if (gws_limit && (global_work_size > gws_limit))
		global_work_size = gws_limit;

	if (lws_is_power_of_two && (local_work_size & (local_work_size - 1)))
		  get_power_of_two(local_work_size);

	/* Adjust, if necessary */
	if (!local_work_size)
		global_work_size = GET_MULTIPLE_OR_ZERO(global_work_size, 64);
	else if (global_work_size)
		global_work_size = GET_MULTIPLE_OR_ZERO(global_work_size, local_work_size);

	/* Ensure local_work_size is not oversized */
	ocl_max_lws = get_task_max_work_group_size();
	if (local_work_size > ocl_max_lws) {
		local_work_size = ocl_max_lws;
		if (lws_is_power_of_two && (local_work_size & (local_work_size - 1))) {
		  get_power_of_two(local_work_size);
		  local_work_size >>= 1;
		}
	}

	/* Enumerate GWS using *LWS=NULL (unless it was set explicitly) */
	needed_best_gws = need_best_gws = !global_work_size;
	if (need_best_gws) {
		int max_duration1 = max_duration;
		int have_lws = !(!local_work_size || need_best_lws);
		if (have_lws) {
			need_best_gws = 0;
		} else if (mask_int_cand.num_int_cand < 2) {
			max_duration1 = (max_duration + 1) / 2;
		}
		find_best_gws(self, gpu_id, rounds, max_duration1, have_lws);
	} else {
		create_clobj(global_work_size, self);
	}

	if (!local_work_size || need_best_lws) {
		find_best_lws(self, gpu_id);
		if (lws_is_power_of_two && (local_work_size & (local_work_size - 1))) {
			get_power_of_two(local_work_size);
			local_work_size >>= 1;
		}
	}

	if (need_best_gws) {
		release_clobj();
		find_best_gws(self, gpu_id, rounds, max_duration, 1);
	}

#if HAVE_MPI
	if (autotune_real_db && mpi_p > 1 &&
	    !(options.lws && options.gws) && !rec_restored &&
	    cfg_get_bool(SECTION_OPTIONS, SUBSECTION_MPI, "MPIAllGPUsSame", 0)) {
		uint32_t lws, gws, mpi_lws, mpi_gws;

		if (john_main_process)
			log_event("- Enforcing same work sizes on all MPI nodes");
		lws = local_work_size;
		gws = global_work_size;
		MPI_Allreduce(&lws, &mpi_lws, 1, MPI_UNSIGNED, MPI_MIN, MPI_COMM_WORLD);
		MPI_Allreduce(&gws, &mpi_gws, 1, MPI_UNSIGNED, MPI_MIN, MPI_COMM_WORLD);
		local_work_size = mpi_lws;
		global_work_size = mpi_gws;

		if (john_main_process && !(options.flags & FLG_SHOW_CHK) &&
		    ((autotune_real_db && !mask_increments_len) ||
		     options.verbosity > VERB_DEFAULT)) {
			fprintf(stderr,
"All nodes: Local worksize (LWS) "Zu", global worksize (GWS) "Zu" ("Zu" blocks)\n",
			        local_work_size, global_work_size,
			        global_work_size / local_work_size);
		}
	} else
#endif
	if (!(options.flags & FLG_SHOW_CHK) && !(options.lws && options.gws) &&
	    ((autotune_real_db && !mask_increments_len) ||
	     options.verbosity > VERB_DEFAULT)) {
		if (benchmark_running)
			fprintf(stderr, "\n");
		if (options.node_count)
			fprintf(stderr, "%u: ", NODE);
		fprintf(stderr,
"Local worksize (LWS) "Zu", global worksize (GWS) "Zu" ("Zu" blocks)\n",
		        local_work_size, global_work_size,
		        global_work_size / local_work_size);
	}
#ifdef DEBUG
	else if (!(options.flags & FLG_SHOW_CHK))
		fprintf(stderr, "{"Zu"/"Zu"} ", global_work_size, local_work_size);
#endif

	/* Adjust to the final configuration */
	release_clobj();
	global_work_size = GET_EXACT_MULTIPLE(global_work_size, local_work_size);
	create_clobj(global_work_size, self);

#if HAVE_MPI
	if (!cfg_get_bool(SECTION_OPTIONS, SUBSECTION_MPI, "MPIAllGPUsSame", 0) ||
	    john_main_process)
#endif
	log_event("- OpenCL LWS: "Zu"%s, GWS: "Zu" %s("Zu" blocks)",
	          local_work_size,
	          (need_best_lws && !needed_best_gws) ? " (auto-tuned)" : "",
	          global_work_size,
	          (need_best_lws && needed_best_gws) ? "(both auto-tuned) " :
	          (needed_best_gws) ? "(auto-tuned) " : "",
	          global_work_size / local_work_size);

	self->params.min_keys_per_crypt = opencl_calc_min_kpc(local_work_size,
	                                                      global_work_size,
	                                                      ocl_v_width);
	self->params.max_keys_per_crypt = global_work_size * ocl_v_width;

	autotuned++;
	ocl_autotune_running = 0;

	/* Just suppress a compiler warning */
	if (0) autotune_run(NULL, 0, 0, 0);
}

static void autotune_run(struct fmt_main *self, unsigned int rounds,
	size_t gws_limit, int max_duration)
{
	return autotune_run_extra(self, rounds, gws_limit, max_duration, CL_FALSE);
}

#endif  /* _COMMON_TUNE_H */
