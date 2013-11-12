/*
 * Developed by Claudio André <claudio.andre at correios.net.br> in 2012
 *
 *
 * Copyright (c) 2012 Claudio André <claudio.andre at correios.net.br>
 * This program comes with ABSOLUTELY NO WARRANTY; express or implied.
 *
 * This is free software, and you are welcome to redistribute it
 * under certain conditions; as expressed here
 * http://www.gnu.org/licenses/gpl-2.0.html
 */

#ifndef _COMMON_TUNE_H
#define _COMMON_TUNE_H

/* Macro for get a multiple of a given value */
#define GET_MULTIPLE_BIGGER(dividend, divisor)	(local_work_size) ? (((dividend + divisor - 1) / divisor) * divisor) : (dividend)

//Necessary definitions.
static size_t get_task_max_size();
static size_t get_default_workgroup();
static size_t get_task_max_work_group_size();
static void create_clobj(size_t gws, struct fmt_main * self);
static void find_best_lws(struct fmt_main * self, int sequential_id);
static void find_best_gws(struct fmt_main * self, int sequential_id);

/* --
  This function does the common part of auto-tune adjustments,
  preparation and execution. It is shared code to be inserted
  in each format file.
-- */
static void common_run_auto_tune(struct fmt_main * self) {

	/* Read LWS/GWS prefs from config or environment */
	opencl_get_user_preferences(OCL_CONFIG);

	if (!global_work_size && !getenv("GWS"))
		global_work_size = get_task_max_size();

	if (!local_work_size && !getenv("LWS"))
		local_work_size = get_default_workgroup();

	//Check if local_work_size is a valid number.
	if (local_work_size > get_task_max_work_group_size()){
		local_work_size = 0; //Force find a valid number.
	}
	self->params.max_keys_per_crypt =  opencl_v_width *
		(global_work_size ? global_work_size : get_task_max_size());

	/* Enumerate GWS using *LWS=NULL (unless it was set explicitly) */
	if (!global_work_size)
		find_best_gws(self, ocl_gpu_id);
	else
		create_clobj(global_work_size, self);

	if (!local_work_size)
		find_best_lws(self, ocl_gpu_id);

	if (options.verbosity > 2)
		fprintf(stderr,
		        "Local worksize (LWS) %zd, global worksize (GWS) %zd\n",
		        local_work_size, global_work_size);
	self->params.min_keys_per_crypt = local_work_size * opencl_v_width;
	self->params.max_keys_per_crypt = global_work_size * opencl_v_width;
}

/* Can be used to select a 'good' default gws size */
size_t common_get_task_max_size(int multiplier, int keys_per_core_cpu,
	int keys_per_core_gpu, cl_kernel crypt_kernel);

/* Can be used to select a 'good' default lws size */
size_t common_get_task_max_work_group_size(int use_local_memory,
	int local_memory_size, cl_kernel crypt_kernel);

/* --
  This function could be used to calculated the best num
  of keys per crypt for the given format
-- */
void common_find_best_gws(int sequential_id, unsigned int rounds, int step,
	unsigned long long int max_run_time);

/* --
  This function could be used to calculated the best local
  group size for the given format
-- */
void common_find_best_lws(size_t group_size_limit,
	int sequential_id, cl_kernel crypt_kernel);

#endif  /* _COMMON_TUNE_H */
