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
	self->params.max_keys_per_crypt = (global_work_size ? global_work_size: get_task_max_size());

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
	self->params.min_keys_per_crypt = local_work_size;
	self->params.max_keys_per_crypt = global_work_size;
}

#endif  /* _COMMON_TUNE_H */
