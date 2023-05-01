/*
 * Developed by Claudio André <claudioandre.br at gmail.com> in 2012
 *
 * Copyright (c) 2012-2015 Claudio André <claudioandre.br at gmail.com>
 * This program comes with ABSOLUTELY NO WARRANTY; express or implied.
 *
 * This is free software, and you are welcome to redistribute it
 * under certain conditions; as expressed here
 * http://www.gnu.org/licenses/gpl-2.0.html
 */

#ifdef HAVE_OPENCL

#include "opencl_common.h"

/* Allow the developer to select configurable step size for gws. */
int autotune_get_next_gws_size(size_t num, int step, int startup,
                               int default_value)
{
	if (startup) {
		if (step == 0)
			return GET_EXACT_MULTIPLE(default_value, local_work_size);
		else
			return GET_EXACT_MULTIPLE(step, local_work_size);
	}

	if (step < 1)
		return num * 2;

	return num + step;
}

int autotune_get_prev_gws_size(size_t num, int step)
{
	int value;

	if (step < 1)
		value = MAX(1, num >> 1);
	else
		value = MAX(1, num - step);

	if (value < local_work_size)
		local_work_size = value;

	return value;
}

/* Can be used to select a 'good' default lws size */
size_t autotune_get_task_max_work_group_size(int use_local_memory,
                                           int local_memory_size,
                                           cl_kernel crypt_kernel)
{

	size_t max_available;

	if (use_local_memory)
		max_available = get_local_memory_size(gpu_id) /
			(local_memory_size);
	else
		max_available = get_device_max_lws(gpu_id);

	if (max_available > get_kernel_max_lws(gpu_id, crypt_kernel))
		return get_kernel_max_lws(gpu_id, crypt_kernel);

	return max_available;
}

/* Can be used to select a 'good' default gws size */
size_t autotune_get_task_max_size(int multiplier, int keys_per_core_cpu,
                                int keys_per_core_gpu, cl_kernel crypt_kernel)
{
	size_t max_available;

	max_available = get_max_compute_units(gpu_id);

	if (cpu(device_info[gpu_id]))
		return max_available * keys_per_core_cpu;
	else if (gpu_intel(device_info[gpu_id]))
		return 0;
	else
		return max_available * multiplier * keys_per_core_gpu *
			get_kernel_max_lws(gpu_id, crypt_kernel);
}

/* --
   This function could be used to calculated the best local
   group size for the given format
   -- */
void autotune_find_best_lws(size_t group_size_limit,
                          int sequential_id, cl_kernel crypt_kernel)
{
	//Call the default function.
	opencl_find_best_lws(group_size_limit, sequential_id, crypt_kernel);
}

/* --
   This function could be used to calculated the best num
   of keys per crypt for the given format
   -- */
void autotune_find_best_gws(int sequential_id, unsigned int rounds, int step,
                            int max_duration, int have_lws)
{
	char *tmp_value;

	if ((tmp_value = getenv("STEP")))
		step = atoi(tmp_value);

	step = GET_MULTIPLE_OR_ZERO(step, local_work_size);

	//Call the default function.
	opencl_find_best_gws(step, max_duration, sequential_id, rounds, have_lws);
}

#endif
