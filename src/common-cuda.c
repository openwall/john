#include <ctype.h>
#include "cuda_common.h"
#include "options.h"

#ifndef HAVE_OPENCL
/* If we have OpenCL as well, we use its exact same function */
void advance_cursor()
{
	static int pos = 0;
	char cursor[4] = { '/', '-', '\\', '|' };
	fprintf(stderr, "%c\b", cursor[pos]);
	pos = (pos + 1) % 4;
}
#endif

void cuda_init(unsigned int cuda_gpu_id)
{
	int devices;
	struct list_entry *current;

	if ((current = options.gpu_devices->head)) {
		if (current->next) {
			fprintf(stderr, "Only one CUDA device supported.\n");
			exit(1);
		}
		if (!isdigit(current->data[0])) {
			fprintf(stderr, "Invalid CUDA device id \"%s\"\n",
			        current->data);
			exit(1);
		}
		cuda_gpu_id = atoi(current->data);
	} else
		cuda_gpu_id = 0;

	HANDLE_ERROR(cudaGetDeviceCount(&devices));
	if (cuda_gpu_id < devices && devices > 0)
		cudaSetDevice(cuda_gpu_id);
	else {
		fprintf(stderr, "Invalid CUDA device id = %d\n", cuda_gpu_id);
		exit(1);
	}
}
