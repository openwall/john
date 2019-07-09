/*
 * This software is Copyright (c) 2015 Sayantan Datta <stdatta at openwall dot com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */
#ifdef HAVE_OPENCL

#include <sys/time.h>

#include "opencl_mscash2_helper_plug.h"
#include "options.h"

#define PADDING				1024

typedef struct {
	unsigned int 	istate[5];
	unsigned int 	ostate[5];
	unsigned int 	buf[5];
	unsigned int 	out[4];
} devIterTempSz;

typedef struct {
	cl_mem bufferDccHashes;
	cl_mem bufferSha1Hashes;
	cl_mem bufferSalt;
	cl_mem bufferDcc2Hashes;
	cl_mem bufferIterTemp;
} deviceBuffer;

typedef struct {
	cl_kernel devKernel[4];
	size_t devLws;
	size_t devGws;
	unsigned int devInUse;
} deviceParam;

static deviceBuffer *devBuffer = NULL;
static deviceParam *devParam = NULL;
static cl_event *events = NULL;
static unsigned int eventCtr = 0;
static unsigned int maxActiveDevices = 0;

void initNumDevices(void)
{
	devBuffer = (deviceBuffer *) mem_calloc(MAX_GPU_DEVICES, sizeof(deviceBuffer));
	devParam = (deviceParam *) mem_calloc(MAX_GPU_DEVICES, sizeof(deviceParam));
	events = (cl_event *) mem_alloc(MAX_GPU_DEVICES * sizeof(cl_event));
}

static void createDevObjGws(size_t gws, int jtrUniqDevId)
{
	devBuffer[jtrUniqDevId].bufferDccHashes = clCreateBuffer(context[jtrUniqDevId], CL_MEM_READ_ONLY, 4 * (gws + PADDING) * sizeof(cl_uint), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Failed allocating bufferDccHashes.");

	devBuffer[jtrUniqDevId].bufferDcc2Hashes = clCreateBuffer(context[jtrUniqDevId], CL_MEM_WRITE_ONLY, 4 * (gws + PADDING) * sizeof(cl_uint), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Failed allocating bufferDcc2Hashes.");

	devBuffer[jtrUniqDevId].bufferIterTemp = clCreateBuffer(context[jtrUniqDevId], CL_MEM_READ_WRITE, (gws + PADDING) * sizeof(devIterTempSz), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Failed allocating bufferIterTemp.");

	devBuffer[jtrUniqDevId].bufferSha1Hashes = clCreateBuffer(context[jtrUniqDevId], CL_MEM_READ_WRITE, 5 * (gws + PADDING) * sizeof(cl_uint), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Failed allocating bufferSha1Hashes.");

	HANDLE_CLERROR(clSetKernelArg(devParam[jtrUniqDevId].devKernel[0], 0, sizeof(cl_mem), &devBuffer[jtrUniqDevId].bufferDccHashes), "Set Kernel 0 Arg 0 :FAILED");
	HANDLE_CLERROR(clSetKernelArg(devParam[jtrUniqDevId].devKernel[0], 3, sizeof(cl_mem), &devBuffer[jtrUniqDevId].bufferIterTemp), "Set Kernel 0 Arg 3 :FAILED");
	HANDLE_CLERROR(clSetKernelArg(devParam[jtrUniqDevId].devKernel[1], 0, sizeof(cl_mem), &devBuffer[jtrUniqDevId].bufferDccHashes), "Set Kernel 1 Arg 0 :FAILED");
	HANDLE_CLERROR(clSetKernelArg(devParam[jtrUniqDevId].devKernel[1], 1, sizeof(cl_mem), &devBuffer[jtrUniqDevId].bufferIterTemp), "Set Kernel 1 Arg 1 :FAILED");
	HANDLE_CLERROR(clSetKernelArg(devParam[jtrUniqDevId].devKernel[1], 2, sizeof(cl_mem), &devBuffer[jtrUniqDevId].bufferSha1Hashes), "Set Kernel 1 Arg 2 :FAILED");
	HANDLE_CLERROR(clSetKernelArg(devParam[jtrUniqDevId].devKernel[2], 0, sizeof(cl_mem), &devBuffer[jtrUniqDevId].bufferIterTemp), "Set Kernel 2 Arg 0 :FAILED");
	HANDLE_CLERROR(clSetKernelArg(devParam[jtrUniqDevId].devKernel[3], 0, sizeof(cl_mem), &devBuffer[jtrUniqDevId].bufferIterTemp), "Set Kernel 3 Arg 0 :FAILED");
	HANDLE_CLERROR(clSetKernelArg(devParam[jtrUniqDevId].devKernel[3], 1, sizeof(cl_mem), &devBuffer[jtrUniqDevId].bufferDcc2Hashes), "Set Kernel 3 Arg 1 :FAILED");
}

static void releaseDevObjGws(int jtrUniqDevId)
{
	if (devBuffer[jtrUniqDevId].bufferIterTemp) {
		HANDLE_CLERROR(clReleaseMemObject(devBuffer[jtrUniqDevId].bufferDccHashes), "Failed releasing bufferDccHashes.");
		HANDLE_CLERROR(clReleaseMemObject(devBuffer[jtrUniqDevId].bufferDcc2Hashes), "Failed releasing bufferDcc2Hashes.");
		HANDLE_CLERROR(clReleaseMemObject(devBuffer[jtrUniqDevId].bufferIterTemp), "Failed releasing bufferIterTemp.");
		HANDLE_CLERROR(clReleaseMemObject(devBuffer[jtrUniqDevId].bufferSha1Hashes), "Failed releasing bufferSha1Hashes.");
		devBuffer[jtrUniqDevId].bufferIterTemp = 0;
	}
}

static void createDevObj(int jtrUniqDevId)
{
	devBuffer[jtrUniqDevId].bufferSalt = clCreateBuffer(context[jtrUniqDevId], CL_MEM_READ_ONLY, SALT_BUFFER_SIZE, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Failed allocating bufferSalt.");

	HANDLE_CLERROR(clSetKernelArg(devParam[jtrUniqDevId].devKernel[0], 1, sizeof(cl_mem), &devBuffer[jtrUniqDevId].bufferSalt), "Set Kernel 0 Arg 1 :FAILED");
}

static void releaseDevObj(int jtrUniqDevId)
{
	if (devBuffer[jtrUniqDevId].bufferSalt) {
		HANDLE_CLERROR(clReleaseMemObject(devBuffer[jtrUniqDevId].bufferSalt), "Failed releasing bufferSalt.");
		devBuffer[jtrUniqDevId].bufferSalt = 0;
	}
}

void releaseAll()
{
	int 	i;

	for (i = 0; i < get_number_of_devices_in_use(); i++) {
	releaseDevObjGws(engaged_devices[i]);
	releaseDevObj(engaged_devices[i]);
	if (devParam[engaged_devices[i]].devKernel[0]) {
		HANDLE_CLERROR(clReleaseKernel(devParam[engaged_devices[i]].devKernel[0]), "Error releasing kernel pbkdf2_preprocess_short");
		HANDLE_CLERROR(clReleaseKernel(devParam[engaged_devices[i]].devKernel[1]), "Error releasing kernel pbkdf2_preprocess_long");
		HANDLE_CLERROR(clReleaseKernel(devParam[engaged_devices[i]].devKernel[2]), "Error releasing kernel pbkdf2_iter");
		HANDLE_CLERROR(clReleaseKernel(devParam[engaged_devices[i]].devKernel[3]), "Error releasing kernel pbkdf2_postprocess");
		HANDLE_CLERROR(clReleaseProgram(program[engaged_devices[i]]), "Error releasing Program");
		devParam[engaged_devices[i]].devKernel[0] = 0;
		}
	 }

	 MEM_FREE(events);
	 MEM_FREE(devBuffer);
	 MEM_FREE(devParam);
}

static size_t findLwsLimit(int jtrUniqDevId)
{
	size_t minLws[4] = { 0 };

	minLws[0] = get_kernel_max_lws(jtrUniqDevId, devParam[jtrUniqDevId].devKernel[0]);
	minLws[1] = get_kernel_max_lws(jtrUniqDevId, devParam[jtrUniqDevId].devKernel[1]);
	minLws[2] = get_kernel_max_lws(jtrUniqDevId, devParam[jtrUniqDevId].devKernel[2]);
	minLws[3] = get_kernel_max_lws(jtrUniqDevId, devParam[jtrUniqDevId].devKernel[3]);

	if (minLws[0] > minLws[1])
		minLws[0] = minLws[1];
	if (minLws[2] > minLws[3])
		minLws[2] = minLws[3];
	if (minLws[0] > minLws[2])
		minLws[0] = minLws[2];

	return minLws[0];
}

static size_t preferredLwsSize(int jtrUniqDevId)
{
	size_t minLws[4] = { 0 };

	minLws[0] = get_kernel_preferred_multiple(jtrUniqDevId, devParam[jtrUniqDevId].devKernel[0]);
	minLws[1] = get_kernel_preferred_multiple(jtrUniqDevId, devParam[jtrUniqDevId].devKernel[1]);
	minLws[2] = get_kernel_preferred_multiple(jtrUniqDevId, devParam[jtrUniqDevId].devKernel[2]);
	minLws[3] = get_kernel_preferred_multiple(jtrUniqDevId, devParam[jtrUniqDevId].devKernel[3]);

	if (minLws[0] > minLws[1])
		minLws[0] = minLws[1];
	if (minLws[2] > minLws[3])
		minLws[2] = minLws[3];
	if (minLws[0] > minLws[2])
		minLws[0] = minLws[2];

	return minLws[0];
}

static void execKernel(cl_uint *hostDccHashes, cl_uint *hostSha1Hashes, cl_uint *hostSalt, cl_uint saltlen, unsigned int iterCount, cl_uint *hostDcc2Hashes, cl_uint keyCount, int jtrUniqDevId, cl_command_queue cmdQueue)
{
	size_t 		N = keyCount, *M = devParam[jtrUniqDevId].devLws ? &devParam[jtrUniqDevId].devLws : NULL;
	unsigned int 	i, itrCntKrnl = ITERATION_COUNT_PER_CALL;

	N = devParam[jtrUniqDevId].devLws ? (keyCount + devParam[jtrUniqDevId].devLws - 1) / devParam[jtrUniqDevId].devLws * devParam[jtrUniqDevId].devLws : keyCount;

	HANDLE_CLERROR(clEnqueueWriteBuffer(cmdQueue, devBuffer[jtrUniqDevId].bufferDccHashes, CL_FALSE, 0, 4 * keyCount * sizeof(cl_uint), hostDccHashes, 0, NULL, NULL ), "Failed in clEnqueueWriteBuffer bufferDccHashes.");
	if (saltlen > 22)
		HANDLE_CLERROR(clEnqueueWriteBuffer(cmdQueue, devBuffer[jtrUniqDevId].bufferSha1Hashes, CL_FALSE, 0, 5 * keyCount * sizeof(cl_uint), hostSha1Hashes, 0, NULL, NULL ), "Failed in clEnqueueWriteBuffer bufferSha1Hashes.");
	else
	      HANDLE_CLERROR(clSetKernelArg(devParam[jtrUniqDevId].devKernel[0], 2, sizeof(cl_uint), &saltlen), "Set Kernel 0 Arg 2 :FAILED");

	HANDLE_CLERROR(clEnqueueWriteBuffer(cmdQueue, devBuffer[jtrUniqDevId].bufferSalt, CL_FALSE, 0, SALT_BUFFER_SIZE, hostSalt, 0, NULL, NULL ), "Failed in clEnqueueWriteBuffer bufferSalt.");

	if (saltlen < 23)
		HANDLE_CLERROR(clEnqueueNDRangeKernel(cmdQueue, devParam[jtrUniqDevId].devKernel[0], 1, NULL, &N, M, 0, NULL, NULL), "Failed in clEnqueueNDRangeKernel devKernel[0].");
	else
		HANDLE_CLERROR(clEnqueueNDRangeKernel(cmdQueue, devParam[jtrUniqDevId].devKernel[1], 1, NULL, &N, M, 0, NULL, NULL), "Failed in clEnqueueNDRangeKernel devKernel[1].");

	for (i = 0; i < iterCount - 1; i += itrCntKrnl ) {
		if (i + itrCntKrnl >= iterCount)
			itrCntKrnl = iterCount - i - 1;

		HANDLE_CLERROR(clSetKernelArg(devParam[jtrUniqDevId].devKernel[2], 1, sizeof(cl_uint), &itrCntKrnl), "Set Kernel 1 Arg 1 :FAILED");

		M = devParam[jtrUniqDevId].devLws ? &devParam[jtrUniqDevId].devLws : NULL;
		HANDLE_CLERROR(clEnqueueNDRangeKernel(cmdQueue, devParam[jtrUniqDevId].devKernel[2], 1, NULL, &N, M, 0, NULL, NULL), "Failed in clEnqueueNDRangeKernel devKernel[2].");

		opencl_process_event();
	}

	M = devParam[jtrUniqDevId].devLws ? &devParam[jtrUniqDevId].devLws : NULL;
	HANDLE_CLERROR(clEnqueueNDRangeKernel(cmdQueue, devParam[jtrUniqDevId].devKernel[3], 1, NULL, &N, M, 0, NULL, &events[eventCtr]), "Failed in clEnqueueNDRangeKernel devKernel[2].");

        eventCtr++;
}

static size_t autoTune(int jtrUniqDevId, long double kernelRunMs)
{
	size_t gwsLimit, gwsInit, gwsRound;
	size_t lwsLimit, lwsInit;

	struct timeval startc, endc;
	long double timeMs = 0, minTimeMs = 0;

	size_t pcount, count;

	int tuneGws, tuneLws;

	cl_uint *hostDccHashes, *hostSalt, *hostDcc2Hashes;

	unsigned int i;
	unsigned int a = 0xffaabbcc;
	unsigned int b = 0xbbccaaee;
	unsigned int c = 0xccffbbdd;
	unsigned int d = 0xff123456;

	gwsLimit = get_max_mem_alloc_size
		   (jtrUniqDevId) / sizeof(devIterTempSz);
	get_power_of_two(gwsLimit);
	if (gwsLimit + PADDING >
		get_max_mem_alloc_size
		(jtrUniqDevId) / sizeof(devIterTempSz))
		gwsLimit >>= 1;

	lwsLimit = findLwsLimit(jtrUniqDevId);
	lwsInit = preferredLwsSize(jtrUniqDevId);

	gwsInit = 1024;
	gwsRound = 8192;
	if (cpu(device_info[jtrUniqDevId])) {
		gwsInit = 256;
		gwsRound = 64;
		if (lwsLimit > 8)
			lwsLimit = 8;
		if (lwsInit > 8)
			lwsInit = 8;
	}

	if (gwsInit > gwsLimit)
		gwsInit = gwsLimit;
	if (gwsInit < lwsInit)
		lwsInit = gwsInit;

	local_work_size = 0;
	global_work_size = 0;
	tuneGws = 1;
	tuneLws = 1;
	opencl_get_user_preferences(FORMAT_LABEL);
	if (local_work_size) {
		tuneLws = 0;
		if (local_work_size & (local_work_size - 1))
			get_power_of_two(local_work_size);
		if (local_work_size > lwsLimit)
			local_work_size = lwsLimit;
	}
	if (global_work_size)
		tuneGws = 0;

	devParam[jtrUniqDevId].devLws = local_work_size;
	devParam[jtrUniqDevId].devGws = global_work_size;

#if 0
	 fprintf(stderr, "lwsInit:"Zu" lwsLimit:"Zu""
			 " gwsInit:"Zu" gwsLimit:"Zu"\n",
			  lwsInit, lwsLimit, gwsInit,
			  gwsLimit);
#endif
	/* Auto tune start.*/
	pcount = gwsInit;
	count = 0;
#define calcMs(start, end)	\
		((long double)(end.tv_sec - start.tv_sec) * 1000.000 + \
			(long double)(end.tv_usec - start.tv_usec) / 1000.000)
	if (tuneGws) {
		createDevObjGws(pcount, jtrUniqDevId);
		hostDccHashes = (cl_uint *) mem_alloc(pcount * sizeof(cl_uint) * 4);
		hostDcc2Hashes = (cl_uint *) mem_calloc(pcount * 4, sizeof(cl_uint));
		hostSalt = (cl_uint *) mem_alloc(SALT_BUFFER_SIZE);
		for (i = 0; i < pcount; i++) {
			hostDccHashes[i * 4] = a++;
			hostDccHashes[i * 4 + 1] = a + b++;
			hostDccHashes[i * 4 + 2] = c++;
			hostDccHashes[i * 4 + 3] = c + d++;
		}
		memset(hostSalt, 0x2B, SALT_BUFFER_SIZE);

		gettimeofday(&startc, NULL);
		eventCtr = 0;
		execKernel(hostDccHashes, NULL, hostSalt, 20, 10240, hostDcc2Hashes, pcount, jtrUniqDevId, queue[jtrUniqDevId]);
		HANDLE_CLERROR(clFinish(queue[jtrUniqDevId]), "Finish Error");
		gettimeofday(&endc, NULL);

		timeMs = calcMs(startc, endc);
		count = (size_t)((kernelRunMs / timeMs) * (long double)gwsInit);
		count = GET_NEXT_MULTIPLE(count, gwsRound);

		MEM_FREE(hostDccHashes);
		MEM_FREE(hostDcc2Hashes);
		MEM_FREE(hostSalt);
		releaseDevObjGws(jtrUniqDevId);

		pcount = count;
		createDevObjGws(pcount, jtrUniqDevId);
		hostDccHashes = (cl_uint *) mem_alloc(pcount * sizeof(cl_uint) * 4);
		hostDcc2Hashes = (cl_uint *) mem_calloc(pcount * 4, sizeof(cl_uint));
		hostSalt = (cl_uint *) mem_alloc(SALT_BUFFER_SIZE);
		for (i = 0; i < pcount; i++) {
			hostDccHashes[i * 4] = a++;
			hostDccHashes[i * 4 + 1] = a + b++;
			hostDccHashes[i * 4 + 2] = c++;
			hostDccHashes[i * 4 + 3] = c + d++;
		}
		memset(hostSalt, 0x2B, SALT_BUFFER_SIZE);

		gettimeofday(&startc, NULL);
		eventCtr = 0;
		execKernel(hostDccHashes, NULL, hostSalt, 20, 10240, hostDcc2Hashes, pcount, jtrUniqDevId, queue[jtrUniqDevId]);
		HANDLE_CLERROR(clFinish(queue[jtrUniqDevId]), "Finish Error");
		gettimeofday(&endc, NULL);

		timeMs = calcMs(startc, endc);
		count = (size_t)((kernelRunMs / timeMs) * (long double)count);
		count = GET_NEXT_MULTIPLE(count, gwsRound);

		MEM_FREE(hostDccHashes);
		MEM_FREE(hostDcc2Hashes);
		MEM_FREE(hostSalt);
	}

	if (tuneGws && tuneLws)
		releaseDevObjGws(jtrUniqDevId);

	if (tuneLws) {
		size_t bestLws;
		count = tuneGws ? count : devParam[jtrUniqDevId].devGws;

		createDevObjGws(count, jtrUniqDevId);
		pcount = count;
		hostDccHashes = (cl_uint *) mem_alloc(pcount * sizeof(cl_uint) * 4);
		hostDcc2Hashes = (cl_uint *) mem_calloc(pcount * 4, sizeof(cl_uint));
		hostSalt = (cl_uint *) mem_alloc(SALT_BUFFER_SIZE);
		for (i = 0; i < pcount; i++) {
			hostDccHashes[i * 4] = a++;
			hostDccHashes[i * 4 + 1] = a + b++;
			hostDccHashes[i * 4 + 2] = c++;
			hostDccHashes[i * 4 + 3] = c + d++;
		}
		memset(hostSalt, 0x2B, SALT_BUFFER_SIZE);

		devParam[jtrUniqDevId].devLws = lwsInit;

		gettimeofday(&startc, NULL);
		eventCtr = 0;
		execKernel(hostDccHashes, NULL, hostSalt, 20, 10240, hostDcc2Hashes, pcount, jtrUniqDevId, queue[jtrUniqDevId]);
		HANDLE_CLERROR(clFinish(queue[jtrUniqDevId]), "Finish Error");
		gettimeofday(&endc, NULL);

		timeMs = calcMs(startc, endc);

		minTimeMs = timeMs;
		bestLws = devParam[jtrUniqDevId].devLws;

		devParam[jtrUniqDevId].devLws = 2 * lwsInit;

		while (devParam[jtrUniqDevId].devLws <= lwsLimit) {
			for (i = 0; i < pcount; i++) {
				hostDccHashes[i * 4] = a++;
				hostDccHashes[i * 4 + 1] = a + b++;
				hostDccHashes[i * 4 + 2] = c++;
				hostDccHashes[i * 4 + 3] = c + d++;
			}
			gettimeofday(&startc, NULL);
			pcount = count;
			eventCtr = 0;
			execKernel(hostDccHashes, NULL, hostSalt, 20, 10240, hostDcc2Hashes, pcount, jtrUniqDevId, queue[jtrUniqDevId]);
			HANDLE_CLERROR(clFinish(queue[jtrUniqDevId]), "Finish Error");
			gettimeofday(&endc, NULL);

			timeMs = calcMs(startc, endc);

			if (minTimeMs > timeMs) {
				minTimeMs = timeMs;
				bestLws = devParam[jtrUniqDevId].devLws;
			}

			devParam[jtrUniqDevId].devLws *= 2;
		}

		devParam[jtrUniqDevId].devLws = bestLws;

		if (devParam[jtrUniqDevId].devLws > lwsLimit)
			devParam[jtrUniqDevId].devLws = lwsLimit;

		MEM_FREE(hostDccHashes);
		MEM_FREE(hostDcc2Hashes);
		MEM_FREE(hostSalt);
	}

	if (tuneGws && tuneLws) {
		count = (size_t)((kernelRunMs / minTimeMs) * (long double)count);
		count = GET_NEXT_MULTIPLE(count, gwsRound);
	}

	if (tuneGws) {
		if (count > gwsLimit)
			count = gwsLimit;
		releaseDevObjGws(jtrUniqDevId);
		createDevObjGws(count, jtrUniqDevId);
		devParam[jtrUniqDevId].devGws = count;
	}

	if (!tuneGws && !tuneLws)
		createDevObjGws(devParam[jtrUniqDevId].devGws, jtrUniqDevId);
	/* Auto tune finish.*/

	if (devParam[jtrUniqDevId].devGws % gwsRound) {
		devParam[jtrUniqDevId].devGws = GET_NEXT_MULTIPLE(devParam[jtrUniqDevId].devGws, gwsRound);
		releaseDevObjGws(jtrUniqDevId);
		if (devParam[jtrUniqDevId].devGws > gwsLimit)
			devParam[jtrUniqDevId].devGws = gwsLimit;
		createDevObjGws(devParam[jtrUniqDevId].devGws, jtrUniqDevId);
	}

	if (devParam[jtrUniqDevId].devGws > gwsLimit) {
		releaseDevObjGws(jtrUniqDevId);
		devParam[jtrUniqDevId].devGws = gwsLimit;
		createDevObjGws(devParam[jtrUniqDevId].devGws, jtrUniqDevId);
	}

	if ((!self_test_running && options.verbosity >= VERB_DEFAULT) ||
	    ocl_always_show_ws)
		fprintf(stdout, "Dev#%d LWS="Zu" GWS="Zu"%s", jtrUniqDevId,
		        devParam[jtrUniqDevId].devLws, devParam[jtrUniqDevId].devGws,
		        benchmark_running ? " " : "\n");

#undef calcMs
	return devParam[jtrUniqDevId].devGws;
}

size_t selectDevice(int jtrUniqDevId, struct fmt_main *self)
{
	char buildOpts[300];

	sprintf(buildOpts, "-D SALT_BUFFER_SIZE=" Zu, SALT_BUFFER_SIZE);
	opencl_init("$JOHN/opencl/pbkdf2_kernel.cl", jtrUniqDevId, buildOpts);

	devParam[jtrUniqDevId].devKernel[0] = clCreateKernel(program[jtrUniqDevId], "pbkdf2_preprocess_short", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel pbkdf2_preprocess_short.");

	devParam[jtrUniqDevId].devKernel[1] = clCreateKernel(program[jtrUniqDevId], "pbkdf2_preprocess_long", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel pbkdf2_preprocess_long.");

	devParam[jtrUniqDevId].devKernel[2] = clCreateKernel(program[jtrUniqDevId], "pbkdf2_iter", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel pbkdf2_iter.");

	devParam[jtrUniqDevId].devKernel[3] = clCreateKernel(program[jtrUniqDevId], "pbkdf2_postprocess", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel pbkdf2_postprocess.");

	createDevObj(jtrUniqDevId);

	maxActiveDevices++;

	return autoTune(jtrUniqDevId, 1000);
}

void dcc2Execute(cl_uint *hostDccHashes, cl_uint *hostSha1Hashes, cl_uint *hostSalt, cl_uint saltlen, cl_uint iterCount, cl_uint *hostDcc2Hashes, cl_uint numKeys)
{
	int 		i;
	unsigned int 	workPart, workOffset = 0;
	cl_int 		ret;

#ifdef  _DEBUG
	struct timeval startc, endc;
#endif

	eventCtr = 0;
	memset(hostDcc2Hashes, 0, numKeys * sizeof(cl_uint));

	///Divide memory and work
	for (i = 0; i < maxActiveDevices; ++i) {
		if (i == maxActiveDevices - 1)
			workPart = numKeys - workOffset;
		else
			workPart = devParam[engaged_devices[i]].devGws;

		if ((int)workPart <= 0)
			workPart = devParam[engaged_devices[i]].devLws;
#ifdef  _DEBUG
		gettimeofday(&startc, NULL) ;
		fprintf(stderr, "Work Offset:%d  Work Part Size:%d Event No:%d",workOffset,workPart,event_ctr);

		if (workPart != devParam[engaged_devices[i]].devGws)
			fprintf(stderr, "Deficit: %d "Zu"\n",  engaged_devices[i], devParam[engaged_devices[i]].devGws - workPart);
#endif

		///call to execKernel()
		execKernel(hostDccHashes + 4 * workOffset, hostSha1Hashes + 5 * workOffset, hostSalt, saltlen, iterCount, hostDcc2Hashes + 4 * workOffset, workPart, engaged_devices[i], queue[engaged_devices[i]]);
		workOffset += workPart;

#ifdef  _DEBUG
		gettimeofday(&endc, NULL);
		fprintf(stderr, "GPU enqueue time:%f\n",(endc.tv_sec - startc.tv_sec) + (double)(endc.tv_usec - startc.tv_usec) / 1000000.000) ;
#endif
	}

	///Synchronize all kernels
	for (i = maxActiveDevices - 1; i >= 0; --i)
		HANDLE_CLERROR(clFlush(queue[engaged_devices[i]]), "Flush Error");

	for (i = 0; i < maxActiveDevices; ++i) {
		while (1) {
			HANDLE_CLERROR(clGetEventInfo(events[i], CL_EVENT_COMMAND_EXECUTION_STATUS, sizeof(cl_int), &ret, NULL), "Error in Get Event Info");
			if ((ret) == CL_COMPLETE)
				break;
#ifdef  _DEBUG
			 printf("%d%d ", ret, i);
#endif
		}
	}

	eventCtr = workPart = workOffset = 0;

	///Read results back from all kernels
	for (i = 0; i < maxActiveDevices; ++i) {
		if (i == maxActiveDevices - 1)
			workPart = numKeys - workOffset;

		else
			workPart = devParam[engaged_devices[i]].devGws;

		if ((int)workPart <= 0)
			workPart = devParam[engaged_devices[i]].devLws;

#ifdef  _DEBUG
		gettimeofday(&startc, NULL) ;
		fprintf(stderr, "Work Offset:%d  Work Part Size:%d Event No:%d",workOffset,workPart,eventCtr);
#endif

		///Read results back from device
		HANDLE_CLERROR(clEnqueueReadBuffer(queue[engaged_devices[i]],
					devBuffer[engaged_devices[i]].bufferDcc2Hashes,
						CL_FALSE, 0,
						4 * workPart * sizeof(cl_uint),
						hostDcc2Hashes + 4 * workOffset,
						0,
						NULL,
						NULL), "Write :FAILED");
			workOffset += workPart;

#ifdef  _DEBUG
			gettimeofday(&endc, NULL);
			fprintf(stderr, "GPU enqueue time:%f\n",(endc.tv_sec - startc.tv_sec) + (double)(endc.tv_usec - startc.tv_usec) / 1000000.000) ;
#endif
			HANDLE_CLERROR(clReleaseEvent(events[i]), "Error releasing events[i].");
		}

	for (i = 0; i < maxActiveDevices; ++i)
		HANDLE_CLERROR(clFinish(queue[engaged_devices[i]]), "Finish Error");

}

#endif
