/*
 * This software is Copyright (c) 2015 Sayantan Datta <stdatta at openwall dot com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */
#ifdef HAVE_OPENCL

#include "opencl_common.h"

#define FORMAT_LABEL	           "mscash2-opencl"

/*
 * Acceptable Values : 2 , 4 , 8 ,16 , 32 , 64 , 128 ,256 , 512 , 1024 , 2048 , 5120 , 10240
 */
#define ITERATION_COUNT_PER_CALL  	1024
#define MAX_SALT_LENGTH           	128
#define SALT_BUFFER_SIZE		((((MAX_SALT_LENGTH + 1) << 1) + sizeof(cl_uint)) / sizeof(cl_uint) * sizeof(cl_uint))

/*
 * Initialize host side buffer for all devices.
 */
extern void initNumDevices(void);

/*
 * selectDevice(int jtrUniqDevNo,struct fmt_main *fmt)
 * jtrUniqDevNo:Each device is assigned a unqiue number by john.
 * Returns optimal global work size for selected device/
 */
extern size_t selectDevice(int jtrUniqDevId, struct fmt_main *self);

/*
 * Release various host/device buffers.
 */
extern void releaseAll(void);

/*
 *  Enqueue kernels and synchronize multiple devices.
 */
extern void dcc2Execute(cl_uint *hostDccHashes, cl_uint *hostSha1Hashes, cl_uint *hostSalt, cl_uint saltlen, cl_uint iterCount, cl_uint *hostDcc2Hashes, cl_uint numKeys);

#endif
