/*
 * Optimized rotate OpenCL functions
 *
 * This software is
 * Copyright (c) 2013 Lukas Odzioba <ukasz at openwall dot net>
 * Copyright (c) 2014-2018 magnum
 * Copyright (c) 2021 Solar Designer
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#ifndef OPENCL_ROTATE_H
#define OPENCL_ROTATE_H

#include "opencl_device_info.h"

#define ror32(x, n) rotate(x, 32U-(n))

#if gpu_amd(DEVICE_INFO) && SCALAR && defined(cl_amd_media_ops) && !__MESA__
#pragma OPENCL EXTENSION cl_amd_media_ops : enable
#define opt_ror64(x, n)	((n) < 32 ? \
	 (amd_bitalign((uint)((x) >> 32), (uint)(x), (uint)(n)) | \
	  ((ulong)amd_bitalign((uint)(x), (uint)((x) >> 32), (uint)(n)) << 32)) \
	 : \
	 (amd_bitalign((uint)(x), (uint)((x) >> 32), (uint)(n) - 32) | \
	  ((ulong)amd_bitalign((uint)((x) >> 32), (uint)(x), (uint)(n) - 32) << 32)))
#if amd_gcn(DEVICE_INFO) && DEV_VER_MAJOR < 1912
/* Bug seen with multiples of 8 */
#define ror64(x, n) (((n) != 8) ? opt_ror64(x, n) : rotate(x, (ulong)(64 - (n))))
#else
#define ror64(x, n) opt_ror64(x, n)
#endif
#elif __OS_X__ && gpu_nvidia(DEVICE_INFO)
/* Bug workaround for OSX nvidia 10.2.7 310.41.25f01 */
#define ror64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#else
#define ror64(x, n) rotate(x, (ulong)(64 - (n)))
#endif

#endif
