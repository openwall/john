/*
 * Optimized rotate OpenCL functions
 *
 * This software is
 * Copyright (c) 2013 Lukas Odzioba <ukasz at openwall dot net>
 * Copyright (c) 2014-2024 magnum
 * Copyright (c) 2021 Solar Designer
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#ifndef OPENCL_ROTATE_H
#define OPENCL_ROTATE_H

#include "opencl_device_info.h"

/*
 * This was reported to give some speedup, but is mostly untested in this source
 * tree (I briefly tested it with a rotate-heavy version of AES and saw no change
 * in speed).  Besides, it would be outrageously stupid by nvidia not use this
 * instruction anyway, when applicable.  Perhaps historically they did not.
 * Leaving it here as a curious reference. - magnum
 */
#if 0 && gpu_nvidia(DEVICE_INFO) && SM_MAJOR >= 2
INLINE uint byte_perm(uint a, uint b, uint imm)
{
    uint r;
    asm("prmt.b32 %0, %1, %2, %3;"
	    : "=r" (r)
	    : "r" (a), "r" (b), "i" (imm));
    return r;
}

INLINE uint ror32(uint x, uint n)
{
	switch (n) {
	case 8:
		return byte_perm(x, 0, 0x00000321U);
	case 16:
		return byte_perm(x, 0, 0x00001032U);
	case 24:
		return byte_perm(x, 0, 0x00002103U);
	default:
		return rotate(x, 32 - n);
	}
}
#else
#define ror32(x, n) rotate(x, 32U-(n))
#endif

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
