/*
 * This software is Copyright (c) 2021, magnum
 * and is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modifications, are permitted.
 */

#include "opencl_device_info.h"
#include "opencl_misc.h"
#include "opencl_mask.h"
#define AES_SRC_TYPE __constant
#include "opencl_aes.h"

typedef struct {
	unsigned char ciphertext[16];
} salt_t;

INLINE void prepare(__global const uchar *pwbuf, __global const uint *index, uchar *password)
{
	uint i;
	uint gid = get_global_id(0);
	uint base = index[gid];
	uint len = index[gid + 1] - base;

	pwbuf += base;

	/* Work-around for self-tests not always calling set_key() like IRL */
	if (len > PLAINTEXT_LENGTH)
		len = 0;

	for (i = 0; i < len; i++)
		password[i] = pwbuf[i];
	for (; i < PLAINTEXT_LENGTH; i++)
		password[i] = '0';
}

__kernel
void cryptoSafe(__global const uchar *pwbuf,
                __global const uint *index,
                __constant salt_t *salt,
                __global uint *result,
                volatile __global uint *crack_count_ret,
                __global uint *int_key_loc,
#if USE_CONST_CACHE
                __constant
#else
                __global
#endif
                uint *int_keys)
{
	uchar password[PLAINTEXT_LENGTH];
	uint i;
	uint gid = get_global_id(0);
#if NUM_INT_KEYS > 1 && !IS_STATIC_GPU_MASK
	uint ikl = int_key_loc[gid];
	uint loc0 = ikl & 0xff;
#if MASK_FMT_INT_PLHDR > 1
#if LOC_1 >= 0
	uint loc1 = (ikl & 0xff00) >> 8;
#endif
#endif
#if MASK_FMT_INT_PLHDR > 2
#if LOC_2 >= 0
	uint loc2 = (ikl & 0xff0000) >> 16;
#endif
#endif
#if MASK_FMT_INT_PLHDR > 3
#if LOC_3 >= 0
	uint loc3 = (ikl & 0xff000000) >> 24;
#endif
#endif
#endif

#if !IS_STATIC_GPU_MASK
#define GPU_LOC_0 loc0
#define GPU_LOC_1 loc1
#define GPU_LOC_2 loc2
#define GPU_LOC_3 loc3
#else
#define GPU_LOC_0 LOC_0
#define GPU_LOC_1 LOC_1
#define GPU_LOC_2 LOC_2
#define GPU_LOC_3 LOC_3
#endif

	__local aes_local_t lt;

	/* Prepare password, pad to length 32 with ASCII '0's */
	prepare(pwbuf, index, password);

	/* Apply GPU-side mask */
	for (i = 0; i < NUM_INT_KEYS; i++) {
#if gpu_nvidia(DEVICE_INFO)
		/* Driver bug workaround. Seen with 535.183.01 */
		volatile
#endif
			uint gidx = gid * NUM_INT_KEYS + i;

#if NUM_INT_KEYS > 1
		password[GPU_LOC_0] = int_keys[i] & 0xff;
#if MASK_FMT_INT_PLHDR > 1
#if LOC_1 >= 0
		password[GPU_LOC_1] = (int_keys[i] & 0xff00) >> 8;
#endif
#endif
#if MASK_FMT_INT_PLHDR > 2
#if LOC_2 >= 0
		password[GPU_LOC_2] = (int_keys[i] & 0xff0000) >> 16;
#endif
#endif
#if MASK_FMT_INT_PLHDR > 3
#if LOC_3 >= 0
		password[GPU_LOC_3] = (int_keys[i] & 0xff000000) >> 24;
#endif
#endif
#endif

		AES_KEY aes_decrypt_key; aes_decrypt_key.lt = &lt;
		unsigned char plain[16], iv[16] = { 0 };

		AES_set_decrypt_key(password, 256, &aes_decrypt_key);
		AES_cbc_decrypt(salt->ciphertext, plain, 16, &aes_decrypt_key, iv);

		if ((result[gidx] = !memcmp_pc(plain, "[{\"coinName\":\"", 14)))
			atomic_max(crack_count_ret, gidx + 1);
	}
}
