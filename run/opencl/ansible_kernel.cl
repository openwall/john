/*
 * This software is Copyright 2018 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include "pbkdf2_hmac_sha256_kernel.cl"
#define HMAC_KEY_TYPE __global const
#define HMAC_MSG_TYPE MAYBE_CONSTANT
#define HMAC_OUT_TYPE __global
#if __OS_X__ && gpu_amd(DEVICE_INFO)
/* This is a workaround for driver/runtime bugs */
#define MAYBE_VOLATILE volatile
#else
#define MAYBE_VOLATILE
#endif
#include "opencl_hmac_sha256.h"

/*
 * Note that this struct includes the one in opencl_pbkdf2_hmac_sha256.h
 * and custom stuff appended.
 */
typedef struct {
	salt_t   pbkdf2;
	uint32_t bloblen;
	uint8_t  blob[BLOBLEN];
} ansible_salt_t;

__kernel void ansible_final(__global crack_t *out,
                            MAYBE_CONSTANT ansible_salt_t *salt,
                            __global state_t *state)
{
	uint ix = get_global_id(0);

	pbkdf2_sha256_final(out, &salt->pbkdf2, state);

	hmac_sha256(out[ix].hash, 32, salt->blob, salt->bloblen, out[ix].hash, 16);
}
