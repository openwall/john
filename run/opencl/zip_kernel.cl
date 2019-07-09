/*
 * This software is Copyright (c) 2018 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include "pbkdf2_hmac_sha1_unsplit_kernel.cl"
#include "opencl_sha1_ctx.h"
#define HMAC_KEY_TYPE __global
#define HMAC_MSG_TYPE __global const
#define HMAC_OUT_TYPE __global
#include "opencl_hmac_sha1.h"

#define WINZIP_BINARY_SIZE 10

typedef struct {
	uint32_t iterations;
	uint32_t key_len;
	uint32_t length;
	uint8_t  salt[64];
	uint32_t comp_len;
	uchar    passverify[2];
} zip_salt;

__kernel void zip(__global const pbkdf2_password *inbuffer,
                  __global pbkdf2_hash *outbuffer,
                  __constant zip_salt *salt,
                  __global const uchar *saltdata)
{
	uint idx = get_global_id(0);

	pbkdf2(inbuffer[idx].v, inbuffer[idx].length,
	       salt->salt, salt->length, salt->iterations,
	       outbuffer[idx].v, 2, 2 * salt->key_len);

	if (*(__global ushort*)outbuffer[idx].v ==
	    *(__constant ushort*)salt->passverify) {

		pbkdf2(inbuffer[idx].v, inbuffer[idx].length,
		       salt->salt, salt->length, salt->iterations,
		       outbuffer[idx].v, salt->key_len, salt->key_len);
		hmac_sha1(outbuffer[idx].v, salt->key_len,
		          saltdata, salt->comp_len,
		          outbuffer[idx].v, WINZIP_BINARY_SIZE);
	} else
		memset_g(outbuffer[idx].v, 0, WINZIP_BINARY_SIZE);
}
