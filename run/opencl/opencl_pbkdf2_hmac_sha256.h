/*
 * This software is Copyright (c) 2013 Lukas Odzioba <ukasz at openwall dot net>
 * Copyright (c) 2018 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * salt->skip_bytes means "skip leading output bytes" and can be given in
 * multiples of underlying hash size (in this case 32). So to calculate only
 * byte 33-64 (second chunk) you can say "salt->outlen=32 salt->skip_bytes=32"
 * for a 2x boost. The 1st byte of output array will then be 1st byte of second
 * chunk so its actual size can be 32 as opposed to 64.
 */

#ifndef _OPENCL_PBKDF2_HMAC_SHA256_H
#define _OPENCL_PBKDF2_HMAC_SHA256_H

#ifndef MAX_OUTLEN
#if OUTLEN
#define MAX_OUTLEN OUTLEN
#else
#define MAX_OUTLEN 32
#endif
#endif

#if !OUTLEN && _OPENCL_COMPILER
#define OUTLEN salt->outlen
#endif

#ifndef PLAINTEXT_LENGTH
#define PLAINTEXT_LENGTH        55
#endif

typedef struct {
	uint32_t rounds;
	uint8_t  salt[179];
	uint32_t length;
	uint32_t outlen;
	uint32_t skip_bytes;
} salt_t;

typedef struct {
	uint32_t ipad[8];
	uint32_t opad[8];
	uint32_t hash[8];
	uint32_t W[8];
	uint32_t rounds;
	uint32_t pass;
} state_t;

typedef struct {
	uint8_t length;
	uint8_t v[PLAINTEXT_LENGTH];
} pass_t;

typedef struct {
	uint32_t hash[((MAX_OUTLEN + 31) / 32) * 32 / sizeof(uint32_t)];
} crack_t;


#endif
