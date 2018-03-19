/*
 * This software is Copyright (c) 2013 Lukas Odzioba <ukasz at openwall dot net>
 * Copyright (c) 2018 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
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

#ifndef OUTLEN
#define OUTLEN salt->outlen
#endif

#define PLAINTEXT_LENGTH        55

typedef struct {
	uint32_t rounds;
	uint8_t salt[179];
	uint32_t length;
	uint32_t outlen;
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
