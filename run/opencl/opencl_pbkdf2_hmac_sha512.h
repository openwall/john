/*
 * This software is Copyright (c) 2012-2020 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */
#ifndef _OPENCL_PBKDF2_HMAC_SHA512_H
#define _OPENCL_PBKDF2_HMAC_SHA512_H

#define PBKDF2_64_MAX_SALT_SIZE 107 /* 1 limb w/ 4 byte loop counter */

typedef struct {
	uint64_t v[(PLAINTEXT_LENGTH + 7) / 8];
	uint64_t length;
} pass_t;

typedef struct {
	uint64_t hash[8];
} crack_t;

typedef struct {
	uint64_t salt[(PBKDF2_64_MAX_SALT_SIZE + 1 + 4 + 7) / 8];
	uint32_t length;
	uint32_t rounds;
} salt_t;

typedef struct {
	uint64_t ipad[8];
	uint64_t opad[8];
	uint64_t hash[8];
	uint64_t W[8];
	uint32_t rounds;
} state_t;

#endif
