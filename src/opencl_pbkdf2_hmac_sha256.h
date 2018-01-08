/*
 * This software is Copyright (c) 2013 Lukas Odzioba <ukasz at openwall dot net>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#ifndef _OPENCL_PBKDF2_HMAC_SHA256_H
#define _OPENCL_PBKDF2_HMAC_SHA256_H

#define PLAINTEXT_LENGTH        55

typedef struct {
	uint32_t rounds;
	uint8_t salt[179];
	uint32_t length;
} salt_t;

typedef struct {
	uint32_t ipad[8];
	uint32_t opad[8];
	uint32_t hash[8];
	uint32_t W[8];
	uint32_t rounds;
} state_t;

typedef struct {
	uint8_t length;
	uint8_t v[PLAINTEXT_LENGTH];
} pass_t;

typedef struct {
	uint32_t hash[8];
} crack_t;


#endif
