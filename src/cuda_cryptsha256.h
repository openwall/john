/*
* This software is Copyright (c) 2011 Lukas Odzioba <lukas dot odzioba at gmail dot com>
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
*/
#ifndef _CRYPTSHA256_H
#define _CRYPTSHA256_H

#include <assert.h>
#include "common.h"
#include "stdint.h"
#include <stdbool.h>

#define BLOCKS 14
#define THREADS 192//set 320 for fermi

#define KEYS_PER_CRYPT BLOCKS*THREADS

#define rol(x,n) ((x << n) | (x >> (32-n)))
#define ror(x,n) ((x >> n) | (x << (32-n)))
#define Ch(x,y,z) ((x & y) ^ ( (~x) & z))
#define Maj(x,y,z) ((x & y) ^ (x & z) ^ (y & z))
#define Sigma0(x) ((ror(x,2))  ^ (ror(x,13)) ^ (ror(x,22)))
#define Sigma1(x) ((ror(x,6))  ^ (ror(x,11)) ^ (ror(x,25)))
#define sigma0(x) ((ror(x,7))  ^ (ror(x,18)) ^(x>>3))
#define sigma1(x) ((ror(x,17)) ^ (ror(x,19)) ^(x>>10))

#define SHOW(x) printf("%s = %08x\n",#x,(x))
# define SWAP(n) \
    (((n) << 24) | (((n) & 0xff00) << 8) | (((n) >> 8) & 0xff00) | ((n) >> 24))

#define PLAINTEXT_LENGTH 23
#define SALT_LEN_MAX 16

typedef struct {
	uint32_t H[8];
	uint32_t total;
	uint32_t buflen;
	uint8_t buffer[64];
} sha256_ctx;

typedef struct {
	unsigned char saltlen;
	uint32_t rounds;
	char salt[SALT_LEN_MAX + 1];
} crypt_sha256_salt;

typedef struct {
	unsigned char length;
	unsigned char v[PLAINTEXT_LENGTH];
} crypt_sha256_password;


#define hash_addr(j,idx) (((j)*(KEYS_PER_CRYPT))+(idx))
typedef struct {
	uint32_t v[8];		//256 bits
} crypt_sha256_hash;

#endif
