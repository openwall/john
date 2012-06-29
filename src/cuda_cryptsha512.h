/*
* This software is Copyright (c) 2011 Lukas Odzioba <lukas dot odzioba at gmail dot com>
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
*/
#ifndef _CRYPTSHA512_H
#define _CRYPTSHA512_H
#include <assert.h>
#include "common.h"
#include <stdint.h>
#include <stdbool.h>

#define uint8_t  unsigned char
#define uint32_t unsigned int
#define uint64_t unsigned long long int

#define BLOCKS 14
#define THREADS 128//set 256 on fermi

#define KEYS_PER_CRYPT BLOCKS*THREADS

#define MAX(x,y) ((x) > (y) ? (x) : (y))
#define MIN(x,y) ((x) < (y) ? (x) : (y))
#define SALT_LEN_MAX 16
#define ROUNDS_DEFAULT 5000
#define ROUNDS_MIN 1000
#define ROUNDS_MAX 999999999

static const char sha512_salt_prefix[] = "$6$";
static const char sha256_rounds_prefix[] = "rounds=";


#define rol(x,n) ((x << n) | (x >> (64-n)))
#define ror(x,n) ((x >> n) | (x << (64-n)))
#define Ch(x,y,z) ((x & y) ^ ( (~x) & z))
#define Maj(x,y,z) ((x & y) ^ (x & z) ^ (y & z))
#define Sigma0(x) ((ror(x,28))  ^ (ror(x,34)) ^ (ror(x,39)))
#define Sigma1(x) ((ror(x,14))  ^ (ror(x,18)) ^ (ror(x,41)))
#define sigma0(x) ((ror(x,1))  ^ (ror(x,8)) ^(x>>7))
#define sigma1(x) ((ror(x,19)) ^ (ror(x,61)) ^(x>>6))

# define SWAP32(n) \
    (((n) << 24) | (((n) & 0xff00) << 8) | (((n) >> 8) & 0xff00) | ((n) >> 24))

# define SWAP64(n) \
  (((n) << 56)					\
   | (((n) & 0xff00) << 40)			\
   | (((n) & 0xff0000) << 24)			\
   | (((n) & 0xff000000) << 8)			\
   | (((n) >> 8) & 0xff000000)			\
   | (((n) >> 24) & 0xff0000)			\
   | (((n) >> 40) & 0xff00)			\
   | ((n) >> 56))

#define hash_addr(j,idx) (((j)*(KEYS_PER_CRYPT))+(idx))


typedef struct {
	uint64_t H[8];
	uint32_t total;
	uint32_t buflen;
	uint8_t buffer[128];	//1024bits
} sha512_ctx;

typedef struct {
	uint32_t rounds;
	uint8_t saltlen;
	char salt[63];
} crypt_sha512_salt;

typedef struct {
	uint8_t length;
	uint8_t v[16];
} crypt_sha512_password;

typedef struct {
	uint64_t v[8];		//512 bits
} crypt_sha512_hash;

#endif
