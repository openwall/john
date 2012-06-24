/*
* This software is Copyright (c) 2011,2012 Lukas Odzioba <ukasz at openwall dot net>
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
*/
#ifndef _CUDA_CRYPTMD5_H
#define _CUDA_CRYPTMD5_H
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include "common.h"

#define uint32_t unsigned int
#define uint8_t unsigned char

#define MIN(a,b) ((a)<(b)?(a):(b))
#define MAX(a,b) ((a)>(b)?(a):(b))

#define BLOCKS			28*3
#define THREADS 		256
#define KEYS_PER_CRYPT		BLOCKS*THREADS
#define PLAINTEXT_LENGTH	15

typedef struct {
	uint32_t hash[4];	//hash that we are looking for
	uint8_t length;   //salt length
	char salt[8];
	char prefix;		// 'a' when $apr1$ or '1' when $1$
} crypt_md5_salt;

typedef struct {
	uint8_t length;
	uint8_t v[PLAINTEXT_LENGTH];
} crypt_md5_password;

typedef struct {
	  char cracked;
} crypt_md5_crack;

typedef struct __attribute__((__aligned__(4))){
	uint8_t buffer[64];
} md5_ctx ;

static const char md5_salt_prefix[] = "$1$";
static const char apr1_salt_prefix[] = "$apr1$";

#define ROTATE_LEFT(x, s) ((x << s) | (x >> (32 - s)))

#define F(x, y, z) ((z) ^ ((x) & ((y) ^ (z))))
#define G(x, y, z) ((y) ^ ((z) & ((x) ^ (y))))

#define H(x, y, z) (x^y^z)
#define I(x, y, z) (y^(x|~z))

#define FF(v, w, x, y, z, s, ac) { \
 v = ROTATE_LEFT(v + z + ac + F(w, x, y), s) + w; \
 }
#define GG(v, w, x, y, z, s, ac) { \
 v = ROTATE_LEFT(v + z + ac + G(w, x, y), s) + w; \
 }
#define HH(v, w, x, y, z, s, ac) { \
 v = ROTATE_LEFT(v + z + ac + H(w, x, y), s) + w; \
 }
#define II(v, w, x, y, z, s, ac) { \
 v = ROTATE_LEFT(v + z + ac + I(w, x, y), s) + w; \
 }
#define FF2(v, w, x, y, s, ac) { \
 v = ROTATE_LEFT(v + ac + F(w, x, y), s) + w; \
 }
#define GG2(v, w, x, y, s, ac) { \
 v = ROTATE_LEFT(v + ac + G(w, x, y), s) + w; \
 }
#define HH2(v, w, x, y, s, ac) { \
 v = ROTATE_LEFT(v + ac + H(w, x, y), s) + w; \
 }
#define II2(v, w, x, y, s, ac) { \
 v = ROTATE_LEFT(v + ac + I(w, x, y), s) + w; \
 }

#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

#define AC1				0xd76aa477
#define AC2pCd				0xf8fa0bcc
#define AC3pCc				0xbcdb4dd9
#define AC4pCb				0xb18b7a77
#define MASK1				0x77777777


#endif
