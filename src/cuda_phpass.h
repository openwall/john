/*
* This software is Copyright (c) 2011,2012 Lukas Odzioba <ukasz at openwall dot net>
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
*/
#ifndef _PHPASS_H
#define _PHPASS_H
#include "common.h"
#define uint8_t 			unsigned char
#define uint32_t 			unsigned int

#define ROTATE_LEFT(x, s) 		((x << s) | (x >> (32 - s)))
#define BLOCKS 				126
#define THREADS 			256
#define KEYS_PER_CRYPT 			BLOCKS*THREADS
#define SALT_SIZE			sizeof(phpass_salt)

#define F(x, y, z)			((z) ^ ((x) & ((y) ^ (z))))
#define G(x, y, z)			((y) ^ ((z) & ((x) ^ (y))))
#define H(x, y, z)			((x) ^ (y) ^ (z))
#define I(x, y, z)			((y) ^ ((x) | ~(z)))

#define address(j,idx) 			(((j)*KEYS_PER_CRYPT)+(idx))

#define FF(a, b, c, d, x, s, ac) \
  {(a) += F ((b), (c), (d)) + (x) + (uint32_t)(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }
#define GG(a, b, c, d, x, s, ac) \
  {(a) += G ((b), (c), (d)) + (x) + (uint32_t)(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }
#define HH(a, b, c, d, x, s, ac) \
  {(a) += H ((b), (c), (d)) + (x) + (uint32_t)(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }
#define II(a, b, c, d, x, s, ac) \
  {(a) += I ((b), (c), (d)) + (x) + (uint32_t)(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }

#define S11				7
#define S12				12
#define S13				17
#define S14				22
#define S21				5
#define S22				9
#define S23				14
#define S24				20
#define S31				4
#define S32				11
#define S33				16
#define S34				23
#define S41				6
#define S42				10
#define S43				15
#define S44				21

#define AC1				0xd76aa477
#define AC2pCd				0xf8fa0bcc
#define AC3pCc				0xbcdb4dd9
#define AC4pCb				0xb18b7a77
#define MASK1				0x77777777

typedef struct {
	uint8_t v[15];
	uint8_t length;
} phpass_password;

typedef struct {
	uint8_t salt[8];
	uint32_t hash[4];
	uint32_t rounds;
} phpass_salt;

typedef struct {
	uint8_t cracked;
} phpass_crack;

#endif
