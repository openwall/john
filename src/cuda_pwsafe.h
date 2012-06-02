/*
* This software is Copyright (c) 2012 Lukas Odzioba <ukasz@openwall.net> 
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
*/
#ifndef _CUDA_PWSAFE_H
#define _CUDA_PWSAFE_H
#include "common.h"
#define uint8_t                         unsigned char
#define uint32_t                        unsigned int

#define THREADS                         512
#define BLOCKS                          112//14 // 112 is good for gtx460
#define KEYS_PER_CRYPT                  THREADS*BLOCKS

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))
#define rol(x,n) ((x << n) | (x >> (32-n)))
#define ror(x,n) ((x >> n) | (x << (32-n)))
#define Ch(x, y, z) (z ^ (x & (y ^ z)))
#define Maj(x, y, z) ((y & z) | (x & (y | z)))
#define Sigma0(x) ((ror(x,2))  ^ (ror(x,13)) ^ (ror(x,22)))
#define Sigma1(x) ((ror(x,6))  ^ (ror(x,11)) ^ (ror(x,25)))
#define sigma0(x) ((ror(x,7))  ^ (ror(x,18)) ^ (x>>3))
#define sigma1(x) ((ror(x,17)) ^ (ror(x,19)) ^ (x>>10))
# define SWAP32(n) \
    (((n) << 24) | (((n) & 0xff00) << 8) | (((n) >> 8) & 0xff00) | ((n) >> 24))

typedef struct {
        uint8_t v[15];
        uint8_t length;
} pwsafe_pass;

typedef struct {
        uint32_t cracked;       ///cracked or not
} pwsafe_hash;

typedef struct {
        int version;
        uint32_t iterations;
        uint8_t hash[32];
        uint8_t length;
        uint8_t salt[32];
} pwsafe_salt;

#endif
