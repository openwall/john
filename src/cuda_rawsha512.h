/*
 * This software is Copyright (c) 2012 Myrice <qqlddg at gmail dot com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
*/

#ifndef _CUDA_SHA512_H
#define _CUDA_SHA512_H

#define uint8_t  unsigned char
#define uint32_t unsigned int
#define uint64_t unsigned long long int

#define BLOCKS 4096
#define THREADS 128
#define KEYS_PER_CRYPT (BLOCKS*THREADS)
#define ITERATIONS 1
#define MIN_KEYS_PER_CRYPT	(KEYS_PER_CRYPT)
#define MAX_KEYS_PER_CRYPT	(ITERATIONS*KEYS_PER_CRYPT)

#define SALT_SIZE		0

#define BINARY_SIZE 8
#define FULL_BINARY_SIZE 64

#define PLAINTEXT_LENGTH		20
#define CIPHERTEXT_LENGTH		128

extern uint8_t sha512_key_changed;

# define SWAP64(n) \
  (((n) << 56)					\
   | (((n) & 0xff00) << 40)			\
   | (((n) & 0xff0000) << 24)			\
   | (((n) & 0xff000000) << 8)			\
   | (((n) >> 8) & 0xff000000)			\
   | (((n) >> 24) & 0xff0000)			\
   | (((n) >> 40) & 0xff00)			\
   | ((n) >> 56))


#define rol(x,n) ((x << n) | (x >> (64-n)))
#define ror(x,n) ((x >> n) | (x << (64-n)))
#define Ch(x,y,z) ((x & y) ^ ( (~x) & z))
#define Maj(x,y,z) ((x & y) ^ (x & z) ^ (y & z))
#define Sigma0(x) ((ror(x,28))  ^ (ror(x,34)) ^ (ror(x,39)))
#define Sigma1(x) ((ror(x,14))  ^ (ror(x,18)) ^ (ror(x,41)))
#define sigma0(x) ((ror(x,1))  ^ (ror(x,8)) ^(x>>7))
#define sigma1(x) ((ror(x,19)) ^ (ror(x,61)) ^(x>>6))

#define hash_addr(j,idx) (((j)*(MAX_KEYS_PER_CRYPT))+(idx))


typedef struct { // notice memory align problem
	uint8_t buffer[128];	//1024bits
	uint32_t buflen;
	uint64_t H[8];
} sha512_ctx;

typedef struct {
    uint8_t length;
    char v[PLAINTEXT_LENGTH+1];
} sha512_key;

typedef uint64_t sha512_hash[BINARY_SIZE / 8]; // up to 512 bits


#endif

