/*
 * Developed by Claudio André <claudio.andre at correios.net.br> in 2012   
 * Based on source code provided by Lukas Odzioba
 *
 * This software is:
 * Copyright (c) 2011 Lukas Odzioba <lukas dot odzioba at gmail dot com> 
 * Copyright (c) 2012 Claudio André <claudio.andre at correios.net.br>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 * 
 * This program comes with ABSOLUTELY NO WARRANTY; express or implied .
 */

#ifndef _CRYPTSHA512_H 
#define _CRYPTSHA512_H

//Type names definition. 
#define uint8_t  unsigned char
#define uint16_t unsigned short
#define uint32_t unsigned int
#define uint64_t ulong  //Tip: unsigned long long int failed on compile (AMD).

//Functions.
#define MAX(x,y)                ((x) > (y) ? (x) : (y))
#define MIN(x,y)                ((x) < (y) ? (x) : (y))

#define ROUNDS_DEFAULT          5000
#define ROUNDS_MIN              1000
#define ROUNDS_MAX              999999999

#define SALT_SIZE               16
#define PLAINTEXT_LENGTH        16     
#define BINARY_SIZE             (3+16+86)       ///TODO: Magic number?

#define KEYS_PER_CORE_CPU       512
#define KEYS_PER_CORE_GPU       1024
#define MIN_KEYS_PER_CRYPT	128
#define MAX_KEYS_PER_CRYPT	2048*2048*128

#define rol(x,n)                rotate(x,n) 
#define ror(x,n)                rotate(x, (ulong) 64-n)
#define Ch(x,y,z)               ((x & y) ^ ( (~x) & z))
#define Maj(x,y,z)              ((x & y) ^ (x & z) ^ (y & z))
#define Sigma0(x)               ((ror(x,28)) ^ (ror(x,34)) ^ (ror(x,39)))
#define Sigma1(x)               ((ror(x,14)) ^ (ror(x,18)) ^ (ror(x,41)))
#define sigma0(x)               ((ror(x,1))  ^ (ror(x,8))  ^ (x>>7))
#define sigma1(x)               ((ror(x,19)) ^ (ror(x,61)) ^ (x>>6))

# define SWAP64(n) \
  (((n) << 56)					\
   | (((n) & 0xff00) << 40)			\
   | (((n) & 0xff0000) << 24)			\
   | (((n) & 0xff000000) << 8)			\
   | (((n) >> 8) & 0xff000000)			\
   | (((n) >> 24) & 0xff0000)			\
   | (((n) >> 40) & 0xff00)			\
   | ((n) >> 56))

//Data types.
typedef union {
    uint8_t  mem_08[8];
    uint16_t mem_16[4];
    uint32_t mem_32[2];
    uint64_t mem_64[1];
} buffer_64;

typedef struct {
	uint64_t  H[8];          //512 bits
	uint32_t  total;
	uint32_t  buflen;
	buffer_64 buffer[16];	//1024bits
} sha512_ctx;

typedef struct {
	uint32_t rounds;
	uint8_t  saltlen;
	uint8_t  salt[SALT_SIZE];
} crypt_sha512_salt;

typedef struct {
	uint8_t length;
	uint8_t v[PLAINTEXT_LENGTH];
} crypt_sha512_password;

typedef struct {
	uint64_t v[8];		//512 bits
} crypt_sha512_hash;

typedef struct {
        crypt_sha512_password  pass_info;
        crypt_sha512_salt      salt_info;
        sha512_ctx             ctx_info;
        buffer_64              alt_result[8];
        buffer_64              temp_result[8];
        uint8_t                s_sequence[SALT_SIZE];
        uint8_t                p_sequence[PLAINTEXT_LENGTH];
} working_memory;

#endif