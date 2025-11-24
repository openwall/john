/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */
 /*
  *  Original taken from https://github.com/guanzhi/GmSSL.
  *  Modified slightly. Removed KDF/HMAC.
  */
#ifndef SM3_H
#define SM3_H
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SM3_BLOCK_SIZE 64
#define SM3_HASH_LENGTH 32

/* algorithm context */
typedef struct sm3_ctx {
	uint32_t hash[8];       /* 256-bit hash */
	unsigned char block[SM3_BLOCK_SIZE];    /* 512-bit message block */
	uint64_t num_blocks;    /* processed number of blocks */
	uint64_t num;           /* index in the buffer of the last byte stored */
} sm3_ctx;

/* hash functions */

void sm3_init(sm3_ctx *ctx);
void sm3_update(sm3_ctx *ctx, const unsigned char *data, size_t size);
void sm3_final(sm3_ctx *ctx, unsigned char *result);

#ifdef __cplusplus
}                               /* extern "C" */
#endif                          /* __cplusplus */
#endif                          /* SM3_H */
