/*
 * Developed by Claudio André <claudioandre.br at gmail.com> in 2012
 *
 * More information at http://openwall.info/wiki/john/OpenCL-SHA-256
 *
 * Copyright (c) 2012-2015 Claudio André <claudioandre.br at gmail.com>
 * This program comes with ABSOLUTELY NO WARRANTY; express or implied.
 *
 * This is free software, and you are welcome to redistribute it
 * under certain conditions; as expressed here
 * http://www.gnu.org/licenses/gpl-2.0.html
 */

#ifndef _CRYPTSHA256_H
#define _CRYPTSHA256_H

#include "opencl_device_info.h"
#include "opencl_sha256.h"

#define SALT_LENGTH             16
#define PLAINTEXT_LENGTH        24
#define BUFFER_ARRAY            8
#define SALT_ARRAY              (SALT_LENGTH / 4)
#define PLAINTEXT_ARRAY         (PLAINTEXT_LENGTH / 4)
#define SEED                    1024
#define STEP                    0
#define HASH_LOOPS              (7*3*2)

#define KEYS_PER_CORE_CPU       128
#define KEYS_PER_CORE_GPU       1

//Data types.
typedef union buffer_32_u {
	uint8_t mem_08[4];
	uint16_t mem_16[2];
	uint32_t mem_32[1];
} buffer_32;

typedef struct {
	uint32_t rounds;
	uint32_t length;
	uint32_t final;
	buffer_32 salt[SALT_ARRAY];
} sha256_salt;

#define SALT_SIZE               sizeof(sha256_salt)

typedef struct {
	uint32_t length;
	buffer_32 pass[PLAINTEXT_ARRAY];
} sha256_password;

typedef struct {
	uint32_t v[8];              //256 bits
} sha256_hash;

typedef struct {
	uint32_t H[8];              //256 bits
	uint32_t total;
	uint32_t buflen;
	buffer_32 buffer[16];       //512 bits
#if __CPU__
	uint64_t safety_trail;      //To avoid memory override
#endif
} sha256_ctx;

typedef struct {
	buffer_32 alt_result[8];
	buffer_32 temp_result[SALT_ARRAY];
	buffer_32 p_sequence[PLAINTEXT_ARRAY];
} sha256_buffers;

#ifndef _OPENCL_COMPILER
static const char *warn[] = {
	"xfer: ", ", crypt: ", ", xfer back: ",
	", prep: ", ", pp: ", ", final: ", ", var: ", "/"
};
#endif

#endif                          /* _CRYPTSHA256_H */
