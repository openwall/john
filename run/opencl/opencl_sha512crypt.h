/*
 * Developed by Claudio André <claudioandre.br at gmail.com> in 2012
 *
 * More information at http://openwall.info/wiki/john/OpenCL-SHA-512
 *
 * Copyright (c) 2012-2015 Claudio André <claudioandre.br at gmail.com>
 * This program comes with ABSOLUTELY NO WARRANTY; express or implied.
 *
 * This is free software, and you are welcome to redistribute it
 * under certain conditions; as expressed here
 * http://www.gnu.org/licenses/gpl-2.0.html
 */

#ifndef _CRYPTSHA512_H
#define _CRYPTSHA512_H

#include "opencl_device_info.h"
#include "opencl_sha512.h"

/* ***
 *   IMPORTANT => due to optimizations
 *       len(salt) + len(key) MUST BE less than 40 bytes.
 *
 *       - if the user has a 16 bytes salt, he will never be able to crack a
 *       password of 24 bytes. If the salt has less than 16 bytes
 *       JtR will be able to crack a 24 bytes password without problems.
 *
 *   So, for safety, the format claims its limit is, in fact,
 *       - PLAINTEXT_LENGTH 23
 *** */

//Constants.
#define SALT_LENGTH             16
#define SALT_ALIGN              8
#define PLAINTEXT_LENGTH        23
#define CIPHERTEXT_LENGTH   86
#define BUFFER_ARRAY            8
#define SALT_ARRAY              (SALT_LENGTH / 8)
#define PLAINTEXT_ARRAY         ((PLAINTEXT_LENGTH + 7) / 8)
#define BINARY_SIZE             64
#define BINARY_ALIGN            sizeof(uint64_t)
#define SEED                    1024
#define STEP                    0

#define LOOP_SIZE               (7*3*2)
#define HASH_LOOPS              (LOOP_SIZE * 2)

#define KEYS_PER_CORE_CPU       128
#define KEYS_PER_CORE_GPU       1

//Data types.
typedef union buffer_64_u {
	uint8_t mem_08[8];
	uint16_t mem_16[4];
	uint32_t mem_32[2];
	uint64_t mem_64[1];
} buffer_64;

typedef struct {
	uint32_t rounds;
	uint32_t length;
	uint32_t final;
	buffer_64 salt[SALT_ARRAY];
} sha512_salt;

#define SALT_SIZE               sizeof(sha512_salt)

typedef struct {
	uint32_t length;
	buffer_64 pass[PLAINTEXT_ARRAY];
} sha512_password;

typedef struct {
	uint64_t v[8];              //512 bits
} sha512_hash;

typedef struct {
	uint64_t H[8];              //512 bits
	uint32_t total;
	uint32_t buflen;
	buffer_64 buffer[16];       //1024bits
#if __CPU__
	uint64_t safety_trail;      //To avoid memory override
#endif
} sha512_ctx;

typedef struct {
	buffer_64 alt_result[8];
	buffer_64 temp_result[SALT_ARRAY];
	buffer_64 p_sequence[PLAINTEXT_ARRAY];
} sha512_buffers;

#ifndef _OPENCL_COMPILER
static const char *warn[] = {
	"xfer: ", ", crypt: ", ", xfer back: ",
	", prep: ", ", pp: ", ", final: ", ", var: ", "/"
};
#endif

#endif                          /* _CRYPTSHA512_H */
