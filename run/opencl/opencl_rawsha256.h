/*
 * Developed by Claudio André <claudioandre.br at gmail.com> in 2012
 *
 * More information at http://openwall.info/wiki/john/OpenCL-RAWSHA-256
 *
 * Copyright (c) 2012-2015 Claudio André <claudioandre.br at gmail.com>
 * This program comes with ABSOLUTELY NO WARRANTY; express or implied.
 *
 * This is free software, and you are welcome to redistribute it
 * under certain conditions; as expressed here
 * http://www.gnu.org/licenses/gpl-2.0.html
 */

#ifndef _RAWSHA256_H
#define _RAWSHA256_H

#include "opencl_device_info.h"
#include "opencl_sha256.h"

//Constants.
#define RAW_PLAINTEXT_LENGTH    55  /* 55 characters + 0x80 */
#define PLAINTEXT_LENGTH    RAW_PLAINTEXT_LENGTH

#define BUFFER_SIZE             56  /* RAW_PLAINTEXT_LENGTH multiple of 4 */

#ifdef _OPENCL_COMPILER
#define BINARY_SIZE             32
#endif

#define HASH_PARTS      BINARY_SIZE / 4
#define SALT_SIZE               0
#define SALT_ALIGN              1
#define STEP            0
#define SEED            1024

#define KEYS_PER_CORE_CPU       65536
#define KEYS_PER_CORE_GPU       512

#define SPREAD_32(X0, X1, X2, X3, SIZE_MIN_1, X, Y) {                         \
	X = (X0) ^ (X1) ^ (X2);                                               \
	X = X & SIZE_MIN_1;                                                   \
	Y = (X + (X3)) ^ (X0);                                                \
	Y = Y & SIZE_MIN_1;                                                   \
}

//Data types.
typedef union buffer_32_u {
	uint8_t mem_08[4];
	uint16_t mem_16[2];
	uint32_t mem_32[1];
} buffer_32;

typedef struct {
	uint32_t v[8];              //256 bits
} sha256_hash;

typedef struct {
	uint32_t buflen;
	buffer_32 buffer[16];       //512 bits
} sha256_ctx;

#ifndef _OPENCL_COMPILER
static const char *warn[] = {
	"prep: ", ", xfer pass: ", ", idx: ", ", crypt: ", ", result: ",
	", mask xfer: ", " + "
};
#endif

#endif                          /* _RAWSHA256_H */
