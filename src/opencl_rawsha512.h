/*
 * Developed by Claudio André <claudioandre.br at gmail.com> in 2012
 *
 * More information at http://openwall.info/wiki/john/OpenCL-RAWSHA-512
 * More information at http://openwall.info/wiki/john/OpenCL-XSHA-512
 *
 * Copyright (c) 2012-2016 Claudio André <claudioandre.br at gmail.com>
 * This program comes with ABSOLUTELY NO WARRANTY; express or implied.
 *
 * This is free software, and you are welcome to redistribute it
 * under certain conditions; as expressed here
 * http://www.gnu.org/licenses/gpl-2.0.html
 */

#ifndef _RAWSHA512_NG_H
#define _RAWSHA512_NG_H

#include "opencl_device_info.h"
#include "opencl_sha512.h"

//Constants.
#define PLAINTEXT_LENGTH        55  /* 55 characters + 0x80 */
#define BUFFER_SIZE             56  /* PLAINTEXT_LENGTH multiple of 4 */

#ifdef _OPENCL_COMPILER
#define BINARY_SIZE             64
#endif

#define HASH_PARTS              BINARY_SIZE / 8
#define SALT_SIZE_RAW           0
#define SALT_SIZE_X             4
#define SALT_ALIGN              4
#define STEP                    0
#define SEED                    128

#define KEYS_PER_CORE_CPU       65536
#define KEYS_PER_CORE_GPU       512

#define SPREAD_64(X0, X1, SIZE_MIN_1, X, Y) {                                 \
	X = ((uint)((X0) >> 32)) ^ ((uint)(X0)) ^ ((uint)((X1) >> 32));       \
	X = X & SIZE_MIN_1;                                                   \
	Y = (X + ((uint)(X1))) ^ ((uint)((X0) >> 32));                        \
	Y = Y & SIZE_MIN_1;                                                   \
}

//Data types.
typedef union buffer_64_u {
	uint8_t mem_08[8];
	uint16_t mem_16[4];
	uint32_t mem_32[2];
	uint64_t mem_64[1];
} buffer_64;

typedef struct {
	uint32_t salt;
} sha512_salt;

typedef struct {
	uint64_t v[8];              //512 bits
} sha512_hash;

typedef struct {
	uint32_t buflen;
	buffer_64 buffer[16];       //1024bits
} sha512_ctx;

#ifndef _OPENCL_COMPILER
static const char *warn[] = {
	"prep: ", ", xfer pass: ", ", idx: ", ", crypt: ", ", result: ",
	", mask xfer: ", " + "
};
#endif

#endif                          /* _RAWSHA512_NG_H */
