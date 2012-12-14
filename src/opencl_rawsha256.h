/*
 * Developed by Claudio André <claudio.andre at correios.net.br> in 2012
 *
 * More information at http://openwall.info/wiki/john/OpenCL-RAWSHA-256
 *
 * Copyright (c) 2012 Claudio André <claudio.andre at correios.net.br>
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
#define PLAINTEXT_LENGTH        32      /* 31 characters + 0x80 */
#define PLAINTEXT_TEXT          "32"
#define CIPHERTEXT_LENGTH       64
#define PLAINTEXT_ARRAY         (PLAINTEXT_LENGTH / 4)
#define BINARY_SIZE             4
#define FULL_BINARY_SIZE        32
#define SALT_SIZE               0
#define STEP                    65536

#define KEYS_PER_CORE_CPU       65536
#define KEYS_PER_CORE_GPU       512

//Data types.
typedef union {
    uint8_t                     mem_08[4];
    uint16_t                    mem_16[2];
    uint32_t                    mem_32[1];
} buffer_32;

typedef struct {
    uint32_t                    length;
    buffer_32                   pass[PLAINTEXT_ARRAY];
} sha256_password;

typedef struct {
    uint32_t                    v[8];           //256 bits
} sha256_hash;

typedef struct {
    uint32_t                    H[8];           //256 bits
    uint32_t                    buflen;
    buffer_32                   buffer[16];     //512 bits
} sha256_ctx;

#ifndef _OPENCL_COMPILER
    static const char * warn[] = {
        "pass xfer: "  ,  ", crypt: "    ,  ", result xfer: "
};
#endif

#endif  /* _RAWSHA256_H */