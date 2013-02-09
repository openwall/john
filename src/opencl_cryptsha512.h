/*
 * Developed by Claudio André <claudio.andre at correios.net.br> in 2012
 *
 * More information at http://openwall.info/wiki/john/OpenCL-SHA-512
 *
 * Copyright (c) 2012 Claudio André <claudio.andre at correios.net.br>
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

//Constants.
#define ROUNDS_PREFIX           "rounds="
#define ROUNDS_DEFAULT          5000
#define ROUNDS_MIN              1	/* Drepper has it as 1000 */
#define ROUNDS_MAX              999999999

#define SALT_LENGTH             16
#define PLAINTEXT_LENGTH        24
#define CIPHERTEXT_LENGTH	86
#define BUFFER_ARRAY            8
#define SALT_ARRAY              (SALT_LENGTH / 8)
#define PLAINTEXT_ARRAY         (PLAINTEXT_LENGTH / 8)
#define BINARY_SIZE             64
#define STEP                    512

#define HASH_LOOPS              (7*3*2)
#define KEYS_PER_CORE_CPU       128
#define KEYS_PER_CORE_GPU       512

//Data types.
typedef union {
    uint8_t                     mem_08[8];
    uint16_t                    mem_16[4];
    uint32_t                    mem_32[2];
    uint64_t                    mem_64[1];
} buffer_64;

typedef struct {
    uint32_t                    rounds;
    uint32_t                    length;
    uint32_t                    final;
    buffer_64                   salt[SALT_ARRAY];
} sha512_salt;
#define SALT_SIZE               sizeof(sha512_salt)

typedef struct {
    uint32_t                    length;
    buffer_64                   pass[PLAINTEXT_ARRAY];
} sha512_password;

typedef struct {
    uint64_t                    v[8];           //512 bits
} sha512_hash;

typedef struct {
    uint64_t                    H[8];           //512 bits
    uint32_t                    total;
    uint32_t                    buflen;
    buffer_64                   buffer[16];     //1024bits
#if cpu(DEVICE_INFO)
    uint64_t                    safety_trail;   //To avoid memory override
#endif
} sha512_ctx;

typedef struct {
    buffer_64                   alt_result[8];
    buffer_64                   temp_result[SALT_ARRAY];
    buffer_64                   p_sequence[PLAINTEXT_ARRAY];
} sha512_buffers;

#ifndef _OPENCL_COMPILER
    static const char * warn[] = {
        "salt xfer: "  ,  ", pass xfer: "  ,  ", crypt: "    ,  ", result xfer: ",
        ", crypt: "    ,  "/"              ,  ", prepare: "  ,  ", final: "
};
#endif

#endif  /* _CRYPTSHA512_H */
