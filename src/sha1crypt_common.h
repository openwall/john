/*
 * sha1crypt cracker patch for JtR, common code. 2014 by JimF
 * This file takes replicated but common code, shared between the CPU
 * and the GPU formats, and places it into one common location
 */

#if !defined (sha1crypt_common_h__)
#define sha1crypt_common_h__

#include "arch.h"
#include "formats.h"

#define BENCHMARK_COMMENT           ""
#define BENCHMARK_LENGTH            0x507

#define SHA1_MAGIC "$sha1$"
#define SHA1_MAGIC_LEN (sizeof(SHA1_MAGIC)-1)

// max valid salt len in hash is shorter than this (by length of "$sha1$" and length of base10 string of rounds)
#undef  SALT_LENGTH
#define SALT_LENGTH                 64
#define SALT_BUFFER_LENGTH          115

#undef  CHECKSUM_LENGTH
#define CHECKSUM_LENGTH             28
#define BINARY_SIZE                 20

extern struct fmt_tests sha1crypt_common_tests[];

int sha1crypt_common_valid(char * ciphertext, struct fmt_main * self);
void *sha1crypt_common_get_binary(char * ciphertext);

#endif // #define sha1crypt_common_h__
