/*
 * rawsha1 cracker patch for JtR, common code. 2015 by JimF
 * This file takes replicated but common code, shared between the CPU
 * and the GPU formats, and places it into one common location
 */

#if !defined (rawsha1_common_h__)
#define rawsha1_common_h__

#include "arch.h"
#include "formats.h"

#define FORMAT_TAG_OLD			"$dynamic_26$"
#define TAG_LENGTH_OLD			12
#define FORMAT_TAG				"{SHA}"
#define TAG_LENGTH				5

#define HASH_LENGTH_OLD			40
#define HASH_LENGTH				28
#define CIPHERTEXT_LENGTH		(HASH_LENGTH + TAG_LENGTH)

#define DIGEST_SIZE				20
#define SALT_SIZE				0
#define SALT_ALIGN				1

extern struct fmt_tests rawsha1_common_tests[];

int rawsha1_common_valid(char * ciphertext, struct fmt_main * self);
char *rawsha1_common_split(char *ciphertext, int index, struct fmt_main *self);
char *rawsha1_common_prepare(char *split_fields[10], struct fmt_main *self);
void *rawsha1_common_get_rev_binary(char *ciphertext);
void *rawsha1_common_get_binary(char *ciphertext);
void *rawsha1_common_get_binary(char * ciphertext);

#endif // #define rawsha1_common_h__
