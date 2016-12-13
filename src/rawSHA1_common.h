/*
 * rawsha1 cracker patch for JtR, common code. 2015 by JimF
 * This file takes replicated but common code, shared between the CPU
 * and the GPU formats, and places it into one common location
 */

#if !defined (rawsha1_common_h__)
#define rawsha1_common_h__

#include "arch.h"
#include "formats.h"

#define FORMAT_TAG				"$dynamic_26$"
#define TAG_LENGTH				(sizeof(FORMAT_TAG)-1)
#define FORMAT_TAG_OLD			"{SHA}"
#define TAG_LENGTH_OLD			(sizeof(FORMAT_TAG_OLD)-1)

#define HASH_LENGTH				40
#define HASH_LENGTH_OLD			28
#define CIPHERTEXT_LENGTH		(HASH_LENGTH + TAG_LENGTH)

#define DIGEST_SIZE				20
#define AX_DIGEST_SIZE			16
#define SALT_SIZE				0
#define SALT_ALIGN				1

extern struct fmt_tests rawsha1_common_tests[];
extern struct fmt_tests axcrypt_common_tests[];

int rawsha1_common_valid(char *ciphertext, struct fmt_main *self);
char *rawsha1_common_split(char *ciphertext, int index, struct fmt_main *self);
char *rawsha1_common_prepare(char *split_fields[10], struct fmt_main *self);
void *rawsha1_common_get_rev_binary(char *ciphertext);
void *rawsha1_common_get_binary(char *ciphertext);
int rawsha1_axcrypt_valid(char *ciphertext, struct fmt_main *self);
char *rawsha1_axcrypt_split(char *ciphertext, int index, struct fmt_main *self);

#endif // #define rawsha1_common_h__
