/*
 * This software is Copyright (c) 2015 JimF, <jfoug at openwall.com>, and
 * it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * Azure ActiveDirectory, V1 cracker patch for JtR, common code.
 * This file takes replicated but common code, shared between the CPU
 * and the GPU formats, and places it into one common location
 */

#if !defined (AzureAD_common_h__)
#define AzureAD_common_h__

#include "arch.h"
#include "formats.h"

#define FORMAT_TAG                      "v1;PPH1_MD4,"
#define TAG_LENGTH                      (sizeof(FORMAT_TAG)-1)

#define HASH_LENGTH                     64
#define SALT_HASH_LEN                   20
#define ROUNDS                          100
#define ROUNDS_LEN                      3
#define EXTRA_LEN                       3
#define CIPHERTEXT_LENGTH               (HASH_LENGTH+TAG_LENGTH+SALT_HASH_LEN+ROUNDS_LEN+EXTRA_LEN)

#define DIGEST_SIZE                     32
#define SALT_SIZE                       sizeof(struct AzureAD_custom_salt)
#define SALT_ALIGN                      sizeof(int)

struct AzureAD_custom_salt {
	int iterations;
	int salt_len;
	unsigned char salt[32];
	char version[8];	// not used 'yet'
};

extern struct AzureAD_custom_salt *AzureAD_cur_salt;

extern struct fmt_tests AzureAD_common_tests[];

int AzureAD_common_valid(char * ciphertext, struct fmt_main * self);
char *AzureAD_common_split(char *ciphertext, int index, struct fmt_main *self);
void *AzureAD_common_get_binary(char * ciphertext);

#endif // #define AzureAD_common_h__
