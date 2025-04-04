/*
 * Office 2007-2013 cracker patch for JtR, common code. This software is
 * Copyright (c) 2014 by JimF
 * Copyright (c) 2012-2025 magnum
 * and is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include "formats.h"

#define FORMAT_TAG_OFFICE           "$office$*"
#define FORMAT_TAG_OFFICE_LEN       (sizeof(FORMAT_TAG_OFFICE)-1)

#define BINARY_SIZE              sizeof(fmt_data)
#define BINARY_ALIGN             sizeof(size_t)
#define SALT_SIZE                sizeof(*cur_salt)
#define SALT_ALIGN               sizeof(int)

typedef struct ms_office_custom_salt_t {
	uint8_t salt[16];
	unsigned int version;
	int verifierHashSize;
	int keySize;
	int saltSize;
	unsigned int spinCount;
} ms_office_custom_salt;

typedef struct ms_office_binary_blob_t {
	uint8_t encryptedVerifier[16];
	uint8_t encryptedVerifierHash[32];
} ms_office_binary_blob;

extern void *ms_office_common_get_salt(char *ciphertext);
extern void *ms_office_common_binary(char *ciphertext);
extern int ms_office_common_valid(char *ciphertext, struct fmt_main *self);

/* other 'common' functions for MSOffice */
extern unsigned int ms_office_common_iteration_count(void *salt);
extern unsigned int ms_office_common_version(void *salt);
extern int ms_office_binary_hash_0(void *binary);
extern int ms_office_binary_hash_1(void *binary);
extern int ms_office_binary_hash_2(void *binary);
extern int ms_office_binary_hash_3(void *binary);
extern int ms_office_binary_hash_4(void *binary);
extern int ms_office_binary_hash_5(void *binary);
extern int ms_office_binary_hash_6(void *binary);
