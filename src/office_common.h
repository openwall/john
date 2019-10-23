/*
 * Office 2007-2013 cracker patch for JtR, common code. This software is
 * Copyright (c) 2014 by JimF
 * Copyright (c) 2012-2019 magnum
 * and is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * This file takes replicated but common code, shared between the CPU
 * office format, and the GPU office formats, and places it into one
 * common location.
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

void *ms_office_common_get_salt(char *ciphertext);
void *ms_office_common_binary(char *ciphertext);
int ms_office_common_valid(char *ciphertext, struct fmt_main *self);

/* other 'common' functions for MSOffice */
unsigned int ms_office_common_iteration_count(void *salt);
unsigned int ms_office_common_version(void *salt);
