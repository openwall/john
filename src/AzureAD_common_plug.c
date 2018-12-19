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

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "base64_convert.h"
#include "johnswap.h"
#include "AzureAD_common.h"

struct AzureAD_custom_salt *AzureAD_cur_salt;

struct fmt_tests AzureAD_common_tests[] = {
	{"v1;PPH1_MD4,724b754c4b6d30526f36,100,367ff0ac2a1cb334bb26609c8bfc8ae5f619d1eaf07568df040f407504a20241;", "openwall"},
	{"v1;PPH1_MD4,465564476f786e705069,100,612a80cb011bee1f929c7a9e2bd16d98a79f2deb9f44919100f7c0ec74508560;", "JohnTheRipper"},
	{"v1;PPH1_MD4,31414275383876386e32,100,102ce242cde4339e934d7c6b539d49ae340b02dd380815666b98bd036cd4dc4f;", "password"},
	{"v1;PPH1_MD4,31744d38756c67387a37,100,1c78cb339ff883040968f71a765662246d54852eebc878bbda75f540bcdfada4;", "password"},
	{NULL}
};

int AzureAD_common_valid(char *ciphertext, struct fmt_main *self) {
	/* this format 'does' appear to be written to extend. At this time, we
	 * have coded parts read for this, however, right now, we have 2 hard
	 * coded things in valid that will keep any extensions from running
	 * (until someone places changes in code to make sure the extension
	 * runs properly). This hard codes are the "v1" in the signature, and
	 * the ,100, iteration counts.  The most logical change would be a
	 * v2 and 10000 iterations (or something like that). However, v2
	 * may be a different underlying algorithm, so these hard coded
	 * valid checks are left in for now.
	 */
	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		return 0;
	ciphertext += TAG_LENGTH;
	if (base64_valid_length(ciphertext, e_b64_hex, 0, 0) != SALT_HASH_LEN)
		return 0;
	ciphertext += SALT_HASH_LEN;
	if (*ciphertext != ',')
		return 0;
	++ciphertext;
	if (strncmp(ciphertext, "100,", 4))
		return 0;
	ciphertext += 4;
	if (base64_valid_length(ciphertext, e_b64_hex, 0, 0) != HASH_LENGTH || strlen(ciphertext) != HASH_LENGTH+1)
		return 0;
	return ciphertext[HASH_LENGTH] == ';';
}

char *AzureAD_common_split(char *ciphertext, int index, struct fmt_main *self) {
	static char Buf[120];
	strncpy(Buf, ciphertext, 119);
	Buf[119] = 0;
	strlwr(&Buf[TAG_LENGTH]);
	return Buf;
}

void *AzureAD_common_get_binary(char *ciphertext) {
	static uint32_t full[DIGEST_SIZE / 4];
	unsigned char *realcipher = (unsigned char*)full;

	ciphertext += (TAG_LENGTH + SALT_HASH_LEN + ROUNDS_LEN + 2);
	base64_convert(ciphertext, e_b64_hex, 64, realcipher, e_b64_raw, sizeof(full), 0, 0);
	return (void*)realcipher;
}
