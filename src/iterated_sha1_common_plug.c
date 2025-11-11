/*
 * Copyright (c) 2025, magnum
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include "formats.h"
#include "common.h"
#include "base64_convert.h"
#include "iterated_sha1_common.h"

/*
 * Salt is prefixed as in $s.$p whereas the "salted-sha1" format has it
 * suffixed as in $p.$s (and that format does not support iterations).
 *
 * Salt length is infered - the last 160 bits is the actual SHA-1 hash.
 * Salt is also hex and thus must be an even number of hex characters,
 * but it can be zero length for no salt.
 *
 * Iterations must be >= 1. With no salt and 1 iteration, this is raw
 * SHA-1 (supported but not optimized - there's a specific format for that).
 */
struct fmt_tests iterated_sha1_tests[] = {
	// Canonical ciphertexts:
	// 8 bytes salt, 1024 iterations
	{"$sisha1$1024$6f77746f6f77746f5fa823ad3c2dc9b58893df73d52b2108b2efce45", "magnum"},
	{"$sisha1$1024$6a6f686e72697070a3a2baadacf154dca88a9ea31400481748e253bb", "password"},
	// 6 bytes salt, 512 iterations
	{"$sisha1$512$cafe80babe000cd885f153e249671f703039a5dce8a4ad771175", "ripper"},
	// 3 bytes salt, 2 iterations
	{"$sisha1$2$616c7436370ca78308b8bb605ae3d66e1c18ac1c50fa52", "short"},
	// 4 bytes salt, 1 iteration
	{"$sisha1$1$73616c74d46dd115de9a2f3bf32d42b38d1b437e5f8b92a7", "clear"},
	// Raw SHA-1 (just for testing)
	{"$sisha1$1$2fbf0eba37de1d1d633bc1ed943b907f9b360d4c", "azertyuiop1"},
	// Raw ciphertexts:
	// 1024 iterations (default)
	{"6a6f686e72697070a48cd538757a88deaf12b93f4758e27017852ba3", "John the Ripper"},
	// XSHA: 4 bytes salt, 1 iteration (implicit for length 48 only)
	{"474379622bd7b9f84bd6e4bb52abf9d01705efb0a2426655", "passWOrd"},
	{NULL}
};

/*
 * Convert raw ciphertext to canonical ciphertext with inferred salt length
 * and 1024 iterations (with exception for XSHA).
 */
char *iterated_sha1_prepare(char *fields[10], struct fmt_main *self)
{
	static char out[FORMAT_TAG_LEN + 4 + 1 + 2 * 8 + 40 + 1];

	if (!strncasecmp(fields[1], FORMAT_TAG, FORMAT_TAG_LEN))
		return fields[1];

	int len = strnlen(fields[1], 56 + 1);
	int iter, extra;

	if (len < MIN_CIPHERTEXT_LEN || len > MAX_CIPHERTEXT_LEN)
		return fields[1];
	if (hexlenl(fields[1], &extra) != len || extra)
		return fields[1];

	if (len == 48) // XSHA
		iter = 1;
	else
		iter = 1024;

	sprintf(out, "%s%d$%s", FORMAT_TAG, iter, fields[1]);
	return out;
}

int iterated_sha1_valid(char *ciphertext, struct fmt_main *self)
{
	if (strncasecmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
		return 0;
	ciphertext += FORMAT_TAG_LEN;

	int iter = getdec(ciphertext, '$');
	if (iter < 1 || iter > MAX_ITER)
		return 0;

	ciphertext = strchr(ciphertext, '$') + 1;

	int len = strnlen(ciphertext, MAX_CIPHERTEXT_LEN + 1);
	if (len & 1 || len > MAX_CIPHERTEXT_LEN)
		return 0;

	int extra;
	if (hexlenl(ciphertext, &extra) < MIN_CIPHERTEXT_LEN || extra)
		return 0;

	return 1;
}

void* iterated_sha1_get_binary(char* ciphertext)
{
	static uint8_t binary[BINARY_SIZE];

	ciphertext += strlen(ciphertext) - 2 * BINARY_SIZE;
	base64_convert(ciphertext, e_b64_hex, 2 * BINARY_SIZE, binary, e_b64_raw, BINARY_SIZE, flg_Base64_DONOT_NULL_TERMINATE, 0);

#if defined(SIMD_COEF_32) && ARCH_LITTLE_ENDIAN
	alter_endianity(binary, BINARY_SIZE);
#endif

	return binary;
}

void* iterated_sha1_get_salt(char* ciphertext)
{
	static salt_t salt_blob;

	memset(&salt_blob, 0, sizeof(salt_blob));

	ciphertext += FORMAT_TAG_LEN;

	salt_blob.iter = atoi(ciphertext);
	ciphertext = strchr(ciphertext, '$') + 1;

	char* bin = ciphertext + strlen(ciphertext) - 40;
	salt_blob.len = (bin - ciphertext) / 2;

	base64_convert(ciphertext, e_b64_hex, 2 * salt_blob.len, salt_blob.salt, e_b64_raw, salt_blob.len, flg_Base64_DONOT_NULL_TERMINATE, 0);

	return &salt_blob;
}

int iterated_sha1_salt_hash(void *salt)
{
	salt_t *salt_blob = salt;

	return (salt_blob->len ^ salt_blob->iter ^ salt_blob->salt[0]) & (SALT_HASH_SIZE - 1);
}

unsigned int iterated_sha1_iterations(void *salt)
{
	salt_t *cur_salt = salt;

	return cur_salt->iter;
}
