/*
 * Copyright (c) 2026, Dhiru Kholia
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include <string.h>

#include "formats.h"
#include "common.h"
#include "iterated_sha256_common.h"

struct fmt_tests iterated_sha256_tests[] = {
	// Cisco-ISE-SHA256
	{"465865d4226c4d9696e601f2c99b25ae2c194ec01806bafc93933331acfc1a60e8bdcca8be9fa245a5fa16029bb52480915746f47d1c539d01da7ec6f37468d1", "hashcat"},
	// {"$sisha256$129$e8bdcca8be9fa245a5fa16029bb52480915746f47d1c539d01da7ec6f37468d1465865d4226c4d9696e601f2c99b25ae2c194ec01806bafc93933331acfc1a60", "hashcat"},

	// Synthetic test vectors
	{"a6c9702dae629b71383eb2819f00464985c2188db7ff83a9cb5137eb6ee975d500112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", "OpenAI2026!"},
	// {"$sisha256$129$00112233445566778899aabbccddeeff00112233445566778899aabbccddeeffa6c9702dae629b71383eb2819f00464985c2188db7ff83a9cb5137eb6ee975d5", "OpenAI2026!"},
	// Simple test with 1 iteration (just SHA256(salt || password))
	{"$sisha256$1$73616c7413601bda4ea78e55a07b98866d2be6be0744e3866f13c00c811cab608a28f322", "password"},
	{NULL}
};

/*
 * Untagged hash format (Cisco-ISE): 128 hex chars
 *   <hex_hash><hex_salt>  (32-byte hash + 32-byte salt)
 *
 * Tagged hash format (variable salt length):
 *   $sisha256$N$<hex_salt><hex_hash>
 *   where N is the total number of hash rounds (1 means only the initial hash)
 */
int iterated_sha256_valid(char *ciphertext, struct fmt_main *self)
{
	if (!strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN)) {
		int extra;
		int len;
		int iter;

		ciphertext += FORMAT_TAG_LEN;

		iter = getdec(ciphertext, '$');
		if (iter < 1 || iter > MAX_ITERATIONS)
			return 0;

		ciphertext = strchr(ciphertext, '$');
		if (!ciphertext)
			return 0;
		ciphertext++;

		len = strnlen(ciphertext, BINARY_SIZE * 2 + MAX_SALT_BYTES * 2 + 1);
		if (len & 1)
			return 0;
		if (len < BINARY_SIZE * 2 || len > BINARY_SIZE * 2 + MAX_SALT_BYTES * 2)
			return 0;
		if (hexlenl(ciphertext, &extra) != len || extra)
			return 0;

		return 1;
	}

	if (strlen(ciphertext) != CIPHERTEXT_LENGTH)
		return 0;
	if (!ishex(ciphertext))
		return 0;
	return 1;
}

void *iterated_sha256_get_binary(char *ciphertext)
{
	static union {
		unsigned char b[BINARY_SIZE];
		uint32_t dummy;
	} out;
	const char *p = ciphertext;
	int i;

	if (!strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN)) {
		p += FORMAT_TAG_LEN;
		p = strchr(p, '$') + 1;
		p += strlen(p) - (BINARY_SIZE * 2);
	}

	for (i = 0; i < BINARY_SIZE; i++) {
		out.b[i] = (atoi16[ARCH_INDEX(p[0])] << 4) | atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out.b;
}

void *iterated_sha256_get_salt(char *ciphertext)
{
	static salt_t out;
	const char *p = ciphertext;
	int i;

	memset(&out, 0, sizeof(out));

	if (!strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN)) {
		int len;

		p += FORMAT_TAG_LEN;
		out.iter = getdec(p, '$');
		p = strchr(p, '$') + 1;

		len = strlen(p);
		out.len = (len - BINARY_SIZE * 2) / 2;

		for (i = 0; i < (int)out.len; i++) {
			((unsigned char *)out.salt)[i] =
			    (atoi16[ARCH_INDEX(p[0])] << 4) | atoi16[ARCH_INDEX(p[1])];
			p += 2;
		}
	} else {
		out.iter = ISE_TOTAL_ROUNDS;
		out.len = SALT_BYTES;
		p += CIPHERTEXT_LENGTH - (SALT_BYTES * 2);

		for (i = 0; i < SALT_BYTES; i++) {
			((unsigned char *)out.salt)[i] =
			    (atoi16[ARCH_INDEX(p[0])] << 4) | atoi16[ARCH_INDEX(p[1])];
			p += 2;
		}
	}

	return &out;
}

int iterated_sha256_salt_hash(void *salt)
{
	salt_t *s = salt;

	return (s->iter ^ s->len ^ s->salt[0]) & (SALT_HASH_SIZE - 1);
}

unsigned int iterated_sha256_iterations(void *salt)
{
	salt_t *s = salt;

	return s->iter;
}
