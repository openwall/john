/*
 * This software is
 * Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * Copyright (c) 2014 m3g9tr0n (Spiros Fraganastasis),
 * Copyright (c) 2016 Fist0urs <eddy.maaalou at gmail.com>, and
 * Copyright (c) 2017 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#define FORMAT_TAG           "$keepass$*"
#define FORMAT_TAG_LEN       (sizeof(FORMAT_TAG)-1)
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	0x107
#define PLAINTEXT_LENGTH	124
#define BINARY_SIZE		0
#define BINARY_ALIGN		MEM_ALIGN_NONE
#define SALT_SIZE		sizeof(keepass_salt_t)
#if ARCH_ALLOWS_UNALIGNED
// Avoid a compiler bug, see #1284
#define SALT_ALIGN		1
#else
// salt align of 4 was crashing on sparc due to the long long value.
#define SALT_ALIGN		sizeof(long long)
#endif
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

extern struct fmt_tests keepass_tests[];

/* This format should be dyna salt instead! */
#define MAX_CONT_SIZE 0x1000000

typedef struct {
	long long offset;
	int version;
	int isinline;
	int keyfilesize;
	int have_keyfile;
	int contentsize;
	uint32_t key_transf_rounds;
	int algorithm; // 1 for Twofish
	unsigned char final_randomseed[32];
	unsigned char enc_iv[16];
	unsigned char keyfile[32];
	unsigned char contents_hash[32];
	unsigned char transf_randomseed[32];
	unsigned char expected_bytes[32];
	unsigned char contents[MAX_CONT_SIZE];
} keepass_salt_t;

extern char (*keepass_key)[PLAINTEXT_LENGTH + 1];
extern keepass_salt_t *keepass_salt;
extern int keepass_valid(char *ciphertext, struct fmt_main *self);
extern void *keepass_get_salt(char *ciphertext);
extern void keepass_set_key(char *key, int index);
extern char *keepass_get_key(int index);
extern unsigned int keepass_iteration_count(void *salt);
extern unsigned int keepass_version(void *salt);
extern unsigned int keepass_algorithm(void *salt);
