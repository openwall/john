/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2016 JimF
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 *
 * This file contains functions and data which are common among the GPG
 * crackers (CPU, and OpenCL formats).
 */

#include "dyna_salt.h"

#define BENCHMARK_COMMENT    ""
#define FORMAT_TAG           "$gpg$*"
#define FORMAT_TAG_LEN       (sizeof(FORMAT_TAG)-1)
#define BINARY_SIZE          0
#define BINARY_ALIGN         MEM_ALIGN_WORD
#define SALT_LENGTH          8
#define SALT_ALIGN           (sizeof(void*))
#define PLAINTEXT_LENGTH     125

// Minimum number of bits when checking the first BN
#define MIN_BN_BITS 64

extern struct fmt_tests gpg_common_gpg_tests[];

extern int gpg_common_valid(char *ciphertext, struct fmt_main *self, int is_CPU);
extern int gpg_common_check(unsigned char *keydata, int ks);
extern void *gpg_common_get_salt(char *ciphertext);

extern uint32_t gpg_common_keySize(char algorithm);
extern uint32_t gpg_common_blockSize(char algorithm);
extern unsigned int gpg_common_gpg_s2k_count(void *salt);
extern unsigned int gpg_common_gpg_hash_algorithm(void *salt);
extern unsigned int gpg_common_gpg_cipher_algorithm(void *salt);

enum {
	SPEC_SIMPLE = 0,
	SPEC_SALTED = 1,
	SPEC_ITERATED_SALTED = 3
};

enum {
	PKA_UNKNOWN = 0,
	PKA_RSA_ENCSIGN = 1,
	PKA_DSA = 17,
	PKA_EG = 20,  // TODO???  wtf is this one???
	PKA_ELGAMAL = 16
};

enum {
	CIPHER_UNKNOWN = -1,
	CIPHER_CAST5 = 3,
	CIPHER_BLOWFISH = 4,
	CIPHER_AES128 = 7,
	CIPHER_AES192 = 8,
	CIPHER_AES256 = 9,
	CIPHER_IDEA = 1,
	CIPHER_3DES = 2,
	CIPHER_TWOFISH = 10,
	CIPHER_CAMELLIA128 = 11,
	CIPHER_CAMELLIA192 = 12,
	CIPHER_CAMELLIA256 = 13,
};

enum {
	HASH_UNKNOWN = -1,
	HASH_MD5 = 1,
	HASH_SHA1 = 2,
	HASH_RIPEMD160 = 3,
	HASH_SHA256 = 8,
	HASH_SHA384 = 9,
	HASH_SHA512 = 10,
	HASH_SHA224 = 11
};

#ifndef MD5_DIGEST_LENGTH
#define MD5_DIGEST_LENGTH 16
#endif

struct gpg_common_custom_salt {
	dyna_salt dsalt;
	int datalen;
	char spec;
	char pk_algorithm;
	char hash_algorithm;
	char cipher_algorithm;
	int usage;
	int bits;
	unsigned char salt[SALT_LENGTH];
	unsigned char iv[16];
	int ivlen;
	int count;
	void (*s2kfun)(char *, unsigned char*, int);
	unsigned char p[0x2000]; // gpg --homedir . --s2k-cipher-algo 3des --simple-sk-checksum --gen-key
	unsigned char q[0x2000]; // those can have larger p and q values.
	unsigned char g[0x200];
	unsigned char y[0x200];
	unsigned char x[0x200];
	unsigned char n[0x200];
	unsigned char d[0x200];
	int pl;
	int ql;
	int gl;
	int yl;
	int xl;
	int nl;
	int dl;
	int symmetric_mode;
	unsigned char data[1];
};

extern struct gpg_common_custom_salt *gpg_common_cur_salt;
