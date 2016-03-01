/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2016 JimF
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 *
 *  Functions and data which is common among the GPG crackers
 *  (CPU, OpenCL)
 */

#define BENCHMARK_COMMENT		           ""
#define BENCHMARK_LENGTH		           -1001
#define BINARY_SIZE                        0
#define BINARY_ALIGN                       MEM_ALIGN_WORD
#define SALT_LENGTH                        8
#define SALT_ALIGN                         (sizeof(void*))

// Minimum number of bits when checking the first BN
#define MIN_BN_BITS 64
#define BIG_ENOUGH 8192

extern int gpg_common_valid(char *ciphertext, struct fmt_main *self, int is_CPU_format);
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
	PKA_EG = 20
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

#ifndef SHA_DIGEST_LENGTH
#define SHA_DIGEST_LENGTH 20
#endif

#ifndef SHA256_DIGEST_LENGTH
#define SHA256_DIGEST_LENGTH 32
#endif

#ifndef SHA512_DIGEST_LENGTH
#define SHA512_DIGEST_LENGTH 64
#endif

struct gpg_common_custom_salt {
	int datalen;
	unsigned char data[BIG_ENOUGH * 2];
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
	unsigned char p[BIG_ENOUGH];
	unsigned char q[BIG_ENOUGH];
	unsigned char g[BIG_ENOUGH];
	unsigned char y[BIG_ENOUGH];
	unsigned char x[BIG_ENOUGH];
	unsigned char n[BIG_ENOUGH];
	unsigned char d[BIG_ENOUGH];
	int pl;
	int ql;
	int gl;
	int yl;
	int xl;
	int nl;
	int dl;
	int symmetric_mode;
};

extern struct gpg_common_custom_salt *gpg_common_cur_salt;
