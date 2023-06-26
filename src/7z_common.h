/*
 * This software is Copyright (c) 2013-2020 magnum, and it is hereby released to the general
 * public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#ifndef _7Z_COMMON_H
#define _7Z_COMMON_H

#include "aes.h"
#include "lzma/LzmaDec.h"
#include "lzma/Lzma2Dec.h"
#include "lzma/Bra.h"
#include "lzma/CpuArch.h"
#include "lzma/Delta.h"
#include "crc32.h"

#define FORMAT_NAME             "7-Zip archive encryption"
#define FORMAT_TAG              "$7z$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG)-1)
#define BENCHMARK_COMMENT       " (512K iterations)"
/*
 * The format exploits the fact that the salt is usually empty,
 * so KDF result can be reused.
 */
#define BENCHMARK_LENGTH        7
#define BINARY_SIZE             0
#define BINARY_ALIGN            1
#define SALT_SIZE               sizeof(sevenzip_salt_t*)
#define SALT_ALIGN              sizeof(sevenzip_salt_t*)

typedef struct sevenzip_salt_s {
	dyna_salt dsalt;
	size_t aes_length;  /* AES length (even blocks) */
	size_t packed_size; /* Deflated length */
	size_t crc_len;     /* Inflated length */
	int NumCyclesPower;
	int SaltSize;
	int ivSize;
	int type;
	unsigned char iv[16];
	unsigned char salt[16];
	unsigned int crc;
	unsigned char decoder_props[LZMA_PROPS_SIZE];
	unsigned char preproc_props;
	unsigned char data[1];
} sevenzip_salt_t;

extern sevenzip_salt_t *sevenzip_salt;

extern int sevenzip_trust_padding;
extern struct fmt_tests sevenzip_tests[];

extern int sevenzip_valid(char *ciphertext, struct fmt_main *self);
extern void *sevenzip_get_salt(char *ciphertext);
extern int sevenzip_salt_compare(const void *x, const void *y);
extern int sevenzip_decrypt(unsigned char *derived_key);
extern unsigned int sevenzip_iteration_count(void *salt);
extern unsigned int sevenzip_padding_size(void *salt);
extern unsigned int sevenzip_compression_type(void *salt);
extern unsigned int sevenzip_data_len(void *salt);

#endif /* _7Z_COMMON_H */
