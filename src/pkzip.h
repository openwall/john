/*
 * This software is Copyright (c) 2011-2018 Jim Fougeron,
 * Copyright (c) 2013-2021 magnum,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */
#ifndef PKZIP_H
#define PKZIP_H

#include "dyna_salt.h"
#include "crc32.h"

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t  u8;
typedef char     c8;

u64 fget64LE(FILE *fp);
u32 fget32LE(FILE *fp);
u16 fget16LE(FILE *fp);

#define MAX_PKZ_FILES 8

// These came from the gladman headers
#define KEY_LENGTH(mode)    (8 * ((mode) & 3) + 8)
#define SALT_LENGTH(mode)   (4 * ((mode) & 3) + 4)
#define KEYING_ITERATIONS   1000
#define PASSWORD_VERIFIER
#ifdef  PASSWORD_VERIFIER
#define PWD_VER_LENGTH      2
#else
#define PWD_VER_LENGTH      0
#endif

#if USE_PKZIP_MAGIC
typedef struct zip_magic_signatures_t {
	u8 *magic_signature[8];
	u8  magic_sig_len[8];
	u8  magic_count;
	u8  max_len;
} ZIP_SIGS;
#endif

typedef struct zip_hash_type_t {
	u8 *h;						// at getsalt time, we leave these null.  Later in setsalt, we 'fix' them
	u8 type;					// JtR hash version. Version 2 ($pkzip2$) is now the deprecated one.
	u16 c;
	u16 c2;
	u64 datlen;
	u8 magic;					// This is used as 'magic' signature type. Also, 255 is 'generic text'
	u8 full_zip;
	u32 compType;				// the type of compression  0 or 8
#if USE_PKZIP_MAGIC
	ZIP_SIGS *pSig;
#endif
} ZIP_HASH;

typedef struct winzip_salt_t {
	dyna_salt dsalt;
	uint64_t comp_len;
	struct {
		uint16_t type : 4;
		uint16_t mode : 4;
	} v;
	unsigned char passverify[2];
	unsigned char salt[SALT_LENGTH(3)];
	unsigned char datablob[1];
} winzip_salt;

typedef struct zip_salt_t {
	dyna_salt dsalt;
	char fname[1024];			// if the zip is too large, we open the file in cmp_exact read the
								// data a small buffer at a time.  If the zip blob is small enough
								// (under 16k), then it simply read into H[x].h at init() time.
								// and cmp_exact does not need fname to be used.
	long offset;				// this is the offset to zip data (if we have to read from the file).
	ZIP_HASH H[MAX_PKZ_FILES];
	u32 full_zip_idx;			// the index (0, 1, 2) which contains the 'full zip' data.
	// start of the dyna zip 'compared' data.
	u32 cnt;					// number of hashes
	u32 chk_bytes;				// number of bytes valid in checksum (1 or 2)
	u32 crc32;					// if a 'full' file of encr data, then this is the CRC
	u64 compLen;				// length of compressed data (whether part or full)
	u64 deCompLen;				// length of decompressed data (if full).
	u32 compType;				// the type of compression  0 or 8

	u8  zip_data[1];			// we 'move' the H[x].h data to here.  Then we 'fix' it up when later setting the salt.
} PKZ_SALT;

typedef union MY_WORD {
	u32 u;
	u8  c[4];
} MY_WORD;

/* Here is the 'common' code */
#define WINZIP_BENCHMARK_COMMENT	""
#define WINZIP_BENCHMARK_LENGTH	0x507
#define WINZIP_BINARY_SIZE         10
#define WINZIP_FORMAT_TAG		"$zip2$"
#define WINZIP_FORMAT_CLOSE_TAG	"$/zip2$"
#define WINZIP_TAG_LENGTH		6

extern int winzip_common_valid(char *ciphertext, struct fmt_main *self);
extern char *winzip_common_split(char *ciphertext, int index, struct fmt_main *self);
extern void *winzip_common_binary(char *ciphertext);
extern void *winzip_common_get_salt(char *ciphertext);

extern struct fmt_tests winzip_common_tests[];

#endif /* PKZIP_H */
