/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2012 magnum
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#ifndef _COMMON_RAWSHA512_H
#define _COMMON_RAWSHA512_H

/* ------ Contains (at least) prepare(), valid() and split() ------ */
#define DIGEST_SIZE                     64
#define BINARY_ALIGN                    sizeof(uint64_t)

#define BENCHMARK_COMMENT               ""
#define BENCHMARK_LENGTH            7
#define XSHA512_BENCHMARK_LENGTH    7
#define NSLDAP_BENCHMARK_LENGTH     7

#define FORMAT_TAG			"$SHA512$"
#define XSHA512_FORMAT_TAG              "$LION$"
#define NSLDAP_FORMAT_TAG               "{SSHA512}"

#define TAG_LENGTH			(sizeof(FORMAT_TAG) - 1)
#define XSHA512_TAG_LENGTH              (sizeof(XSHA512_FORMAT_TAG) - 1)
#define NSLDAP_TAG_LENGTH               (sizeof(NSLDAP_FORMAT_TAG) - 1)

#define NSLDAP_SALT_LEN                 16      // bytes, the base64 representation is longer
#define NSLDAP_SALT_SIZE                (NSLDAP_SALT_LEN + sizeof(unsigned int))

#define CIPHERTEXT_LENGTH		128
#define XSHA512_CIPHERTEXT_LENGTH	136
#define NSLDAP_CIPHERTEXT_LENGTH        ((DIGEST_SIZE + 1 + NSLDAP_SALT_LEN + 2) / 3 * 4)

#define NSLDAP_BASE64_ALPHABET	  \
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

int sha512_common_valid(char *ciphertext, struct fmt_main *self);
int sha512_common_valid_xsha512(char *ciphertext, struct fmt_main *self);
int sha512_common_valid_nsldap(char *ciphertext, struct fmt_main *self);

void * sha512_common_binary(char *ciphertext);
void * sha512_common_binary_BE(char *ciphertext);
void * sha512_common_binary_rev(char *ciphertext);
void * sha512_common_binary_xsha512(char *ciphertext);
void * sha512_common_binary_xsha512_BE(char *ciphertext);
void * sha512_common_binary_xsha512_rev(char *ciphertext);
void * sha512_common_binary_nsldap(char *ciphertext);

char * sha512_common_prepare_xsha512(char *split_fields[10], struct fmt_main *self);

char * sha512_common_split(char *ciphertext, int index, struct fmt_main *self);
char * sha512_common_split_xsha512(char *ciphertext, int index, struct fmt_main *pFmt);

extern struct fmt_tests sha512_common_tests_rawsha512_111[];
extern struct fmt_tests sha512_common_tests_rawsha512_20[];
extern struct fmt_tests sha512_common_tests_ssha512[];
extern struct fmt_tests sha512_common_tests_xsha512[];
extern struct fmt_tests sha512_common_tests_xsha512_20[];

#endif
