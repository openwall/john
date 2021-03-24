/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2016 JimF
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 *
 *  Functions and data which is common among the pbkdf2_hmac_* crackers
 *  (CPU, OpenCL)
 */

#include <assert.h>

#define BENCHMARK_COMMENT                  ""
#define BENCHMARK_LENGTH                   0x107

#define PBKDF2_32_BINARY_ALIGN             sizeof(uint32_t)
#define PBKDF2_32_MAX_SALT_SIZE            179 /* 3 limb md4/md5/sha1/sha256 max when 4 byte loop counter is appended */
#define PBKDF2_64_MAX_SALT_SIZE            107 /* 1 limb sha512 max when 4 byte loop counter is appended */

#define PBKDF2_MDx_BINARY_SIZE             16
#define PBKDF2_MDx_MAX_BINARY_SIZE         (4 * PBKDF2_MDx_BINARY_SIZE)

#define PBKDF2_MD4_FORMAT_TAG              "$pbkdf2-hmac-md4$"
#define PBKDF2_MD4_TAG_LEN                 (sizeof(PBKDF2_MD4_FORMAT_TAG) - 1)
#define PBKDF2_MD4_MAX_CIPHERTEXT_LENGTH   (PBKDF2_MD4_TAG_LEN + 6 + 1 + 2*PBKDF2_32_MAX_SALT_SIZE + 1 + 2*PBKDF2_MDx_MAX_BINARY_SIZE)

#define PBKDF2_MD5_FORMAT_TAG              "$pbkdf2-hmac-md5$"
#define PBKDF2_MD5_TAG_LEN                 (sizeof(PBKDF2_MD5_FORMAT_TAG) - 1)
#define PBKDF2_MD5_MAX_CIPHERTEXT_LENGTH   (PBKDF2_MD5_TAG_LEN + 6 + 1 + 2*PBKDF2_32_MAX_SALT_SIZE + 1 + 2*PBKDF2_MDx_MAX_BINARY_SIZE)

#define PBKDF2_SHA1_BINARY_SIZE             20
#define PBKDF2_SHA1_MAX_BINARY_SIZE         (4 * PBKDF2_SHA1_BINARY_SIZE)
#define PBKDF2_SHA1_FORMAT_TAG              "$pbkdf2-hmac-sha1$"
#define PBKDF2_SHA1_TAG_LEN                 (sizeof(PBKDF2_SHA1_FORMAT_TAG) - 1)
/* additional signatures handled, but converted in prepare */
#define PKCS5S2_TAG                         "{PKCS5S2}"
#define PKCS5S2_TAG_LEN                     (sizeof(PKCS5S2_TAG)-1)
#define PK5K2_TAG                           "$p5k2$"
#define PK5K2_TAG_LEN                       (sizeof(PK5K2_TAG)-1)
#define PBKDF2_SHA1_MAX_CIPHERTEXT_LENGTH   (PBKDF2_SHA1_TAG_LEN + 6 + 1 + 2*PBKDF2_32_MAX_SALT_SIZE + 1 + 2*PBKDF2_SHA1_MAX_BINARY_SIZE)

#define PBKDF2_SHA256_BINARY_SIZE           32
#define PBKDF2_SHA256_FORMAT_TAG            "$pbkdf2-sha256$"
#define PBKDF2_SHA256_TAG_LEN               (sizeof(PBKDF2_SHA256_FORMAT_TAG) - 1)
/* other signature handled within prepare */
#define FORMAT_TAG_CISCO8                   "$8$"
#define FORMAT_TAG_CISCO8_LEN               (sizeof(FORMAT_TAG_CISCO8) - 1)
#define PBKDF2_SHA256_MAX_BINARY_SIZE       (4 * PBKDF2_SHA256_BINARY_SIZE)
#define PBKDF2_SHA256_MAX_CIPHERTEXT_LENGTH (PBKDF2_SHA256_TAG_LEN + 6 + 1 + (PBKDF2_32_MAX_SALT_SIZE*4+2)/3 + 1 + (PBKDF2_SHA256_MAX_BINARY_SIZE*4+2)/3)

#define PBKDF2_SHA512_BINARY_SIZE           64
#define PBKDF2_SHA512_BINARY_ALIGN          sizeof(uint64_t)
#define PBKDF2_SHA512_FORMAT_TAG            "$pbkdf2-hmac-sha512$"
#define PBKDF2_SHA512_TAG_LEN               (sizeof(PBKDF2_SHA512_FORMAT_TAG) - 1)
/* other signatures handled within prepare */
#define FORMAT_TAG_ML               "$ml$"
#define FORMAT_TAG_ML_LEN           (sizeof(FORMAT_TAG_ML) - 1)
#define FORMAT_TAG_GRUB             "grub.pbkdf2.sha512."
#define FORMAT_TAG_GRUB_LEN         (sizeof(FORMAT_TAG_GRUB) - 1)
#define PBKDF2_SHA512_MAX_BINARY_SIZE       (4 * PBKDF2_SHA512_BINARY_SIZE)
#define PBKDF2_SHA512_MAX_CIPHERTEXT_LENGTH (PBKDF2_SHA512_TAG_LEN + 6 + 1 + 2*PBKDF2_64_MAX_SALT_SIZE + 1 + 2*PBKDF2_SHA512_MAX_BINARY_SIZE)

/* md4 common functions/data */
extern struct fmt_tests pbkdf2_hmac_md4_common_tests[];
extern int pbkdf2_hmac_md4_valid(char *ciphertext, struct fmt_main *self);
extern char *pbkdf2_hmac_md4_split(char *ciphertext, int index, struct fmt_main *self);
extern void *pbkdf2_hmac_md4_binary(char *ciphertext);
extern int pbkdf2_hmac_md4_cmp_exact(char *key, char *source, unsigned char *salt, int salt_len, int iterations);

/* md5 common functions/data */
extern struct fmt_tests pbkdf2_hmac_md5_common_tests[];
extern int pbkdf2_hmac_md5_valid(char *ciphertext, struct fmt_main *self);
extern char *pbkdf2_hmac_md5_split(char *ciphertext, int index, struct fmt_main *self);
extern void *pbkdf2_hmac_md5_binary(char *ciphertext);
extern int pbkdf2_hmac_md5_cmp_exact(char *key, char *source, unsigned char *salt, int salt_len, int iterations);

/* sha1 common functions/data */
extern struct fmt_tests pbkdf2_hmac_sha1_common_tests[];
extern int pbkdf2_hmac_sha1_valid(char *ciphertext, struct fmt_main *self);
extern char *pbkdf2_hmac_sha1_prepare(char *fields[10], struct fmt_main *self);
extern char *pbkdf2_hmac_sha1_split(char *ciphertext, int index, struct fmt_main *self);
extern void *pbkdf2_hmac_sha1_binary(char *ciphertext);
extern int pbkdf2_hmac_sha1_cmp_exact(char *key, char *source, unsigned char *salt, int salt_len, int iterations);

/* sha256 common functions/data */
extern struct fmt_tests pbkdf2_hmac_sha256_common_tests[];
extern int pbkdf2_hmac_sha256_valid(char *ciphertext, struct fmt_main *self);
extern char *pbkdf2_hmac_sha256_prepare(char *fields[10], struct fmt_main *self);
extern void *pbkdf2_hmac_sha256_binary(char *ciphertext);

/* sha512 common functions/data */
extern struct fmt_tests pbkdf2_hmac_sha512_common_tests[];
extern int pbkdf2_hmac_sha512_valid(char *ciphertext, struct fmt_main *self);
extern char *pbkdf2_hmac_sha512_prepare(char *fields[10], struct fmt_main *self);
extern char *pbkdf2_hmac_sha512_split(char *ciphertext, int index, struct fmt_main *self);
extern void *pbkdf2_hmac_sha512_binary(char *ciphertext);
extern int pbkdf2_hmac_sha512_cmp_exact(char *key, char *source, unsigned char *salt, int salt_len, int iterations);
