/*
 * This software is Copyright (c) 2021, magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#ifndef CRYPTOSAFE_COMMON_H
#define CRYPTOSAFE_COMMON_H

#define FORMAT_NAME         ""
#define FORMAT_TAG           "$cryptosafe$1$"
#define FORMAT_TAG_LEN       (sizeof(FORMAT_TAG)-1)
#define BENCHMARK_COMMENT   ""
#define BENCHMARK_LENGTH    0x107
#define PLAINTEXT_LENGTH    32
#define BINARY_SIZE         0
#define BINARY_ALIGN        1
#define SALT_SIZE           sizeof(struct custom_salt)
#define SALT_ALIGN          sizeof(int)

extern struct fmt_tests cryptosafe_tests[];

struct custom_salt {
	unsigned char ciphertext[16];
};

//extern struct fmt_tests cryptosafe_tests[];

extern int cryptosafe_valid(char *ciphertext, struct fmt_main *self);
extern char *cryptosafe_split(char *ciphertext, int index, struct fmt_main *self);
extern void *cryptosafe_get_salt(char *ciphertext);

#endif /* CRYPTOSAFE_COMMON_H */
