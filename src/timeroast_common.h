/*
 * SNTP-MS "Timeroast" patch for john
 *
 * This software is Copyright (c) 2023 magnum
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#define PLAINTEXT_LENGTH    27
#define BENCHMARK_COMMENT   ""
#define BENCHMARK_LENGTH    7
#define FORMAT_TAG          "$sntp-ms$"
#define FORMAT_TAG_LEN      (sizeof(FORMAT_TAG) - 1)
#define BINARY_SIZE         16
#define BINARY_ALIGN        sizeof(uint32_t)
#define SALT_SIZE           48
#define SALT_ALIGN          sizeof(uint32_t)

extern struct fmt_tests timeroast_tests[];

extern int   timeroast_valid(char *ciphertext, struct fmt_main *self);
extern void *timeroast_binary(char *ciphertext);
extern void *timeroast_salt(char *ciphertext);
