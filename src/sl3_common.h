/*
 * Copyright (c) 2017 magnum.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#define FORMAT_NAME         "Nokia operator unlock"
#define BENCHMARK_COMMENT   ""

#define PLAINTEXT_MINLEN    15
#define PLAINTEXT_LENGTH    15

#define CIPHERTEXT_LENGTH   (SL3_MAGIC_LENGTH + 14 + 1 + 2 * BINARY_SIZE)

#define BINARY_SIZE         20
#define BINARY_ALIGN        4
#define SALT_SIZE           9
#define SALT_ALIGN          4

#define SL3_MAGIC           "$sl3$"
#define SL3_MAGIC_LENGTH    (sizeof(SL3_MAGIC) - 1)

extern struct fmt_tests sl3_tests[];

extern char *sl3_prepare(char *split_fields[10], struct fmt_main *self);
extern int sl3_valid(char *ciphertext, struct fmt_main *self);
extern void *sl3_get_salt(char *ciphertext);
extern int sl3_salt_hash(void *salt);
