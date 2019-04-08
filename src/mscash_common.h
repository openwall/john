/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) Feb 29, 2016 JimF
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 *
 *  Functions and data which is common among the mscash and mscash2 crackers
 *  (CPU, OpenCL)
 */

#define BENCHMARK_COMMENT                 ""
#define BENCHMARK_LENGTH                  7
#define FORMAT_TAG                        "M$"
#define FORMAT_TAG_LEN                   (sizeof(FORMAT_TAG)-1)
#define FORMAT_TAG2                       "$DCC2$"
#define FORMAT_TAG2_LEN                  (sizeof(FORMAT_TAG2)-1)
#define BINARY_SIZE                       16
#define BINARY_ALIGN                      sizeof(uint32_t)
#define SALT_ALIGN                        sizeof(uint32_t)

#define MSCASH1_MAX_CIPHERTEXT_LENGTH    (2 + 19*3 + 1 + 32) // x3 because salt may be UTF-8 in input
#define MSCASH1_MAX_SALT_LENGTH          19




extern struct fmt_tests mscash1_common_tests[];
extern struct fmt_tests mscash2_common_tests[];

extern void mscash1_adjust_tests(struct fmt_main *self, unsigned encoding,
                                 unsigned plain_len,
                                 void (*set_key_utf8)(char*,int),
                                 void (*set_key_encoding)(char*,int));

extern int   mscash1_common_valid(char *ciphertext, struct fmt_main *self);
extern char *mscash1_common_split(char *ciphertext, int index, struct fmt_main *self);
extern char *mscash1_common_prepare(char *split_fields[10], struct fmt_main *self);
extern void *mscash_common_binary(char *ciphertext);

extern void mscash2_adjust_tests(unsigned encoding, unsigned plain_len, unsigned salt_len);
extern int mscash2_common_valid(char *ciphertext, int max_salt_length, struct fmt_main *self);
extern char *mscash2_common_split(char *ciphertext, int index, struct fmt_main *self);
extern char *mscash2_common_prepare(char *split_fields[10], struct fmt_main *self);
