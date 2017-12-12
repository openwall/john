/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2016 JimF
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 *
 *  Functions and data which is common among the phpass-md5 crackers
 *  (CPU, OpenCL)
 */


#define BENCHMARK_LENGTH		-1 // only 1 salt is pretty much same speed.

#define PHPASS_GPU_PLAINTEXT_LENGTH    15
#define PHPASS_CPU_PLAINTEXT_LENGTH    39
#define PHPASS_CIPHERTEXT_LENGTH       34
#define PHPASS_BINARY_SIZE             16
#define PHPASS_SALT_ALIGN              sizeof(uint32_t)
#define PHPASS_BINARY_ALIGN            sizeof(uint32_t)
#define FORMAT_TAG                     "$P$"
#define FORMAT_TAG_LEN                (sizeof(FORMAT_TAG)-1)
#define FORMAT_TAG2                    "$H$"
#define FORMAT_TAG3                    "$dynamic_17$"
#define FORMAT_TAG3_LEN               (sizeof(FORMAT_TAG3)-1)


extern int phpass_common_valid(char *ciphertext, struct fmt_main *self);
extern void *phpass_common_binary(char *ciphertext);
extern char *phpass_common_split(char *ciphertext, int index, struct fmt_main *self);
extern char *phpass_common_prepare(char *split_fields[10], struct fmt_main *self);
extern unsigned int phpass_common_iteration_count(void *salt);

extern struct fmt_tests phpass_common_tests_15[];
extern struct fmt_tests phpass_common_tests_39[];
