/*
 * Based on work by Tim Medin, Michael Kramer (SySS GmbH) and Fist0urs
 *
 * This software is Copyright (c) 2023 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#define FORMAT_NAME          "Kerberos 5 TGS-REP etype 23"
#define FORMAT_TAG           "$krb5tgs$23$"
#define FORMAT_TAG_LEN       (sizeof(FORMAT_TAG)-1)
#define BENCHMARK_COMMENT    ""
#define BENCHMARK_LENGTH     7
#define BINARY_SIZE          0
#define BINARY_ALIGN         MEM_ALIGN_NONE
#define SALT_SIZE            sizeof(struct custom_salt *)
#define SALT_ALIGN           sizeof(struct custom_salt *)

typedef struct {
	dyna_salt dsalt;
	unsigned char edata1[16];
	uint32_t edata2len;
	unsigned char edata2[1];
} krb5tgs_salt;

extern size_t krb5tgs_max_data_len;

extern struct fmt_tests krb5tgs_tests[];

extern char *krb5tgs_split(char *ciphertext, int index, struct fmt_main *self);
extern int krb5tgs_valid(char *ciphertext, struct fmt_main *self);
extern void *krb5tgs_get_salt(char *ciphertext);
