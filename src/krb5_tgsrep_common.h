/*
 * Common code for the TGS-REP etype 17/18 formats.
 *
 * This software is Copyright (c) 2023 magnum,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include "formats.h"
#include "dyna_salt.h"

#define FORMAT_TAG              "$krb5tgs$"
#define FORMAT_TAG_LEN          (sizeof(FORMAT_TAG)-1)
#define ETYPE_TAG_LEN           3  // "17$" / "18$"
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x507
#define BINARY_SIZE             0
#define BINARY_ALIGN            MEM_ALIGN_NONE
#define SALT_SIZE               sizeof(krb5tgsrep_salt*)
#define SALT_ALIGN              sizeof(krb5tgsrep_salt*)

typedef struct {
	dyna_salt dsalt;
	int etype;
	char salt[256];            /* (...)$User$realm$(...) --> REALMUser */
	unsigned char edata1[12];  /* hmac-sha1 stripped to 12 bytes */
	uint32_t edata2len;
	unsigned char *edata2;
} krb5tgsrep_salt;

extern struct fmt_tests krb5_tgsrep_tests[];

extern int krb5_tgsrep_valid(char *ciphertext, struct fmt_main *self);
extern void *krb5_tgsrep_get_salt(char *ciphertext);
extern unsigned int krb5_tgsrep_etype(void *salt);
