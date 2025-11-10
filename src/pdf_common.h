/*
 * PDF cracker patch for JtR. Hacked together during Monsoon of 2012 by
 * Dhiru Kholia <dhiru.kholia at gmail.com>.
 *
 * This software is
 * Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>
 * Copyright (c) 2013, Shane Quigley
 * Copyright (c) 2024, magnum
 *
 * Uses code from pdfcrack, Sumatra PDF and MuPDF which are under GPL.
 */

#include <string.h>

#include "arch.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#include "misc.h"
#include "loader.h"
#include "options.h"
#include "logger.h"

#define FORMAT_NAME         "PDF encrypted document"
#define ALGORITHM_BASE      "MD5-RC4 / SHA2-AES"
#define FORMAT_TAG          "$pdf$"
#define FORMAT_TAG_LEN      (sizeof(FORMAT_TAG)-1)
#define FORMAT_TAG_OLD      "$pdf$Standard*"
#define FORMAT_TAG_OLD_LEN  (sizeof(FORMAT_TAG_OLD)-1)
#define BENCHMARK_COMMENT   ""
#define BENCHMARK_LENGTH    0x507
#define PLAINTEXT_LENGTH    MAX_PLAINTEXT_LENGTH
#define BINARY_SIZE         0
#define SALT_SIZE           sizeof(pdf_salt_type)
#define BINARY_ALIGN        1
#define SALT_ALIGN          sizeof(int)
#define MIN_KEYS_PER_CRYPT  1

#define MAX_KEY_SIZE        256
#define MAX_U_LEN           sizeof((pdf_salt_type){}.u)
#define MAX_O_LEN           sizeof((pdf_salt_type){}.o)

typedef struct {
	int V;                 // populated but unused
	int R;
	int P;
	int encrypt_metadata;
	unsigned char u[128];
	unsigned char o[128];
	unsigned char id[128];
	int key_length;        // key length in bits
	int id_len;
	int u_len;
	int o_len;
} pdf_salt_type;

extern pdf_salt_type *pdf_salt;
extern int *pdf_cracked;
extern int any_pdf_cracked;
extern size_t pdf_cracked_size;
extern struct fmt_tests pdf_tests[];
extern const unsigned char pdf_padding[32];

extern int pdf_valid(char *ciphertext, struct fmt_main *self);
extern char *pdf_prepare(char *split_fields[10], struct fmt_main *self);
extern void *pdf_get_salt(char *ciphertext);
extern int pdf_cmp_all(void *binary, int count);
extern int pdf_cmp_one(void *binary, int index);
extern int pdf_cmp_exact(char *source, int index);
extern unsigned int pdf_revision(void *salt);
extern unsigned int pdf_keylen(void *salt);
