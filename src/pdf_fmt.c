/**
 * Copyright (C) 2006 Henning Norén
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 *
 * Re-factored for JtR by Dhiru Kholia during June, 2011 for GSoC.
 *
 * References:
 *
 * http://www.adobe.com/devnet/pdf/pdf_reference.html
 * http://www.cs.cmu.edu/~dst/Adobe/Gallery/anon21jul01-pdf-encryption.txt
 * http://www.novapdf.com/kb/pdf-example-files-created-with-with-novapdf-138.html
 *
 * TODO: add support for detecting AESV2 and AESV3 encrypted documents
 * lacking "trailer dictionary" to pdfparser.c */

#undef MEM_FREE

#include <string.h>

#include "arch.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#include "misc.h"

#include "pdfcrack.h"
#include "pdfparser.h"

#define FORMAT_LABEL        "pdf"
#define FORMAT_NAME         "pdf"
#define ALGORITHM_NAME      "32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT   ""
#define BENCHMARK_LENGTH    -1000
#define PLAINTEXT_LENGTH    32
#define BINARY_SIZE         0
#define SALT_SIZE		sizeof(*salt_struct)
#define MIN_KEYS_PER_CRYPT  1
#define MAX_KEYS_PER_CRYPT  1

static struct custom_salt *salt_struct;
static char saved_key[PLAINTEXT_LENGTH + 1];
static char has_been_cracked;

static struct fmt_tests pdf_tests[] = {
	{"$pdf$Standard*badad1e86442699427116d3e5d5271bc80a27814fc5e80f815efeef839354c5f*289ece9b5ce451a5d7064693dab3badf101112131415161718191a1b1c1d1e1f*16*34b1b6e593787af681a9b63fa8bf563b*1*1*0*1*4*128*-4*3*2", "test"},
	{NULL}
};

static void init(struct fmt_main *pFmt)
{

}

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	return !strncmp(ciphertext, "$pdf$", 5);
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	int i;
	char *p;

	ctcopy += 5;	/* skip over "$pdf$" marker */
	salt_struct = mem_calloc_tiny(sizeof(struct custom_salt), MEM_ALIGN_WORD);

	/* restore serialized data */
	salt_struct->e.s_handler = strtok(ctcopy, "*");
	salt_struct->e.o_string = (uint8_t *) malloc(32);
	p = strtok(NULL, "*");
	for (i = 0; i < 32; i++)
		salt_struct->e.o_string[i] =
		    atoi16[ARCH_INDEX(p[i * 2])] * 16 +
		    atoi16[ARCH_INDEX(p[i * 2 + 1])];
	salt_struct->e.u_string = (uint8_t *) malloc(32);
	p = strtok(NULL, "*");
	for (i = 0; i < 32; i++)
		salt_struct->e.u_string[i] =
		    atoi16[ARCH_INDEX(p[i * 2])] * 16 +
		    atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtok(NULL, "*");
	salt_struct->e.fileIDLen = atoi(p);
	salt_struct->e.fileID = (uint8_t *) malloc(salt_struct->e.fileIDLen);
	p = strtok(NULL, "*");
	for (i = 0; i < salt_struct->e.fileIDLen; i++)
		salt_struct->e.fileID[i] =
		    atoi16[ARCH_INDEX(p[i * 2])] * 16 +
		    atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtok(NULL, "*");
	salt_struct->e.encryptMetaData = atoi(p);
	p = strtok(NULL, "*");
	salt_struct->e.work_with_user = atoi(p);
	p = strtok(NULL, "*");
	salt_struct->e.have_userpassword = atoi(p);
	p = strtok(NULL, "*");
	salt_struct->e.version_major = atoi(p);
	p = strtok(NULL, "*");
	salt_struct->e.version_minor = atoi(p);
	p = strtok(NULL, "*");
	salt_struct->e.length = atoi(p);
	p = strtok(NULL, "*");
	salt_struct->e.permissions = atoi(p);
	p = strtok(NULL, "*");
	salt_struct->e.revision = atoi(p);
	p = strtok(NULL, "*");
	salt_struct->e.version = atoi(p);
	if (salt_struct->e.have_userpassword)
		salt_struct->userpassword = (unsigned char *)strtok(NULL, "*");
	free(keeptr);
	/* try to initialize the cracking-engine */
	if (!initPDFCrack(salt_struct)) {
		fprintf(stderr, "Wrong userpassword, '%s'\n", salt_struct->userpassword);
		exit(-1);
	}
	return (void *)salt_struct;
}

static void set_salt(void *salt)
{
	salt_struct = (struct custom_salt *)salt;
	loadPDFCrack(salt_struct);
}

static void pdf_set_key(char *key, int index)
{
	int len = strlen(key);
	if (len > PLAINTEXT_LENGTH)
		len = PLAINTEXT_LENGTH;
	memcpy(saved_key, key, len);
	saved_key[len] = 0;
	has_been_cracked = 0;
}

static char *get_key(int index)
{
	return saved_key;
}

static void crypt_all(int count)
{
	/* do the actual crunching */
	has_been_cracked = runCrack(saved_key, salt_struct);
}

static int cmp_all(void *binary, int count)
{
	return 1;
}

static int cmp_one(void *binary, int index)
{
	return has_been_cracked;
}

static int cmp_exact(char *source, int index)
{
	return has_been_cracked;
}

struct fmt_main fmt_pdf = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		SALT_SIZE,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT,
		pdf_tests
	},
	{
		init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		set_salt,
		pdf_set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			fmt_default_get_hash
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};
