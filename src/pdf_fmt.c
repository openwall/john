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
#ifdef _OPENMP
#include <omp.h>
#define OMP_SCALE               64
#endif
#include "pdfcrack.h"
#include "pdfparser.h"

#define FORMAT_LABEL        "pdf"
#define FORMAT_NAME         "PDF MD5 RC4"
#define ALGORITHM_NAME      "32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT   ""
#define BENCHMARK_LENGTH    -1000
#define PLAINTEXT_LENGTH    32
#define BINARY_SIZE         0
#define SALT_SIZE		sizeof(struct custom_salt)
#define MIN_KEYS_PER_CRYPT  1
#define MAX_KEYS_PER_CRYPT  1

#if defined (_OPENMP)
static int omp_t = 1;
#endif

static struct custom_salt *cur_salt;
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *cracked;
static int any_cracked;
static size_t cracked_size;

static struct fmt_tests pdf_tests[] = {
	{"$pdf$Standard*badad1e86442699427116d3e5d5271bc80a27814fc5e80f815efeef839354c5f*289ece9b5ce451a5d7064693dab3badf101112131415161718191a1b1c1d1e1f*16*34b1b6e593787af681a9b63fa8bf563b*1*1*0*1*4*128*-4*3*2", "test"},
	{"$pdf$Standard*d83a8ab680f144dfb2ff2334c206a6060779e007701ab881767f961aecda7984*a5ed4de7e078cb75dfdcd63e8da7a25800000000000000000000000000000000*16*06a7f710cf8dfafbd394540d40984ae2*1*1*0*1*4*128*-1028*3*2", "July2099"},
	{"$pdf$Standard*2446dd5ed2e18b3ce1ac9b56733226018e3f5c2639051eb1c9b2b215b30bc820*fa3af175d761963c8449ee7015b7770800000000000000000000000000000000*16*12a4da1abe6b7a1ceb84610bad87236d*1*1*0*1*4*128*-1028*3*2", "WHATwhatWHERE?"},
	{"$pdf$Standard*6a80a547b8b8b7636fcc5b322f1c63ce4b670c9b01f2aace09e48d85e1f19f83*e64eb62fc46be66e33571d50a29b464100000000000000000000000000000000*16*14a8c53ffa4a79b3ed9421ef15618420*1*1*0*1*4*128*-1028*3*2", "38r285a9"},
	{NULL}
};

static void init(struct fmt_main *self)
{
#if defined (_OPENMP)
	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
			self->params.max_keys_per_crypt, MEM_ALIGN_NONE);
	any_cracked = 0;
	cracked_size = sizeof(*cracked) * self->params.max_keys_per_crypt;
	cracked = mem_calloc_tiny(cracked_size, MEM_ALIGN_WORD);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	return !strncmp(ciphertext, "$pdf$", 5);
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	int i;
	char *p;
	static struct custom_salt cs;
	ctcopy += 5;	/* skip over "$pdf$" marker */
	memset(cs.encKeyWorkSpace, 0, 128);

	/* restore serialized data */
	cs.e.s_handler = strtok(ctcopy, "*");
	cs.e.o_string = (uint8_t *) malloc(32);
	p = strtok(NULL, "*");
	for (i = 0; i < 32; i++)
		cs.e.o_string[i] =
		    atoi16[ARCH_INDEX(p[i * 2])] * 16 +
		    atoi16[ARCH_INDEX(p[i * 2 + 1])];
	cs.e.u_string = (uint8_t *) malloc(32);
	p = strtok(NULL, "*");
	for (i = 0; i < 32; i++)
		cs.e.u_string[i] =
		    atoi16[ARCH_INDEX(p[i * 2])] * 16 +
		    atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtok(NULL, "*");
	cs.e.fileIDLen = atoi(p);
	cs.e.fileID = (uint8_t *) malloc(cs.e.fileIDLen);
	p = strtok(NULL, "*");
	for (i = 0; i < cs.e.fileIDLen; i++)
		cs.e.fileID[i] =
		    atoi16[ARCH_INDEX(p[i * 2])] * 16 +
		    atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtok(NULL, "*");
	cs.e.encryptMetaData = atoi(p);
	p = strtok(NULL, "*");
	cs.e.work_with_user = atoi(p);
	p = strtok(NULL, "*");
	cs.e.have_userpassword = atoi(p);
	p = strtok(NULL, "*");
	cs.e.version_major = atoi(p);
	p = strtok(NULL, "*");
	cs.e.version_minor = atoi(p);
	p = strtok(NULL, "*");
	cs.e.length = atoi(p);
	p = strtok(NULL, "*");
	cs.e.permissions = atoi(p);
	p = strtok(NULL, "*");
	cs.e.revision = atoi(p);
	p = strtok(NULL, "*");
	cs.e.version = atoi(p);
	if (cs.e.have_userpassword)
		cs.userpassword = (unsigned char *)strtok(NULL, "*");
	else
		cs.userpassword = NULL;
	cs.knownPassword = false;
	MEM_FREE(keeptr);
	/* try to initialize the cracking-engine */
	if (!initPDFCrack(&cs)) {
		fprintf(stderr, "Wrong userpassword, '%s'\n", cs.userpassword);
		exit(-1);
	}
	return (void *)&cs;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
	loadPDFCrack(cur_salt);
	if (any_cracked) {
		memset(cracked, 0, cracked_size);
		any_cracked = 0;
	}
}

static void pdf_set_key(char *key, int index)
{
	int saved_key_length = strlen(key);
	if (saved_key_length > PLAINTEXT_LENGTH)
		saved_key_length = PLAINTEXT_LENGTH;
	memcpy(saved_key[index], key, saved_key_length);
	saved_key[index][saved_key_length] = 0;
}

static char *get_key(int index)
{
	return saved_key[index];
}

static void crypt_all(int count)
{
	int index = 0;
#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index++)
#endif
	{
		/* do the actual crunching */
		cracked[index] = runCrack(saved_key[index], cur_salt);
		if(cracked[index] == 1)
			any_cracked = 1;
	}
}

static int cmp_all(void *binary, int count)
{
	return any_cracked;
}

static int cmp_one(void *binary, int index)
{
	return cracked[index];
}

static int cmp_exact(char *source, int index)
{
	return cracked[index];
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
		FMT_CASE | FMT_8_BIT | FMT_OMP,
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
