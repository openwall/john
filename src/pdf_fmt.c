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

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

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
#define SALT_SIZE           5120
#define MIN_KEYS_PER_CRYPT  1
#define MAX_KEYS_PER_CRYPT  1

static EncData e;

static char saved_key[PLAINTEXT_LENGTH + 1];
static char has_been_cracked;

static struct fmt_tests pdf_tests[] = {
    {"$pdf$Standard*badad1e86442699427116d3e5d5271bc80a27814fc5e80f815efeef839354c5f*289ece9b5ce451a5d7064693dab3badf101112131415161718191a1b1c1d1e1f*16*34b1b6e593787af681a9b63fa8bf563b*1*1*0*1*4*128*-4*3*2", "test"},
	{NULL}
};

static void init(struct fmt_main *pFmt)
{
	/* OpenSSL init, cleanup part is left to OS */
	SSL_load_error_strings();
	SSL_library_init();
	OpenSSL_add_all_algorithms();
}

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	return !strncmp(ciphertext, "$pdf$", 5);
}

static void *get_salt(char *ciphertext)
{
	static char copy[SALT_SIZE+1];
	//char *copy = strdup(ciphertext);  // this causes a crash in debugging MSVC, due to reading past the end of this allocated buffer.  The 'static' is the proper size.
	strcpy(copy, ciphertext);
	return (void *) copy;
}

static void set_salt(void *_salt)
{
	unsigned char *salt = (unsigned char*)_salt;
	int i;
	char *p;
	unsigned char *copy;
	unsigned char *userpassword = NULL;

#ifdef PDF_FMT_DEBUG
	printf("%s\n", (char *)salt);
#endif
	salt += 5;		/* skip over "$pdf$" marker */
	copy = (unsigned char*)strdup((char*)salt);

	freeEncData(&e, 1);

	/* restore serialized data */
	e.s_handler = strdup(strtok((char*)copy, "*"));
	e.o_string = (uint8_t *) malloc(32);
	p = strtok(NULL, "*");
	for (i = 0; i < 32; i++)
		e.o_string[i] =
		    atoi16[ARCH_INDEX(p[i * 2])] * 16 +
		    atoi16[ARCH_INDEX(p[i * 2 + 1])];
	e.u_string = (uint8_t *) malloc(32);
	p = strtok(NULL, "*");
	for (i = 0; i < 32; i++)
		e.u_string[i] =
		    atoi16[ARCH_INDEX(p[i * 2])] * 16 +
		    atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtok(NULL, "*");
	e.fileIDLen = atoi(p);
	e.fileID = (uint8_t *) malloc(e.fileIDLen);
	p = strtok(NULL, "*");
	for (i = 0; i < e.fileIDLen; i++)
		e.fileID[i] =
		    atoi16[ARCH_INDEX(p[i * 2])] * 16 +
		    atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtok(NULL, "*");
	e.encryptMetaData = atoi(p);
	p = strtok(NULL, "*");
	e.work_with_user = atoi(p);
	p = strtok(NULL, "*");
	e.have_userpassword = atoi(p);
	p = strtok(NULL, "*");
	e.version_major = atoi(p);
	p = strtok(NULL, "*");
	e.version_minor = atoi(p);
	p = strtok(NULL, "*");
	e.length = atoi(p);
	p = strtok(NULL, "*");
	e.permissions = atoi(p);
	p = strtok(NULL, "*");
	e.revision = atoi(p);
	p = strtok(NULL, "*");
	e.version = atoi(p);
	if (e.have_userpassword) {
	    printf("received userpassword\n");
		userpassword = (unsigned char *)strtok(NULL, "*");
	}
#ifdef PDF_FMT_DEBUG
	printEncData(&e);
#endif
	/* try to initialize the cracking-engine */
	if (!initPDFCrack(&e, userpassword, e.work_with_user)) {
		cleanPDFCrack();
		fprintf(stderr, "Wrong userpassword, '%s'\n", userpassword);
		exit(-1);
	}
	free(copy);
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
    has_been_cracked = runCrack(saved_key);
#ifdef PDF_FMT_DEBUG
    if(has_been_cracked)
        printf("*** found password : %s\n", saved_key);
#endif
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
