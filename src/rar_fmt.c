/* RAR 3.x cracker patch for JtR. Hacked together during
 * April of 2011 by Dhiru Kholia <dhiru.kholia at gmail.com> for GSoC.
 *
 * This software is Copyright © 2011, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 *
 * This program uses code present in the public domain unrar utility written by
 * Alexander Roshal (http://www.rarlab.com/rar/unrarsrc-4.0.7.tar.gz). Specifically,
 * lines 240 to 274 from crypt.cpp are used.
 *
 * Huge thanks to Marc Bevand <m.bevand (at) gmail.com> for releasing unrarhp
 * (http://www.zorinaq.com/unrarhp/) and documenting the RAR encryption scheme.
 * This patch is made possible by unrarhp's documentation.
 *
 * http://anrieff.net/ucbench/technical_qna.html is another useful reference
 * for RAR encryption scheme.
 *
 * rar -p mode support is based on rar's technote.txt documentation and is
 * currently incomplete.
 *
 * http://kthoom.googlecode.com/hg/docs/unrar.html
 * http://acritum.com/winrar/rar-format
 * http://en.wikipedia.org/wiki/Rar
 * http://code.google.com/p/theunarchiver/
 * http://www.win-rar.com/index.php?id=24&kb_article_id=162
 *
 * "PPMd implementation of PPMII by Dmitry Shkarin"
 * "Lempel-Ziv (LZSS)"
 *
 * For type = 0 for files encrypted with "rar -hp ..." option
 * archive_name:$rar3$*type*hex(salt)*hex(partial-file-contents)
 *
 * For type = 1 for files encrypted with "rar -p ..." option
 * archive_name:$rar3$*type*hex(salt)*hex(crc)*PACK_SIZE*UNP_SIZE*archive_name*file-offset-for-ciphertext-data*method:::file_name
 *
 */

#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>

#undef MEM_FREE

/* temporary for dump_print() */
#include <ctype.h>

#include <string.h>
#include <assert.h>
#include <errno.h>
#include "arch.h"
#include "crc32.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "unicode.h"
#include "johnswap.h"

#define FORMAT_LABEL        "rar"
#define FORMAT_NAME         "rar"
#define ALGORITHM_NAME      "32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT   ""
#define BENCHMARK_LENGTH    -1
#define PLAINTEXT_LENGTH    32
#define BINARY_SIZE         2
#define SALT_SIZE           512
#define MIN_KEYS_PER_CRYPT  1
#define MAX_KEYS_PER_CRYPT  1

static char saved_key[3 * PLAINTEXT_LENGTH + 1];
static int has_been_cracked = 0;
static unsigned char saved_salt[8];
static unsigned char saved_ct[16];
static int type;  /* type of rar file */

/* for rar -p mode */
static char command[4096 + 64];
static unsigned char FILE_CRC[4];
static int PACK_SIZE;
static int UNP_SIZE;
static unsigned char *ciphertext;
static unsigned char *plaintext;
static char *archive_name;
static char *method;

static struct fmt_tests rar_tests[] = {
	{"$rar3$*0*c9dea41b149b53b4*fcbdb66122d8ebdb32532c22ca7ab9ec*24",
	    "password"},
	{NULL}
};

extern struct fmt_main rar_fmt;
static void init(struct fmt_main *pFmt)
{
	/* OpenSSL init, cleanup part is left to OS */
	SSL_load_error_strings();
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	if (options.utf8)
		rar_fmt.params.plaintext_length = PLAINTEXT_LENGTH * 3;
}

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	return !strncmp(ciphertext, "$rar3$*", 7);
}

static void *get_salt(char *ciphertext)
{
	return ciphertext;
}

static void set_salt(void *salt)
{
	int i, count;
	/* extract data from "salt" */
	char *encoded_salt;
	char *saltcopy = strdup(salt);
	char *keep_ptr = saltcopy;
	saltcopy += 7;		/* skip over "$rar3$*" */
	type = atoi(strtok(saltcopy, "*"));
	encoded_salt = strtok(NULL, "*");
	for (i = 0; i < 8; i++)
		saved_salt[i] = atoi16[ARCH_INDEX(encoded_salt[i * 2])] * 16
		    + atoi16[ARCH_INDEX(encoded_salt[i * 2 + 1])];
	if (type == 0) {	/* rar-hp mode */
		char *encoded_ct = strtok(NULL, "*");
		for (i = 0; i < 16; i++)
			saved_ct[i] = atoi16[ARCH_INDEX(encoded_ct[i * 2])]
			    * 16 + atoi16[ARCH_INDEX(encoded_ct[i * 2 + 1])];
	} else {
		long pos;
		FILE *fp;
		char *p = strtok(NULL, "*");
		for (i = 0; i < 4; i++)
			FILE_CRC[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16 +
			    atoi16[ARCH_INDEX(p[i * 2 + 1])];
		PACK_SIZE = atoi(strtok(NULL, "*"));
		UNP_SIZE = atoi(strtok(NULL, "*"));
		archive_name = strtok(NULL, "*");
		pos = atol(strtok(NULL, "*"));
		method = strtok(NULL, "*");
		/* load ciphertext */
		if (!(fp = fopen(archive_name, "rb"))) {
			fprintf(stderr, "! %s: %s\n", archive_name,
			    strerror(errno));
			error();
		}
		fseek(fp, pos, SEEK_SET);
		if (ciphertext) free(ciphertext);
		if (plaintext) free(plaintext);
		ciphertext = (unsigned char *) malloc(PACK_SIZE);
		plaintext = (unsigned char *) malloc(PACK_SIZE);
		count = fread(ciphertext, 1, PACK_SIZE, fp);
		assert(count == PACK_SIZE);
		fclose(fp);
	}
	has_been_cracked = 0;
	free(keep_ptr);
}

/* could be DES set_key of old OpenSSL, which isn't what we mean */
#undef set_key

static void set_key(char *key, int index)
{
	int saved_key_length = strlen(key);
	if (saved_key_length > 3 * PLAINTEXT_LENGTH)
		saved_key_length = 3 * PLAINTEXT_LENGTH;
	memcpy(saved_key, key, saved_key_length);
	saved_key[saved_key_length] = 0;
}

static char *get_key(int index)
{
	return saved_key;
}

#if 0
static void dump_print(void *data, int len)
{
	char *p = (char*)data;

	while(len--) {
		if (isprint(*p))
			putchar(*p);
		else
			putchar('.');
		p++;
	}
	puts("");
}
#endif

static void crypt_all(int count)
{
	if (type == 1 && method[1] != '0') {
		FILE *fp;
		int len, ret;

		len = sprintf(command, "%s%s%s%s", "unrar t -p", saved_key, " -inul ", archive_name);
		command[len] = 0;
		fp = popen(command, "r");
		ret = pclose(fp);
		if( ret == 0)
			has_been_cracked = 1;
	} else {
		int i = 0, j = 0;
		UTF16 utf16key[PLAINTEXT_LENGTH + 1];
		char *encoded_key = (char*)utf16key;
		int plen;
#if ARCH_LITTLE_ENDIAN && ARCH_ALLOWS_UNALIGNED
		unsigned char RawPsw[2 * PLAINTEXT_LENGTH + 8 + sizeof(int)];
#else
		unsigned char RawPsw[2 * PLAINTEXT_LENGTH + 8];
#endif
		unsigned char aes_key[16];
		unsigned char aes_iv[16];
		int RawLength;
		SHA_CTX ctx;
		const int HashRounds = 0x40000;
		unsigned int digest[5];
#if ARCH_LITTLE_ENDIAN && ARCH_ALLOWS_UNALIGNED
		unsigned int *PswNum;
#endif

		/* UTF-16LE encode the password, encoding aware */
		plen = enc_to_utf16(utf16key, PLAINTEXT_LENGTH, (UTF8*)saved_key, strlen(saved_key));
		if (plen <= 0)
			saved_key[-plen] = 0;
		if (plen < 0)
			plen = strlen16(utf16key);

#if ARCH_LITTLE_ENDIAN && ARCH_ALLOWS_UNALIGNED
		RawLength = (plen <<= 1) + 8 + 3;
		PswNum = (unsigned int*)&RawPsw[plen + 8];
		*PswNum = 0;
#else
		RawLength = (plen <<= 1) + 8;
#endif

		/* derive IV and key for AES from saved_key and saved_salt,
		 * this code block is based on unrarhp's and unrar's sources */

		memcpy(RawPsw, encoded_key, plen);
		memcpy(RawPsw + plen, saved_salt, 8);
		SHA1_Init(&ctx);
		for (i = 0; i < HashRounds; i++) {
#if !(ARCH_LITTLE_ENDIAN && ARCH_ALLOWS_UNALIGNED)
			unsigned char PswNum[3];
#endif

			SHA1_Update(&ctx, RawPsw, RawLength);
#if ARCH_LITTLE_ENDIAN && ARCH_ALLOWS_UNALIGNED
			*PswNum += 1;
#else
			PswNum[0] = (unsigned char) i;
			PswNum[1] = (unsigned char) (i >> 8);
			PswNum[2] = (unsigned char) (i >> 16);
			SHA1_Update(&ctx, PswNum, 3);
#endif
			if (i % (HashRounds / 16) == 0) {
				SHA_CTX tempctx = ctx;
				unsigned int digest[5];
				SHA1_Final((unsigned char *) digest, &tempctx);
				aes_iv[i / (HashRounds / 16)] =
					(unsigned char)JOHNSWAP(digest[4]);
			}
		}
		SHA1_Final((unsigned char *) digest, &ctx);
		for (j = 0; j < 5; j++)	/* reverse byte order */
			digest[j] = JOHNSWAP(digest[j]);
		for (i = 0; i < 4; i++)
			for (j = 0; j < 4; j++)
				aes_key[i * 4 + j] =
					(unsigned char) (digest[i] >> (j * 8));
		if (type == 0) {
			char ct[16];
			AES_KEY key;
			unsigned char output[16];

			memcpy(ct, saved_ct, 16);
			/* AES decrypt, uses aes_iv, aes_key and saved_ct */
			AES_set_decrypt_key((unsigned char *) aes_key, 16 * 8, &key);	/* AES-128 */
			AES_cbc_encrypt((unsigned char *) ct, output, 16, &key,
			                (unsigned char *) aes_iv, AES_DECRYPT);
			if (!memcmp(output, "\xc4\x3d\x7b\x00\x40\x07\x00", 7))
				has_been_cracked = 1;
		} else {
			AES_KEY key;
			CRC32_t crc;
			unsigned char crc_out[4];

			/* -p -m0: use full decryption with CRC check */
			AES_set_decrypt_key((unsigned char *) aes_key, 16 * 8,
			                    &key);
			AES_cbc_encrypt((unsigned char *) ciphertext, plaintext,
			                PACK_SIZE, &key, (unsigned char *)
			                aes_iv, AES_DECRYPT);

			/* compute CRC of the decompressed plaintext block */
			CRC32_Init(&crc);
			CRC32_Update(&crc, plaintext, UNP_SIZE);
			CRC32_Final(crc_out, crc);

			/* Compare computed CRC with stored CRC (FILE_CRC) */
			has_been_cracked = !memcmp(crc_out, FILE_CRC, 4);
		}
	}
}

static int cmp_all(void *binary, int count)
{
	return has_been_cracked;
}

static int cmp_one(void *binary, int index)
{
	return 1;
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main rar_fmt = {
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
		FMT_CASE | FMT_8_BIT | FMT_UNICODE | FMT_UTF8,
		rar_tests
	}, {
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
		set_key,
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
