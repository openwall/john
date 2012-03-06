/* RAR 3.x cracker patch for JtR. Hacked together during
 * April of 2011 by Dhiru Kholia <dhiru.kholia at gmail.com> for GSoC.
 * magnum added -p mode support, using code based on libclamav.
 *
 * This software is Copyright © 2011, Dhiru Kholia <dhiru.kholia at gmail.com>
 * and (c) 2012, magnum and it is hereby released to the general public under
 * the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * This program uses code present in the public domain unrar utility written by
 * Alexander Roshal (http://www.rarlab.com/rar/unrarsrc-4.0.7.tar.gz).
 * Specifically, lines 240 to 274 from crypt.cpp are used.
 *
 * Huge thanks to Marc Bevand <m.bevand (at) gmail.com> for releasing unrarhp
 * (http://www.zorinaq.com/unrarhp/) and documenting the RAR encryption scheme.
 * This patch is made possible by unrarhp's documentation.
 *
 * http://anrieff.net/ucbench/technical_qna.html is another useful reference
 * for RAR encryption scheme.
 *
 * For type = 0 for files encrypted with "rar -hp ..." option
 * archive_name:$rar3$*type*hex(salt)*hex(partial-file-contents):type::::archive_name
 *
 * For type = 1 for files encrypted with "rar -p ..." option
 * archive_name:$rar3$*type*hex(salt)*hex(crc)*PACK_SIZE*UNP_SIZE*archive_name*offset-for-ciphertext*method:type::file_name
 *
 */

#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>

#undef MEM_FREE

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
#include "unrar.h"

#define FORMAT_LABEL		"rar"
#define FORMAT_NAME		"RAR3"
#define ALGORITHM_NAME		"32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define PLAINTEXT_LENGTH	32
#define BINARY_SIZE		2
#define SALT_SIZE		512
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1


/* The reason we want to bump OMP_SCALE in this case is to even out the
 * difference in processing time for different keys. But this hash is so slow,
 * we can't set it very high */
#ifdef _OPENMP
#include <omp.h>
#define OMP_SCALE		4
#endif
static int omp_t = 1;

static char (*saved_key)[3 * PLAINTEXT_LENGTH + 1];
static int (*cracked);
static unpack_data_t (*unpack_data);
static unsigned char saved_salt[8];
static unsigned char saved_ct[16];
static int type;  /* type of rar file */

/* for rar -p mode */
static unsigned int FILE_CRC;
static int PACK_SIZE;
static int UNP_SIZE;
static unsigned char *ciphertext;
static char *archive_name;
static int method;

static struct fmt_tests rar_tests[] = {
	{"$rar3$*0*c9dea41b149b53b4*fcbdb66122d8ebdb32532c22ca7ab9ec*24",
	    "password"},
	{NULL}
};

static void init(struct fmt_main *pFmt)
{
#if defined (_OPENMP)
	omp_t = omp_get_max_threads();
	pFmt->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	pFmt->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
	                            pFmt->params.max_keys_per_crypt,
	                            MEM_ALIGN_NONE);
	cracked = mem_calloc_tiny(sizeof(*cracked) *
	                          pFmt->params.max_keys_per_crypt,
	                          MEM_ALIGN_WORD);
	unpack_data = mem_calloc_tiny(sizeof(*unpack_data) *
	                              pFmt->params.max_keys_per_crypt,
	                              MEM_ALIGN_WORD);

	/* OpenSSL init, cleanup part is left to OS */
	SSL_load_error_strings();
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	if (options.utf8)
		pFmt->params.plaintext_length = PLAINTEXT_LENGTH * 3;
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
			((unsigned char*)&FILE_CRC)[i] =
				atoi16[ARCH_INDEX(p[i * 2])] * 16 +
				atoi16[ARCH_INDEX(p[i * 2 + 1])];
		PACK_SIZE = atoi(strtok(NULL, "*"));
		UNP_SIZE = atoi(strtok(NULL, "*"));
		archive_name = strtok(NULL, "*");
		pos = atol(strtok(NULL, "*"));
		p = strtok(NULL, "*");
		method = atoi16[ARCH_INDEX(p[0])] * 16 +
			atoi16[ARCH_INDEX(p[1])];
		if (method != 0x30)
			FILE_CRC = ~FILE_CRC;
		/* load ciphertext */
		if (!(fp = fopen(archive_name, "rb"))) {
			fprintf(stderr, "! %s: %s\n", archive_name,
			    strerror(errno));
			error();
		}
		fseek(fp, pos, SEEK_SET);
		if (ciphertext) free(ciphertext);
		ciphertext = (unsigned char *) malloc(PACK_SIZE);
		count = fread(ciphertext, 1, PACK_SIZE, fp);
		if (count != PACK_SIZE) {
			fprintf(stderr, "Error loading file from archive '%s', expected %d bytes, got %d. Archive possibly damaged.\n", archive_name, PACK_SIZE, count);
			exit(0);
		}
		fclose(fp);
	}
	memset(cracked, 0, sizeof(*cracked) * omp_t * MAX_KEYS_PER_CRYPT);
	free(keep_ptr);
}

/* could be DES set_key of old OpenSSL, which isn't what we mean */
#undef set_key

static void set_key(char *key, int index)
{
	int saved_key_length = strlen(key);
	if (saved_key_length > 3 * PLAINTEXT_LENGTH)
		saved_key_length = 3 * PLAINTEXT_LENGTH;
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
		plen = enc_to_utf16(utf16key, PLAINTEXT_LENGTH,
		                    (UTF8*)saved_key[index],
		                    strlen(saved_key[index]));
		if (plen <= 0)
			saved_key[index][-plen] = 0;
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
			AES_KEY key;
			unsigned char output[16];

			/* AES decrypt, uses aes_iv, aes_key and saved_ct */
			AES_set_decrypt_key((unsigned char *) aes_key, 16 * 8,
			                    &key);	/* AES-128 */
			AES_cbc_encrypt((unsigned char *) saved_ct, output, 16,
			                &key, (unsigned char *) aes_iv,
			                AES_DECRYPT);
			if (!memcmp(output, "\xc4\x3d\x7b\x00\x40\x07\x00", 7))
				cracked[index] = 1;
		} else {
			AES_KEY key;

			if (method == 0x30) { /* stored, not deflated */
				CRC32_t crc;
				unsigned char crc_out[4];
				unsigned char plainbuf[0x8010];
				unsigned int size = UNP_SIZE;
				unsigned char *cipher = ciphertext;

				/* Use full decryption with CRC check.
				   Compute CRC of the decompressed plaintext */
				AES_set_decrypt_key((unsigned char *) aes_key,
				                    16 * 8, &key);
				CRC32_Init(&crc);
				while(size) {
					int len = 0x8000;
					if (len > size) len = size + 15;

					AES_cbc_encrypt(cipher, plainbuf, len,
					                &key, aes_iv,
					                AES_DECRYPT);

					if (len > size) len = size;
					CRC32_Update(&crc, plainbuf, len);
					cipher += len;
					size -= len;
				}
				CRC32_Final(crc_out, crc);
				//printf("%08x\n", ~*(unsigned int*)crc_out);
				//dump_stuff_msg("computed", crc_out, 4);
				//dump_stuff_msg("stored", &FILE_CRC, 4);

				/* Compare computed CRC with stored CRC
				   (FILE_CRC) */
				cracked[index] = !memcmp(crc_out, &FILE_CRC, 4);
			} else {
				const int solid = 0;
				unpack_data_t *unpack_t =
					&unpack_data[index];

				rar_unpack_init_data(solid, unpack_t);
				unpack_t->max_size = UNP_SIZE;
				unpack_t->dest_unp_size = UNP_SIZE;
				unpack_t->pack_size = PACK_SIZE;
				unpack_t->iv = aes_iv;

				AES_set_decrypt_key(aes_key, 16 * 8,
				                    &unpack_t->key);
				if (rar_unpack29(ciphertext, solid, unpack_t))
					cracked[index] =
						!memcmp(&unpack_t->unp_crc,
						        &FILE_CRC, 4);
			}
		}
	}
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (cracked[index])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return cracked[index];
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
		FMT_CASE | FMT_8_BIT | FMT_UNICODE | FMT_UTF8 | FMT_OMP,
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
